#!/usr/bin/env python3
"""
Audit SSH authorized_keys files for security issues.

Scans authorized_keys files to detect potential security issues:
- Keys with dangerous options (command=, no-pty combined with permitopen)
- Keys with unrestricted access (no from= restriction)
- Weak key algorithms (DSA, RSA < 2048 bits, ECDSA < 256 bits)
- Duplicate keys across users
- Keys with comments that might indicate shared/generic access
- Expired or very old keys (based on comment patterns)

Useful for large-scale baremetal environments where SSH access must be
audited regularly for compliance and security.

Exit codes:
    0 - No security issues detected
    1 - Security warnings or issues found
    2 - Usage error or access denied
"""

import argparse
import base64
import glob
import json
import os
import pwd
import re
import struct
import sys
from collections import defaultdict


def get_all_users():
    """Get all system users with home directories."""
    users = []
    try:
        for pw in pwd.getpwall():
            if pw.pw_dir and os.path.isdir(pw.pw_dir):
                users.append({
                    'username': pw.pw_name,
                    'uid': pw.pw_uid,
                    'home': pw.pw_dir,
                    'shell': pw.pw_shell,
                })
    except Exception:
        pass
    return users


def find_authorized_keys_files(users=None, additional_paths=None):
    """Find all authorized_keys files on the system."""
    files = []

    # Standard locations per user
    if users:
        for user in users:
            standard_path = os.path.join(user['home'], '.ssh', 'authorized_keys')
            if os.path.isfile(standard_path):
                files.append({
                    'path': standard_path,
                    'username': user['username'],
                    'uid': user['uid'],
                })

            # Also check authorized_keys2 (legacy)
            legacy_path = os.path.join(user['home'], '.ssh', 'authorized_keys2')
            if os.path.isfile(legacy_path):
                files.append({
                    'path': legacy_path,
                    'username': user['username'],
                    'uid': user['uid'],
                })

    # Additional paths (e.g., /etc/ssh/authorized_keys/)
    if additional_paths:
        for pattern in additional_paths:
            for path in glob.glob(pattern):
                if os.path.isfile(path):
                    files.append({
                        'path': path,
                        'username': os.path.basename(path),
                        'uid': None,
                    })

    return files


def parse_key_options(options_str):
    """Parse SSH key options string into a dictionary."""
    options = {}
    if not options_str:
        return options

    # Options can be comma-separated, but values can contain commas in quotes
    # Simple parsing for common options
    current = ''
    in_quotes = False

    for char in options_str:
        if char == '"':
            in_quotes = not in_quotes
            current += char
        elif char == ',' and not in_quotes:
            if current.strip():
                parse_single_option(current.strip(), options)
            current = ''
        else:
            current += char

    if current.strip():
        parse_single_option(current.strip(), options)

    return options


def parse_single_option(opt_str, options):
    """Parse a single key option."""
    if '=' in opt_str:
        key, value = opt_str.split('=', 1)
        # Remove quotes from value if present
        value = value.strip('"')
        options[key.lower()] = value
    else:
        options[opt_str.lower()] = True


def get_key_bits(key_type, key_data):
    """Extract key bit length from key data."""
    try:
        decoded = base64.b64decode(key_data)

        if key_type in ('ssh-rsa', 'rsa'):
            # RSA key format: string(key_type) + mpint(e) + mpint(n)
            # Parse past key type string and exponent to get modulus
            offset = 0

            # Skip key type string
            str_len = struct.unpack('>I', decoded[offset:offset+4])[0]
            offset += 4 + str_len

            # Skip exponent
            exp_len = struct.unpack('>I', decoded[offset:offset+4])[0]
            offset += 4 + exp_len

            # Get modulus length (this determines key size)
            mod_len = struct.unpack('>I', decoded[offset:offset+4])[0]
            # Subtract 1 if there's a leading zero byte (for positive number encoding)
            if decoded[offset+4] == 0:
                mod_len -= 1
            return mod_len * 8

        elif key_type in ('ssh-dss', 'dsa'):
            return 1024  # DSA is always 1024 bits

        elif key_type.startswith('ecdsa-sha2-'):
            # Extract curve from key type
            curve = key_type.split('-')[-1]
            curve_bits = {
                'nistp256': 256,
                'nistp384': 384,
                'nistp521': 521,
            }
            return curve_bits.get(curve, 256)

        elif key_type in ('ssh-ed25519', 'ed25519'):
            return 256  # Ed25519 is always 256 bits

    except Exception:
        pass

    return None


def parse_authorized_keys_line(line):
    """Parse a single authorized_keys line."""
    line = line.strip()

    # Skip empty lines and comments
    if not line or line.startswith('#'):
        return None

    # Key types we recognize
    key_types = [
        'ssh-rsa', 'ssh-dss', 'ssh-ed25519',
        'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
        'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com',
    ]

    # Find the key type in the line
    options_str = None
    key_type = None
    key_data = None
    comment = None

    for kt in key_types:
        if kt in line:
            idx = line.index(kt)
            if idx > 0:
                options_str = line[:idx].strip()
            remaining = line[idx:].split(None, 2)
            if len(remaining) >= 2:
                key_type = remaining[0]
                key_data = remaining[1]
                if len(remaining) > 2:
                    comment = remaining[2]
            break

    if not key_type or not key_data:
        return None

    options = parse_key_options(options_str)

    return {
        'key_type': key_type,
        'key_data': key_data,
        'comment': comment,
        'options': options,
        'options_str': options_str,
        'raw_line': line,
    }


def analyze_key_security(key_info, username):
    """Analyze a key for security issues."""
    issues = []
    key_type = key_info['key_type']
    options = key_info['options']
    comment = key_info['comment'] or ''

    # Check for weak algorithms
    if key_type in ('ssh-dss', 'dsa'):
        issues.append({
            'severity': 'critical',
            'issue': 'weak_algorithm',
            'message': 'DSA keys are deprecated and considered weak',
        })

    # Check RSA key size
    if key_type in ('ssh-rsa', 'rsa'):
        bits = get_key_bits(key_type, key_info['key_data'])
        if bits:
            if bits < 2048:
                issues.append({
                    'severity': 'critical',
                    'issue': 'weak_key_size',
                    'message': f'RSA key is only {bits} bits (minimum 2048 recommended)',
                })
            elif bits < 3072:
                issues.append({
                    'severity': 'warning',
                    'issue': 'short_key_size',
                    'message': f'RSA key is {bits} bits (3072+ recommended for long-term security)',
                })

    # Check for dangerous options
    if 'command' in options:
        cmd = options['command']
        # Some forced commands are acceptable
        dangerous_patterns = [
            r'/bin/sh', r'/bin/bash', r'/bin/zsh',
            r'\$\(', r'`',  # Command substitution
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, cmd, re.IGNORECASE):
                issues.append({
                    'severity': 'warning',
                    'issue': 'dangerous_command',
                    'message': f'Forced command may allow shell access: {cmd[:50]}',
                })
                break

    # Check for unrestricted access (no from= restriction)
    if 'from' not in options:
        issues.append({
            'severity': 'info',
            'issue': 'unrestricted_source',
            'message': 'Key has no source IP restriction (from= option)',
        })

    # Check for concerning options combinations
    if 'no-pty' in options and 'permitopen' in options:
        issues.append({
            'severity': 'info',
            'issue': 'tunnel_only_key',
            'message': 'Key configured for tunneling only (no-pty + permitopen)',
        })

    if 'agent-forwarding' in options or 'permit-agent-forwarding' in options:
        issues.append({
            'severity': 'warning',
            'issue': 'agent_forwarding',
            'message': 'Agent forwarding enabled (security risk if host compromised)',
        })

    # Check comment for concerning patterns
    comment_lower = comment.lower()
    concerning_comments = [
        (r'shared', 'warning', 'Comment suggests shared key'),
        (r'generic', 'warning', 'Comment suggests generic/shared key'),
        (r'temp(orary)?', 'warning', 'Comment suggests temporary key'),
        (r'test', 'info', 'Comment suggests test key'),
        (r'old', 'info', 'Comment suggests outdated key'),
        (r'backup', 'info', 'Comment suggests backup access key'),
        (r'@(gmail|yahoo|hotmail|outlook)\.com', 'info', 'Personal email in comment'),
    ]
    for pattern, severity, message in concerning_comments:
        if re.search(pattern, comment_lower):
            issues.append({
                'severity': severity,
                'issue': 'concerning_comment',
                'message': message,
            })
            break

    # Check for root user with unrestricted keys
    if username == 'root' and 'from' not in options and 'command' not in options:
        issues.append({
            'severity': 'critical',
            'issue': 'unrestricted_root',
            'message': 'Unrestricted SSH key for root user',
        })

    return issues


def audit_authorized_keys(file_info, verbose=False):
    """Audit a single authorized_keys file."""
    results = {
        'path': file_info['path'],
        'username': file_info['username'],
        'uid': file_info['uid'],
        'keys': [],
        'issues': [],
        'readable': True,
        'key_count': 0,
    }

    try:
        with open(file_info['path'], 'r') as f:
            lines = f.readlines()
    except PermissionError:
        results['readable'] = False
        results['issues'].append({
            'severity': 'error',
            'issue': 'permission_denied',
            'message': f"Cannot read {file_info['path']}",
        })
        return results
    except Exception as e:
        results['readable'] = False
        results['issues'].append({
            'severity': 'error',
            'issue': 'read_error',
            'message': str(e),
        })
        return results

    # Check file permissions
    try:
        stat_info = os.stat(file_info['path'])
        mode = stat_info.st_mode & 0o777
        if mode & 0o022:  # Group or world writable
            results['issues'].append({
                'severity': 'critical',
                'issue': 'insecure_permissions',
                'message': f'File has insecure permissions: {oct(mode)}',
            })
    except Exception:
        pass

    for line_num, line in enumerate(lines, 1):
        key_info = parse_authorized_keys_line(line)
        if not key_info:
            continue

        results['key_count'] += 1
        key_info['line_number'] = line_num

        # Analyze security
        key_issues = analyze_key_security(key_info, file_info['username'])
        key_info['issues'] = key_issues

        if verbose or key_issues:
            results['keys'].append(key_info)

        results['issues'].extend(key_issues)

    return results


def find_duplicate_keys(all_results):
    """Find keys that appear in multiple authorized_keys files."""
    key_map = defaultdict(list)

    for result in all_results:
        for key in result.get('keys', []):
            # Use key data as fingerprint (ignoring options and comments)
            key_fingerprint = key['key_data'][:64]  # First 64 chars is enough
            key_map[key_fingerprint].append({
                'username': result['username'],
                'path': result['path'],
                'comment': key.get('comment'),
            })

    duplicates = []
    for key_fp, locations in key_map.items():
        if len(locations) > 1:
            duplicates.append({
                'key_fingerprint': key_fp + '...',
                'locations': locations,
            })

    return duplicates


def format_plain(all_results, duplicates, summary, verbose=False):
    """Format results as plain text."""
    output = []

    output.append("SSH Authorized Keys Audit Report")
    output.append("=" * 60)
    output.append("")
    output.append(f"Files scanned: {summary['files_scanned']}")
    output.append(f"Total keys found: {summary['total_keys']}")
    output.append(f"Critical issues: {summary['critical_count']}")
    output.append(f"Warnings: {summary['warning_count']}")
    output.append(f"Info items: {summary['info_count']}")
    output.append("")

    # Show critical and warning issues
    for result in all_results:
        critical_warnings = [i for i in result['issues']
                           if i['severity'] in ('critical', 'warning', 'error')]
        if critical_warnings or verbose:
            output.append(f"User: {result['username']}")
            output.append(f"File: {result['path']}")
            output.append(f"Keys: {result['key_count']}")

            if not result['readable']:
                output.append("  [ERROR] Cannot read file")
            else:
                for issue in result['issues']:
                    if issue['severity'] in ('critical', 'error'):
                        output.append(f"  [CRITICAL] {issue['message']}")
                    elif issue['severity'] == 'warning':
                        output.append(f"  [WARNING] {issue['message']}")
                    elif verbose and issue['severity'] == 'info':
                        output.append(f"  [INFO] {issue['message']}")

            output.append("")

    # Show duplicates
    if duplicates:
        output.append("Duplicate Keys Detected:")
        output.append("-" * 60)
        for dup in duplicates:
            output.append(f"Key found in {len(dup['locations'])} locations:")
            for loc in dup['locations']:
                comment = f" ({loc['comment']})" if loc.get('comment') else ""
                output.append(f"  - {loc['username']}: {loc['path']}{comment}")
        output.append("")

    # Summary
    if summary['critical_count'] > 0:
        output.append(f"ALERT: {summary['critical_count']} critical issue(s) require attention!")
    elif summary['warning_count'] > 0:
        output.append(f"WARNING: {summary['warning_count']} issue(s) found")
    else:
        output.append("No critical issues detected")

    return '\n'.join(output)


def format_json(all_results, duplicates, summary):
    """Format results as JSON."""
    return json.dumps({
        'summary': summary,
        'duplicate_keys': duplicates,
        'files': all_results,
    }, indent=2, default=str)


def format_table(all_results, summary):
    """Format results as a table."""
    output = []

    header = f"{'USER':<15} {'KEYS':<6} {'CRIT':<6} {'WARN':<6} {'PATH':<40}"
    output.append(header)
    output.append("-" * len(header))

    for result in all_results:
        crit = len([i for i in result['issues'] if i['severity'] == 'critical'])
        warn = len([i for i in result['issues'] if i['severity'] == 'warning'])
        path = result['path']
        if len(path) > 40:
            path = '...' + path[-37:]
        output.append(
            f"{result['username']:<15} {result['key_count']:<6} "
            f"{crit:<6} {warn:<6} {path:<40}"
        )

    output.append("-" * len(header))
    output.append(
        f"{'TOTAL':<15} {summary['total_keys']:<6} "
        f"{summary['critical_count']:<6} {summary['warning_count']:<6}"
    )

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Audit SSH authorized_keys files for security issues.',
        epilog='''
Examples:
  # Scan all users' authorized_keys files
  baremetal_authorized_keys_audit.py

  # Scan specific user
  baremetal_authorized_keys_audit.py --user root

  # Include additional paths (e.g., centralized key directory)
  baremetal_authorized_keys_audit.py --additional-paths "/etc/ssh/authorized_keys/*"

  # Output as JSON for monitoring integration
  baremetal_authorized_keys_audit.py --format json

  # Only show critical and warning issues
  baremetal_authorized_keys_audit.py --warn-only

Exit codes:
  0 - No security issues detected
  1 - Security warnings or critical issues found
  2 - Usage error or access denied
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show all keys and info-level issues'
    )
    parser.add_argument(
        '-u', '--user',
        help='Audit only specific user'
    )
    parser.add_argument(
        '--additional-paths',
        nargs='+',
        help='Additional paths/globs to scan (e.g., /etc/ssh/authorized_keys/*)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show files with warnings or critical issues'
    )
    parser.add_argument(
        '--no-duplicates',
        action='store_true',
        help='Skip duplicate key detection'
    )

    args = parser.parse_args()

    # Get users to scan
    if args.user:
        try:
            pw = pwd.getpwnam(args.user)
            users = [{
                'username': pw.pw_name,
                'uid': pw.pw_uid,
                'home': pw.pw_dir,
                'shell': pw.pw_shell,
            }]
        except KeyError:
            print(f"Error: User '{args.user}' not found", file=sys.stderr)
            return 2
    else:
        users = get_all_users()

    # Find authorized_keys files
    files = find_authorized_keys_files(users, args.additional_paths)

    if not files:
        if args.format == 'json':
            print(json.dumps({'summary': {'files_scanned': 0, 'total_keys': 0}, 'files': []}))
        else:
            print("No authorized_keys files found")
        return 0

    # Audit each file
    all_results = []
    for file_info in files:
        result = audit_authorized_keys(file_info, args.verbose)
        all_results.append(result)

    # Find duplicates
    duplicates = [] if args.no_duplicates else find_duplicate_keys(all_results)

    # Filter if warn-only
    if args.warn_only:
        all_results = [
            r for r in all_results
            if any(i['severity'] in ('critical', 'warning', 'error')
                   for i in r['issues'])
        ]

    # Calculate summary
    summary = {
        'files_scanned': len(files),
        'files_with_issues': len([r for r in all_results if r['issues']]),
        'total_keys': sum(r['key_count'] for r in all_results),
        'critical_count': sum(
            1 for r in all_results
            for i in r['issues']
            if i['severity'] == 'critical'
        ),
        'warning_count': sum(
            1 for r in all_results
            for i in r['issues']
            if i['severity'] == 'warning'
        ),
        'info_count': sum(
            1 for r in all_results
            for i in r['issues']
            if i['severity'] == 'info'
        ),
        'duplicate_key_sets': len(duplicates),
    }

    # Format output
    if args.format == 'json':
        output = format_json(all_results, duplicates, summary)
    elif args.format == 'table':
        output = format_table(all_results, summary)
    else:
        output = format_plain(all_results, duplicates, summary, args.verbose)

    print(output)

    # Determine exit code
    if summary['critical_count'] > 0:
        return 1
    elif summary['warning_count'] > 0:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
