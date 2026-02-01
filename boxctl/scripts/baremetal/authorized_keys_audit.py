#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, audit, ssh, keys, authentication]
#   privilege: root
#   brief: Audit SSH authorized_keys files for security issues

"""
Audit SSH authorized_keys files for security issues.

Scans authorized_keys files to detect potential security issues:
- Keys with dangerous options (command= with shell access)
- Keys with unrestricted access (no from= restriction)
- Weak key algorithms (DSA)
- Keys with comments suggesting shared/temporary access
- Unrestricted root keys (critical)

Returns exit code 1 if security issues are found.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Key types we recognize
KEY_TYPES = [
    'ssh-rsa', 'ssh-dss', 'ssh-ed25519',
    'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
    'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com',
]


def parse_key_options(options_str: str | None) -> dict[str, Any]:
    """Parse SSH key options string into a dictionary."""
    options: dict[str, Any] = {}
    if not options_str:
        return options

    current = ''
    in_quotes = False

    for char in options_str:
        if char == '"':
            in_quotes = not in_quotes
            current += char
        elif char == ',' and not in_quotes:
            if current.strip():
                _parse_single_option(current.strip(), options)
            current = ''
        else:
            current += char

    if current.strip():
        _parse_single_option(current.strip(), options)

    return options


def _parse_single_option(opt_str: str, options: dict[str, Any]) -> None:
    """Parse a single key option."""
    if '=' in opt_str:
        key, value = opt_str.split('=', 1)
        options[key.lower()] = value.strip('"')
    else:
        options[opt_str.lower()] = True


def parse_authorized_keys_line(line: str) -> dict[str, Any] | None:
    """Parse a single authorized_keys line."""
    line = line.strip()

    # Skip empty lines and comments
    if not line or line.startswith('#'):
        return None

    # Find the key type in the line
    options_str = None
    key_type = None
    key_data = None
    comment = None

    for kt in KEY_TYPES:
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
        'key_data': key_data[:32] + '...',  # Truncate for display
        'comment': comment,
        'options': options,
    }


def analyze_key_security(key_info: dict[str, Any], username: str) -> list[dict[str, Any]]:
    """Analyze a key for security issues."""
    issues = []
    key_type = key_info['key_type']
    options = key_info['options']
    comment = key_info.get('comment') or ''

    # Check for weak algorithms
    if key_type in ('ssh-dss', 'dsa'):
        issues.append({
            'severity': 'critical',
            'issue': 'weak_algorithm',
            'message': 'DSA keys are deprecated and considered weak',
        })

    # Check for dangerous command options
    if 'command' in options:
        cmd = options['command']
        dangerous_patterns = [
            r'/bin/sh', r'/bin/bash', r'/bin/zsh',
            r'\$\(', r'`',
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, cmd, re.IGNORECASE):
                issues.append({
                    'severity': 'warning',
                    'issue': 'dangerous_command',
                    'message': f'Forced command may allow shell access',
                })
                break

    # Check for unrestricted access
    if 'from' not in options:
        issues.append({
            'severity': 'info',
            'issue': 'unrestricted_source',
            'message': 'Key has no source IP restriction (from= option)',
        })

    # Check for agent forwarding
    if 'agent-forwarding' in options or 'permit-agent-forwarding' in options:
        issues.append({
            'severity': 'warning',
            'issue': 'agent_forwarding',
            'message': 'Agent forwarding enabled (security risk)',
        })

    # Check for concerning comments
    comment_lower = comment.lower()
    concerning_patterns = [
        (r'shared', 'warning', 'Comment suggests shared key'),
        (r'temp(orary)?', 'warning', 'Comment suggests temporary key'),
        (r'test', 'info', 'Comment suggests test key'),
    ]
    for pattern, severity, message in concerning_patterns:
        if re.search(pattern, comment_lower):
            issues.append({
                'severity': severity,
                'issue': 'concerning_comment',
                'message': message,
            })
            break

    # Check for unrestricted root keys - critical
    if username == 'root' and 'from' not in options and 'command' not in options:
        issues.append({
            'severity': 'critical',
            'issue': 'unrestricted_root',
            'message': 'Unrestricted SSH key for root user',
        })

    return issues


def audit_authorized_keys_content(
    content: str,
    username: str,
    filepath: str
) -> dict[str, Any]:
    """Audit authorized_keys content for security issues."""
    result = {
        'path': filepath,
        'username': username,
        'keys': [],
        'issues': [],
        'key_count': 0,
    }

    for line_num, line in enumerate(content.split('\n'), 1):
        key_info = parse_authorized_keys_line(line)
        if not key_info:
            continue

        result['key_count'] += 1
        key_info['line_number'] = line_num

        # Analyze security
        key_issues = analyze_key_security(key_info, username)
        key_info['issues'] = key_issues

        result['keys'].append(key_info)
        result['issues'].extend(key_issues)

    return result


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit SSH authorized_keys files for security issues"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show all keys including those without issues")
    parser.add_argument("-u", "--user", help="Audit only specific user")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show warning and critical issues")
    opts = parser.parse_args(args)

    # Get passwd entries to find home directories
    try:
        passwd_content = context.read_file('/etc/passwd')
    except (FileNotFoundError, PermissionError) as e:
        output.error(f"Cannot read /etc/passwd: {e}")
        return 2

    # Parse passwd and find authorized_keys files
    users_to_check = []
    for line in passwd_content.strip().split('\n'):
        if not line or line.startswith('#'):
            continue
        parts = line.split(':')
        if len(parts) >= 6:
            username = parts[0]
            home = parts[5]
            if opts.user and username != opts.user:
                continue
            users_to_check.append((username, home))

    if opts.user and not users_to_check:
        output.error(f"User '{opts.user}' not found")
        return 2

    # Audit each user's authorized_keys
    all_results = []
    total_keys = 0
    critical_count = 0
    warning_count = 0
    info_count = 0

    for username, home in users_to_check:
        auth_keys_path = f"{home}/.ssh/authorized_keys"

        if not context.file_exists(auth_keys_path):
            continue

        try:
            content = context.read_file(auth_keys_path)
        except (FileNotFoundError, PermissionError):
            continue

        result = audit_authorized_keys_content(content, username, auth_keys_path)
        total_keys += result['key_count']

        for issue in result['issues']:
            if issue['severity'] == 'critical':
                critical_count += 1
            elif issue['severity'] == 'warning':
                warning_count += 1
            elif issue['severity'] == 'info':
                info_count += 1

        # Filter based on warn-only flag
        if opts.warn_only:
            result['issues'] = [
                i for i in result['issues']
                if i['severity'] in ('critical', 'warning')
            ]
            if not result['issues']:
                continue

        if result['key_count'] > 0 or result['issues']:
            all_results.append(result)

    # Emit structured output
    output.emit({
        'files_scanned': len(all_results),
        'total_keys': total_keys,
        'critical_count': critical_count,
        'warning_count': warning_count,
        'info_count': info_count,
        'files': all_results if opts.verbose else [
            {
                'path': r['path'],
                'username': r['username'],
                'key_count': r['key_count'],
                'issues': r['issues'],
            }
            for r in all_results
        ],
    })

    # Set summary
    if critical_count > 0:
        output.set_summary(f"{critical_count} critical, {warning_count} warnings")
    elif warning_count > 0:
        output.set_summary(f"{warning_count} warnings found")
    else:
        output.set_summary(f"{total_keys} keys scanned, no issues")

    # Return 1 if any critical or warning issues
    if critical_count > 0 or warning_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
