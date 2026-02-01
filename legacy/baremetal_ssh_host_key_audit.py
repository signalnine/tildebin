#!/usr/bin/env python3
"""
Audit SSH host key configuration and security on baremetal systems.

Validates SSH server host keys for security issues including:
- Weak key algorithms (DSA, RSA < 2048 bits, ECDSA < 256 bits)
- Missing recommended key types (Ed25519)
- Key file permission problems
- Key age and rotation status
- Consistency between public and private key pairs

Critical for large-scale environments where SSH security is essential
and weak or misconfigured host keys pose security risks.

Exit codes:
    0 - All host keys pass security checks
    1 - Security issues detected (weak keys, permission problems)
    2 - Usage error or SSH configuration not accessible
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# Default SSH host key directory
DEFAULT_SSH_DIR = '/etc/ssh'

# Key type recommendations
KEY_RECOMMENDATIONS = {
    'ed25519': {'recommended': True, 'min_bits': 256},
    'ecdsa': {'recommended': True, 'min_bits': 256},
    'rsa': {'recommended': True, 'min_bits': 2048, 'preferred_bits': 4096},
    'dsa': {'recommended': False, 'reason': 'DSA is deprecated and insecure'},
}

# Expected key file patterns
HOST_KEY_PATTERNS = [
    ('ssh_host_ed25519_key', 'ed25519'),
    ('ssh_host_ecdsa_key', 'ecdsa'),
    ('ssh_host_rsa_key', 'rsa'),
    ('ssh_host_dsa_key', 'dsa'),
]


def get_key_info_from_file(key_path):
    """Extract key information using ssh-keygen."""
    try:
        result = subprocess.run(
            ['ssh-keygen', '-l', '-f', key_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return None

        # Parse output: "2048 SHA256:xxx user@host (RSA)"
        # or: "256 SHA256:xxx user@host (ED25519)"
        output = result.stdout.strip()
        parts = output.split()
        if len(parts) >= 4:
            bits = int(parts[0])
            fingerprint = parts[1]
            # Key type is in parentheses at the end
            key_type_match = re.search(r'\((\w+)\)$', output)
            key_type = key_type_match.group(1).lower() if key_type_match else 'unknown'

            return {
                'bits': bits,
                'fingerprint': fingerprint,
                'key_type': key_type
            }
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass
    return None


def check_file_permissions(file_path):
    """Check if file permissions are secure for SSH keys."""
    try:
        stat_info = os.stat(file_path)
        mode = stat_info.st_mode & 0o777
        uid = stat_info.st_uid

        issues = []

        # Private keys should be 600 or 640
        if file_path.endswith('.pub'):
            # Public keys can be world-readable (644 is fine)
            if mode & 0o002:  # World-writable is never OK
                issues.append(f'World-writable ({oct(mode)})')
        else:
            # Private keys: should be 600 (owner read/write only)
            if mode & 0o077:  # Group or world access
                issues.append(f'Too permissive ({oct(mode)}, should be 0600)')

        # Should be owned by root
        if uid != 0:
            issues.append(f'Not owned by root (uid={uid})')

        return {
            'mode': oct(mode),
            'uid': uid,
            'secure': len(issues) == 0,
            'issues': issues
        }
    except OSError as e:
        return {
            'mode': None,
            'uid': None,
            'secure': False,
            'issues': [f'Cannot stat file: {e}']
        }


def get_file_age_days(file_path):
    """Get file modification time age in days."""
    try:
        mtime = os.path.getmtime(file_path)
        age_seconds = datetime.now().timestamp() - mtime
        return int(age_seconds / 86400)
    except OSError:
        return None


def check_key_pair_consistency(private_key_path):
    """Verify public and private key match."""
    public_key_path = private_key_path + '.pub'

    if not os.path.exists(public_key_path):
        return {'consistent': False, 'issue': 'Public key file missing'}

    try:
        # Get fingerprints of both keys
        priv_result = subprocess.run(
            ['ssh-keygen', '-l', '-f', private_key_path],
            capture_output=True, text=True, timeout=10
        )
        pub_result = subprocess.run(
            ['ssh-keygen', '-l', '-f', public_key_path],
            capture_output=True, text=True, timeout=10
        )

        if priv_result.returncode != 0 or pub_result.returncode != 0:
            return {'consistent': False, 'issue': 'Cannot read key fingerprint'}

        # Compare fingerprints
        priv_fp = priv_result.stdout.split()[1] if priv_result.stdout else ''
        pub_fp = pub_result.stdout.split()[1] if pub_result.stdout else ''

        if priv_fp == pub_fp:
            return {'consistent': True, 'issue': None}
        else:
            return {'consistent': False, 'issue': 'Fingerprint mismatch between public and private key'}

    except (subprocess.TimeoutExpired, IndexError):
        return {'consistent': False, 'issue': 'Error comparing keys'}


def evaluate_key_security(key_type, bits):
    """Evaluate if a key meets security requirements."""
    issues = []
    warnings = []

    recommendation = KEY_RECOMMENDATIONS.get(key_type, {})

    if not recommendation.get('recommended', True):
        issues.append(recommendation.get('reason', f'{key_type} is not recommended'))
        return issues, warnings

    min_bits = recommendation.get('min_bits', 0)
    preferred_bits = recommendation.get('preferred_bits', min_bits)

    if bits < min_bits:
        issues.append(f'Key size {bits} bits is below minimum ({min_bits} bits)')
    elif bits < preferred_bits:
        warnings.append(f'Key size {bits} bits is below preferred ({preferred_bits} bits)')

    return issues, warnings


def audit_ssh_host_keys(ssh_dir, max_key_age_days=None):
    """Audit all SSH host keys in the specified directory."""
    results = {
        'ssh_dir': ssh_dir,
        'keys': [],
        'issues': [],
        'warnings': [],
        'missing_recommended': [],
        'summary': {
            'total_keys': 0,
            'secure_keys': 0,
            'weak_keys': 0,
            'permission_issues': 0
        }
    }

    if not os.path.isdir(ssh_dir):
        results['issues'].append(f'SSH directory not found: {ssh_dir}')
        return results

    # Track which recommended key types we find
    found_types = set()

    # Check each expected host key
    for key_filename, expected_type in HOST_KEY_PATTERNS:
        key_path = os.path.join(ssh_dir, key_filename)

        if not os.path.exists(key_path):
            continue

        key_info = {
            'path': key_path,
            'filename': key_filename,
            'expected_type': expected_type,
            'exists': True,
            'issues': [],
            'warnings': []
        }

        # Get key details
        key_details = get_key_info_from_file(key_path)
        if key_details:
            key_info.update(key_details)
            found_types.add(key_details['key_type'])

            # Evaluate security
            sec_issues, sec_warnings = evaluate_key_security(
                key_details['key_type'],
                key_details['bits']
            )
            key_info['issues'].extend(sec_issues)
            key_info['warnings'].extend(sec_warnings)
        else:
            key_info['issues'].append('Cannot read key information')

        # Check permissions
        perm_info = check_file_permissions(key_path)
        key_info['permissions'] = perm_info
        if not perm_info['secure']:
            key_info['issues'].extend(perm_info['issues'])
            results['summary']['permission_issues'] += 1

        # Check key pair consistency
        consistency = check_key_pair_consistency(key_path)
        key_info['key_pair_consistent'] = consistency['consistent']
        if not consistency['consistent']:
            key_info['issues'].append(consistency['issue'])

        # Check key age
        age_days = get_file_age_days(key_path)
        key_info['age_days'] = age_days
        if max_key_age_days and age_days and age_days > max_key_age_days:
            key_info['warnings'].append(
                f'Key is {age_days} days old (threshold: {max_key_age_days})'
            )

        # Update summary
        results['summary']['total_keys'] += 1
        if key_info['issues']:
            results['summary']['weak_keys'] += 1
            for issue in key_info['issues']:
                results['issues'].append(f"{key_filename}: {issue}")
        else:
            results['summary']['secure_keys'] += 1

        for warning in key_info['warnings']:
            results['warnings'].append(f"{key_filename}: {warning}")

        results['keys'].append(key_info)

    # Check for missing recommended key types
    recommended_types = ['ed25519']  # Ed25519 should always be present
    for rec_type in recommended_types:
        if rec_type not in found_types:
            results['missing_recommended'].append(rec_type)
            results['warnings'].append(
                f'Recommended key type missing: {rec_type}'
            )

    # Check if DSA key exists (deprecated)
    if 'dsa' in found_types:
        results['warnings'].append(
            'DSA host key present - consider removing (deprecated)'
        )

    return results


def format_plain(results, verbose=False):
    """Format output as plain text."""
    lines = []

    lines.append("SSH Host Key Audit")
    lines.append("=" * 50)
    lines.append(f"SSH Directory: {results['ssh_dir']}")
    lines.append("")

    summary = results['summary']
    lines.append(f"Total host keys: {summary['total_keys']}")
    lines.append(f"Secure keys: {summary['secure_keys']}")
    lines.append(f"Keys with issues: {summary['weak_keys']}")
    lines.append(f"Permission issues: {summary['permission_issues']}")
    lines.append("")

    if verbose or results['issues']:
        lines.append("Key Details:")
        lines.append("-" * 50)
        for key in results['keys']:
            status = "SECURE" if not key['issues'] else "ISSUES"
            bits = key.get('bits', '?')
            key_type = key.get('key_type', 'unknown').upper()
            lines.append(f"  {key['filename']}")
            lines.append(f"    Type: {key_type}, Bits: {bits}, Status: {status}")

            if key.get('fingerprint'):
                lines.append(f"    Fingerprint: {key['fingerprint']}")

            if key.get('age_days') is not None:
                lines.append(f"    Age: {key['age_days']} days")

            if key['issues']:
                for issue in key['issues']:
                    lines.append(f"    [!] {issue}")

            if verbose and key['warnings']:
                for warning in key['warnings']:
                    lines.append(f"    [*] {warning}")

            lines.append("")

    # Show issues
    if results['issues']:
        lines.append("ISSUES:")
        for issue in results['issues']:
            lines.append(f"  [!] {issue}")
        lines.append("")

    # Show warnings
    if results['warnings']:
        lines.append("WARNINGS:")
        for warning in results['warnings']:
            lines.append(f"  [*] {warning}")
        lines.append("")

    # Summary
    if not results['issues'] and not results['warnings']:
        lines.append("[OK] All SSH host keys pass security checks")
    elif results['issues']:
        lines.append("[!!] Security issues detected - action required")
    else:
        lines.append("[*] Warnings detected - review recommended")

    return "\n".join(lines)


def format_json(results):
    """Format output as JSON."""
    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'ssh_dir': results['ssh_dir'],
        'summary': results['summary'],
        'keys': results['keys'],
        'issues': results['issues'],
        'warnings': results['warnings'],
        'missing_recommended': results['missing_recommended'],
        'status': 'critical' if results['issues'] else (
            'warning' if results['warnings'] else 'healthy'
        ),
        'healthy': len(results['issues']) == 0
    }
    return json.dumps(output, indent=2)


def format_table(results):
    """Format output as a table."""
    lines = []

    lines.append("+" + "-" * 70 + "+")
    lines.append("| SSH Host Key Audit" + " " * 51 + "|")
    lines.append("+" + "-" * 70 + "+")

    lines.append(f"| {'Key File':<30} | {'Type':<8} | {'Bits':<6} | {'Status':<15} |")
    lines.append("+" + "-" * 70 + "+")

    for key in results['keys']:
        filename = key['filename'][:30]
        key_type = key.get('key_type', '?')[:8].upper()
        bits = str(key.get('bits', '?'))[:6]
        status = "SECURE" if not key['issues'] else "ISSUES"

        lines.append(f"| {filename:<30} | {key_type:<8} | {bits:<6} | {status:<15} |")

    lines.append("+" + "-" * 70 + "+")

    summary = results['summary']
    lines.append(f"| Total: {summary['total_keys']}, Secure: {summary['secure_keys']}, "
                f"Issues: {summary['weak_keys']}" + " " * 27 + "|")
    lines.append("+" + "-" * 70 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Audit SSH host key configuration and security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic audit
  %(prog)s

  # JSON output for monitoring
  %(prog)s --format json

  # Check with key age threshold (365 days)
  %(prog)s --max-age 365

  # Custom SSH directory
  %(prog)s --ssh-dir /etc/ssh

  # Only show if issues detected
  %(prog)s --warn-only

Security checks performed:
  - Key algorithm strength (rejects DSA, weak RSA/ECDSA)
  - Key file permissions (private keys should be 0600)
  - Key pair consistency (public/private match)
  - Missing recommended key types (Ed25519)
  - Key age (optional threshold)

Exit codes:
  0 - All host keys pass security checks
  1 - Security issues detected
  2 - Usage error or SSH configuration not accessible
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--ssh-dir',
        default=DEFAULT_SSH_DIR,
        help=f'SSH configuration directory (default: {DEFAULT_SSH_DIR})'
    )
    parser.add_argument(
        '--max-age',
        type=int,
        default=None,
        metavar='DAYS',
        help='Warn if keys are older than DAYS (default: no age check)'
    )
    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information for all keys'
    )

    args = parser.parse_args()

    # Validate max-age
    if args.max_age is not None and args.max_age < 1:
        print("Error: --max-age must be a positive integer", file=sys.stderr)
        sys.exit(2)

    # Check if ssh-keygen is available
    try:
        subprocess.run(['ssh-keygen', '-V'], capture_output=True, timeout=5)
    except FileNotFoundError:
        print("Error: ssh-keygen not found in PATH", file=sys.stderr)
        print("Install OpenSSH: sudo apt-get install openssh-client", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print("Error: ssh-keygen timed out", file=sys.stderr)
        sys.exit(2)

    # Check if SSH directory exists
    if not os.path.isdir(args.ssh_dir):
        print(f"Error: SSH directory not found: {args.ssh_dir}", file=sys.stderr)
        sys.exit(2)

    # Perform audit
    results = audit_ssh_host_keys(args.ssh_dir, args.max_age)

    # Format output
    if args.format == 'json':
        output = format_json(results)
    elif args.format == 'table':
        output = format_table(results)
    else:
        output = format_plain(results, args.verbose)

    # Print output (respecting --warn-only)
    if not args.warn_only or results['issues'] or results['warnings']:
        print(output)

    # Return appropriate exit code
    return 1 if results['issues'] else 0


if __name__ == '__main__':
    sys.exit(main())
