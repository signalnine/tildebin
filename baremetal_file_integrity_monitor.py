#!/usr/bin/env python3
"""
Monitor critical system files for unexpected changes (file integrity monitoring).

Computes and verifies checksums of critical system files to detect unauthorized
modifications. This is essential for:
- Security compliance (PCI-DSS, HIPAA, SOC2)
- Detecting rootkits and malware
- Configuration drift detection
- Change management auditing

Default monitored paths include:
- /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers
- /etc/ssh/sshd_config
- Critical binaries in /bin, /sbin, /usr/bin, /usr/sbin
- Boot configuration files

The script can operate in three modes:
1. Baseline mode (--baseline): Generate initial checksums
2. Verify mode (default): Compare current state against baseline
3. Report mode (--report): Show current file states without comparison

Exit codes:
    0 - All files match baseline / baseline created successfully
    1 - File integrity violations detected
    2 - Usage error or missing dependencies
"""

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


# Default critical files to monitor
DEFAULT_CRITICAL_FILES = [
    # Authentication and authorization
    '/etc/passwd',
    '/etc/shadow',
    '/etc/group',
    '/etc/gshadow',
    '/etc/sudoers',
    '/etc/login.defs',
    '/etc/pam.d/common-auth',
    '/etc/pam.d/common-password',
    '/etc/pam.d/sshd',
    '/etc/pam.d/su',
    '/etc/pam.d/sudo',
    '/etc/security/limits.conf',
    '/etc/security/access.conf',

    # SSH configuration
    '/etc/ssh/sshd_config',
    '/etc/ssh/ssh_config',

    # System configuration
    '/etc/fstab',
    '/etc/hosts',
    '/etc/hosts.allow',
    '/etc/hosts.deny',
    '/etc/resolv.conf',
    '/etc/nsswitch.conf',
    '/etc/sysctl.conf',
    '/etc/environment',
    '/etc/profile',
    '/etc/crontab',

    # Network configuration
    '/etc/network/interfaces',
    '/etc/netplan/01-netcfg.yaml',

    # Boot configuration
    '/etc/default/grub',
    '/boot/grub/grub.cfg',

    # Kernel modules
    '/etc/modules',
    '/etc/modprobe.d/blacklist.conf',

    # System binaries (most critical)
    '/bin/login',
    '/bin/su',
    '/bin/sudo',
    '/usr/bin/sudo',
    '/usr/bin/passwd',
    '/usr/bin/ssh',
    '/usr/bin/scp',
    '/usr/sbin/sshd',
    '/sbin/init',
    '/lib/systemd/systemd',
]

# Additional directories to scan for binaries
BINARY_DIRS = [
    '/bin',
    '/sbin',
    '/usr/bin',
    '/usr/sbin',
]

# Common critical binaries to check in binary directories
CRITICAL_BINARIES = [
    'bash', 'sh', 'dash', 'zsh',
    'login', 'su', 'sudo',
    'passwd', 'chpasswd', 'useradd', 'userdel', 'usermod',
    'ssh', 'sshd', 'scp', 'sftp',
    'cron', 'crontab', 'at', 'atd',
    'iptables', 'ip6tables', 'nft',
    'mount', 'umount',
    'init', 'systemctl', 'journalctl',
    'ls', 'cat', 'cp', 'mv', 'rm', 'chmod', 'chown',
    'ps', 'top', 'kill', 'pkill',
    'netstat', 'ss', 'ip', 'ifconfig',
    'find', 'grep', 'awk', 'sed',
]


def get_default_baseline_path():
    """Get the default baseline file path."""
    # Try common locations
    candidates = [
        '/var/lib/file-integrity/baseline.json',
        '/etc/file-integrity/baseline.json',
        os.path.expanduser('~/.file-integrity-baseline.json'),
    ]

    for path in candidates:
        parent = os.path.dirname(path)
        if os.path.isdir(parent) and os.access(parent, os.W_OK):
            return path

    # Default to home directory
    return os.path.expanduser('~/.file-integrity-baseline.json')


def compute_file_hash(filepath, algorithm='sha256'):
    """Compute cryptographic hash of a file."""
    try:
        hasher = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (IOError, OSError, PermissionError):
        return None


def get_file_metadata(filepath):
    """Get file metadata including permissions, owner, size, mtime."""
    try:
        st = os.stat(filepath)
        return {
            'size': st.st_size,
            'mode': stat.filemode(st.st_mode),
            'mode_octal': oct(st.st_mode)[-4:],
            'uid': st.st_uid,
            'gid': st.st_gid,
            'mtime': datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            'ctime': datetime.fromtimestamp(st.st_ctime, timezone.utc).isoformat(),
            'inode': st.st_ino,
            'nlink': st.st_nlink,
        }
    except (IOError, OSError, PermissionError):
        return None


def get_file_info(filepath, algorithm='sha256'):
    """Get complete file information including hash and metadata."""
    info = {
        'path': filepath,
        'exists': os.path.exists(filepath),
        'readable': os.access(filepath, os.R_OK) if os.path.exists(filepath) else False,
    }

    if info['exists'] and info['readable']:
        info['hash'] = compute_file_hash(filepath, algorithm)
        info['metadata'] = get_file_metadata(filepath)
        info['is_symlink'] = os.path.islink(filepath)
        if info['is_symlink']:
            try:
                info['symlink_target'] = os.readlink(filepath)
            except (IOError, OSError):
                info['symlink_target'] = None

    return info


def expand_file_list(file_list, include_binaries=True):
    """Expand file list to include critical binaries."""
    expanded = set(file_list)

    if include_binaries:
        for binary in CRITICAL_BINARIES:
            for bindir in BINARY_DIRS:
                path = os.path.join(bindir, binary)
                if os.path.exists(path):
                    expanded.add(path)

    return sorted(expanded)


def create_baseline(files, algorithm='sha256'):
    """Create a baseline of file states."""
    baseline = {
        'version': '1.0',
        'created': datetime.now(timezone.utc).isoformat(),
        'algorithm': algorithm,
        'hostname': os.uname().nodename,
        'files': {},
    }

    for filepath in files:
        info = get_file_info(filepath, algorithm)
        baseline['files'][filepath] = info

    return baseline


def load_baseline(baseline_path):
    """Load baseline from file."""
    try:
        with open(baseline_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid baseline file format: {e}")


def save_baseline(baseline, baseline_path):
    """Save baseline to file."""
    parent = os.path.dirname(baseline_path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, mode=0o700)

    with open(baseline_path, 'w') as f:
        json.dump(baseline, f, indent=2)

    # Set restrictive permissions
    os.chmod(baseline_path, 0o600)


def verify_against_baseline(current, baseline, check_metadata=True):
    """Compare current state against baseline and return violations."""
    violations = []
    warnings = []

    baseline_files = baseline.get('files', {})
    algorithm = baseline.get('algorithm', 'sha256')

    # Check all baseline files
    for filepath, baseline_info in baseline_files.items():
        current_info = current['files'].get(filepath)

        if not current_info:
            # File was in baseline but not checked now
            violations.append({
                'type': 'missing_check',
                'path': filepath,
                'message': 'File not checked in current scan',
            })
            continue

        # File existence change
        if baseline_info.get('exists') and not current_info.get('exists'):
            violations.append({
                'type': 'deleted',
                'path': filepath,
                'message': 'File was deleted',
                'severity': 'CRITICAL',
            })
            continue

        if not baseline_info.get('exists') and current_info.get('exists'):
            violations.append({
                'type': 'created',
                'path': filepath,
                'message': 'File was created (did not exist in baseline)',
                'severity': 'WARNING',
            })
            continue

        if not current_info.get('exists'):
            # File didn't exist in baseline and doesn't exist now - OK
            continue

        # Hash change (most critical)
        baseline_hash = baseline_info.get('hash')
        current_hash = current_info.get('hash')

        if baseline_hash and current_hash and baseline_hash != current_hash:
            violations.append({
                'type': 'modified',
                'path': filepath,
                'message': 'File content changed',
                'severity': 'CRITICAL',
                'baseline_hash': baseline_hash,
                'current_hash': current_hash,
            })
            continue

        # Permission changes
        if check_metadata:
            baseline_meta = baseline_info.get('metadata', {})
            current_meta = current_info.get('metadata', {})

            if baseline_meta and current_meta:
                # Mode change
                if baseline_meta.get('mode_octal') != current_meta.get('mode_octal'):
                    violations.append({
                        'type': 'permission_change',
                        'path': filepath,
                        'message': f"Permissions changed: {baseline_meta.get('mode')} -> {current_meta.get('mode')}",
                        'severity': 'WARNING',
                        'baseline_mode': baseline_meta.get('mode_octal'),
                        'current_mode': current_meta.get('mode_octal'),
                    })

                # Owner change
                if baseline_meta.get('uid') != current_meta.get('uid'):
                    warnings.append({
                        'type': 'owner_change',
                        'path': filepath,
                        'message': f"Owner UID changed: {baseline_meta.get('uid')} -> {current_meta.get('uid')}",
                        'severity': 'WARNING',
                    })

                # Group change
                if baseline_meta.get('gid') != current_meta.get('gid'):
                    warnings.append({
                        'type': 'group_change',
                        'path': filepath,
                        'message': f"Group GID changed: {baseline_meta.get('gid')} -> {current_meta.get('gid')}",
                        'severity': 'WARNING',
                    })

    # Check for new files in current scan not in baseline
    for filepath, current_info in current['files'].items():
        if filepath not in baseline_files:
            if current_info.get('exists'):
                warnings.append({
                    'type': 'new_file',
                    'path': filepath,
                    'message': 'New file not in baseline',
                    'severity': 'INFO',
                })

    return violations, warnings


def output_plain(result, violations, warnings, verbose=False, warn_only=False):
    """Output results in plain text format."""
    if warn_only and not violations and not warnings:
        return

    total_files = len(result['files'])
    accessible = sum(1 for f in result['files'].values() if f.get('readable'))

    if not warn_only:
        print("File Integrity Monitor")
        print("=" * 60)
        print(f"Hostname:       {result.get('hostname', 'unknown')}")
        print(f"Scan time:      {result.get('created', 'unknown')}")
        print(f"Algorithm:      {result.get('algorithm', 'sha256')}")
        print(f"Files checked:  {total_files}")
        print(f"Accessible:     {accessible}")
        print()

    if violations:
        print("INTEGRITY VIOLATIONS:")
        print("-" * 60)
        for v in violations:
            severity = v.get('severity', 'UNKNOWN')
            print(f"  [{severity}] {v['type'].upper()}: {v['path']}")
            print(f"           {v['message']}")
            if verbose and 'baseline_hash' in v:
                print(f"           Baseline: {v['baseline_hash'][:16]}...")
                print(f"           Current:  {v['current_hash'][:16]}...")
        print()

    if warnings and not warn_only:
        print("WARNINGS:")
        print("-" * 60)
        for w in warnings:
            print(f"  [{w.get('severity', 'WARNING')}] {w['type'].upper()}: {w['path']}")
            print(f"           {w['message']}")
        print()

    if not warn_only:
        if violations:
            critical_count = sum(1 for v in violations if v.get('severity') == 'CRITICAL')
            print(f"[!!] {len(violations)} integrity violation(s) detected ({critical_count} critical)")
        elif warnings:
            print(f"[--] {len(warnings)} warning(s), no integrity violations")
        else:
            print("[OK] All files match baseline")


def output_json(result, violations, warnings, baseline_info=None):
    """Output results in JSON format."""
    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'scan': result,
        'baseline': {
            'hostname': baseline_info.get('hostname') if baseline_info else None,
            'created': baseline_info.get('created') if baseline_info else None,
        } if baseline_info else None,
        'summary': {
            'total_files': len(result.get('files', {})),
            'accessible': sum(1 for f in result.get('files', {}).values() if f.get('readable')),
            'violations': len(violations),
            'warnings': len(warnings),
            'critical_violations': sum(1 for v in violations if v.get('severity') == 'CRITICAL'),
        },
        'violations': violations,
        'warnings': warnings,
        'healthy': len(violations) == 0,
    }
    print(json.dumps(output, indent=2))


def output_table(result, violations, warnings, warn_only=False):
    """Output results in table format."""
    if warn_only and not violations and not warnings:
        return

    print(f"{'Status':<10} {'Severity':<10} {'Type':<20} {'Path'}")
    print("=" * 80)

    for v in violations:
        print(f"{'VIOLATION':<10} {v.get('severity', 'UNKNOWN'):<10} {v['type']:<20} {v['path']}")

    for w in warnings:
        print(f"{'WARNING':<10} {w.get('severity', 'INFO'):<10} {w['type']:<20} {w['path']}")

    if not violations and not warnings:
        print(f"{'OK':<10} {'-':<10} {'no_issues':<20} All files match baseline")

    print("=" * 80)
    print(f"Total: {len(violations)} violations, {len(warnings)} warnings")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor critical system files for integrity violations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --baseline                   # Create initial baseline
  %(prog)s                              # Verify against baseline
  %(prog)s --format json                # JSON output for automation
  %(prog)s --report                     # Show current state (no comparison)
  %(prog)s -f /path/to/custom/list.txt  # Use custom file list

Default monitored files:
  - Authentication: /etc/passwd, /etc/shadow, /etc/sudoers
  - SSH: /etc/ssh/sshd_config
  - Critical binaries: /bin/login, /usr/bin/sudo, etc.
  - System config: /etc/fstab, /etc/hosts, /etc/crontab

Exit codes:
  0 - All files match baseline / baseline created
  1 - Integrity violations detected
  2 - Usage error or missing dependencies
"""
    )

    parser.add_argument(
        '--baseline', '-b',
        action='store_true',
        help='Create a new baseline (overwrites existing)'
    )

    parser.add_argument(
        '--baseline-file',
        default=None,
        help='Path to baseline file (default: auto-detected)'
    )

    parser.add_argument(
        '--report', '-r',
        action='store_true',
        help='Report current file states without comparing to baseline'
    )

    parser.add_argument(
        '--files', '-f',
        help='Path to file containing list of files to monitor (one per line)'
    )

    parser.add_argument(
        '--no-binaries',
        action='store_true',
        help='Do not include critical system binaries in scan'
    )

    parser.add_argument(
        '--no-metadata',
        action='store_true',
        help='Only check file content hash, not permissions/ownership'
    )

    parser.add_argument(
        '--algorithm', '-a',
        choices=['sha256', 'sha512', 'sha1', 'md5'],
        default='sha256',
        help='Hash algorithm to use (default: sha256)'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including hash values'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if violations or warnings detected'
    )

    args = parser.parse_args()

    # Determine baseline path
    baseline_path = args.baseline_file or get_default_baseline_path()

    # Build file list
    if args.files:
        try:
            with open(args.files, 'r') as f:
                file_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"Error: File list not found: {args.files}", file=sys.stderr)
            sys.exit(2)
    else:
        file_list = DEFAULT_CRITICAL_FILES

    # Expand to include binaries
    file_list = expand_file_list(file_list, include_binaries=not args.no_binaries)

    # Create current state
    current = create_baseline(file_list, args.algorithm)

    # Mode: Create baseline
    if args.baseline:
        try:
            save_baseline(current, baseline_path)
            file_count = len(current['files'])
            accessible = sum(1 for f in current['files'].values() if f.get('readable'))

            if args.format == 'json':
                output = {
                    'action': 'baseline_created',
                    'path': baseline_path,
                    'files': file_count,
                    'accessible': accessible,
                    'timestamp': current['created'],
                }
                print(json.dumps(output, indent=2))
            else:
                print(f"Baseline created: {baseline_path}")
                print(f"  Files: {file_count}")
                print(f"  Accessible: {accessible}")
                print(f"  Algorithm: {args.algorithm}")

            sys.exit(0)
        except (IOError, OSError, PermissionError) as e:
            print(f"Error: Cannot write baseline: {e}", file=sys.stderr)
            sys.exit(2)

    # Mode: Report only (no comparison)
    if args.report:
        if args.format == 'json':
            output_json(current, [], [])
        elif args.format == 'table':
            output_table(current, [], [], warn_only=args.warn_only)
        else:
            output_plain(current, [], [], verbose=args.verbose, warn_only=args.warn_only)
        sys.exit(0)

    # Mode: Verify against baseline
    baseline = load_baseline(baseline_path)

    if baseline is None:
        print(f"Error: No baseline found at {baseline_path}", file=sys.stderr)
        print("Create one with: --baseline", file=sys.stderr)
        sys.exit(2)

    # Verify
    violations, warnings = verify_against_baseline(
        current, baseline,
        check_metadata=not args.no_metadata
    )

    # Output
    if args.format == 'json':
        output_json(current, violations, warnings, baseline)
    elif args.format == 'table':
        output_table(current, violations, warnings, warn_only=args.warn_only)
    else:
        output_plain(current, violations, warnings, verbose=args.verbose, warn_only=args.warn_only)

    # Exit code
    if violations:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
