#!/usr/bin/env python3
"""
Audit SUID and SGID binaries on baremetal Linux systems.

Finds and reports all files with SUID (Set User ID) or SGID (Set Group ID)
bits set. These files run with elevated privileges and are common targets
for privilege escalation attacks. Regular auditing helps detect:

- Unexpected SUID/SGID binaries (potential backdoors)
- Non-standard locations for privileged binaries
- Changes to the SUID/SGID file inventory
- Known vulnerable SUID programs

Essential for security compliance, detecting unauthorized privilege
escalation vectors, and maintaining datacenter security posture.

Exit codes:
    0 - Audit completed successfully, no warnings
    1 - Warnings found (unexpected or suspicious binaries)
    2 - Usage error or permission denied
"""

import argparse
import json
import os
import pwd
import grp
import stat
import subprocess
import sys
from collections import defaultdict


# Common expected SUID binaries on Linux systems
EXPECTED_SUID_BINARIES = {
    '/usr/bin/passwd',
    '/usr/bin/chfn',
    '/usr/bin/chsh',
    '/usr/bin/gpasswd',
    '/usr/bin/newgrp',
    '/usr/bin/su',
    '/usr/bin/sudo',
    '/usr/bin/mount',
    '/usr/bin/umount',
    '/usr/bin/pkexec',
    '/usr/bin/crontab',
    '/usr/bin/at',
    '/usr/bin/fusermount',
    '/usr/bin/fusermount3',
    '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
    '/usr/lib/openssh/ssh-keysign',
    '/usr/libexec/openssh/ssh-keysign',
    '/usr/lib/polkit-1/polkit-agent-helper-1',
    '/usr/libexec/polkit-agent-helper-1',
    '/usr/sbin/pam_timestamp_check',
    '/usr/sbin/unix_chkpwd',
    '/usr/lib/pt_chown',
    '/usr/bin/expiry',
    '/usr/bin/chage',
    '/usr/bin/wall',
    '/usr/bin/write',
    '/bin/passwd',
    '/bin/su',
    '/bin/mount',
    '/bin/umount',
    '/bin/ping',
    '/usr/bin/ping',
    '/usr/bin/traceroute',
    '/usr/sbin/traceroute',
}

# Common expected SGID binaries
EXPECTED_SGID_BINARIES = {
    '/usr/bin/wall',
    '/usr/bin/write',
    '/usr/bin/chage',
    '/usr/bin/expiry',
    '/usr/bin/crontab',
    '/usr/bin/ssh-agent',
    '/usr/bin/locate',
    '/usr/bin/mlocate',
    '/usr/sbin/postdrop',
    '/usr/sbin/postqueue',
    '/usr/bin/bsd-write',
    '/usr/bin/dotlockfile',
    '/usr/lib/utempter/utempter',
}

# Directories that should NOT have SUID/SGID binaries
SUSPICIOUS_DIRS = {
    '/tmp',
    '/var/tmp',
    '/dev/shm',
    '/home',
    '/root',
}


def get_file_info(filepath):
    """Get detailed information about a file."""
    try:
        st = os.stat(filepath)
        mode = st.st_mode

        # Get owner/group names
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)

        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)

        return {
            'path': filepath,
            'mode': oct(mode),
            'mode_str': stat.filemode(mode),
            'uid': st.st_uid,
            'gid': st.st_gid,
            'owner': owner,
            'group': group,
            'size': st.st_size,
            'mtime': st.st_mtime,
            'is_suid': bool(mode & stat.S_ISUID),
            'is_sgid': bool(mode & stat.S_ISGID),
            'is_sticky': bool(mode & stat.S_ISVTX),
        }
    except (OSError, IOError) as e:
        return {
            'path': filepath,
            'error': str(e),
        }


def find_suid_sgid_files(search_paths=None, exclude_paths=None):
    """Find all SUID and SGID files using find command."""
    if search_paths is None:
        search_paths = ['/']

    if exclude_paths is None:
        exclude_paths = ['/proc', '/sys', '/run', '/dev']

    files = []

    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue

        # Build find command
        cmd = ['find', search_path]

        # Add exclusions
        for exc in exclude_paths:
            cmd.extend(['-path', exc, '-prune', '-o'])

        # Find SUID or SGID files
        cmd.extend(['-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '-print'])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            for line in result.stdout.strip().split('\n'):
                if line and not line.startswith('find:'):
                    files.append(line)

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass

    return sorted(set(files))


def analyze_files(files, check_unexpected=True):
    """Analyze SUID/SGID files and categorize them."""
    results = {
        'suid_files': [],
        'sgid_files': [],
        'suid_sgid_files': [],
        'unexpected_suid': [],
        'unexpected_sgid': [],
        'suspicious_location': [],
        'root_owned_suid': [],
        'non_root_suid': [],
        'warnings': [],
        'by_owner': defaultdict(list),
        'by_directory': defaultdict(list),
    }

    for filepath in files:
        info = get_file_info(filepath)
        if 'error' in info:
            results['warnings'].append(f"Cannot stat {filepath}: {info['error']}")
            continue

        # Categorize by type
        if info['is_suid'] and info['is_sgid']:
            results['suid_sgid_files'].append(info)
        elif info['is_suid']:
            results['suid_files'].append(info)
        elif info['is_sgid']:
            results['sgid_files'].append(info)

        # Check ownership for SUID files
        if info['is_suid']:
            if info['uid'] == 0:
                results['root_owned_suid'].append(info)
            else:
                results['non_root_suid'].append(info)

        # Check for unexpected binaries
        if check_unexpected:
            if info['is_suid'] and filepath not in EXPECTED_SUID_BINARIES:
                results['unexpected_suid'].append(info)
            if info['is_sgid'] and filepath not in EXPECTED_SGID_BINARIES:
                results['unexpected_sgid'].append(info)

        # Check for suspicious locations
        for suspicious_dir in SUSPICIOUS_DIRS:
            if filepath.startswith(suspicious_dir + '/'):
                results['suspicious_location'].append(info)
                results['warnings'].append(
                    f"SUID/SGID file in suspicious location: {filepath}"
                )
                break

        # Organize by owner
        results['by_owner'][info['owner']].append(info)

        # Organize by directory
        directory = os.path.dirname(filepath)
        results['by_directory'][directory].append(info)

    # Convert defaultdicts to regular dicts for JSON serialization
    results['by_owner'] = dict(results['by_owner'])
    results['by_directory'] = dict(results['by_directory'])

    return results


def output_plain(results, verbose=False, warn_only=False):
    """Output results in plain text format."""
    total_suid = len(results['suid_files']) + len(results['suid_sgid_files'])
    total_sgid = len(results['sgid_files']) + len(results['suid_sgid_files'])

    if not warn_only:
        print(f"SUID/SGID Binary Audit")
        print(f"=" * 50)
        print(f"Total SUID files: {total_suid}")
        print(f"Total SGID files: {total_sgid}")
        print(f"Root-owned SUID: {len(results['root_owned_suid'])}")
        print(f"Non-root SUID: {len(results['non_root_suid'])}")
        print(f"Unexpected SUID: {len(results['unexpected_suid'])}")
        print(f"Unexpected SGID: {len(results['unexpected_sgid'])}")
        print(f"Suspicious locations: {len(results['suspicious_location'])}")
        print()

    # Always show warnings and suspicious files
    if results['suspicious_location']:
        print("SUSPICIOUS LOCATIONS (potential security issue):")
        for info in results['suspicious_location']:
            print(f"  [!!] {info['mode_str']} {info['owner']}:{info['group']} {info['path']}")
        print()

    if results['unexpected_suid'] and not warn_only:
        print("UNEXPECTED SUID FILES (review required):")
        for info in results['unexpected_suid'][:20]:  # Limit to 20
            print(f"  [--] {info['mode_str']} {info['owner']}:{info['group']} {info['path']}")
        if len(results['unexpected_suid']) > 20:
            print(f"  ... and {len(results['unexpected_suid']) - 20} more")
        print()

    if results['unexpected_sgid'] and not warn_only:
        print("UNEXPECTED SGID FILES (review required):")
        for info in results['unexpected_sgid'][:20]:
            print(f"  [--] {info['mode_str']} {info['owner']}:{info['group']} {info['path']}")
        if len(results['unexpected_sgid']) > 20:
            print(f"  ... and {len(results['unexpected_sgid']) - 20} more")
        print()

    if results['non_root_suid']:
        print("NON-ROOT SUID FILES (potential risk):")
        for info in results['non_root_suid']:
            print(f"  [!!] {info['mode_str']} {info['owner']}:{info['group']} {info['path']}")
        print()

    if verbose and not warn_only:
        print("ALL SUID FILES:")
        for info in results['suid_files'] + results['suid_sgid_files']:
            print(f"  {info['mode_str']} {info['owner']}:{info['group']} {info['path']}")
        print()

        print("ALL SGID FILES:")
        for info in results['sgid_files'] + results['suid_sgid_files']:
            print(f"  {info['mode_str']} {info['owner']}:{info['group']} {info['path']}")

    if results['warnings']:
        print()
        print("WARNINGS:")
        for warning in results['warnings']:
            print(f"  ! {warning}")


def output_json(results):
    """Output results in JSON format."""
    output = {
        'summary': {
            'total_suid': len(results['suid_files']) + len(results['suid_sgid_files']),
            'total_sgid': len(results['sgid_files']) + len(results['suid_sgid_files']),
            'root_owned_suid': len(results['root_owned_suid']),
            'non_root_suid': len(results['non_root_suid']),
            'unexpected_suid': len(results['unexpected_suid']),
            'unexpected_sgid': len(results['unexpected_sgid']),
            'suspicious_locations': len(results['suspicious_location']),
        },
        'suid_files': results['suid_files'],
        'sgid_files': results['sgid_files'],
        'suid_sgid_files': results['suid_sgid_files'],
        'unexpected_suid': results['unexpected_suid'],
        'unexpected_sgid': results['unexpected_sgid'],
        'suspicious_location': results['suspicious_location'],
        'non_root_suid': results['non_root_suid'],
        'warnings': results['warnings'],
        'by_owner': results['by_owner'],
        'by_directory': results['by_directory'],
    }
    print(json.dumps(output, indent=2, default=str))


def output_table(results, verbose=False, warn_only=False):
    """Output results in table format."""
    print("=" * 90)
    print("SUID/SGID BINARY AUDIT REPORT")
    print("=" * 90)

    if not warn_only:
        print()
        print(f"{'CATEGORY':<35} {'COUNT':>10}")
        print("-" * 45)
        print(f"{'Total SUID files':<35} {len(results['suid_files']) + len(results['suid_sgid_files']):>10}")
        print(f"{'Total SGID files':<35} {len(results['sgid_files']) + len(results['suid_sgid_files']):>10}")
        print(f"{'Root-owned SUID':<35} {len(results['root_owned_suid']):>10}")
        print(f"{'Non-root SUID':<35} {len(results['non_root_suid']):>10}")
        print(f"{'Unexpected SUID':<35} {len(results['unexpected_suid']):>10}")
        print(f"{'Unexpected SGID':<35} {len(results['unexpected_sgid']):>10}")
        print(f"{'Suspicious locations':<35} {len(results['suspicious_location']):>10}")

    if results['suspicious_location'] or results['non_root_suid']:
        print()
        print("SECURITY CONCERNS:")
        print("-" * 90)
        print(f"{'PERMISSIONS':<12} {'OWNER':<12} {'GROUP':<12} {'PATH':<50}")
        print("-" * 90)

        for info in results['suspicious_location'] + results['non_root_suid']:
            path = info['path'][:50] if len(info['path']) > 50 else info['path']
            print(f"{info['mode_str']:<12} {info['owner']:<12} {info['group']:<12} {path:<50}")

    if verbose and not warn_only:
        print()
        print("ALL SUID/SGID FILES:")
        print("-" * 90)
        all_files = results['suid_files'] + results['sgid_files'] + results['suid_sgid_files']
        for info in sorted(all_files, key=lambda x: x['path']):
            path = info['path'][:50] if len(info['path']) > 50 else info['path']
            print(f"{info['mode_str']:<12} {info['owner']:<12} {info['group']:<12} {path:<50}")

    print("=" * 90)


def main():
    parser = argparse.ArgumentParser(
        description='Audit SUID and SGID binaries on Linux systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Audit entire filesystem
  %(prog)s --path /usr            # Audit only /usr
  %(prog)s --format json          # JSON output for automation
  %(prog)s --verbose              # Show all files found
  %(prog)s --warn-only            # Only show security concerns
  %(prog)s --no-expected-check    # Don't flag unexpected binaries

Security recommendations:
  - Review all unexpected SUID/SGID binaries
  - Remove SUID/SGID from files in /tmp, /home, etc.
  - Minimize the number of SUID root binaries
  - Consider using capabilities instead of SUID

Exit codes:
  0 - Audit completed, no security concerns
  1 - Security concerns found (suspicious locations, non-root SUID)
  2 - Usage error or insufficient permissions
"""
    )

    parser.add_argument(
        '-p', '--path',
        action='append',
        dest='paths',
        help='Path(s) to search (default: /). Can be specified multiple times.'
    )

    parser.add_argument(
        '-e', '--exclude',
        action='append',
        dest='excludes',
        help='Path(s) to exclude. Can be specified multiple times.'
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
        help='Show all SUID/SGID files found'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show security concerns'
    )

    parser.add_argument(
        '--no-expected-check',
        action='store_true',
        help='Do not check against expected binary list'
    )

    args = parser.parse_args()

    # Set default paths
    search_paths = args.paths if args.paths else ['/']
    exclude_paths = args.excludes if args.excludes else ['/proc', '/sys', '/run', '/dev']

    # Check if we have permission to search
    for path in search_paths:
        if not os.path.exists(path):
            print(f"Error: Path does not exist: {path}", file=sys.stderr)
            sys.exit(2)

    # Find SUID/SGID files
    files = find_suid_sgid_files(search_paths, exclude_paths)

    if not files:
        if args.format == 'json':
            print(json.dumps({'summary': {'total_suid': 0, 'total_sgid': 0}, 'files': []}, indent=2))
        else:
            print("No SUID/SGID files found")
        sys.exit(0)

    # Analyze files
    results = analyze_files(files, check_unexpected=not args.no_expected_check)

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.verbose, args.warn_only)
    else:
        output_plain(results, args.verbose, args.warn_only)

    # Determine exit code
    if results['suspicious_location'] or results['non_root_suid']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
