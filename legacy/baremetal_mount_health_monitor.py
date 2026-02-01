#!/usr/bin/env python3
"""
Monitor mounted filesystem health and detect hung or problematic mounts.

This script monitors all mounted filesystems for issues including:
- Hung/unresponsive mounts (NFS, CIFS, FUSE that stop responding)
- Stale NFS file handles
- Mount propagation issues
- Bind mount consistency
- Mount option validation
- Filesystem-specific health indicators

Detecting hung mounts is critical in large-scale environments where a single
unresponsive NFS server can cause processes to hang in D-state, potentially
cascading into system-wide failures if critical paths become inaccessible.

Exit codes:
    0 - All mounts healthy
    1 - Mount issues detected (hung, stale, or misconfigured)
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import json
import os
import signal
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError


class TimeoutException(Exception):
    """Raised when a mount access times out."""
    pass


def timeout_handler(signum, frame):
    """Signal handler for mount access timeout."""
    raise TimeoutException("Mount access timed out")


def parse_proc_mounts():
    """Parse /proc/mounts to get current mount information.

    Returns:
        list: List of mount dictionaries
    """
    mounts = []
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 6:
                    device, mountpoint, fstype, options, dump, fsck = parts[:6]
                    mounts.append({
                        'device': device,
                        'mountpoint': mountpoint,
                        'fstype': fstype,
                        'options': options.split(','),
                        'dump': int(dump),
                        'fsck': int(fsck)
                    })
        return mounts
    except FileNotFoundError:
        print("Error: /proc/mounts not found", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading /proc/mounts: {e}", file=sys.stderr)
        sys.exit(2)


def parse_proc_mountinfo():
    """Parse /proc/self/mountinfo for detailed mount information.

    Returns:
        dict: Mountpoint to mountinfo mapping
    """
    mountinfo = {}
    try:
        with open('/proc/self/mountinfo', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 10:
                    # Format: id parent_id major:minor root mountpoint options ... - fstype source super_options
                    mount_id = int(parts[0])
                    parent_id = int(parts[1])
                    major_minor = parts[2]
                    root = parts[3]
                    mountpoint = parts[4]
                    mount_options = parts[5].split(',')

                    # Find the separator '-' and parse fstype/source
                    sep_idx = parts.index('-') if '-' in parts else -1
                    if sep_idx > 0 and len(parts) > sep_idx + 2:
                        fstype = parts[sep_idx + 1]
                        source = parts[sep_idx + 2]
                        super_options = parts[sep_idx + 3].split(',') if len(parts) > sep_idx + 3 else []
                    else:
                        fstype = ''
                        source = ''
                        super_options = []

                    mountinfo[mountpoint] = {
                        'mount_id': mount_id,
                        'parent_id': parent_id,
                        'major_minor': major_minor,
                        'root': root,
                        'mount_options': mount_options,
                        'fstype': fstype,
                        'source': source,
                        'super_options': super_options
                    }
        return mountinfo
    except Exception:
        return {}


def check_mount_accessible(mountpoint, timeout_secs=5):
    """Check if a mountpoint is accessible (not hung).

    Uses stat() with a timeout to detect hung mounts.

    Args:
        mountpoint: Path to the mountpoint
        timeout_secs: Timeout in seconds

    Returns:
        tuple: (accessible, error_message, is_hung)
        - accessible: True if mount responded (even with permission error)
        - error_message: Error description if any
        - is_hung: True only if mount timed out (didn't respond)
    """
    def stat_mount():
        try:
            os.stat(mountpoint)
            return True, None, False
        except PermissionError:
            # Permission denied means the mount IS responding, just can't access
            return True, "Permission denied (mount is responding)", False
        except OSError as e:
            # Other OS errors - mount responded but has issues
            return False, str(e), False

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(stat_mount)
            try:
                result = future.result(timeout=timeout_secs)
                return result
            except FuturesTimeoutError:
                return False, f"Mount hung (no response in {timeout_secs}s)", True
    except Exception as e:
        return False, str(e), False


def check_stale_nfs(mountpoint, options):
    """Check for stale NFS file handles.

    Args:
        mountpoint: NFS mountpoint path
        options: Mount options list

    Returns:
        tuple: (is_stale, message)
    """
    # Check if this is a soft mount (soft mounts can report stale handles)
    is_soft = 'soft' in options

    try:
        # Try to list directory - this will fail with ESTALE for stale handles
        os.listdir(mountpoint)
        return False, None
    except OSError as e:
        if e.errno == 116:  # ESTALE - Stale file handle
            return True, "Stale NFS file handle detected"
        elif e.errno == 5:  # EIO - I/O error (common with NFS issues)
            return True, "I/O error (possible NFS server issue)"
        elif e.errno == 2:  # ENOENT
            return False, None  # Mount point exists but empty
        else:
            return False, None
    except Exception:
        return False, None


def check_bind_mount_consistency(mount, mountinfo):
    """Check bind mount for consistency with source.

    Args:
        mount: Mount dictionary
        mountinfo: Mountinfo dictionary

    Returns:
        list: List of issues found
    """
    issues = []
    mountpoint = mount['mountpoint']

    if mountpoint not in mountinfo:
        return issues

    info = mountinfo[mountpoint]

    # Check if bind mount source still exists
    if 'bind' in mount['options']:
        source = mount['device']
        if not os.path.exists(source):
            issues.append(f"Bind mount source '{source}' does not exist")

    # Check for recursive vs non-recursive bind consistency
    if info['root'] != '/':
        # This is a bind mount of a subdirectory
        full_source = os.path.join(info['source'], info['root'].lstrip('/'))
        if not os.path.exists(full_source):
            issues.append(f"Bind mount source path no longer exists")

    return issues


def check_mount_options(mount, expected_options):
    """Check mount options against expected configuration.

    Args:
        mount: Mount dictionary
        expected_options: Dict of fstype -> required options

    Returns:
        list: List of option issues
    """
    issues = []
    fstype = mount['fstype']
    options = mount['options']

    if fstype in expected_options:
        for required in expected_options[fstype]:
            if required not in options:
                issues.append(f"Missing recommended option '{required}' for {fstype}")

    # Check for dangerous options
    dangerous = {
        'nobarrier': 'Data integrity risk',
        'data=writeback': 'Crash recovery risk for ext3/4',
        'async': 'Data loss risk on crash (NFS)'
    }

    for opt, risk in dangerous.items():
        if opt in options:
            issues.append(f"Option '{opt}' present: {risk}")

    return issues


def check_readonly_issues(mount):
    """Check for filesystem mounted read-only unexpectedly.

    Args:
        mount: Mount dictionary

    Returns:
        tuple: (is_readonly_issue, message)
    """
    options = mount['options']
    fstype = mount['fstype']

    # Skip pseudo filesystems that are always read-only
    pseudo_fs = {'proc', 'sysfs', 'devpts', 'cgroup', 'cgroup2', 'securityfs',
                 'pstore', 'debugfs', 'tracefs', 'configfs', 'hugetlbfs',
                 'mqueue', 'binfmt_misc', 'fusectl', 'efivarfs', 'squashfs'}

    if fstype in pseudo_fs:
        return False, None

    # Check if mounted ro but appears to be a writable filesystem
    if 'ro' in options:
        # These are typically writable filesystems
        writable_fs = {'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'zfs',
                       'nfs', 'nfs4', 'cifs', 'tmpfs'}
        if fstype in writable_fs:
            # Could be intentional, but flag for review
            return True, f"{fstype} mounted read-only (may indicate filesystem errors)"

    return False, None


def analyze_mounts(mounts, mountinfo, timeout_secs, skip_virtual, check_options):
    """Analyze all mounts for issues.

    Args:
        mounts: List of mount dictionaries
        mountinfo: Mountinfo dictionary
        timeout_secs: Timeout for accessibility checks
        skip_virtual: Skip virtual/pseudo filesystems
        check_options: Check mount options

    Returns:
        dict: Analysis results
    """
    results = {
        'total_mounts': len(mounts),
        'checked': 0,
        'healthy': 0,
        'issues': [],
        'hung_mounts': [],
        'stale_mounts': [],
        'readonly_issues': [],
        'option_issues': [],
        'bind_issues': [],
        'mounts': []
    }

    # Virtual/pseudo filesystems to skip
    virtual_fs = {'proc', 'sysfs', 'devpts', 'cgroup', 'cgroup2', 'securityfs',
                  'pstore', 'debugfs', 'tracefs', 'configfs', 'hugetlbfs',
                  'mqueue', 'binfmt_misc', 'fusectl', 'efivarfs', 'autofs',
                  'devtmpfs', 'rpc_pipefs', 'nfsd', 'overlay'}

    # Expected options for common filesystem types
    expected_options = {
        'ext4': [],  # defaults are usually fine
        'xfs': [],
        'nfs': [],
        'nfs4': []
    }

    for mount in mounts:
        fstype = mount['fstype']
        mountpoint = mount['mountpoint']

        # Skip virtual filesystems if requested
        if skip_virtual and fstype in virtual_fs:
            continue

        results['checked'] += 1
        mount_result = {
            'mountpoint': mountpoint,
            'device': mount['device'],
            'fstype': fstype,
            'options': mount['options'],
            'status': 'healthy',
            'issues': []
        }

        # Check accessibility (hung mount detection)
        # Skip certain paths that may block normally
        skip_paths = {'/proc', '/sys', '/dev'}
        should_check_access = not any(mountpoint.startswith(p) for p in skip_paths)

        if should_check_access and fstype not in virtual_fs:
            accessible, error, is_hung = check_mount_accessible(mountpoint, timeout_secs)
            if is_hung:
                # Mount timed out - truly hung
                mount_result['status'] = 'hung'
                mount_result['issues'].append(f"Mount not responding: {error}")
                results['hung_mounts'].append(mountpoint)
                results['issues'].append({
                    'severity': 'CRITICAL',
                    'mountpoint': mountpoint,
                    'type': 'hung',
                    'message': f"Mount '{mountpoint}' is hung or unresponsive: {error}"
                })
            elif not accessible and error:
                # Mount responded but has errors (not hung, just broken)
                mount_result['issues'].append(f"Mount error: {error}")

        # Check for stale NFS handles
        if fstype in ('nfs', 'nfs4') and mount_result['status'] != 'hung':
            is_stale, stale_msg = check_stale_nfs(mountpoint, mount['options'])
            if is_stale:
                mount_result['status'] = 'stale'
                mount_result['issues'].append(stale_msg)
                results['stale_mounts'].append(mountpoint)
                results['issues'].append({
                    'severity': 'CRITICAL',
                    'mountpoint': mountpoint,
                    'type': 'stale',
                    'message': f"NFS mount '{mountpoint}': {stale_msg}"
                })

        # Check for read-only issues
        is_ro_issue, ro_msg = check_readonly_issues(mount)
        if is_ro_issue:
            mount_result['issues'].append(ro_msg)
            results['readonly_issues'].append(mountpoint)
            results['issues'].append({
                'severity': 'WARNING',
                'mountpoint': mountpoint,
                'type': 'readonly',
                'message': f"Mount '{mountpoint}': {ro_msg}"
            })

        # Check bind mount consistency
        if 'bind' in mount['options'] or (mountpoint in mountinfo and mountinfo[mountpoint]['root'] != '/'):
            bind_issues = check_bind_mount_consistency(mount, mountinfo)
            if bind_issues:
                mount_result['issues'].extend(bind_issues)
                results['bind_issues'].append(mountpoint)
                for issue in bind_issues:
                    results['issues'].append({
                        'severity': 'WARNING',
                        'mountpoint': mountpoint,
                        'type': 'bind',
                        'message': f"Bind mount '{mountpoint}': {issue}"
                    })

        # Check mount options
        if check_options:
            opt_issues = check_mount_options(mount, expected_options)
            if opt_issues:
                mount_result['issues'].extend(opt_issues)
                results['option_issues'].append(mountpoint)
                for issue in opt_issues:
                    results['issues'].append({
                        'severity': 'INFO',
                        'mountpoint': mountpoint,
                        'type': 'options',
                        'message': f"Mount '{mountpoint}': {issue}"
                    })

        if mount_result['status'] == 'healthy' and not mount_result['issues']:
            results['healthy'] += 1
        elif mount_result['status'] == 'healthy' and mount_result['issues']:
            mount_result['status'] = 'warning'

        results['mounts'].append(mount_result)

    return results


def output_plain(results, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only or results['issues']:
        print("Mount Health Summary:")
        print(f"  Total mounts:    {results['total_mounts']}")
        print(f"  Checked:         {results['checked']}")
        print(f"  Healthy:         {results['healthy']}")
        print(f"  Hung mounts:     {len(results['hung_mounts'])}")
        print(f"  Stale mounts:    {len(results['stale_mounts'])}")
        print(f"  Read-only issues: {len(results['readonly_issues'])}")
        print()

        if verbose:
            print("Mount Details:")
            for mount in results['mounts']:
                status_icon = {
                    'healthy': '[OK]',
                    'warning': '[WARN]',
                    'hung': '[HUNG]',
                    'stale': '[STALE]'
                }.get(mount['status'], '[??]')

                print(f"  {status_icon} {mount['mountpoint']}")
                print(f"       Device: {mount['device']}")
                print(f"       Type:   {mount['fstype']}")
                if mount['issues']:
                    for issue in mount['issues']:
                        print(f"       Issue:  {issue}")
            print()

    if results['issues']:
        print("Detected Issues:")
        for issue in results['issues']:
            severity = issue['severity']
            if warn_only and severity == 'INFO':
                continue
            print(f"  [{severity}] {issue['message']}")
    elif not warn_only:
        print("[OK] All mounts healthy")


def output_json(results, verbose):
    """Output results in JSON format."""
    output = {
        'summary': {
            'total_mounts': results['total_mounts'],
            'checked': results['checked'],
            'healthy': results['healthy'],
            'hung_count': len(results['hung_mounts']),
            'stale_count': len(results['stale_mounts']),
            'readonly_issues': len(results['readonly_issues']),
            'bind_issues': len(results['bind_issues']),
            'option_issues': len(results['option_issues'])
        },
        'issues': results['issues'],
        'has_critical': any(i['severity'] == 'CRITICAL' for i in results['issues']),
        'has_issues': len([i for i in results['issues'] if i['severity'] != 'INFO']) > 0
    }

    if results['hung_mounts']:
        output['hung_mounts'] = results['hung_mounts']
    if results['stale_mounts']:
        output['stale_mounts'] = results['stale_mounts']

    if verbose:
        output['mounts'] = results['mounts']

    print(json.dumps(output, indent=2))


def output_table(results, verbose, warn_only):
    """Output results in table format."""
    if not warn_only or results['issues']:
        print("=" * 80)
        print("MOUNT HEALTH MONITOR")
        print("=" * 80)
        print(f"{'Total Mounts:':<20} {results['total_mounts']}")
        print(f"{'Checked:':<20} {results['checked']}")
        print(f"{'Healthy:':<20} {results['healthy']}")
        print(f"{'Hung:':<20} {len(results['hung_mounts'])}")
        print(f"{'Stale:':<20} {len(results['stale_mounts'])}")
        print("-" * 80)
        print()

        if verbose:
            print("MOUNT STATUS")
            print("-" * 80)
            print(f"{'Status':<8} {'Mountpoint':<35} {'Type':<10} {'Device':<25}")
            print("-" * 80)
            for mount in results['mounts']:
                status = mount['status'].upper()[:6]
                mp = mount['mountpoint'][:34]
                fstype = mount['fstype'][:9]
                device = mount['device'][:24]
                print(f"{status:<8} {mp:<35} {fstype:<10} {device:<25}")
            print("-" * 80)
            print()

    if results['issues']:
        print("ISSUES DETECTED")
        print("=" * 80)
        for issue in results['issues']:
            severity = issue['severity']
            if warn_only and severity == 'INFO':
                continue
            print(f"[{severity}] {issue['message']}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor mounted filesystem health and detect issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all mounts with default settings
  %(prog)s --format json            # JSON output for monitoring tools
  %(prog)s --verbose                # Show detailed mount information
  %(prog)s --timeout 10             # Increase timeout for slow NFS mounts
  %(prog)s --skip-virtual           # Skip pseudo filesystems (proc, sys, etc.)
  %(prog)s --warn-only              # Only show if issues detected

What This Tool Detects:
  - Hung mounts: NFS/CIFS/FUSE mounts that stop responding (processes go D-state)
  - Stale NFS handles: ESTALE errors indicating server-side changes
  - Read-only remounts: Filesystems remounted ro due to errors
  - Bind mount issues: Missing source paths, inconsistent configurations
  - Mount option warnings: Dangerous options that risk data integrity

Exit codes:
  0 - All mounts healthy
  1 - Mount issues detected
  2 - Usage error or missing dependencies
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed mount information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        metavar='SECS',
        help='Timeout in seconds for mount accessibility checks (default: %(default)s)'
    )

    parser.add_argument(
        '--skip-virtual',
        action='store_true',
        help='Skip virtual/pseudo filesystems (proc, sysfs, cgroup, etc.)'
    )

    parser.add_argument(
        '--check-options',
        action='store_true',
        help='Check mount options for potential issues'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.timeout < 1:
        print("Error: --timeout must be at least 1 second", file=sys.stderr)
        sys.exit(2)

    if args.timeout > 60:
        print("Error: --timeout cannot exceed 60 seconds", file=sys.stderr)
        sys.exit(2)

    # Read mount information
    mounts = parse_proc_mounts()
    mountinfo = parse_proc_mountinfo()

    # Analyze mounts
    results = analyze_mounts(
        mounts,
        mountinfo,
        args.timeout,
        args.skip_virtual,
        args.check_options
    )

    # Output results
    if args.format == 'json':
        output_json(results, args.verbose)
    elif args.format == 'table':
        output_table(results, args.verbose, args.warn_only)
    else:  # plain
        output_plain(results, args.verbose, args.warn_only)

    # Determine exit code
    has_critical = any(i['severity'] == 'CRITICAL' for i in results['issues'])
    has_warning = any(i['severity'] == 'WARNING' for i in results['issues'])

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
