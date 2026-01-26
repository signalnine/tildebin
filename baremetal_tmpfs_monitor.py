#!/usr/bin/env python3
"""
Monitor tmpfs filesystem usage on baremetal systems.

Tracks tmpfs mounts including /dev/shm, /run, /tmp, and custom tmpfs
filesystems. Detects high usage that could lead to silent OOM conditions,
since tmpfs exhaustion doesn't trigger standard disk space alerts.

Exit codes:
    0 - All tmpfs filesystems healthy (usage below thresholds)
    1 - Warning or critical usage detected on one or more tmpfs
    2 - Usage error or missing dependencies
"""

import argparse
import json
import os
import sys


def read_file(path):
    """Read file contents, return None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError):
        return None


def get_tmpfs_mounts():
    """
    Get all tmpfs mount points from /proc/mounts.

    Returns:
        List of dicts with mount info: mountpoint, device, options
    """
    mounts = []
    content = read_file('/proc/mounts')

    if not content:
        return mounts

    for line in content.strip().split('\n'):
        parts = line.split()
        if len(parts) >= 4:
            device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]

            if fstype == 'tmpfs':
                mounts.append({
                    'device': device,
                    'mountpoint': mountpoint,
                    'options': options
                })

    return mounts


def get_tmpfs_usage(mountpoint):
    """
    Get usage statistics for a tmpfs mountpoint using statvfs.

    Returns:
        Dict with size_bytes, used_bytes, avail_bytes, used_percent, inode stats
        Returns None if mountpoint is inaccessible
    """
    try:
        stat = os.statvfs(mountpoint)

        # Block-based stats
        block_size = stat.f_frsize
        total_blocks = stat.f_blocks
        free_blocks = stat.f_bfree
        avail_blocks = stat.f_bavail

        total_bytes = total_blocks * block_size
        free_bytes = free_blocks * block_size
        avail_bytes = avail_blocks * block_size
        used_bytes = total_bytes - free_bytes

        used_percent = (used_bytes / total_bytes * 100) if total_bytes > 0 else 0

        # Inode stats
        total_inodes = stat.f_files
        free_inodes = stat.f_ffree
        used_inodes = total_inodes - free_inodes
        inode_percent = (used_inodes / total_inodes * 100) if total_inodes > 0 else 0

        return {
            'size_bytes': total_bytes,
            'used_bytes': used_bytes,
            'avail_bytes': avail_bytes,
            'used_percent': used_percent,
            'total_inodes': total_inodes,
            'used_inodes': used_inodes,
            'free_inodes': free_inodes,
            'inode_percent': inode_percent
        }

    except (OSError, IOError):
        return None


def format_bytes(bytes_val):
    """Format bytes to human-readable string."""
    for unit, divisor in [('T', 1024**4), ('G', 1024**3),
                          ('M', 1024**2), ('K', 1024)]:
        if bytes_val >= divisor:
            return f"{bytes_val / divisor:.1f}{unit}"
    return f"{bytes_val}B"


def get_status(used_percent, warn_threshold, crit_threshold):
    """Determine status based on usage percentage."""
    if used_percent >= crit_threshold:
        return 'CRITICAL'
    elif used_percent >= warn_threshold:
        return 'WARNING'
    return 'OK'


def analyze_tmpfs(mounts, warn_threshold, crit_threshold):
    """
    Analyze all tmpfs mounts and return status information.

    Args:
        mounts: List of mount dicts from get_tmpfs_mounts()
        warn_threshold: Warning threshold percentage
        crit_threshold: Critical threshold percentage

    Returns:
        List of dicts with full analysis for each mount
    """
    results = []

    for mount in mounts:
        mountpoint = mount['mountpoint']
        usage = get_tmpfs_usage(mountpoint)

        if usage is None:
            results.append({
                'mountpoint': mountpoint,
                'device': mount['device'],
                'accessible': False,
                'status': 'UNKNOWN'
            })
            continue

        space_status = get_status(usage['used_percent'], warn_threshold, crit_threshold)
        inode_status = get_status(usage['inode_percent'], warn_threshold, crit_threshold)

        # Overall status is worst of space or inode
        if space_status == 'CRITICAL' or inode_status == 'CRITICAL':
            overall_status = 'CRITICAL'
        elif space_status == 'WARNING' or inode_status == 'WARNING':
            overall_status = 'WARNING'
        else:
            overall_status = 'OK'

        results.append({
            'mountpoint': mountpoint,
            'device': mount['device'],
            'options': mount['options'],
            'accessible': True,
            'size_bytes': usage['size_bytes'],
            'used_bytes': usage['used_bytes'],
            'avail_bytes': usage['avail_bytes'],
            'used_percent': usage['used_percent'],
            'total_inodes': usage['total_inodes'],
            'used_inodes': usage['used_inodes'],
            'free_inodes': usage['free_inodes'],
            'inode_percent': usage['inode_percent'],
            'space_status': space_status,
            'inode_status': inode_status,
            'status': overall_status
        })

    return results


def output_plain(results, warn_only=False, verbose=False):
    """Output results in plain text format."""
    lines = []

    filtered = [r for r in results if not warn_only or r['status'] != 'OK']

    if not filtered:
        if warn_only:
            return "No tmpfs issues detected."
        return "No tmpfs filesystems found."

    for r in filtered:
        if not r['accessible']:
            lines.append(f"{r['mountpoint']} INACCESSIBLE")
            continue

        status_str = r['status']
        size_str = format_bytes(r['size_bytes'])
        used_str = format_bytes(r['used_bytes'])

        lines.append(f"{r['mountpoint']} {status_str} "
                     f"{used_str}/{size_str} ({r['used_percent']:.1f}%)")

        if verbose:
            lines.append(f"  Device: {r['device']}")
            lines.append(f"  Inodes: {r['used_inodes']}/{r['total_inodes']} "
                         f"({r['inode_percent']:.1f}%)")
            if r['space_status'] != 'OK':
                lines.append(f"  Space status: {r['space_status']}")
            if r['inode_status'] != 'OK':
                lines.append(f"  Inode status: {r['inode_status']}")

    return '\n'.join(lines)


def output_json(results, warn_only=False):
    """Output results in JSON format."""
    filtered = results if not warn_only else [r for r in results if r['status'] != 'OK']

    output = {
        'tmpfs_count': len(results),
        'issues_count': sum(1 for r in results if r['status'] != 'OK'),
        'filesystems': filtered
    }

    return json.dumps(output, indent=2)


def output_table(results, warn_only=False):
    """Output results in table format."""
    lines = []

    filtered = [r for r in results if not warn_only or r['status'] != 'OK']

    if not filtered:
        if warn_only:
            return "No tmpfs issues detected."
        return "No tmpfs filesystems found."

    lines.append(f"{'Mountpoint':<25} {'Size':>10} {'Used':>10} {'Use%':>7} "
                 f"{'Inode%':>7} {'Status':<10}")
    lines.append("-" * 75)

    for r in filtered:
        if not r['accessible']:
            lines.append(f"{r['mountpoint']:<25} {'N/A':>10} {'N/A':>10} "
                         f"{'N/A':>7} {'N/A':>7} {'UNKNOWN':<10}")
            continue

        size_str = format_bytes(r['size_bytes'])
        used_str = format_bytes(r['used_bytes'])

        lines.append(f"{r['mountpoint']:<25} {size_str:>10} {used_str:>10} "
                     f"{r['used_percent']:>6.1f}% {r['inode_percent']:>6.1f}% "
                     f"{r['status']:<10}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor tmpfs filesystem usage on baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all tmpfs filesystems
  %(prog)s

  # Show only warnings and critical issues
  %(prog)s --warn-only

  # Output in JSON format for monitoring systems
  %(prog)s --format json

  # Custom thresholds (warn at 70%%, critical at 85%%)
  %(prog)s --warn 70 --critical 85

  # Monitor specific mountpoint
  %(prog)s --mountpoint /dev/shm

  # Verbose output with inode details
  %(prog)s --verbose

Exit codes:
  0 - All tmpfs filesystems healthy
  1 - Warning or critical usage detected
  2 - Usage error or missing dependencies

Notes:
  - tmpfs exhaustion can cause silent OOM conditions
  - /dev/shm is commonly used for shared memory (databases, IPC)
  - /run and /tmp are often tmpfs on modern Linux systems
  - Both space and inode usage are monitored
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show tmpfs with warnings or critical status'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed information including inodes and options'
    )
    parser.add_argument(
        '--warn',
        type=float,
        default=80.0,
        help='Warning threshold percentage (default: 80)'
    )
    parser.add_argument(
        '--critical',
        type=float,
        default=90.0,
        help='Critical threshold percentage (default: 90)'
    )
    parser.add_argument(
        '--mountpoint', '-m',
        help='Monitor only this specific tmpfs mountpoint'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn < 0 or args.warn > 100:
        print("Error: --warn must be between 0 and 100", file=sys.stderr)
        return 2

    if args.critical < 0 or args.critical > 100:
        print("Error: --critical must be between 0 and 100", file=sys.stderr)
        return 2

    if args.warn >= args.critical:
        print("Error: --warn must be less than --critical", file=sys.stderr)
        return 2

    # Get tmpfs mounts
    mounts = get_tmpfs_mounts()

    if not mounts:
        print("No tmpfs filesystems found", file=sys.stderr)
        return 0

    # Filter to specific mountpoint if requested
    if args.mountpoint:
        mounts = [m for m in mounts if m['mountpoint'] == args.mountpoint]
        if not mounts:
            print(f"Error: Mountpoint {args.mountpoint} not found or not tmpfs",
                  file=sys.stderr)
            return 2

    # Analyze tmpfs usage
    results = analyze_tmpfs(mounts, args.warn, args.critical)

    # Output results
    if args.format == 'json':
        output = output_json(results, args.warn_only)
    elif args.format == 'table':
        output = output_table(results, args.warn_only)
    else:
        output = output_plain(results, args.warn_only, args.verbose)

    print(output)

    # Determine exit code
    has_issues = any(r['status'] != 'OK' for r in results)
    return 1 if has_issues else 0


if __name__ == '__main__':
    sys.exit(main())
