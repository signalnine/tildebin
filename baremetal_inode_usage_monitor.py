#!/usr/bin/env python3
"""
Monitor inode usage across filesystems to detect exhaustion before it causes issues.

In large-scale baremetal environments, inode exhaustion is a common but overlooked
problem. Filesystems can run out of inodes before running out of disk space,
especially with workloads that create many small files (mail servers, web caches,
container image layers, package repositories).

This script monitors:
- Current inode usage percentage per filesystem
- Filesystems approaching inode exhaustion thresholds
- Inode-to-space ratio anomalies (high inode usage with low space usage)
- Filesystems that cannot grow their inode tables (ext4 vs XFS differences)

Exit codes:
    0 - All filesystems have healthy inode usage
    1 - Warnings or critical inode usage detected
    2 - Usage error or missing dependency

Examples:
    # Check all filesystems
    baremetal_inode_usage_monitor.py

    # JSON output for monitoring systems
    baremetal_inode_usage_monitor.py --format json

    # Only show filesystems with warnings
    baremetal_inode_usage_monitor.py --warn-only

    # Set custom warning threshold (default: 80%)
    baremetal_inode_usage_monitor.py --warn-threshold 70

    # Set custom critical threshold (default: 95%)
    baremetal_inode_usage_monitor.py --critical-threshold 90
"""

import argparse
import sys
import os
import subprocess
import json
from datetime import datetime


def run_command(cmd):
    """Execute shell command and return result."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}"
    except Exception as e:
        return -1, "", str(e)


def get_inode_info():
    """Get inode usage information from df -i."""
    filesystems = []

    returncode, stdout, stderr = run_command(['df', '-i', '-P'])
    if returncode != 0:
        return filesystems

    lines = stdout.strip().split('\n')
    if len(lines) < 2:
        return filesystems

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue

        device = parts[0]
        mount_point = parts[5]

        # Skip pseudo-filesystems and read-only system mounts
        if device in ['tmpfs', 'devtmpfs', 'none', 'overlay']:
            continue
        if mount_point.startswith('/sys') or mount_point.startswith('/proc'):
            continue
        if mount_point.startswith('/run') and 'snapd' not in mount_point:
            # Keep /run/snapd mounts but skip others
            if mount_point == '/run':
                continue
        if mount_point.startswith('/dev') and mount_point != '/dev':
            continue
        # Skip snap mounts (squashfs, always 100% full by design)
        if mount_point.startswith('/snap/'):
            continue

        try:
            inodes_total = int(parts[1]) if parts[1] != '-' else 0
            inodes_used = int(parts[2]) if parts[2] != '-' else 0
            inodes_free = int(parts[3]) if parts[3] != '-' else 0
            use_percent_str = parts[4].rstrip('%')
            use_percent = int(use_percent_str) if use_percent_str != '-' else 0
        except (ValueError, IndexError):
            continue

        # Skip filesystems with no inodes (some virtual filesystems)
        if inodes_total == 0:
            continue

        filesystems.append({
            'device': device,
            'mount_point': mount_point,
            'inodes_total': inodes_total,
            'inodes_used': inodes_used,
            'inodes_free': inodes_free,
            'use_percent': use_percent,
        })

    return filesystems


def get_disk_usage(mount_point):
    """Get disk space usage for a mount point."""
    returncode, stdout, stderr = run_command(['df', '-B1', '-P', mount_point])
    if returncode != 0:
        return None

    lines = stdout.strip().split('\n')
    if len(lines) < 2:
        return None

    parts = lines[1].split()
    if len(parts) < 5:
        return None

    try:
        size_bytes = int(parts[1])
        used_bytes = int(parts[2])
        avail_bytes = int(parts[3])
        use_percent_str = parts[4].rstrip('%')
        use_percent = int(use_percent_str) if use_percent_str.isdigit() else 0
    except (ValueError, IndexError):
        return None

    return {
        'size_bytes': size_bytes,
        'used_bytes': used_bytes,
        'available_bytes': avail_bytes,
        'use_percent': use_percent,
    }


def get_filesystem_type(mount_point):
    """Get the filesystem type for a mount point."""
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == mount_point:
                    return parts[2]
    except IOError:
        pass
    return 'unknown'


def analyze_inode_usage(fs_info, disk_info, fs_type, warn_threshold, critical_threshold):
    """Analyze inode usage and return issues."""
    issues = []
    use_percent = fs_info['use_percent']

    # Check against thresholds
    if use_percent >= critical_threshold:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'inode_exhaustion',
            'message': f"Inode usage at {use_percent}% (critical threshold: {critical_threshold}%)"
        })
    elif use_percent >= warn_threshold:
        issues.append({
            'severity': 'WARNING',
            'type': 'inode_usage',
            'message': f"Inode usage at {use_percent}% (warning threshold: {warn_threshold}%)"
        })

    # Check for inode/space imbalance
    if disk_info and use_percent > 0:
        space_percent = disk_info.get('use_percent', 0)

        # High inode usage with low space usage indicates many small files
        if use_percent > 50 and space_percent < 20:
            ratio = use_percent / max(space_percent, 1)
            if ratio > 5:
                issues.append({
                    'severity': 'INFO',
                    'type': 'inode_space_imbalance',
                    'message': f"Inode usage ({use_percent}%) much higher than space usage ({space_percent}%) - many small files"
                })

        # Low inode usage with high space usage indicates large files
        if space_percent > 80 and use_percent < 20:
            issues.append({
                'severity': 'INFO',
                'type': 'large_files',
                'message': f"Space usage ({space_percent}%) much higher than inode usage ({use_percent}%) - large files present"
            })

    # Filesystem-specific warnings
    if fs_type == 'ext4':
        # ext4 has fixed inode count at creation time
        if use_percent >= 70:
            issues.append({
                'severity': 'INFO',
                'type': 'fs_limitation',
                'message': "ext4 filesystem - inode count is fixed at creation time"
            })

    return issues


def format_count(count):
    """Format large numbers with suffixes."""
    if count >= 1_000_000_000:
        return f"{count / 1_000_000_000:.1f}B"
    elif count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    elif count >= 1_000:
        return f"{count / 1_000:.1f}K"
    else:
        return str(count)


def output_plain(results, verbose, warn_only):
    """Plain text output format."""
    has_issues = False

    for result in results:
        mount_point = result['mount_point']
        use_percent = result['use_percent']
        status = result['status']

        # Skip healthy filesystems in warn-only mode
        if warn_only and status == 'healthy':
            continue

        status_symbol = {
            'healthy': '[OK]',
            'info': '[INFO]',
            'warning': '[WARN]',
            'critical': '[CRIT]',
        }.get(status, '[??]')

        print(f"{status_symbol} {mount_point}")
        print(f"    Inodes: {use_percent}% used ({format_count(result['inodes_used'])}/{format_count(result['inodes_total'])})")

        if status in ['critical', 'warning']:
            has_issues = True

        if verbose or status != 'healthy':
            if result.get('disk_usage'):
                disk = result['disk_usage']
                print(f"    Space:  {disk['use_percent']}% used")

            print(f"    Type:   {result.get('fs_type', 'unknown')}")

        for issue in result.get('issues', []):
            if warn_only and issue['severity'] == 'INFO':
                continue
            print(f"    [{issue['severity']}] {issue['message']}")

    return has_issues


def output_json(results):
    """JSON output format."""
    summary = {
        'total': len(results),
        'healthy': sum(1 for r in results if r['status'] == 'healthy'),
        'warning': sum(1 for r in results if r['status'] == 'warning'),
        'critical': sum(1 for r in results if r['status'] == 'critical'),
        'info': sum(1 for r in results if r['status'] == 'info'),
    }

    output = {
        'timestamp': datetime.now().isoformat(),
        'filesystems': results,
        'summary': summary,
    }

    print(json.dumps(output, indent=2, default=str))

    return summary['critical'] > 0 or summary['warning'] > 0


def output_table(results, verbose, warn_only):
    """Tabular output format."""
    if warn_only:
        results = [r for r in results if r['status'] != 'healthy']

    if not results:
        print("No inode usage issues detected")
        return False

    print(f"{'Mount Point':<30} {'Inodes Used':<15} {'Inodes Free':<15} {'%Used':<8} {'Status':<10}")
    print("-" * 85)

    has_issues = False
    for result in results:
        mount = result['mount_point'][:29]
        used = format_count(result['inodes_used'])
        free = format_count(result['inodes_free'])
        pct = f"{result['use_percent']}%"
        status = result['status'].upper()

        print(f"{mount:<30} {used:<15} {free:<15} {pct:<8} {status:<10}")

        if result['status'] in ['critical', 'warning']:
            has_issues = True

    print("-" * 85)

    # Summary
    critical = sum(1 for r in results if r['status'] == 'critical')
    warning = sum(1 for r in results if r['status'] == 'warning')
    if critical or warning:
        print(f"\nSummary: {critical} critical, {warning} warning")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor inode usage across filesystems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all filesystems
  %(prog)s --format json            # JSON output for monitoring
  %(prog)s --warn-only              # Only show issues
  %(prog)s --warn-threshold 70      # Custom warning threshold
  %(prog)s --critical-threshold 90  # Custom critical threshold

Why Monitor Inodes:
  Filesystems can run out of inodes before disk space, especially with:
  - Mail servers (many small message files)
  - Web caches and CDN storage
  - Container image layers
  - Package repositories and build caches
  - Logging systems with many small log files

  ext4 filesystems have a fixed inode count set at creation time,
  while XFS can dynamically allocate more inodes as needed.

Exit codes:
  0 - All filesystems have healthy inode usage
  1 - Warnings or critical issues detected
  2 - Usage error
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
        help='Show detailed information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show filesystems with issues'
    )

    parser.add_argument(
        '--warn-threshold',
        type=int,
        default=80,
        metavar='PCT',
        help='Warning threshold percentage (default: %(default)s)'
    )

    parser.add_argument(
        '--critical-threshold',
        type=int,
        default=95,
        metavar='PCT',
        help='Critical threshold percentage (default: %(default)s)'
    )

    parser.add_argument(
        '-m', '--mount',
        help='Check specific mount point only'
    )

    args = parser.parse_args()

    # Validate thresholds - check range first, then ordering
    if not (0 < args.warn_threshold < 100) or not (0 < args.critical_threshold <= 100):
        print("Error: Thresholds must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.warn_threshold >= args.critical_threshold:
        print("Error: Warning threshold must be less than critical threshold", file=sys.stderr)
        sys.exit(2)

    # Get inode information
    filesystems = get_inode_info()

    if args.mount:
        filesystems = [fs for fs in filesystems if fs['mount_point'] == args.mount]
        if not filesystems:
            print(f"Error: Mount point {args.mount} not found", file=sys.stderr)
            sys.exit(2)

    if not filesystems:
        if args.format == 'json':
            print(json.dumps({
                'timestamp': datetime.now().isoformat(),
                'filesystems': [],
                'summary': {'total': 0, 'healthy': 0, 'warning': 0, 'critical': 0}
            }))
        else:
            print("No filesystems found to monitor")
        sys.exit(0)

    # Analyze each filesystem
    results = []
    for fs in filesystems:
        disk_info = get_disk_usage(fs['mount_point'])
        fs_type = get_filesystem_type(fs['mount_point'])

        issues = analyze_inode_usage(
            fs, disk_info, fs_type,
            args.warn_threshold, args.critical_threshold
        )

        # Determine status
        if any(i['severity'] == 'CRITICAL' for i in issues):
            status = 'critical'
        elif any(i['severity'] == 'WARNING' for i in issues):
            status = 'warning'
        elif any(i['severity'] == 'INFO' for i in issues):
            status = 'info'
        else:
            status = 'healthy'

        result = {
            **fs,
            'fs_type': fs_type,
            'disk_usage': disk_info,
            'issues': issues,
            'status': status,
        }
        results.append(result)

    # Sort by usage percentage descending
    results.sort(key=lambda x: x['use_percent'], reverse=True)

    # Output results
    if args.format == 'json':
        has_issues = output_json(results)
    elif args.format == 'table':
        has_issues = output_table(results, args.verbose, args.warn_only)
    else:
        has_issues = output_plain(results, args.verbose, args.warn_only)

    # Exit code
    has_critical = any(r['status'] == 'critical' for r in results)
    has_warning = any(r['status'] == 'warning' for r in results)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
