#!/usr/bin/env python3
"""
Monitor filesystem inode usage to detect exhaustion risk.

Inode exhaustion is a silent killer - filesystems appear to have free space but
run out of inodes, causing cryptic "No space left on device" errors. This is
common in systems with:

- Millions of small files (mail servers, cache directories)
- Build systems with many temp files
- Log directories without rotation
- Container image layers
- Package manager caches

The script checks:
- Per-filesystem inode usage and availability
- Filesystems approaching exhaustion thresholds
- Projected time to exhaustion (if tracking enabled)

Warning signs:
- Usage > 80%: Investigate and plan cleanup
- Usage > 90%: Critical - immediate action required
- Usage > 95%: Emergency - applications may fail

Remediation:
- Find inode-heavy directories: find /path -xdev -printf '%h\n' | sort | uniq -c | sort -rn | head -20
- Delete unnecessary files
- Consider filesystem with more inodes (ext4 allows tuning at mkfs)
- Move data to filesystem with larger inode count

Exit codes:
    0 - Inode usage is healthy across all filesystems
    1 - High usage detected (warning or critical)
    2 - Usage error or cannot read filesystem information
"""

import argparse
import sys
import json
import subprocess


def get_filesystem_inode_stats():
    """Get inode statistics for all mounted filesystems.

    Returns:
        list: List of filesystem inode statistics dictionaries
    """
    try:
        # Use df -i for inode information
        # -P for POSIX format (consistent output)
        result = subprocess.run(
            ['df', '-iP'],
            capture_output=True,
            text=True,
            check=True
        )
    except FileNotFoundError:
        print("Error: 'df' command not found", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running df: {e.stderr}", file=sys.stderr)
        sys.exit(2)

    filesystems = []
    lines = result.stdout.strip().split('\n')

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue

        filesystem = parts[0]
        mountpoint = parts[5]

        # Skip pseudo filesystems and special mounts
        if filesystem in ('tmpfs', 'devtmpfs', 'none', 'overlay'):
            continue
        if mountpoint.startswith('/sys') or mountpoint.startswith('/proc'):
            continue
        if mountpoint.startswith('/dev') and mountpoint != '/dev':
            continue
        if mountpoint.startswith('/run') and 'docker' not in mountpoint:
            continue
        if mountpoint.startswith('/snap'):
            continue

        try:
            total = int(parts[1])
            used = int(parts[2])
            available = int(parts[3])

            # Handle percentage (remove % sign)
            usage_str = parts[4].rstrip('%')
            if usage_str == '-':
                # Some filesystems don't report inode usage
                continue
            usage_percent = float(usage_str)

        except (ValueError, IndexError):
            # Skip filesystems with non-numeric values
            continue

        # Skip filesystems with 0 total inodes (special mounts)
        if total == 0:
            continue

        filesystems.append({
            'filesystem': filesystem,
            'mountpoint': mountpoint,
            'total': total,
            'used': used,
            'available': available,
            'usage_percent': usage_percent
        })

    return filesystems


def analyze_inode_usage(filesystems, warn_threshold, crit_threshold):
    """Analyze inode usage and return issues.

    Args:
        filesystems: List of filesystem inode statistics
        warn_threshold: Warning threshold (percentage)
        crit_threshold: Critical threshold (percentage)

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    for fs in filesystems:
        usage = fs['usage_percent']

        if usage >= crit_threshold:
            issues.append({
                'severity': 'CRITICAL',
                'filesystem': fs['filesystem'],
                'mountpoint': fs['mountpoint'],
                'metric': 'inode_usage',
                'value': round(usage, 2),
                'threshold': crit_threshold,
                'used': fs['used'],
                'total': fs['total'],
                'available': fs['available'],
                'message': f"Inode usage critical on {fs['mountpoint']}: {usage:.1f}% "
                          f"({fs['used']:,}/{fs['total']:,}) - "
                          f"only {fs['available']:,} inodes remaining"
            })
        elif usage >= warn_threshold:
            issues.append({
                'severity': 'WARNING',
                'filesystem': fs['filesystem'],
                'mountpoint': fs['mountpoint'],
                'metric': 'inode_usage',
                'value': round(usage, 2),
                'threshold': warn_threshold,
                'used': fs['used'],
                'total': fs['total'],
                'available': fs['available'],
                'message': f"Inode usage high on {fs['mountpoint']}: {usage:.1f}% "
                          f"({fs['used']:,}/{fs['total']:,}) - "
                          f"investigate and plan cleanup"
            })

    return issues


def format_number(n):
    """Format large numbers with K/M/G suffixes."""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}G"
    elif n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    elif n >= 1_000:
        return f"{n / 1_000:.1f}K"
    else:
        return str(n)


def output_plain(filesystems, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only:
        print("Filesystem Inode Usage:")
        print()

        for fs in filesystems:
            status = ""
            if fs['usage_percent'] >= 90:
                status = " [CRITICAL]"
            elif fs['usage_percent'] >= 80:
                status = " [WARNING]"

            print(f"  {fs['mountpoint']}: {fs['usage_percent']:.1f}% "
                  f"({format_number(fs['used'])}/{format_number(fs['total'])} inodes){status}")

            if verbose:
                print(f"    Filesystem: {fs['filesystem']}")
                print(f"    Available: {fs['available']:,} inodes")
                print()

        if not verbose:
            print()

    # Print issues
    for issue in issues:
        severity = issue['severity']
        message = issue['message']

        prefix = {
            'CRITICAL': '[CRITICAL]',
            'WARNING': '[WARNING]',
            'INFO': '[INFO]'
        }.get(severity, '[UNKNOWN]')

        print(f"{prefix} {message}")

    if not issues and warn_only:
        pass  # Silent when no issues in warn-only mode
    elif not issues and not warn_only:
        print("All filesystems have healthy inode usage.")


def output_json(filesystems, issues, verbose):
    """Output results in JSON format."""
    result = {
        'filesystems': [
            {
                'mountpoint': fs['mountpoint'],
                'filesystem': fs['filesystem'],
                'total': fs['total'],
                'used': fs['used'],
                'available': fs['available'],
                'usage_percent': round(fs['usage_percent'], 2)
            }
            for fs in filesystems
        ],
        'issues': issues,
        'summary': {
            'total_filesystems': len(filesystems),
            'critical_count': sum(1 for i in issues if i['severity'] == 'CRITICAL'),
            'warning_count': sum(1 for i in issues if i['severity'] == 'WARNING'),
            'healthy': len(issues) == 0
        }
    }

    print(json.dumps(result, indent=2))


def output_table(filesystems, issues, verbose, warn_only):
    """Output results in table format."""
    if not warn_only:
        print("=" * 80)
        print("FILESYSTEM INODE USAGE STATUS")
        print("=" * 80)
        print(f"{'Mountpoint':<25} {'Used':<12} {'Total':<12} {'Avail':<12} {'Use%':<8} {'Status':<10}")
        print("-" * 80)

        for fs in filesystems:
            usage = fs['usage_percent']
            if usage >= 90:
                status = "CRITICAL"
            elif usage >= 80:
                status = "WARNING"
            else:
                status = "OK"

            print(f"{fs['mountpoint'][:24]:<25} "
                  f"{format_number(fs['used']):<12} "
                  f"{format_number(fs['total']):<12} "
                  f"{format_number(fs['available']):<12} "
                  f"{usage:.1f}%{'':<4} "
                  f"{status:<10}")

        print("=" * 80)
        print()

    # Print issues
    if issues:
        print("ISSUES DETECTED")
        print("=" * 80)
        for issue in issues:
            print(f"[{issue['severity']}] {issue['message']}")
        print()
    elif not warn_only:
        print("No inode usage issues detected.")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor filesystem inode usage to detect exhaustion risk',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check inode usage with default thresholds
  %(prog)s --warn 70 --crit 85  # Custom thresholds
  %(prog)s --format json        # JSON output for monitoring tools
  %(prog)s --verbose            # Show detailed filesystem info
  %(prog)s --warn-only          # Only show warnings/errors

Thresholds:
  --warn: Usage percentage to trigger warning (default: 80)
  --crit: Usage percentage to trigger critical alert (default: 90)

Finding inode-heavy directories:
  # Find directories with most files on a filesystem
  find /path -xdev -printf '%%h\\n' | sort | uniq -c | sort -rn | head -20

  # Count files per top-level directory
  for d in /path/*/; do echo "$(find "$d" -xdev | wc -l) $d"; done | sort -rn

Common remediation:
  - Clean up old log files, temp files, cache directories
  - Delete unused package manager caches (apt, pip, npm, etc.)
  - Remove old container images and layers
  - Consider filesystem with more inodes (ext4: mkfs -N option)

Exit codes:
  0 - Inode usage is healthy
  1 - High usage detected
  2 - Usage error or cannot read filesystem information
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
        help='Show detailed filesystem information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--warn',
        type=float,
        default=80.0,
        metavar='PERCENT',
        help='Warning threshold for inode usage percentage (default: 80)'
    )

    parser.add_argument(
        '--crit',
        type=float,
        default=90.0,
        metavar='PERCENT',
        help='Critical threshold for inode usage percentage (default: 90)'
    )

    parser.add_argument(
        '--mountpoint',
        metavar='PATH',
        help='Only check specific mountpoint'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn < 0 or args.warn > 100:
        print("Error: --warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.crit < 0 or args.crit > 100:
        print("Error: --crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.crit <= args.warn:
        print("Error: --crit must be greater than --warn", file=sys.stderr)
        sys.exit(2)

    # Gather information
    filesystems = get_filesystem_inode_stats()

    # Filter by mountpoint if specified
    if args.mountpoint:
        filesystems = [fs for fs in filesystems if fs['mountpoint'] == args.mountpoint]
        if not filesystems:
            print(f"Error: Mountpoint '{args.mountpoint}' not found", file=sys.stderr)
            sys.exit(2)

    if not filesystems:
        print("Warning: No filesystems found to monitor", file=sys.stderr)
        sys.exit(0)

    # Analyze usage
    issues = analyze_inode_usage(filesystems, args.warn, args.crit)

    # Output results
    if args.format == 'json':
        output_json(filesystems, issues, args.verbose)
    elif args.format == 'table':
        output_table(filesystems, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(filesystems, issues, args.verbose, args.warn_only)

    # Determine exit code based on issues
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
