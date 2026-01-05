#!/usr/bin/env python3
"""
Monitor Linux connection tracking (conntrack) table saturation.

This script monitors the netfilter connection tracking table usage, which
tracks all active network connections for stateful packet inspection. Table
exhaustion causes new connections to be dropped, which is a common failure
mode during:

- DDoS attacks that create many connections
- Traffic spikes (flash crowds, viral events)
- Misconfigured applications opening many connections
- Port scanning or network reconnaissance
- Systems handling many short-lived connections (load balancers, proxies)

The script reads from /proc/net/nf_conntrack to check:
- nf_conntrack_count: Current number of tracked connections
- nf_conntrack_max: Maximum table size
- Usage percentage and headroom

Warning signs:
- Usage > 75%: Time to investigate and potentially increase limit
- Usage > 90%: Critical - new connections may be dropped
- Rapid growth: Possible attack or application issue

Remediation:
- Increase nf_conntrack_max: sysctl -w net.netfilter.nf_conntrack_max=262144
- Reduce timeout values for faster cleanup
- Identify and fix applications creating excessive connections
- Implement rate limiting for connection-heavy services

Exit codes:
    0 - Connection tracking usage is healthy
    1 - High usage detected (warning or critical)
    2 - Usage error or conntrack not available (module not loaded)
"""

import argparse
import sys
import json
import os


def read_proc_value(path, required=True, default=None):
    """Read a single integer value from /proc or /sys.

    Args:
        path: Full path to the file to read
        required: If True, exit on missing file; if False, return default
        default: Default value to return if file missing and not required

    Returns:
        int: Value read from the file, or default if not required and missing

    Raises:
        SystemExit: If required file cannot be read
    """
    try:
        with open(path, 'r') as f:
            return int(f.read().strip())
    except FileNotFoundError:
        if required:
            print(f"Error: {path} not found", file=sys.stderr)
            print("Connection tracking may not be enabled.", file=sys.stderr)
            print("Load the module: modprobe nf_conntrack", file=sys.stderr)
            sys.exit(2)
        return default
    except ValueError as e:
        print(f"Error: Invalid value in {path}: {e}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"Error: Permission denied reading {path}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        sys.exit(2)


def get_conntrack_stats():
    """Gather connection tracking statistics.

    Returns:
        dict: Connection tracking statistics
    """
    # Primary paths (modern kernels)
    count_paths = [
        '/proc/sys/net/netfilter/nf_conntrack_count',
        '/proc/sys/net/nf_conntrack_count'  # Older path
    ]
    max_paths = [
        '/proc/sys/net/netfilter/nf_conntrack_max',
        '/proc/sys/net/nf_conntrack_max'  # Older path
    ]

    # Find the working paths
    count = None
    max_val = None

    for path in count_paths:
        if os.path.exists(path):
            count = read_proc_value(path)
            break

    for path in max_paths:
        if os.path.exists(path):
            max_val = read_proc_value(path)
            break

    if count is None:
        print("Error: Could not read conntrack count", file=sys.stderr)
        print("Connection tracking may not be enabled.", file=sys.stderr)
        print("Load the module: modprobe nf_conntrack", file=sys.stderr)
        sys.exit(2)

    if max_val is None:
        print("Error: Could not read conntrack max", file=sys.stderr)
        sys.exit(2)

    # Calculate stats
    usage_percent = (count / max_val * 100) if max_val > 0 else 0
    available = max_val - count

    stats = {
        'count': count,
        'max': max_val,
        'available': available,
        'usage_percent': usage_percent
    }

    # Try to get additional timeout info (optional)
    timeout_paths = {
        'tcp_established': '/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established',
        'tcp_time_wait': '/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait',
        'udp': '/proc/sys/net/netfilter/nf_conntrack_udp_timeout',
        'generic': '/proc/sys/net/netfilter/nf_conntrack_generic_timeout'
    }

    stats['timeouts'] = {}
    for name, path in timeout_paths.items():
        val = read_proc_value(path, required=False)
        if val is not None:
            stats['timeouts'][name] = val

    return stats


def get_conntrack_buckets():
    """Get hash table bucket information.

    Returns:
        dict: Bucket statistics or None if unavailable
    """
    bucket_path = '/proc/sys/net/netfilter/nf_conntrack_buckets'
    buckets = read_proc_value(bucket_path, required=False)

    if buckets is not None:
        return {'buckets': buckets}
    return None


def analyze_conntrack(stats, warn_threshold, crit_threshold):
    """Analyze connection tracking usage and return issues.

    Args:
        stats: Connection tracking statistics dict
        warn_threshold: Warning threshold (percentage)
        crit_threshold: Critical threshold (percentage)

    Returns:
        list: List of issue dictionaries
    """
    issues = []
    usage = stats['usage_percent']

    # Check usage thresholds
    if usage >= crit_threshold:
        issues.append({
            'severity': 'CRITICAL',
            'metric': 'conntrack_usage',
            'value': round(usage, 2),
            'threshold': crit_threshold,
            'message': f'Connection tracking table nearly full: {usage:.1f}% '
                      f'({stats["count"]}/{stats["max"]}) - '
                      f'new connections may be dropped'
        })
    elif usage >= warn_threshold:
        issues.append({
            'severity': 'WARNING',
            'metric': 'conntrack_usage',
            'value': round(usage, 2),
            'threshold': warn_threshold,
            'message': f'Connection tracking table usage high: {usage:.1f}% '
                      f'({stats["count"]}/{stats["max"]}) - '
                      f'consider increasing nf_conntrack_max'
        })

    # Check if available slots are low (absolute number)
    if stats['available'] < 1000 and stats['max'] >= 10000:
        issues.append({
            'severity': 'WARNING',
            'metric': 'conntrack_available',
            'value': stats['available'],
            'message': f'Only {stats["available"]} connection tracking slots available'
        })

    return issues


def output_plain(stats, bucket_info, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only or issues:
        print(f"Conntrack: {stats['count']} / {stats['max']} "
              f"({stats['usage_percent']:.1f}% used)")
        print(f"Available: {stats['available']} slots")

        if verbose:
            if bucket_info:
                print(f"Hash buckets: {bucket_info['buckets']}")

            if stats['timeouts']:
                print("\nTimeouts:")
                for name, val in stats['timeouts'].items():
                    print(f"  {name}: {val}s")

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


def output_json(stats, bucket_info, issues, verbose):
    """Output results in JSON format."""
    result = {
        'conntrack': {
            'count': stats['count'],
            'max': stats['max'],
            'available': stats['available'],
            'usage_percent': round(stats['usage_percent'], 2)
        },
        'issues': issues
    }

    if verbose:
        if bucket_info:
            result['conntrack']['buckets'] = bucket_info['buckets']
        if stats['timeouts']:
            result['timeouts'] = stats['timeouts']

    print(json.dumps(result, indent=2))


def output_table(stats, bucket_info, issues, verbose, warn_only):
    """Output results in table format."""
    if not warn_only or issues:
        print("=" * 70)
        print("CONNECTION TRACKING STATUS")
        print("=" * 70)
        print(f"{'Metric':<30} {'Value':<25} {'Status':<15}")
        print("-" * 70)

        # Determine status
        usage = stats['usage_percent']
        if usage >= 90:
            status = "CRITICAL"
        elif usage >= 75:
            status = "WARNING"
        else:
            status = "OK"

        print(f"{'Current Connections':<30} {stats['count']:<25} {status:<15}")
        print(f"{'Maximum Connections':<30} {stats['max']:<25}")
        print(f"{'Available Slots':<30} {stats['available']:<25}")
        print(f"{'Usage':<30} {usage:.1f}%{'':<20}")

        if verbose:
            if bucket_info:
                print(f"{'Hash Buckets':<30} {bucket_info['buckets']:<25}")

            if stats['timeouts']:
                print()
                print("TIMEOUT SETTINGS (seconds)")
                print("-" * 70)
                for name, val in stats['timeouts'].items():
                    display_name = name.replace('_', ' ').title()
                    print(f"{'  ' + display_name:<30} {val:<25}")

        print("=" * 70)
        print()

    # Print issues
    if issues:
        print("ISSUES DETECTED")
        print("=" * 70)
        for issue in issues:
            print(f"[{issue['severity']}] {issue['message']}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor Linux connection tracking (conntrack) table saturation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check conntrack with default thresholds
  %(prog)s --warn 80 --crit 95  # Custom thresholds
  %(prog)s --format json        # JSON output for monitoring tools
  %(prog)s --verbose            # Show timeout settings and hash info
  %(prog)s --warn-only          # Only show warnings/errors

Thresholds:
  --warn: Usage percentage to trigger warning (default: 75)
  --crit: Usage percentage to trigger critical alert (default: 90)

Common remediation:
  # Increase max connections
  sysctl -w net.netfilter.nf_conntrack_max=262144

  # Make permanent in /etc/sysctl.conf
  net.netfilter.nf_conntrack_max = 262144

  # Reduce timeout for faster cleanup
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=3600

Exit codes:
  0 - Connection tracking usage is healthy
  1 - High usage detected
  2 - Usage error or conntrack module not loaded
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
        help='Show detailed timeout and hash table information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--warn',
        type=float,
        default=75.0,
        metavar='PERCENT',
        help='Warning threshold for usage percentage (default: 75)'
    )

    parser.add_argument(
        '--crit',
        type=float,
        default=90.0,
        metavar='PERCENT',
        help='Critical threshold for usage percentage (default: 90)'
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
    stats = get_conntrack_stats()
    bucket_info = get_conntrack_buckets()

    # Analyze usage
    issues = analyze_conntrack(stats, args.warn, args.crit)

    # Output results
    if args.format == 'json':
        output_json(stats, bucket_info, issues, args.verbose)
    elif args.format == 'table':
        output_table(stats, bucket_info, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(stats, bucket_info, issues, args.verbose, args.warn_only)

    # Determine exit code based on issues
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
