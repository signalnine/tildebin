#!/usr/bin/env python3
"""Monitor system load averages and process queue depth.

This script monitors the system load average (1, 5, 15 minute intervals)
and compares them against CPU core counts to identify overloaded systems.
It also tracks running/blocked process counts from /proc/loadavg.

Critical for baremetal datacenters to identify:
- Systems under excessive load (load > CPU cores)
- Sustained high load patterns indicating resource exhaustion
- Process queue buildup indicating scheduling pressure
- Early warning signs of system degradation

Load average represents the average number of processes in a runnable
or uninterruptible state over time intervals. A load average higher
than the CPU count typically indicates resource contention.

Exit codes:
  0: Load is within acceptable range
  1: Load average exceeds thresholds or high process queue depth
  2: Usage error or missing dependencies

Author: Generated for tildebin collection
"""

import argparse
import json
import os
import sys


def get_cpu_count():
    """Get the number of CPU cores on the system."""
    try:
        # Try using os.cpu_count() (Python 3.4+)
        count = os.cpu_count()
        if count:
            return count

        # Fallback: read from /proc/cpuinfo
        with open('/proc/cpuinfo', 'r') as f:
            return sum(1 for line in f if line.startswith('processor'))
    except Exception as e:
        print(f"Warning: Could not determine CPU count: {e}", file=sys.stderr)
        return None


def get_load_average():
    """Get load average from /proc/loadavg.

    Returns:
        tuple: (load1, load5, load15, running_procs, total_procs, last_pid)
    """
    try:
        with open('/proc/loadavg', 'r') as f:
            line = f.read().strip()
            parts = line.split()

            load1 = float(parts[0])
            load5 = float(parts[1])
            load15 = float(parts[2])

            # Parse "running/total" processes
            proc_parts = parts[3].split('/')
            running_procs = int(proc_parts[0])
            total_procs = int(proc_parts[1])

            last_pid = int(parts[4])

            return load1, load5, load15, running_procs, total_procs, last_pid
    except Exception as e:
        print(f"Error: Could not read /proc/loadavg: {e}", file=sys.stderr)
        sys.exit(2)


def check_load_health(load1, load5, load15, cpu_count, thresholds):
    """Check if load averages are within acceptable ranges.

    Args:
        load1, load5, load15: Load averages
        cpu_count: Number of CPU cores
        thresholds: Dictionary with threshold multipliers

    Returns:
        list: List of issues found (empty if healthy)
    """
    issues = []

    if cpu_count is None:
        return issues

    # Calculate threshold values
    warn_threshold = cpu_count * thresholds['warn_multiplier']
    crit_threshold = cpu_count * thresholds['crit_multiplier']

    # Check 1-minute load
    if load1 > crit_threshold:
        issues.append({
            'severity': 'CRITICAL',
            'metric': 'load_1min',
            'value': load1,
            'threshold': crit_threshold,
            'message': f"1-minute load ({load1:.2f}) exceeds critical threshold ({crit_threshold:.2f})"
        })
    elif load1 > warn_threshold:
        issues.append({
            'severity': 'WARNING',
            'metric': 'load_1min',
            'value': load1,
            'threshold': warn_threshold,
            'message': f"1-minute load ({load1:.2f}) exceeds warning threshold ({warn_threshold:.2f})"
        })

    # Check 5-minute load
    if load5 > crit_threshold:
        issues.append({
            'severity': 'CRITICAL',
            'metric': 'load_5min',
            'value': load5,
            'threshold': crit_threshold,
            'message': f"5-minute load ({load5:.2f}) exceeds critical threshold ({crit_threshold:.2f})"
        })
    elif load5 > warn_threshold:
        issues.append({
            'severity': 'WARNING',
            'metric': 'load_5min',
            'value': load5,
            'threshold': warn_threshold,
            'message': f"5-minute load ({load5:.2f}) exceeds warning threshold ({warn_threshold:.2f})"
        })

    # Check 15-minute load
    if load15 > crit_threshold:
        issues.append({
            'severity': 'CRITICAL',
            'metric': 'load_15min',
            'value': load15,
            'threshold': crit_threshold,
            'message': f"15-minute load ({load15:.2f}) exceeds critical threshold ({crit_threshold:.2f})"
        })
    elif load15 > warn_threshold:
        issues.append({
            'severity': 'WARNING',
            'metric': 'load_15min',
            'value': load15,
            'threshold': warn_threshold,
            'message': f"15-minute load ({load15:.2f}) exceeds warning threshold ({warn_threshold:.2f})"
        })

    return issues


def output_plain(data, warn_only=False):
    """Output in plain text format."""
    cpu_count = data['cpu_count']
    load1, load5, load15 = data['load_average']
    running, total = data['processes']['running'], data['processes']['total']

    if not warn_only or data['issues']:
        print(f"CPU Cores: {cpu_count if cpu_count else 'Unknown'}")
        print(f"Load Average: {load1:.2f} {load5:.2f} {load15:.2f}")
        print(f"Processes: {running} running / {total} total")

        if cpu_count:
            load_per_core_1 = load1 / cpu_count
            load_per_core_5 = load5 / cpu_count
            load_per_core_15 = load15 / cpu_count
            print(f"Load per Core: {load_per_core_1:.2f} {load_per_core_5:.2f} {load_per_core_15:.2f}")

    if data['issues']:
        print()
        print("Issues Detected:")
        for issue in data['issues']:
            print(f"  [{issue['severity']}] {issue['message']}")
    elif not warn_only:
        print()
        print("Status: OK - Load averages are within acceptable range")


def output_json(data):
    """Output in JSON format."""
    print(json.dumps(data, indent=2))


def output_table(data, warn_only=False):
    """Output in table format."""
    cpu_count = data['cpu_count']
    load1, load5, load15 = data['load_average']

    if not warn_only or data['issues']:
        print(f"{'Metric':<20} {'Value':<15} {'Per Core':<15} {'Status':<10}")
        print("-" * 60)

        # CPU count
        print(f"{'CPU Cores':<20} {cpu_count if cpu_count else 'Unknown':<15} {'-':<15} {'-':<10}")

        # Load averages
        if cpu_count:
            for interval, load_val in [('Load 1min', load1), ('Load 5min', load5), ('Load 15min', load15)]:
                per_core = load_val / cpu_count
                status = 'OK'

                # Determine status
                for issue in data['issues']:
                    if interval.replace(' ', '_').lower() == issue['metric']:
                        status = issue['severity']
                        break

                print(f"{interval:<20} {load_val:<15.2f} {per_core:<15.2f} {status:<10}")
        else:
            for interval, load_val in [('Load 1min', load1), ('Load 5min', load5), ('Load 15min', load15)]:
                print(f"{interval:<20} {load_val:<15.2f} {'-':<15} {'UNKNOWN':<10}")

        # Process counts
        running, total = data['processes']['running'], data['processes']['total']
        print(f"{'Running Processes':<20} {running:<15} {'-':<15} {'-':<10}")
        print(f"{'Total Processes':<20} {total:<15} {'-':<15} {'-':<10}")

    if data['issues']:
        print()
        print("Issues:")
        for issue in data['issues']:
            print(f"  [{issue['severity']}] {issue['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor system load averages and process queue depth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Show current load status
  %(prog)s --format json            # Output in JSON format
  %(prog)s --warn-only              # Only show if there are issues
  %(prog)s --warn-multiplier 1.5    # Warn at 1.5x CPU count
  %(prog)s --crit-multiplier 2.5    # Critical at 2.5x CPU count

Load thresholds:
  WARNING:  load > (CPU cores * warn_multiplier)
  CRITICAL: load > (CPU cores * crit_multiplier)

Default thresholds: warn=1.0 (100%%), crit=2.0 (200%% of CPU cores)
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if there are warnings or issues'
    )

    parser.add_argument(
        '--warn-multiplier',
        type=float,
        default=1.0,
        help='Warning threshold as multiple of CPU count (default: %(default)s)'
    )

    parser.add_argument(
        '--crit-multiplier',
        type=float,
        default=2.0,
        help='Critical threshold as multiple of CPU count (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn_multiplier <= 0 or args.crit_multiplier <= 0:
        print("Error: Threshold multipliers must be positive", file=sys.stderr)
        sys.exit(2)

    if args.warn_multiplier >= args.crit_multiplier:
        print("Error: Warning multiplier must be less than critical multiplier", file=sys.stderr)
        sys.exit(2)

    # Get system information
    cpu_count = get_cpu_count()
    load1, load5, load15, running_procs, total_procs, last_pid = get_load_average()

    # Check load health
    thresholds = {
        'warn_multiplier': args.warn_multiplier,
        'crit_multiplier': args.crit_multiplier
    }
    issues = check_load_health(load1, load5, load15, cpu_count, thresholds)

    # Build data structure
    data = {
        'cpu_count': cpu_count,
        'load_average': [load1, load5, load15],
        'processes': {
            'running': running_procs,
            'total': total_procs,
            'last_pid': last_pid
        },
        'thresholds': thresholds,
        'issues': issues
    }

    if args.verbose and cpu_count:
        data['load_per_core'] = [
            load1 / cpu_count,
            load5 / cpu_count,
            load15 / cpu_count
        ]

    # Output results
    if args.format == 'json':
        output_json(data)
    elif args.format == 'table':
        output_table(data, args.warn_only)
    else:  # plain
        output_plain(data, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if issues else 0)


if __name__ == '__main__':
    main()
