#!/usr/bin/env python3
"""
Monitor CPU thermal throttling events on baremetal systems.

Detects CPU thermal throttling by reading kernel throttle counters from
/sys/devices/system/cpu/cpu*/thermal_throttle/. Unlike temperature monitoring
which shows current temps, this script shows actual throttling events that
indicate performance degradation has occurred.

Useful for:
- Detecting datacenter cooling problems before they cause failures
- Identifying servers with degraded performance due to thermal issues
- Auditing thermal throttle history across a fleet
- Correlating performance issues with thermal events

Exit codes:
  0 - Success (no throttling detected)
  1 - Throttling detected (current or historical)
  2 - Usage error or missing dependencies
"""

import argparse
import glob
import json
import os
import sys
from collections import defaultdict


def check_thermal_throttle_available():
    """Check if thermal throttle interface is available."""
    return os.path.exists('/sys/devices/system/cpu/cpu0/thermal_throttle')


def read_sysfs_file(path):
    """Read a sysfs file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def get_cpu_count():
    """Get the number of CPUs in the system."""
    cpu_dirs = glob.glob('/sys/devices/system/cpu/cpu[0-9]*')
    return len(cpu_dirs)


def get_throttle_info(cpu_num):
    """
    Get thermal throttle information for a specific CPU.

    Returns dict with core and package throttle counts.
    """
    base_path = f'/sys/devices/system/cpu/cpu{cpu_num}/thermal_throttle'

    if not os.path.exists(base_path):
        return None

    info = {
        'cpu': cpu_num,
        'core_throttle_count': 0,
        'package_throttle_count': 0,
        'core_throttle_max_time_ms': None,
        'package_throttle_max_time_ms': None,
        'core_throttle_total_time_ms': None,
        'package_throttle_total_time_ms': None,
    }

    # Read core throttle count
    core_count = read_sysfs_file(f'{base_path}/core_throttle_count')
    if core_count is not None:
        try:
            info['core_throttle_count'] = int(core_count)
        except ValueError:
            pass

    # Read package throttle count
    pkg_count = read_sysfs_file(f'{base_path}/package_throttle_count')
    if pkg_count is not None:
        try:
            info['package_throttle_count'] = int(pkg_count)
        except ValueError:
            pass

    # Read core throttle max time (may not exist on all systems)
    core_max_time = read_sysfs_file(f'{base_path}/core_throttle_max_time_ms')
    if core_max_time is not None:
        try:
            info['core_throttle_max_time_ms'] = int(core_max_time)
        except ValueError:
            pass

    # Read package throttle max time
    pkg_max_time = read_sysfs_file(f'{base_path}/package_throttle_max_time_ms')
    if pkg_max_time is not None:
        try:
            info['package_throttle_max_time_ms'] = int(pkg_max_time)
        except ValueError:
            pass

    # Read core throttle total time
    core_total = read_sysfs_file(f'{base_path}/core_throttle_total_time_ms')
    if core_total is not None:
        try:
            info['core_throttle_total_time_ms'] = int(core_total)
        except ValueError:
            pass

    # Read package throttle total time
    pkg_total = read_sysfs_file(f'{base_path}/package_throttle_total_time_ms')
    if pkg_total is not None:
        try:
            info['package_throttle_total_time_ms'] = int(pkg_total)
        except ValueError:
            pass

    return info


def analyze_throttle_data(cpu_data):
    """
    Analyze throttle data and compute summary statistics.

    Returns a dict with:
    - total_core_throttles: sum of all core throttle events
    - total_package_throttles: sum of all package throttle events
    - affected_cores: list of CPUs with core throttle events
    - packages_affected: unique packages with throttle events
    - status: OK, WARNING, or CRITICAL
    """
    summary = {
        'total_cpus': len(cpu_data),
        'total_core_throttles': 0,
        'total_package_throttles': 0,
        'max_core_throttle_count': 0,
        'max_package_throttle_count': 0,
        'affected_cores': [],
        'cores_with_throttles': 0,
        'total_throttle_time_ms': 0,
        'status': 'OK',
        'issues': []
    }

    for cpu in cpu_data:
        core_count = cpu.get('core_throttle_count', 0)
        pkg_count = cpu.get('package_throttle_count', 0)

        summary['total_core_throttles'] += core_count
        summary['total_package_throttles'] += pkg_count

        if core_count > summary['max_core_throttle_count']:
            summary['max_core_throttle_count'] = core_count

        if pkg_count > summary['max_package_throttle_count']:
            summary['max_package_throttle_count'] = pkg_count

        if core_count > 0:
            summary['affected_cores'].append(cpu['cpu'])
            summary['cores_with_throttles'] += 1

        # Add throttle time if available
        if cpu.get('core_throttle_total_time_ms'):
            summary['total_throttle_time_ms'] += cpu['core_throttle_total_time_ms']
        if cpu.get('package_throttle_total_time_ms'):
            summary['total_throttle_time_ms'] += cpu['package_throttle_total_time_ms']

    # Determine status
    if summary['total_core_throttles'] > 0 or summary['total_package_throttles'] > 0:
        summary['status'] = 'WARNING'

        if summary['total_core_throttles'] > 0:
            summary['issues'].append(
                f"{summary['total_core_throttles']} core throttle events "
                f"across {summary['cores_with_throttles']} CPUs"
            )

        if summary['total_package_throttles'] > 0:
            summary['issues'].append(
                f"{summary['total_package_throttles']} package throttle events"
            )

        if summary['total_throttle_time_ms'] > 0:
            time_sec = summary['total_throttle_time_ms'] / 1000
            summary['issues'].append(
                f"Total throttle time: {time_sec:.1f} seconds"
            )

        # Critical if significant throttling (arbitrary threshold)
        if summary['total_core_throttles'] > 100 or summary['total_package_throttles'] > 100:
            summary['status'] = 'CRITICAL'

    return summary


def format_time_ms(ms):
    """Format milliseconds into human-readable format."""
    if ms is None:
        return 'N/A'
    if ms < 1000:
        return f'{ms}ms'
    elif ms < 60000:
        return f'{ms/1000:.1f}s'
    else:
        return f'{ms/60000:.1f}m'


def output_plain(cpu_data, summary, verbose=False):
    """Output results in plain text format."""
    # Header with status
    status_icon = {'OK': '[OK]', 'WARNING': '[WARN]', 'CRITICAL': '[CRIT]'}
    print(f"Thermal Throttle Status: {status_icon.get(summary['status'], '')} {summary['status']}")
    print(f"CPUs Checked: {summary['total_cpus']}")

    if summary['status'] == 'OK':
        print("No thermal throttling detected.")
        return

    # Summary of issues
    print(f"\nThrottle Summary:")
    print(f"  Core throttle events:    {summary['total_core_throttles']}")
    print(f"  Package throttle events: {summary['total_package_throttles']}")
    print(f"  CPUs with throttles:     {summary['cores_with_throttles']}/{summary['total_cpus']}")

    if summary['total_throttle_time_ms'] > 0:
        print(f"  Total throttle time:     {format_time_ms(summary['total_throttle_time_ms'])}")

    # Show affected CPUs
    if summary['affected_cores']:
        print(f"\nAffected CPUs: {', '.join(map(str, summary['affected_cores'][:10]))}", end='')
        if len(summary['affected_cores']) > 10:
            print(f" ... and {len(summary['affected_cores']) - 10} more")
        else:
            print()

    # Verbose: show per-CPU details
    if verbose:
        print(f"\nPer-CPU Details:")
        print(f"  {'CPU':<6} {'Core Throttles':<16} {'Pkg Throttles':<16} {'Time':<12}")
        print(f"  {'-'*50}")

        for cpu in sorted(cpu_data, key=lambda x: x['cpu']):
            if cpu['core_throttle_count'] > 0 or cpu['package_throttle_count'] > 0:
                time_str = format_time_ms(cpu.get('core_throttle_total_time_ms'))
                print(f"  {cpu['cpu']:<6} {cpu['core_throttle_count']:<16} "
                      f"{cpu['package_throttle_count']:<16} {time_str:<12}")


def output_json(cpu_data, summary):
    """Output results in JSON format."""
    output = {
        'summary': summary,
        'cpus': cpu_data
    }
    print(json.dumps(output, indent=2))


def output_table(cpu_data, summary, warn_only=False):
    """Output results in table format."""
    print(f"{'CPU':<6} {'Core Throttles':<16} {'Pkg Throttles':<16} "
          f"{'Core Time':<12} {'Pkg Time':<12} {'Status':<10}")
    print("-" * 72)

    for cpu in sorted(cpu_data, key=lambda x: x['cpu']):
        has_throttles = cpu['core_throttle_count'] > 0 or cpu['package_throttle_count'] > 0

        if warn_only and not has_throttles:
            continue

        status = 'THROTTLED' if has_throttles else 'OK'
        core_time = format_time_ms(cpu.get('core_throttle_total_time_ms'))
        pkg_time = format_time_ms(cpu.get('package_throttle_total_time_ms'))

        print(f"{cpu['cpu']:<6} {cpu['core_throttle_count']:<16} "
              f"{cpu['package_throttle_count']:<16} "
              f"{core_time:<12} {pkg_time:<12} {status:<10}")

    # Print summary line
    print("-" * 72)
    print(f"{'TOTAL':<6} {summary['total_core_throttles']:<16} "
          f"{summary['total_package_throttles']:<16} "
          f"{format_time_ms(summary['total_throttle_time_ms']):<12} {'':<12} "
          f"{summary['status']:<10}")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor CPU thermal throttling events on baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check for thermal throttling
  %(prog)s

  # Show only CPUs that have throttled
  %(prog)s --warn-only

  # Verbose output with per-CPU details
  %(prog)s --verbose

  # Output as JSON for monitoring integration
  %(prog)s --format json

  # Table format for easy reading
  %(prog)s --format table

Exit codes:
  0 - No throttling detected
  1 - Throttling detected (historical or current)
  2 - Usage error or missing dependencies

Notes:
  Throttle counts persist across reboots on some systems but reset on others.
  A non-zero count indicates throttling has occurred since the counter was
  last reset. For ongoing monitoring, compare counts over time.
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show CPUs with throttle events'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed per-CPU information'
    )
    parser.add_argument(
        '--threshold',
        type=int,
        default=0,
        help='Minimum throttle count to report as issue (default: 0)'
    )

    args = parser.parse_args()

    # Check if thermal throttle interface is available
    if not check_thermal_throttle_available():
        print("Error: Thermal throttle interface not available", file=sys.stderr)
        print("This system may not support thermal throttle monitoring or", file=sys.stderr)
        print("the required kernel modules are not loaded.", file=sys.stderr)
        print("Check if /sys/devices/system/cpu/cpu0/thermal_throttle exists.", file=sys.stderr)
        return 2

    # Get CPU count
    cpu_count = get_cpu_count()
    if cpu_count == 0:
        print("Error: Could not determine CPU count", file=sys.stderr)
        return 2

    # Gather throttle information for all CPUs
    cpu_data = []
    for cpu_num in range(cpu_count):
        info = get_throttle_info(cpu_num)
        if info:
            cpu_data.append(info)

    if not cpu_data:
        print("Error: Could not read thermal throttle information", file=sys.stderr)
        return 2

    # Analyze data
    summary = analyze_throttle_data(cpu_data)

    # Apply threshold filter
    if args.threshold > 0:
        # Only consider it an issue if throttles exceed threshold
        if (summary['total_core_throttles'] < args.threshold and
                summary['total_package_throttles'] < args.threshold):
            summary['status'] = 'OK'
            summary['issues'] = []

    # Filter if warn-only
    if args.warn_only:
        cpu_data = [c for c in cpu_data
                    if c['core_throttle_count'] > 0 or c['package_throttle_count'] > 0]
        if not cpu_data and summary['status'] == 'OK':
            if args.format == 'json':
                print('{"summary": {"status": "OK", "total_cpus": %d, '
                      '"total_core_throttles": 0, "total_package_throttles": 0}, '
                      '"cpus": []}' % cpu_count)
            else:
                print("No thermal throttling detected.")
            return 0

    # Output results
    if args.format == 'json':
        output_json(cpu_data, summary)
    elif args.format == 'table':
        output_table(cpu_data, summary, args.warn_only)
    else:
        output_plain(cpu_data, summary, args.verbose)

    # Determine exit code
    return 1 if summary['status'] != 'OK' else 0


if __name__ == '__main__':
    sys.exit(main())
