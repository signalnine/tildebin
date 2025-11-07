#!/usr/bin/env python3
"""
Monitor CPU frequency scaling and governor settings on baremetal systems.

Checks CPU frequency settings, governors, and identifies CPUs running at
unexpected frequencies. Critical for detecting performance issues in
large-scale baremetal environments where CPU throttling or incorrect
governor settings can impact workload performance.

Exit codes:
  0 - Success (all CPUs configured correctly)
  1 - Warning/Critical issues detected (throttling, wrong governor, etc.)
  2 - Usage error or missing dependencies
"""

import argparse
import glob
import json
import os
import sys


def check_cpufreq_available():
    """Check if cpufreq interface is available."""
    return os.path.exists('/sys/devices/system/cpu/cpu0/cpufreq')


def get_cpu_count():
    """Get the number of CPUs in the system."""
    cpu_dirs = glob.glob('/sys/devices/system/cpu/cpu[0-9]*')
    return len(cpu_dirs)


def read_sysfs_file(path):
    """Read a sysfs file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def get_cpu_info(cpu_num):
    """
    Get frequency and governor information for a specific CPU.

    Returns dict with current freq, min freq, max freq, governor,
    available governors, and driver.
    """
    base_path = f'/sys/devices/system/cpu/cpu{cpu_num}/cpufreq'

    if not os.path.exists(base_path):
        return None

    info = {
        'cpu': cpu_num,
        'current_freq': None,
        'min_freq': None,
        'max_freq': None,
        'scaling_min_freq': None,
        'scaling_max_freq': None,
        'governor': None,
        'available_governors': [],
        'driver': None,
        'status': 'OK'
    }

    # Read current frequency (in kHz)
    current_freq = read_sysfs_file(f'{base_path}/scaling_cur_freq')
    if current_freq:
        info['current_freq'] = int(current_freq)

    # Read hardware limits
    min_freq = read_sysfs_file(f'{base_path}/cpuinfo_min_freq')
    if min_freq:
        info['min_freq'] = int(min_freq)

    max_freq = read_sysfs_file(f'{base_path}/cpuinfo_max_freq')
    if max_freq:
        info['max_freq'] = int(max_freq)

    # Read scaling limits
    scaling_min = read_sysfs_file(f'{base_path}/scaling_min_freq')
    if scaling_min:
        info['scaling_min_freq'] = int(scaling_min)

    scaling_max = read_sysfs_file(f'{base_path}/scaling_max_freq')
    if scaling_max:
        info['scaling_max_freq'] = int(scaling_max)

    # Read governor
    governor = read_sysfs_file(f'{base_path}/scaling_governor')
    if governor:
        info['governor'] = governor

    # Read available governors
    available_gov = read_sysfs_file(f'{base_path}/scaling_available_governors')
    if available_gov:
        info['available_governors'] = available_gov.split()

    # Read driver
    driver = read_sysfs_file(f'{base_path}/scaling_driver')
    if driver:
        info['driver'] = driver

    return info


def analyze_cpu_status(cpu_info, expected_governor=None, check_throttling=True):
    """
    Analyze CPU info and determine status.

    Sets status to WARNING or CRITICAL based on:
    - Governor mismatch with expected
    - CPU running below maximum frequency (potential throttling)
    - Scaling limits set below hardware maximum
    """
    if not cpu_info:
        return cpu_info

    issues = []

    # Check governor
    if expected_governor and cpu_info['governor'] != expected_governor:
        issues.append(f"Governor is '{cpu_info['governor']}', expected '{expected_governor}'")
        cpu_info['status'] = 'WARNING'

    # Check for throttling (current freq significantly below max)
    if check_throttling and cpu_info['current_freq'] and cpu_info['max_freq']:
        freq_percent = (cpu_info['current_freq'] / cpu_info['max_freq']) * 100
        # Only flag if CPU is stuck at low frequency (below 50% of max)
        # This avoids false positives from normal frequency scaling
        if freq_percent < 50:
            issues.append(f"Running at {freq_percent:.1f}% of max frequency (possible throttling)")
            if cpu_info['status'] == 'OK':
                cpu_info['status'] = 'WARNING'

    # Check if scaling limits are artificially constrained
    if cpu_info['scaling_max_freq'] and cpu_info['max_freq']:
        if cpu_info['scaling_max_freq'] < cpu_info['max_freq']:
            diff_mhz = (cpu_info['max_freq'] - cpu_info['scaling_max_freq']) / 1000
            issues.append(f"Scaling max limited to {cpu_info['scaling_max_freq']/1000:.0f} MHz "
                         f"(hardware max: {cpu_info['max_freq']/1000:.0f} MHz, -{diff_mhz:.0f} MHz)")
            if cpu_info['status'] == 'OK':
                cpu_info['status'] = 'WARNING'

    cpu_info['issues'] = issues
    return cpu_info


def format_freq_mhz(freq_khz):
    """Convert frequency from kHz to MHz for display."""
    if freq_khz is None:
        return 'N/A'
    return f"{freq_khz / 1000:.0f} MHz"


def output_plain(cpu_data, verbose=False):
    """Output results in plain text format."""
    if not cpu_data:
        print("No CPU frequency data available")
        return

    # Summary
    total_cpus = len(cpu_data)
    ok_cpus = sum(1 for c in cpu_data if c['status'] == 'OK')
    warn_cpus = sum(1 for c in cpu_data if c['status'] == 'WARNING')

    print(f"CPU Frequency Status: {ok_cpus}/{total_cpus} CPUs OK")

    if cpu_data[0]['driver']:
        print(f"Driver: {cpu_data[0]['driver']}")

    # Governor summary
    governors = {}
    for cpu in cpu_data:
        gov = cpu['governor']
        if gov not in governors:
            governors[gov] = 0
        governors[gov] += 1

    print(f"Governors: {', '.join(f'{gov}={count}' for gov, count in sorted(governors.items()))}")

    # Frequency range
    if cpu_data[0]['min_freq'] and cpu_data[0]['max_freq']:
        print(f"Hardware Range: {format_freq_mhz(cpu_data[0]['min_freq'])} - "
              f"{format_freq_mhz(cpu_data[0]['max_freq'])}")

    # Show CPUs with issues
    if warn_cpus > 0:
        print(f"\nCPUs with Issues ({warn_cpus}):")
        for cpu in cpu_data:
            if cpu['status'] != 'OK':
                print(f"\n  CPU {cpu['cpu']}: {cpu['status']}")
                print(f"    Governor: {cpu['governor']}")
                print(f"    Current: {format_freq_mhz(cpu['current_freq'])}, "
                      f"Max: {format_freq_mhz(cpu['max_freq'])}")
                if cpu.get('issues'):
                    for issue in cpu['issues']:
                        print(f"    - {issue}")

    # Verbose: show all CPUs
    if verbose and ok_cpus > 0:
        print(f"\nHealthy CPUs ({ok_cpus}):")
        for cpu in cpu_data:
            if cpu['status'] == 'OK':
                print(f"  CPU {cpu['cpu']}: {cpu['governor']}, "
                      f"{format_freq_mhz(cpu['current_freq'])} / "
                      f"{format_freq_mhz(cpu['max_freq'])}")


def output_json(cpu_data):
    """Output results in JSON format."""
    print(json.dumps(cpu_data, indent=2))


def output_table(cpu_data):
    """Output results in table format."""
    if not cpu_data:
        print("No CPU frequency data available")
        return

    # Header
    print(f"{'CPU':<6} {'Governor':<12} {'Current':<10} {'Max':<10} {'Scaling Max':<12} {'Status':<10}")
    print("-" * 70)

    # Rows
    for cpu in cpu_data:
        print(f"{cpu['cpu']:<6} "
              f"{cpu['governor'] or 'N/A':<12} "
              f"{format_freq_mhz(cpu['current_freq']):<10} "
              f"{format_freq_mhz(cpu['max_freq']):<10} "
              f"{format_freq_mhz(cpu['scaling_max_freq']):<12} "
              f"{cpu['status']:<10}")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor CPU frequency scaling and governor settings',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check CPU frequency status
  %(prog)s

  # Check and expect 'performance' governor on all CPUs
  %(prog)s --expected-governor performance

  # Show only CPUs with issues
  %(prog)s --warn-only

  # Output in JSON format
  %(prog)s --format json

  # Show all CPUs including healthy ones
  %(prog)s --verbose

Exit codes:
  0 - All CPUs configured correctly
  1 - Issues detected (wrong governor, throttling, etc.)
  2 - Usage error or missing dependencies
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--expected-governor',
        help='Expected governor (e.g., performance, powersave, ondemand)'
    )
    parser.add_argument(
        '--no-throttle-check',
        action='store_true',
        help='Disable throttling detection (avoid false positives)'
    )
    parser.add_argument(
        '--warn-only',
        action='store_true',
        help='Only show CPUs with warnings or issues'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed information for all CPUs'
    )

    args = parser.parse_args()

    # Check if cpufreq is available
    if not check_cpufreq_available():
        print("Error: CPU frequency scaling interface not available", file=sys.stderr)
        print("This system may not support cpufreq or the required kernel modules are not loaded",
              file=sys.stderr)
        return 2

    # Get CPU count
    cpu_count = get_cpu_count()
    if cpu_count == 0:
        print("Error: Could not determine CPU count", file=sys.stderr)
        return 2

    # Gather CPU information
    cpu_data = []
    for cpu_num in range(cpu_count):
        cpu_info = get_cpu_info(cpu_num)
        if cpu_info:
            cpu_info = analyze_cpu_status(
                cpu_info,
                expected_governor=args.expected_governor,
                check_throttling=not args.no_throttle_check
            )
            cpu_data.append(cpu_info)

    if not cpu_data:
        print("Error: Could not read CPU frequency information", file=sys.stderr)
        return 2

    # Filter if warn-only
    if args.warn_only:
        cpu_data = [c for c in cpu_data if c['status'] != 'OK']
        if not cpu_data:
            if args.format == 'json':
                print("[]")
            else:
                print("All CPUs OK")
            return 0

    # Output results
    if args.format == 'json':
        output_json(cpu_data)
    elif args.format == 'table':
        output_table(cpu_data)
    else:
        output_plain(cpu_data, verbose=args.verbose)

    # Determine exit code
    has_warnings = any(c['status'] != 'OK' for c in cpu_data)
    return 1 if has_warnings else 0


if __name__ == '__main__':
    sys.exit(main())
