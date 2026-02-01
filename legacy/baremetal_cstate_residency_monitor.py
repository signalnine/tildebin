#!/usr/bin/env python3
"""
Monitor CPU C-state residency on baremetal systems.

Monitors CPU idle states (C-states) to analyze power management effectiveness.
C-states represent different levels of CPU power saving, from C0 (active) to
deeper states like C1, C3, C6, etc. Understanding C-state residency helps
identify power management issues, thermal problems, or workloads that prevent
efficient power saving.

Useful for:
  - Validating power management configuration in datacenters
  - Identifying CPUs stuck in shallow C-states (wasting power)
  - Detecting workloads preventing deep sleep states
  - Capacity planning for power budgets

Exit codes:
    0 - Success (C-state data retrieved)
    1 - Warning (potential issues detected, e.g., no deep sleep residency)
    2 - Usage error or missing dependencies (no cpuidle support)
"""

import argparse
import glob
import json
import os
import sys


def check_cpuidle_available():
    """Check if cpuidle interface is available."""
    return os.path.exists('/sys/devices/system/cpu/cpu0/cpuidle')


def read_sysfs_file(path):
    """Read a sysfs file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError, PermissionError):
        return None


def get_cpu_count():
    """Get the number of CPUs in the system."""
    cpu_dirs = glob.glob('/sys/devices/system/cpu/cpu[0-9]*')
    return len(cpu_dirs)


def get_cstate_info(cpu_num):
    """
    Get C-state information for a specific CPU.

    Returns dict with C-state names, residency times, and usage counts.
    """
    base_path = f'/sys/devices/system/cpu/cpu{cpu_num}/cpuidle'

    if not os.path.exists(base_path):
        return None

    states = []
    state_dirs = sorted(glob.glob(f'{base_path}/state[0-9]*'))

    for state_dir in state_dirs:
        state_info = {}

        # State name (e.g., POLL, C1, C1E, C3, C6, etc.)
        name = read_sysfs_file(f'{state_dir}/name')
        if name:
            state_info['name'] = name
        else:
            state_info['name'] = os.path.basename(state_dir)

        # Description
        desc = read_sysfs_file(f'{state_dir}/desc')
        if desc:
            state_info['desc'] = desc

        # Latency to enter this state (microseconds)
        latency = read_sysfs_file(f'{state_dir}/latency')
        if latency:
            state_info['latency_us'] = int(latency)

        # Residency requirement (microseconds) - minimum time to make entering worthwhile
        residency = read_sysfs_file(f'{state_dir}/residency')
        if residency:
            state_info['residency_us'] = int(residency)

        # Time spent in this state (microseconds)
        time_us = read_sysfs_file(f'{state_dir}/time')
        if time_us:
            state_info['time_us'] = int(time_us)

        # Number of times this state was entered
        usage = read_sysfs_file(f'{state_dir}/usage')
        if usage:
            state_info['usage'] = int(usage)

        # Is this state disabled?
        disabled = read_sysfs_file(f'{state_dir}/disable')
        state_info['disabled'] = disabled == '1' if disabled else False

        states.append(state_info)

    return {
        'cpu': cpu_num,
        'states': states
    }


def get_cpuidle_driver():
    """Get the current cpuidle driver name."""
    driver = read_sysfs_file('/sys/devices/system/cpu/cpuidle/current_driver')
    return driver or 'unknown'


def get_cpuidle_governor():
    """Get the current cpuidle governor name."""
    governor = read_sysfs_file('/sys/devices/system/cpu/cpuidle/current_governor')
    return governor or 'unknown'


def calculate_residency_percentages(cpu_data):
    """
    Calculate C-state residency percentages for each CPU.

    Adds 'percentage' field to each state showing time spent in that state
    relative to total idle time.
    """
    for cpu in cpu_data:
        total_time = sum(s.get('time_us', 0) for s in cpu['states'])

        for state in cpu['states']:
            if total_time > 0 and 'time_us' in state:
                state['percentage'] = (state['time_us'] / total_time) * 100
            else:
                state['percentage'] = 0.0


def analyze_cstate_issues(cpu_data, min_deep_residency=10.0):
    """
    Analyze C-state data for potential issues.

    Returns list of issues found.
    """
    issues = []

    # Check for CPUs with no deep C-state residency
    for cpu in cpu_data:
        deep_states = [s for s in cpu['states']
                       if s['name'] not in ('POLL', 'C0', 'C1') and not s.get('disabled')]

        if deep_states:
            deep_residency = sum(s.get('percentage', 0) for s in deep_states)
            if deep_residency < min_deep_residency:
                issues.append({
                    'cpu': cpu['cpu'],
                    'type': 'low_deep_residency',
                    'message': f"CPU {cpu['cpu']}: Only {deep_residency:.1f}% time in deep C-states"
                })

        # Check for disabled states
        disabled = [s['name'] for s in cpu['states'] if s.get('disabled')]
        if disabled:
            issues.append({
                'cpu': cpu['cpu'],
                'type': 'disabled_states',
                'message': f"CPU {cpu['cpu']}: States disabled: {', '.join(disabled)}"
            })

    return issues


def format_time(microseconds):
    """Format microseconds into human-readable time."""
    if microseconds is None:
        return 'N/A'

    if microseconds < 1000:
        return f"{microseconds} us"
    elif microseconds < 1000000:
        return f"{microseconds/1000:.1f} ms"
    elif microseconds < 60000000:
        return f"{microseconds/1000000:.2f} s"
    elif microseconds < 3600000000:
        return f"{microseconds/60000000:.1f} min"
    else:
        return f"{microseconds/3600000000:.1f} hr"


def output_plain(cpu_data, driver, governor, issues, verbose=False, warn_only=False):
    """Output results in plain text format."""
    if warn_only and not issues:
        print("All CPUs have healthy C-state residency")
        return

    # Summary header
    print(f"CPU Idle Driver: {driver}")
    print(f"CPU Idle Governor: {governor}")
    print(f"CPUs: {len(cpu_data)}")
    print()

    # Aggregate C-state summary across all CPUs
    if cpu_data:
        # Get state names from first CPU (assume all CPUs have same states)
        state_names = [s['name'] for s in cpu_data[0]['states']]

        # Calculate average residency per state
        avg_residency = {}
        for state_name in state_names:
            percentages = []
            for cpu in cpu_data:
                for state in cpu['states']:
                    if state['name'] == state_name:
                        percentages.append(state.get('percentage', 0))
                        break
            if percentages:
                avg_residency[state_name] = sum(percentages) / len(percentages)

        print("Average C-State Residency:")
        for state_name in state_names:
            pct = avg_residency.get(state_name, 0)
            bar_len = int(pct / 2)  # Scale to 50 chars max
            bar = '#' * bar_len
            print(f"  {state_name:8} {pct:5.1f}% {bar}")
        print()

    # Show issues
    if issues:
        print(f"Issues Detected ({len(issues)}):")
        for issue in issues:
            print(f"  [WARN] {issue['message']}")
        print()

    # Verbose: per-CPU details
    if verbose:
        print("Per-CPU C-State Details:")
        print("-" * 70)
        for cpu in cpu_data:
            print(f"\nCPU {cpu['cpu']}:")
            for state in cpu['states']:
                disabled = " [DISABLED]" if state.get('disabled') else ""
                pct = state.get('percentage', 0)
                time_str = format_time(state.get('time_us'))
                usage = state.get('usage', 0)
                latency = state.get('latency_us', 0)
                print(f"  {state['name']:8} {pct:5.1f}% | "
                      f"time: {time_str:>10} | "
                      f"entries: {usage:>10} | "
                      f"latency: {latency:>5} us{disabled}")


def output_json(cpu_data, driver, governor, issues):
    """Output results in JSON format."""
    result = {
        'driver': driver,
        'governor': governor,
        'cpu_count': len(cpu_data),
        'cpus': cpu_data,
        'issues': issues
    }
    print(json.dumps(result, indent=2))


def output_table(cpu_data, driver, governor, warn_only=False):
    """Output results in table format."""
    if not cpu_data:
        print("No C-state data available")
        return

    # Get state names from first CPU
    state_names = [s['name'] for s in cpu_data[0]['states']]

    # Header
    header = f"{'CPU':<5}"
    for name in state_names:
        header += f" {name:>8}"
    print(header)
    print("-" * len(header))

    # Per-CPU rows showing residency percentages
    for cpu in cpu_data:
        row = f"{cpu['cpu']:<5}"
        for state in cpu['states']:
            pct = state.get('percentage', 0)
            disabled = '*' if state.get('disabled') else ''
            row += f" {pct:>7.1f}{disabled}"
        print(row)

    print()
    print(f"Driver: {driver}, Governor: {governor}")
    print("* = state disabled")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor CPU C-state residency on baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check C-state residency summary
  %(prog)s

  # Show detailed per-CPU information
  %(prog)s --verbose

  # Only show CPUs with potential issues
  %(prog)s --warn-only

  # Output in JSON format for automation
  %(prog)s --format json

  # Custom threshold for deep sleep warning (default 10%%)
  %(prog)s --min-deep-residency 5

Exit codes:
  0 - C-state data retrieved successfully
  1 - Issues detected (low deep sleep residency, disabled states)
  2 - Usage error or no cpuidle support
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
        help='Show detailed per-CPU C-state information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings or issues'
    )

    parser.add_argument(
        '--min-deep-residency',
        type=float,
        default=10.0,
        metavar='PCT',
        help='Minimum deep C-state residency percentage before warning (default: %(default)s)'
    )

    args = parser.parse_args()

    # Check if cpuidle is available
    if not check_cpuidle_available():
        print("Error: CPU idle state interface not available", file=sys.stderr)
        print("", file=sys.stderr)
        print("This system may not support cpuidle or the required", file=sys.stderr)
        print("kernel modules are not loaded. Check:", file=sys.stderr)
        print("  - Kernel config: CONFIG_CPU_IDLE=y", file=sys.stderr)
        print("  - Driver loaded: intel_idle or acpi_idle", file=sys.stderr)
        sys.exit(2)

    # Get driver and governor info
    driver = get_cpuidle_driver()
    governor = get_cpuidle_governor()

    # Get CPU count
    cpu_count = get_cpu_count()
    if cpu_count == 0:
        print("Error: Could not determine CPU count", file=sys.stderr)
        sys.exit(2)

    # Gather C-state information for all CPUs
    cpu_data = []
    for cpu_num in range(cpu_count):
        cpu_info = get_cstate_info(cpu_num)
        if cpu_info and cpu_info['states']:
            cpu_data.append(cpu_info)

    if not cpu_data:
        print("Error: Could not read C-state information", file=sys.stderr)
        print("Ensure cpuidle is enabled and driver is loaded", file=sys.stderr)
        sys.exit(2)

    # Calculate residency percentages
    calculate_residency_percentages(cpu_data)

    # Analyze for issues
    issues = analyze_cstate_issues(cpu_data, args.min_deep_residency)

    # Output results
    if args.format == 'json':
        output_json(cpu_data, driver, governor, issues)
    elif args.format == 'table':
        output_table(cpu_data, driver, governor, args.warn_only)
    else:
        output_plain(cpu_data, driver, governor, issues, args.verbose, args.warn_only)

    # Exit code based on issues
    sys.exit(1 if issues else 0)


if __name__ == '__main__':
    main()
