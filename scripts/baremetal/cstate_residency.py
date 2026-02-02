#!/usr/bin/env python3
# boxctl:
#   category: baremetal/power
#   tags: [power, cpu, cstate, idle, energy]
#   requires: []
#   privilege: user
#   related: [cpu_usage, thermal_zone]
#   brief: Monitor CPU C-state residency for power management analysis

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

Returns exit code 1 if potential issues detected (low deep sleep residency).
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_cpuidle_available(context: Context) -> bool:
    """Check if cpuidle interface is available."""
    return context.file_exists('/sys/devices/system/cpu/cpu0/cpuidle')


def get_cpuidle_driver(context: Context) -> str:
    """Get the current cpuidle driver name."""
    path = '/sys/devices/system/cpu/cpuidle/current_driver'
    if context.file_exists(path):
        try:
            return context.read_file(path).strip()
        except Exception:
            pass
    return 'unknown'


def get_cpuidle_governor(context: Context) -> str:
    """Get the current cpuidle governor name."""
    path = '/sys/devices/system/cpu/cpuidle/current_governor'
    if context.file_exists(path):
        try:
            return context.read_file(path).strip()
        except Exception:
            pass
    return 'unknown'


def get_cpu_count(context: Context) -> int:
    """Get the number of CPUs in the system."""
    cpu_dirs = context.glob('cpu[0-9]*', '/sys/devices/system/cpu')
    return len(cpu_dirs)


def get_cstate_info(cpu_num: int, context: Context) -> dict[str, Any] | None:
    """Get C-state information for a specific CPU."""
    base_path = f'/sys/devices/system/cpu/cpu{cpu_num}/cpuidle'

    if not context.file_exists(base_path):
        return None

    states = []
    state_dirs = context.glob('state[0-9]*', base_path)

    for state_dir in sorted(state_dirs):
        state_info = {}

        # State name (e.g., POLL, C1, C1E, C3, C6, etc.)
        name_path = f'{state_dir}/name'
        if context.file_exists(name_path):
            try:
                state_info['name'] = context.read_file(name_path).strip()
            except Exception:
                state_info['name'] = state_dir.split('/')[-1]
        else:
            state_info['name'] = state_dir.split('/')[-1]

        # Time spent in this state (microseconds)
        time_path = f'{state_dir}/time'
        if context.file_exists(time_path):
            try:
                state_info['time_us'] = int(context.read_file(time_path).strip())
            except Exception:
                pass

        # Number of times this state was entered
        usage_path = f'{state_dir}/usage'
        if context.file_exists(usage_path):
            try:
                state_info['usage'] = int(context.read_file(usage_path).strip())
            except Exception:
                pass

        # Is this state disabled?
        disable_path = f'{state_dir}/disable'
        if context.file_exists(disable_path):
            try:
                state_info['disabled'] = context.read_file(disable_path).strip() == '1'
            except Exception:
                state_info['disabled'] = False
        else:
            state_info['disabled'] = False

        # Latency to enter this state (microseconds)
        latency_path = f'{state_dir}/latency'
        if context.file_exists(latency_path):
            try:
                state_info['latency_us'] = int(context.read_file(latency_path).strip())
            except Exception:
                pass

        states.append(state_info)

    return {
        'cpu': cpu_num,
        'states': states,
    }


def calculate_residency_percentages(cpu_data: list[dict[str, Any]]) -> None:
    """Calculate C-state residency percentages for each CPU."""
    for cpu in cpu_data:
        total_time = sum(s.get('time_us', 0) for s in cpu['states'])

        for state in cpu['states']:
            if total_time > 0 and 'time_us' in state:
                state['percentage'] = (state['time_us'] / total_time) * 100
            else:
                state['percentage'] = 0.0


def analyze_cstate_issues(
    cpu_data: list[dict[str, Any]],
    min_deep_residency: float = 10.0,
) -> list[dict[str, Any]]:
    """Analyze C-state data for potential issues."""
    issues = []

    for cpu in cpu_data:
        # Check for CPUs with no deep C-state residency
        deep_states = [
            s for s in cpu['states']
            if s['name'] not in ('POLL', 'C0', 'C1') and not s.get('disabled')
        ]

        if deep_states:
            deep_residency = sum(s.get('percentage', 0) for s in deep_states)
            if deep_residency < min_deep_residency:
                issues.append({
                    'cpu': cpu['cpu'],
                    'type': 'low_deep_residency',
                    'message': f"CPU {cpu['cpu']}: Only {deep_residency:.1f}% time in deep C-states",
                    'severity': 'WARNING',
                })

        # Check for disabled states
        disabled = [s['name'] for s in cpu['states'] if s.get('disabled')]
        if disabled:
            issues.append({
                'cpu': cpu['cpu'],
                'type': 'disabled_states',
                'message': f"CPU {cpu['cpu']}: States disabled: {', '.join(disabled)}",
                'severity': 'WARNING',
            })

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor CPU C-state residency")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed per-CPU info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument(
        "--min-deep-residency",
        type=float,
        default=10.0,
        metavar="PCT",
        help="Minimum deep C-state residency percentage before warning (default: 10)"
    )
    opts = parser.parse_args(args)

    # Check if cpuidle is available
    if not check_cpuidle_available(context):
        output.error("CPU idle state interface not available")
        output.error("Requires kernel CONFIG_CPU_IDLE and intel_idle or acpi_idle driver")
        return 2

    # Get driver and governor info
    driver = get_cpuidle_driver(context)
    governor = get_cpuidle_governor(context)

    # Get CPU count
    cpu_count = get_cpu_count(context)
    if cpu_count == 0:
        output.error("Could not determine CPU count")
        return 2

    # Gather C-state information for all CPUs
    cpu_data = []
    for cpu_num in range(cpu_count):
        cpu_info = get_cstate_info(cpu_num, context)
        if cpu_info and cpu_info['states']:
            cpu_data.append(cpu_info)

    if not cpu_data:
        output.error("Could not read C-state information")
        return 2

    # Calculate residency percentages
    calculate_residency_percentages(cpu_data)

    # Analyze for issues
    issues = analyze_cstate_issues(cpu_data, opts.min_deep_residency)

    # Build output data
    data = {
        'driver': driver,
        'governor': governor,
        'cpu_count': len(cpu_data),
        'issues': issues,
    }

    # Calculate average residency across all CPUs
    if cpu_data and cpu_data[0]['states']:
        state_names = [s['name'] for s in cpu_data[0]['states']]
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

        data['average_residency'] = avg_residency

    if opts.verbose:
        data['cpus'] = cpu_data

    output.emit(data)

    # Generate summary
    if issues:
        output.set_summary(f"{len(issues)} power efficiency issues")
    else:
        output.set_summary(f"{len(cpu_data)} CPUs, {driver} driver")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
