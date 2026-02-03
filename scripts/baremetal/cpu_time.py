#!/usr/bin/env python3
# boxctl:
#   category: baremetal/performance
#   tags: [cpu, performance, monitoring, steal, iowait]
#   requires: []
#   privilege: none
#   related: [cpu_isolation, cpu_microcode, load_average]
#   brief: Analyze CPU time distribution across all CPUs

"""
Analyze CPU time distribution across all CPUs.

Monitors CPU time breakdown including user, system, iowait, steal, softirq,
and other states. Useful for identifying:
- Virtualization overhead (steal time)
- I/O bottlenecks (iowait)
- Interrupt storms (softirq/irq)
- System call overhead (system time)
- Per-CPU imbalances
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output

# Default thresholds
DEFAULT_THRESHOLDS = {
    'steal_warning': 5.0,
    'steal_critical': 15.0,
    'iowait_warning': 10.0,
    'iowait_critical': 25.0,
    'interrupt_warning': 10.0,
    'interrupt_critical': 25.0,
    'system_warning': 30.0,
    'system_critical': 50.0,
    'imbalance_warning': 40.0,
    'imbalance_critical': 60.0,
}


def parse_proc_stat(content: str) -> dict[str, dict[str, int]]:
    """Parse CPU statistics from /proc/stat content."""
    cpu_stats = {}

    for line in content.split('\n'):
        if not line.startswith('cpu'):
            continue

        parts = line.split()
        cpu_name = parts[0]
        # Fields: user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
        values = [int(x) for x in parts[1:]]

        # Pad with zeros if older kernel with fewer fields
        while len(values) < 10:
            values.append(0)

        cpu_stats[cpu_name] = {
            'user': values[0],
            'nice': values[1],
            'system': values[2],
            'idle': values[3],
            'iowait': values[4],
            'irq': values[5],
            'softirq': values[6],
            'steal': values[7],
            'guest': values[8],
            'guest_nice': values[9],
        }

    return cpu_stats


def calculate_percentages(stats: dict[str, dict[str, int]]) -> dict[str, dict[str, float]]:
    """Calculate percentage breakdown for each CPU."""
    results = {}

    for cpu_name, values in stats.items():
        total = sum(values.values())
        if total == 0:
            continue

        percentages = {}
        for key, value in values.items():
            percentages[key] = round((value / total) * 100, 2)

        # Calculate derived metrics
        percentages['total_busy'] = round(100 - percentages['idle'], 2)
        percentages['total_wait'] = round(percentages['iowait'] + percentages['steal'], 2)
        percentages['total_interrupt'] = round(percentages['irq'] + percentages['softirq'], 2)

        results[cpu_name] = percentages

    return results


def analyze_issues(percentages: dict, thresholds: dict) -> list[dict[str, Any]]:
    """Analyze CPU percentages for potential issues."""
    issues = []

    # Analyze aggregate CPU
    if 'cpu' in percentages:
        agg = percentages['cpu']

        if agg['steal'] >= thresholds['steal_critical']:
            issues.append({
                'severity': 'critical',
                'category': 'virtualization',
                'cpu': 'aggregate',
                'message': f"High steal time: {agg['steal']}% (threshold: {thresholds['steal_critical']}%)",
                'value': agg['steal'],
            })
        elif agg['steal'] >= thresholds['steal_warning']:
            issues.append({
                'severity': 'warning',
                'category': 'virtualization',
                'cpu': 'aggregate',
                'message': f"Elevated steal time: {agg['steal']}% (threshold: {thresholds['steal_warning']}%)",
                'value': agg['steal'],
            })

        if agg['iowait'] >= thresholds['iowait_critical']:
            issues.append({
                'severity': 'critical',
                'category': 'io',
                'cpu': 'aggregate',
                'message': f"High I/O wait: {agg['iowait']}% (threshold: {thresholds['iowait_critical']}%)",
                'value': agg['iowait'],
            })
        elif agg['iowait'] >= thresholds['iowait_warning']:
            issues.append({
                'severity': 'warning',
                'category': 'io',
                'cpu': 'aggregate',
                'message': f"Elevated I/O wait: {agg['iowait']}% (threshold: {thresholds['iowait_warning']}%)",
                'value': agg['iowait'],
            })

        if agg['total_interrupt'] >= thresholds['interrupt_critical']:
            issues.append({
                'severity': 'critical',
                'category': 'interrupt',
                'cpu': 'aggregate',
                'message': f"High interrupt time: {agg['total_interrupt']}% (threshold: {thresholds['interrupt_critical']}%)",
                'value': agg['total_interrupt'],
            })
        elif agg['total_interrupt'] >= thresholds['interrupt_warning']:
            issues.append({
                'severity': 'warning',
                'category': 'interrupt',
                'cpu': 'aggregate',
                'message': f"Elevated interrupt time: {agg['total_interrupt']}% (threshold: {thresholds['interrupt_warning']}%)",
                'value': agg['total_interrupt'],
            })

        if agg['system'] >= thresholds['system_critical']:
            issues.append({
                'severity': 'critical',
                'category': 'system',
                'cpu': 'aggregate',
                'message': f"High system time: {agg['system']}% (threshold: {thresholds['system_critical']}%)",
                'value': agg['system'],
            })
        elif agg['system'] >= thresholds['system_warning']:
            issues.append({
                'severity': 'warning',
                'category': 'system',
                'cpu': 'aggregate',
                'message': f"Elevated system time: {agg['system']}% (threshold: {thresholds['system_warning']}%)",
                'value': agg['system'],
            })

    # Check per-CPU imbalance
    per_cpu = {k: v for k, v in percentages.items() if k != 'cpu'}
    if len(per_cpu) > 1:
        busy_values = [v['total_busy'] for v in per_cpu.values()]
        if busy_values:
            max_busy = max(busy_values)
            min_busy = min(busy_values)
            spread = max_busy - min_busy

            if spread >= thresholds['imbalance_critical']:
                issues.append({
                    'severity': 'critical',
                    'category': 'imbalance',
                    'cpu': 'per-cpu',
                    'message': f"CPU load imbalance: {spread:.1f}% spread (max: {max_busy:.1f}%, min: {min_busy:.1f}%)",
                    'value': spread,
                })
            elif spread >= thresholds['imbalance_warning']:
                issues.append({
                    'severity': 'warning',
                    'category': 'imbalance',
                    'cpu': 'per-cpu',
                    'message': f"CPU load imbalance: {spread:.1f}% spread (max: {max_busy:.1f}%, min: {min_busy:.1f}%)",
                    'value': spread,
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
    parser = argparse.ArgumentParser(description="Analyze CPU time distribution")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show per-CPU breakdown")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")

    # Threshold arguments
    parser.add_argument("--steal-warn", type=float, default=DEFAULT_THRESHOLDS['steal_warning'],
                        metavar="PCT", help="Steal time warning threshold")
    parser.add_argument("--steal-crit", type=float, default=DEFAULT_THRESHOLDS['steal_critical'],
                        metavar="PCT", help="Steal time critical threshold")
    parser.add_argument("--iowait-warn", type=float, default=DEFAULT_THRESHOLDS['iowait_warning'],
                        metavar="PCT", help="I/O wait warning threshold")
    parser.add_argument("--iowait-crit", type=float, default=DEFAULT_THRESHOLDS['iowait_critical'],
                        metavar="PCT", help="I/O wait critical threshold")
    parser.add_argument("--system-warn", type=float, default=DEFAULT_THRESHOLDS['system_warning'],
                        metavar="PCT", help="System time warning threshold")
    parser.add_argument("--system-crit", type=float, default=DEFAULT_THRESHOLDS['system_critical'],
                        metavar="PCT", help="System time critical threshold")

    opts = parser.parse_args(args)

    # Build thresholds dict
    thresholds = {
        'steal_warning': opts.steal_warn,
        'steal_critical': opts.steal_crit,
        'iowait_warning': opts.iowait_warn,
        'iowait_critical': opts.iowait_crit,
        'system_warning': opts.system_warn,
        'system_critical': opts.system_crit,
        'interrupt_warning': DEFAULT_THRESHOLDS['interrupt_warning'],
        'interrupt_critical': DEFAULT_THRESHOLDS['interrupt_critical'],
        'imbalance_warning': DEFAULT_THRESHOLDS['imbalance_warning'],
        'imbalance_critical': DEFAULT_THRESHOLDS['imbalance_critical'],
    }

    # Read /proc/stat
    try:
        stat_content = context.read_file('/proc/stat')
    except FileNotFoundError:
        output.error("/proc/stat not found. This script requires a Linux system.")

        output.render(opts.format, "Analyze CPU time distribution across all CPUs")
        return 2
    except OSError as e:
        output.error(f"Cannot read /proc/stat: {e}")

        output.render(opts.format, "Analyze CPU time distribution across all CPUs")
        return 2

    # Parse and calculate
    stats = parse_proc_stat(stat_content)
    percentages = calculate_percentages(stats)

    if 'cpu' not in percentages:
        output.error("No CPU statistics available")

        output.render(opts.format, "Analyze CPU time distribution across all CPUs")
        return 2

    # Analyze
    issues = analyze_issues(percentages, thresholds)

    # Build result
    agg = percentages['cpu']
    result = {
        'aggregate': {
            'user': agg['user'],
            'system': agg['system'],
            'idle': agg['idle'],
            'iowait': agg['iowait'],
            'steal': agg['steal'],
            'irq': agg['irq'],
            'softirq': agg['softirq'],
            'total_busy': agg['total_busy'],
            'total_interrupt': agg['total_interrupt'],
        },
        'cpu_count': len([k for k in percentages if k != 'cpu']),
        'issues': issues,
    }

    if opts.verbose:
        result['per_cpu'] = {k: v for k, v in percentages.items() if k != 'cpu'}

    output.emit(result)

    # Set summary
    has_critical = any(i['severity'] == 'critical' for i in issues)
    has_warning = any(i['severity'] == 'warning' for i in issues)

    if has_critical:
        output.set_summary(f"critical CPU issues: {agg['total_busy']:.1f}% busy")
    elif has_warning:
        output.set_summary(f"CPU warnings: {agg['total_busy']:.1f}% busy")
    else:
        output.set_summary(f"CPU healthy: {agg['total_busy']:.1f}% busy, {agg['idle']:.1f}% idle")

    # Exit code
    if has_critical or has_warning:

        output.render(opts.format, "Analyze CPU time distribution across all CPUs")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
