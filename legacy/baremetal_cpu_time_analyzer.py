#!/usr/bin/env python3
"""
Analyze CPU time distribution across all CPUs.

Monitors CPU time breakdown including user, system, iowait, steal, softirq,
and other states. Useful for identifying:
- Virtualization overhead (steal time)
- I/O bottlenecks (iowait)
- Interrupt storms (softirq/irq)
- System call overhead (system time)
- Per-CPU imbalances

Exit codes:
    0 - No issues detected (all metrics within thresholds)
    1 - Warnings or issues detected (high steal, iowait, etc.)
    2 - Usage error or required files not available
"""

import argparse
import sys
import json
import os
from collections import defaultdict


def read_proc_stat():
    """Read CPU statistics from /proc/stat"""
    try:
        with open('/proc/stat', 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("Error: /proc/stat not found", file=sys.stderr)
        print("This script requires a Linux system", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Permission denied reading /proc/stat", file=sys.stderr)
        sys.exit(2)

    cpu_stats = {}
    for line in lines:
        if line.startswith('cpu'):
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


def calculate_percentages(stats):
    """Calculate percentage breakdown for each CPU"""
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


def analyze_issues(percentages, thresholds):
    """Analyze CPU percentages for potential issues"""
    issues = []

    # Analyze aggregate CPU
    if 'cpu' in percentages:
        agg = percentages['cpu']

        if agg['steal'] >= thresholds['steal_critical']:
            issues.append({
                'severity': 'CRITICAL',
                'category': 'virtualization',
                'cpu': 'aggregate',
                'message': f"High steal time: {agg['steal']}% (threshold: {thresholds['steal_critical']}%)",
                'value': agg['steal'],
            })
        elif agg['steal'] >= thresholds['steal_warning']:
            issues.append({
                'severity': 'WARNING',
                'category': 'virtualization',
                'cpu': 'aggregate',
                'message': f"Elevated steal time: {agg['steal']}% (threshold: {thresholds['steal_warning']}%)",
                'value': agg['steal'],
            })

        if agg['iowait'] >= thresholds['iowait_critical']:
            issues.append({
                'severity': 'CRITICAL',
                'category': 'io',
                'cpu': 'aggregate',
                'message': f"High I/O wait: {agg['iowait']}% (threshold: {thresholds['iowait_critical']}%)",
                'value': agg['iowait'],
            })
        elif agg['iowait'] >= thresholds['iowait_warning']:
            issues.append({
                'severity': 'WARNING',
                'category': 'io',
                'cpu': 'aggregate',
                'message': f"Elevated I/O wait: {agg['iowait']}% (threshold: {thresholds['iowait_warning']}%)",
                'value': agg['iowait'],
            })

        if agg['total_interrupt'] >= thresholds['interrupt_critical']:
            issues.append({
                'severity': 'CRITICAL',
                'category': 'interrupt',
                'cpu': 'aggregate',
                'message': f"High interrupt time: {agg['total_interrupt']}% (threshold: {thresholds['interrupt_critical']}%)",
                'value': agg['total_interrupt'],
            })
        elif agg['total_interrupt'] >= thresholds['interrupt_warning']:
            issues.append({
                'severity': 'WARNING',
                'category': 'interrupt',
                'cpu': 'aggregate',
                'message': f"Elevated interrupt time: {agg['total_interrupt']}% (threshold: {thresholds['interrupt_warning']}%)",
                'value': agg['total_interrupt'],
            })

        if agg['system'] >= thresholds['system_critical']:
            issues.append({
                'severity': 'CRITICAL',
                'category': 'system',
                'cpu': 'aggregate',
                'message': f"High system time: {agg['system']}% (threshold: {thresholds['system_critical']}%)",
                'value': agg['system'],
            })
        elif agg['system'] >= thresholds['system_warning']:
            issues.append({
                'severity': 'WARNING',
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
                    'severity': 'CRITICAL',
                    'category': 'imbalance',
                    'cpu': 'per-cpu',
                    'message': f"CPU load imbalance: {spread:.1f}% spread (max: {max_busy:.1f}%, min: {min_busy:.1f}%)",
                    'value': spread,
                })
            elif spread >= thresholds['imbalance_warning']:
                issues.append({
                    'severity': 'WARNING',
                    'category': 'imbalance',
                    'cpu': 'per-cpu',
                    'message': f"CPU load imbalance: {spread:.1f}% spread (max: {max_busy:.1f}%, min: {min_busy:.1f}%)",
                    'value': spread,
                })

    return issues


def output_plain(percentages, issues, verbose=False, warn_only=False):
    """Output results in plain text format"""
    if warn_only and not issues:
        return

    if not warn_only:
        # Show aggregate CPU breakdown
        if 'cpu' in percentages:
            agg = percentages['cpu']
            print("CPU Time Distribution (aggregate)")
            print("=" * 50)
            print(f"  User:      {agg['user']:6.2f}%")
            print(f"  Nice:      {agg['nice']:6.2f}%")
            print(f"  System:    {agg['system']:6.2f}%")
            print(f"  Idle:      {agg['idle']:6.2f}%")
            print(f"  I/O Wait:  {agg['iowait']:6.2f}%")
            print(f"  IRQ:       {agg['irq']:6.2f}%")
            print(f"  SoftIRQ:   {agg['softirq']:6.2f}%")
            print(f"  Steal:     {agg['steal']:6.2f}%")
            if agg['guest'] > 0:
                print(f"  Guest:     {agg['guest']:6.2f}%")
            print()
            print(f"  Total Busy:      {agg['total_busy']:6.2f}%")
            print(f"  Total Wait:      {agg['total_wait']:6.2f}%")
            print(f"  Total Interrupt: {agg['total_interrupt']:6.2f}%")
            print()

        if verbose:
            # Show per-CPU breakdown
            per_cpu = sorted(
                [(k, v) for k, v in percentages.items() if k != 'cpu'],
                key=lambda x: int(x[0].replace('cpu', ''))
            )
            if per_cpu:
                print("Per-CPU Breakdown")
                print("=" * 80)
                print(f"{'CPU':<8} {'User':>8} {'System':>8} {'Idle':>8} {'IOWait':>8} {'Steal':>8} {'IRQ':>8}")
                print("-" * 80)
                for cpu_name, stats in per_cpu:
                    print(f"{cpu_name:<8} {stats['user']:>7.1f}% {stats['system']:>7.1f}% "
                          f"{stats['idle']:>7.1f}% {stats['iowait']:>7.1f}% "
                          f"{stats['steal']:>7.1f}% {stats['total_interrupt']:>7.1f}%")
                print()

    # Show issues
    if issues:
        print("Issues Detected")
        print("=" * 50)
        for issue in sorted(issues, key=lambda x: (x['severity'] != 'CRITICAL', x['category'])):
            marker = "!!!" if issue['severity'] == 'CRITICAL' else "  "
            print(f"{marker} [{issue['severity']}] {issue['message']}")
    elif not warn_only:
        print("No issues detected")


def output_json(percentages, issues):
    """Output results in JSON format"""
    output = {
        'summary': {
            'cpu_count': len([k for k in percentages if k != 'cpu']),
            'issue_count': len(issues),
            'critical_count': sum(1 for i in issues if i['severity'] == 'CRITICAL'),
            'warning_count': sum(1 for i in issues if i['severity'] == 'WARNING'),
        },
        'aggregate': percentages.get('cpu', {}),
        'per_cpu': {k: v for k, v in percentages.items() if k != 'cpu'},
        'issues': issues,
    }
    print(json.dumps(output, indent=2))


def output_table(percentages, issues, warn_only=False):
    """Output results in table format"""
    if warn_only and not issues:
        return

    if not warn_only and 'cpu' in percentages:
        agg = percentages['cpu']
        print(f"{'Metric':<20} {'Value':>10} {'Status':<15}")
        print("=" * 45)

        def get_status(value, warn_thresh, crit_thresh):
            if value >= crit_thresh:
                return "CRITICAL"
            elif value >= warn_thresh:
                return "WARNING"
            return "OK"

        metrics = [
            ('User', agg['user'], 80, 95),
            ('System', agg['system'], 30, 50),
            ('I/O Wait', agg['iowait'], 10, 25),
            ('Steal', agg['steal'], 5, 15),
            ('IRQ + SoftIRQ', agg['total_interrupt'], 10, 25),
            ('Total Busy', agg['total_busy'], 80, 95),
        ]

        for name, value, warn, crit in metrics:
            status = get_status(value, warn, crit)
            print(f"{name:<20} {value:>9.2f}% {status:<15}")
        print()

    if issues:
        print(f"{'Severity':<10} {'Category':<15} {'Message':<50}")
        print("=" * 75)
        for issue in issues:
            print(f"{issue['severity']:<10} {issue['category']:<15} {issue['message'][:50]:<50}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Analyze CPU time distribution across all CPUs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic CPU time analysis
  %(prog)s -v                       # Show per-CPU breakdown
  %(prog)s --format json            # JSON output for scripting
  %(prog)s --steal-warn 3           # Lower steal time threshold
  %(prog)s --warn-only              # Only show issues

Metrics monitored:
  - User time: Time spent running user processes
  - System time: Time spent in kernel mode
  - I/O Wait: Time waiting for I/O operations
  - Steal: Time stolen by hypervisor (virtualization overhead)
  - IRQ/SoftIRQ: Time handling hardware/software interrupts
  - CPU imbalance: Uneven load distribution across CPUs
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
        help='Show per-CPU breakdown'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show issues, suppress normal output'
    )

    # Threshold arguments
    parser.add_argument(
        '--steal-warn',
        type=float,
        default=5.0,
        metavar='PCT',
        help='Steal time warning threshold (default: %(default)s%%)'
    )

    parser.add_argument(
        '--steal-crit',
        type=float,
        default=15.0,
        metavar='PCT',
        help='Steal time critical threshold (default: %(default)s%%)'
    )

    parser.add_argument(
        '--iowait-warn',
        type=float,
        default=10.0,
        metavar='PCT',
        help='I/O wait warning threshold (default: %(default)s%%)'
    )

    parser.add_argument(
        '--iowait-crit',
        type=float,
        default=25.0,
        metavar='PCT',
        help='I/O wait critical threshold (default: %(default)s%%)'
    )

    parser.add_argument(
        '--interrupt-warn',
        type=float,
        default=10.0,
        metavar='PCT',
        help='Interrupt time warning threshold (default: %(default)s%%)'
    )

    parser.add_argument(
        '--interrupt-crit',
        type=float,
        default=25.0,
        metavar='PCT',
        help='Interrupt time critical threshold (default: %(default)s%%)'
    )

    parser.add_argument(
        '--system-warn',
        type=float,
        default=30.0,
        metavar='PCT',
        help='System time warning threshold (default: %(default)s%%)'
    )

    parser.add_argument(
        '--system-crit',
        type=float,
        default=50.0,
        metavar='PCT',
        help='System time critical threshold (default: %(default)s%%)'
    )

    parser.add_argument(
        '--imbalance-warn',
        type=float,
        default=40.0,
        metavar='PCT',
        help='CPU imbalance warning threshold (default: %(default)s%%)'
    )

    parser.add_argument(
        '--imbalance-crit',
        type=float,
        default=60.0,
        metavar='PCT',
        help='CPU imbalance critical threshold (default: %(default)s%%)'
    )

    args = parser.parse_args()

    # Build thresholds dict
    thresholds = {
        'steal_warning': args.steal_warn,
        'steal_critical': args.steal_crit,
        'iowait_warning': args.iowait_warn,
        'iowait_critical': args.iowait_crit,
        'interrupt_warning': args.interrupt_warn,
        'interrupt_critical': args.interrupt_crit,
        'system_warning': args.system_warn,
        'system_critical': args.system_crit,
        'imbalance_warning': args.imbalance_warn,
        'imbalance_critical': args.imbalance_crit,
    }

    # Read and analyze CPU stats
    stats = read_proc_stat()
    percentages = calculate_percentages(stats)
    issues = analyze_issues(percentages, thresholds)

    # Output results
    if args.format == 'json':
        output_json(percentages, issues)
    elif args.format == 'table':
        output_table(percentages, issues, warn_only=args.warn_only)
    else:  # plain
        output_plain(percentages, issues, verbose=args.verbose, warn_only=args.warn_only)

    # Exit based on findings
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
