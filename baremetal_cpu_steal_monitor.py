#!/usr/bin/env python3
"""
Monitor CPU steal time for virtualized environments.

CPU steal time represents the percentage of time a virtual CPU waits for a real
CPU while the hypervisor is servicing another virtual processor. High steal time
indicates the physical host is overcommitted and your VM is not getting its fair
share of CPU resources.

This is critical for:
- Cloud instances (AWS, GCP, Azure) where noisy neighbors steal CPU
- Virtualized datacenters running on overcommitted hypervisors
- Detecting hypervisor resource contention before it impacts applications
- Capacity planning for VM density on physical hosts

Metrics tracked:
- Per-CPU steal percentage from /proc/stat
- System-wide average steal time
- Steal time trends over sampling interval
- CPU utilization breakdown (user, system, idle, iowait, steal)

When to worry about steal time:
- < 5%: Normal for virtualized environments
- 5-10%: Elevated, monitor closely
- 10-20%: High, consider migrating or resizing VM
- > 20%: Critical, VM is severely resource-starved

Exit codes:
    0 - Steal time within acceptable limits
    1 - High steal time detected (exceeds warning threshold)
    2 - Usage error or /proc filesystem not available
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


def read_proc_stat() -> Optional[List[str]]:
    """Read /proc/stat and return lines."""
    try:
        with open('/proc/stat', 'r') as f:
            return f.readlines()
    except (OSError, IOError, PermissionError):
        return None


def parse_cpu_line(line: str) -> Optional[Dict[str, int]]:
    """Parse a CPU line from /proc/stat.

    Format: cpu[N] user nice system idle iowait irq softirq steal guest guest_nice
    All values are in jiffies (typically 1/100th of a second).
    """
    parts = line.split()
    if len(parts) < 5:
        return None

    cpu_name = parts[0]
    try:
        values = [int(x) for x in parts[1:]]
    except ValueError:
        return None

    # Ensure we have enough fields (steal is field 8, index 7)
    while len(values) < 10:
        values.append(0)

    return {
        'cpu': cpu_name,
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


def get_cpu_stats() -> Dict[str, Dict[str, int]]:
    """Get CPU statistics from /proc/stat."""
    lines = read_proc_stat()
    if not lines:
        return {}

    stats = {}
    for line in lines:
        if line.startswith('cpu'):
            parsed = parse_cpu_line(line)
            if parsed:
                stats[parsed['cpu']] = parsed

    return stats


def calculate_percentages(before: Dict[str, int], after: Dict[str, int]) -> Dict[str, float]:
    """Calculate CPU percentage breakdown between two samples."""
    # Calculate deltas
    delta = {}
    for key in ['user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal', 'guest', 'guest_nice']:
        delta[key] = max(0, after.get(key, 0) - before.get(key, 0))

    # Total CPU time
    total = sum(delta.values())
    if total == 0:
        return {key: 0.0 for key in delta}

    # Calculate percentages
    return {key: (value / total) * 100 for key, value in delta.items()}


def analyze_steal(before_stats: Dict, after_stats: Dict,
                  warn_threshold: float, crit_threshold: float) -> Dict[str, Any]:
    """Analyze steal time across all CPUs."""
    analysis = {
        'timestamp': datetime.now().isoformat(),
        'cpus': {},
        'summary': {},
        'issues': [],
        'warnings': [],
    }

    steal_values = []
    all_percentages = []

    for cpu_name in sorted(after_stats.keys()):
        if cpu_name not in before_stats:
            continue

        percentages = calculate_percentages(before_stats[cpu_name], after_stats[cpu_name])
        steal_pct = percentages['steal']

        analysis['cpus'][cpu_name] = {
            'user': round(percentages['user'], 2),
            'nice': round(percentages['nice'], 2),
            'system': round(percentages['system'], 2),
            'idle': round(percentages['idle'], 2),
            'iowait': round(percentages['iowait'], 2),
            'irq': round(percentages['irq'], 2),
            'softirq': round(percentages['softirq'], 2),
            'steal': round(steal_pct, 2),
            'guest': round(percentages['guest'], 2),
        }

        # Track individual CPU steals (excluding aggregate 'cpu')
        if cpu_name != 'cpu':
            steal_values.append(steal_pct)
            all_percentages.append(percentages)

            # Check for per-CPU issues
            if steal_pct >= crit_threshold:
                analysis['issues'].append({
                    'cpu': cpu_name,
                    'severity': 'critical',
                    'steal_pct': round(steal_pct, 2),
                    'message': f'{cpu_name}: steal time {steal_pct:.1f}% (critical threshold: {crit_threshold}%)',
                })
            elif steal_pct >= warn_threshold:
                analysis['warnings'].append({
                    'cpu': cpu_name,
                    'severity': 'warning',
                    'steal_pct': round(steal_pct, 2),
                    'message': f'{cpu_name}: steal time {steal_pct:.1f}% (warning threshold: {warn_threshold}%)',
                })

    # Calculate summary statistics
    if steal_values:
        avg_steal = sum(steal_values) / len(steal_values)
        max_steal = max(steal_values)
        min_steal = min(steal_values)

        analysis['summary'] = {
            'cpu_count': len(steal_values),
            'avg_steal_pct': round(avg_steal, 2),
            'max_steal_pct': round(max_steal, 2),
            'min_steal_pct': round(min_steal, 2),
            'warn_threshold': warn_threshold,
            'crit_threshold': crit_threshold,
        }

        # Check aggregate steal
        if 'cpu' in analysis['cpus']:
            aggregate_steal = analysis['cpus']['cpu']['steal']
            analysis['summary']['aggregate_steal_pct'] = aggregate_steal

            if aggregate_steal >= crit_threshold:
                analysis['issues'].insert(0, {
                    'cpu': 'aggregate',
                    'severity': 'critical',
                    'steal_pct': round(aggregate_steal, 2),
                    'message': f'System-wide steal time {aggregate_steal:.1f}% exceeds critical threshold ({crit_threshold}%)',
                })
            elif aggregate_steal >= warn_threshold:
                analysis['warnings'].insert(0, {
                    'cpu': 'aggregate',
                    'severity': 'warning',
                    'steal_pct': round(aggregate_steal, 2),
                    'message': f'System-wide steal time {aggregate_steal:.1f}% exceeds warning threshold ({warn_threshold}%)',
                })

    return analysis


def output_plain(analysis: Dict, verbose: bool, warn_only: bool) -> None:
    """Output results in plain text format."""
    if warn_only and not analysis['issues'] and not analysis['warnings']:
        return

    summary = analysis.get('summary', {})
    aggregate = analysis['cpus'].get('cpu', {})

    print("CPU Steal Time Monitor")
    print("=" * 60)
    print()

    # Show issues first
    if analysis['issues']:
        print("CRITICAL:")
        for issue in analysis['issues']:
            print(f"  [!!] {issue['message']}")
        print()

    if analysis['warnings']:
        print("WARNINGS:")
        for warning in analysis['warnings']:
            print(f"  [!] {warning['message']}")
        print()

    if not warn_only:
        # System summary
        if aggregate:
            print("System-wide CPU usage:")
            print(f"  User:     {aggregate.get('user', 0):>6.1f}%")
            print(f"  System:   {aggregate.get('system', 0):>6.1f}%")
            print(f"  Idle:     {aggregate.get('idle', 0):>6.1f}%")
            print(f"  I/O Wait: {aggregate.get('iowait', 0):>6.1f}%")
            print(f"  Steal:    {aggregate.get('steal', 0):>6.1f}%")
            if aggregate.get('irq', 0) > 0 or aggregate.get('softirq', 0) > 0:
                print(f"  IRQ:      {aggregate.get('irq', 0):>6.1f}%")
                print(f"  SoftIRQ:  {aggregate.get('softirq', 0):>6.1f}%")
            print()

        if summary:
            print(f"Steal time statistics ({summary.get('cpu_count', 0)} CPUs):")
            print(f"  Average: {summary.get('avg_steal_pct', 0):.2f}%")
            print(f"  Maximum: {summary.get('max_steal_pct', 0):.2f}%")
            print(f"  Minimum: {summary.get('min_steal_pct', 0):.2f}%")
            print()

        if verbose:
            # Per-CPU breakdown
            print("Per-CPU steal time:")
            print("-" * 60)
            print(f"{'CPU':<8} {'User':>8} {'System':>8} {'Idle':>8} {'IOWait':>8} {'Steal':>8}")
            print("-" * 60)

            for cpu_name, data in sorted(analysis['cpus'].items()):
                if cpu_name == 'cpu':
                    continue  # Skip aggregate in per-CPU list
                print(f"{cpu_name:<8} {data['user']:>7.1f}% {data['system']:>7.1f}% "
                      f"{data['idle']:>7.1f}% {data['iowait']:>7.1f}% {data['steal']:>7.1f}%")
            print()

    if not analysis['issues'] and not analysis['warnings']:
        steal = summary.get('aggregate_steal_pct', summary.get('avg_steal_pct', 0))
        print(f"Status: OK - Steal time {steal:.1f}% is within acceptable limits")


def output_json(analysis: Dict) -> None:
    """Output results in JSON format."""
    has_issues = len(analysis['issues']) > 0
    has_warnings = len(analysis['warnings']) > 0

    if has_issues:
        status = 'critical'
    elif has_warnings:
        status = 'warning'
    else:
        status = 'ok'

    result = {
        'timestamp': analysis['timestamp'],
        'status': status,
        'summary': analysis['summary'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'cpus': analysis['cpus'],
    }

    print(json.dumps(result, indent=2))


def output_table(analysis: Dict, warn_only: bool) -> None:
    """Output results in table format."""
    if warn_only and not analysis['issues'] and not analysis['warnings']:
        print("No CPU steal time issues detected")
        return

    print(f"{'CPU':<8} {'User':>8} {'System':>8} {'Idle':>8} {'IOWait':>8} {'Steal':>8} {'Status':<10}")
    print("=" * 70)

    for cpu_name, data in sorted(analysis['cpus'].items()):
        # Determine status
        status = 'OK'
        for issue in analysis['issues']:
            if issue['cpu'] == cpu_name or (cpu_name == 'cpu' and issue['cpu'] == 'aggregate'):
                status = 'CRITICAL'
                break
        if status == 'OK':
            for warning in analysis['warnings']:
                if warning['cpu'] == cpu_name or (cpu_name == 'cpu' and warning['cpu'] == 'aggregate'):
                    status = 'WARNING'
                    break

        label = 'TOTAL' if cpu_name == 'cpu' else cpu_name
        print(f"{label:<8} {data['user']:>7.1f}% {data['system']:>7.1f}% "
              f"{data['idle']:>7.1f}% {data['iowait']:>7.1f}% {data['steal']:>7.1f}% {status:<10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor CPU steal time for virtualized environments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Quick steal time check (1 second sample)
  %(prog)s --interval 5           Sample for 5 seconds (more accurate)
  %(prog)s --format json          Output in JSON for monitoring systems
  %(prog)s --warn-only            Only show output if thresholds exceeded
  %(prog)s --warn 5 --crit 15     Custom warning/critical thresholds
  %(prog)s --verbose              Show per-CPU breakdown

What is CPU steal time?
  Steal time occurs when a hypervisor takes CPU cycles away from your VM
  to service other VMs on the same physical host. It indicates your VM
  is not getting the CPU resources it was allocated.

Steal time interpretation:
  < 5%%   - Normal for shared virtualized environments
  5-10%%  - Elevated, may impact latency-sensitive applications
  10-20%% - High, application performance likely degraded
  > 20%%  - Critical, VM is severely CPU-starved

Remediation options:
  - Request VM migration to less loaded host
  - Upgrade to dedicated/reserved CPU instances
  - Resize VM to get more CPU allocation
  - Contact cloud provider about noisy neighbors
  - Consider moving workload to dedicated hardware

Exit codes:
  0 - Steal time within acceptable limits
  1 - High steal time detected (exceeds threshold)
  2 - Usage error or /proc filesystem unavailable
"""
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed per-CPU breakdown'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if thresholds exceeded'
    )

    parser.add_argument(
        '--interval',
        type=float,
        default=1.0,
        metavar='SECS',
        help='Sampling interval in seconds (default: 1.0)'
    )

    parser.add_argument(
        '--warn',
        type=float,
        default=5.0,
        metavar='PCT',
        help='Warning threshold percentage (default: 5.0)'
    )

    parser.add_argument(
        '--crit',
        type=float,
        default=15.0,
        metavar='PCT',
        help='Critical threshold percentage (default: 15.0)'
    )

    args = parser.parse_args()

    # Validate interval
    if args.interval <= 0:
        print("Error: Interval must be positive", file=sys.stderr)
        sys.exit(2)
    if args.interval > 300:
        print("Error: Interval cannot exceed 300 seconds", file=sys.stderr)
        sys.exit(2)

    # Validate thresholds
    if args.warn < 0 or args.warn > 100:
        print("Error: --warn must be 0-100", file=sys.stderr)
        sys.exit(2)

    if args.crit < 0 or args.crit > 100:
        print("Error: --crit must be 0-100", file=sys.stderr)
        sys.exit(2)

    if args.warn >= args.crit:
        print("Error: --warn must be less than --crit", file=sys.stderr)
        sys.exit(2)

    # Check for /proc filesystem
    if not os.path.isdir('/proc'):
        print("Error: /proc filesystem not available", file=sys.stderr)
        print("This script requires a Linux system with procfs", file=sys.stderr)
        sys.exit(2)

    # Check for /proc/stat
    if not os.path.exists('/proc/stat'):
        print("Error: /proc/stat not available", file=sys.stderr)
        sys.exit(2)

    # Take first sample
    before_stats = get_cpu_stats()
    if not before_stats:
        print("Error: Unable to read CPU statistics from /proc/stat", file=sys.stderr)
        sys.exit(2)

    # Wait for sampling interval
    time.sleep(args.interval)

    # Take second sample
    after_stats = get_cpu_stats()
    if not after_stats:
        print("Error: Unable to read CPU statistics for second sample", file=sys.stderr)
        sys.exit(2)

    # Analyze steal time
    analysis = analyze_steal(before_stats, after_stats, args.warn, args.crit)

    # Output results
    if args.format == 'json':
        output_json(analysis)
    elif args.format == 'table':
        output_table(analysis, args.warn_only)
    else:
        output_plain(analysis, args.verbose, args.warn_only)

    # Determine exit code
    if analysis['issues']:
        sys.exit(1)
    elif analysis['warnings']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
