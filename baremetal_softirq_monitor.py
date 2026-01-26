#!/usr/bin/env python3
"""
Monitor softirq activity and detect CPU imbalance or overload.

This script analyzes software interrupt (softirq) statistics from /proc/softirqs
to identify CPU cores that are overloaded with interrupt processing. This is
critical for diagnosing:

- Network performance issues (NET_RX/NET_TX bottlenecks)
- Storage I/O latency (BLOCK softirqs)
- Timer-related jitter (TIMER, HRTIMER)
- CPU imbalance in interrupt handling
- RCU callback storms
- Tasklet processing delays

High softirq activity on specific CPUs can cause:
- Increased latency for applications pinned to those CPUs
- Network packet drops due to processing delays
- Uneven CPU utilization across cores
- Application jitter in latency-sensitive workloads

Softirq types monitored:
- HI: High-priority tasklets
- TIMER: Timer interrupt processing
- NET_TX: Network transmit processing
- NET_RX: Network receive processing
- BLOCK: Block device I/O completion
- IRQ_POLL: IRQ polling
- TASKLET: Low-priority tasklets
- SCHED: Scheduler-related processing
- HRTIMER: High-resolution timers
- RCU: Read-Copy-Update callbacks

Exit codes:
    0 - No issues detected (balanced softirq distribution)
    1 - Warnings detected (imbalanced or high softirq activity)
    2 - Usage error or /proc filesystem not available
"""

import argparse
import sys
import os
import json
import time
from collections import defaultdict


def read_softirqs():
    """Read softirq counters from /proc/softirqs.

    Returns:
        dict: Nested dict of {softirq_type: {cpu_id: count}}
    """
    softirqs = defaultdict(dict)

    try:
        with open('/proc/softirqs', 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("Error: /proc/softirqs not found (non-Linux system?)", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Permission denied reading /proc/softirqs", file=sys.stderr)
        sys.exit(2)

    if not lines:
        return softirqs

    # First line contains CPU headers
    header = lines[0].strip().split()
    cpu_count = len(header)  # CPU0, CPU1, etc.

    # Parse each softirq type
    for line in lines[1:]:
        parts = line.strip().split()
        if len(parts) < 2:
            continue

        irq_type = parts[0].rstrip(':')
        counts = parts[1:]

        for i, count in enumerate(counts):
            if i < cpu_count:
                try:
                    softirqs[irq_type][i] = int(count)
                except ValueError:
                    softirqs[irq_type][i] = 0

    return softirqs


def get_cpu_count():
    """Get number of CPU cores."""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            return sum(1 for line in f if line.startswith('processor'))
    except Exception:
        return os.cpu_count() or 1


def calculate_rates(before, after, interval):
    """Calculate per-second rates between two snapshots.

    Args:
        before: First softirq snapshot
        after: Second softirq snapshot
        interval: Time in seconds between snapshots

    Returns:
        dict: Rates per softirq type per CPU
    """
    rates = defaultdict(dict)

    for irq_type in after:
        for cpu in after[irq_type]:
            before_count = before.get(irq_type, {}).get(cpu, 0)
            after_count = after[irq_type][cpu]
            delta = after_count - before_count
            if delta < 0:
                delta = 0  # Counter wrapped
            rates[irq_type][cpu] = delta / interval

    return rates


def analyze_softirqs(softirqs, rates, imbalance_threshold, rate_threshold):
    """Analyze softirq distribution for issues.

    Args:
        softirqs: Current softirq counts
        rates: Softirq rates per second (if available)
        imbalance_threshold: Ratio threshold for CPU imbalance
        rate_threshold: Rate threshold for high activity warning

    Returns:
        list: List of detected issues
    """
    issues = []
    cpu_count = get_cpu_count()

    # Key softirq types to monitor closely
    critical_types = ['NET_RX', 'NET_TX', 'BLOCK', 'TIMER', 'RCU']

    for irq_type in softirqs:
        counts = softirqs[irq_type]
        if not counts:
            continue

        total = sum(counts.values())
        if total == 0:
            continue

        # Calculate per-CPU percentage
        cpu_percentages = {cpu: (count / total * 100) if total > 0 else 0
                          for cpu, count in counts.items()}

        # Check for imbalance (one CPU handling much more than others)
        if cpu_count > 1 and len(counts) > 1:
            avg_percentage = 100.0 / cpu_count
            max_cpu = max(cpu_percentages.items(), key=lambda x: x[1])
            min_cpu = min(cpu_percentages.items(), key=lambda x: x[1])

            # Detect imbalance: max CPU handles significantly more than average
            if max_cpu[1] > avg_percentage * imbalance_threshold:
                severity = 'WARNING' if irq_type in critical_types else 'INFO'
                issues.append({
                    'severity': severity,
                    'type': 'imbalance',
                    'irq_type': irq_type,
                    'cpu': max_cpu[0],
                    'percentage': round(max_cpu[1], 1),
                    'expected': round(avg_percentage, 1),
                    'message': f"{irq_type}: CPU{max_cpu[0]} handles {max_cpu[1]:.1f}% "
                              f"(expected ~{avg_percentage:.1f}% per CPU)"
                })

    # Check rates for high activity
    if rates:
        for irq_type in rates:
            for cpu, rate in rates[irq_type].items():
                if rate > rate_threshold:
                    severity = 'WARNING' if irq_type in critical_types else 'INFO'
                    issues.append({
                        'severity': severity,
                        'type': 'high_rate',
                        'irq_type': irq_type,
                        'cpu': cpu,
                        'rate': round(rate, 1),
                        'threshold': rate_threshold,
                        'message': f"{irq_type}: CPU{cpu} processing {rate:.0f}/s "
                                  f"(threshold: {rate_threshold}/s)"
                    })

        # Check for NET_RX/NET_TX asymmetry (indicates RSS/RPS issues)
        if 'NET_RX' in rates and 'NET_TX' in rates:
            rx_rates = rates['NET_RX']
            tx_rates = rates['NET_TX']

            # Find CPUs with high RX but very low TX or vice versa
            for cpu in set(rx_rates.keys()) | set(tx_rates.keys()):
                rx = rx_rates.get(cpu, 0)
                tx = tx_rates.get(cpu, 0)

                # Check if one direction is heavily loaded while other is idle
                if rx > rate_threshold / 2 and tx < rx / 10:
                    issues.append({
                        'severity': 'INFO',
                        'type': 'asymmetry',
                        'irq_type': 'NET_RX/TX',
                        'cpu': cpu,
                        'rx_rate': round(rx, 1),
                        'tx_rate': round(tx, 1),
                        'message': f"CPU{cpu}: RX={rx:.0f}/s TX={tx:.0f}/s - "
                                  f"consider RSS/RPS tuning"
                    })

    return issues


def output_plain(softirqs, rates, issues, cpu_count, verbose, warn_only):
    """Output results in plain text format."""
    if warn_only and not issues:
        return

    if not warn_only:
        print(f"CPU Count: {cpu_count}")
        print(f"Softirq Types: {len(softirqs)}")
        print()

        if verbose:
            # Show per-type totals
            print("Softirq Totals:")
            print("=" * 50)
            for irq_type in sorted(softirqs.keys()):
                total = sum(softirqs[irq_type].values())
                print(f"  {irq_type:<15} {total:>15,}")
            print()

            if rates:
                print("Current Rates (per second):")
                print("=" * 70)
                print(f"{'Type':<12}", end='')
                for cpu in range(min(cpu_count, 8)):
                    print(f"{'CPU' + str(cpu):>8}", end='')
                if cpu_count > 8:
                    print("  ...", end='')
                print()
                print("-" * 70)

                for irq_type in ['NET_RX', 'NET_TX', 'BLOCK', 'TIMER', 'SCHED', 'RCU']:
                    if irq_type in rates:
                        print(f"{irq_type:<12}", end='')
                        for cpu in range(min(cpu_count, 8)):
                            rate = rates[irq_type].get(cpu, 0)
                            if rate >= 1000:
                                print(f"{rate/1000:>7.1f}K", end='')
                            else:
                                print(f"{rate:>8.0f}", end='')
                        print()
                print()

    if issues:
        print(f"Found {len(issues)} issue(s):")
        print("=" * 60)
        for issue in sorted(issues, key=lambda x: (x['severity'] != 'WARNING', x['type'])):
            severity_marker = "[!]" if issue['severity'] == 'WARNING' else "[i]"
            print(f"{severity_marker} {issue['message']}")
        print()
    elif not warn_only:
        print("No softirq issues detected.")


def output_json(softirqs, rates, issues, cpu_count):
    """Output results in JSON format."""
    # Calculate totals per type
    totals = {irq_type: sum(counts.values())
              for irq_type, counts in softirqs.items()}

    # Calculate total rates if available
    rate_totals = {}
    if rates:
        rate_totals = {irq_type: sum(r.values())
                       for irq_type, r in rates.items()}

    output = {
        'summary': {
            'cpu_count': cpu_count,
            'softirq_types': len(softirqs),
            'issue_count': len(issues),
            'warning_count': sum(1 for i in issues if i['severity'] == 'WARNING'),
        },
        'totals': totals,
        'issues': issues
    }

    if rates:
        output['rates'] = {
            irq_type: {f'cpu{cpu}': round(rate, 1) for cpu, rate in r.items()}
            for irq_type, r in rates.items()
        }
        output['rate_totals'] = {k: round(v, 1) for k, v in rate_totals.items()}

    print(json.dumps(output, indent=2))


def output_table(softirqs, rates, issues, cpu_count, warn_only):
    """Output results in table format."""
    if warn_only and not issues:
        return

    if not warn_only and rates:
        # Show rate table for critical softirq types
        print("=" * 80)
        print("SOFTIRQ RATES (per second)")
        print("=" * 80)

        # Header
        print(f"{'Type':<12}", end='')
        for cpu in range(min(cpu_count, 8)):
            print(f"{'CPU' + str(cpu):>9}", end='')
        print(f"{'Total':>10}")
        print("-" * 80)

        # Data rows for key types
        for irq_type in ['NET_RX', 'NET_TX', 'BLOCK', 'TIMER', 'SCHED', 'RCU', 'TASKLET']:
            if irq_type in rates:
                print(f"{irq_type:<12}", end='')
                total = 0
                for cpu in range(min(cpu_count, 8)):
                    rate = rates[irq_type].get(cpu, 0)
                    total += rate
                    if rate >= 1000:
                        print(f"{rate/1000:>8.1f}K", end='')
                    else:
                        print(f"{rate:>9.0f}", end='')
                if total >= 1000:
                    print(f"{total/1000:>9.1f}K")
                else:
                    print(f"{total:>10.0f}")

        print("=" * 80)
        print()

    if issues:
        print("ISSUES DETECTED")
        print("=" * 80)
        print(f"{'Severity':<10} {'Type':<15} {'IRQ':<10} {'Details':<40}")
        print("-" * 80)
        for issue in issues:
            details = f"CPU{issue.get('cpu', '?')}"
            if 'percentage' in issue:
                details += f" ({issue['percentage']:.1f}%)"
            elif 'rate' in issue:
                details += f" ({issue['rate']:.0f}/s)"
            print(f"{issue['severity']:<10} {issue['type']:<15} "
                  f"{issue['irq_type']:<10} {details:<40}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor softirq activity and detect CPU imbalance or overload',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Snapshot of current softirq distribution
  %(prog)s --interval 2              # Monitor rates over 2 second interval
  %(prog)s --format json             # JSON output for automation
  %(prog)s --imbalance 3.0           # Alert if CPU handles 3x expected load
  %(prog)s --rate-threshold 50000    # Alert if rate exceeds 50k/s
  %(prog)s -v --interval 1           # Verbose output with 1s rate sampling

Softirq types explained:
  NET_RX    Network receive processing (most critical for servers)
  NET_TX    Network transmit processing
  BLOCK     Block device I/O completion
  TIMER     Timer interrupt processing
  SCHED     Scheduler load balancing
  RCU       Read-Copy-Update callbacks
  TASKLET   Deferred work processing
  HRTIMER   High-resolution timer processing

Common issues:
  - Imbalanced NET_RX: Configure RSS (Receive Side Scaling)
  - High RCU rates: Possible RCU callback storm
  - Single CPU overload: Check IRQ affinity settings

Exit codes:
  0 - No issues detected
  1 - Warnings detected (imbalance or high activity)
  2 - Usage error or /proc unavailable
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
        help='Show detailed softirq information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    parser.add_argument(
        '-i', '--interval',
        type=float,
        default=0,
        metavar='SECONDS',
        help='Sampling interval to calculate rates (default: snapshot only)'
    )

    parser.add_argument(
        '--imbalance',
        type=float,
        default=2.5,
        metavar='RATIO',
        help='Imbalance ratio threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--rate-threshold',
        type=int,
        default=100000,
        metavar='COUNT',
        help='Rate threshold per CPU for warnings (default: %(default)s/s)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.interval < 0:
        print("Error: --interval must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.imbalance <= 1:
        print("Error: --imbalance must be greater than 1", file=sys.stderr)
        sys.exit(2)

    if args.rate_threshold <= 0:
        print("Error: --rate-threshold must be positive", file=sys.stderr)
        sys.exit(2)

    # Check /proc availability
    if not os.path.exists('/proc/softirqs'):
        print("Error: /proc/softirqs not found", file=sys.stderr)
        print("This script requires Linux procfs", file=sys.stderr)
        sys.exit(2)

    cpu_count = get_cpu_count()

    # Read softirq data
    rates = None
    if args.interval > 0:
        # Take two snapshots to calculate rates
        before = read_softirqs()
        time.sleep(args.interval)
        after = read_softirqs()
        rates = calculate_rates(before, after, args.interval)
        softirqs = after
    else:
        softirqs = read_softirqs()

    # Analyze for issues
    issues = analyze_softirqs(softirqs, rates, args.imbalance, args.rate_threshold)

    # Output results
    if args.format == 'json':
        output_json(softirqs, rates, issues, cpu_count)
    elif args.format == 'table':
        output_table(softirqs, rates, issues, cpu_count, args.warn_only)
    else:  # plain
        output_plain(softirqs, rates, issues, cpu_count, args.verbose, args.warn_only)

    # Exit based on findings
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)
    sys.exit(1 if has_warnings else 0)


if __name__ == '__main__':
    main()
