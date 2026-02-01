#!/usr/bin/env python3
"""
Monitor Linux softnet backlog statistics for network packet processing issues.

The softnet subsystem handles incoming network packets via per-CPU queues.
When these queues overflow or processing stalls, packets are dropped silently
without generating ICMP errors, making issues hard to diagnose.

This script monitors /proc/net/softnet_stat for:
- Packet processing counts per CPU
- Drops due to queue overflow (netdev_budget exhausted)
- Time squeeze events (CPU couldn't process all packets in time slice)
- Flow limit drops (per-flow rate limiting)
- Backlog length growth trends
- CPU imbalance in packet processing

Common causes of softnet issues:
- High packet rates overwhelming CPU capacity
- IRQ affinity misconfiguration (all packets hitting one CPU)
- netdev_budget too low for workload
- Interrupt coalescing misconfigured
- Network driver bugs or performance issues

Remediation:
- Increase netdev_budget: sysctl -w net.core.netdev_budget=600
- Increase backlog: sysctl -w net.core.netdev_max_backlog=2000
- Configure RPS/RFS for better CPU distribution
- Check IRQ affinity and balance with irqbalance
- Consider network driver tuning (ring buffer sizes)

Exit codes:
    0 - Softnet statistics healthy, no drops or squeezes
    1 - Drops or time squeezes detected (warning or critical)
    2 - Cannot read /proc/net/softnet_stat or usage error
"""

import argparse
import sys
import json
import os
from collections import defaultdict


def read_softnet_stat():
    """
    Read and parse /proc/net/softnet_stat.

    Each line represents a CPU and contains space-separated hex values:
    Column 0: total packets processed
    Column 1: dropped packets (queue full)
    Column 2: time_squeeze (ran out of time budget)
    Column 3-8: varies by kernel version
    Column 9 (if present): cpu_collision
    Column 10 (if present): received_rps
    Column 11 (if present): flow_limit_count

    Returns:
        list: List of dicts with per-CPU statistics, or None on error
    """
    stats = []

    try:
        with open('/proc/net/softnet_stat', 'r') as f:
            for cpu_idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue

                fields = line.split()
                if len(fields) < 3:
                    continue

                try:
                    cpu_stat = {
                        'cpu': cpu_idx,
                        'processed': int(fields[0], 16),
                        'dropped': int(fields[1], 16),
                        'time_squeeze': int(fields[2], 16),
                    }

                    # Optional fields depending on kernel version
                    if len(fields) > 9:
                        cpu_stat['cpu_collision'] = int(fields[9], 16)
                    if len(fields) > 10:
                        cpu_stat['received_rps'] = int(fields[10], 16)
                    if len(fields) > 11:
                        cpu_stat['flow_limit_count'] = int(fields[11], 16)

                    stats.append(cpu_stat)
                except (ValueError, IndexError):
                    continue

        return stats

    except FileNotFoundError:
        return None
    except PermissionError:
        return None


def get_kernel_settings():
    """
    Read relevant sysctl settings for softnet.

    Returns:
        dict: Dictionary of kernel settings
    """
    settings = {}

    paths = {
        'netdev_budget': '/proc/sys/net/core/netdev_budget',
        'netdev_budget_usecs': '/proc/sys/net/core/netdev_budget_usecs',
        'netdev_max_backlog': '/proc/sys/net/core/netdev_max_backlog',
        'rps_sock_flow_entries': '/proc/sys/net/core/rps_sock_flow_entries',
        'flow_limit_cpu_bitmap': '/proc/sys/net/core/flow_limit_cpu_bitmap',
    }

    for name, path in paths.items():
        try:
            with open(path, 'r') as f:
                value = f.read().strip()
                try:
                    settings[name] = int(value)
                except ValueError:
                    settings[name] = value
        except (FileNotFoundError, PermissionError):
            pass

    return settings


def calculate_totals(cpu_stats):
    """
    Calculate aggregate statistics across all CPUs.

    Args:
        cpu_stats: List of per-CPU stat dictionaries

    Returns:
        dict: Aggregate statistics
    """
    totals = {
        'total_processed': 0,
        'total_dropped': 0,
        'total_time_squeeze': 0,
        'total_flow_limit': 0,
        'cpu_count': len(cpu_stats),
    }

    for stat in cpu_stats:
        totals['total_processed'] += stat.get('processed', 0)
        totals['total_dropped'] += stat.get('dropped', 0)
        totals['total_time_squeeze'] += stat.get('time_squeeze', 0)
        totals['total_flow_limit'] += stat.get('flow_limit_count', 0)

    return totals


def detect_cpu_imbalance(cpu_stats, threshold_ratio=10):
    """
    Detect significant imbalance in packet processing across CPUs.

    Args:
        cpu_stats: List of per-CPU stat dictionaries
        threshold_ratio: Max/min ratio threshold for imbalance

    Returns:
        dict or None: Imbalance info if detected, None otherwise
    """
    if len(cpu_stats) < 2:
        return None

    processed_counts = [s.get('processed', 0) for s in cpu_stats]
    if not processed_counts:
        return None

    max_processed = max(processed_counts)
    min_processed = min(processed_counts)

    # Avoid division by zero; skip if all zeros
    if min_processed == 0:
        if max_processed > 0:
            return {
                'max_cpu': processed_counts.index(max_processed),
                'max_processed': max_processed,
                'min_cpu': processed_counts.index(min_processed),
                'min_processed': min_processed,
                'ratio': float('inf'),
            }
        return None

    ratio = max_processed / min_processed

    if ratio > threshold_ratio:
        return {
            'max_cpu': processed_counts.index(max_processed),
            'max_processed': max_processed,
            'min_cpu': processed_counts.index(min_processed),
            'min_processed': min_processed,
            'ratio': ratio,
        }

    return None


def analyze_stats(cpu_stats, totals, settings, drop_warn, drop_crit,
                  squeeze_warn, squeeze_crit):
    """
    Analyze softnet statistics and generate issues.

    Args:
        cpu_stats: Per-CPU statistics
        totals: Aggregate totals
        settings: Kernel settings
        drop_warn: Warning threshold for drops
        drop_crit: Critical threshold for drops
        squeeze_warn: Warning threshold for time squeezes
        squeeze_crit: Critical threshold for time squeezes

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    # Check total drops
    if totals['total_dropped'] >= drop_crit:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'packet_drops',
            'value': totals['total_dropped'],
            'message': f"Critical packet drops detected: {totals['total_dropped']:,} "
                      f"packets dropped due to backlog overflow"
        })
    elif totals['total_dropped'] >= drop_warn:
        issues.append({
            'severity': 'WARNING',
            'type': 'packet_drops',
            'value': totals['total_dropped'],
            'message': f"Packet drops detected: {totals['total_dropped']:,} "
                      f"packets dropped due to backlog overflow"
        })

    # Check time squeeze events
    if totals['total_time_squeeze'] >= squeeze_crit:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'time_squeeze',
            'value': totals['total_time_squeeze'],
            'message': f"Critical time squeeze events: {totals['total_time_squeeze']:,} "
                      f"(CPU couldn't keep up with packet rate)"
        })
    elif totals['total_time_squeeze'] >= squeeze_warn:
        issues.append({
            'severity': 'WARNING',
            'type': 'time_squeeze',
            'value': totals['total_time_squeeze'],
            'message': f"Time squeeze events detected: {totals['total_time_squeeze']:,} "
                      f"(CPU processing budget exhausted)"
        })

    # Check flow limit drops
    if totals['total_flow_limit'] > 0:
        issues.append({
            'severity': 'WARNING',
            'type': 'flow_limit',
            'value': totals['total_flow_limit'],
            'message': f"Flow limit drops: {totals['total_flow_limit']:,} "
                      f"(per-flow rate limiting triggered)"
        })

    # Check for CPU imbalance
    imbalance = detect_cpu_imbalance(cpu_stats)
    if imbalance:
        issues.append({
            'severity': 'WARNING',
            'type': 'cpu_imbalance',
            'max_cpu': imbalance['max_cpu'],
            'min_cpu': imbalance['min_cpu'],
            'ratio': imbalance['ratio'],
            'message': f"CPU packet processing imbalance: CPU{imbalance['max_cpu']} "
                      f"processed {imbalance['ratio']:.1f}x more than CPU{imbalance['min_cpu']} "
                      f"(check IRQ affinity or enable RPS)"
        })

    # Check for small netdev_budget (common misconfiguration)
    if settings.get('netdev_budget') and settings['netdev_budget'] < 300:
        if totals['total_time_squeeze'] > 0:
            issues.append({
                'severity': 'WARNING',
                'type': 'low_budget',
                'value': settings['netdev_budget'],
                'message': f"netdev_budget is low ({settings['netdev_budget']}) and "
                          f"time squeezes detected. Consider: sysctl -w net.core.netdev_budget=600"
            })

    # Check for small backlog queue
    if settings.get('netdev_max_backlog') and settings['netdev_max_backlog'] < 1000:
        if totals['total_dropped'] > 0:
            issues.append({
                'severity': 'WARNING',
                'type': 'low_backlog',
                'value': settings['netdev_max_backlog'],
                'message': f"netdev_max_backlog is low ({settings['netdev_max_backlog']}) and "
                          f"drops detected. Consider: sysctl -w net.core.netdev_max_backlog=2000"
            })

    # Check per-CPU for concentrated issues
    for stat in cpu_stats:
        if stat['dropped'] > drop_crit and stat['dropped'] > totals['total_dropped'] * 0.5:
            issues.append({
                'severity': 'CRITICAL',
                'type': 'cpu_drops',
                'cpu': stat['cpu'],
                'value': stat['dropped'],
                'message': f"CPU{stat['cpu']} has majority of drops ({stat['dropped']:,}). "
                          f"Check IRQ affinity for network interfaces"
            })
            break  # Only report once

    return issues


def format_plain(cpu_stats, totals, settings, issues, verbose=False, warn_only=False):
    """Format output as plain text."""
    lines = []

    if warn_only and not issues:
        return "No softnet issues detected"

    if not warn_only:
        lines.append("Softnet Backlog Statistics")
        lines.append("=" * 60)
        lines.append("")

        # Kernel settings
        lines.append("Kernel Settings:")
        lines.append(f"  netdev_budget:      {settings.get('netdev_budget', 'N/A'):>10}")
        lines.append(f"  netdev_max_backlog: {settings.get('netdev_max_backlog', 'N/A'):>10}")
        if 'netdev_budget_usecs' in settings:
            lines.append(f"  netdev_budget_usecs:{settings['netdev_budget_usecs']:>10}")
        lines.append("")

        # Aggregate stats
        lines.append("Aggregate Statistics:")
        lines.append(f"  Packets processed:  {totals['total_processed']:>15,}")
        lines.append(f"  Packets dropped:    {totals['total_dropped']:>15,}")
        lines.append(f"  Time squeezes:      {totals['total_time_squeeze']:>15,}")
        if totals['total_flow_limit'] > 0:
            lines.append(f"  Flow limit drops:   {totals['total_flow_limit']:>15,}")
        lines.append("")

        # Per-CPU stats
        if verbose or len(cpu_stats) <= 8:
            lines.append("Per-CPU Statistics:")
            lines.append(f"  {'CPU':<6} {'Processed':>15} {'Dropped':>12} {'Squeeze':>12}")
            lines.append("  " + "-" * 47)

            for stat in cpu_stats:
                lines.append(f"  {stat['cpu']:<6} {stat['processed']:>15,} "
                           f"{stat['dropped']:>12,} {stat['time_squeeze']:>12,}")
            lines.append("")
        else:
            # Just show CPUs with issues
            problem_cpus = [s for s in cpu_stats
                          if s['dropped'] > 0 or s['time_squeeze'] > 0]
            if problem_cpus:
                lines.append("CPUs with issues:")
                for stat in problem_cpus[:5]:
                    lines.append(f"  CPU{stat['cpu']}: {stat['dropped']:,} drops, "
                               f"{stat['time_squeeze']:,} squeezes")
                lines.append("")

    # Issues
    if issues:
        lines.append("Issues Detected:")
        lines.append("-" * 60)
        for issue in sorted(issues, key=lambda x: x['severity'] != 'CRITICAL'):
            marker = "!!!" if issue['severity'] == 'CRITICAL' else " ! "
            lines.append(f"{marker} [{issue['severity']}] {issue['message']}")
        lines.append("")

        # Remediation hints
        lines.append("Remediation:")
        if any(i['type'] in ('packet_drops', 'low_backlog') for i in issues):
            lines.append("  Increase backlog queue:")
            lines.append("    sysctl -w net.core.netdev_max_backlog=2000")
        if any(i['type'] in ('time_squeeze', 'low_budget') for i in issues):
            lines.append("  Increase processing budget:")
            lines.append("    sysctl -w net.core.netdev_budget=600")
        if any(i['type'] == 'cpu_imbalance' for i in issues):
            lines.append("  Enable Receive Packet Steering (RPS):")
            lines.append("    echo 'ff' > /sys/class/net/<iface>/queues/rx-0/rps_cpus")
            lines.append("  Or check IRQ affinity with irqbalance")
    elif not warn_only:
        lines.append("Status: Softnet statistics healthy")

    return '\n'.join(lines)


def format_json(cpu_stats, totals, settings, issues):
    """Format output as JSON."""
    output = {
        'settings': settings,
        'totals': totals,
        'per_cpu': cpu_stats,
        'issues': issues,
        'healthy': len([i for i in issues if i['severity'] == 'CRITICAL']) == 0
                   and totals['total_dropped'] == 0
                   and totals['total_time_squeeze'] == 0,
    }
    return json.dumps(output, indent=2)


def format_table(cpu_stats, totals, settings, issues):
    """Format output as a table."""
    lines = []

    lines.append(f"{'Metric':<30} {'Value':>15}")
    lines.append("=" * 47)

    lines.append(f"{'CPU Count':<30} {totals['cpu_count']:>15}")
    lines.append(f"{'Total Processed':<30} {totals['total_processed']:>15,}")
    lines.append(f"{'Total Dropped':<30} {totals['total_dropped']:>15,}")
    lines.append(f"{'Total Time Squeezes':<30} {totals['total_time_squeeze']:>15,}")

    lines.append("")
    lines.append(f"{'Setting':<30} {'Value':>15}")
    lines.append("-" * 47)
    lines.append(f"{'netdev_budget':<30} {settings.get('netdev_budget', 'N/A'):>15}")
    lines.append(f"{'netdev_max_backlog':<30} {settings.get('netdev_max_backlog', 'N/A'):>15}")

    if issues:
        lines.append("")
        lines.append("Issues:")
        for issue in issues:
            lines.append(f"  [{issue['severity']}] {issue['message']}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Linux softnet backlog statistics for packet processing issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic softnet monitoring
  %(prog)s -v                       # Show all per-CPU statistics
  %(prog)s --format json            # JSON output for scripting
  %(prog)s --warn-only              # Only show if issues detected
  %(prog)s --drop-warn 100          # Alert on 100+ drops

Common causes of softnet issues:
  - High packet rate overwhelming CPU
  - IRQ affinity misconfiguration
  - Small netdev_budget or netdev_max_backlog
  - Network driver performance issues

Exit codes:
  0 - Softnet statistics healthy
  1 - Drops or time squeezes detected
  2 - Cannot read /proc/net/softnet_stat
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
        help='Show all per-CPU statistics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if issues are detected'
    )

    parser.add_argument(
        '--drop-warn',
        type=int,
        default=1,
        metavar='N',
        help='Warning threshold for packet drops (default: %(default)s)'
    )

    parser.add_argument(
        '--drop-crit',
        type=int,
        default=1000,
        metavar='N',
        help='Critical threshold for packet drops (default: %(default)s)'
    )

    parser.add_argument(
        '--squeeze-warn',
        type=int,
        default=1,
        metavar='N',
        help='Warning threshold for time squeezes (default: %(default)s)'
    )

    parser.add_argument(
        '--squeeze-crit',
        type=int,
        default=1000,
        metavar='N',
        help='Critical threshold for time squeezes (default: %(default)s)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.drop_warn < 0 or args.drop_crit < 0:
        print("Error: Drop thresholds must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.squeeze_warn < 0 or args.squeeze_crit < 0:
        print("Error: Squeeze thresholds must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.drop_warn > args.drop_crit:
        print("Error: --drop-warn must be less than or equal to --drop-crit",
              file=sys.stderr)
        sys.exit(2)

    if args.squeeze_warn > args.squeeze_crit:
        print("Error: --squeeze-warn must be less than or equal to --squeeze-crit",
              file=sys.stderr)
        sys.exit(2)

    # Read softnet statistics
    cpu_stats = read_softnet_stat()

    if cpu_stats is None:
        print("Error: Cannot read /proc/net/softnet_stat", file=sys.stderr)
        print("This script requires a Linux system with softnet statistics",
              file=sys.stderr)
        sys.exit(2)

    if not cpu_stats:
        print("Error: No softnet statistics found", file=sys.stderr)
        sys.exit(2)

    # Get kernel settings
    settings = get_kernel_settings()

    # Calculate totals
    totals = calculate_totals(cpu_stats)

    # Analyze statistics
    issues = analyze_stats(cpu_stats, totals, settings,
                          args.drop_warn, args.drop_crit,
                          args.squeeze_warn, args.squeeze_crit)

    # Handle warn-only mode with no issues
    if args.warn_only and not issues:
        if args.format == 'json':
            print(json.dumps({'healthy': True, 'issues': []}))
        sys.exit(0)

    # Format output
    if args.format == 'json':
        output = format_json(cpu_stats, totals, settings, issues)
    elif args.format == 'table':
        output = format_table(cpu_stats, totals, settings, issues)
    else:
        output = format_plain(cpu_stats, totals, settings, issues,
                             verbose=args.verbose, warn_only=args.warn_only)

    print(output)

    # Exit code based on issues
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
