#!/usr/bin/env python3
"""
Analyze I/O latency patterns and identify slow storage operations.

This script monitors block device I/O latency by sampling /proc/diskstats
and calculating latency metrics over a configurable interval. It identifies
devices with high latency that may impact application performance.

Unlike iostat (which shows averages), this tool focuses on latency spikes
and patterns by taking multiple samples and calculating statistics.

Metrics tracked:
- Average I/O service time per device
- Read vs write latency comparison
- I/O time percentage (time spent doing I/O)
- Queue wait time estimation

Useful for:
- Identifying storage performance bottlenecks
- Detecting intermittent I/O latency spikes
- Comparing read vs write performance
- Pre-maintenance storage health verification
- Capacity planning based on I/O patterns

Exit codes:
    0 - All devices performing within thresholds
    1 - Latency warnings or issues detected
    2 - Usage error or missing data sources
"""

import argparse
import sys
import os
import json
import time
from collections import defaultdict


def read_diskstats():
    """
    Read /proc/diskstats and return parsed device statistics.

    /proc/diskstats format (kernel 4.18+):
    Field  1: major number
    Field  2: minor number
    Field  3: device name
    Field  4: reads completed
    Field  5: reads merged
    Field  6: sectors read
    Field  7: ms spent reading
    Field  8: writes completed
    Field  9: writes merged
    Field 10: sectors written
    Field 11: ms spent writing
    Field 12: I/Os in progress
    Field 13: ms doing I/O
    Field 14: weighted ms doing I/O
    Field 15+: discard/flush stats (kernel 4.18+)
    """
    stats = {}

    try:
        with open('/proc/diskstats', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 14:
                    continue

                device = parts[2]

                # Skip virtual devices by default
                if device.startswith(('loop', 'ram', 'dm-')):
                    continue

                # Skip partitions (we want whole devices)
                # Partitions have numbers at the end like sda1, nvme0n1p1
                # Keep nvme0n1 but skip nvme0n1p1
                if any(c.isdigit() for c in device):
                    # Check if it's an NVMe namespace (nvme0n1) vs partition (nvme0n1p1)
                    if 'nvme' in device:
                        if 'p' in device.split('n')[-1]:
                            continue
                    else:
                        # For traditional devices, skip if ends with digit
                        if device[-1].isdigit():
                            continue

                try:
                    stats[device] = {
                        'reads_completed': int(parts[3]),
                        'reads_merged': int(parts[4]),
                        'sectors_read': int(parts[5]),
                        'ms_reading': int(parts[6]),
                        'writes_completed': int(parts[7]),
                        'writes_merged': int(parts[8]),
                        'sectors_written': int(parts[9]),
                        'ms_writing': int(parts[10]),
                        'ios_in_progress': int(parts[11]),
                        'ms_doing_io': int(parts[12]),
                        'weighted_ms_doing_io': int(parts[13]),
                    }
                except (ValueError, IndexError):
                    continue

    except FileNotFoundError:
        return None
    except PermissionError:
        return None

    return stats


def calculate_latency_stats(before, after, interval_ms):
    """
    Calculate latency statistics from two diskstats samples.

    Returns dict with latency metrics per device.
    """
    results = {}

    for device in after:
        if device not in before:
            continue

        b = before[device]
        a = after[device]

        # Calculate deltas
        reads_delta = a['reads_completed'] - b['reads_completed']
        writes_delta = a['writes_completed'] - b['writes_completed']
        read_ms_delta = a['ms_reading'] - b['ms_reading']
        write_ms_delta = a['ms_writing'] - b['ms_writing']
        io_ms_delta = a['ms_doing_io'] - b['ms_doing_io']
        weighted_ms_delta = a['weighted_ms_doing_io'] - b['weighted_ms_doing_io']

        total_ios = reads_delta + writes_delta
        total_io_ms = read_ms_delta + write_ms_delta

        # Calculate average latency per I/O
        avg_read_latency_ms = 0.0
        avg_write_latency_ms = 0.0
        avg_io_latency_ms = 0.0

        if reads_delta > 0:
            avg_read_latency_ms = read_ms_delta / reads_delta

        if writes_delta > 0:
            avg_write_latency_ms = write_ms_delta / writes_delta

        if total_ios > 0:
            avg_io_latency_ms = total_io_ms / total_ios

        # Calculate utilization (% of time doing I/O)
        util_pct = (io_ms_delta / interval_ms) * 100.0 if interval_ms > 0 else 0.0
        util_pct = min(util_pct, 100.0)  # Cap at 100%

        # Calculate average queue depth from weighted time
        avg_queue_depth = 0.0
        if interval_ms > 0:
            avg_queue_depth = weighted_ms_delta / interval_ms

        results[device] = {
            'device': device,
            'reads': reads_delta,
            'writes': writes_delta,
            'total_ios': total_ios,
            'avg_read_latency_ms': round(avg_read_latency_ms, 2),
            'avg_write_latency_ms': round(avg_write_latency_ms, 2),
            'avg_io_latency_ms': round(avg_io_latency_ms, 2),
            'util_pct': round(util_pct, 1),
            'avg_queue_depth': round(avg_queue_depth, 2),
            'ios_in_progress': a['ios_in_progress'],
        }

    return results


def analyze_latency(stats, warn_latency_ms, crit_latency_ms, warn_util_pct):
    """
    Analyze latency statistics and identify issues.

    Returns list of issues found.
    """
    issues = []

    for device, data in stats.items():
        device_issues = []
        severity = 'OK'

        # Skip devices with no I/O activity
        if data['total_ios'] == 0:
            continue

        avg_latency = data['avg_io_latency_ms']
        read_latency = data['avg_read_latency_ms']
        write_latency = data['avg_write_latency_ms']
        util = data['util_pct']

        # Check overall latency
        if avg_latency >= crit_latency_ms:
            device_issues.append(
                f"CRITICAL: Average I/O latency {avg_latency:.1f}ms exceeds {crit_latency_ms}ms"
            )
            severity = 'CRITICAL'
        elif avg_latency >= warn_latency_ms:
            device_issues.append(
                f"WARNING: Average I/O latency {avg_latency:.1f}ms exceeds {warn_latency_ms}ms"
            )
            if severity == 'OK':
                severity = 'WARNING'

        # Check for read/write latency imbalance
        if read_latency > 0 and write_latency > 0:
            if read_latency > write_latency * 3:
                device_issues.append(
                    f"INFO: Read latency ({read_latency:.1f}ms) much higher than write ({write_latency:.1f}ms)"
                )
            elif write_latency > read_latency * 3:
                device_issues.append(
                    f"INFO: Write latency ({write_latency:.1f}ms) much higher than read ({read_latency:.1f}ms)"
                )

        # Check utilization
        if util >= 95:
            device_issues.append(
                f"CRITICAL: Device utilization at {util:.1f}% (saturated)"
            )
            severity = 'CRITICAL'
        elif util >= warn_util_pct:
            device_issues.append(
                f"WARNING: Device utilization at {util:.1f}%"
            )
            if severity == 'OK':
                severity = 'WARNING'

        # Check queue depth
        if data['avg_queue_depth'] > 32:
            device_issues.append(
                f"WARNING: High average queue depth {data['avg_queue_depth']:.1f}"
            )
            if severity == 'OK':
                severity = 'WARNING'

        if device_issues:
            issues.append({
                'device': device,
                'severity': severity,
                'issues': device_issues,
                'stats': data
            })

    return issues


def output_plain(stats, issues, warn_only=False, verbose=False):
    """Output results in plain text format."""
    lines = []

    if not warn_only:
        lines.append("Device I/O Latency Analysis:")
        lines.append("")

        for device, data in sorted(stats.items()):
            if data['total_ios'] == 0:
                if verbose:
                    lines.append(f"  {device}: no I/O activity")
                continue

            lines.append(
                f"  {device}: "
                f"lat={data['avg_io_latency_ms']:.1f}ms "
                f"(r={data['avg_read_latency_ms']:.1f}ms w={data['avg_write_latency_ms']:.1f}ms) "
                f"util={data['util_pct']:.0f}% "
                f"ios={data['total_ios']} "
                f"qdepth={data['avg_queue_depth']:.1f}"
            )

        lines.append("")

    if issues:
        critical = [i for i in issues if i['severity'] == 'CRITICAL']
        warnings = [i for i in issues if i['severity'] == 'WARNING']

        if critical:
            lines.append(f"CRITICAL Issues ({len(critical)}):")
            for issue in critical:
                lines.append(f"  {issue['device']}:")
                for msg in issue['issues']:
                    lines.append(f"    !!! {msg}")
            lines.append("")

        if warnings:
            lines.append(f"Warnings ({len(warnings)}):")
            for issue in warnings:
                lines.append(f"  {issue['device']}:")
                for msg in issue['issues']:
                    lines.append(f"    {msg}")
            lines.append("")
    elif not warn_only:
        lines.append("No latency issues detected.")

    return '\n'.join(lines)


def output_json(stats, issues):
    """Output results in JSON format."""
    result = {
        'devices': stats,
        'issues': issues,
        'summary': {
            'total_devices': len(stats),
            'devices_with_activity': len([d for d in stats.values() if d['total_ios'] > 0]),
            'total_issues': len(issues),
            'critical_count': len([i for i in issues if i['severity'] == 'CRITICAL']),
            'warning_count': len([i for i in issues if i['severity'] == 'WARNING']),
        }
    }
    return json.dumps(result, indent=2)


def output_table(stats, issues, warn_only=False):
    """Output results in table format."""
    lines = []

    if not warn_only:
        lines.append(
            f"{'Device':<12} {'Avg Lat':<10} {'Read Lat':<10} {'Write Lat':<10} "
            f"{'Util%':<8} {'IOs':<10} {'QDepth':<8}"
        )
        lines.append("-" * 78)

        for device, data in sorted(stats.items()):
            if data['total_ios'] == 0:
                continue

            lines.append(
                f"{device:<12} "
                f"{data['avg_io_latency_ms']:<10.2f} "
                f"{data['avg_read_latency_ms']:<10.2f} "
                f"{data['avg_write_latency_ms']:<10.2f} "
                f"{data['util_pct']:<8.1f} "
                f"{data['total_ios']:<10} "
                f"{data['avg_queue_depth']:<8.2f}"
            )

        lines.append("")

    if issues:
        lines.append(f"{'Device':<12} {'Severity':<10} {'Issue':<56}")
        lines.append("-" * 78)

        for issue in issues:
            for i, msg in enumerate(issue['issues']):
                if i == 0:
                    lines.append(f"{issue['device']:<12} {issue['severity']:<10} {msg:<56}")
                else:
                    lines.append(f"{'':<12} {'':<10} {msg:<56}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze I/O latency patterns and identify slow storage operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Analyze with 1 second sample
  %(prog)s --interval 5             # 5 second sample for more accuracy
  %(prog)s --format json            # JSON output
  %(prog)s --warn-latency 20        # Warn on latency > 20ms
  %(prog)s --warn-only              # Only show issues

Latency interpretation:
  < 1ms    - Excellent (SSD/NVMe)
  1-5ms    - Good (fast storage)
  5-20ms   - Acceptable (typical HDD)
  20-50ms  - Slow (aging HDD or bottleneck)
  > 50ms   - Critical (investigate immediately)

Exit codes:
  0 - All devices performing within thresholds
  1 - Latency warnings or issues detected
  2 - Usage error or missing data sources

Notes:
  - Samples /proc/diskstats over the specified interval
  - Longer intervals provide more accurate averages
  - Queue depth > 1 indicates concurrent I/O
  - High utilization with low latency is fine; high latency is not
        """
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including idle devices"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Sampling interval in seconds (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-latency",
        type=float,
        default=50.0,
        help="Warning threshold for average latency in ms (default: %(default)s)"
    )

    parser.add_argument(
        "--crit-latency",
        type=float,
        default=100.0,
        help="Critical threshold for average latency in ms (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-util",
        type=float,
        default=80.0,
        help="Warning threshold for utilization percentage (default: %(default)s)"
    )

    parser.add_argument(
        "--device",
        help="Monitor specific device only (e.g., sda, nvme0n1)"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.interval <= 0:
        print("Error: Interval must be positive", file=sys.stderr)
        sys.exit(2)

    if args.interval > 60:
        print("Error: Interval cannot exceed 60 seconds", file=sys.stderr)
        sys.exit(2)

    if args.warn_latency <= 0 or args.crit_latency <= 0:
        print("Error: Latency thresholds must be positive", file=sys.stderr)
        sys.exit(2)

    if args.warn_latency >= args.crit_latency:
        print("Error: Warning latency must be less than critical latency", file=sys.stderr)
        sys.exit(2)

    if not 0 < args.warn_util <= 100:
        print("Error: Utilization warning threshold must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    # Take first sample
    before = read_diskstats()

    if before is None:
        print("Error: Could not read /proc/diskstats", file=sys.stderr)
        print("Ensure you have read access to /proc/diskstats", file=sys.stderr)
        sys.exit(2)

    if not before:
        print("Error: No block devices found in /proc/diskstats", file=sys.stderr)
        sys.exit(2)

    # Filter to specific device if requested
    if args.device:
        if args.device not in before:
            print(f"Error: Device '{args.device}' not found", file=sys.stderr)
            print(f"Available devices: {', '.join(sorted(before.keys()))}", file=sys.stderr)
            sys.exit(2)
        before = {args.device: before[args.device]}

    # Wait for interval
    time.sleep(args.interval)

    # Take second sample
    after = read_diskstats()

    if after is None:
        print("Error: Could not read /proc/diskstats for second sample", file=sys.stderr)
        sys.exit(2)

    if args.device:
        after = {args.device: after[args.device]}

    # Calculate latency statistics
    interval_ms = args.interval * 1000
    stats = calculate_latency_stats(before, after, interval_ms)

    if not stats:
        print("Error: No devices to analyze", file=sys.stderr)
        sys.exit(2)

    # Analyze for issues
    issues = analyze_latency(stats, args.warn_latency, args.crit_latency, args.warn_util)

    # Output results
    if args.format == "json":
        output = output_json(stats, issues)
    elif args.format == "table":
        output = output_table(stats, issues, warn_only=args.warn_only)
    else:
        output = output_plain(stats, issues, warn_only=args.warn_only, verbose=args.verbose)

    print(output)

    # Exit based on findings
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
