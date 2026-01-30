#!/usr/bin/env python3
"""
Monitor disk I/O latency to detect performance issues.

Analyzes /proc/diskstats and /sys/block/*/stat to measure disk I/O latency
and identify devices with slow response times. High I/O latency often indicates
overloaded disks, failing hardware, or misconfigured storage.

Key features:
- Reports average read/write latency per device
- Identifies devices exceeding latency thresholds
- Tracks I/O queue depth and utilization
- Supports filtering by device name pattern
- Calculates I/O wait percentage from /proc/stat

Use cases:
- Proactive detection of disk performance degradation
- Identifying overloaded storage devices
- Capacity planning for high-IOPS workloads
- Pre-incident visibility into storage latency
- Troubleshooting slow application response times

Exit codes:
    0 - No latency issues detected
    1 - Latency warnings or threshold exceeded
    2 - Usage error or unable to read disk statistics
"""

import argparse
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional


def read_proc_file(path: str) -> Optional[str]:
    """Read a /proc or /sys file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (OSError, IOError, PermissionError):
        return None


def parse_diskstats() -> Dict[str, Dict[str, int]]:
    """Parse /proc/diskstats and return device statistics."""
    content = read_proc_file('/proc/diskstats')
    if not content:
        return {}

    devices = {}
    for line in content.strip().split('\n'):
        parts = line.split()
        if len(parts) < 14:
            continue

        # Format: major minor name rd_ios rd_merges rd_sectors rd_ticks
        #         wr_ios wr_merges wr_sectors wr_ticks in_flight io_ticks weighted_io_ticks
        try:
            device_name = parts[2]

            # Skip loop, ram, and dm- devices by default (partitions and virtual)
            if device_name.startswith(('loop', 'ram')):
                continue

            devices[device_name] = {
                'rd_ios': int(parts[3]),        # Read I/Os completed
                'rd_merges': int(parts[4]),     # Reads merged
                'rd_sectors': int(parts[5]),    # Sectors read
                'rd_ticks': int(parts[6]),      # Time spent reading (ms)
                'wr_ios': int(parts[7]),        # Write I/Os completed
                'wr_merges': int(parts[8]),     # Writes merged
                'wr_sectors': int(parts[9]),    # Sectors written
                'wr_ticks': int(parts[10]),     # Time spent writing (ms)
                'in_flight': int(parts[11]),    # I/Os currently in progress
                'io_ticks': int(parts[12]),     # Time spent doing I/Os (ms)
                'weighted_io_ticks': int(parts[13]),  # Weighted time spent doing I/Os
            }
        except (ValueError, IndexError):
            continue

    return devices


def get_device_scheduler(device: str) -> Optional[str]:
    """Get the I/O scheduler for a device."""
    # Strip partition numbers to get base device
    base_device = re.sub(r'[0-9]+$', '', device)
    if base_device.startswith('nvme'):
        # NVMe devices use nvmeXnY format
        base_device = re.sub(r'p[0-9]+$', '', device)

    scheduler_path = f'/sys/block/{base_device}/queue/scheduler'
    content = read_proc_file(scheduler_path)
    if content:
        # Active scheduler is in brackets [mq-deadline]
        match = re.search(r'\[([^\]]+)\]', content)
        if match:
            return match.group(1)
    return None


def get_device_rotational(device: str) -> Optional[bool]:
    """Check if device is rotational (HDD) or not (SSD/NVMe)."""
    base_device = re.sub(r'[0-9]+$', '', device)
    if base_device.startswith('nvme'):
        base_device = re.sub(r'p[0-9]+$', '', device)

    rotational_path = f'/sys/block/{base_device}/queue/rotational'
    content = read_proc_file(rotational_path)
    if content:
        return content.strip() == '1'
    return None


def get_cpu_io_wait() -> Optional[float]:
    """Get CPU I/O wait percentage from /proc/stat."""
    content = read_proc_file('/proc/stat')
    if not content:
        return None

    for line in content.split('\n'):
        if line.startswith('cpu '):
            parts = line.split()
            if len(parts) >= 5:
                try:
                    # cpu user nice system idle iowait ...
                    user = int(parts[1])
                    nice = int(parts[2])
                    system = int(parts[3])
                    idle = int(parts[4])
                    iowait = int(parts[5]) if len(parts) > 5 else 0

                    total = user + nice + system + idle + iowait
                    if total > 0:
                        return (iowait / total) * 100
                except (ValueError, IndexError):
                    pass
    return None


def calculate_latency(stats: Dict[str, int]) -> Dict[str, Any]:
    """Calculate latency metrics from disk stats."""
    rd_ios = stats.get('rd_ios', 0)
    wr_ios = stats.get('wr_ios', 0)
    rd_ticks = stats.get('rd_ticks', 0)
    wr_ticks = stats.get('wr_ticks', 0)

    # Average latency in milliseconds
    rd_latency_avg = rd_ticks / rd_ios if rd_ios > 0 else 0.0
    wr_latency_avg = wr_ticks / wr_ios if wr_ios > 0 else 0.0

    # Combined average
    total_ios = rd_ios + wr_ios
    total_ticks = rd_ticks + wr_ticks
    avg_latency = total_ticks / total_ios if total_ios > 0 else 0.0

    return {
        'read_latency_ms': round(rd_latency_avg, 2),
        'write_latency_ms': round(wr_latency_avg, 2),
        'avg_latency_ms': round(avg_latency, 2),
        'read_iops': rd_ios,
        'write_iops': wr_ios,
        'total_iops': total_ios,
        'in_flight': stats.get('in_flight', 0),
        'io_ticks': stats.get('io_ticks', 0),
    }


def filter_devices(devices: Dict[str, Dict], pattern: Optional[str],
                   include_partitions: bool) -> Dict[str, Dict]:
    """Filter devices by pattern and partition setting."""
    filtered = {}

    for name, stats in devices.items():
        # Skip partitions unless requested
        if not include_partitions:
            # Skip if device name ends with a number (partition)
            # but not NVMe devices which use nvmeXnYpZ format
            if re.match(r'.+[0-9]$', name) and not name.startswith('nvme'):
                continue
            if re.match(r'nvme[0-9]+n[0-9]+p[0-9]+$', name):
                continue

        # Apply pattern filter
        if pattern:
            try:
                if not re.search(pattern, name, re.IGNORECASE):
                    continue
            except re.error:
                continue

        filtered[name] = stats

    return filtered


def analyze_devices(devices: Dict[str, Dict],
                    read_warn: float, write_warn: float,
                    avg_warn: float) -> Dict[str, Any]:
    """Analyze devices and identify issues."""
    results = []
    issues = []

    for name, stats in sorted(devices.items()):
        latency = calculate_latency(stats)
        scheduler = get_device_scheduler(name)
        rotational = get_device_rotational(name)

        device_info = {
            'device': name,
            'type': 'HDD' if rotational else 'SSD/NVMe' if rotational is False else 'unknown',
            'scheduler': scheduler,
            **latency,
        }
        results.append(device_info)

        # Check thresholds
        if latency['read_latency_ms'] > read_warn and latency['read_iops'] > 0:
            issues.append({
                'type': 'READ_LATENCY_HIGH',
                'severity': 'warning',
                'device': name,
                'value': latency['read_latency_ms'],
                'threshold': read_warn,
                'message': f"Device {name}: Read latency {latency['read_latency_ms']:.1f}ms exceeds {read_warn}ms threshold"
            })

        if latency['write_latency_ms'] > write_warn and latency['write_iops'] > 0:
            issues.append({
                'type': 'WRITE_LATENCY_HIGH',
                'severity': 'warning',
                'device': name,
                'value': latency['write_latency_ms'],
                'threshold': write_warn,
                'message': f"Device {name}: Write latency {latency['write_latency_ms']:.1f}ms exceeds {write_warn}ms threshold"
            })

        if latency['avg_latency_ms'] > avg_warn and latency['total_iops'] > 0:
            issues.append({
                'type': 'AVG_LATENCY_HIGH',
                'severity': 'warning',
                'device': name,
                'value': latency['avg_latency_ms'],
                'threshold': avg_warn,
                'message': f"Device {name}: Average latency {latency['avg_latency_ms']:.1f}ms exceeds {avg_warn}ms threshold"
            })

        # High queue depth can indicate overload
        if latency['in_flight'] > 64:
            issues.append({
                'type': 'QUEUE_DEPTH_HIGH',
                'severity': 'warning',
                'device': name,
                'value': latency['in_flight'],
                'message': f"Device {name}: High I/O queue depth ({latency['in_flight']} in flight)"
            })

    io_wait = get_cpu_io_wait()

    return {
        'devices': results,
        'issues': issues,
        'io_wait_pct': round(io_wait, 2) if io_wait is not None else None,
        'device_count': len(results),
    }


def output_plain(analysis: Dict, warn_only: bool, verbose: bool) -> None:
    """Output in plain text format."""
    issues = analysis['issues']
    devices = analysis['devices']

    # Print issues first
    if issues:
        print("ISSUES DETECTED:")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")
        print()

    if warn_only and not issues:
        print("OK - No disk latency issues detected")
        return

    # I/O wait summary
    if analysis['io_wait_pct'] is not None:
        print(f"System I/O Wait: {analysis['io_wait_pct']:.1f}%")
        print()

    # Device summary
    print("Disk I/O Latency Summary:")
    print(f"  {'Device':<12} {'Type':<10} {'Rd Lat':>8} {'Wr Lat':>8} {'Avg Lat':>8} {'Queue':>6}")
    print("  " + "-" * 56)

    for dev in devices:
        rd_lat = f"{dev['read_latency_ms']:.1f}ms" if dev['read_iops'] > 0 else "N/A"
        wr_lat = f"{dev['write_latency_ms']:.1f}ms" if dev['write_iops'] > 0 else "N/A"
        avg_lat = f"{dev['avg_latency_ms']:.1f}ms" if dev['total_iops'] > 0 else "N/A"

        print(f"  {dev['device']:<12} {dev['type']:<10} {rd_lat:>8} {wr_lat:>8} {avg_lat:>8} {dev['in_flight']:>6}")

    if verbose:
        print()
        print("Device Details:")
        for dev in devices:
            print(f"\n  {dev['device']}:")
            print(f"    Type: {dev['type']}")
            print(f"    Scheduler: {dev['scheduler'] or 'unknown'}")
            print(f"    Read IOPS: {dev['read_iops']}")
            print(f"    Write IOPS: {dev['write_iops']}")
            print(f"    I/O Ticks: {dev['io_ticks']}ms")


def output_json(analysis: Dict) -> None:
    """Output in JSON format."""
    status = 'warning' if analysis['issues'] else 'ok'

    result = {
        'status': status,
        'summary': {
            'device_count': analysis['device_count'],
            'io_wait_pct': analysis['io_wait_pct'],
            'issue_count': len(analysis['issues']),
        },
        'issues': analysis['issues'],
        'devices': analysis['devices'],
    }
    print(json.dumps(result, indent=2))


def output_table(analysis: Dict, warn_only: bool) -> None:
    """Output in table format."""
    issues = analysis['issues']

    if warn_only:
        if not issues:
            print("No disk latency issues detected")
            return
        print(f"{'Device':<12} {'Type':<20} {'Value':>10} {'Threshold':>10}")
        print("-" * 56)
        for issue in issues:
            print(f"{issue['device']:<12} {issue['type']:<20} "
                  f"{issue.get('value', 0):>10.1f} {issue.get('threshold', 0):>10.1f}")
        return

    # Full table
    print(f"{'Device':<12} {'Type':<10} {'Rd Lat(ms)':>12} {'Wr Lat(ms)':>12} {'Avg Lat(ms)':>12}")
    print("-" * 62)
    for dev in analysis['devices']:
        print(f"{dev['device']:<12} {dev['type']:<10} "
              f"{dev['read_latency_ms']:>12.2f} {dev['write_latency_ms']:>12.2f} "
              f"{dev['avg_latency_ms']:>12.2f}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor disk I/O latency for performance issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         Show disk latency summary
  %(prog)s --warn-only             Only show if there are issues
  %(prog)s --device 'sd.*'         Filter to sd* devices
  %(prog)s --device nvme           Filter to NVMe devices
  %(prog)s --format json           JSON output for monitoring systems
  %(prog)s --read-warn 50          Warn if read latency exceeds 50ms
  %(prog)s --include-partitions    Include partition devices

Exit codes:
  0 - No latency issues detected
  1 - Latency warnings or threshold exceeded
  2 - Usage error or unable to read disk statistics
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
        help='Show detailed device information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show if there are issues'
    )

    parser.add_argument(
        '-d', '--device',
        type=str,
        metavar='PATTERN',
        help='Filter to devices matching pattern (regex)'
    )

    parser.add_argument(
        '--include-partitions',
        action='store_true',
        help='Include partition devices in output'
    )

    parser.add_argument(
        '--read-warn',
        type=float,
        default=100.0,
        metavar='MS',
        help='Warn if read latency exceeds MS milliseconds (default: 100)'
    )

    parser.add_argument(
        '--write-warn',
        type=float,
        default=100.0,
        metavar='MS',
        help='Warn if write latency exceeds MS milliseconds (default: 100)'
    )

    parser.add_argument(
        '--avg-warn',
        type=float,
        default=100.0,
        metavar='MS',
        help='Warn if average latency exceeds MS milliseconds (default: 100)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.read_warn < 0:
        print("Error: --read-warn must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.write_warn < 0:
        print("Error: --write-warn must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.avg_warn < 0:
        print("Error: --avg-warn must be non-negative", file=sys.stderr)
        sys.exit(2)

    # Validate regex pattern
    if args.device:
        try:
            re.compile(args.device)
        except re.error as e:
            print(f"Error: Invalid device pattern: {e}", file=sys.stderr)
            sys.exit(2)

    # Check if we can read /proc/diskstats
    if not os.path.isfile('/proc/diskstats'):
        print("Error: /proc/diskstats not available", file=sys.stderr)
        print("This script requires the procfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Get disk statistics
    devices = parse_diskstats()

    if not devices:
        print("Error: No disk devices found", file=sys.stderr)
        sys.exit(2)

    # Filter devices
    devices = filter_devices(devices, args.device, args.include_partitions)

    if not devices:
        print("Error: No devices match filter criteria", file=sys.stderr)
        sys.exit(2)

    # Analyze
    analysis = analyze_devices(
        devices,
        read_warn=args.read_warn,
        write_warn=args.write_warn,
        avg_warn=args.avg_warn
    )

    # Output
    if args.format == 'json':
        output_json(analysis)
    elif args.format == 'table':
        output_table(analysis, args.warn_only)
    else:
        output_plain(analysis, args.warn_only, args.verbose)

    # Exit code based on issues
    if analysis['issues']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
