#!/usr/bin/env python3
"""
Monitor disk I/O queue depths to detect storage bottlenecks and saturation.

This script monitors block device queue depths by sampling /sys/block/*/stat
and /proc/diskstats to identify storage devices under heavy load. High queue
depths indicate I/O saturation that causes latency spikes and performance
degradation.

Useful for:
- Detecting storage bottlenecks before they cause application issues
- Identifying devices with consistently high queue depths
- Capacity planning for storage subsystems
- Correlating performance issues with I/O saturation
- Monitoring NVMe, SSD, and HDD queue utilization

Exit codes:
    0 - All devices healthy (queue depths below thresholds)
    1 - Warnings detected (high queue depths or saturation)
    2 - Usage error or no block devices found
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict


def get_block_devices():
    """Get list of physical block devices."""
    devices = []
    block_path = '/sys/block'

    if not os.path.exists(block_path):
        return devices

    try:
        for device in os.listdir(block_path):
            # Skip loop devices, ram disks, and device mapper initially
            if device.startswith('loop') or device.startswith('ram'):
                continue

            device_path = os.path.join(block_path, device)

            # Check if it's a real device (has a 'device' symlink or is virtual)
            device_link = os.path.join(device_path, 'device')
            is_physical = os.path.exists(device_link)

            # Also include device mapper and md devices (RAID)
            is_dm = device.startswith('dm-')
            is_md = device.startswith('md')
            is_nvme = device.startswith('nvme')

            if is_physical or is_dm or is_md or is_nvme:
                devices.append(device)

    except (OSError, PermissionError):
        pass

    return sorted(devices)


def read_device_stat(device):
    """Read I/O statistics from /sys/block/<device>/stat."""
    stat_path = f'/sys/block/{device}/stat'

    try:
        with open(stat_path, 'r') as f:
            fields = f.read().split()

        if len(fields) >= 11:
            # Fields from Documentation/block/stat.txt:
            # 0: reads completed
            # 1: reads merged
            # 2: sectors read
            # 3: time reading (ms)
            # 4: writes completed
            # 5: writes merged
            # 6: sectors written
            # 7: time writing (ms)
            # 8: I/Os currently in progress (queue depth)
            # 9: time doing I/Os (ms)
            # 10: weighted time doing I/Os (ms)
            return {
                'reads_completed': int(fields[0]),
                'reads_merged': int(fields[1]),
                'sectors_read': int(fields[2]),
                'read_time_ms': int(fields[3]),
                'writes_completed': int(fields[4]),
                'writes_merged': int(fields[5]),
                'sectors_written': int(fields[6]),
                'write_time_ms': int(fields[7]),
                'ios_in_progress': int(fields[8]),
                'io_time_ms': int(fields[9]),
                'weighted_io_time_ms': int(fields[10])
            }
    except (OSError, PermissionError, ValueError, IndexError):
        pass

    return None


def get_queue_depth_limit(device):
    """Get the maximum queue depth for a device."""
    # Try nr_requests (scheduler queue depth)
    nr_requests_path = f'/sys/block/{device}/queue/nr_requests'
    try:
        with open(nr_requests_path, 'r') as f:
            return int(f.read().strip())
    except (OSError, PermissionError, ValueError):
        pass

    # Default to 128 (common default)
    return 128


def get_device_scheduler(device):
    """Get the I/O scheduler for a device."""
    scheduler_path = f'/sys/block/{device}/queue/scheduler'
    try:
        with open(scheduler_path, 'r') as f:
            content = f.read().strip()
            # Active scheduler is in brackets, e.g. "[mq-deadline] none"
            import re
            match = re.search(r'\[([^\]]+)\]', content)
            if match:
                return match.group(1)
            return content
    except (OSError, PermissionError):
        return 'unknown'


def get_device_type(device):
    """Determine device type (nvme, ssd, hdd, virtual)."""
    # NVMe devices
    if device.startswith('nvme'):
        return 'nvme'

    # Check rotational flag
    rotational_path = f'/sys/block/{device}/queue/rotational'
    try:
        with open(rotational_path, 'r') as f:
            rotational = int(f.read().strip())
            return 'hdd' if rotational == 1 else 'ssd'
    except (OSError, PermissionError, ValueError):
        pass

    # Device mapper or MD
    if device.startswith('dm-'):
        return 'dm'
    if device.startswith('md'):
        return 'raid'

    return 'unknown'


def get_device_size_gb(device):
    """Get device size in GB."""
    size_path = f'/sys/block/{device}/size'
    try:
        with open(size_path, 'r') as f:
            sectors = int(f.read().strip())
            # Sectors are 512 bytes
            return (sectors * 512) / (1024 ** 3)
    except (OSError, PermissionError, ValueError):
        return 0


def sample_queue_depths(devices, samples=5, interval=0.2):
    """Sample queue depths over time to get average and max."""
    results = defaultdict(lambda: {'samples': [], 'ios': []})

    for _ in range(samples):
        for device in devices:
            stat = read_device_stat(device)
            if stat:
                results[device]['samples'].append(stat['ios_in_progress'])
                results[device]['ios'].append(
                    stat['reads_completed'] + stat['writes_completed']
                )
        if _ < samples - 1:
            time.sleep(interval)

    # Calculate statistics
    device_stats = {}
    for device, data in results.items():
        samples_list = data['samples']
        if samples_list:
            device_stats[device] = {
                'current': samples_list[-1],
                'avg': sum(samples_list) / len(samples_list),
                'max': max(samples_list),
                'min': min(samples_list)
            }

            # Calculate IOPS from IO count change
            ios_list = data['ios']
            if len(ios_list) >= 2:
                total_interval = interval * (len(ios_list) - 1)
                io_diff = ios_list[-1] - ios_list[0]
                if total_interval > 0:
                    device_stats[device]['iops'] = io_diff / total_interval
                else:
                    device_stats[device]['iops'] = 0
            else:
                device_stats[device]['iops'] = 0

    return device_stats


def analyze_device(device, queue_stats, warn_threshold, crit_threshold):
    """Analyze a single device and return status."""
    info = {
        'device': device,
        'device_path': f'/dev/{device}',
        'type': get_device_type(device),
        'scheduler': get_device_scheduler(device),
        'max_queue_depth': get_queue_depth_limit(device),
        'size_gb': round(get_device_size_gb(device), 2),
        'queue_depth': queue_stats.get('current', 0),
        'queue_depth_avg': round(queue_stats.get('avg', 0), 2),
        'queue_depth_max': queue_stats.get('max', 0),
        'iops': round(queue_stats.get('iops', 0), 1),
        'status': 'ok',
        'utilization_pct': 0
    }

    # Calculate queue utilization percentage
    if info['max_queue_depth'] > 0:
        info['utilization_pct'] = round(
            (info['queue_depth_avg'] / info['max_queue_depth']) * 100, 1
        )

    # Determine status based on thresholds
    avg_depth = info['queue_depth_avg']
    max_depth = info['queue_depth_max']

    if avg_depth >= crit_threshold or max_depth >= crit_threshold * 2:
        info['status'] = 'critical'
    elif avg_depth >= warn_threshold or max_depth >= warn_threshold * 2:
        info['status'] = 'warning'

    return info


def output_plain(results, verbose=False, warn_only=False):
    """Output results in plain text format."""
    if not results:
        print("No block devices found")
        return

    # Summary counts
    total = len(results)
    critical = sum(1 for r in results if r['status'] == 'critical')
    warning = sum(1 for r in results if r['status'] == 'warning')
    ok = sum(1 for r in results if r['status'] == 'ok')

    print(f"Disk Queue Monitor: {total} devices, {critical} critical, {warning} warning, {ok} ok")
    print()

    # Sort by status (critical first) then by queue depth
    status_order = {'critical': 0, 'warning': 1, 'ok': 2}
    sorted_results = sorted(
        results,
        key=lambda x: (status_order.get(x['status'], 3), -x['queue_depth_avg'])
    )

    for device in sorted_results:
        if warn_only and device['status'] == 'ok':
            continue

        status_symbols = {
            'critical': '!!!',
            'warning': '!! ',
            'ok': '   '
        }
        symbol = status_symbols.get(device['status'], '   ')

        name = device['device']
        avg = device['queue_depth_avg']
        max_q = device['queue_depth_max']
        util = device['utilization_pct']
        iops = device['iops']

        print(f"[{symbol}] {name}: avg={avg:.1f} max={max_q} util={util:.1f}% iops={iops:.0f}")

        if verbose:
            print(f"       Type: {device['type']}, Scheduler: {device['scheduler']}")
            print(f"       Size: {device['size_gb']} GB, Max Queue: {device['max_queue_depth']}")
        print()


def output_json(results):
    """Output results in JSON format."""
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'summary': {
            'total_devices': len(results),
            'critical': sum(1 for r in results if r['status'] == 'critical'),
            'warning': sum(1 for r in results if r['status'] == 'warning'),
            'ok': sum(1 for r in results if r['status'] == 'ok')
        },
        'devices': results
    }
    print(json.dumps(output, indent=2))


def output_table(results, warn_only=False):
    """Output results in table format."""
    if not results:
        print("No block devices found")
        return

    # Filter if warn_only
    if warn_only:
        results = [r for r in results if r['status'] != 'ok']

    if not results:
        print("No issues found")
        return

    # Print header
    print(f"{'Device':<12} {'Type':<6} {'Status':<10} {'Avg Q':<8} {'Max Q':<8} {'Util %':<8} {'IOPS':<10}")
    print("-" * 72)

    # Sort by status then queue depth
    status_order = {'critical': 0, 'warning': 1, 'ok': 2}
    sorted_results = sorted(
        results,
        key=lambda x: (status_order.get(x['status'], 3), -x['queue_depth_avg'])
    )

    for device in sorted_results:
        name = device['device'][:11]
        dtype = device['type'][:5]
        status = device['status'].upper()[:9]
        avg = f"{device['queue_depth_avg']:.1f}"
        max_q = str(device['queue_depth_max'])
        util = f"{device['utilization_pct']:.1f}"
        iops = f"{device['iops']:.0f}"

        print(f"{name:<12} {dtype:<6} {status:<10} {avg:<8} {max_q:<8} {util:<8} {iops:<10}")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor disk I/O queue depths for storage bottleneck detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         # Monitor all devices
  %(prog)s --format json           # JSON output for automation
  %(prog)s --format table          # Tabular output
  %(prog)s -w                      # Only show devices with issues
  %(prog)s --warn 16 --crit 32     # Custom thresholds
  %(prog)s --samples 10            # More samples for accuracy

Exit codes:
  0 - All devices healthy
  1 - High queue depths detected
  2 - Usage error or no devices found
        """
    )

    parser.add_argument(
        '--format',
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
        help='Only show devices with warnings or errors'
    )

    parser.add_argument(
        '--warn',
        type=int,
        default=16,
        metavar='N',
        help='Warning threshold for average queue depth (default: 16)'
    )

    parser.add_argument(
        '--crit',
        type=int,
        default=32,
        metavar='N',
        help='Critical threshold for average queue depth (default: 32)'
    )

    parser.add_argument(
        '--samples',
        type=int,
        default=5,
        metavar='N',
        help='Number of samples to collect (default: 5)'
    )

    parser.add_argument(
        '--interval',
        type=float,
        default=0.2,
        metavar='SEC',
        help='Interval between samples in seconds (default: 0.2)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn >= args.crit:
        print("Error: Warning threshold must be less than critical threshold",
              file=sys.stderr)
        sys.exit(2)

    # Get block devices
    devices = get_block_devices()

    if not devices:
        if args.format == 'json':
            print('{"error": "No block devices found", "devices": []}')
        else:
            print("Error: No block devices found", file=sys.stderr)
        sys.exit(2)

    # Sample queue depths
    queue_stats = sample_queue_depths(devices, args.samples, args.interval)

    # Analyze each device
    results = []
    for device in devices:
        if device in queue_stats:
            info = analyze_device(
                device,
                queue_stats[device],
                args.warn,
                args.crit
            )
            results.append(info)

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.verbose, args.warn_only)

    # Determine exit code
    has_issues = any(r['status'] in ('critical', 'warning') for r in results)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
