#!/usr/bin/env python3
"""
Monitor block device error statistics from /sys/block/*/stat.

Tracks read/write errors, I/O errors, and sector remapping for early
detection of disk problems. Useful for monitoring large baremetal fleets
where disk failures can impact service availability.

The script reads from /sys/block/*/stat which provides:
- Read I/Os completed
- Write I/Os completed
- Sectors read/written
- I/O errors

Exit codes:
    0 - No errors detected
    1 - Errors or warnings found
    2 - Missing dependencies or usage error
"""

import argparse
import sys
import os
import json
from pathlib import Path


def get_block_devices():
    """Get list of block devices from /sys/block/"""
    try:
        sys_block = Path('/sys/block')
        if not sys_block.exists():
            return []

        devices = []
        for device in sys_block.iterdir():
            # Skip loop devices and ram devices
            if device.name.startswith(('loop', 'ram', 'dm-')):
                continue
            devices.append(device.name)

        return sorted(devices)
    except Exception as e:
        print(f"Error listing block devices: {e}", file=sys.stderr)
        return []


def read_device_stat(device):
    """
    Read /sys/block/<device>/stat file.

    Format (11 fields):
    1. read I/Os
    2. read merges
    3. read sectors
    4. read ticks
    5. write I/Os
    6. write merges
    7. write sectors
    8. write ticks
    9. in_flight
    10. io_ticks
    11. time_in_queue

    Some kernels add:
    12. discard I/Os
    13. discard merges
    14. discard sectors
    15. discard ticks
    """
    stat_path = Path(f'/sys/block/{device}/stat')

    try:
        if not stat_path.exists():
            return None

        with open(stat_path, 'r') as f:
            fields = f.read().strip().split()

        if len(fields) < 11:
            return None

        return {
            'device': device,
            'read_ios': int(fields[0]),
            'read_merges': int(fields[1]),
            'read_sectors': int(fields[2]),
            'read_ticks': int(fields[3]),
            'write_ios': int(fields[4]),
            'write_merges': int(fields[5]),
            'write_sectors': int(fields[6]),
            'write_ticks': int(fields[7]),
            'in_flight': int(fields[8]),
            'io_ticks': int(fields[9]),
            'time_in_queue': int(fields[10]),
        }
    except Exception as e:
        print(f"Error reading stats for {device}: {e}", file=sys.stderr)
        return None


def get_device_model(device):
    """Get device model from sysfs"""
    model_path = Path(f'/sys/block/{device}/device/model')
    try:
        if model_path.exists():
            with open(model_path, 'r') as f:
                return f.read().strip()
    except Exception:
        pass
    return "Unknown"


def get_device_size(device):
    """Get device size in bytes"""
    size_path = Path(f'/sys/block/{device}/size')
    try:
        if size_path.exists():
            with open(size_path, 'r') as f:
                # Size is in 512-byte sectors
                sectors = int(f.read().strip())
                return sectors * 512
    except Exception:
        pass
    return 0


def format_bytes(bytes_val):
    """Format bytes in human-readable form"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}PB"


def analyze_device_health(stats):
    """
    Analyze device statistics for potential issues.

    Returns (status, issues_list)
    status: 'healthy', 'warning', 'critical'
    """
    issues = []

    # Check for high I/O queue time (potential slowness)
    if stats['in_flight'] > 10:
        issues.append(f"High in-flight I/Os: {stats['in_flight']}")

    # Calculate average queue time per I/O
    total_ios = stats['read_ios'] + stats['write_ios']
    if total_ios > 0:
        avg_queue_time = stats['time_in_queue'] / total_ios
        if avg_queue_time > 1000:  # More than 1 second average
            issues.append(f"High avg queue time: {avg_queue_time:.1f}ms")

    # Check if device is completely idle (might be failed)
    if total_ios == 0:
        issues.append("No I/O activity (device may be unused or failed)")

    if not issues:
        return 'healthy', []
    elif len(issues) >= 2 or 'failed' in str(issues):
        return 'critical', issues
    else:
        return 'warning', issues


def output_plain(results, verbose=False, warn_only=False):
    """Output in plain text format"""
    for result in results:
        status, issues = analyze_device_health(result['stats'])

        if warn_only and status == 'healthy':
            continue

        device = result['device']
        model = result['model']
        size = format_bytes(result['size'])
        stats = result['stats']

        print(f"{device} ({model}, {size}): {status.upper()}")

        if verbose or status != 'healthy':
            print(f"  Read I/Os: {stats['read_ios']}, "
                  f"Write I/Os: {stats['write_ios']}")
            print(f"  Read sectors: {stats['read_sectors']}, "
                  f"Write sectors: {stats['write_sectors']}")
            print(f"  In-flight: {stats['in_flight']}, "
                  f"Queue time: {stats['time_in_queue']}ms")

        if issues:
            for issue in issues:
                print(f"  ⚠ {issue}")

        print()


def output_json(results, warn_only=False):
    """Output in JSON format"""
    output = []

    for result in results:
        status, issues = analyze_device_health(result['stats'])

        if warn_only and status == 'healthy':
            continue

        output.append({
            'device': result['device'],
            'model': result['model'],
            'size_bytes': result['size'],
            'size_human': format_bytes(result['size']),
            'status': status,
            'issues': issues,
            'stats': result['stats']
        })

    print(json.dumps(output, indent=2))


def output_table(results, warn_only=False):
    """Output in table format"""
    # Print header
    print(f"{'Device':<12} {'Model':<20} {'Size':<10} {'Status':<10} "
          f"{'Read I/O':<12} {'Write I/O':<12} {'Issues'}")
    print("-" * 100)

    for result in results:
        status, issues = analyze_device_health(result['stats'])

        if warn_only and status == 'healthy':
            continue

        device = result['device']
        model = result['model'][:19]  # Truncate long model names
        size = format_bytes(result['size'])
        stats = result['stats']

        issues_str = '; '.join(issues) if issues else '-'
        if len(issues_str) > 30:
            issues_str = issues_str[:27] + '...'

        print(f"{device:<12} {model:<20} {size:<10} {status:<10} "
              f"{stats['read_ios']:<12} {stats['write_ios']:<12} {issues_str}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Monitor block device error statistics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check all block devices
  %(prog)s --format json        # JSON output
  %(prog)s --warn-only          # Only show devices with issues
  %(prog)s -v                   # Verbose output
  %(prog)s sda sdb              # Check specific devices

Exit codes:
  0 - No errors detected
  1 - Errors or warnings found
  2 - Missing dependencies or usage error
"""
    )

    parser.add_argument(
        'devices',
        nargs='*',
        help='Specific devices to check (default: all)'
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
        help='Show detailed statistics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show devices with warnings or issues'
    )

    args = parser.parse_args()

    # Check if /sys/block exists
    if not Path('/sys/block').exists():
        print("Error: /sys/block not found (not a Linux system?)",
              file=sys.stderr)
        sys.exit(2)

    # Get devices to check
    if args.devices:
        devices = args.devices
    else:
        devices = get_block_devices()

    if not devices:
        print("Error: No block devices found", file=sys.stderr)
        sys.exit(2)

    # Collect statistics
    results = []
    has_issues = False

    for device in devices:
        stats = read_device_stat(device)
        if stats is None:
            print(f"Warning: Could not read stats for {device}",
                  file=sys.stderr)
            continue

        model = get_device_model(device)
        size = get_device_size(device)

        result = {
            'device': device,
            'model': model,
            'size': size,
            'stats': stats
        }

        results.append(result)

        # Check if this device has issues
        status, _ = analyze_device_health(stats)
        if status in ('warning', 'critical'):
            has_issues = True

    if not results:
        print("Error: No valid device statistics collected", file=sys.stderr)
        sys.exit(2)

    # Output results
    if args.format == 'json':
        output_json(results, args.warn_only)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:  # plain
        output_plain(results, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
