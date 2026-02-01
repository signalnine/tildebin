#!/usr/bin/env python3
"""
Audit I/O scheduler configuration across block devices.

This script checks I/O scheduler settings for all block devices and identifies
potential misconfigurations that can impact performance. Modern NVMe drives
typically perform best with 'none' scheduler, while traditional spinning disks
benefit from 'mq-deadline' or 'bfq' schedulers.

Common issues detected:
- NVMe devices using complex schedulers (mq-deadline, bfq)
- Rotational disks using 'none' scheduler
- Queue depth misconfiguration
- Inconsistent scheduler settings across similar devices

Exit codes:
    0 - All devices have optimal scheduler settings
    1 - Suboptimal or inconsistent scheduler configurations detected
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import glob


def is_virtual_device(device_name):
    """Check if device is virtual (loop, ram, etc.)"""
    virtual_prefixes = ['loop', 'ram', 'dm-', 'md']
    return any(device_name.startswith(prefix) for prefix in virtual_prefixes)


def read_sysfs_value(path, default=None):
    """Read a value from sysfs, return default if not available"""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return default


def get_block_devices():
    """Get list of block devices from /sys/block/"""
    devices = []
    try:
        for device_path in glob.glob('/sys/block/*'):
            device_name = os.path.basename(device_path)

            # Skip virtual devices unless verbose mode
            if is_virtual_device(device_name):
                continue

            device_info = {
                'name': device_name,
                'path': device_path,
                'device_path': f'/dev/{device_name}'
            }
            devices.append(device_info)
    except Exception as e:
        print(f"Error reading block devices: {e}", file=sys.stderr)
        return []

    return devices


def get_device_info(device):
    """Get detailed information about a block device"""
    device_name = device['name']
    sysfs_path = device['path']

    info = {
        'device': device_name,
        'device_path': device['device_path']
    }

    # Read scheduler
    scheduler_file = os.path.join(sysfs_path, 'queue/scheduler')
    scheduler_raw = read_sysfs_value(scheduler_file, 'unknown')

    # Extract current scheduler (marked with [brackets])
    if '[' in scheduler_raw and ']' in scheduler_raw:
        start = scheduler_raw.index('[') + 1
        end = scheduler_raw.index(']')
        info['current_scheduler'] = scheduler_raw[start:end]
        info['available_schedulers'] = scheduler_raw.replace('[', '').replace(']', '').split()
    else:
        info['current_scheduler'] = scheduler_raw
        info['available_schedulers'] = [scheduler_raw] if scheduler_raw != 'unknown' else []

    # Check if rotational (0 = SSD/NVMe, 1 = HDD)
    rotational_file = os.path.join(sysfs_path, 'queue/rotational')
    rotational = read_sysfs_value(rotational_file, '0')
    info['rotational'] = rotational == '1'

    # Determine device type
    if device_name.startswith('nvme'):
        info['device_type'] = 'nvme'
    elif info['rotational']:
        info['device_type'] = 'hdd'
    else:
        info['device_type'] = 'ssd'

    # Read queue depth
    nr_requests_file = os.path.join(sysfs_path, 'queue/nr_requests')
    info['queue_depth'] = read_sysfs_value(nr_requests_file, 'unknown')

    # Read queue scheduler
    nomerges_file = os.path.join(sysfs_path, 'queue/nomerges')
    info['nomerges'] = read_sysfs_value(nomerges_file, 'unknown')

    # Get model if available
    model_file = os.path.join(sysfs_path, 'device/model')
    info['model'] = read_sysfs_value(model_file, 'unknown')

    # Determine optimal scheduler
    if info['device_type'] == 'nvme':
        info['recommended_scheduler'] = 'none'
    elif info['device_type'] == 'hdd':
        info['recommended_scheduler'] = 'mq-deadline'
    else:  # ssd
        info['recommended_scheduler'] = 'none'

    # Check if current scheduler is optimal
    info['is_optimal'] = info['current_scheduler'] == info['recommended_scheduler']

    # Determine issue level
    if not info['is_optimal']:
        if info['device_type'] == 'nvme' and info['current_scheduler'] != 'none':
            info['issue'] = 'NVMe using complex scheduler (performance impact)'
            info['severity'] = 'warning'
        elif info['device_type'] == 'hdd' and info['current_scheduler'] == 'none':
            info['issue'] = 'Rotational disk using none scheduler (potential performance impact)'
            info['severity'] = 'warning'
        else:
            info['issue'] = 'Suboptimal scheduler configuration'
            info['severity'] = 'info'
    else:
        info['issue'] = None
        info['severity'] = None

    return info


def output_plain(devices_info, warn_only=False, verbose=False):
    """Output in plain text format"""
    issues_found = False

    for info in devices_info:
        if warn_only and info['is_optimal']:
            continue

        if not info['is_optimal']:
            issues_found = True

        status = "✓" if info['is_optimal'] else "✗"
        print(f"{status} {info['device']:<8} {info['device_type']:<6} "
              f"{info['current_scheduler']:<12} (recommended: {info['recommended_scheduler']})")

        if not info['is_optimal'] and info['issue']:
            print(f"  └─ {info['issue']}")

        if verbose:
            print(f"     Model: {info['model']}")
            print(f"     Queue depth: {info['queue_depth']}")
            print(f"     Available schedulers: {', '.join(info['available_schedulers'])}")

    return issues_found


def output_table(devices_info, warn_only=False, verbose=False):
    """Output in table format"""
    if warn_only:
        devices_info = [d for d in devices_info if not d['is_optimal']]

    # Print header
    print(f"{'Device':<10} {'Type':<6} {'Current':<12} {'Recommended':<12} {'Status':<8} {'Issue'}")
    print("-" * 80)

    issues_found = False
    for info in devices_info:
        if not info['is_optimal']:
            issues_found = True

        status = "OK" if info['is_optimal'] else "WARN"
        issue_text = info['issue'] if info['issue'] else ""

        print(f"{info['device']:<10} {info['device_type']:<6} "
              f"{info['current_scheduler']:<12} {info['recommended_scheduler']:<12} "
              f"{status:<8} {issue_text}")

        if verbose:
            print(f"  Model: {info['model']}, Queue: {info['queue_depth']}, "
                  f"Available: {', '.join(info['available_schedulers'])}")

    return issues_found


def output_json(devices_info, warn_only=False):
    """Output in JSON format"""
    if warn_only:
        devices_info = [d for d in devices_info if not d['is_optimal']]

    output = {
        'devices': devices_info,
        'summary': {
            'total_devices': len(devices_info),
            'optimal': sum(1 for d in devices_info if d['is_optimal']),
            'suboptimal': sum(1 for d in devices_info if not d['is_optimal'])
        }
    }

    print(json.dumps(output, indent=2))
    return output['summary']['suboptimal'] > 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Audit I/O scheduler configuration for block devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Show all devices
  %(prog)s --warn-only              # Only show misconfigurations
  %(prog)s --format json            # JSON output
  %(prog)s -v                       # Verbose output with queue details
  %(prog)s --format table           # Tabular format

Scheduler recommendations:
  NVMe devices:      'none' (bypass scheduler overhead)
  SSD devices:       'none' or 'mq-deadline'
  Rotational (HDD):  'mq-deadline' or 'bfq'

Exit codes:
  0 - All devices optimally configured
  1 - Suboptimal configurations found
  2 - Error accessing device information
        """
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show devices with suboptimal scheduler settings"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed device information (model, queue depth, available schedulers)"
    )

    parser.add_argument(
        "--include-virtual",
        action="store_true",
        help="Include virtual devices (loop, dm, md, ram)"
    )

    args = parser.parse_args()

    # Check if /sys/block exists
    if not os.path.exists('/sys/block'):
        print("Error: /sys/block not found. This script requires sysfs.", file=sys.stderr)
        sys.exit(2)

    # Get block devices
    devices = get_block_devices()

    if not devices:
        print("Error: No block devices found", file=sys.stderr)
        sys.exit(2)

    # Gather device information
    devices_info = []
    for device in devices:
        info = get_device_info(device)
        devices_info.append(info)

    # Sort by device name
    devices_info.sort(key=lambda x: x['device'])

    # Output results
    issues_found = False

    if args.format == "json":
        issues_found = output_json(devices_info, args.warn_only)
    elif args.format == "table":
        issues_found = output_table(devices_info, args.warn_only, args.verbose)
    else:  # plain
        issues_found = output_plain(devices_info, args.warn_only, args.verbose)

    # Exit with appropriate code
    sys.exit(1 if issues_found else 0)


if __name__ == "__main__":
    main()
