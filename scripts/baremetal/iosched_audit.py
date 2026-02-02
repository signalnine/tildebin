#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [audit, iosched, disk, performance, scheduler]
#   requires: []
#   privilege: user
#   related: [disk_io_latency, disk_queue_monitor, nvme_health]
#   brief: Audit I/O scheduler configuration for block devices

"""
Audit I/O scheduler configuration across block devices.

Checks I/O scheduler settings for all block devices and identifies
potential misconfigurations that can impact performance. Modern NVMe drives
typically perform best with 'none' scheduler, while traditional spinning disks
benefit from 'mq-deadline' or 'bfq' schedulers.

Returns exit code 1 if suboptimal configurations are found.
"""

import argparse
import glob
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def is_virtual_device(device_name: str) -> bool:
    """Check if device is virtual (loop, ram, etc.)."""
    virtual_prefixes = ['loop', 'ram', 'dm-', 'md']
    return any(device_name.startswith(prefix) for prefix in virtual_prefixes)


def read_sysfs_value(path: str, default: str | None = None) -> str | None:
    """Read a value from sysfs, return default if not available."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return default


def get_device_info(device_name: str, sysfs_path: str) -> dict[str, Any]:
    """Get detailed information about a block device."""
    info = {
        'device': device_name,
        'device_path': f'/dev/{device_name}'
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

    # Determine status
    if not info['is_optimal']:
        info['status'] = 'warning'
        if info['device_type'] == 'nvme' and info['current_scheduler'] != 'none':
            info['issue'] = 'NVMe using complex scheduler (performance impact)'
        elif info['device_type'] == 'hdd' and info['current_scheduler'] == 'none':
            info['issue'] = 'Rotational disk using none scheduler (potential impact)'
        else:
            info['issue'] = 'Suboptimal scheduler configuration'
    else:
        info['status'] = 'healthy'
        info['issue'] = None

    return info


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all optimal, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit I/O scheduler configuration for block devices"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show devices with suboptimal scheduler settings"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed device information"
    )
    parser.add_argument(
        "--include-virtual",
        action="store_true",
        help="Include virtual devices (loop, dm, md, ram)"
    )

    opts = parser.parse_args(args)

    # Check if /sys/block exists
    if not context.file_exists('/sys/block'):
        output.error("/sys/block not found. This script requires sysfs.")
        return 2

    # Get block devices
    devices_info = []
    try:
        for device_path in glob.glob('/sys/block/*'):
            device_name = os.path.basename(device_path)

            # Skip virtual devices unless requested
            if not opts.include_virtual and is_virtual_device(device_name):
                continue

            info = get_device_info(device_name, device_path)
            devices_info.append(info)
    except Exception as e:
        output.error(f"Failed to read block devices: {e}")
        return 2

    if not devices_info:
        output.warning("No block devices found")
        output.emit({"devices": []})
        return 0

    # Sort by device name
    devices_info.sort(key=lambda x: x['device'])

    # Filter for warn-only mode
    filtered = devices_info
    if opts.warn_only:
        filtered = [d for d in devices_info if not d['is_optimal']]

    # Remove verbose fields if not requested
    if not opts.verbose:
        for device in filtered:
            device.pop('available_schedulers', None)
            device.pop('queue_depth', None)
            device.pop('model', None)

    output.emit({"devices": filtered})

    # Set summary
    total = len(devices_info)
    optimal = sum(1 for d in devices_info if d['is_optimal'])
    suboptimal = total - optimal
    output.set_summary(f"{optimal}/{total} devices optimal")

    return 1 if suboptimal > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
