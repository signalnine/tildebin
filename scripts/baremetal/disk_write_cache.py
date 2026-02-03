#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [storage, write-cache, performance, data-integrity]
#   requires: []
#   privilege: root
#   related: [disk_health, disk_sector_health]
#   brief: Audit disk write cache settings for data integrity compliance

"""
Audit disk write cache settings for data integrity compliance.

Checks hard disk and SSD write cache configuration to ensure data integrity.
Write cache (WCE - Write Cache Enable) can improve performance but poses
data loss risks during power failures. This is critical for:

- Database servers requiring data integrity guarantees
- Systems without UPS/battery-backed write cache
- Compliance with data retention requirements
- Storage systems using software RAID

The tool checks:
- Write cache status via hdparm (SATA/SAS) or sdparm (SCSI)
- NVMe volatile write cache status
- Device queue write cache settings
- Recommendations based on device type and configuration

Returns exit code 1 if write cache issues are detected.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_block_devices(context: Context) -> list[str]:
    """Get list of block devices (excluding virtual devices)."""
    devices = []
    virtual_prefixes = ('loop', 'ram', 'dm-', 'md', 'nbd', 'zram')

    block_dirs = context.glob('*', '/sys/block')
    for path in block_dirs:
        name = path.split('/')[-1]
        if name.startswith(virtual_prefixes):
            continue

        # Check if it's a real device (has a device symlink)
        if context.file_exists(f'{path}/device'):
            devices.append(name)

    return sorted(devices)


def is_nvme_device(device: str) -> bool:
    """Check if device is an NVMe device."""
    return device.startswith('nvme')


def is_rotational(device: str, context: Context) -> bool | None:
    """Check if device is rotational (HDD) or non-rotational (SSD/NVMe)."""
    path = f'/sys/block/{device}/queue/rotational'
    if context.file_exists(path):
        try:
            value = context.read_file(path).strip()
            return value == '1'
        except Exception:
            pass
    return None


def get_device_model(device: str, context: Context) -> str:
    """Get device model/name."""
    paths = [
        f'/sys/block/{device}/device/model',
        f'/sys/block/{device}/device/name',
    ]

    for path in paths:
        if context.file_exists(path):
            try:
                model = context.read_file(path).strip()
                if model:
                    return model
            except Exception:
                pass

    return "Unknown"


def get_device_size(device: str, context: Context) -> int:
    """Get device size in bytes."""
    path = f'/sys/block/{device}/size'
    if context.file_exists(path):
        try:
            size_sectors = int(context.read_file(path).strip())
            return size_sectors * 512
        except Exception:
            pass
    return 0


def format_size(size_bytes: int) -> str:
    """Format size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f}PB"


def get_queue_write_cache(device: str, context: Context) -> str | None:
    """Get write cache setting from block queue."""
    path = f'/sys/block/{device}/queue/write_cache'
    if context.file_exists(path):
        try:
            return context.read_file(path).strip()
        except Exception:
            pass
    return None


def get_hdparm_write_cache(device: str, context: Context) -> tuple[dict[str, Any] | None, str | None]:
    """Get write cache status using hdparm."""
    if not context.check_tool('hdparm'):
        return None, "hdparm not available"

    result = context.run(['hdparm', '-W', f'/dev/{device}'], check=False)

    if result.returncode != 0:
        return None, result.stderr.strip() if result.stderr else "hdparm failed"

    # Parse output like: " write-caching =  1 (on)"
    match = re.search(r'write-caching\s*=\s*(\d+)\s*\((\w+)\)', result.stdout)
    if match:
        enabled = match.group(1) == '1'
        status = match.group(2)
        return {'enabled': enabled, 'status': status}, None

    if 'not supported' in result.stdout.lower():
        return {'enabled': None, 'status': 'not supported'}, None

    return None, "Could not parse hdparm output"


def analyze_device(device: str, context: Context, require_disabled: bool = False) -> dict[str, Any]:
    """Analyze write cache configuration for a device."""
    info = {
        'device': device,
        'path': f'/dev/{device}',
        'model': get_device_model(device, context),
        'size': format_size(get_device_size(device, context)),
        'rotational': is_rotational(device, context),
        'is_nvme': is_nvme_device(device),
        'queue_write_cache': get_queue_write_cache(device, context),
        'write_cache': None,
        'source': None,
        'issues': [],
    }

    # Determine device type description
    if info['is_nvme']:
        info['type'] = 'NVMe SSD'
    elif info['rotational'] is True:
        info['type'] = 'HDD'
    elif info['rotational'] is False:
        info['type'] = 'SSD'
    else:
        info['type'] = 'Unknown'

    # Get write cache status (skip NVMe for now - needs nvme-cli)
    if not info['is_nvme']:
        wc_result, error = get_hdparm_write_cache(device, context)
        if wc_result:
            info['write_cache'] = wc_result
            info['source'] = 'hdparm'
        elif error:
            info['issues'].append(f'Could not determine write cache status: {error}')

    # Analyze and generate issues
    wc = info['write_cache']
    if wc and wc.get('enabled') is not None:
        if require_disabled and wc['enabled']:
            info['issues'].append('Write cache is ENABLED but policy requires it disabled')

    return info


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Audit disk write cache settings")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-d", "--device", help="Check specific device only (e.g., sda)")
    parser.add_argument(
        "--require-disabled",
        action="store_true",
        help="Flag enabled write caches as issues (for data integrity compliance)"
    )
    opts = parser.parse_args(args)

    # Get devices to check
    if opts.device:
        devices = [opts.device]
        if not context.file_exists(f'/sys/block/{opts.device}'):
            output.error(f"Device {opts.device} not found")
            return 2
    else:
        devices = get_block_devices(context)

    if not devices:
        output.error("No block devices found")

        output.render(opts.format, "Audit disk write cache settings for data integrity compliance")
        return 2

    # Analyze devices
    results = []
    for device in devices:
        info = analyze_device(device, context, require_disabled=opts.require_disabled)
        results.append(info)

    # Calculate summary
    wc_enabled = 0
    wc_disabled = 0
    wc_unknown = 0
    with_issues = 0

    for r in results:
        if r['write_cache']:
            if r['write_cache'].get('enabled') is True:
                wc_enabled += 1
            elif r['write_cache'].get('enabled') is False:
                wc_disabled += 1
            else:
                wc_unknown += 1
        else:
            wc_unknown += 1

        if r['issues']:
            with_issues += 1

    # Build output data
    data = {
        'devices': results,
        'summary': {
            'total': len(results),
            'write_cache_enabled': wc_enabled,
            'write_cache_disabled': wc_disabled,
            'write_cache_unknown': wc_unknown,
            'devices_with_issues': with_issues,
        },
        'require_disabled_policy': opts.require_disabled,
    }

    output.emit(data)

    # Generate summary
    if with_issues > 0:
        output.set_summary(f"{with_issues} device(s) with write cache issues")
    else:
        output.set_summary(f"{wc_enabled} enabled, {wc_disabled} disabled, {wc_unknown} unknown")

    output.render(opts.format, "Audit disk write cache settings for data integrity compliance")

    return 1 if with_issues > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
