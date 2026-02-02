#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [disk, partition, alignment, performance, ssd]
#   requires: [lsblk]
#   privilege: none
#   related: [disk_health, disk_io_latency, nvme_health]
#   brief: Check disk partition alignment for optimal performance

"""
Check disk partition alignment for optimal performance.

Partition alignment is critical for SSD and modern HDD performance. Misaligned
partitions cause read-modify-write cycles that significantly degrade I/O
performance.

Checks:
- Partition start offset alignment to physical sector size
- Optimal alignment for common configurations (1MiB boundary)
- Detection of legacy MBR-style misalignment (starting at sector 63)
- RAID stripe alignment when applicable
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_block_devices(context: Context) -> list[str]:
    """Get list of block devices (disks)."""
    result = context.run(["lsblk", "-d", "-n", "-o", "NAME,TYPE"], check=False)
    if result.returncode != 0:
        return []

    devices = []
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == 'disk':
            devices.append(parts[0])
    return devices


def get_device_info(device: str, context: Context) -> tuple[str, str]:
    """Get device model and size."""
    result = context.run(
        ["lsblk", "-n", "-o", "SIZE,MODEL", f"/dev/{device}"],
        check=False
    )

    if result.returncode != 0:
        return "N/A", "N/A"

    parts = result.stdout.strip().split(None, 1)
    size = parts[0] if len(parts) > 0 else "N/A"
    model = parts[1].strip() if len(parts) > 1 else "N/A"

    return size, model


def get_sector_sizes(device: str, context: Context) -> tuple[int, int]:
    """Get logical and physical sector sizes for a device."""
    logical_sector_size = 512
    physical_sector_size = 512

    try:
        content = context.read_file(f"/sys/block/{device}/queue/logical_block_size")
        logical_sector_size = int(content.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    try:
        content = context.read_file(f"/sys/block/{device}/queue/physical_block_size")
        physical_sector_size = int(content.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    return logical_sector_size, physical_sector_size


def get_optimal_io_size(device: str, context: Context) -> tuple[int, int]:
    """Get optimal I/O size hint from device."""
    optimal_io_size = 0
    minimum_io_size = 0

    try:
        content = context.read_file(f"/sys/block/{device}/queue/optimal_io_size")
        optimal_io_size = int(content.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    try:
        content = context.read_file(f"/sys/block/{device}/queue/minimum_io_size")
        minimum_io_size = int(content.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    return optimal_io_size, minimum_io_size


def is_ssd(device: str, context: Context) -> bool:
    """Check if device is an SSD (rotational = 0)."""
    try:
        content = context.read_file(f"/sys/block/{device}/queue/rotational")
        return content.strip() == '0'
    except (FileNotFoundError, PermissionError):
        return device.startswith('nvme')


def get_partitions_sfdisk(device: str, context: Context) -> list[dict] | None:
    """Get partition information using sfdisk."""
    import re

    result = context.run(['sfdisk', '-d', f'/dev/{device}'], check=False)
    if result.returncode != 0:
        return None

    partitions = []
    for line in result.stdout.strip().split('\n'):
        match = re.match(r'^(/dev/\S+)\s*:\s*start=\s*(\d+)', line)
        if match:
            part_path, start = match.groups()
            part_name = part_path.split('/')[-1]
            part_num = re.sub(r'^[a-z]+', '', part_name.replace(device, ''))

            partitions.append({
                'number': part_num or '?',
                'start_sector': int(start),
                'name': part_name,
            })

    return partitions


def get_partitions_lsblk(device: str, context: Context) -> list[dict] | None:
    """Get partition information using lsblk."""
    result = context.run(
        ['lsblk', '-n', '-o', 'NAME,TYPE', '-l', f'/dev/{device}'],
        check=False
    )
    if result.returncode != 0:
        return None

    partitions = []
    for line in result.stdout.strip().split('\n'):
        parts = line.split()
        if len(parts) >= 2 and parts[1] == 'part':
            part_name = parts[0]
            # Extract partition number
            import re
            match = re.search(r'(\d+)$', part_name)
            part_num = match.group(1) if match else '?'

            # Try to get start sector from sysfs
            start_sector = 0
            try:
                content = context.read_file(f'/sys/block/{device}/{part_name}/start')
                start_sector = int(content.strip())
            except (FileNotFoundError, ValueError):
                pass

            partitions.append({
                'number': part_num,
                'start_sector': start_sector,
                'name': part_name,
            })

    return partitions if partitions else None


def check_alignment(
    start_sector: int,
    logical_sector_size: int,
    physical_sector_size: int,
    optimal_io_size: int = 0
) -> tuple[bool, str, list[dict]]:
    """Check if a partition start is properly aligned."""
    issues = []

    start_bytes = start_sector * logical_sector_size

    if start_bytes % physical_sector_size != 0:
        issues.append({
            'severity': 'ERROR',
            'type': 'physical_sector',
            'message': f'Not aligned to physical sector size ({physical_sector_size}B)'
        })

    mib_boundary = 1048576
    aligned_to_mib = start_bytes % mib_boundary == 0
    aligned_to_4k = start_bytes % 4096 == 0

    if start_sector == 63:
        issues.append({
            'severity': 'WARNING',
            'type': 'legacy_mbr',
            'message': 'Legacy MBR alignment at sector 63 (misaligned for modern drives)'
        })

    if optimal_io_size > 0 and start_bytes % optimal_io_size != 0:
        issues.append({
            'severity': 'WARNING',
            'type': 'optimal_io',
            'message': f'Not aligned to optimal I/O size ({optimal_io_size}B)'
        })

    is_aligned = len(issues) == 0

    if aligned_to_mib:
        alignment = '1MiB'
    elif aligned_to_4k:
        alignment = '4K'
    elif start_bytes % physical_sector_size == 0:
        alignment = f'{physical_sector_size}B'
    else:
        alignment = 'none'

    return is_aligned, alignment, issues


def format_bytes(num_bytes: int) -> str:
    """Format bytes in human-readable form."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024:
            return f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}TB"


def analyze_device(device: str, context: Context, verbose: bool = False) -> dict[str, Any]:
    """Analyze partition alignment for a device."""
    size, model = get_device_info(device, context)
    logical_ss, physical_ss = get_sector_sizes(device, context)
    optimal_io, min_io = get_optimal_io_size(device, context)
    ssd = is_ssd(device, context)

    result = {
        'device': device,
        'path': f'/dev/{device}',
        'size': size,
        'model': model,
        'type': 'SSD' if ssd else 'HDD',
        'logical_sector_size': logical_ss,
        'physical_sector_size': physical_ss,
        'optimal_io_size': optimal_io,
        'partitions': [],
        'issues': [],
        'status': 'OK'
    }

    result['advanced_format'] = physical_ss > logical_ss

    # Get partitions (try sfdisk first, then lsblk)
    partitions = get_partitions_sfdisk(device, context)
    if partitions is None:
        partitions = get_partitions_lsblk(device, context)

    if not partitions:
        return result

    for part in partitions:
        is_aligned, alignment, issues = check_alignment(
            part['start_sector'],
            logical_ss,
            physical_ss,
            optimal_io
        )

        part_info = {
            'number': part['number'],
            'start_sector': part['start_sector'],
            'start_bytes': part['start_sector'] * logical_ss,
            'aligned': is_aligned,
            'alignment': alignment,
            'issues': issues
        }

        result['partitions'].append(part_info)

        for issue in issues:
            if issue['severity'] in ['ERROR', 'WARNING']:
                result['issues'].append({
                    'severity': issue['severity'],
                    'partition': part['number'],
                    'message': issue['message']
                })
                if result['status'] == 'OK':
                    result['status'] = 'WARNING'
                if issue['severity'] == 'ERROR':
                    result['status'] = 'ERROR'

    return result


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all aligned, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Check disk partition alignment")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("-d", "--device", help="Specific device to check")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for lsblk
    if not context.check_tool("lsblk"):
        output.error("lsblk not found")
        return 2

    # Get devices to check
    if opts.device:
        device = opts.device.replace('/dev/', '')
        devices = [device]
    else:
        devices = get_block_devices(context)

    if not devices:
        output.warning("No block devices found")
        output.emit({'devices': []})
        return 1

    # Analyze devices
    results = []
    has_issues = False

    for device in devices:
        result = analyze_device(device, context, opts.verbose)
        results.append(result)

        if result['status'] != 'OK':
            has_issues = True

    output.emit({'devices': results})

    # Set summary
    aligned_count = sum(1 for r in results if r['status'] == 'OK')
    total_count = len(results)

    if has_issues:
        misaligned_count = total_count - aligned_count
        output.set_summary(f"{misaligned_count} device(s) with alignment issues")
        return 1
    else:
        output.set_summary(f"All {total_count} device(s) properly aligned")
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
