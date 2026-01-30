#!/usr/bin/env python3
"""
Check disk partition alignment for optimal performance.

Partition alignment is critical for SSD and modern HDD performance. Misaligned
partitions cause read-modify-write cycles that significantly degrade I/O
performance. This is especially important for:

- SSDs with 4K or larger physical sectors
- Advanced Format HDDs (4K sector size)
- RAID arrays with specific stripe sizes
- NVMe drives with various LBA formats

The tool checks:
- Partition start offset alignment to physical sector size
- Optimal alignment for common configurations (1MiB boundary)
- Detection of legacy MBR-style misalignment (starting at sector 63)
- RAID stripe alignment when applicable

Exit codes:
    0 - All partitions properly aligned
    1 - Misaligned partitions found
    2 - Usage error or missing dependency
"""

import argparse
import subprocess
import sys
import json
import os
import re


def run_command(cmd, shell=False):
    """Execute a command and return output"""
    try:
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def get_block_devices():
    """Get list of block devices (disks)"""
    returncode, stdout, stderr = run_command(
        "lsblk -d -n -o NAME,TYPE | grep disk | awk '{print $1}'",
        shell=True
    )
    if returncode != 0:
        return []

    devices = []
    for dev in stdout.strip().split('\n'):
        if dev.strip():
            devices.append(dev.strip())
    return devices


def get_device_info(device):
    """Get device model and size"""
    dev_path = "/dev/{}".format(device)
    returncode, stdout, stderr = run_command(
        "lsblk -n -o SIZE,MODEL {} | head -1".format(dev_path),
        shell=True
    )

    if returncode != 0:
        return "N/A", "N/A"

    parts = stdout.strip().split(None, 1)
    size = parts[0] if len(parts) > 0 else "N/A"
    model = parts[1].strip() if len(parts) > 1 else "N/A"

    return size, model


def get_sector_sizes(device):
    """Get logical and physical sector sizes for a device"""
    queue_path = "/sys/block/{}/queue".format(device)

    logical_sector_size = 512  # default
    physical_sector_size = 512  # default

    try:
        with open(os.path.join(queue_path, "logical_block_size"), 'r') as f:
            logical_sector_size = int(f.read().strip())
    except (IOError, OSError, ValueError):
        pass

    try:
        with open(os.path.join(queue_path, "physical_block_size"), 'r') as f:
            physical_sector_size = int(f.read().strip())
    except (IOError, OSError, ValueError):
        pass

    return logical_sector_size, physical_sector_size


def get_optimal_io_size(device):
    """Get optimal I/O size hint from device"""
    queue_path = "/sys/block/{}/queue".format(device)

    optimal_io_size = 0
    minimum_io_size = 0

    try:
        with open(os.path.join(queue_path, "optimal_io_size"), 'r') as f:
            optimal_io_size = int(f.read().strip())
    except (IOError, OSError, ValueError):
        pass

    try:
        with open(os.path.join(queue_path, "minimum_io_size"), 'r') as f:
            minimum_io_size = int(f.read().strip())
    except (IOError, OSError, ValueError):
        pass

    return optimal_io_size, minimum_io_size


def is_ssd(device):
    """Check if device is an SSD (rotational = 0)"""
    rotational_path = "/sys/block/{}/queue/rotational".format(device)
    try:
        with open(rotational_path, 'r') as f:
            return f.read().strip() == '0'
    except (IOError, OSError):
        return device.startswith('nvme')


def get_partitions_parted(device):
    """Get partition information using parted"""
    dev_path = "/dev/{}".format(device)
    returncode, stdout, stderr = run_command(
        ['parted', '-s', '-m', dev_path, 'unit', 's', 'print'],
    )

    if returncode != 0:
        return None

    partitions = []
    lines = stdout.strip().split('\n')

    for line in lines:
        # Skip header lines and empty lines
        if not line or line.startswith('BYT;') or line.startswith('/dev/'):
            continue

        parts = line.rstrip(';').split(':')
        if len(parts) >= 4:
            try:
                # Format: number:start:end:size:filesystem:name:flags
                part_num = parts[0]
                # Remove 's' suffix from sector values
                start_sectors = int(parts[1].rstrip('s'))
                end_sectors = int(parts[2].rstrip('s'))
                size_sectors = int(parts[3].rstrip('s'))

                partitions.append({
                    'number': part_num,
                    'start_sector': start_sectors,
                    'end_sector': end_sectors,
                    'size_sectors': size_sectors,
                    'filesystem': parts[4] if len(parts) > 4 else '',
                    'name': parts[5] if len(parts) > 5 else '',
                })
            except (ValueError, IndexError):
                continue

    return partitions


def get_partitions_sfdisk(device):
    """Get partition information using sfdisk (fallback)"""
    dev_path = "/dev/{}".format(device)
    returncode, stdout, stderr = run_command(
        ['sfdisk', '-d', dev_path],
    )

    if returncode != 0:
        return None

    partitions = []

    for line in stdout.strip().split('\n'):
        # Parse lines like: /dev/sda1 : start=     2048, size=   1048576, type=...
        match = re.match(r'^(/dev/\S+)\s*:\s*start=\s*(\d+)', line)
        if match:
            part_path, start = match.groups()
            part_name = os.path.basename(part_path)
            # Extract partition number
            part_num = re.sub(r'^[a-z]+', '', part_name.replace(device, ''))

            partitions.append({
                'number': part_num or '?',
                'start_sector': int(start),
                'end_sector': 0,  # sfdisk -d doesn't give us this easily
                'size_sectors': 0,
                'filesystem': '',
                'name': part_name,
            })

    return partitions


def get_partitions(device):
    """Get partition information for a device"""
    # Try parted first
    partitions = get_partitions_parted(device)
    if partitions is not None:
        return partitions

    # Fall back to sfdisk
    partitions = get_partitions_sfdisk(device)
    if partitions is not None:
        return partitions

    return []


def check_alignment(start_sector, logical_sector_size, physical_sector_size,
                    optimal_io_size=0):
    """
    Check if a partition start is properly aligned.

    Returns tuple: (is_aligned, alignment_boundary, issues)
    """
    issues = []

    # Calculate start offset in bytes
    start_bytes = start_sector * logical_sector_size

    # Check alignment to physical sector size
    if start_bytes % physical_sector_size != 0:
        issues.append({
            'severity': 'ERROR',
            'type': 'physical_sector',
            'message': 'Not aligned to physical sector size ({}B)'.format(
                physical_sector_size
            )
        })

    # Check for 1MiB alignment (modern standard, 1048576 bytes)
    mib_boundary = 1048576
    aligned_to_mib = start_bytes % mib_boundary == 0

    # Check for 4K alignment (4096 bytes)
    aligned_to_4k = start_bytes % 4096 == 0

    # Legacy misalignment detection (sector 63 was common for old MBR)
    if start_sector == 63:
        issues.append({
            'severity': 'WARNING',
            'type': 'legacy_mbr',
            'message': 'Legacy MBR alignment at sector 63 (misaligned for modern drives)'
        })

    # Check optimal I/O size alignment if provided
    if optimal_io_size > 0 and start_bytes % optimal_io_size != 0:
        issues.append({
            'severity': 'WARNING',
            'type': 'optimal_io',
            'message': 'Not aligned to optimal I/O size ({}B)'.format(
                optimal_io_size
            )
        })

    # Determine overall alignment status
    if issues:
        # Check if any are errors (not warnings)
        has_errors = any(i['severity'] == 'ERROR' for i in issues)
        is_aligned = False
    else:
        is_aligned = True
        has_errors = False

    # Determine what it's aligned to
    if aligned_to_mib:
        alignment = '1MiB'
    elif aligned_to_4k:
        alignment = '4K'
    elif start_bytes % physical_sector_size == 0:
        alignment = '{}B'.format(physical_sector_size)
    else:
        alignment = 'none'

    return is_aligned, alignment, issues


def format_bytes(num_bytes):
    """Format bytes in human-readable form"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024:
            return "{:.1f}{}".format(num_bytes, unit)
        num_bytes /= 1024
    return "{:.1f}TB".format(num_bytes)


def analyze_device(device, verbose=False):
    """Analyze partition alignment for a device"""
    dev_path = "/dev/{}".format(device)
    size, model = get_device_info(device)
    logical_ss, physical_ss = get_sector_sizes(device)
    optimal_io, min_io = get_optimal_io_size(device)
    ssd = is_ssd(device)

    result = {
        'device': device,
        'path': dev_path,
        'size': size,
        'model': model,
        'type': 'SSD' if ssd else 'HDD',
        'logical_sector_size': logical_ss,
        'physical_sector_size': physical_ss,
        'optimal_io_size': optimal_io,
        'minimum_io_size': min_io,
        'partitions': [],
        'issues': [],
        'status': 'OK'
    }

    # Check for Advanced Format drive (4K physical sectors)
    if physical_ss > logical_ss:
        result['advanced_format'] = True
        if verbose:
            result['issues'].append({
                'severity': 'INFO',
                'message': 'Advanced Format drive ({}B physical, {}B logical)'.format(
                    physical_ss, logical_ss
                )
            })
    else:
        result['advanced_format'] = False

    # Get partitions
    partitions = get_partitions(device)

    if not partitions:
        if verbose:
            result['issues'].append({
                'severity': 'INFO',
                'message': 'No partitions found'
            })
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

        # Aggregate issues to device level
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


def format_output_plain(results, warn_only, verbose):
    """Format output as plain text"""
    if not results:
        print("No block devices found")
        return

    print("Partition Alignment Report")
    print("=" * 70)
    print()

    devices_shown = 0

    for result in results:
        if warn_only and result['status'] == 'OK':
            continue

        devices_shown += 1

        status_symbol = {
            'OK': '[OK]',
            'WARNING': '[WARN]',
            'ERROR': '[ERR]'
        }.get(result['status'], '[???]')

        print("{} {} ({}) - {} {}".format(
            status_symbol,
            result['device'],
            result['type'],
            result['size'],
            result['model']
        ))

        if verbose or result['status'] != 'OK':
            print("    Sector sizes: logical={}B, physical={}B".format(
                result['logical_sector_size'],
                result['physical_sector_size']
            ))
            if result['optimal_io_size'] > 0:
                print("    Optimal I/O: {}".format(
                    format_bytes(result['optimal_io_size'])
                ))

        for part in result['partitions']:
            if warn_only and part['aligned']:
                continue

            status = "aligned" if part['aligned'] else "MISALIGNED"
            print("    Partition {}: sector {} ({}) - {} to {}".format(
                part['number'],
                part['start_sector'],
                format_bytes(part['start_bytes']),
                status,
                part['alignment']
            ))

            for issue in part['issues']:
                print("      {}: {}".format(issue['severity'], issue['message']))

        print()

    if devices_shown == 0:
        if warn_only:
            print("All partitions are properly aligned")
        else:
            print("No block devices found")


def format_output_table(results, warn_only):
    """Format output as table"""
    print("{:<12} {:<6} {:<10} {:<12} {:<10} {:<10} {}".format(
        "Device", "Part", "Start", "Offset", "Aligned", "Boundary", "Issues"
    ))
    print("-" * 80)

    for result in results:
        for part in result['partitions']:
            if warn_only and part['aligned']:
                continue

            issue_count = len(part['issues'])
            issues_str = "{} issue(s)".format(issue_count) if issue_count else ""

            print("{:<12} {:<6} {:<10} {:<12} {:<10} {:<10} {}".format(
                result['device'],
                part['number'],
                part['start_sector'],
                format_bytes(part['start_bytes']),
                'Yes' if part['aligned'] else 'No',
                part['alignment'],
                issues_str
            ))


def format_output_json(results):
    """Format output as JSON"""
    print(json.dumps({'devices': results}, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Check disk partition alignment for optimal performance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Partition Alignment Guidelines:
  - Modern drives should have partitions aligned to 1MiB (2048 sectors)
  - At minimum, partitions should be aligned to 4K (8 sectors for 512B logical)
  - SSDs and Advanced Format HDDs are especially sensitive to misalignment
  - Legacy sector 63 alignment causes significant performance degradation

Examples:
  %(prog)s                    # Check all devices
  %(prog)s -d sda             # Check specific device
  %(prog)s --format json      # JSON output for automation
  %(prog)s --warn-only        # Only show misaligned partitions
"""
    )

    parser.add_argument(
        "-d", "--device",
        help="Specific device to check (e.g., sda, nvme0n1)"
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
        help="Show detailed information including aligned partitions"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show misaligned partitions"
    )

    args = parser.parse_args()

    # Get devices to check
    if args.device:
        device = args.device.replace('/dev/', '')
        devices = [device]
    else:
        devices = get_block_devices()

    if not devices:
        print("No block devices found")
        sys.exit(0)

    # Analyze devices
    results = []
    has_issues = False

    for device in devices:
        result = analyze_device(device, args.verbose)
        results.append(result)

        if result['status'] != 'OK':
            has_issues = True

    # Output results
    if args.format == "json":
        format_output_json(results)
    elif args.format == "table":
        format_output_table(results, args.warn_only)
    else:
        format_output_plain(results, args.warn_only, args.verbose)

    # Exit with appropriate code
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
