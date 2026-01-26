#!/usr/bin/env python3
"""
Monitor SCSI/SAS device error counters from sysfs.

Tracks SCSI error counters (iotmo_cnt, iodone_cnt, ioerr_cnt, iorequest_cnt)
for early detection of failing disks, SAS cables, or HBA issues. Useful for
monitoring large baremetal fleets with SAS disk arrays where SCSI-level
errors can indicate problems before full disk failure.

The script reads from /sys/class/scsi_device/*/device/ which provides:
- iorequest_cnt: Total I/O requests sent
- iodone_cnt: I/O requests completed successfully
- ioerr_cnt: I/O requests that resulted in errors
- iotmo_cnt: I/O requests that timed out
- device type, vendor, model, and revision

These counters are cumulative since boot and non-zero error counts
warrant investigation, especially if they increase over time.

Exit codes:
    0 - No errors detected
    1 - Errors or warnings found
    2 - Missing dependencies or usage error
"""

import argparse
import sys
import json
from pathlib import Path


def get_scsi_devices():
    """Get list of SCSI devices from /sys/class/scsi_device/"""
    try:
        scsi_class = Path('/sys/class/scsi_device')
        if not scsi_class.exists():
            return []

        devices = []
        for device_link in scsi_class.iterdir():
            device_path = device_link / 'device'
            if device_path.exists():
                devices.append({
                    'id': device_link.name,
                    'path': device_path
                })

        return sorted(devices, key=lambda x: x['id'])
    except Exception as e:
        print(f"Error listing SCSI devices: {e}", file=sys.stderr)
        return []


def read_sysfs_file(path):
    """Read a sysfs file and return stripped content or None."""
    try:
        if path.exists():
            with open(path, 'r') as f:
                return f.read().strip()
    except (PermissionError, IOError):
        pass
    return None


def read_sysfs_int(path):
    """Read a sysfs file and return integer value or 0."""
    content = read_sysfs_file(path)
    if content:
        try:
            return int(content, 0)  # base 0 handles hex (0x) prefix
        except ValueError:
            pass
    return 0


def get_device_info(device_path):
    """Get SCSI device information from sysfs."""
    info = {
        'vendor': read_sysfs_file(device_path / 'vendor') or 'Unknown',
        'model': read_sysfs_file(device_path / 'model') or 'Unknown',
        'rev': read_sysfs_file(device_path / 'rev') or '',
        'type': read_sysfs_file(device_path / 'type') or 'Unknown',
        'state': read_sysfs_file(device_path / 'state') or 'Unknown',
    }

    # Get the block device name if this is a disk
    block_path = device_path / 'block'
    if block_path.exists():
        try:
            block_devices = list(block_path.iterdir())
            if block_devices:
                info['block_device'] = block_devices[0].name
        except Exception:
            pass

    return info


def get_error_counters(device_path):
    """Get SCSI error counters from sysfs."""
    return {
        'iorequest_cnt': read_sysfs_int(device_path / 'iorequest_cnt'),
        'iodone_cnt': read_sysfs_int(device_path / 'iodone_cnt'),
        'ioerr_cnt': read_sysfs_int(device_path / 'ioerr_cnt'),
        'iotmo_cnt': read_sysfs_int(device_path / 'iotmo_cnt'),
    }


def get_device_type_name(type_code):
    """Convert SCSI device type code to name."""
    # SCSI device type codes per SPC specification
    types = {
        '0': 'disk',
        '1': 'tape',
        '2': 'printer',
        '3': 'processor',
        '4': 'worm',
        '5': 'cdrom',
        '6': 'scanner',
        '7': 'optical',
        '8': 'changer',
        '9': 'comm',
        '12': 'raid',
        '13': 'enclosure',
        '14': 'rbc',
    }
    return types.get(type_code, f'type-{type_code}')


def analyze_device_health(counters, info):
    """
    Analyze SCSI error counters for potential issues.

    Returns (status, issues_list)
    status: 'healthy', 'warning', 'critical'
    """
    issues = []

    # Check for I/O errors
    if counters['ioerr_cnt'] > 0:
        issues.append(f"I/O errors: {counters['ioerr_cnt']}")

    # Check for I/O timeouts (often indicates cable/path issues)
    if counters['iotmo_cnt'] > 0:
        issues.append(f"I/O timeouts: {counters['iotmo_cnt']}")

    # Check device state
    if info['state'] not in ('running', 'Unknown'):
        issues.append(f"Device state: {info['state']}")

    # Calculate error rate if we have I/O requests
    if counters['iorequest_cnt'] > 0:
        error_rate = (counters['ioerr_cnt'] + counters['iotmo_cnt']) / counters['iorequest_cnt']
        if error_rate > 0.01:  # More than 1% error rate
            issues.append(f"High error rate: {error_rate:.2%}")

    # Check for mismatched request/done counts
    if counters['iorequest_cnt'] > 0:
        done_ratio = counters['iodone_cnt'] / counters['iorequest_cnt']
        if done_ratio < 0.99:  # Less than 99% completion
            pending = counters['iorequest_cnt'] - counters['iodone_cnt'] - counters['ioerr_cnt']
            if pending > 100:  # Significant pending I/O
                issues.append(f"High pending I/O: {pending}")

    # Determine severity
    if not issues:
        return 'healthy', []
    elif counters['ioerr_cnt'] > 100 or counters['iotmo_cnt'] > 10:
        return 'critical', issues
    else:
        return 'warning', issues


def output_plain(results, verbose=False, warn_only=False):
    """Output in plain text format."""
    for result in results:
        status, issues = result['health']

        if warn_only and status == 'healthy':
            continue

        device_id = result['id']
        info = result['info']
        counters = result['counters']

        # Build device description
        device_name = info.get('block_device', '')
        device_type = get_device_type_name(info['type'])
        vendor_model = f"{info['vendor'].strip()} {info['model'].strip()}"

        if device_name:
            print(f"{device_id} ({device_name}, {device_type}): {vendor_model} - {status.upper()}")
        else:
            print(f"{device_id} ({device_type}): {vendor_model} - {status.upper()}")

        if verbose or status != 'healthy':
            print(f"  Requests: {counters['iorequest_cnt']}, "
                  f"Done: {counters['iodone_cnt']}, "
                  f"Errors: {counters['ioerr_cnt']}, "
                  f"Timeouts: {counters['iotmo_cnt']}")
            print(f"  State: {info['state']}")

        if issues:
            for issue in issues:
                print(f"  WARNING: {issue}")

        if verbose or status != 'healthy':
            print()


def output_json(results, warn_only=False):
    """Output in JSON format."""
    output = []

    for result in results:
        status, issues = result['health']

        if warn_only and status == 'healthy':
            continue

        output.append({
            'scsi_id': result['id'],
            'block_device': result['info'].get('block_device'),
            'vendor': result['info']['vendor'].strip(),
            'model': result['info']['model'].strip(),
            'revision': result['info']['rev'].strip(),
            'type': get_device_type_name(result['info']['type']),
            'state': result['info']['state'],
            'status': status,
            'issues': issues,
            'counters': result['counters']
        })

    print(json.dumps(output, indent=2))


def output_table(results, warn_only=False):
    """Output in table format."""
    # Print header
    print(f"{'SCSI ID':<12} {'Device':<8} {'Type':<10} {'Vendor/Model':<25} "
          f"{'Errors':<8} {'Timeouts':<10} {'Status':<10} {'Issues'}")
    print("-" * 110)

    for result in results:
        status, issues = result['health']

        if warn_only and status == 'healthy':
            continue

        device_id = result['id']
        info = result['info']
        counters = result['counters']

        device_name = info.get('block_device', '-')
        device_type = get_device_type_name(info['type'])[:10]
        vendor_model = f"{info['vendor'].strip()} {info['model'].strip()}"[:25]

        issues_str = '; '.join(issues) if issues else '-'
        if len(issues_str) > 25:
            issues_str = issues_str[:22] + '...'

        print(f"{device_id:<12} {device_name:<8} {device_type:<10} {vendor_model:<25} "
              f"{counters['ioerr_cnt']:<8} {counters['iotmo_cnt']:<10} "
              f"{status:<10} {issues_str}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor SCSI/SAS device error counters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check all SCSI devices
  %(prog)s --format json        # JSON output
  %(prog)s --warn-only          # Only show devices with issues
  %(prog)s -v                   # Verbose output

Error counters explained:
  iorequest_cnt - Total I/O requests sent to device
  iodone_cnt    - I/O requests completed successfully
  ioerr_cnt     - I/O requests that resulted in errors
  iotmo_cnt     - I/O requests that timed out

Non-zero ioerr_cnt or iotmo_cnt values warrant investigation.
Timeouts often indicate SAS cable, expander, or HBA issues.
Errors may indicate media problems or device failure.

Exit codes:
  0 - No errors detected
  1 - Errors or warnings found
  2 - Missing dependencies or usage error
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
        help='Show detailed statistics for all devices'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show devices with warnings or issues'
    )

    parser.add_argument(
        '--disks-only',
        action='store_true',
        help='Only show disk devices (type 0)'
    )

    args = parser.parse_args()

    # Check if /sys/class/scsi_device exists
    if not Path('/sys/class/scsi_device').exists():
        print("Error: /sys/class/scsi_device not found", file=sys.stderr)
        print("SCSI subsystem may not be loaded or this is not a Linux system",
              file=sys.stderr)
        sys.exit(2)

    # Get SCSI devices
    devices = get_scsi_devices()

    if not devices:
        print("Error: No SCSI devices found", file=sys.stderr)
        sys.exit(2)

    # Collect statistics
    results = []
    has_issues = False

    for device in devices:
        info = get_device_info(device['path'])

        # Filter to disks only if requested
        if args.disks_only and info['type'] != '0':
            continue

        counters = get_error_counters(device['path'])
        health = analyze_device_health(counters, info)

        results.append({
            'id': device['id'],
            'info': info,
            'counters': counters,
            'health': health
        })

        # Check if this device has issues
        if health[0] in ('warning', 'critical'):
            has_issues = True

    if not results:
        if args.disks_only:
            print("No SCSI disk devices found", file=sys.stderr)
        else:
            print("No SCSI device statistics collected", file=sys.stderr)
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
