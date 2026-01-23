#!/usr/bin/env python3
"""
Monitor TRIM/discard support status for SSDs and NVMe drives.

TRIM (ATA) or unmap/deallocate (NVMe/SCSI) commands allow the OS to inform
SSDs which blocks are no longer in use, enabling the drive's garbage collection
to work efficiently. Without TRIM, SSD performance degrades over time as the
drive cannot distinguish used from unused blocks.

This tool checks:
- Whether the block device supports discard operations
- Filesystem mount options (discard vs fstrim)
- Actual discard granularity and alignment
- Identifies misconfigured SSDs that should have TRIM enabled

Exit codes:
    0 - All SSDs have proper TRIM configuration
    1 - SSDs found with TRIM misconfiguration or warnings
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
    """Get list of block devices that could be SSDs"""
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


def is_ssd(device):
    """Check if device is an SSD (rotational = 0)"""
    rotational_path = "/sys/block/{}/queue/rotational".format(device)
    try:
        with open(rotational_path, 'r') as f:
            return f.read().strip() == '0'
    except (IOError, OSError):
        # If we can't determine, check if it's NVMe (always SSD)
        return device.startswith('nvme')


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


def get_discard_support(device):
    """Check if device supports discard operations"""
    queue_path = "/sys/block/{}/queue".format(device)

    result = {
        'supported': False,
        'discard_granularity': 0,
        'discard_max_bytes': 0,
        'discard_zeroes_data': False
    }

    # Check discard_granularity - if non-zero, discard is supported
    granularity_path = os.path.join(queue_path, "discard_granularity")
    try:
        with open(granularity_path, 'r') as f:
            result['discard_granularity'] = int(f.read().strip())
            result['supported'] = result['discard_granularity'] > 0
    except (IOError, OSError, ValueError):
        pass

    # Check discard_max_bytes
    max_bytes_path = os.path.join(queue_path, "discard_max_bytes")
    try:
        with open(max_bytes_path, 'r') as f:
            result['discard_max_bytes'] = int(f.read().strip())
    except (IOError, OSError, ValueError):
        pass

    # Check discard_zeroes_data (deprecated but useful info)
    zeroes_path = os.path.join(queue_path, "discard_zeroes_data")
    try:
        with open(zeroes_path, 'r') as f:
            result['discard_zeroes_data'] = f.read().strip() == '1'
    except (IOError, OSError):
        pass

    return result


def get_mount_info():
    """Get mount information for all filesystems"""
    returncode, stdout, stderr = run_command(['mount'])
    if returncode != 0:
        return {}

    mounts = {}
    for line in stdout.split('\n'):
        if not line:
            continue
        # Format: /dev/sda1 on /mnt type ext4 (rw,discard)
        match = re.match(r'^(/dev/\S+) on (\S+) type (\S+) \(([^)]*)\)', line)
        if match:
            device, mountpoint, fstype, options = match.groups()
            mounts[device] = {
                'mountpoint': mountpoint,
                'fstype': fstype,
                'options': options.split(','),
                'has_discard': 'discard' in options
            }

    return mounts


def get_fstab_info():
    """Parse /etc/fstab for discard mount options"""
    fstab = {}
    try:
        with open('/etc/fstab', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    device, mountpoint, fstype, options = parts[0:4]
                    fstab[device] = {
                        'mountpoint': mountpoint,
                        'fstype': fstype,
                        'options': options.split(','),
                        'has_discard': 'discard' in options
                    }
    except (IOError, OSError):
        pass

    return fstab


def check_fstrim_timer():
    """Check if fstrim.timer is enabled (systemd)"""
    returncode, stdout, stderr = run_command(
        ['systemctl', 'is-enabled', 'fstrim.timer']
    )
    if returncode == 0:
        return stdout.strip() == 'enabled'

    # Also check if it's active
    returncode, stdout, stderr = run_command(
        ['systemctl', 'is-active', 'fstrim.timer']
    )
    return returncode == 0


def get_partitions(device):
    """Get partitions for a device"""
    returncode, stdout, stderr = run_command(
        "lsblk -n -o NAME /dev/{} | tail -n +2".format(device),
        shell=True
    )
    if returncode != 0:
        return []

    partitions = []
    for line in stdout.strip().split('\n'):
        part = line.strip().lstrip('├─└─│ ')
        if part:
            partitions.append(part)
    return partitions


def analyze_device(device, mounts, fstab, fstrim_enabled, verbose):
    """Analyze TRIM status for a single device"""
    dev_path = "/dev/{}".format(device)
    size, model = get_device_info(device)
    discard_info = get_discard_support(device)
    is_nvme = device.startswith('nvme')

    result = {
        'device': device,
        'path': dev_path,
        'size': size,
        'model': model,
        'type': 'NVMe' if is_nvme else 'SATA/SAS SSD',
        'discard_supported': discard_info['supported'],
        'discard_granularity': discard_info['discard_granularity'],
        'discard_max_bytes': discard_info['discard_max_bytes'],
        'partitions': [],
        'issues': [],
        'status': 'OK'
    }

    if not discard_info['supported']:
        result['issues'].append({
            'severity': 'WARNING',
            'message': 'Device does not support discard operations'
        })
        result['status'] = 'WARNING'
        return result

    # Check partitions/mounts
    partitions = get_partitions(device)

    for part in partitions:
        part_path = "/dev/{}".format(part)
        part_info = {
            'partition': part,
            'mounted': False,
            'mountpoint': None,
            'has_discard_mount': False,
            'in_fstab': False,
            'fstab_has_discard': False
        }

        # Check if mounted
        if part_path in mounts:
            mount = mounts[part_path]
            part_info['mounted'] = True
            part_info['mountpoint'] = mount['mountpoint']
            part_info['has_discard_mount'] = mount['has_discard']
            part_info['fstype'] = mount['fstype']

        # Check fstab
        for fstab_dev, fstab_mount in fstab.items():
            # Handle UUID= and LABEL= entries
            if part_path in fstab_dev or fstab_dev.endswith(part):
                part_info['in_fstab'] = True
                part_info['fstab_has_discard'] = fstab_mount['has_discard']
                break

        result['partitions'].append(part_info)

        # Check for issues
        if part_info['mounted'] and not part_info['has_discard_mount']:
            if not fstrim_enabled:
                result['issues'].append({
                    'severity': 'WARNING',
                    'message': '{} mounted without discard option and fstrim.timer not enabled'.format(part)
                })
                result['status'] = 'WARNING'
            elif verbose:
                result['issues'].append({
                    'severity': 'INFO',
                    'message': '{} using fstrim.timer instead of mount discard (recommended)'.format(part)
                })

    # Also check if whole disk is in mounts (e.g., /dev/nvme0n1 without partitions)
    if dev_path in mounts and not partitions:
        mount = mounts[dev_path]
        if not mount['has_discard'] and not fstrim_enabled:
            result['issues'].append({
                'severity': 'WARNING',
                'message': 'Device mounted without discard and fstrim.timer not enabled'
            })
            result['status'] = 'WARNING'

    return result


def format_bytes(num_bytes):
    """Format bytes in human-readable form"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024:
            return "{:.1f}{}".format(num_bytes, unit)
        num_bytes /= 1024
    return "{:.1f}TB".format(num_bytes)


def format_output_plain(results, fstrim_enabled, warn_only, verbose):
    """Format output as plain text"""
    if not results:
        print("No SSDs found")
        return

    print("TRIM/Discard Status Report")
    print("=" * 60)
    print("fstrim.timer: {}".format("ENABLED" if fstrim_enabled else "DISABLED"))
    print()

    for result in results:
        if warn_only and result['status'] == 'OK' and not result['issues']:
            continue

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

        if result['discard_supported']:
            print("    Discard: supported (granularity: {}, max: {})".format(
                format_bytes(result['discard_granularity']),
                format_bytes(result['discard_max_bytes'])
            ))
        else:
            print("    Discard: NOT SUPPORTED")

        if verbose or result['issues']:
            for part in result['partitions']:
                if part['mounted']:
                    discard_str = "discard" if part['has_discard_mount'] else "no discard"
                    print("    {} -> {} ({})".format(
                        part['partition'],
                        part['mountpoint'],
                        discard_str
                    ))

        for issue in result['issues']:
            print("    {}: {}".format(issue['severity'], issue['message']))

        print()


def format_output_table(results, warn_only):
    """Format output as table"""
    if warn_only:
        results = [r for r in results if r['status'] != 'OK' or r['issues']]

    if not results:
        print("No SSDs with TRIM issues found")
        return

    print("{:<12} {:<10} {:<8} {:<10} {:<10} {}".format(
        "Device", "Type", "Size", "Discard", "Status", "Issues"
    ))
    print("-" * 70)

    for result in results:
        issue_count = len(result['issues'])
        issues_str = "{} issue(s)".format(issue_count) if issue_count else "OK"

        print("{:<12} {:<10} {:<8} {:<10} {:<10} {}".format(
            result['device'],
            'NVMe' if 'nvme' in result['device'] else 'SSD',
            result['size'],
            'Yes' if result['discard_supported'] else 'No',
            result['status'],
            issues_str
        ))


def format_output_json(results, fstrim_enabled):
    """Format output as JSON"""
    output = {
        'fstrim_timer_enabled': fstrim_enabled,
        'devices': results
    }
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Monitor TRIM/discard status for SSDs and NVMe drives",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
TRIM Configuration Best Practices:
  1. Use fstrim.timer (recommended) - weekly batch TRIM operations
  2. Or use 'discard' mount option - continuous TRIM (higher overhead)
  3. Ensure your SSD supports and has TRIM enabled

Examples:
  %(prog)s                    # Check all SSDs
  %(prog)s -d nvme0n1         # Check specific device
  %(prog)s --format json      # JSON output for automation
  %(prog)s --warn-only        # Only show issues
"""
    )

    parser.add_argument(
        "-d", "--device",
        help="Specific device to check (e.g., nvme0n1, sda)"
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
        help="Show detailed information including partition mount status"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show devices with TRIM issues"
    )

    args = parser.parse_args()

    # Get system information
    mounts = get_mount_info()
    fstab = get_fstab_info()
    fstrim_enabled = check_fstrim_timer()

    # Get devices to check
    if args.device:
        # Strip /dev/ prefix if provided
        device = args.device.replace('/dev/', '')
        if not is_ssd(device):
            print("Warning: {} does not appear to be an SSD".format(device),
                  file=sys.stderr)
        devices = [device]
    else:
        all_devices = get_block_devices()
        devices = [d for d in all_devices if is_ssd(d)]

    if not devices:
        print("No SSDs found")
        sys.exit(0)

    # Analyze devices
    results = []
    has_issues = False

    for device in devices:
        result = analyze_device(device, mounts, fstab, fstrim_enabled, args.verbose)
        results.append(result)

        if result['status'] != 'OK':
            has_issues = True

    # Output results
    if args.format == "json":
        format_output_json(results, fstrim_enabled)
    elif args.format == "table":
        format_output_table(results, args.warn_only)
    else:
        format_output_plain(results, fstrim_enabled, args.warn_only, args.verbose)

    # Exit with appropriate code
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
