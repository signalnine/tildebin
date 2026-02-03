#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, encryption, luks, disk, storage]
#   requires: [cryptsetup]
#   privilege: root
#   related: [disk_health, firmware_security]
#   brief: Check disk encryption status for LUKS/dm-crypt volumes

"""
Monitor disk encryption status for LUKS/dm-crypt volumes.

Checks block devices for encryption status, reports LUKS version,
cipher details, and identifies unencrypted partitions that may need
protection. Useful for security compliance auditing.

Returns exit code 1 if unencrypted data partitions are found.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_block_devices(context: Context) -> list[dict[str, Any]]:
    """Get list of block devices with partition info."""
    result = context.run(['lsblk', '-n', '-o', 'NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE', '-l'], check=False)
    if result.returncode != 0:
        return []

    devices = []
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0]
            dev_type = parts[1]
            size = parts[2] if len(parts) > 2 else "N/A"
            mountpoint = parts[3] if len(parts) > 3 else ""
            fstype = parts[4] if len(parts) > 4 else ""

            devices.append({
                'name': name,
                'path': f"/dev/{name}",
                'type': dev_type,
                'size': size,
                'mountpoint': mountpoint,
                'fstype': fstype,
            })

    return devices


def check_luks_status(device_path: str, context: Context) -> dict[str, Any] | None:
    """Check if a device is LUKS encrypted."""
    result = context.run(['cryptsetup', 'isLuks', device_path], check=False)

    if result.returncode == 0:
        # Device is LUKS encrypted, get details
        return get_luks_details(device_path, context)

    return None


def get_luks_details(device_path: str, context: Context) -> dict[str, Any]:
    """Get LUKS encryption details for a device."""
    result = context.run(['cryptsetup', 'luksDump', device_path], check=False)

    if result.returncode != 0:
        return {
            'encrypted': True,
            'type': 'LUKS',
            'error': result.stderr.strip() or "Unable to read LUKS header",
        }

    details = {
        'encrypted': True,
        'type': 'LUKS',
        'version': None,
        'cipher': None,
        'cipher_mode': None,
        'hash': None,
        'key_slots_used': 0,
    }

    for line in result.stdout.split('\n'):
        line = line.strip()
        if line.startswith('Version:'):
            details['version'] = line.split(':', 1)[1].strip()
        elif line.startswith('Cipher name:'):
            details['cipher'] = line.split(':', 1)[1].strip()
        elif line.startswith('Cipher mode:'):
            details['cipher_mode'] = line.split(':', 1)[1].strip()
        elif line.startswith('Hash spec:'):
            details['hash'] = line.split(':', 1)[1].strip()
        elif 'ENABLED' in line and 'Key Slot' in line:
            details['key_slots_used'] += 1

    return details


def check_dm_crypt_status(device_name: str, context: Context) -> dict[str, Any] | None:
    """Check if device is an active dm-crypt mapping."""
    dm_path = f"/sys/block/{device_name}/dm/uuid"
    if context.file_exists(dm_path):
        try:
            uuid = context.read_file(dm_path).strip()
            if uuid.startswith('CRYPT-'):
                return {
                    'encrypted': True,
                    'type': 'dm-crypt',
                    'uuid': uuid,
                }
        except Exception:
            pass
    return None


def is_data_partition(device: dict[str, Any]) -> bool:
    """Determine if a partition likely contains user data."""
    # Skip certain device types
    if device['type'] in ['disk', 'rom', 'loop']:
        return False

    # Skip swap partitions
    if device['fstype'] == 'swap':
        return False

    # Skip EFI system partition
    if device['mountpoint'] in ['/boot/efi', '/boot']:
        return False

    # Skip crypto_LUKS (these are encrypted containers)
    if device['fstype'] == 'crypto_LUKS':
        return False

    # Skip dm-crypt mapped devices (already encrypted)
    if device['name'].startswith('dm-'):
        return False

    # Skip LVM physical volumes that are likely inside LUKS
    if device['fstype'] == 'LVM2_member':
        return False

    # Partitions with actual filesystems are data partitions
    if device['fstype'] in ['ext4', 'ext3', 'xfs', 'btrfs', 'ntfs', 'vfat']:
        return True

    # Partitions with mountpoints contain data
    if device['mountpoint']:
        return True

    return False


def analyze_encryption_status(
    devices: list[dict[str, Any]],
    context: Context,
    check_all: bool = False,
) -> tuple[list[dict[str, Any]], bool]:
    """Analyze encryption status of all devices."""
    results = []
    has_issues = False

    for device in devices:
        result = {
            'device': device['path'],
            'name': device['name'],
            'type': device['type'],
            'size': device['size'],
            'mountpoint': device['mountpoint'],
            'fstype': device['fstype'],
            'encryption': None,
            'is_data_partition': False,
            'warning': False,
        }

        # Check LUKS status for partitions
        if device['type'] == 'part':
            luks_info = check_luks_status(device['path'], context)
            if luks_info:
                result['encryption'] = luks_info

        # Check dm-crypt status for device mapper devices
        if device['name'].startswith('dm-') or device['type'] == 'crypt':
            dm_info = check_dm_crypt_status(device['name'], context)
            if dm_info:
                result['encryption'] = dm_info

        # Check if this is a data partition that should be encrypted
        result['is_data_partition'] = is_data_partition(device)

        # Flag unencrypted data partitions as warnings
        if result['is_data_partition'] and not result['encryption']:
            result['warning'] = True
            has_issues = True

        # Include in results if relevant
        if check_all or result['encryption'] or result['is_data_partition']:
            results.append(result)

    return results, has_issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all encrypted, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Check disk encryption status (LUKS/dm-crypt)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed encryption info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-a", "--all", action="store_true", help="Show all block devices")
    opts = parser.parse_args(args)

    # Check for cryptsetup
    if not context.check_tool('cryptsetup'):
        output.error("cryptsetup not found. Install cryptsetup package.")

        output.render(opts.format, "Check disk encryption status for LUKS/dm-crypt volumes")
        return 2

    # Get block devices
    devices = get_block_devices(context)
    if not devices:
        output.error("No block devices found")

        output.render(opts.format, "Check disk encryption status for LUKS/dm-crypt volumes")
        return 2

    # Analyze encryption status
    results, has_issues = analyze_encryption_status(devices, context, check_all=opts.all)

    # Build output data
    encrypted_count = sum(1 for r in results if r['encryption'])
    unencrypted_data = sum(1 for r in results if r['warning'])

    data = {
        'devices': results,
        'summary': {
            'total': len(results),
            'encrypted': encrypted_count,
            'unencrypted_data': unencrypted_data,
            'has_issues': has_issues,
        },
    }

    if not opts.verbose:
        # Remove detailed encryption info in non-verbose mode
        for device in data['devices']:
            if device['encryption']:
                device['encryption'] = {
                    'encrypted': True,
                    'type': device['encryption'].get('type', 'unknown'),
                }

    output.emit(data)

    # Generate summary
    if unencrypted_data > 0:
        output.set_summary(f"{unencrypted_data} unencrypted data partition(s)")
    else:
        output.set_summary(f"{encrypted_count} encrypted, no unencrypted data")

    output.render(opts.format, "Check disk encryption status for LUKS/dm-crypt volumes")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
