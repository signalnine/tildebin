#!/usr/bin/env python3
"""
Monitor disk encryption status for LUKS/dm-crypt volumes.

Checks block devices for encryption status, reports LUKS version,
cipher details, and identifies unencrypted partitions that may need
protection. Useful for security compliance auditing.

Exit codes:
    0 - All checked devices are encrypted (or no issues found)
    1 - Unencrypted data partitions found or encryption issues detected
    2 - Usage error or missing dependency (cryptsetup)
"""

import argparse
import subprocess
import sys
import json
import os


def run_command(cmd):
    """Execute a command and return output"""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def check_cryptsetup_available():
    """Check if cryptsetup is installed"""
    returncode, _, _ = run_command(["which", "cryptsetup"])
    return returncode == 0


def get_block_devices():
    """Get list of block devices with partition info"""
    returncode, stdout, stderr = run_command([
        "lsblk", "-n", "-o", "NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE", "-l"
    ])
    if returncode != 0:
        return []

    devices = []
    for line in stdout.strip().split('\n'):
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
                'path': "/dev/{}".format(name),
                'type': dev_type,
                'size': size,
                'mountpoint': mountpoint,
                'fstype': fstype
            })

    return devices


def check_luks_status(device_path):
    """Check if a device is LUKS encrypted"""
    # Check if device is a LUKS container
    returncode, stdout, stderr = run_command([
        "cryptsetup", "isLuks", device_path
    ])

    if returncode == 0:
        # Device is LUKS encrypted, get details
        return get_luks_details(device_path)

    return None


def get_luks_details(device_path):
    """Get LUKS encryption details for a device"""
    returncode, stdout, stderr = run_command([
        "cryptsetup", "luksDump", device_path
    ])

    if returncode != 0:
        return {
            'encrypted': True,
            'type': 'LUKS',
            'error': stderr.strip() or "Unable to read LUKS header"
        }

    details = {
        'encrypted': True,
        'type': 'LUKS',
        'version': None,
        'cipher': None,
        'cipher_mode': None,
        'hash': None,
        'key_slots_used': 0,
        'key_slots_total': 8
    }

    for line in stdout.split('\n'):
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


def check_dm_crypt_status(device_name):
    """Check if device is an active dm-crypt mapping"""
    dm_path = "/sys/block/{}/dm/uuid".format(device_name)
    if os.path.exists(dm_path):
        try:
            with open(dm_path, 'r') as f:
                uuid = f.read().strip()
                if uuid.startswith('CRYPT-'):
                    return {
                        'encrypted': True,
                        'type': 'dm-crypt',
                        'uuid': uuid
                    }
        except (IOError, OSError):
            pass
    return None


def is_data_partition(device):
    """Determine if a partition likely contains user data"""
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


def analyze_encryption_status(devices, check_all=False):
    """Analyze encryption status of all devices"""
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
            'warning': False
        }

        # Check LUKS status for partitions
        if device['type'] == 'part':
            luks_info = check_luks_status(device['path'])
            if luks_info:
                result['encryption'] = luks_info

        # Check dm-crypt status for device mapper devices
        if device['name'].startswith('dm-') or device['type'] == 'crypt':
            dm_info = check_dm_crypt_status(device['name'])
            if dm_info:
                result['encryption'] = dm_info

        # Check if this is a data partition that should be encrypted
        result['is_data_partition'] = is_data_partition(device)

        # Flag unencrypted data partitions as warnings
        if result['is_data_partition'] and not result['encryption']:
            result['warning'] = True
            has_issues = True

        # Include in results if it's relevant
        if check_all or result['encryption'] or result['is_data_partition']:
            results.append(result)

    return results, has_issues


def output_plain(results, verbose=False, warn_only=False):
    """Output results in plain text format"""
    if warn_only:
        results = [r for r in results if r['warning']]

    if not results:
        if warn_only:
            print("No encryption issues found")
        else:
            print("No relevant block devices found")
        return

    # Group by encryption status
    encrypted = [r for r in results if r['encryption']]
    unencrypted_data = [r for r in results if r['warning']]

    if encrypted:
        print("=== Encrypted Devices ===")
        for r in encrypted:
            enc = r['encryption']
            enc_type = enc.get('type', 'Unknown')
            version = enc.get('version', '')
            cipher = enc.get('cipher', '')
            cipher_mode = enc.get('cipher_mode', '')

            status_line = "{} ({}) - {} {}".format(
                r['device'], r['size'], enc_type,
                version if version else ""
            ).strip()

            print("  [OK] {}".format(status_line))

            if verbose and cipher:
                print("       Cipher: {}-{}".format(cipher, cipher_mode))
                if enc.get('hash'):
                    print("       Hash: {}".format(enc['hash']))
                if enc.get('key_slots_used'):
                    print("       Key slots: {}/{}".format(
                        enc['key_slots_used'], enc['key_slots_total']
                    ))
        print()

    if unencrypted_data:
        print("=== Unencrypted Data Partitions ===")
        for r in unencrypted_data:
            mount_info = " mounted at {}".format(r['mountpoint']) if r['mountpoint'] else ""
            fs_info = " ({})".format(r['fstype']) if r['fstype'] else ""
            print("  [WARN] {} ({}){}{}".format(
                r['device'], r['size'], fs_info, mount_info
            ))
        print()

    # Summary
    print("Summary: {} encrypted, {} unencrypted data partitions".format(
        len(encrypted), len(unencrypted_data)
    ))


def output_json(results):
    """Output results in JSON format"""
    output = {
        'devices': results,
        'summary': {
            'total': len(results),
            'encrypted': len([r for r in results if r['encryption']]),
            'unencrypted_data': len([r for r in results if r['warning']]),
            'has_issues': any(r['warning'] for r in results)
        }
    }
    print(json.dumps(output, indent=2))


def output_table(results, warn_only=False):
    """Output results in table format"""
    if warn_only:
        results = [r for r in results if r['warning']]

    if not results:
        print("No relevant devices found")
        return

    # Print header
    print("{:<15} {:<8} {:<10} {:<12} {:<20} {:<8}".format(
        "DEVICE", "SIZE", "TYPE", "ENCRYPTION", "MOUNTPOINT", "STATUS"
    ))
    print("-" * 80)

    for r in results:
        enc_type = ""
        if r['encryption']:
            enc = r['encryption']
            enc_type = "{} {}".format(
                enc.get('type', ''),
                enc.get('version', '')
            ).strip()

        status = "OK" if r['encryption'] else ("WARN" if r['warning'] else "-")

        print("{:<15} {:<8} {:<10} {:<12} {:<20} {:<8}".format(
            r['name'][:15],
            r['size'][:8],
            r['type'][:10],
            enc_type[:12] if enc_type else "-",
            (r['mountpoint'] or "-")[:20],
            status
        ))


def main():
    parser = argparse.ArgumentParser(
        description="Check disk encryption status (LUKS/dm-crypt)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    Show encryption status of data partitions
  %(prog)s --all              Show all block devices
  %(prog)s --format json      Output in JSON format
  %(prog)s --warn-only        Only show unencrypted data partitions

Exit codes:
  0 - All data partitions encrypted (or no issues)
  1 - Unencrypted data partitions found
  2 - Missing dependency (cryptsetup)
"""
    )

    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Show all block devices, not just relevant ones"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed encryption information"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show unencrypted data partitions"
    )

    args = parser.parse_args()

    # Check if cryptsetup is available
    if not check_cryptsetup_available():
        print("Error: cryptsetup is not installed", file=sys.stderr)
        print("Install with:", file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt-get install cryptsetup", file=sys.stderr)
        print("  RHEL/CentOS: sudo yum install cryptsetup", file=sys.stderr)
        sys.exit(2)

    # Get block devices
    devices = get_block_devices()
    if not devices:
        print("No block devices found", file=sys.stderr)
        sys.exit(1)

    # Analyze encryption status
    results, has_issues = analyze_encryption_status(devices, check_all=args.all)

    # Output results
    if args.format == "json":
        output_json(results)
    elif args.format == "table":
        output_table(results, warn_only=args.warn_only)
    else:
        output_plain(results, verbose=args.verbose, warn_only=args.warn_only)

    # Exit code based on findings
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
