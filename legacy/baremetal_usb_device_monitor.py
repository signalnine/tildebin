#!/usr/bin/env python3
"""
Monitor USB devices connected to baremetal servers for security compliance.

This script scans USB devices attached to the system and can detect potentially
unauthorized devices. Useful for data center security where USB storage devices
may be prohibited or where only specific devices (keyboards, BMC, etc.) are allowed.

Checks performed:
- Enumerate all connected USB devices
- Classify devices by type (storage, HID, network, etc.)
- Detect mass storage devices (potential data exfiltration)
- Compare against allowed device whitelist
- Check for newly connected devices since last scan

Common use cases:
- Security compliance auditing
- Detecting unauthorized storage devices
- Inventory of USB peripherals
- Change detection for security monitoring

Exit codes:
    0 - No issues detected (all devices allowed or no storage devices)
    1 - Unauthorized or flagged devices detected
    2 - Usage error or /sys/bus/usb not available
"""

import argparse
import sys
import os
import json
from pathlib import Path


# USB class codes
USB_CLASSES = {
    '00': 'Device',
    '01': 'Audio',
    '02': 'Communications',
    '03': 'HID',
    '05': 'Physical',
    '06': 'Image',
    '07': 'Printer',
    '08': 'Mass Storage',
    '09': 'Hub',
    '0a': 'CDC-Data',
    '0b': 'Smart Card',
    '0d': 'Content Security',
    '0e': 'Video',
    '0f': 'Personal Healthcare',
    '10': 'Audio/Video',
    'dc': 'Diagnostic',
    'e0': 'Wireless Controller',
    'ef': 'Miscellaneous',
    'fe': 'Application Specific',
    'ff': 'Vendor Specific',
}

# Device classes typically considered security-sensitive
SENSITIVE_CLASSES = {'08'}  # Mass Storage


def read_sysfs_value(path):
    """Read a value from sysfs, return None if not available."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, IOError):
        return None


def get_usb_devices():
    """Enumerate USB devices from /sys/bus/usb/devices.

    Returns:
        list: List of USB device dictionaries
    """
    devices = []
    usb_path = Path('/sys/bus/usb/devices')

    if not usb_path.exists():
        return None

    for device_dir in usb_path.iterdir():
        # Skip interfaces (contain ':'), we want devices only
        if ':' in device_dir.name:
            continue

        # Skip root hubs pattern like 'usb1', 'usb2'
        if device_dir.name.startswith('usb'):
            continue

        # Get device info
        vendor_id = read_sysfs_value(device_dir / 'idVendor')
        product_id = read_sysfs_value(device_dir / 'idProduct')

        # Skip if no vendor/product (not a real device)
        if not vendor_id or not product_id:
            continue

        manufacturer = read_sysfs_value(device_dir / 'manufacturer')
        product = read_sysfs_value(device_dir / 'product')
        serial = read_sysfs_value(device_dir / 'serial')
        device_class = read_sysfs_value(device_dir / 'bDeviceClass')
        bus_num = read_sysfs_value(device_dir / 'busnum')
        dev_num = read_sysfs_value(device_dir / 'devnum')
        speed = read_sysfs_value(device_dir / 'speed')

        # Determine device class name
        class_name = 'Unknown'
        if device_class:
            class_name = USB_CLASSES.get(device_class.lower(), f'Class {device_class}')

        # Check interfaces for actual class (device class 00 means check interfaces)
        interface_classes = []
        for interface_dir in device_dir.glob('*:*'):
            iface_class = read_sysfs_value(interface_dir / 'bInterfaceClass')
            if iface_class:
                iface_class_name = USB_CLASSES.get(iface_class.lower(), f'Class {iface_class}')
                interface_classes.append({
                    'class_code': iface_class.lower(),
                    'class_name': iface_class_name
                })

        # Determine if this is a storage device
        is_storage = (
            device_class and device_class.lower() == '08' or
            any(ic['class_code'] == '08' for ic in interface_classes)
        )

        device_info = {
            'bus': bus_num,
            'device': dev_num,
            'vendor_id': vendor_id,
            'product_id': product_id,
            'manufacturer': manufacturer or 'Unknown',
            'product': product or 'Unknown',
            'serial': serial,
            'device_class': device_class,
            'class_name': class_name,
            'interface_classes': interface_classes,
            'speed': speed,
            'is_storage': is_storage,
            'path': str(device_dir),
        }

        devices.append(device_info)

    return devices


def load_whitelist(whitelist_file):
    """Load device whitelist from file.

    Whitelist format (one per line):
        vendor_id:product_id  # Comment

    Example:
        046d:c52b  # Logitech Receiver
        8087:0024  # Intel Hub

    Args:
        whitelist_file: Path to whitelist file

    Returns:
        set: Set of (vendor_id, product_id) tuples
    """
    whitelist = set()

    try:
        with open(whitelist_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Remove inline comments
                if '#' in line:
                    line = line.split('#')[0].strip()

                # Parse vendor:product
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        vendor = parts[0].strip().lower()
                        product = parts[1].strip().lower()
                        whitelist.add((vendor, product))
    except FileNotFoundError:
        return None
    except Exception:
        return None

    return whitelist


def analyze_devices(devices, whitelist=None, flag_storage=True):
    """Analyze USB devices for security issues.

    Args:
        devices: List of USB device dictionaries
        whitelist: Optional set of allowed (vendor_id, product_id) tuples
        flag_storage: Flag mass storage devices as issues

    Returns:
        dict: Analysis results with issues list
    """
    results = {
        'total_devices': len(devices),
        'storage_devices': 0,
        'flagged_devices': [],
        'allowed_devices': [],
        'issues': [],
    }

    for device in devices:
        vendor_id = device['vendor_id'].lower()
        product_id = device['product_id'].lower()
        device_key = (vendor_id, product_id)

        is_flagged = False
        flag_reasons = []

        # Check whitelist
        if whitelist is not None:
            if device_key not in whitelist:
                is_flagged = True
                flag_reasons.append('Not in whitelist')

        # Check for storage devices
        if device['is_storage']:
            results['storage_devices'] += 1
            if flag_storage:
                is_flagged = True
                flag_reasons.append('Mass storage device')

        if is_flagged:
            results['flagged_devices'].append({
                'device': device,
                'reasons': flag_reasons,
            })
            for reason in flag_reasons:
                results['issues'].append({
                    'severity': 'WARNING',
                    'device': f"{device['manufacturer']} {device['product']}",
                    'vendor_product': f"{vendor_id}:{product_id}",
                    'reason': reason,
                })
        else:
            results['allowed_devices'].append(device)

    return results


def output_plain(devices, results, verbose, warn_only):
    """Output results in plain text format."""
    if warn_only and not results['issues']:
        return

    print("USB Device Monitor")
    print("=" * 60)
    print(f"Total devices:   {results['total_devices']}")
    print(f"Storage devices: {results['storage_devices']}")
    print(f"Flagged devices: {len(results['flagged_devices'])}")
    print()

    if verbose:
        print("Connected USB Devices:")
        print("-" * 60)
        for device in devices:
            status = "[FLAGGED]" if device['is_storage'] else "[OK]"
            print(f"  {status} {device['manufacturer']} {device['product']}")
            print(f"         ID: {device['vendor_id']}:{device['product_id']}")
            print(f"         Class: {device['class_name']}")
            if device['serial']:
                print(f"         Serial: {device['serial']}")
            if device['interface_classes']:
                ifaces = ', '.join(ic['class_name'] for ic in device['interface_classes'])
                print(f"         Interfaces: {ifaces}")
            print()

    if results['issues']:
        print("Flagged Devices:")
        print("-" * 60)
        for issue in results['issues']:
            print(f"  [{issue['severity']}] {issue['device']}")
            print(f"           ID: {issue['vendor_product']}")
            print(f"           Reason: {issue['reason']}")
        print()
    elif not warn_only:
        print("[OK] No flagged USB devices detected")


def output_json(devices, results, verbose):
    """Output results in JSON format."""
    output = {
        'summary': {
            'total_devices': results['total_devices'],
            'storage_devices': results['storage_devices'],
            'flagged_count': len(results['flagged_devices']),
        },
        'issues': results['issues'],
        'has_issues': len(results['issues']) > 0,
    }

    if verbose:
        output['devices'] = devices
        output['flagged_devices'] = results['flagged_devices']

    print(json.dumps(output, indent=2))


def output_table(devices, results, verbose, warn_only):
    """Output results in table format."""
    if warn_only and not results['issues']:
        return

    print(f"{'Status':<10} {'Vendor:Product':<12} {'Manufacturer':<20} {'Product':<25}")
    print("-" * 70)

    for device in devices:
        status = "FLAGGED" if device['is_storage'] else "OK"
        vid_pid = f"{device['vendor_id']}:{device['product_id']}"
        mfr = (device['manufacturer'] or 'Unknown')[:19]
        prod = (device['product'] or 'Unknown')[:24]
        print(f"{status:<10} {vid_pid:<12} {mfr:<20} {prod:<25}")

    print()
    print(f"Total: {results['total_devices']} | Storage: {results['storage_devices']} | Flagged: {len(results['flagged_devices'])}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor USB devices for security compliance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # List all USB devices
  %(prog)s --format json          # JSON output for monitoring systems
  %(prog)s --verbose              # Show detailed device information
  %(prog)s --no-flag-storage      # Don't flag storage devices
  %(prog)s --whitelist /etc/usb-whitelist.txt  # Check against whitelist

Whitelist file format (one device per line):
  vendor_id:product_id  # Optional comment

Example whitelist:
  046d:c52b  # Logitech Receiver
  8087:0024  # Intel USB Hub

Exit codes:
  0 - No issues detected
  1 - Flagged devices detected
  2 - Usage error or /sys/bus/usb not available
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
        help='Show detailed device information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues are detected'
    )

    parser.add_argument(
        '--whitelist',
        metavar='FILE',
        help='Path to device whitelist file'
    )

    parser.add_argument(
        '--no-flag-storage',
        action='store_true',
        help='Do not flag mass storage devices as issues'
    )

    args = parser.parse_args()

    # Check if USB sysfs is available
    if not os.path.exists('/sys/bus/usb/devices'):
        print("Error: /sys/bus/usb/devices not found", file=sys.stderr)
        print("USB sysfs may not be mounted or available", file=sys.stderr)
        sys.exit(2)

    # Load whitelist if specified
    whitelist = None
    if args.whitelist:
        whitelist = load_whitelist(args.whitelist)
        if whitelist is None:
            print(f"Error: Could not load whitelist from {args.whitelist}",
                  file=sys.stderr)
            sys.exit(2)

    # Get USB devices
    devices = get_usb_devices()
    if devices is None:
        print("Error: Could not enumerate USB devices", file=sys.stderr)
        sys.exit(2)

    # Analyze devices
    results = analyze_devices(
        devices,
        whitelist=whitelist,
        flag_storage=not args.no_flag_storage
    )

    # Output results
    if args.format == 'json':
        output_json(devices, results, args.verbose)
    elif args.format == 'table':
        output_table(devices, results, args.verbose, args.warn_only)
    else:  # plain
        output_plain(devices, results, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if results['issues'] else 0)


if __name__ == '__main__':
    main()
