#!/usr/bin/env python3
"""
Monitor pending firmware updates using fwupd.

Checks for available firmware updates on baremetal systems using the fwupd
(firmware update daemon) service. This helps maintain security and stability
by ensuring firmware is kept up to date across the fleet.

Detects:
- Devices with available firmware updates
- Security-critical firmware updates
- UEFI capsule update readiness
- Firmware update service health
- Devices with known firmware issues

Critical for:
- Security compliance (CVEs fixed in firmware)
- Hardware stability (bug fixes)
- Feature enablement (new capabilities)
- Fleet management (tracking firmware versions)

Exit codes:
    0 - No pending updates or all devices up to date
    1 - Pending firmware updates found
    2 - Usage error or fwupdmgr not available
"""

import argparse
import json
import subprocess
import sys
from typing import Any, Dict, List, Optional


def run_fwupdmgr(args: List[str], check: bool = True) -> tuple:
    """Execute fwupdmgr command and return output."""
    try:
        result = subprocess.run(
            ['fwupdmgr'] + args,
            capture_output=True,
            text=True,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        print("Error: fwupdmgr not found in PATH", file=sys.stderr)
        print("Install fwupd: sudo apt-get install fwupd", file=sys.stderr)
        sys.exit(2)


def check_fwupd_service() -> Dict[str, Any]:
    """Check if fwupd service is running and healthy."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'fwupd'],
            capture_output=True,
            text=True
        )
        service_active = result.returncode == 0

        # Get service status details
        result = subprocess.run(
            ['systemctl', 'show', 'fwupd', '--property=ActiveState,SubState'],
            capture_output=True,
            text=True
        )
        state_info = {}
        for line in result.stdout.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                state_info[key] = value

        return {
            'active': service_active,
            'state': state_info.get('ActiveState', 'unknown'),
            'substate': state_info.get('SubState', 'unknown'),
        }
    except FileNotFoundError:
        return {
            'active': False,
            'state': 'not-found',
            'substate': 'systemd not available',
        }


def get_devices() -> List[Dict[str, Any]]:
    """Get list of devices that can be updated."""
    returncode, stdout, stderr = run_fwupdmgr(['get-devices', '--json'], check=False)

    if returncode != 0:
        # Try without JSON (older versions)
        returncode, stdout, stderr = run_fwupdmgr(['get-devices'], check=False)
        if returncode != 0:
            return []
        # Parse plain text output (simplified)
        return parse_plain_devices(stdout)

    try:
        data = json.loads(stdout)
        return data.get('Devices', [])
    except json.JSONDecodeError:
        return []


def parse_plain_devices(output: str) -> List[Dict[str, Any]]:
    """Parse plain text device output from older fwupdmgr versions."""
    devices = []
    current_device = {}

    for line in output.split('\n'):
        line = line.strip()
        if not line:
            if current_device:
                devices.append(current_device)
                current_device = {}
            continue

        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            if key == 'Device':
                if current_device:
                    devices.append(current_device)
                current_device = {'Name': value}
            elif key == 'DeviceId':
                current_device['DeviceId'] = value
            elif key == 'Guid':
                current_device['Guid'] = value
            elif key == 'Version':
                current_device['Version'] = value
            elif key == 'Vendor':
                current_device['Vendor'] = value
            elif key == 'UpdateState':
                current_device['UpdateState'] = value

    if current_device:
        devices.append(current_device)

    return devices


def get_updates() -> List[Dict[str, Any]]:
    """Get list of available updates."""
    returncode, stdout, stderr = run_fwupdmgr(['get-updates', '--json'], check=False)

    if returncode != 0:
        # No updates available or error
        if 'No updates available' in stderr or 'No updates available' in stdout:
            return []
        # Try without JSON
        returncode, stdout, stderr = run_fwupdmgr(['get-updates'], check=False)
        if returncode != 0:
            return []
        return parse_plain_updates(stdout)

    try:
        data = json.loads(stdout)
        return data.get('Devices', [])
    except json.JSONDecodeError:
        return []


def parse_plain_updates(output: str) -> List[Dict[str, Any]]:
    """Parse plain text update output from older fwupdmgr versions."""
    updates = []
    current_update = {}

    for line in output.split('\n'):
        line = line.strip()
        if not line:
            if current_update:
                updates.append(current_update)
                current_update = {}
            continue

        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            if key in ['Device', 'Name']:
                if current_update:
                    updates.append(current_update)
                current_update = {'Name': value}
            elif key == 'Version':
                current_update['Version'] = value
            elif key == 'Remote':
                current_update['Remote'] = value
            elif key == 'Summary':
                current_update['Summary'] = value
            elif key == 'Urgency':
                current_update['Urgency'] = value
            elif key == 'Security':
                current_update['IsSecurityRisk'] = value.lower() == 'true'

    if current_update:
        updates.append(current_update)

    return updates


def get_history() -> List[Dict[str, Any]]:
    """Get firmware update history."""
    returncode, stdout, stderr = run_fwupdmgr(['get-history', '--json'], check=False)

    if returncode != 0:
        return []

    try:
        data = json.loads(stdout)
        return data.get('Devices', [])
    except json.JSONDecodeError:
        return []


def analyze_device(device: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a device for update status."""
    name = device.get('Name', device.get('DeviceId', 'Unknown'))
    vendor = device.get('Vendor', 'Unknown')
    version = device.get('Version', 'Unknown')
    device_id = device.get('DeviceId', '')

    # Check for flags
    flags = device.get('Flags', [])
    can_update = 'updatable' in flags or 'updatable-hidden' in flags
    needs_reboot = 'needs-reboot' in flags
    is_internal = 'internal' in flags

    # Check for releases (available updates)
    releases = device.get('Releases', [])
    has_update = len(releases) > 0

    # Get update details if available
    update_info = None
    if releases:
        latest = releases[0]
        update_info = {
            'version': latest.get('Version', 'Unknown'),
            'urgency': latest.get('Urgency', 'unknown'),
            'summary': latest.get('Summary', ''),
            'is_security': latest.get('IsSecurityRisk', False),
        }

    return {
        'name': name,
        'vendor': vendor,
        'current_version': version,
        'device_id': device_id,
        'can_update': can_update,
        'needs_reboot': needs_reboot,
        'is_internal': is_internal,
        'has_update': has_update,
        'update_info': update_info,
    }


def refresh_metadata(force: bool = False) -> bool:
    """Refresh firmware metadata from remotes."""
    args = ['refresh']
    if force:
        args.append('--force')

    returncode, stdout, stderr = run_fwupdmgr(args, check=False)
    return returncode == 0


def output_plain(service_status: Dict, devices: List[Dict], updates: List[Dict], verbose: bool):
    """Plain text output."""
    # Service status
    if verbose:
        print("=== fwupd Service Status ===")
        status_icon = "active" if service_status['active'] else "inactive"
        print(f"Service: {status_icon} ({service_status['state']}/{service_status['substate']})")
        print()

    # Devices summary
    if verbose:
        print("=== Firmware Devices ===")
        for device in devices:
            status = "can update" if device['can_update'] else "not updatable"
            print(f"  {device['name']} ({device['vendor']})")
            print(f"    Version: {device['current_version']}")
            print(f"    Status: {status}")
            if device['has_update'] and device['update_info']:
                info = device['update_info']
                print(f"    Update available: {info['version']}")
                if info['is_security']:
                    print(f"    [SECURITY UPDATE]")
            print()

    # Updates summary
    devices_with_updates = [d for d in devices if d['has_update']]

    if devices_with_updates:
        print("=== Pending Firmware Updates ===")
        for device in devices_with_updates:
            info = device['update_info']
            security_tag = " [SECURITY]" if info and info.get('is_security') else ""
            urgency = info.get('urgency', 'unknown') if info else 'unknown'

            print(f"  {device['name']}")
            print(f"    Current: {device['current_version']}")
            print(f"    Available: {info['version'] if info else 'unknown'}{security_tag}")
            print(f"    Urgency: {urgency}")
            if info and info.get('summary'):
                print(f"    Summary: {info['summary']}")
            print()
    else:
        print("No pending firmware updates")
        print()

    # Summary
    total_devices = len(devices)
    updatable_devices = sum(1 for d in devices if d['can_update'])
    pending_updates = len(devices_with_updates)
    security_updates = sum(
        1 for d in devices_with_updates
        if d['update_info'] and d['update_info'].get('is_security')
    )

    print("=== Summary ===")
    print(f"Total devices: {total_devices}")
    print(f"Updatable devices: {updatable_devices}")
    print(f"Pending updates: {pending_updates}")
    if security_updates:
        print(f"Security updates: {security_updates}")


def output_json(service_status: Dict, devices: List[Dict], updates: List[Dict]):
    """JSON output."""
    devices_with_updates = [d for d in devices if d['has_update']]
    security_updates = sum(
        1 for d in devices_with_updates
        if d['update_info'] and d['update_info'].get('is_security')
    )

    output = {
        'service': service_status,
        'devices': devices,
        'summary': {
            'total_devices': len(devices),
            'updatable_devices': sum(1 for d in devices if d['can_update']),
            'pending_updates': len(devices_with_updates),
            'security_updates': security_updates,
        }
    }
    print(json.dumps(output, indent=2))


def output_table(service_status: Dict, devices: List[Dict], updates: List[Dict]):
    """Tabular output."""
    print(f"{'Device':<35} {'Vendor':<20} {'Current':<15} {'Available':<15} {'Urgency':<10}")
    print("-" * 100)

    for device in devices:
        if not device['can_update']:
            continue

        name = device['name'][:34]
        vendor = device['vendor'][:19]
        current = device['current_version'][:14]

        if device['has_update'] and device['update_info']:
            info = device['update_info']
            available = info['version'][:14]
            urgency = info.get('urgency', 'unknown')[:9]
            if info.get('is_security'):
                urgency = f"*{urgency}"
        else:
            available = "-"
            urgency = "-"

        print(f"{name:<35} {vendor:<20} {current:<15} {available:<15} {urgency:<10}")

    print()
    print("* = Security update")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor pending firmware updates using fwupd',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check for pending updates
  %(prog)s --refresh                # Refresh metadata before checking
  %(prog)s --format json            # JSON output for automation
  %(prog)s --verbose                # Show all device details
  %(prog)s --security-only          # Only show security updates

Exit codes:
  0 - No pending updates
  1 - Pending firmware updates found
  2 - Usage error or fwupdmgr unavailable
        """
    )

    parser.add_argument(
        '--format', '-f',
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
        '--refresh',
        action='store_true',
        help='Refresh firmware metadata before checking'
    )

    parser.add_argument(
        '--force-refresh',
        action='store_true',
        help='Force refresh even if recently updated'
    )

    parser.add_argument(
        '--security-only',
        action='store_true',
        help='Only show/count security-related updates'
    )

    args = parser.parse_args()

    # Check service status
    service_status = check_fwupd_service()

    # Optionally refresh metadata
    if args.refresh or args.force_refresh:
        if args.format == 'plain':
            print("Refreshing firmware metadata...")
        refresh_metadata(force=args.force_refresh)

    # Get device and update information
    raw_devices = get_devices()
    devices = [analyze_device(d) for d in raw_devices]

    # Filter for security-only if requested
    if args.security_only:
        devices = [
            d for d in devices
            if d['has_update'] and d['update_info'] and d['update_info'].get('is_security')
        ]

    # Get update history (for verbose output)
    updates = get_updates()

    # Output results
    if args.format == 'json':
        output_json(service_status, devices, updates)
    elif args.format == 'table':
        output_table(service_status, devices, updates)
    else:
        output_plain(service_status, devices, updates, args.verbose)

    # Determine exit code
    has_updates = any(d['has_update'] for d in devices)
    sys.exit(1 if has_updates else 0)


if __name__ == '__main__':
    main()
