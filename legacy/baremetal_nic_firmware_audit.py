#!/usr/bin/env python3
"""
Audit NIC driver and firmware versions across network interfaces.

Identifies inconsistencies in NIC firmware/driver versions that can cause
subtle packet loss, latency issues, or performance degradation in large-scale
baremetal environments.

Exit codes:
    0 - All NICs consistent (or no physical NICs found)
    1 - Inconsistencies or issues detected
    2 - Usage error or missing dependency (ethtool required)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict


def run_command(cmd):
    """Execute a command and return output."""
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


def check_ethtool_available():
    """Check if ethtool is available."""
    returncode, _, _ = run_command(['which', 'ethtool'])
    return returncode == 0


def get_physical_interfaces():
    """Get list of physical network interfaces (excluding virtual/loopback)."""
    interfaces = []

    try:
        net_path = '/sys/class/net'
        for iface in os.listdir(net_path):
            # Skip loopback
            if iface == 'lo':
                continue

            # Check if it's a physical device (has a device symlink)
            device_path = os.path.join(net_path, iface, 'device')
            if os.path.exists(device_path):
                # Skip virtual interfaces (bridges, bonds, vlans, etc.)
                iface_type_path = os.path.join(net_path, iface, 'type')
                try:
                    with open(iface_type_path, 'r') as f:
                        iface_type = int(f.read().strip())
                        # Type 1 = Ethernet
                        if iface_type == 1:
                            interfaces.append(iface)
                except (IOError, ValueError):
                    # If we can't read type, include it anyway
                    interfaces.append(iface)
    except OSError:
        pass

    return sorted(interfaces)


def get_driver_info(iface):
    """Get driver information for an interface using ethtool."""
    info = {
        'driver': 'unknown',
        'driver_version': 'unknown',
        'firmware_version': 'unknown',
        'bus_info': 'unknown'
    }

    returncode, stdout, stderr = run_command(['ethtool', '-i', iface])
    if returncode != 0:
        return info

    for line in stdout.split('\n'):
        if ':' in line:
            key, _, value = line.partition(':')
            key = key.strip().lower().replace('-', '_')
            value = value.strip()

            if key == 'driver':
                info['driver'] = value
            elif key == 'version':
                info['driver_version'] = value
            elif key == 'firmware_version':
                info['firmware_version'] = value
            elif key == 'bus_info':
                info['bus_info'] = value

    return info


def get_link_info(iface):
    """Get link speed and duplex information."""
    info = {
        'speed': 'unknown',
        'duplex': 'unknown',
        'link_detected': False
    }

    returncode, stdout, stderr = run_command(['ethtool', iface])
    if returncode != 0:
        return info

    for line in stdout.split('\n'):
        line = line.strip()
        if line.startswith('Speed:'):
            info['speed'] = line.split(':', 1)[1].strip()
        elif line.startswith('Duplex:'):
            info['duplex'] = line.split(':', 1)[1].strip()
        elif line.startswith('Link detected:'):
            info['link_detected'] = 'yes' in line.lower()

    return info


def get_pci_info(bus_info):
    """Get PCI device information using lspci."""
    if not bus_info or bus_info == 'unknown':
        return {'vendor': 'unknown', 'device': 'unknown'}

    # Extract PCI address (e.g., "0000:03:00.0" from "0000:03:00.0")
    pci_addr = bus_info.replace('PCI:', '').strip()

    returncode, stdout, stderr = run_command(['lspci', '-s', pci_addr])
    if returncode != 0 or not stdout.strip():
        return {'vendor': 'unknown', 'device': 'unknown'}

    # Parse output like "03:00.0 Ethernet controller: Intel Corporation I350 Gigabit Network Connection"
    parts = stdout.strip().split(':', 2)
    if len(parts) >= 3:
        device_info = parts[2].strip()
        # Try to extract vendor
        if 'Intel' in device_info:
            return {'vendor': 'Intel', 'device': device_info}
        elif 'Broadcom' in device_info:
            return {'vendor': 'Broadcom', 'device': device_info}
        elif 'Mellanox' in device_info or 'NVIDIA' in device_info:
            return {'vendor': 'Mellanox/NVIDIA', 'device': device_info}
        elif 'Realtek' in device_info:
            return {'vendor': 'Realtek', 'device': device_info}
        else:
            return {'vendor': 'Other', 'device': device_info}

    return {'vendor': 'unknown', 'device': 'unknown'}


def audit_interfaces(interfaces, expected_versions=None):
    """Audit all interfaces and check for inconsistencies."""
    results = []
    driver_versions = defaultdict(list)
    firmware_versions = defaultdict(list)

    for iface in interfaces:
        driver_info = get_driver_info(iface)
        link_info = get_link_info(iface)
        pci_info = get_pci_info(driver_info['bus_info'])

        result = {
            'interface': iface,
            'driver': driver_info['driver'],
            'driver_version': driver_info['driver_version'],
            'firmware_version': driver_info['firmware_version'],
            'bus_info': driver_info['bus_info'],
            'vendor': pci_info['vendor'],
            'device': pci_info['device'],
            'speed': link_info['speed'],
            'duplex': link_info['duplex'],
            'link_detected': link_info['link_detected'],
            'issues': []
        }

        # Track versions by driver for consistency checking
        driver = driver_info['driver']
        if driver != 'unknown':
            driver_versions[driver].append({
                'interface': iface,
                'version': driver_info['driver_version']
            })
            firmware_versions[driver].append({
                'interface': iface,
                'version': driver_info['firmware_version']
            })

        # Check against expected versions if provided
        if expected_versions:
            if driver in expected_versions:
                expected = expected_versions[driver]
                if 'driver_version' in expected:
                    if driver_info['driver_version'] != expected['driver_version']:
                        result['issues'].append(
                            f"Driver version mismatch: expected {expected['driver_version']}, "
                            f"got {driver_info['driver_version']}"
                        )
                if 'firmware_version' in expected:
                    if driver_info['firmware_version'] != expected['firmware_version']:
                        result['issues'].append(
                            f"Firmware version mismatch: expected {expected['firmware_version']}, "
                            f"got {driver_info['firmware_version']}"
                        )

        results.append(result)

    # Check for inconsistencies across same-driver interfaces
    inconsistencies = []

    for driver, versions in driver_versions.items():
        unique_versions = set(v['version'] for v in versions)
        if len(unique_versions) > 1:
            inconsistencies.append({
                'type': 'driver_version',
                'driver': driver,
                'versions': list(unique_versions),
                'interfaces': [v['interface'] for v in versions]
            })
            # Mark affected interfaces
            for result in results:
                if result['driver'] == driver:
                    result['issues'].append(
                        f"Inconsistent driver version across {driver} interfaces"
                    )

    for driver, versions in firmware_versions.items():
        unique_versions = set(v['version'] for v in versions if v['version'] != 'unknown')
        if len(unique_versions) > 1:
            inconsistencies.append({
                'type': 'firmware_version',
                'driver': driver,
                'versions': list(unique_versions),
                'interfaces': [v['interface'] for v in versions]
            })
            # Mark affected interfaces
            for result in results:
                if result['driver'] == driver:
                    if not any('Inconsistent firmware' in i for i in result['issues']):
                        result['issues'].append(
                            f"Inconsistent firmware version across {driver} interfaces"
                        )

    return results, inconsistencies


def output_plain(results, inconsistencies, verbose=False, warn_only=False):
    """Output results in plain text format."""
    if warn_only:
        results = [r for r in results if r['issues']]

    if not results:
        print("No physical network interfaces found (or no issues in --warn-only mode)")
        return

    print("NIC Firmware/Driver Audit")
    print("=" * 80)
    print()

    for result in results:
        status = "OK" if not result['issues'] else "ISSUE"
        symbol = "+" if not result['issues'] else "!"

        print(f"[{symbol}] {result['interface']} ({status})")
        print(f"    Driver: {result['driver']} v{result['driver_version']}")
        print(f"    Firmware: {result['firmware_version']}")
        print(f"    Vendor: {result['vendor']}")
        print(f"    Link: {result['speed']} {result['duplex']} "
              f"({'up' if result['link_detected'] else 'down'})")

        if verbose:
            print(f"    Bus: {result['bus_info']}")
            print(f"    Device: {result['device']}")

        if result['issues']:
            for issue in result['issues']:
                print(f"    WARNING: {issue}")

        print()

    if inconsistencies:
        print("Inconsistencies Detected:")
        print("-" * 40)
        for inc in inconsistencies:
            print(f"  {inc['type'].replace('_', ' ').title()}: {inc['driver']}")
            print(f"    Versions found: {', '.join(inc['versions'])}")
            print(f"    Affected: {', '.join(inc['interfaces'])}")
            print()


def output_json(results, inconsistencies):
    """Output results in JSON format."""
    output = {
        'interfaces': results,
        'inconsistencies': inconsistencies,
        'summary': {
            'total_interfaces': len(results),
            'interfaces_with_issues': sum(1 for r in results if r['issues']),
            'inconsistency_count': len(inconsistencies)
        }
    }
    print(json.dumps(output, indent=2))


def output_table(results, inconsistencies, warn_only=False):
    """Output results in table format."""
    if warn_only:
        results = [r for r in results if r['issues']]

    if not results:
        print("No interfaces to display")
        return

    # Header
    print(f"{'Interface':<12} {'Driver':<12} {'Driver Ver':<15} {'Firmware Ver':<20} {'Speed':<12} {'Status':<8}")
    print("-" * 85)

    for result in results:
        status = "OK" if not result['issues'] else "ISSUE"
        print(f"{result['interface']:<12} "
              f"{result['driver']:<12} "
              f"{result['driver_version']:<15} "
              f"{result['firmware_version']:<20} "
              f"{result['speed']:<12} "
              f"{status:<8}")

    if inconsistencies:
        print()
        print("Inconsistencies:")
        for inc in inconsistencies:
            print(f"  - {inc['driver']}: {inc['type'].replace('_', ' ')} varies "
                  f"({', '.join(inc['versions'])})")


def load_expected_versions(filepath):
    """Load expected versions from a JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading expected versions file: {e}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        description="Audit NIC driver and firmware versions for consistency",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Audit all physical NICs
  %(prog)s --format json      # JSON output for monitoring
  %(prog)s -v                 # Verbose output with PCI details
  %(prog)s --warn-only        # Only show interfaces with issues
  %(prog)s --expected versions.json  # Compare against expected versions

Expected versions file format (JSON):
  {
    "ixgbe": {"driver_version": "5.15.0", "firmware_version": "0x800014e1"},
    "mlx5_core": {"driver_version": "5.8-1.0.0", "firmware_version": "16.35.2000"}
  }
        """
    )

    parser.add_argument(
        "-i", "--interface",
        help="Specific interface to audit (default: all physical NICs)"
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
        help="Show detailed information including PCI bus and device details"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show interfaces with issues or inconsistencies"
    )
    parser.add_argument(
        "--expected",
        metavar="FILE",
        help="JSON file with expected driver/firmware versions"
    )

    args = parser.parse_args()

    # Check for ethtool
    if not check_ethtool_available():
        print("Error: ethtool is required but not found", file=sys.stderr)
        print("Install with: sudo apt-get install ethtool", file=sys.stderr)
        sys.exit(2)

    # Get interfaces to audit
    if args.interface:
        interfaces = [args.interface]
    else:
        interfaces = get_physical_interfaces()

    if not interfaces:
        if args.format == "json":
            print(json.dumps({"interfaces": [], "inconsistencies": [],
                            "summary": {"total_interfaces": 0}}))
        else:
            print("No physical network interfaces found")
        sys.exit(0)

    # Load expected versions if provided
    expected_versions = None
    if args.expected:
        expected_versions = load_expected_versions(args.expected)

    # Audit interfaces
    results, inconsistencies = audit_interfaces(interfaces, expected_versions)

    # Output results
    if args.format == "json":
        output_json(results, inconsistencies)
    elif args.format == "table":
        output_table(results, inconsistencies, args.warn_only)
    else:
        output_plain(results, inconsistencies, args.verbose, args.warn_only)

    # Exit code based on findings
    has_issues = any(r['issues'] for r in results) or inconsistencies
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
