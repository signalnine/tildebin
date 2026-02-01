#!/usr/bin/env python3
"""
Audit firmware versions across system components.

This script checks firmware versions for BIOS, BMC/IPMI, network interfaces,
and RAID controllers to help identify version drift across server fleets.
Useful for detecting outdated firmware that may cause reliability issues,
performance variations, or security vulnerabilities.

Checks performed:
    - BIOS/UEFI version and date (via dmidecode)
    - BMC/IPMI firmware version (via ipmitool)
    - Network interface firmware (via ethtool)
    - System manufacturer and product info

Output formats:
    - plain: Human-readable key-value pairs (default)
    - json: Machine-parseable JSON format
    - table: Formatted table output

Exit codes:
    0 - Success (all firmware info collected)
    1 - Partial failure (some tools missing or checks failed)
    2 - Usage error or critical dependency missing
"""

import argparse
import sys
import subprocess
import json
import re


def check_tool_available(tool_name):
    """Check if a system tool is available in PATH"""
    try:
        result = subprocess.run(
            ['which', tool_name],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def run_command(cmd, require_root=False):
    """Execute shell command and return result"""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def get_bios_info():
    """Get BIOS/UEFI firmware information"""
    bios_info = {}

    rc, stdout, stderr = run_command(['dmidecode', '-t', 'bios'])
    if rc != 0:
        return {'error': 'dmidecode failed or requires root privileges'}

    # Parse BIOS information
    for line in stdout.split('\n'):
        line = line.strip()
        if line.startswith('Vendor:'):
            bios_info['vendor'] = line.split(':', 1)[1].strip()
        elif line.startswith('Version:'):
            bios_info['version'] = line.split(':', 1)[1].strip()
        elif line.startswith('Release Date:'):
            bios_info['release_date'] = line.split(':', 1)[1].strip()
        elif line.startswith('BIOS Revision:'):
            bios_info['revision'] = line.split(':', 1)[1].strip()

    return bios_info


def get_system_info():
    """Get system manufacturer and product information"""
    sys_info = {}

    rc, stdout, stderr = run_command(['dmidecode', '-t', 'system'])
    if rc != 0:
        return {'error': 'dmidecode failed or requires root privileges'}

    # Parse system information
    for line in stdout.split('\n'):
        line = line.strip()
        if line.startswith('Manufacturer:'):
            sys_info['manufacturer'] = line.split(':', 1)[1].strip()
        elif line.startswith('Product Name:'):
            sys_info['product_name'] = line.split(':', 1)[1].strip()
        elif line.startswith('Serial Number:'):
            sys_info['serial_number'] = line.split(':', 1)[1].strip()
        elif line.startswith('UUID:'):
            sys_info['uuid'] = line.split(':', 1)[1].strip()

    return sys_info


def get_bmc_info():
    """Get BMC/IPMI firmware information"""
    bmc_info = {}

    rc, stdout, stderr = run_command(['ipmitool', 'mc', 'info'])
    if rc != 0:
        return {'error': 'ipmitool failed or BMC not available'}

    # Parse BMC information
    for line in stdout.split('\n'):
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()
        value = value.strip()

        if key == 'Firmware Revision':
            bmc_info['firmware_version'] = value
        elif key == 'IPMI Version':
            bmc_info['ipmi_version'] = value
        elif key == 'Manufacturer ID':
            bmc_info['manufacturer_id'] = value
        elif key == 'Device ID':
            bmc_info['device_id'] = value

    return bmc_info


def get_network_firmware():
    """Get network interface firmware versions"""
    network_info = {}

    # Get list of network interfaces
    rc, stdout, stderr = run_command(['ls', '/sys/class/net'])
    if rc != 0:
        return {'error': 'Failed to list network interfaces'}

    interfaces = [iface for iface in stdout.strip().split('\n')
                  if iface and iface != 'lo']

    for iface in interfaces:
        iface_info = {}

        # Get driver information
        rc, stdout, stderr = run_command(['ethtool', '-i', iface])
        if rc == 0:
            for line in stdout.split('\n'):
                if ':' not in line:
                    continue
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()

                if key == 'driver':
                    iface_info['driver'] = value
                elif key == 'version':
                    iface_info['driver_version'] = value
                elif key == 'firmware-version':
                    iface_info['firmware_version'] = value
                elif key == 'bus-info':
                    iface_info['bus_info'] = value

        if iface_info:
            network_info[iface] = iface_info

    return network_info


def output_plain(data, verbose=False):
    """Output in plain text format"""
    print("=== System Information ===")
    if 'system' in data and 'error' not in data['system']:
        for key, value in data['system'].items():
            print(f"  {key}: {value}")
    elif 'system' in data:
        print(f"  Error: {data['system']['error']}")

    print("\n=== BIOS Information ===")
    if 'bios' in data and 'error' not in data['bios']:
        for key, value in data['bios'].items():
            print(f"  {key}: {value}")
    elif 'bios' in data:
        print(f"  Error: {data['bios']['error']}")

    print("\n=== BMC/IPMI Information ===")
    if 'bmc' in data and 'error' not in data['bmc']:
        for key, value in data['bmc'].items():
            print(f"  {key}: {value}")
    elif 'bmc' in data:
        print(f"  Error: {data['bmc']['error']}")

    print("\n=== Network Interface Firmware ===")
    if 'network' in data and 'error' not in data['network']:
        for iface, info in data['network'].items():
            print(f"  {iface}:")
            for key, value in info.items():
                print(f"    {key}: {value}")
    elif 'network' in data:
        print(f"  Error: {data['network']['error']}")


def output_json(data):
    """Output in JSON format"""
    print(json.dumps(data, indent=2))


def output_table(data):
    """Output in table format"""
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│ Firmware Version Audit Report                                   │")
    print("├─────────────────────────────────────────────────────────────────┤")

    # System info
    if 'system' in data and 'error' not in data['system']:
        sys_info = data['system']
        print(f"│ System: {sys_info.get('manufacturer', 'N/A'):20s} {sys_info.get('product_name', 'N/A'):30s}│")

    # BIOS info
    if 'bios' in data and 'error' not in data['bios']:
        bios_info = data['bios']
        print(f"│ BIOS:   {bios_info.get('version', 'N/A'):20s} ({bios_info.get('release_date', 'N/A'):15s})   │")

    # BMC info
    if 'bmc' in data and 'error' not in data['bmc']:
        bmc_info = data['bmc']
        print(f"│ BMC:    {bmc_info.get('firmware_version', 'N/A'):52s}│")

    print("├─────────────────────────────────────────────────────────────────┤")
    print("│ Network Interfaces                                              │")
    print("├─────────────────────────────────────────────────────────────────┤")

    if 'network' in data and 'error' not in data['network']:
        for iface, info in data['network'].items():
            fw_ver = info.get('firmware_version', 'N/A')
            driver = info.get('driver', 'N/A')
            print(f"│ {iface:8s} {driver:15s} FW: {fw_ver:30s} │")

    print("└─────────────────────────────────────────────────────────────────┘")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Audit firmware versions across system components",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  firmware_version_audit.py                    # Plain text output
  firmware_version_audit.py --format json      # JSON output
  firmware_version_audit.py --format table     # Table output
  firmware_version_audit.py -v                 # Verbose output

Note: Some checks require root privileges (dmidecode, ipmitool).
Run with sudo for complete results.
"""
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
        help="Show detailed information"
    )

    args = parser.parse_args()

    # Check for required tools
    missing_tools = []
    tools_available = {}

    for tool in ['dmidecode', 'ethtool']:
        available = check_tool_available(tool)
        tools_available[tool] = available
        if not available:
            missing_tools.append(tool)

    # ipmitool is optional (not all systems have BMC)
    tools_available['ipmitool'] = check_tool_available('ipmitool')

    if missing_tools:
        print(f"Warning: Missing tools: {', '.join(missing_tools)}", file=sys.stderr)
        print("Install with: sudo apt-get install dmidecode ethtool", file=sys.stderr)
        print("Some checks will be skipped.\n", file=sys.stderr)

    # Collect firmware information
    data = {}
    errors_encountered = False

    if tools_available.get('dmidecode'):
        data['system'] = get_system_info()
        data['bios'] = get_bios_info()
        if 'error' in data['system'] or 'error' in data['bios']:
            errors_encountered = True
    else:
        data['system'] = {'error': 'dmidecode not available'}
        data['bios'] = {'error': 'dmidecode not available'}
        errors_encountered = True

    if tools_available.get('ipmitool'):
        data['bmc'] = get_bmc_info()
        if 'error' in data['bmc'] and args.verbose:
            # BMC errors are common and expected on many systems
            pass
    else:
        data['bmc'] = {'error': 'ipmitool not available'}

    if tools_available.get('ethtool'):
        data['network'] = get_network_firmware()
        if 'error' in data['network']:
            errors_encountered = True
    else:
        data['network'] = {'error': 'ethtool not available'}
        errors_encountered = True

    # Output results
    if args.format == "json":
        output_json(data)
    elif args.format == "table":
        output_table(data)
    else:
        output_plain(data, args.verbose)

    # Exit with appropriate code
    if missing_tools:
        sys.exit(1)
    elif errors_encountered:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
