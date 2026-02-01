#!/usr/bin/env python3
"""
Monitor PCIe device health and link status on baremetal systems.

Checks PCIe link speed, width, and error counters to detect degraded or
failing PCIe devices. Useful for identifying hardware issues with GPUs,
NVMe drives, network cards, and other PCIe devices before they cause
system failures or performance degradation.

Exit codes:
  0 - Success (all PCIe devices healthy)
  1 - Warning/Critical conditions detected
  2 - Usage error or missing dependencies
"""

import argparse
import json
import re
import subprocess
import sys


def check_lspci_available():
    """Check if lspci command is available."""
    try:
        subprocess.run(
            ['lspci', '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def parse_pcie_speed(speed_str):
    """
    Parse PCIe speed string to numeric value for comparison.

    Examples: '2.5GT/s' -> 2.5, '8GT/s' -> 8.0, '16GT/s' -> 16.0
    """
    match = re.search(r'([\d.]+)GT/s', speed_str)
    if match:
        return float(match.group(1))
    return 0.0


def parse_pcie_width(width_str):
    """
    Parse PCIe width string to numeric value for comparison.

    Examples: 'x1' -> 1, 'x16' -> 16
    """
    match = re.search(r'x(\d+)', width_str)
    if match:
        return int(match.group(1))
    return 0


def get_pcie_devices():
    """Get list of all PCIe devices."""
    try:
        result = subprocess.run(
            ['lspci', '-D'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )

        devices = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                # Parse format: "0000:00:00.0 Host bridge: Intel Corporation ..."
                parts = line.split(' ', 1)
                if len(parts) >= 2:
                    pci_addr = parts[0]
                    description = parts[1]
                    devices.append({
                        'address': pci_addr,
                        'description': description
                    })

        return devices
    except subprocess.CalledProcessError as e:
        print(f"Error running lspci: {e}", file=sys.stderr)
        return []


def get_device_details(pci_addr):
    """Get detailed PCIe information for a specific device."""
    try:
        result = subprocess.run(
            ['lspci', '-vvv', '-s', pci_addr],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )

        details = {
            'address': pci_addr,
            'lnk_cap_speed': None,
            'lnk_cap_width': None,
            'lnk_sta_speed': None,
            'lnk_sta_width': None,
            'correctable_errors': 0,
            'uncorrectable_errors': 0,
            'fatal_errors': 0
        }

        output = result.stdout

        # Parse LnkCap (Link Capabilities)
        lnk_cap = re.search(r'LnkCap:.*?Speed ([\d.]+GT/s).*?Width (x\d+)', output)
        if lnk_cap:
            details['lnk_cap_speed'] = lnk_cap.group(1)
            details['lnk_cap_width'] = lnk_cap.group(2)

        # Parse LnkSta (Link Status)
        lnk_sta = re.search(r'LnkSta:.*?Speed ([\d.]+GT/s).*?Width (x\d+)', output)
        if lnk_sta:
            details['lnk_sta_speed'] = lnk_sta.group(1)
            details['lnk_sta_width'] = lnk_sta.group(2)

        # Parse PCIe error counters (if AER is enabled)
        # UncorrErr: errors like Malformed TLP, ECRC errors
        uncorr = re.search(r'UncorrErr:.*', output)
        if uncorr:
            # Count non-minus indicators (minus means no error)
            uncorr_line = uncorr.group(0)
            # Look for specific error flags that aren't followed by '-'
            error_indicators = re.findall(r'(\w+)\+', uncorr_line)
            details['uncorrectable_errors'] = len(error_indicators)

        # CorrErr: correctable errors like Bad TLP, Bad DLLP
        corr = re.search(r'CorrErr:.*', output)
        if corr:
            corr_line = corr.group(0)
            error_indicators = re.findall(r'(\w+)\+', corr_line)
            details['correctable_errors'] = len(error_indicators)

        # Check for fatal errors
        fatal = re.search(r'FatalErr\+', output)
        if fatal:
            details['fatal_errors'] = 1

        return details

    except subprocess.CalledProcessError as e:
        print(f"Error getting details for {pci_addr}: {e}", file=sys.stderr)
        return None


def check_device_health(device_info, details):
    """
    Check if a PCIe device is healthy based on link status and errors.

    Returns dict with status and issues list.
    """
    status = {
        'status': 'OK',
        'issues': []
    }

    if not details:
        status['status'] = 'UNKNOWN'
        status['issues'].append('Unable to read device details')
        return status

    # Skip devices without PCIe link information (like host bridges)
    if not details['lnk_cap_speed'] or not details['lnk_sta_speed']:
        status['status'] = 'N/A'
        return status

    # Check for link speed degradation
    cap_speed = parse_pcie_speed(details['lnk_cap_speed'])
    sta_speed = parse_pcie_speed(details['lnk_sta_speed'])

    if cap_speed > 0 and sta_speed < cap_speed:
        status['status'] = 'WARNING'
        status['issues'].append(
            f"Link speed degraded: running at {details['lnk_sta_speed']} "
            f"(capable of {details['lnk_cap_speed']})"
        )

    # Check for link width degradation
    cap_width = parse_pcie_width(details['lnk_cap_width'])
    sta_width = parse_pcie_width(details['lnk_sta_width'])

    if cap_width > 0 and sta_width < cap_width:
        status['status'] = 'WARNING'
        status['issues'].append(
            f"Link width degraded: running at {details['lnk_sta_width']} "
            f"(capable of {details['lnk_cap_width']})"
        )

    # Check for errors
    if details['fatal_errors'] > 0:
        status['status'] = 'CRITICAL'
        status['issues'].append('Fatal PCIe errors detected')

    if details['uncorrectable_errors'] > 0:
        if status['status'] == 'OK':
            status['status'] = 'CRITICAL'
        status['issues'].append(
            f"{details['uncorrectable_errors']} uncorrectable error type(s) detected"
        )

    if details['correctable_errors'] > 0:
        if status['status'] == 'OK':
            status['status'] = 'WARNING'
        status['issues'].append(
            f"{details['correctable_errors']} correctable error type(s) detected"
        )

    return status


def format_plain(results, warn_only=False, verbose=False):
    """Format results as plain text."""
    output = []

    filtered_results = results
    if warn_only:
        filtered_results = [
            r for r in results
            if r['health']['status'] in ['WARNING', 'CRITICAL', 'UNKNOWN']
        ]

    if not filtered_results:
        if warn_only:
            output.append("No PCIe device issues detected.")
        else:
            output.append("No PCIe devices found.")
        return '\n'.join(output)

    for result in filtered_results:
        addr = result['address']
        desc = result['description']
        health = result['health']
        details = result['details']

        # Status symbol
        status_map = {
            'OK': '✓',
            'WARNING': '⚠',
            'CRITICAL': '✗',
            'UNKNOWN': '?',
            'N/A': '-'
        }
        symbol = status_map.get(health['status'], '?')

        # Skip N/A devices in non-verbose mode
        if health['status'] == 'N/A' and not verbose:
            continue

        output.append(f"{symbol} {addr} - {desc}")

        if details and health['status'] not in ['N/A', 'UNKNOWN']:
            if details['lnk_sta_speed'] and details['lnk_sta_width']:
                link_info = (
                    f"  Link: {details['lnk_sta_speed']} {details['lnk_sta_width']}"
                )
                if verbose and details['lnk_cap_speed'] and details['lnk_cap_width']:
                    link_info += (
                        f" (max: {details['lnk_cap_speed']} {details['lnk_cap_width']})"
                    )
                output.append(link_info)

        if health['issues']:
            for issue in health['issues']:
                output.append(f"  Issue: {issue}")

        output.append("")

    return '\n'.join(output)


def format_json(results, warn_only=False):
    """Format results as JSON."""
    filtered_results = results
    if warn_only:
        filtered_results = [
            r for r in results
            if r['health']['status'] in ['WARNING', 'CRITICAL', 'UNKNOWN']
        ]

    return json.dumps(filtered_results, indent=2)


def format_table(results, warn_only=False):
    """Format results as a table."""
    filtered_results = results
    if warn_only:
        filtered_results = [
            r for r in results
            if r['health']['status'] in ['WARNING', 'CRITICAL', 'UNKNOWN']
        ]

    # Filter out N/A entries for table view
    filtered_results = [r for r in filtered_results if r['health']['status'] != 'N/A']

    if not filtered_results:
        return "No PCIe devices with link information found." if not warn_only else "No issues detected."

    # Header
    header = f"{'ADDRESS':<13} {'LINK STATUS':<20} {'LINK CAPABILITY':<20} {'STATUS':<10} {'DEVICE':<40}"
    separator = '-' * 110
    rows = [header, separator]

    for result in filtered_results:
        addr = result['address']
        desc = result['description'][:40]
        health = result['health']
        details = result['details']

        link_status = 'N/A'
        link_cap = 'N/A'

        if details:
            if details['lnk_sta_speed'] and details['lnk_sta_width']:
                link_status = f"{details['lnk_sta_speed']} {details['lnk_sta_width']}"
            if details['lnk_cap_speed'] and details['lnk_cap_width']:
                link_cap = f"{details['lnk_cap_speed']} {details['lnk_cap_width']}"

        status = health['status']

        row = f"{addr:<13} {link_status:<20} {link_cap:<20} {status:<10} {desc:<40}"
        rows.append(row)

        # Add issue details on next line if present
        if health['issues']:
            for issue in health['issues']:
                rows.append(f"  └─ {issue}")

    return '\n'.join(rows)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor PCIe device health and link status on baremetal systems.',
        epilog='''
Examples:
  # Check all PCIe devices
  pcie_health_monitor.py

  # Show only devices with warnings or errors
  pcie_health_monitor.py --warn-only

  # Output as JSON for monitoring systems
  pcie_health_monitor.py --format json

  # Verbose output showing all link details
  pcie_health_monitor.py --verbose

  # Table format with warnings only
  pcie_health_monitor.py --format table --warn-only

Exit codes:
  0 - All PCIe devices healthy
  1 - Warning or critical conditions detected
  2 - Usage error or missing dependencies
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show devices with warnings or critical status'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed device information including N/A devices'
    )

    args = parser.parse_args()

    # Check if lspci is available
    if not check_lspci_available():
        print("Error: 'lspci' command not found.", file=sys.stderr)
        print("Install pciutils package (e.g., 'apt install pciutils' or 'yum install pciutils')", file=sys.stderr)
        return 2

    # Get all PCIe devices
    devices = get_pcie_devices()

    if not devices:
        print("No PCIe devices found.", file=sys.stderr)
        return 2

    # Gather detailed information and check health
    results = []
    for device in devices:
        details = get_device_details(device['address'])
        health = check_device_health(device, details)

        results.append({
            'address': device['address'],
            'description': device['description'],
            'details': details,
            'health': health
        })

    # Format output
    if args.format == 'json':
        output = format_json(results, args.warn_only)
    elif args.format == 'table':
        output = format_table(results, args.warn_only)
    else:
        output = format_plain(results, args.warn_only, args.verbose)

    print(output)

    # Determine exit code based on health status
    has_warnings = any(r['health']['status'] == 'WARNING' for r in results)
    has_critical = any(r['health']['status'] == 'CRITICAL' for r in results)

    if has_critical or has_warnings:
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
