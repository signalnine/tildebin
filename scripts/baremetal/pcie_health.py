#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, pcie, hardware, bus, link]
#   requires: [lspci]
#   privilege: user
#   related: [pcie_topology, gpu_health, nvme_health]
#   brief: Monitor PCIe device health and link status

"""
Monitor PCIe device health and link status on baremetal systems.

Checks PCIe link speed, width, and error counters to detect degraded or
failing PCIe devices. Useful for identifying hardware issues with GPUs,
NVMe drives, network cards, and other PCIe devices before they cause
system failures or performance degradation.

Returns exit code 1 if any device has warnings or critical conditions.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_pcie_speed(speed_str: str) -> float:
    """Parse PCIe speed string to numeric value."""
    match = re.search(r'([\d.]+)GT/s', speed_str)
    if match:
        return float(match.group(1))
    return 0.0


def parse_pcie_width(width_str: str) -> int:
    """Parse PCIe width string to numeric value."""
    match = re.search(r'x(\d+)', width_str)
    if match:
        return int(match.group(1))
    return 0


def check_device_health(details: dict[str, Any]) -> dict[str, Any]:
    """Check if a PCIe device is healthy based on link status and errors."""
    status = 'healthy'
    issues = []

    if not details:
        return {'status': 'unknown', 'issues': ['Unable to read device details']}

    # Skip devices without PCIe link information
    if not details.get('lnk_cap_speed') or not details.get('lnk_sta_speed'):
        return {'status': 'n/a', 'issues': []}

    # Check for link speed degradation
    cap_speed = parse_pcie_speed(details['lnk_cap_speed'])
    sta_speed = parse_pcie_speed(details['lnk_sta_speed'])

    if cap_speed > 0 and sta_speed < cap_speed:
        status = 'warning'
        issues.append(
            f"Link speed degraded: {details['lnk_sta_speed']} "
            f"(capable of {details['lnk_cap_speed']})"
        )

    # Check for link width degradation
    cap_width = parse_pcie_width(details.get('lnk_cap_width', ''))
    sta_width = parse_pcie_width(details.get('lnk_sta_width', ''))

    if cap_width > 0 and sta_width < cap_width:
        status = 'warning'
        issues.append(
            f"Link width degraded: {details['lnk_sta_width']} "
            f"(capable of {details['lnk_cap_width']})"
        )

    # Check for errors
    if details.get('fatal_errors', 0) > 0:
        status = 'critical'
        issues.append('Fatal PCIe errors detected')

    if details.get('uncorrectable_errors', 0) > 0:
        status = 'critical'
        issues.append(
            f"{details['uncorrectable_errors']} uncorrectable error type(s)"
        )

    if details.get('correctable_errors', 0) > 0:
        if status == 'healthy':
            status = 'warning'
        issues.append(
            f"{details['correctable_errors']} correctable error type(s)"
        )

    return {'status': status, 'issues': issues}


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor PCIe device health and link status"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show devices with warnings or critical status"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed device information"
    )

    opts = parser.parse_args(args)

    # Check if lspci is available
    if not context.check_tool("lspci"):
        output.error("lspci not found. Install pciutils package.")
        return 2

    # Get all PCIe devices
    try:
        result = context.run(['lspci', '-D'], check=True)
    except Exception as e:
        output.error(f"Failed to run lspci: {e}")
        return 2

    devices = []
    for line in result.stdout.strip().split('\n'):
        if line.strip():
            parts = line.split(' ', 1)
            if len(parts) >= 2:
                devices.append({
                    'address': parts[0],
                    'description': parts[1]
                })

    if not devices:
        output.warning("No PCIe devices found")
        output.emit({"devices": []})
        return 0

    # Gather detailed information and check health
    results = []
    for device in devices:
        # Get device details
        try:
            detail_result = context.run(
                ['lspci', '-vvv', '-s', device['address']],
                check=False
            )
            detail_output = detail_result.stdout
        except Exception:
            detail_output = ""

        details = {
            'address': device['address'],
            'lnk_cap_speed': None,
            'lnk_cap_width': None,
            'lnk_sta_speed': None,
            'lnk_sta_width': None,
            'correctable_errors': 0,
            'uncorrectable_errors': 0,
            'fatal_errors': 0
        }

        # Parse LnkCap
        lnk_cap = re.search(r'LnkCap:.*?Speed ([\d.]+GT/s).*?Width (x\d+)', detail_output)
        if lnk_cap:
            details['lnk_cap_speed'] = lnk_cap.group(1)
            details['lnk_cap_width'] = lnk_cap.group(2)

        # Parse LnkSta
        lnk_sta = re.search(r'LnkSta:.*?Speed ([\d.]+GT/s).*?Width (x\d+)', detail_output)
        if lnk_sta:
            details['lnk_sta_speed'] = lnk_sta.group(1)
            details['lnk_sta_width'] = lnk_sta.group(2)

        # Parse error counters
        uncorr = re.search(r'UncorrErr:.*', detail_output)
        if uncorr:
            error_indicators = re.findall(r'(\w+)\+', uncorr.group(0))
            details['uncorrectable_errors'] = len(error_indicators)

        corr = re.search(r'CorrErr:.*', detail_output)
        if corr:
            error_indicators = re.findall(r'(\w+)\+', corr.group(0))
            details['correctable_errors'] = len(error_indicators)

        if re.search(r'FatalErr\+', detail_output):
            details['fatal_errors'] = 1

        health = check_device_health(details)

        result_entry = {
            'address': device['address'],
            'description': device['description'],
            'status': health['status'],
        }

        if opts.verbose:
            result_entry['link_speed'] = details.get('lnk_sta_speed')
            result_entry['link_width'] = details.get('lnk_sta_width')
            result_entry['max_speed'] = details.get('lnk_cap_speed')
            result_entry['max_width'] = details.get('lnk_cap_width')
            result_entry['issues'] = health['issues']

        results.append(result_entry)

    # Filter for warn-only mode and remove N/A devices
    filtered = results
    if opts.warn_only:
        filtered = [r for r in results if r['status'] in ['warning', 'critical', 'unknown']]
    else:
        # In non-verbose mode, filter out N/A devices
        if not opts.verbose:
            filtered = [r for r in results if r['status'] != 'n/a']

    output.emit({"devices": filtered})

    # Set summary
    healthy = sum(1 for r in results if r['status'] == 'healthy')
    warning = sum(1 for r in results if r['status'] == 'warning')
    critical = sum(1 for r in results if r['status'] == 'critical')
    output.set_summary(f"{healthy} healthy, {warning} warning, {critical} critical")

    # Return 1 if any issues
    has_issues = warning > 0 or critical > 0
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
