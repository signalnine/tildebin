#!/usr/bin/env python3
"""
Analyze PCIe topology including IOMMU groups and device-to-NUMA node mapping.

This script provides visibility into PCIe device placement which is critical
for high-performance workloads on baremetal systems with GPUs, HBAs, or
high-speed NICs. Suboptimal PCIe placement can cause significant performance
degradation due to cross-NUMA memory access.

Checks performed:
- PCIe device enumeration with bus/device/function addresses
- IOMMU group organization for device passthrough planning
- Device-to-NUMA node locality mapping
- PCIe link speed and width (current vs capable)
- Detection of devices in suboptimal NUMA placement
- Identification of devices sharing IOMMU groups (passthrough conflicts)

Useful for:
- GPU cluster planning and NUMA-aware placement
- SR-IOV and device passthrough configuration
- Performance optimization for NVMe, GPU, and network workloads
- Pre-deployment hardware verification
- Troubleshooting PCIe-related performance issues

Exit codes:
    0 - All PCIe devices properly configured
    1 - Warnings detected (suboptimal placement, link degradation)
    2 - Usage error or missing data sources
"""

import argparse
import sys
import os
import json
import glob
import re


def read_file_safe(path, default=None):
    """Safely read a file and return contents or default."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, IOError):
        return default


def get_pcie_devices():
    """
    Enumerate PCIe devices from /sys/bus/pci/devices.

    Returns list of device dictionaries with bus address and basic info.
    """
    devices = []
    pci_path = '/sys/bus/pci/devices'

    if not os.path.isdir(pci_path):
        return None, "PCI sysfs not available"

    for dev_addr in os.listdir(pci_path):
        dev_path = os.path.join(pci_path, dev_addr)

        if not os.path.isdir(dev_path):
            continue

        device = {
            'address': dev_addr,
            'path': dev_path,
        }

        # Read vendor and device IDs
        device['vendor_id'] = read_file_safe(os.path.join(dev_path, 'vendor'), '0x0000')
        device['device_id'] = read_file_safe(os.path.join(dev_path, 'device'), '0x0000')

        # Read class code
        device['class'] = read_file_safe(os.path.join(dev_path, 'class'), '0x000000')

        # Get driver binding
        driver_link = os.path.join(dev_path, 'driver')
        if os.path.islink(driver_link):
            device['driver'] = os.path.basename(os.readlink(driver_link))
        else:
            device['driver'] = None

        # Get NUMA node
        numa_node = read_file_safe(os.path.join(dev_path, 'numa_node'), '-1')
        try:
            device['numa_node'] = int(numa_node)
        except ValueError:
            device['numa_node'] = -1

        # Get IOMMU group
        iommu_link = os.path.join(dev_path, 'iommu_group')
        if os.path.islink(iommu_link):
            device['iommu_group'] = int(os.path.basename(os.readlink(iommu_link)))
        else:
            device['iommu_group'] = None

        # Get PCIe link speed and width
        device['current_link_speed'] = read_file_safe(
            os.path.join(dev_path, 'current_link_speed'))
        device['current_link_width'] = read_file_safe(
            os.path.join(dev_path, 'current_link_width'))
        device['max_link_speed'] = read_file_safe(
            os.path.join(dev_path, 'max_link_speed'))
        device['max_link_width'] = read_file_safe(
            os.path.join(dev_path, 'max_link_width'))

        devices.append(device)

    return devices, None


def get_device_class_name(class_code):
    """Convert PCI class code to human-readable name."""
    # Extract base class from full code (0xXXYYZZ -> XX is base class)
    try:
        base_class = (int(class_code, 16) >> 16) & 0xFF
    except (ValueError, TypeError):
        return "Unknown"

    class_names = {
        0x00: "Legacy",
        0x01: "Storage",
        0x02: "Network",
        0x03: "Display",
        0x04: "Multimedia",
        0x05: "Memory",
        0x06: "Bridge",
        0x07: "Communication",
        0x08: "System",
        0x09: "Input",
        0x0a: "Docking",
        0x0b: "Processor",
        0x0c: "Serial Bus",
        0x0d: "Wireless",
        0x0e: "Intelligent I/O",
        0x0f: "Satellite",
        0x10: "Encryption",
        0x11: "Signal Processing",
        0x12: "Processing Accelerator",
        0x13: "Non-Essential",
        0xff: "Unassigned",
    }

    return class_names.get(base_class, f"Class 0x{base_class:02x}")


def parse_link_speed(speed_str):
    """Parse link speed string to GT/s value for comparison."""
    if not speed_str:
        return 0

    # Handle formats like "8.0 GT/s PCIe" or "8 GT/s"
    match = re.search(r'([\d.]+)\s*GT/s', speed_str)
    if match:
        return float(match.group(1))
    return 0


def parse_link_width(width_str):
    """Parse link width string to integer."""
    if not width_str:
        return 0

    # Handle formats like "x16" or "16"
    match = re.search(r'x?(\d+)', width_str)
    if match:
        return int(match.group(1))
    return 0


def analyze_devices(devices, check_numa=True, check_link=True):
    """
    Analyze devices for issues.

    Returns tuple of (enriched_devices, issues)
    """
    issues = []
    enriched = []

    # Group devices by IOMMU group for conflict detection
    iommu_groups = {}
    for dev in devices:
        if dev['iommu_group'] is not None:
            group = dev['iommu_group']
            if group not in iommu_groups:
                iommu_groups[group] = []
            iommu_groups[group].append(dev['address'])

    for dev in devices:
        enriched_dev = dev.copy()
        enriched_dev['class_name'] = get_device_class_name(dev['class'])
        enriched_dev['issues'] = []

        # Check NUMA placement
        if check_numa and dev['numa_node'] == -1:
            # Only warn for significant devices (not bridges)
            base_class = (int(dev['class'], 16) >> 16) & 0xFF
            if base_class not in [0x06]:  # Skip bridges
                enriched_dev['issues'].append("No NUMA affinity (cross-node access possible)")

        # Check PCIe link degradation
        if check_link:
            current_speed = parse_link_speed(dev['current_link_speed'])
            max_speed = parse_link_speed(dev['max_link_speed'])
            current_width = parse_link_width(dev['current_link_width'])
            max_width = parse_link_width(dev['max_link_width'])

            if max_speed > 0 and current_speed < max_speed:
                enriched_dev['issues'].append(
                    f"Link speed degraded: {dev['current_link_speed']} "
                    f"(capable: {dev['max_link_speed']})"
                )

            if max_width > 0 and current_width < max_width:
                enriched_dev['issues'].append(
                    f"Link width degraded: x{current_width} "
                    f"(capable: x{max_width})"
                )

        # Check IOMMU group sharing (potential passthrough conflict)
        if dev['iommu_group'] is not None:
            group_members = iommu_groups.get(dev['iommu_group'], [])
            if len(group_members) > 1:
                other_devices = [a for a in group_members if a != dev['address']]
                enriched_dev['iommu_group_members'] = group_members
                # Only flag as issue for non-bridge devices
                base_class = (int(dev['class'], 16) >> 16) & 0xFF
                if base_class not in [0x06]:
                    enriched_dev['issues'].append(
                        f"Shares IOMMU group {dev['iommu_group']} with {len(other_devices)} "
                        f"other device(s) - may affect passthrough"
                    )

        if enriched_dev['issues']:
            for issue in enriched_dev['issues']:
                issues.append({
                    'address': dev['address'],
                    'class': enriched_dev['class_name'],
                    'message': issue,
                })

        enriched.append(enriched_dev)

    return enriched, issues


def build_numa_summary(devices):
    """Build summary of devices per NUMA node."""
    numa_summary = {}

    for dev in devices:
        node = dev['numa_node']
        if node not in numa_summary:
            numa_summary[node] = {
                'count': 0,
                'by_class': {},
            }

        numa_summary[node]['count'] += 1
        class_name = get_device_class_name(dev['class'])

        if class_name not in numa_summary[node]['by_class']:
            numa_summary[node]['by_class'][class_name] = 0
        numa_summary[node]['by_class'][class_name] += 1

    return numa_summary


def build_iommu_summary(devices):
    """Build summary of IOMMU groups."""
    groups = {}

    for dev in devices:
        if dev['iommu_group'] is None:
            continue

        group = dev['iommu_group']
        if group not in groups:
            groups[group] = []

        groups[group].append({
            'address': dev['address'],
            'class': get_device_class_name(dev['class']),
            'driver': dev['driver'],
        })

    return groups


def output_plain(devices, issues, verbose=False, warn_only=False):
    """Output results in plain text format."""
    lines = []

    if not warn_only:
        # Summary
        numa_summary = build_numa_summary(devices)
        lines.append("PCIe Topology Analysis")
        lines.append("")
        lines.append(f"  Total devices: {len(devices)}")
        lines.append(f"  NUMA nodes with devices: {len([n for n in numa_summary if n >= 0])}")

        # NUMA distribution
        lines.append("")
        lines.append("NUMA Node Distribution:")
        for node in sorted(numa_summary.keys()):
            node_label = f"Node {node}" if node >= 0 else "No affinity"
            classes = numa_summary[node]['by_class']
            class_str = ", ".join(f"{c}: {n}" for c, n in sorted(classes.items()))
            lines.append(f"  {node_label}: {numa_summary[node]['count']} devices ({class_str})")

        lines.append("")

    # Device details (verbose mode)
    if verbose and not warn_only:
        lines.append("Device Details:")
        lines.append("-" * 80)

        # Sort by NUMA node, then address
        sorted_devices = sorted(devices, key=lambda d: (d['numa_node'], d['address']))

        for dev in sorted_devices:
            # Skip bridges in verbose output unless they have issues
            base_class = (int(dev['class'], 16) >> 16) & 0xFF
            if base_class == 0x06 and not dev.get('issues'):
                continue

            lines.append(f"  {dev['address']} [{dev['class_name']}]")
            lines.append(f"    Vendor/Device: {dev['vendor_id']}/{dev['device_id']}")
            lines.append(f"    Driver: {dev['driver'] or 'none'}")
            lines.append(f"    NUMA node: {dev['numa_node']}")

            if dev['iommu_group'] is not None:
                lines.append(f"    IOMMU group: {dev['iommu_group']}")

            if dev['current_link_speed']:
                link_info = f"{dev['current_link_speed']}"
                if dev['max_link_speed'] and dev['current_link_speed'] != dev['max_link_speed']:
                    link_info += f" (max: {dev['max_link_speed']})"
                lines.append(f"    Link speed: {link_info}")

            if dev['current_link_width']:
                width_info = f"{dev['current_link_width']}"
                if dev['max_link_width'] and dev['current_link_width'] != dev['max_link_width']:
                    width_info += f" (max: {dev['max_link_width']})"
                lines.append(f"    Link width: {width_info}")

            if dev.get('issues'):
                for issue in dev['issues']:
                    lines.append(f"    [!] {issue}")

            lines.append("")

    # Issues summary
    if issues:
        lines.append(f"Issues Detected ({len(issues)}):")
        lines.append("-" * 60)
        for issue in issues:
            lines.append(f"  [{issue['address']}] {issue['class']}: {issue['message']}")
        lines.append("")
    elif not warn_only:
        lines.append("No issues detected.")
        lines.append("")

    return '\n'.join(lines)


def output_json(devices, issues):
    """Output results in JSON format."""
    result = {
        'summary': {
            'total_devices': len(devices),
            'issue_count': len(issues),
            'numa_distribution': build_numa_summary(devices),
            'iommu_groups': build_iommu_summary(devices),
        },
        'devices': devices,
        'issues': issues,
    }
    return json.dumps(result, indent=2)


def output_table(devices, issues, warn_only=False):
    """Output results in table format."""
    lines = []

    if not warn_only:
        lines.append(f"{'Address':<14} {'Class':<12} {'NUMA':<6} {'IOMMU':<6} "
                     f"{'Driver':<15} {'Link Speed':<20}")
        lines.append("-" * 80)

        # Sort and filter devices
        sorted_devices = sorted(devices, key=lambda d: (d['numa_node'], d['address']))

        for dev in sorted_devices:
            # Skip bridges unless they have issues
            base_class = (int(dev['class'], 16) >> 16) & 0xFF
            if base_class == 0x06 and not dev.get('issues'):
                continue

            numa = str(dev['numa_node']) if dev['numa_node'] >= 0 else "-"
            iommu = str(dev['iommu_group']) if dev['iommu_group'] is not None else "-"
            driver = (dev['driver'] or '-')[:14]
            link = dev['current_link_speed'][:19] if dev['current_link_speed'] else '-'

            marker = "!" if dev.get('issues') else " "
            lines.append(f"{marker}{dev['address']:<13} {dev['class_name'][:11]:<12} "
                         f"{numa:<6} {iommu:<6} {driver:<15} {link:<20}")

        lines.append("")

    if issues:
        lines.append(f"Issues ({len(issues)}):")
        lines.append("-" * 60)
        for issue in issues:
            lines.append(f"  {issue['address']}: {issue['message']}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze PCIe topology, IOMMU groups, and NUMA placement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic topology analysis
  %(prog)s --format json            # JSON output for automation
  %(prog)s --verbose                # Show all device details
  %(prog)s --warn-only              # Only show issues
  %(prog)s --no-link-check          # Skip link speed/width checks

Understanding the output:
  NUMA node: The memory domain where this device has optimal access.
             Devices with NUMA=-1 have no affinity and may have suboptimal
             memory access performance.

  IOMMU group: Devices in the same group cannot be passed through to VMs
               independently. Devices sharing groups may affect passthrough.

  Link degradation: When current speed/width is below capable values,
                    the device may be in a suboptimal slot or have issues.

Exit codes:
  0 - All PCIe devices properly configured
  1 - Warnings detected (suboptimal placement, link degradation)
  2 - Usage error or missing data sources

See also:
  lspci -vvv         # Detailed PCI device information
  lspci -t           # PCI device tree
  /sys/kernel/iommu_groups/  # IOMMU group details
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
        help="Show detailed per-device information"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show devices with issues"
    )

    parser.add_argument(
        "--no-numa-check",
        action="store_true",
        help="Skip NUMA affinity checks"
    )

    parser.add_argument(
        "--no-link-check",
        action="store_true",
        help="Skip PCIe link speed/width checks"
    )

    args = parser.parse_args()

    # Get PCIe devices
    devices, error = get_pcie_devices()

    if devices is None:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    if not devices:
        print("No PCIe devices found", file=sys.stderr)
        sys.exit(2)

    # Analyze devices
    enriched_devices, issues = analyze_devices(
        devices,
        check_numa=not args.no_numa_check,
        check_link=not args.no_link_check
    )

    # Output
    if args.format == "json":
        output = output_json(enriched_devices, issues)
    elif args.format == "table":
        output = output_table(enriched_devices, issues, warn_only=args.warn_only)
    else:
        output = output_plain(enriched_devices, issues,
                              verbose=args.verbose, warn_only=args.warn_only)

    print(output)

    # Exit based on findings
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
