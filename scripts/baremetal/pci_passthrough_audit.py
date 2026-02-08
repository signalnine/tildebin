#!/usr/bin/env python3
# boxctl:
#   category: baremetal/virtualization
#   tags: [virtualization, pci, passthrough, vfio, iommu, gpu]
#   requires: []
#   privilege: root
#   related: [iommu_status, pcie_health, gpu_health]
#   brief: Audit PCI device passthrough configuration and VFIO bindings

"""
Audit PCI device passthrough configuration and VFIO bindings.

Checks VFIO-bound PCI devices and their IOMMU group isolation to detect
configuration problems that could cause passthrough failures or host instability.

Checks performed:
- Enumerate VFIO-bound devices via /sys/bus/pci/drivers/vfio-pci
- Map IOMMU groups to devices and their bound drivers
- Detect mixed IOMMU groups (VFIO and non-VFIO devices sharing a group)

Mixed IOMMU groups are problematic because all devices in a group share the
same IOMMU translation context. Passing through only some devices in a group
while leaving others bound to host drivers can cause DMA isolation failures.

Exit codes:
    0: No issues detected (or no passthrough configured)
    1: Warnings found (mixed IOMMU groups)
    2: Usage error or missing /sys/bus/pci/devices
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_vfio_devices(context: Context) -> list[str]:
    """Get list of PCI addresses bound to vfio-pci driver.

    Returns list of PCI addresses like ['0000:01:00.0', '0000:01:00.1'].
    """
    vfio_dir = "/sys/bus/pci/drivers/vfio-pci"
    entries = context.glob("*", root=vfio_dir)
    devices = []
    for entry in entries:
        addr = entry.split("/")[-1]
        # PCI addresses look like 0000:01:00.0
        if ":" in addr and "." in addr:
            devices.append(addr)
    return sorted(devices)


def get_iommu_groups(context: Context) -> dict[str, list[str]]:
    """Map IOMMU group numbers to their device addresses.

    Returns dict like {'1': ['0000:00:02.0'], '2': ['0000:01:00.0', '0000:01:00.1']}.
    """
    groups: dict[str, list[str]] = {}
    group_entries = context.glob("*", root="/sys/kernel/iommu_groups")

    for group_path in group_entries:
        group_id = group_path.split("/")[-1]
        # Skip non-numeric entries
        if not group_id.isdigit():
            continue

        devices_dir = f"/sys/kernel/iommu_groups/{group_id}/devices"
        device_entries = context.glob("*", root=devices_dir)
        addrs = []
        for dev_path in device_entries:
            addr = dev_path.split("/")[-1]
            if ":" in addr and "." in addr:
                addrs.append(addr)

        if addrs:
            groups[group_id] = sorted(addrs)

    return groups


def get_device_driver(addr: str, context: Context) -> str:
    """Get the driver bound to a PCI device.

    Returns driver name (e.g. 'vfio-pci', 'nvidia', 'i915') or empty string
    if no driver is bound.
    """
    driver_link = f"/sys/bus/pci/devices/{addr}/driver"
    target = context.readlink(driver_link)
    if not target:
        return ""
    # Symlink target is like ../../../../bus/pci/drivers/vfio-pci
    return target.split("/")[-1]


def analyze_passthrough(
    vfio_devices: list[str],
    iommu_groups: dict[str, list[str]],
    context: Context,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Analyze VFIO passthrough configuration.

    Returns (devices_info, issues) where:
    - devices_info: list of dicts with device/group/driver info
    - issues: list of dicts describing problems found
    """
    devices_info: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []

    # Build reverse map: device addr -> group id
    addr_to_group: dict[str, str] = {}
    for group_id, addrs in iommu_groups.items():
        for addr in addrs:
            addr_to_group[addr] = group_id

    # Collect info for all devices in groups that contain VFIO devices
    vfio_set = set(vfio_devices)
    checked_groups: set[str] = set()

    for addr in vfio_devices:
        group_id = addr_to_group.get(addr, "unknown")
        driver = get_device_driver(addr, context)

        devices_info.append({
            "address": addr,
            "driver": driver,
            "iommu_group": group_id,
            "is_vfio": True,
        })

        # Check the IOMMU group for mixed drivers
        if group_id != "unknown" and group_id not in checked_groups:
            checked_groups.add(group_id)
            group_addrs = iommu_groups.get(group_id, [])

            vfio_in_group = []
            non_vfio_in_group = []

            for group_addr in group_addrs:
                group_driver = get_device_driver(group_addr, context)
                if group_addr in vfio_set or group_driver == "vfio-pci":
                    vfio_in_group.append(group_addr)
                else:
                    non_vfio_in_group.append(group_addr)

            if vfio_in_group and non_vfio_in_group:
                non_vfio_drivers = []
                for nv_addr in non_vfio_in_group:
                    nv_driver = get_device_driver(nv_addr, context)
                    non_vfio_drivers.append(
                        f"{nv_addr} ({nv_driver or 'no driver'})"
                    )

                issues.append({
                    "severity": "warning",
                    "type": "mixed_iommu_group",
                    "iommu_group": group_id,
                    "vfio_devices": vfio_in_group,
                    "non_vfio_devices": non_vfio_in_group,
                    "message": (
                        f"IOMMU group {group_id} has mixed drivers: "
                        f"VFIO [{', '.join(vfio_in_group)}] and "
                        f"non-VFIO [{', '.join(non_vfio_drivers)}]"
                    ),
                })

    return devices_info, issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy or no passthrough configured, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit PCI device passthrough configuration and VFIO bindings"
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show detailed device and group information",
    )
    opts = parser.parse_args(args)

    # Check PCI sysfs availability
    if not context.is_dir("/sys/bus/pci/devices"):
        output.error("/sys/bus/pci/devices not found - PCI sysfs not available")
        output.render(opts.format, "PCI Passthrough Audit")
        return 2

    # Check if vfio-pci driver is loaded
    vfio_dir = "/sys/bus/pci/drivers/vfio-pci"
    if not context.is_dir(vfio_dir):
        output.emit({
            "status": "ok",
            "message": "No VFIO passthrough configured (vfio-pci driver not loaded)",
            "vfio_device_count": 0,
            "devices": [],
            "issues": [],
        })
        output.set_summary("No VFIO passthrough configured")
        output.render(opts.format, "PCI Passthrough Audit")
        return 0

    # Get VFIO-bound devices
    vfio_devices = get_vfio_devices(context)

    if not vfio_devices:
        output.emit({
            "status": "ok",
            "message": "VFIO driver loaded but no devices bound",
            "vfio_device_count": 0,
            "devices": [],
            "issues": [],
        })
        output.set_summary("VFIO driver loaded, no devices bound")
        output.render(opts.format, "PCI Passthrough Audit")
        return 0

    # Get IOMMU groups
    iommu_groups = get_iommu_groups(context)

    # Analyze
    devices_info, issues = analyze_passthrough(vfio_devices, iommu_groups, context)

    has_warnings = any(i["severity"] == "warning" for i in issues)

    if has_warnings:
        overall_status = "warning"
    else:
        overall_status = "healthy"

    output.emit({
        "status": overall_status,
        "vfio_device_count": len(vfio_devices),
        "iommu_group_count": len(iommu_groups),
        "devices": devices_info,
        "issues": issues,
    })

    if has_warnings:
        output.set_summary(
            f"{len(issues)} issue(s) found across {len(vfio_devices)} VFIO device(s)"
        )
    else:
        output.set_summary(
            f"{len(vfio_devices)} VFIO device(s) in isolated IOMMU groups"
        )

    output.render(opts.format, "PCI Passthrough Audit")
    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
