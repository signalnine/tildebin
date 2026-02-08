#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, iommu, vt-d, amd-vi, virtualization, dma]
#   requires: []
#   privilege: root
#   related: [pcie_health, kernel_cmdline_audit]
#   brief: Audit IOMMU/DMA remapping configuration and device isolation

"""
Audit IOMMU/DMA remapping configuration and device isolation.

Checks whether IOMMU (Intel VT-d / AMD-Vi) is enabled and properly configured
for DMA remapping. Important for virtualization security, device passthrough,
and protection against DMA attacks.

Reads from:
- /sys/class/iommu/ for active IOMMU instances
- /sys/kernel/iommu_groups/ for device isolation groups
- /proc/cmdline for kernel IOMMU parameters
- /sys/firmware/acpi/tables/DMAR (Intel) or IVRS (AMD) for hardware support

Returns exit code 1 if IOMMU hardware is present but not enabled.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


IOMMU_CMDLINE_PARAMS = [
    'intel_iommu=on',
    'amd_iommu=on',
    'iommu=pt',
]


def parse_cmdline(cmdline: str) -> dict[str, Any]:
    """Parse kernel command line for IOMMU-related parameters.

    Returns dict with:
        intel_iommu: value if present, else None
        amd_iommu: value if present, else None
        iommu: value if present, else None
        params_found: list of matched IOMMU params
    """
    result: dict[str, Any] = {
        'intel_iommu': None,
        'amd_iommu': None,
        'iommu': None,
        'params_found': [],
    }

    for token in cmdline.split():
        if '=' in token:
            key, _, value = token.partition('=')
        else:
            key, value = token, ''

        if key == 'intel_iommu':
            result['intel_iommu'] = value
        elif key == 'amd_iommu':
            result['amd_iommu'] = value
        elif key == 'iommu':
            result['iommu'] = value

    for param in IOMMU_CMDLINE_PARAMS:
        if param in cmdline:
            result['params_found'].append(param)

    return result


def get_iommu_groups(context: Context) -> list[dict[str, Any]]:
    """Enumerate IOMMU groups and their devices.

    Returns list of dicts, each with:
        group_id: str (group number)
        device_count: int
        devices: list[str] (device directory basenames)
    """
    groups_root = '/sys/kernel/iommu_groups'
    groups = []

    group_dirs = context.glob('*', groups_root)
    for group_path in sorted(group_dirs):
        group_id = group_path.split('/')[-1]
        devices_path = f'{group_path}/devices'
        device_entries = context.glob('*', devices_path)
        device_names = [d.split('/')[-1] for d in device_entries]

        groups.append({
            'group_id': group_id,
            'device_count': len(device_names),
            'devices': device_names,
        })

    return groups


def check_mixed_groups(groups: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Check for IOMMU groups with multiple devices (potential isolation issue).

    Groups with more than one device indicate devices that cannot be
    independently assigned to VMs, which is an informational finding.
    """
    issues = []
    for group in groups:
        if group['device_count'] > 1:
            issues.append({
                'severity': 'INFO',
                'message': (
                    f"IOMMU group {group['group_id']} has "
                    f"{group['device_count']} devices: "
                    f"{', '.join(group['devices'])}"
                ),
            })
    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit IOMMU/DMA remapping configuration and device isolation"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # /proc/cmdline is essential - exit 2 if unreadable
    if not context.file_exists('/proc/cmdline'):
        output.error("Cannot read /proc/cmdline")
        output.render(opts.format, "IOMMU/DMA Remapping Status")
        return 2

    try:
        cmdline = context.read_file('/proc/cmdline').strip()
    except Exception:
        output.error("Cannot read /proc/cmdline")
        output.render(opts.format, "IOMMU/DMA Remapping Status")
        return 2

    # Parse kernel command line for IOMMU params
    cmdline_info = parse_cmdline(cmdline)

    # Check for IOMMU hardware support via ACPI tables
    has_dmar = context.file_exists('/sys/firmware/acpi/tables/DMAR')
    has_ivrs = context.file_exists('/sys/firmware/acpi/tables/IVRS')
    has_hardware = has_dmar or has_ivrs

    # Check if IOMMU is active (populated /sys/class/iommu/)
    iommu_instances = context.glob('*', '/sys/class/iommu')
    iommu_enabled = len(iommu_instances) > 0

    # Enumerate IOMMU groups
    iommu_groups = get_iommu_groups(context)

    # Determine hardware type
    if has_dmar:
        hardware_type = 'Intel VT-d (DMAR)'
    elif has_ivrs:
        hardware_type = 'AMD-Vi (IVRS)'
    else:
        hardware_type = 'none detected'

    # Build issues list
    issues: list[dict[str, str]] = []
    has_critical = False

    if has_hardware and not iommu_enabled:
        # Hardware present but not enabled - CRITICAL
        issues.append({
            'severity': 'CRITICAL',
            'message': (
                f"IOMMU hardware detected ({hardware_type}) but not enabled in kernel. "
                "Add intel_iommu=on or amd_iommu=on to kernel cmdline."
            ),
        })
        has_critical = True
    elif not has_hardware and not iommu_enabled:
        # No hardware at all - INFO
        issues.append({
            'severity': 'INFO',
            'message': 'No IOMMU hardware detected (no DMAR or IVRS ACPI table)',
        })

    # Check for mixed device groups (only if IOMMU is active)
    if iommu_enabled:
        mixed_issues = check_mixed_groups(iommu_groups)
        issues.extend(mixed_issues)

    # Build output data
    data: dict[str, Any] = {
        'iommu_enabled': iommu_enabled,
        'hardware_type': hardware_type,
        'has_dmar': has_dmar,
        'has_ivrs': has_ivrs,
        'iommu_instance_count': len(iommu_instances),
        'iommu_group_count': len(iommu_groups),
        'cmdline_params': cmdline_info['params_found'],
        'issues': issues,
    }

    if opts.verbose:
        data['iommu_instances'] = [p.split('/')[-1] for p in iommu_instances]
        data['iommu_groups'] = iommu_groups
        data['cmdline_detail'] = {
            'intel_iommu': cmdline_info['intel_iommu'],
            'amd_iommu': cmdline_info['amd_iommu'],
            'iommu': cmdline_info['iommu'],
        }

    output.emit(data)

    # Generate summary
    if has_critical:
        output.set_summary("IOMMU hardware present but not enabled")
    elif iommu_enabled:
        output.set_summary(
            f"IOMMU enabled ({hardware_type}), "
            f"{len(iommu_groups)} groups"
        )
    else:
        output.set_summary("No IOMMU hardware detected")

    output.render(opts.format, "IOMMU/DMA Remapping Status")

    return 1 if has_critical else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
