#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, raid, storage, hardware, mdadm]
#   requires: []
#   privilege: root
#   related: [disk_health, nvme_health, lvm_health]
#   brief: Check status of hardware and software RAID arrays

"""
Check status of hardware and software RAID arrays.

Monitors software RAID (mdadm) and hardware RAID (MegaCli for LSI/Broadcom,
hpacucli/ssacli for HP) arrays. Detects degraded arrays, rebuilding status,
and failed drives.

Returns exit code 1 if any array is degraded or rebuilding.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_software_raid_status(context: Context) -> list[dict[str, Any]]:
    """Get status of software RAID arrays (mdadm)."""
    if not context.file_exists("/proc/mdstat"):
        return []

    try:
        mdstat = context.read_file("/proc/mdstat")
    except Exception:
        return []

    arrays = []
    current_array = None

    for line in mdstat.split('\n'):
        # Match array line (e.g., "md0 : active raid1 sda1[0] sdb1[1]")
        array_match = re.match(r'^(md\d+)\s*:\s*(\w+)\s+(\w+)\s+(.+)$', line)
        if array_match:
            if current_array:
                arrays.append(current_array)

            array_name = array_match.group(1)
            state = array_match.group(2)
            raid_level = array_match.group(3)
            devices = array_match.group(4)

            current_array = {
                'name': array_name,
                'type': 'software',
                'state': state,
                'level': raid_level,
                'devices': devices.strip(),
                'status': 'healthy' if state == 'active' else 'degraded',
                'progress': None
            }

        # Match progress line (e.g., "[==>..................]  recovery = 13.0%")
        elif current_array and '[' in line and ']' in line:
            progress_match = re.search(r'(\w+)\s*=\s*([\d.]+)%', line)
            if progress_match:
                operation = progress_match.group(1)
                percentage = progress_match.group(2)
                current_array['progress'] = f"{operation}: {percentage}%"
                current_array['status'] = 'rebuilding'

    if current_array:
        arrays.append(current_array)

    return arrays


def get_megacli_raid_status(context: Context) -> list[dict[str, Any]]:
    """Get status of LSI/Broadcom hardware RAID."""
    # Try different MegaCli command names
    megacli_cmd = None
    for cmd_name in ['megacli', 'MegaCli', 'MegaCli64']:
        if context.check_tool(cmd_name):
            megacli_cmd = cmd_name
            break

    if not megacli_cmd:
        return []

    arrays = []

    # Get adapter count
    try:
        result = context.run([megacli_cmd, '-adpCount', '-NoLog'], check=False)
        if result.returncode != 0:
            return []
    except Exception:
        return []

    adapter_match = re.search(r'Controller Count:\s*(\d+)', result.stdout)
    if not adapter_match:
        return []

    adapter_count = int(adapter_match.group(1))

    for adapter_id in range(adapter_count):
        # Get virtual drive info
        try:
            result = context.run(
                [megacli_cmd, '-LDInfo', '-Lall', f'-a{adapter_id}', '-NoLog'],
                check=False
            )
            if result.returncode != 0:
                continue
        except Exception:
            continue

        # Parse virtual drives
        ld_pattern = r'Virtual Drive:\s*(\d+).*?RAID Level\s*:\s*Primary-(\d+).*?State\s*:\s*(\w+)'
        matches = re.finditer(ld_pattern, result.stdout, re.DOTALL)

        for match in matches:
            vd_id = match.group(1)
            raid_level = match.group(2)
            state = match.group(3)

            arrays.append({
                'name': f"Adapter{adapter_id}_VD{vd_id}",
                'type': 'hardware-lsi',
                'level': f"RAID{raid_level}",
                'state': state,
                'status': 'healthy' if state == 'Optimal' else 'degraded',
                'devices': 'N/A'
            })

    return arrays


def get_hp_raid_status(context: Context) -> list[dict[str, Any]]:
    """Get status of HP hardware RAID."""
    # Try different HP CLI command names
    hp_cmd = None
    for cmd_name in ['hpacucli', 'ssacli', 'hpssacli']:
        if context.check_tool(cmd_name):
            hp_cmd = cmd_name
            break

    if not hp_cmd:
        return []

    arrays = []

    # Get controller info
    try:
        result = context.run([hp_cmd, 'ctrl', 'all', 'show', 'config'], check=False)
        if result.returncode != 0:
            return []
    except Exception:
        return []

    # Parse output for logical drives
    current_controller = None
    for line in result.stdout.split('\n'):
        ctrl_match = re.search(r'Smart Array (\w+)', line)
        if ctrl_match:
            current_controller = ctrl_match.group(1)

        ld_match = re.search(
            r'logicaldrive\s+(\d+)\s+\(([\d.]+\s+\w+),\s+(\w+),\s+(\w+)\)',
            line
        )
        if ld_match and current_controller:
            ld_id = ld_match.group(1)
            size = ld_match.group(2)
            raid_level = ld_match.group(3)
            status = ld_match.group(4)

            arrays.append({
                'name': f"{current_controller}_LD{ld_id}",
                'type': 'hardware-hp',
                'level': raid_level,
                'state': status,
                'status': 'healthy' if status == 'OK' else 'degraded',
                'devices': size
            })

    return arrays


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
        description="Check status of hardware and software RAID arrays"
    )
    parser.add_argument(
        "-t", "--type",
        choices=["all", "software", "hardware"],
        default="all",
        help="Type of RAID to check (default: all)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="Only show arrays with warnings or failures"
    )

    opts = parser.parse_args(args)

    all_arrays = []

    # Check software RAID
    if opts.type in ["all", "software"]:
        sw_arrays = get_software_raid_status(context)
        all_arrays.extend(sw_arrays)

    # Check hardware RAID
    if opts.type in ["all", "hardware"]:
        # Try MegaCli (LSI/Broadcom)
        mega_arrays = get_megacli_raid_status(context)
        all_arrays.extend(mega_arrays)

        # Try HP RAID
        hp_arrays = get_hp_raid_status(context)
        all_arrays.extend(hp_arrays)

    if not all_arrays:
        output.warning("No RAID arrays detected")
        output.emit({"arrays": []})

        output.render(opts.format, "Check status of hardware and software RAID arrays")
        return 0

    # Filter arrays if warn-only mode
    if opts.warn_only:
        all_arrays = [a for a in all_arrays if a['status'] != 'healthy']

    # Remove extra fields in non-verbose mode
    if not opts.verbose:
        for array in all_arrays:
            array.pop('devices', None)
            array.pop('progress', None)

    output.emit({"arrays": all_arrays})

    # Set summary
    healthy = sum(1 for a in all_arrays if a['status'] == 'healthy')
    degraded = sum(1 for a in all_arrays if a['status'] == 'degraded')
    rebuilding = sum(1 for a in all_arrays if a['status'] == 'rebuilding')
    output.set_summary(f"{healthy} healthy, {degraded} degraded, {rebuilding} rebuilding")

    # Exit with error if any array is not healthy
    has_issues = any(a['status'] != 'healthy' for a in all_arrays)

    output.render(opts.format, "Check status of hardware and software RAID arrays")
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
