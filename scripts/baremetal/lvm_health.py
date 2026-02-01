#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, storage, lvm, volume]
#   requires: [lvs]
#   privilege: root
#   related: [disk_health, disk_io_latency]
#   brief: Monitor LVM logical volumes, volume groups, and physical volumes

"""
Monitor LVM (Logical Volume Manager) health and configuration.

Checks LVM logical volumes, volume groups, and physical volumes for:
- Thin pool near-exhaustion before writes fail
- Aging or full snapshots consuming space
- Volume groups near capacity
- Physical volume health and missing PVs
- LVM configuration issues

Returns exit code 1 if any issues are detected.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_percent(value: str) -> float | None:
    """Parse percentage value from LVM output."""
    if not value or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def parse_size(value: str) -> int | None:
    """Parse size value from LVM output (in bytes format)."""
    if not value:
        return None
    value = value.strip()
    if value.endswith("B"):
        value = value[:-1]
    if value.endswith("b"):
        value = value[:-1]
    if value.endswith("g"):
        # Handle gibibytes (multiply by 1024^3)
        try:
            return int(float(value[:-1]) * 1024 * 1024 * 1024)
        except ValueError:
            return None
    try:
        return int(float(value))
    except ValueError:
        return None


def parse_lv_type(attr: str) -> str:
    """Parse LV type from attribute string."""
    if not attr or len(attr) < 1:
        return "unknown"

    type_char = attr[0]
    types = {
        "-": "standard",
        "C": "cache",
        "m": "mirror",
        "M": "mirror_log",
        "o": "origin",
        "O": "origin_merging",
        "r": "raid",
        "R": "raid_metadata",
        "s": "snapshot",
        "S": "snapshot_merging",
        "p": "pvmove",
        "v": "virtual",
        "V": "thin_volume",
        "t": "thin_pool",
        "T": "thin_pool_data",
        "e": "raid_metadata",
    }

    return types.get(type_char, "unknown")


def get_logical_volumes(context: Context) -> list[dict[str, Any]] | None:
    """Get logical volume information using lvs."""
    cmd = [
        "lvs", "--noheadings", "--separator", "|",
        "-o", "lv_name,vg_name,lv_size,data_percent,metadata_percent,"
              "lv_attr,origin,snap_percent,pool_lv,lv_time",
        "--units", "b"
    ]

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return None

    lvs = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 10:
            continue

        lv = {
            "name": parts[0],
            "vg": parts[1],
            "size": parts[2],
            "data_percent": parse_percent(parts[3]),
            "metadata_percent": parse_percent(parts[4]),
            "attr": parts[5],
            "origin": parts[6] if parts[6] else None,
            "snap_percent": parse_percent(parts[7]),
            "pool_lv": parts[8] if parts[8] else None,
            "time": parts[9] if parts[9] else None,
        }

        lv["type"] = parse_lv_type(lv["attr"])
        lvs.append(lv)

    return lvs


def get_volume_groups(context: Context) -> list[dict[str, Any]] | None:
    """Get volume group information using vgs."""
    cmd = [
        "vgs", "--noheadings", "--separator", "|",
        "-o", "vg_name,vg_size,vg_free,pv_count,lv_count,vg_attr",
        "--units", "b"
    ]

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return None

    vgs = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 6:
            continue

        size_bytes = parse_size(parts[1])
        free_bytes = parse_size(parts[2])
        used_bytes = size_bytes - free_bytes if size_bytes and free_bytes else 0

        vg = {
            "name": parts[0],
            "size": parts[1],
            "size_bytes": size_bytes,
            "free": parts[2],
            "free_bytes": free_bytes,
            "used_bytes": used_bytes,
            "used_percent": (used_bytes / size_bytes * 100) if size_bytes else 0,
            "pv_count": int(parts[3]) if parts[3].isdigit() else 0,
            "lv_count": int(parts[4]) if parts[4].isdigit() else 0,
            "attr": parts[5],
        }

        vgs.append(vg)

    return vgs


def get_physical_volumes(context: Context) -> list[dict[str, Any]] | None:
    """Get physical volume information using pvs."""
    cmd = [
        "pvs", "--noheadings", "--separator", "|",
        "-o", "pv_name,vg_name,pv_size,pv_free,pv_attr",
        "--units", "b"
    ]

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return None

    pvs = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue

        size_bytes = parse_size(parts[2])
        free_bytes = parse_size(parts[3])
        used_bytes = size_bytes - free_bytes if size_bytes and free_bytes else 0

        pv = {
            "name": parts[0],
            "vg": parts[1] if parts[1] else None,
            "size": parts[2],
            "size_bytes": size_bytes,
            "free": parts[3],
            "free_bytes": free_bytes,
            "used_bytes": used_bytes,
            "used_percent": (used_bytes / size_bytes * 100) if size_bytes else 0,
            "attr": parts[4],
        }

        pvs.append(pv)

    return pvs


def analyze_logical_volumes(
    lvs: list[dict[str, Any]],
    thin_warn: float,
    thin_crit: float
) -> list[dict[str, Any]]:
    """Analyze logical volumes for issues."""
    issues = []

    for lv in lvs:
        lv_id = f"{lv['vg']}/{lv['name']}"

        # Check thin pool usage
        if lv["type"] == "thin_pool" and lv["data_percent"] is not None:
            if lv["data_percent"] >= thin_crit:
                issues.append({
                    "severity": "CRITICAL",
                    "component": "thin_pool",
                    "name": lv_id,
                    "metric": "data_percent",
                    "value": lv["data_percent"],
                    "threshold": thin_crit,
                    "message": f"Thin pool {lv_id} critically full: "
                               f"{lv['data_percent']:.1f}% data used"
                })
            elif lv["data_percent"] >= thin_warn:
                issues.append({
                    "severity": "WARNING",
                    "component": "thin_pool",
                    "name": lv_id,
                    "metric": "data_percent",
                    "value": lv["data_percent"],
                    "threshold": thin_warn,
                    "message": f"Thin pool {lv_id} running low: "
                               f"{lv['data_percent']:.1f}% data used"
                })

            # Also check metadata usage
            if lv["metadata_percent"] is not None and lv["metadata_percent"] >= thin_warn:
                severity = "CRITICAL" if lv["metadata_percent"] >= thin_crit else "WARNING"
                issues.append({
                    "severity": severity,
                    "component": "thin_pool",
                    "name": lv_id,
                    "metric": "metadata_percent",
                    "value": lv["metadata_percent"],
                    "threshold": thin_warn,
                    "message": f"Thin pool {lv_id} metadata usage: "
                               f"{lv['metadata_percent']:.1f}%"
                })

        # Check snapshot usage
        if lv["type"] == "snapshot" and lv["snap_percent"] is not None:
            if lv["snap_percent"] >= 100:
                issues.append({
                    "severity": "CRITICAL",
                    "component": "snapshot",
                    "name": lv_id,
                    "metric": "snap_percent",
                    "value": lv["snap_percent"],
                    "message": f"Snapshot {lv_id} is FULL (100%) - "
                               f"snapshot is now invalid!"
                })
            elif lv["snap_percent"] >= thin_crit:
                issues.append({
                    "severity": "CRITICAL",
                    "component": "snapshot",
                    "name": lv_id,
                    "metric": "snap_percent",
                    "value": lv["snap_percent"],
                    "threshold": thin_crit,
                    "message": f"Snapshot {lv_id} nearly full: "
                               f"{lv['snap_percent']:.1f}%"
                })
            elif lv["snap_percent"] >= thin_warn:
                issues.append({
                    "severity": "WARNING",
                    "component": "snapshot",
                    "name": lv_id,
                    "metric": "snap_percent",
                    "value": lv["snap_percent"],
                    "threshold": thin_warn,
                    "message": f"Snapshot {lv_id} filling up: "
                               f"{lv['snap_percent']:.1f}%"
                })

    return issues


def analyze_volume_groups(
    vgs: list[dict[str, Any]],
    vg_warn: float,
    vg_crit: float
) -> list[dict[str, Any]]:
    """Analyze volume groups for capacity issues."""
    issues = []

    for vg in vgs:
        if vg["used_percent"] >= vg_crit:
            issues.append({
                "severity": "CRITICAL",
                "component": "volume_group",
                "name": vg["name"],
                "metric": "used_percent",
                "value": vg["used_percent"],
                "threshold": vg_crit,
                "message": f"Volume group {vg['name']} critically full: "
                           f"{vg['used_percent']:.1f}% used"
            })
        elif vg["used_percent"] >= vg_warn:
            issues.append({
                "severity": "WARNING",
                "component": "volume_group",
                "name": vg["name"],
                "metric": "used_percent",
                "value": vg["used_percent"],
                "threshold": vg_warn,
                "message": f"Volume group {vg['name']} running low: "
                           f"{vg['used_percent']:.1f}% used"
            })

    return issues


def analyze_physical_volumes(pvs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analyze physical volumes for issues."""
    issues = []

    for pv in pvs:
        # Check for orphan PVs (not in any VG)
        if not pv["vg"]:
            issues.append({
                "severity": "INFO",
                "component": "physical_volume",
                "name": pv["name"],
                "metric": "orphan",
                "value": True,
                "message": f"Physical volume {pv['name']} is not in any volume group"
            })

        # Check PV attributes for issues
        if pv["attr"] and len(pv["attr"]) >= 3:
            # Position 2 is 'm' for missing
            if pv["attr"][2] == "m":
                issues.append({
                    "severity": "CRITICAL",
                    "component": "physical_volume",
                    "name": pv["name"],
                    "metric": "missing",
                    "value": True,
                    "message": f"Physical volume {pv['name']} is MISSING!"
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
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor LVM logical volumes, volume groups, and physical volumes"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed LVM information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--thin-warn", type=float, default=80.0, metavar="PCT",
                        help="Warning threshold for thin pool usage (default: 80%%)")
    parser.add_argument("--thin-crit", type=float, default=90.0, metavar="PCT",
                        help="Critical threshold for thin pool usage (default: 90%%)")
    parser.add_argument("--vg-warn", type=float, default=85.0, metavar="PCT",
                        help="Warning threshold for volume group usage (default: 85%%)")
    parser.add_argument("--vg-crit", type=float, default=95.0, metavar="PCT",
                        help="Critical threshold for volume group usage (default: 95%%)")
    opts = parser.parse_args(args)

    # Check for LVM tools
    if not context.check_tool("lvs"):
        output.error("LVM tools not found (lvs). Install lvm2 package.")
        return 2

    # Gather LVM information
    lvs = get_logical_volumes(context)
    vgs = get_volume_groups(context)
    pvs = get_physical_volumes(context)

    # Check if any LVM is configured
    if not vgs and not lvs and not pvs:
        output.emit({"message": "No LVM configuration found", "issues": []})
        output.set_summary("No LVM configured")
        return 0

    # Analyze for issues
    issues: list[dict[str, Any]] = []
    if lvs:
        issues.extend(analyze_logical_volumes(lvs, opts.thin_warn, opts.thin_crit))
    if vgs:
        issues.extend(analyze_volume_groups(vgs, opts.vg_warn, opts.vg_crit))
    if pvs:
        issues.extend(analyze_physical_volumes(pvs))

    # Build output data
    data: dict[str, Any] = {
        "summary": {
            "volume_groups": len(vgs) if vgs else 0,
            "logical_volumes": len(lvs) if lvs else 0,
            "physical_volumes": len(pvs) if pvs else 0,
        },
        "issues": issues,
    }

    if opts.verbose:
        data["volume_groups"] = vgs or []
        data["logical_volumes"] = lvs or []
        data["physical_volumes"] = pvs or []

    output.emit(data)

    # Set summary
    critical_count = sum(1 for i in issues if i["severity"] == "CRITICAL")
    warning_count = sum(1 for i in issues if i["severity"] == "WARNING")
    if critical_count > 0:
        output.set_summary(f"{critical_count} critical, {warning_count} warnings")
    elif warning_count > 0:
        output.set_summary(f"{warning_count} warnings")
    else:
        output.set_summary("All LVM components healthy")

    # Determine exit code based on issues
    has_critical = any(issue["severity"] == "CRITICAL" for issue in issues)
    has_warning = any(issue["severity"] == "WARNING" for issue in issues)

    if has_critical or has_warning:
        return 1
    else:
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
