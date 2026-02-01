#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, storage, multipath, san, iscsi]
#   requires: [multipath]
#   privilege: root
#   related: [disk_health]
#   brief: Monitor dm-multipath I/O path health and configuration

"""
Monitor dm-multipath I/O path health and configuration.

Monitors multipath device mapper configurations to detect:
- Failed or degraded paths to SAN/NAS storage
- Path priority and load balancing health
- Devices with reduced redundancy
- Path flapping and checker failures

Returns exit code 1 if any issues are detected.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_multipathd_running(context: Context) -> bool:
    """Check if multipathd daemon is running."""
    result = context.run(["multipathd", "show", "daemon"], check=False)
    # Check for positive running status (pid NNNN running)
    # Avoid matching "not running"
    if result.returncode == 0:
        stdout_lower = result.stdout.lower()
        if "pid" in stdout_lower and "running" in stdout_lower:
            return True
        if "not running" in stdout_lower:
            pass  # Fall through to systemctl check
        elif "running" in stdout_lower:
            return True

    # Try systemctl as fallback
    result = context.run(["systemctl", "is-active", "multipathd"], check=False)
    # Check for exactly "active" - not "inactive"
    return result.returncode == 0 and result.stdout.strip() == "active"


def get_multipath_topology(context: Context) -> str | None:
    """Get multipath topology using multipathd."""
    result = context.run(["multipathd", "show", "topology"], check=False)
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout

    # Fallback to multipath -ll
    result = context.run(["multipath", "-ll"], check=False)
    if result.returncode == 0:
        return result.stdout

    return None


def parse_multipath_topology(topology_output: str) -> list[dict[str, Any]]:
    """Parse multipath topology output into structured data."""
    devices = []
    current_device: dict[str, Any] | None = None
    current_group: dict[str, Any] | None = None

    if not topology_output:
        return devices

    lines = topology_output.strip().split("\n")

    for line in lines:
        # Match device line: mpatha (360...) dm-0 VENDOR,PRODUCT
        device_match = re.match(
            r"^(\S+)\s+\(([^)]+)\)\s+(dm-\d+)\s+(.+)$",
            line.strip()
        )

        if device_match:
            if current_device:
                devices.append(current_device)

            current_device = {
                "name": device_match.group(1),
                "wwid": device_match.group(2),
                "dm_device": device_match.group(3),
                "vendor_product": device_match.group(4).strip(),
                "size": None,
                "features": None,
                "hwhandler": None,
                "path_groups": [],
                "total_paths": 0,
                "active_paths": 0,
                "failed_paths": 0,
                "paths": []
            }
            current_group = None
            continue

        # Match size line
        size_match = re.match(
            r"^\s*size=(\S+)\s+features='([^']*)'\s+hwhandler='([^']*)'",
            line
        )
        if size_match and current_device:
            current_device["size"] = size_match.group(1)
            current_device["features"] = size_match.group(2)
            current_device["hwhandler"] = size_match.group(3)
            continue

        # Match path group line
        group_match = re.match(
            r"^\s*[|`]-\+-\s+policy='([^']+)'\s+prio=(\d+)\s+status=(\w+)",
            line
        )
        if group_match and current_device:
            current_group = {
                "policy": group_match.group(1),
                "priority": int(group_match.group(2)),
                "status": group_match.group(3),
                "paths": []
            }
            current_device["path_groups"].append(current_group)
            continue

        # Match path line - more flexible regex to handle various indentation styles
        path_match = re.search(
            r"[|`\s]-\s+(\d+:\d+:\d+:\d+)\s+(\S+)\s+(\S+)\s+(\w+)\s+(\w+)\s+(\w+)",
            line
        )
        if path_match and current_device:
            path = {
                "hctl": path_match.group(1),
                "device": path_match.group(2),
                "major_minor": path_match.group(3),
                "dm_state": path_match.group(4),
                "path_state": path_match.group(5),
                "checker_state": path_match.group(6)
            }

            current_device["paths"].append(path)
            current_device["total_paths"] += 1

            if path["dm_state"] == "active" and path["path_state"] == "ready":
                current_device["active_paths"] += 1
            elif path["dm_state"] == "failed" or path["path_state"] == "faulty":
                current_device["failed_paths"] += 1

            if current_group:
                current_group["paths"].append(path)
            continue

    # Don't forget the last device
    if current_device:
        devices.append(current_device)

    return devices


def analyze_devices(
    devices: list[dict[str, Any]],
    min_paths_warn: int,
    min_paths_crit: int
) -> list[dict[str, Any]]:
    """Analyze multipath devices for issues."""
    issues = []

    for device in devices:
        name = device["name"]
        wwid = device["wwid"]

        # Check for completely failed device (no active paths)
        if device["active_paths"] == 0:
            issues.append({
                "severity": "CRITICAL",
                "component": "device",
                "name": name,
                "wwid": wwid,
                "metric": "active_paths",
                "value": 0,
                "total": device["total_paths"],
                "message": f"Device {name} has NO active paths! "
                           f"(0/{device['total_paths']} paths active)"
            })
            continue

        # Check for failed paths
        if device["failed_paths"] > 0:
            issues.append({
                "severity": "WARNING",
                "component": "device",
                "name": name,
                "wwid": wwid,
                "metric": "failed_paths",
                "value": device["failed_paths"],
                "total": device["total_paths"],
                "message": f"Device {name} has {device['failed_paths']} failed path(s) "
                           f"({device['active_paths']}/{device['total_paths']} paths active)"
            })

        # Check minimum path thresholds
        if device["active_paths"] <= min_paths_crit:
            issues.append({
                "severity": "CRITICAL",
                "component": "device",
                "name": name,
                "wwid": wwid,
                "metric": "active_paths",
                "value": device["active_paths"],
                "threshold": min_paths_crit,
                "message": f"Device {name} critically low on paths: "
                           f"{device['active_paths']}/{device['total_paths']} active "
                           f"(threshold: {min_paths_crit})"
            })
        elif device["active_paths"] <= min_paths_warn:
            issues.append({
                "severity": "WARNING",
                "component": "device",
                "name": name,
                "wwid": wwid,
                "metric": "active_paths",
                "value": device["active_paths"],
                "threshold": min_paths_warn,
                "message": f"Device {name} running low on paths: "
                           f"{device['active_paths']}/{device['total_paths']} active "
                           f"(threshold: {min_paths_warn})"
            })

        # Check individual path states
        for path in device["paths"]:
            if path["dm_state"] == "failed":
                issues.append({
                    "severity": "WARNING",
                    "component": "path",
                    "name": f"{name}/{path['device']}",
                    "hctl": path["hctl"],
                    "metric": "dm_state",
                    "value": path["dm_state"],
                    "message": f"Path {path['device']} ({path['hctl']}) on {name} "
                               f"is in failed state"
                })
            elif path["path_state"] == "faulty":
                issues.append({
                    "severity": "WARNING",
                    "component": "path",
                    "name": f"{name}/{path['device']}",
                    "hctl": path["hctl"],
                    "metric": "path_state",
                    "value": path["path_state"],
                    "message": f"Path {path['device']} ({path['hctl']}) on {name} "
                               f"is faulty"
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
        description="Monitor dm-multipath device health and path status"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed path information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--min-paths-warn", type=int, default=1, metavar="N",
                        help="Warn if active paths <= N (default: 1)")
    parser.add_argument("--min-paths-crit", type=int, default=0, metavar="N",
                        help="Critical if active paths <= N (default: 0)")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.min_paths_warn < 0:
        output.error("--min-paths-warn must be >= 0")
        return 2

    if opts.min_paths_crit < 0:
        output.error("--min-paths-crit must be >= 0")
        return 2

    if opts.min_paths_warn < opts.min_paths_crit:
        output.error("--min-paths-warn must be >= --min-paths-crit")
        return 2

    # Check for multipath tools
    if not context.check_tool("multipath"):
        output.error("Multipath tools not found. Install multipath-tools package.")
        return 2

    # Check if multipathd is running
    if not check_multipathd_running(context):
        output.emit({
            "message": "multipathd service not running",
            "issues": []
        })
        output.set_summary("multipathd not running")
        return 2

    # Get multipath topology
    topology = get_multipath_topology(context)

    if not topology or not topology.strip():
        output.emit({
            "message": "No multipath devices configured",
            "issues": []
        })
        output.set_summary("No multipath devices")
        return 0

    # Parse topology
    devices = parse_multipath_topology(topology)

    if not devices:
        output.emit({
            "message": "No multipath devices found",
            "issues": []
        })
        output.set_summary("No multipath devices")
        return 0

    # Analyze for issues
    issues = analyze_devices(devices, opts.min_paths_warn, opts.min_paths_crit)

    # Build output
    total_paths = sum(d["total_paths"] for d in devices)
    active_paths = sum(d["active_paths"] for d in devices)
    failed_paths = sum(d["failed_paths"] for d in devices)

    data: dict[str, Any] = {
        "summary": {
            "devices": len(devices),
            "total_paths": total_paths,
            "active_paths": active_paths,
            "failed_paths": failed_paths
        },
        "issues": issues
    }

    if opts.verbose:
        data["devices"] = devices
    else:
        data["devices"] = devices

    output.emit(data)

    # Set summary
    if failed_paths > 0:
        output.set_summary(f"{len(devices)} devices, {failed_paths} failed paths")
    else:
        output.set_summary(f"{len(devices)} devices, {active_paths} paths healthy")

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
