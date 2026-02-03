#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, zfs, filesystem, storage, pool]
#   requires: [zpool]
#   privilege: root
#   related: [btrfs_health, disk_health, inode_usage]
#   brief: Monitor ZFS pool health and configuration

"""
Monitor ZFS pool health and configuration.

Monitors ZFS storage pools for health issues including:
- Pool state (ONLINE, DEGRADED, FAULTED)
- Capacity and fragmentation
- Device errors (read, write, checksum)
- Scrub status and age

Returns exit code 0 if healthy, 1 if issues found, 2 on error.
"""

import argparse
import re
from datetime import datetime
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_pool_list(context: Context) -> list[str]:
    """Get list of ZFS pools."""
    result = context.run(["zpool", "list", "-H", "-o", "name"])
    pools = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
    return pools


def get_pool_properties(pool_name: str, context: Context) -> dict[str, Any]:
    """Get pool properties using zpool list."""
    result = context.run([
        "zpool", "list", "-H", "-p",
        "-o", "name,size,alloc,free,frag,cap,health,altroot",
        pool_name
    ], check=False)

    parts = result.stdout.strip().split("\t")
    if len(parts) < 7:
        return {"name": pool_name, "health": "UNKNOWN"}

    return {
        "name": parts[0],
        "size_bytes": int(parts[1]) if parts[1].isdigit() else 0,
        "alloc_bytes": int(parts[2]) if parts[2].isdigit() else 0,
        "free_bytes": int(parts[3]) if parts[3].isdigit() else 0,
        "fragmentation": int(parts[4]) if parts[4].isdigit() else 0,
        "capacity": int(parts[5]) if parts[5].isdigit() else 0,
        "health": parts[6],
        "altroot": parts[7] if len(parts) > 7 and parts[7] != "-" else None,
    }


def get_pool_status(pool_name: str, context: Context) -> dict[str, Any]:
    """Get detailed pool status including device state."""
    result = context.run(["zpool", "status", "-v", pool_name], check=False)

    status = {
        "name": pool_name,
        "state": None,
        "scan": None,
        "scrub_age_days": None,
        "devices": [],
        "errors": None,
        "status_message": None,
    }

    lines = result.stdout.split("\n")

    for line in lines:
        line_stripped = line.strip()

        # Parse state
        if line_stripped.startswith("state:"):
            status["state"] = line_stripped.split(":", 1)[1].strip()

        # Parse status message
        elif line_stripped.startswith("status:"):
            status["status_message"] = line_stripped.split(":", 1)[1].strip()

        # Parse scan/scrub information
        elif line_stripped.startswith("scan:"):
            status["scan"] = line_stripped.split(":", 1)[1].strip()
            status["scrub_age_days"] = parse_scrub_age(status["scan"])

        # Parse errors
        elif line_stripped.startswith("errors:"):
            status["errors"] = line_stripped.split(":", 1)[1].strip()

        # Parse device lines (indented under config section)
        elif line.startswith("\t") and not line_stripped.startswith("NAME"):
            device = parse_device_line(line)
            if device:
                status["devices"].append(device)

    return status


def parse_scrub_age(scan_line: str) -> int | None:
    """Parse scrub age from scan status line."""
    if not scan_line:
        return None

    if "scrub in progress" in scan_line.lower():
        return 0  # Scrub currently running

    if "none requested" in scan_line.lower():
        return None  # Never scrubbed

    # Try to parse date from common formats
    date_patterns = [
        r"on\s+\w+\s+(\w+)\s+(\d+)\s+[\d:]+\s+(\d{4})",  # on Day Mon DD HH:MM:SS YYYY
        r"(\w+)\s+(\d+),?\s+(\d{4})",  # Mon DD, YYYY
    ]

    for pattern in date_patterns:
        match = re.search(pattern, scan_line)
        if match:
            try:
                month_str = match.group(1)
                day = int(match.group(2))
                year = int(match.group(3))

                months = {
                    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
                    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
                    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
                }
                month = months.get(month_str[:3])
                if month:
                    scrub_date = datetime(year, month, day)
                    age = (datetime.now() - scrub_date).days
                    return max(0, age)
            except (ValueError, KeyError):
                pass

    return None


def parse_device_line(line: str) -> dict[str, Any] | None:
    """Parse a device line from zpool status output."""
    parts = line.split()

    if len(parts) < 2:
        return None

    # Skip header and pool-level lines
    if parts[0] in ["NAME", "STATE", "READ", "WRITE", "CKSUM"]:
        return None

    device = {
        "name": parts[0],
        "state": parts[1] if len(parts) > 1 else "UNKNOWN",
        "read_errors": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
        "write_errors": int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0,
        "checksum_errors": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
        "is_vdev": parts[0].startswith(("mirror", "raidz", "spare", "log", "cache")),
    }

    device["total_errors"] = (
        device["read_errors"] + device["write_errors"] + device["checksum_errors"]
    )

    return device


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human readable format."""
    if bytes_val == 0:
        return "0 B"
    if bytes_val >= 1024**4:
        return f"{bytes_val / (1024**4):.1f} TiB"
    elif bytes_val >= 1024**3:
        return f"{bytes_val / (1024**3):.1f} GiB"
    elif bytes_val >= 1024**2:
        return f"{bytes_val / (1024**2):.1f} MiB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KiB"
    else:
        return f"{bytes_val} B"


def analyze_pools(
    pools_data: list[dict[str, Any]],
    capacity_warn: int,
    capacity_crit: int,
    frag_warn: int,
    scrub_warn_days: int,
    error_threshold: int,
) -> list[dict[str, Any]]:
    """Analyze pools for health issues."""
    issues = []

    for pool in pools_data:
        props = pool["properties"]
        status = pool["status"]
        pool_name = props["name"]

        # Check pool health state
        if props["health"] not in ["ONLINE", "DEGRADED"]:
            issues.append({
                "severity": "CRITICAL",
                "component": "pool",
                "pool": pool_name,
                "metric": "health",
                "value": props["health"],
                "message": f"Pool {pool_name} is {props['health']}",
            })
        elif props["health"] == "DEGRADED":
            issues.append({
                "severity": "CRITICAL",
                "component": "pool",
                "pool": pool_name,
                "metric": "health",
                "value": "DEGRADED",
                "message": f"Pool {pool_name} is DEGRADED - redundancy compromised",
            })

        # Check capacity
        if props["capacity"] >= capacity_crit:
            issues.append({
                "severity": "CRITICAL",
                "component": "pool",
                "pool": pool_name,
                "metric": "capacity",
                "value": props["capacity"],
                "threshold": capacity_crit,
                "message": f"Pool {pool_name} critically full: {props['capacity']}% used",
            })
        elif props["capacity"] >= capacity_warn:
            issues.append({
                "severity": "WARNING",
                "component": "pool",
                "pool": pool_name,
                "metric": "capacity",
                "value": props["capacity"],
                "threshold": capacity_warn,
                "message": f"Pool {pool_name} running low: {props['capacity']}% used",
            })

        # Check fragmentation
        if props["fragmentation"] >= frag_warn:
            issues.append({
                "severity": "WARNING",
                "component": "pool",
                "pool": pool_name,
                "metric": "fragmentation",
                "value": props["fragmentation"],
                "threshold": frag_warn,
                "message": f"Pool {pool_name} fragmentation high: {props['fragmentation']}%",
            })

        # Check scrub age
        if status and status["scrub_age_days"] is not None:
            if status["scrub_age_days"] >= scrub_warn_days:
                issues.append({
                    "severity": "WARNING",
                    "component": "pool",
                    "pool": pool_name,
                    "metric": "scrub_age_days",
                    "value": status["scrub_age_days"],
                    "threshold": scrub_warn_days,
                    "message": f"Pool {pool_name} not scrubbed for {status['scrub_age_days']} days",
                })
        elif status and "none requested" in (status["scan"] or "").lower():
            issues.append({
                "severity": "WARNING",
                "component": "pool",
                "pool": pool_name,
                "metric": "scrub_age_days",
                "value": None,
                "message": f"Pool {pool_name} has never been scrubbed",
            })

        # Check device states and errors
        if status and status["devices"]:
            for device in status["devices"]:
                # Skip vdev entries
                if device["is_vdev"]:
                    continue

                # Check device state
                if device["state"] not in ["ONLINE", "AVAIL"]:
                    severity = "CRITICAL" if device["state"] in ["FAULTED", "OFFLINE", "REMOVED"] else "WARNING"
                    issues.append({
                        "severity": severity,
                        "component": "device",
                        "pool": pool_name,
                        "device": device["name"],
                        "metric": "state",
                        "value": device["state"],
                        "message": f"Device {device['name']} in pool {pool_name} is {device['state']}",
                    })

                # Check device errors
                if device["total_errors"] >= error_threshold:
                    severity = "CRITICAL" if device["total_errors"] >= error_threshold * 10 else "WARNING"
                    issues.append({
                        "severity": severity,
                        "component": "device",
                        "pool": pool_name,
                        "device": device["name"],
                        "metric": "errors",
                        "value": device["total_errors"],
                        "threshold": error_threshold,
                        "message": f"Device {device['name']} in {pool_name} has {device['total_errors']} errors",
                    })

        # Check pool errors
        if status and status["errors"] and status["errors"].lower() != "no known data errors":
            issues.append({
                "severity": "CRITICAL",
                "component": "pool",
                "pool": pool_name,
                "metric": "data_errors",
                "value": status["errors"],
                "message": f"Pool {pool_name} has data errors: {status['errors']}",
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
    parser = argparse.ArgumentParser(description="Monitor ZFS pool health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument(
        "--capacity-warn", type=int, default=80,
        help="Warning threshold for capacity (default: 80%%)"
    )
    parser.add_argument(
        "--capacity-crit", type=int, default=90,
        help="Critical threshold for capacity (default: 90%%)"
    )
    parser.add_argument(
        "--frag-warn", type=int, default=50,
        help="Warning threshold for fragmentation (default: 50%%)"
    )
    parser.add_argument(
        "--scrub-warn", type=int, default=14,
        help="Warning threshold for days since last scrub (default: 14)"
    )
    parser.add_argument(
        "--error-threshold", type=int, default=1,
        help="Device error count threshold (default: 1)"
    )
    opts = parser.parse_args(args)

    # Check for zpool tool
    if not context.check_tool("zpool"):
        output.error("zpool not found. Install zfsutils-linux package.")

        output.render(opts.format, "Monitor ZFS pool health and configuration")
        return 2

    # Get pool list
    try:
        pools = get_pool_list(context)
    except Exception as e:
        output.error(f"Failed to list ZFS pools: {e}")

        output.render(opts.format, "Monitor ZFS pool health and configuration")
        return 2

    if not pools:
        output.emit({"pools": [], "issues": []})
        output.set_summary("No ZFS pools found")

        output.render(opts.format, "Monitor ZFS pool health and configuration")
        return 0

    # Gather pool data
    pools_data = []
    for pool_name in pools:
        props = get_pool_properties(pool_name, context)
        status = get_pool_status(pool_name, context)

        pools_data.append({
            "properties": props,
            "status": status,
        })

    # Analyze for issues
    issues = analyze_pools(
        pools_data,
        opts.capacity_warn,
        opts.capacity_crit,
        opts.frag_warn,
        opts.scrub_warn,
        opts.error_threshold,
    )

    # Emit data
    if opts.verbose:
        output.emit({"pools": pools_data, "issues": issues})
    else:
        # Simplified output
        summary = []
        for pool in pools_data:
            props = pool["properties"]
            summary.append({
                "name": props["name"],
                "health": props["health"],
                "capacity": props["capacity"],
            })
        output.emit({"pools": summary, "issues": issues})

    # Set summary
    healthy = sum(1 for p in pools_data if p["properties"]["health"] == "ONLINE")
    output.set_summary(f"{len(pools_data)} pools, {healthy} healthy, {len(issues)} issues")

    # Log warnings/errors
    for issue in issues:
        if issue["severity"] == "CRITICAL":
            output.error(issue["message"])
        else:
            output.warning(issue["message"])

    # Return exit code
    if any(i["severity"] == "CRITICAL" for i in issues):

        output.render(opts.format, "Monitor ZFS pool health and configuration")
        return 1
    elif issues:

        output.render(opts.format, "Monitor ZFS pool health and configuration")
        return 1
    else:

        output.render(opts.format, "Monitor ZFS pool health and configuration")
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
