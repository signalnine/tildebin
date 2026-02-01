#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, hardware, thermal, cpu, throttling, performance]
#   brief: Monitor CPU thermal throttling events

"""
Monitor CPU thermal throttling events on baremetal systems.

Detects CPU thermal throttling by reading kernel throttle counters from
/sys/devices/system/cpu/cpu*/thermal_throttle/. Unlike temperature monitoring
which shows current temps, this script shows actual throttling events that
indicate performance degradation has occurred.

Useful for:
- Detecting datacenter cooling problems before they cause failures
- Identifying servers with degraded performance due to thermal issues
- Auditing thermal throttle history across a fleet
- Correlating performance issues with thermal events

Exit codes:
    0 - No throttling detected
    1 - Throttling detected (historical or current)
    2 - Usage error or missing dependencies
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


CPU_BASE = "/sys/devices/system/cpu"


def get_cpu_list(context: Context) -> list[int]:
    """Get list of CPU numbers in the system."""
    cpu_dirs = context.glob("cpu[0-9]*", root=CPU_BASE)
    cpus = []
    for path in cpu_dirs:
        name = path.split("/")[-1]
        if name.startswith("cpu") and name[3:].isdigit():
            cpus.append(int(name[3:]))
    return sorted(cpus)


def get_throttle_info(cpu_num: int, context: Context) -> dict[str, Any] | None:
    """
    Get thermal throttle information for a specific CPU.

    Returns dict with core and package throttle counts.
    """
    base_path = f"{CPU_BASE}/cpu{cpu_num}/thermal_throttle"

    if not context.file_exists(base_path):
        return None

    info = {
        "cpu": cpu_num,
        "core_throttle_count": 0,
        "package_throttle_count": 0,
        "core_throttle_total_time_ms": None,
        "package_throttle_total_time_ms": None,
    }

    # Read core throttle count
    try:
        core_count = context.read_file(f"{base_path}/core_throttle_count")
        info["core_throttle_count"] = int(core_count.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    # Read package throttle count
    try:
        pkg_count = context.read_file(f"{base_path}/package_throttle_count")
        info["package_throttle_count"] = int(pkg_count.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    # Read core throttle total time (may not exist on all systems)
    try:
        core_total = context.read_file(f"{base_path}/core_throttle_total_time_ms")
        info["core_throttle_total_time_ms"] = int(core_total.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    # Read package throttle total time
    try:
        pkg_total = context.read_file(f"{base_path}/package_throttle_total_time_ms")
        info["package_throttle_total_time_ms"] = int(pkg_total.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    return info


def analyze_throttle_data(cpu_data: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze throttle data and compute summary statistics.

    Returns a dict with totals and status.
    """
    summary = {
        "total_cpus": len(cpu_data),
        "total_core_throttles": 0,
        "total_package_throttles": 0,
        "max_core_throttle_count": 0,
        "max_package_throttle_count": 0,
        "affected_cpus": [],
        "cpus_with_throttles": 0,
        "total_throttle_time_ms": 0,
        "status": "OK",
    }

    for cpu in cpu_data:
        core_count = cpu.get("core_throttle_count", 0)
        pkg_count = cpu.get("package_throttle_count", 0)

        summary["total_core_throttles"] += core_count
        summary["total_package_throttles"] += pkg_count

        if core_count > summary["max_core_throttle_count"]:
            summary["max_core_throttle_count"] = core_count

        if pkg_count > summary["max_package_throttle_count"]:
            summary["max_package_throttle_count"] = pkg_count

        if core_count > 0 or pkg_count > 0:
            summary["affected_cpus"].append(cpu["cpu"])
            summary["cpus_with_throttles"] += 1

        # Add throttle time if available
        if cpu.get("core_throttle_total_time_ms"):
            summary["total_throttle_time_ms"] += cpu["core_throttle_total_time_ms"]
        if cpu.get("package_throttle_total_time_ms"):
            summary["total_throttle_time_ms"] += cpu["package_throttle_total_time_ms"]

    # Determine status
    if summary["total_core_throttles"] > 0 or summary["total_package_throttles"] > 0:
        summary["status"] = "WARNING"
        # Critical if significant throttling
        if summary["total_core_throttles"] > 100 or summary["total_package_throttles"] > 100:
            summary["status"] = "CRITICAL"

    return summary


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no throttling, 1 = throttling detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor CPU thermal throttling events"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show per-CPU details")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show CPUs with throttle events")
    parser.add_argument("--threshold", type=int, default=0,
                        help="Minimum throttle count to report as issue")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check if thermal throttle interface exists
    test_path = f"{CPU_BASE}/cpu0/thermal_throttle"
    if not context.file_exists(test_path):
        output.error(
            "Thermal throttle interface not available. "
            "Check if /sys/devices/system/cpu/cpu0/thermal_throttle exists."
        )
        return 2

    # Get CPU list
    cpu_nums = get_cpu_list(context)
    if not cpu_nums:
        output.error("Could not determine CPU count")
        return 2

    # Gather throttle info for all CPUs
    cpu_data = []
    for cpu_num in cpu_nums:
        info = get_throttle_info(cpu_num, context)
        if info:
            cpu_data.append(info)

    if not cpu_data:
        output.error("Could not read thermal throttle information")
        return 2

    # Analyze data
    summary = analyze_throttle_data(cpu_data)

    # Apply threshold filter
    if opts.threshold > 0:
        if (summary["total_core_throttles"] < opts.threshold and
                summary["total_package_throttles"] < opts.threshold):
            summary["status"] = "OK"

    # Filter if warn-only
    if opts.warn_only:
        cpu_data = [c for c in cpu_data
                    if c["core_throttle_count"] > 0 or c["package_throttle_count"] > 0]

    # Remove time fields if not verbose
    if not opts.verbose:
        for cpu in cpu_data:
            cpu.pop("core_throttle_total_time_ms", None)
            cpu.pop("package_throttle_total_time_ms", None)

    # Emit data
    output.emit({
        "summary": summary,
        "cpus": cpu_data
    })

    # Set summary message
    if summary["status"] == "OK":
        output.set_summary("No thermal throttling detected")
    else:
        output.set_summary(
            f"{summary['total_core_throttles']} core + "
            f"{summary['total_package_throttles']} package throttle events"
        )

    return 1 if summary["status"] != "OK" else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
