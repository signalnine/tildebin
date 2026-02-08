#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [hardware, fan, cooling, thermal, health]
#   requires: []
#   privilege: user
#   related: [hardware_temperature, thermal_throttle, psu_monitor]
#   brief: Monitor fan speeds and detect cooling failures

"""
Monitor fan speeds and detect cooling failures on baremetal systems.

Reads fan RPM data from sysfs hwmon interface to detect:
- Fans that have stopped spinning (0 RPM) while others are active
- Fans running below their configured minimum RPM threshold

Critical for detecting cooling failures in datacenter environments
before thermal throttling or hardware damage occurs.

Exit codes:
    0 - All fans healthy (or no fan sensors found)
    1 - Fan issues detected (stopped or below minimum)
    2 - Error (hwmon interface not available)
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def discover_hwmon_dirs(context: Context) -> list[str]:
    """Discover hwmon directories under /sys/class/hwmon."""
    return context.glob("hwmon*", root="/sys/class/hwmon")


def read_chip_name(hwmon_dir: str, context: Context) -> str:
    """Read the sensor chip name from a hwmon directory."""
    name_path = f"{hwmon_dir}/name"
    try:
        return context.read_file(name_path).strip()
    except (FileNotFoundError, PermissionError):
        return "unknown"


def discover_fan_inputs(hwmon_dir: str, context: Context) -> list[str]:
    """Discover fan*_input files in a hwmon directory."""
    return context.glob("fan*_input", root=hwmon_dir)


def read_fan_sensor(
    input_path: str,
    chip_name: str,
    context: Context,
) -> dict[str, Any] | None:
    """Read a single fan sensor and its associated metadata.

    Args:
        input_path: Path to fan*_input sysfs file
        chip_name: Name of the hwmon chip
        context: Execution context

    Returns:
        Dict with fan sensor data, or None if unreadable.
    """
    try:
        rpm_str = context.read_file(input_path).strip()
        rpm = int(rpm_str)
    except (FileNotFoundError, PermissionError, ValueError):
        return None

    # Derive base path: /sys/class/hwmon/hwmon0/fan1_input -> fan1
    # The base is everything before _input
    base_path = input_path.rsplit("_input", 1)[0]
    fan_id = base_path.split("/")[-1]

    # Read optional min RPM
    min_rpm = None
    min_path = f"{base_path}_min"
    try:
        min_str = context.read_file(min_path).strip()
        min_rpm = int(min_str)
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    # Read optional label
    label = None
    label_path = f"{base_path}_label"
    try:
        label = context.read_file(label_path).strip()
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    return {
        "fan_id": fan_id,
        "chip": chip_name,
        "label": label,
        "rpm": rpm,
        "min_rpm": min_rpm,
        "path": input_path,
    }


def analyze_fans(fans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analyze fan sensor data and assign status to each fan.

    Logic:
    - A fan at 0 RPM when at least one other fan is spinning -> CRITICAL
    - A fan below its min_rpm threshold (but > 0) -> WARNING
    - Otherwise -> OK

    Args:
        fans: List of fan sensor dicts from read_fan_sensor()

    Returns:
        The same list with 'status' and 'message' fields added.
    """
    any_spinning = any(f["rpm"] > 0 for f in fans)

    for fan in fans:
        if fan["rpm"] == 0 and any_spinning:
            fan["status"] = "CRITICAL"
            fan["message"] = "Fan stopped while others are spinning"
        elif fan["rpm"] == 0 and not any_spinning:
            # All fans at 0 - could be fanless system or all stopped
            fan["status"] = "OK"
            fan["message"] = "Fan not spinning (no active fans detected)"
        elif fan["min_rpm"] is not None and fan["rpm"] < fan["min_rpm"]:
            fan["status"] = "WARNING"
            fan["message"] = (
                f"RPM {fan['rpm']} below minimum {fan['min_rpm']}"
            )
        else:
            fan["status"] = "OK"
            fan["message"] = None

    return fans


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
        description="Monitor fan speeds and detect cooling failures"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed fan information including paths",
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show fans with issues",
    )

    opts = parser.parse_args(args)

    # Check if hwmon interface exists
    hwmon_dirs = discover_hwmon_dirs(context)
    if not hwmon_dirs:
        output.error("hwmon interface not available (/sys/class/hwmon empty or missing)")

        output.render(opts.format, "Monitor fan speeds and detect cooling failures")
        return 2

    # Collect all fan sensors across all hwmon chips
    all_fans: list[dict[str, Any]] = []
    for hwmon_dir in hwmon_dirs:
        chip_name = read_chip_name(hwmon_dir, context)
        fan_inputs = discover_fan_inputs(hwmon_dir, context)

        for input_path in fan_inputs:
            fan = read_fan_sensor(input_path, chip_name, context)
            if fan is not None:
                all_fans.append(fan)

    # No fan sensors found - not an error, just informational
    if not all_fans:
        output.emit({"fans": [], "status": "ok"})
        output.set_summary("No fan sensors found")

        output.render(opts.format, "Monitor fan speeds and detect cooling failures")
        return 0

    # Analyze fan health
    all_fans = analyze_fans(all_fans)

    # Count statuses
    critical_count = sum(1 for f in all_fans if f["status"] == "CRITICAL")
    warning_count = sum(1 for f in all_fans if f["status"] == "WARNING")
    ok_count = sum(1 for f in all_fans if f["status"] == "OK")
    total = len(all_fans)

    # Filter for warn-only
    filtered_fans = all_fans
    if opts.warn_only:
        filtered_fans = [f for f in all_fans if f["status"] != "OK"]

    # Remove verbose fields if not requested
    if not opts.verbose:
        for fan in filtered_fans:
            fan.pop("path", None)
            fan.pop("message", None)

    # Emit data
    output.emit({
        "fans": filtered_fans,
        "summary": {
            "total": total,
            "ok": ok_count,
            "warning": warning_count,
            "critical": critical_count,
        },
    })

    # Set summary
    if critical_count > 0:
        output.set_summary(
            f"{critical_count} fan(s) CRITICAL, {warning_count} warning, "
            f"{ok_count} OK out of {total}"
        )
    elif warning_count > 0:
        output.set_summary(
            f"{warning_count} fan(s) WARNING, {ok_count} OK out of {total}"
        )
    else:
        output.set_summary(f"All {total} fan(s) OK")

    has_issues = critical_count > 0 or warning_count > 0

    output.render(opts.format, "Monitor fan speeds and detect cooling failures")
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
