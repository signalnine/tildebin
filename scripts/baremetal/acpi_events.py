#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [hardware, acpi, thermal, power, events]
#   requires: []
#   privilege: root
#   related: [thermal_zone, thermal_throttle, hardware_temperature]
#   brief: Monitor ACPI thermal trip points, power events, and error conditions

"""
Monitor ACPI thermal trip points, power events, and error conditions.

Reads thermal zone information from /sys/class/thermal/ to check current
temperatures against trip points, and scans dmesg for ACPI-related errors.

Checks performed:
- Thermal zones: current temperature vs trip points
  - Within 10C of critical trip point -> CRITICAL
  - Within 20C of hot or passive trip point -> WARNING
- ACPI errors in dmesg output

Exit codes:
    0 - All temperatures safe, no ACPI errors
    1 - Temperature near trip points or ACPI errors found
    2 - Unable to read thermal data and dmesg unavailable
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


THERMAL_BASE = "/sys/class/thermal"


def get_thermal_zones(context: Context) -> list[dict[str, Any]]:
    """
    Enumerate thermal zones with temperatures and trip points.

    Returns list of dicts with zone name, type, current temp,
    trip points, and proximity alerts.
    """
    zones = []

    zone_paths = sorted(context.glob("thermal_zone*", root=THERMAL_BASE))

    for zone_path in zone_paths:
        zone_name = zone_path.split("/")[-1]
        base = f"{THERMAL_BASE}/{zone_name}"

        # Read current temperature (millidegrees C)
        temp_c = None
        try:
            temp_raw = context.read_file(f"{base}/temp")
            temp_c = int(temp_raw.strip()) / 1000.0
        except (FileNotFoundError, ValueError, PermissionError):
            pass

        zone_type = "unknown"
        try:
            zone_type = context.read_file(f"{base}/type").strip()
        except (FileNotFoundError, PermissionError):
            pass

        # Read trip points
        trip_points = get_trip_points(context, base)

        # Check proximity to trip points
        alerts = check_trip_proximity(temp_c, trip_points)

        zones.append({
            "name": zone_name,
            "type": zone_type,
            "temp_c": temp_c,
            "trip_points": trip_points,
            "alerts": alerts,
        })

    return zones


def get_trip_points(context: Context, zone_base: str) -> list[dict[str, Any]]:
    """
    Read trip point files for a thermal zone.

    Iterates trip_point indices and reads corresponding type/temp files.
    Returns list of dicts with index, type, and temp_c.
    """
    trip_points = []
    idx = 0
    while True:
        try:
            trip_temp_raw = context.read_file(f"{zone_base}/trip_point_{idx}_temp")
            trip_temp_c = int(trip_temp_raw.strip()) / 1000.0

            trip_type = "unknown"
            try:
                trip_type = context.read_file(f"{zone_base}/trip_point_{idx}_type").strip()
            except (FileNotFoundError, PermissionError):
                pass

            trip_points.append({
                "index": idx,
                "type": trip_type,
                "temp_c": trip_temp_c,
            })
            idx += 1
        except (FileNotFoundError, ValueError, PermissionError):
            break

    return trip_points


def check_trip_proximity(
    temp_c: float | None,
    trip_points: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Check if current temperature is near any trip points.

    Rules:
    - Within 10C of critical trip point -> CRITICAL
    - Within 20C of hot or passive trip point -> WARNING

    Returns list of alert dicts with severity, trip_type, trip_temp_c, and margin.
    """
    alerts = []
    if temp_c is None:
        return alerts

    for trip in trip_points:
        trip_type = trip["type"]
        trip_temp = trip["temp_c"]
        margin = trip_temp - temp_c

        if trip_type == "critical" and margin <= 10.0:
            alerts.append({
                "severity": "CRITICAL",
                "trip_type": trip_type,
                "trip_temp_c": trip_temp,
                "margin_c": margin,
            })
        elif trip_type in ("hot", "passive") and margin <= 20.0:
            alerts.append({
                "severity": "WARNING",
                "trip_type": trip_type,
                "trip_temp_c": trip_temp,
                "margin_c": margin,
            })

    return alerts


def parse_acpi_errors(dmesg_output: str) -> list[dict[str, Any]]:
    """
    Parse dmesg output for ACPI error lines.

    Matches lines containing "ACPI" and any of: error, Error, ERROR, fault.
    Returns list of dicts with the matching line.
    """
    errors = []
    acpi_error_pattern = re.compile(r"ACPI.*(?:error|Error|ERROR|fault)")

    for line in dmesg_output.split("\n"):
        if acpi_error_pattern.search(line):
            errors.append({
                "message": line.strip()[:200],
            })

    return errors


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
        description="Monitor ACPI thermal trip points, power events, and error conditions"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show trip point details")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    title = "Monitor ACPI thermal trip points, power events, and error conditions"

    # Gather thermal zone data
    has_thermal_base = context.file_exists(THERMAL_BASE)
    zones = []
    if has_thermal_base:
        zones = get_thermal_zones(context)

    # Gather dmesg ACPI errors
    dmesg_ok = False
    acpi_errors: list[dict[str, Any]] = []
    try:
        result = context.run(["dmesg"], check=True)
        dmesg_ok = True
        acpi_errors = parse_acpi_errors(result.stdout)
    except Exception:
        pass

    # If no thermal zones and dmesg failed -> exit 2
    if not zones and not dmesg_ok:
        output.error(
            "No thermal zones found and dmesg unavailable. "
            "Cannot check ACPI status."
        )
        output.render(opts.format, title)
        return 2

    # If no thermal zones but dmesg works -> exit 0 INFO
    if not zones and dmesg_ok:
        data: dict[str, Any] = {
            "thermal_zones": [],
            "acpi_errors": acpi_errors,
        }
        output.emit(data)

        if acpi_errors:
            output.set_summary(
                f"No thermal zones found; {len(acpi_errors)} ACPI error(s) in dmesg"
            )
            output.render(opts.format, title)
            return 1

        output.set_summary("No thermal zones found; no ACPI errors in dmesg")
        output.render(opts.format, title)
        return 0

    # Process thermal zone alerts
    has_issues = False
    total_critical = 0
    total_warning = 0

    for zone in zones:
        for alert in zone["alerts"]:
            has_issues = True
            if alert["severity"] == "CRITICAL":
                total_critical += 1
            elif alert["severity"] == "WARNING":
                total_warning += 1

    if acpi_errors:
        has_issues = True
        total_warning += len(acpi_errors)

    # Remove verbose-only fields if not verbose
    if not opts.verbose:
        for zone in zones:
            zone.pop("trip_points", None)

    # Emit data
    output.emit({
        "thermal_zones": zones,
        "acpi_errors": acpi_errors,
    })

    # Set summary
    if has_issues:
        parts = []
        if total_critical:
            parts.append(f"{total_critical} CRITICAL")
        if total_warning:
            parts.append(f"{total_warning} WARNING")
        output.set_summary(", ".join(parts))
    else:
        output.set_summary(f"{len(zones)} thermal zone(s) OK, no ACPI errors")

    output.render(opts.format, title)

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
