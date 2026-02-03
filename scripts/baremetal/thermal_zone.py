#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, hardware, thermal, temperature, cooling]
#   brief: Monitor kernel thermal zones and cooling devices

"""
Monitor Linux kernel thermal zones and cooling devices.

Reads thermal zone information from /sys/class/thermal/ to report:
- Current temperatures and thermal zone types
- Trip point temperatures (passive, active, critical, hot)
- Cooling device states and effectiveness
- Temperature headroom to critical thresholds

Exit codes:
    0 - All temperatures below warning thresholds
    1 - Warning, throttling, or critical conditions detected
    2 - Usage error or missing thermal zones
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


THERMAL_BASE = "/sys/class/thermal"


def get_thermal_zones(context: Context) -> list[dict[str, Any]]:
    """
    Enumerate all thermal zones and their properties.

    Returns list of dicts with zone info including temperature,
    type, trip points, and status.
    """
    zones = []

    if not context.file_exists(THERMAL_BASE):
        return zones

    # Get thermal zone directories
    zone_paths = sorted(context.glob("thermal_zone*", root=THERMAL_BASE))

    for zone_path in zone_paths:
        zone_name = zone_path.split("/")[-1]
        base = f"{THERMAL_BASE}/{zone_name}"

        # Read basic zone info
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
        trip_points = []
        trip_idx = 0
        while True:
            try:
                trip_temp_raw = context.read_file(f"{base}/trip_point_{trip_idx}_temp")
                trip_type = "unknown"
                try:
                    trip_type = context.read_file(f"{base}/trip_point_{trip_idx}_type").strip()
                except (FileNotFoundError, PermissionError):
                    pass

                trip_temp_c = int(trip_temp_raw.strip()) / 1000.0
                trip_points.append({
                    "index": trip_idx,
                    "type": trip_type,
                    "temp": trip_temp_c
                })
                trip_idx += 1
            except (FileNotFoundError, ValueError, PermissionError):
                break

        # Determine status based on trip points
        status = "OK"
        triggered_trip = None

        if temp_c is not None:
            for trip in trip_points:
                if temp_c >= trip["temp"]:
                    if trip["type"] == "critical":
                        status = "CRITICAL"
                        triggered_trip = trip
                    elif trip["type"] == "hot" and status != "CRITICAL":
                        status = "HOT"
                        triggered_trip = trip
                    elif trip["type"] in ("passive", "active") and status == "OK":
                        status = "THROTTLING"
                        triggered_trip = trip

        # Calculate headroom to critical
        critical_trip = next((t for t in trip_points if t["type"] == "critical"), None)
        headroom = None
        if temp_c is not None and critical_trip:
            headroom = critical_trip["temp"] - temp_c

        zones.append({
            "name": zone_name,
            "type": zone_type,
            "temp": temp_c,
            "trip_points": trip_points,
            "status": status,
            "triggered_trip": triggered_trip,
            "headroom_to_critical": headroom
        })

    return zones


def get_cooling_devices(context: Context) -> list[dict[str, Any]]:
    """
    Enumerate all cooling devices and their states.

    Returns list of dicts with device info including current and max state.
    """
    devices = []

    if not context.file_exists(THERMAL_BASE):
        return devices

    # Get cooling device directories
    dev_paths = sorted(context.glob("cooling_device*", root=THERMAL_BASE))

    for dev_path in dev_paths:
        dev_name = dev_path.split("/")[-1]
        base = f"{THERMAL_BASE}/{dev_name}"

        dev_type = "unknown"
        try:
            dev_type = context.read_file(f"{base}/type").strip()
        except (FileNotFoundError, PermissionError):
            pass

        cur_state = None
        try:
            cur_state = int(context.read_file(f"{base}/cur_state").strip())
        except (FileNotFoundError, ValueError, PermissionError):
            pass

        max_state = None
        try:
            max_state = int(context.read_file(f"{base}/max_state").strip())
        except (FileNotFoundError, ValueError, PermissionError):
            pass

        # Determine if cooling device is active
        active = cur_state is not None and cur_state > 0
        utilization = None
        if cur_state is not None and max_state is not None and max_state > 0:
            utilization = (cur_state / max_state) * 100

        devices.append({
            "name": dev_name,
            "type": dev_type,
            "cur_state": cur_state,
            "max_state": max_state,
            "active": active,
            "utilization_pct": utilization
        })

    return devices


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Linux kernel thermal zones and cooling devices"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show trip points and utilization")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show zones with warnings or active cooling")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check if thermal sysfs exists
    if not context.file_exists(THERMAL_BASE):
        output.error("/sys/class/thermal not found. System may not have thermal zone support.")

        output.render(opts.format, "Monitor kernel thermal zones and cooling devices")
        return 2

    # Get thermal data
    zones = get_thermal_zones(context)
    cooling_devices = get_cooling_devices(context)

    if not zones:
        output.error("No thermal zones found. Check kernel configuration for CONFIG_THERMAL.")

        output.render(opts.format, "Monitor kernel thermal zones and cooling devices")
        return 2

    # Filter if warn-only
    if opts.warn_only:
        zones = [z for z in zones if z["status"] != "OK"]
        cooling_devices = [d for d in cooling_devices if d["active"]]

    # Remove verbose-only fields if not verbose
    if not opts.verbose:
        for zone in zones:
            zone.pop("trip_points", None)
            zone.pop("triggered_trip", None)
        for dev in cooling_devices:
            dev.pop("utilization_pct", None)

    # Emit data
    output.emit({
        "thermal_zones": zones,
        "cooling_devices": cooling_devices
    })

    # Determine status
    # Get all zones for status check (before filtering)
    all_zones = get_thermal_zones(context)
    has_issues = any(z["status"] != "OK" for z in all_zones)

    # Set summary
    ok_count = sum(1 for z in all_zones if z["status"] == "OK")
    issue_count = len(all_zones) - ok_count
    if has_issues:
        output.set_summary(f"{issue_count} thermal zone(s) with issues")
    else:
        output.set_summary(f"{len(all_zones)} thermal zone(s) OK")

    output.render(opts.format, "Monitor kernel thermal zones and cooling devices")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
