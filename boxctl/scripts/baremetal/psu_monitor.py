#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, hardware, ipmi, power, psu]
#   requires: [ipmitool]
#   privilege: root
#   brief: Monitor Power Supply Unit health via IPMI

"""
Monitor Power Supply Unit (PSU) health on baremetal systems via IPMI.

Checks PSU status including:
- Power supply presence and operational state
- Power supply redundancy status
- Power consumption readings

Critical for large-scale datacenter environments where PSU failures can
cause unexpected outages.

Exit codes:
    0 - All PSUs healthy
    1 - Warning/Critical PSU conditions detected
    2 - Usage error or missing dependencies
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def categorize_status(status_str: str, reading_str: str) -> str:
    """Categorize sensor health based on status and reading."""
    status_lower = status_str.lower().strip()
    reading_lower = reading_str.lower() if reading_str else ""

    # Short IPMI status codes
    # cr = critical, nc = non-critical, nr = non-recoverable
    # lnr/unr = lower/upper non-recoverable
    # lcr/ucr = lower/upper critical
    # lnc/unc = lower/upper non-critical
    if status_lower in ("cr", "lcr", "ucr", "nr", "lnr", "unr"):
        return "CRITICAL"
    if status_lower in ("nc", "lnc", "unc"):
        return "WARNING"

    # Critical conditions
    critical_keywords = [
        "failure", "failed", "fault", "critical", "non-recoverable",
        "not present", "power off", "predictive failure", "ac lost"
    ]
    for kw in critical_keywords:
        if kw in status_lower or kw in reading_lower:
            return "CRITICAL"

    # Warning conditions
    warning_keywords = [
        "degraded", "redundancy lost", "warning", "non-critical",
        "power cycle", "config error", "mismatch"
    ]
    for kw in warning_keywords:
        if kw in status_lower or kw in reading_lower:
            return "WARNING"

    # OK conditions
    ok_keywords = ["ok", "presence detected", "fully redundant", "normal"]
    for kw in ok_keywords:
        if kw in status_lower or kw in reading_lower:
            return "OK"

    # If status contains 'ns' or 'na', it's not available
    if status_lower in ["ns", "na", "disabled"]:
        return "UNKNOWN"

    # Default to unknown
    return "UNKNOWN"


def parse_sdr_line(line: str, sensor_type: str) -> dict[str, Any] | None:
    """Parse a line from ipmitool sdr output."""
    if not line.strip() or "|" not in line:
        return None

    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 3:
        return None

    sensor = {
        "name": parts[0],
        "id": parts[1] if len(parts) > 1 else "",
        "status": parts[2] if len(parts) > 2 else "",
        "entity": parts[3] if len(parts) > 3 else "",
        "reading": parts[4] if len(parts) > 4 else "",
        "type": sensor_type
    }

    sensor["health"] = categorize_status(
        sensor.get("status", ""),
        sensor.get("reading", "")
    )

    return sensor


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
        description="Monitor Power Supply Unit health via IPMI"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed PSU information")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show warning and critical conditions")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for ipmitool
    if not context.check_tool("ipmitool"):
        output.error("ipmitool not found. Install ipmitool package.")
        return 2

    # Get PSU sensors
    psu_sensors = []
    voltage_sensors = []

    # Get Power Supply sensors
    try:
        result = context.run(["ipmitool", "sdr", "type", "Power Supply"], check=False)
        for line in result.stdout.strip().split("\n"):
            sensor = parse_sdr_line(line, "power_supply")
            if sensor:
                psu_sensors.append(sensor)
    except Exception:
        pass

    # Get voltage sensors (PSU-related)
    try:
        result = context.run(["ipmitool", "sdr", "type", "Voltage"], check=False)
        for line in result.stdout.strip().split("\n"):
            sensor = parse_sdr_line(line, "voltage")
            if sensor:
                name_lower = sensor["name"].lower()
                # Filter for PSU-related voltage sensors
                if any(kw in name_lower for kw in ["ps", "psu", "power", "input", "12v", "5v", "3.3v"]):
                    voltage_sensors.append(sensor)
    except Exception:
        pass

    # Calculate summary
    all_sensors = psu_sensors + voltage_sensors
    summary = {
        "total_psu_sensors": len(psu_sensors),
        "total_voltage_sensors": len(voltage_sensors),
        "healthy": 0,
        "warning": 0,
        "critical": 0,
        "unknown": 0
    }

    for sensor in all_sensors:
        health = sensor.get("health", "UNKNOWN")
        if health == "OK":
            summary["healthy"] += 1
        elif health == "WARNING":
            summary["warning"] += 1
        elif health == "CRITICAL":
            summary["critical"] += 1
        else:
            summary["unknown"] += 1

    # Filter if warn-only
    if opts.warn_only:
        psu_sensors = [s for s in psu_sensors if s.get("health") in ["WARNING", "CRITICAL"]]
        voltage_sensors = [s for s in voltage_sensors if s.get("health") in ["WARNING", "CRITICAL"]]

    # Remove verbose-only fields if not verbose
    if not opts.verbose:
        for sensor in psu_sensors + voltage_sensors:
            sensor.pop("id", None)
            sensor.pop("entity", None)

    # Emit data
    output.emit({
        "psu_sensors": psu_sensors,
        "voltage_sensors": voltage_sensors,
        "summary": summary
    })

    # Set summary
    if summary["critical"] > 0:
        output.set_summary(f"{summary['critical']} critical PSU issue(s)")
    elif summary["warning"] > 0:
        output.set_summary(f"{summary['warning']} PSU warning(s)")
    elif len(all_sensors) == 0:
        output.set_summary("No PSU sensors found")
    else:
        output.set_summary(f"{summary['healthy']} PSU sensors OK")

    # Return code
    if summary["critical"] > 0 or summary["warning"] > 0:
        return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
