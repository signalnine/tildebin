#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, hardware, ipmi, temperature, fan, voltage, power]
#   requires: [ipmitool]
#   privilege: root
#   brief: Monitor IPMI sensor readings

"""
Monitor IPMI sensor readings for baremetal systems.

Retrieves and analyzes real-time sensor data from IPMI including:
- Temperature sensors (CPU, system, memory, inlet/outlet)
- Fan speeds and status
- Voltage readings (CPU, memory, system rails)
- Power consumption and PSU status

Exit codes:
    0 - All sensors within normal thresholds
    1 - Sensors in warning or critical state
    2 - Usage error or ipmitool not available
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_sensor_line(line: str) -> dict[str, Any] | None:
    """
    Parse a single line from 'ipmitool sensor list' output.

    Format: Name | Value | Units | Status | Lower NR | Lower C | Lower NC | Upper NC | Upper C | Upper NR
    """
    if not line.strip() or "|" not in line:
        return None

    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 4:
        return None

    name = parts[0]
    value_str = parts[1]
    units = parts[2] if len(parts) > 2 else ""
    status = parts[3] if len(parts) > 3 else "unknown"

    # Parse numeric value
    value = None
    if value_str and value_str.lower() not in ("na", "n/a", "disabled", ""):
        try:
            value = float(value_str)
        except ValueError:
            pass

    # Determine sensor type based on units and name
    sensor_type = categorize_sensor(name, units)

    return {
        "name": name,
        "value": value,
        "units": units,
        "status": status.lower(),
        "type": sensor_type,
    }


def categorize_sensor(name: str, units: str) -> str:
    """Categorize sensor type based on name and units."""
    name_lower = name.lower()
    units_lower = units.lower()

    if "degrees" in units_lower or "temp" in name_lower:
        return "temperature"
    elif "rpm" in units_lower or "fan" in name_lower:
        return "fan"
    elif "volts" in units_lower or "voltage" in name_lower:
        return "voltage"
    elif "watts" in units_lower or "power" in name_lower or "pwr" in name_lower:
        return "power"
    elif "amps" in units_lower or "current" in name_lower:
        return "current"
    elif "intrusion" in name_lower or "chassis" in name_lower:
        return "intrusion"
    elif "psu" in name_lower or "ps" in name_lower or "supply" in name_lower:
        return "psu"
    else:
        return "other"


def determine_severity(status: str, sensor_type: str, value: float | None,
                       temp_warn: float, temp_crit: float) -> str:
    """Determine sensor severity based on status and value."""
    status_lower = status.lower()

    # Status-based severity
    if status_lower in ("ok", "ns", "na"):
        severity = "ok"
    elif "cr" in status_lower or "critical" in status_lower:
        severity = "critical"
    elif "nr" in status_lower or "non-recoverable" in status_lower:
        severity = "critical"
    elif "nc" in status_lower or "non-critical" in status_lower:
        severity = "warning"
    elif "lnr" in status_lower or "unr" in status_lower:
        severity = "critical"
    elif "lcr" in status_lower or "ucr" in status_lower:
        severity = "critical"
    elif "lnc" in status_lower or "unc" in status_lower:
        severity = "warning"
    elif status_lower in ("disabled", "not available"):
        severity = "ok"
    else:
        severity = "warning" if status_lower and status_lower != "ok" else "ok"

    # Override with value-based checks for temperature sensors
    if sensor_type == "temperature" and value is not None:
        if value >= temp_crit:
            severity = "critical"
        elif value >= temp_warn:
            severity = "warning"

    # Check fan sensors - 0 RPM is usually bad
    if sensor_type == "fan" and value is not None:
        if value == 0 and "ok" not in status_lower:
            severity = "critical"

    return severity


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
        description="Monitor IPMI sensor readings"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show additional details")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show sensors with warnings or critical status")
    parser.add_argument("-t", "--type", action="append",
                        choices=["temperature", "fan", "voltage", "power",
                                 "current", "psu", "intrusion", "other"],
                        help="Filter by sensor type")
    parser.add_argument("--temp-warn", type=float, default=75.0,
                        help="Temperature warning threshold (default: 75C)")
    parser.add_argument("--temp-crit", type=float, default=85.0,
                        help="Temperature critical threshold (default: 85C)")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for ipmitool
    if not context.check_tool("ipmitool"):
        output.error("ipmitool not found. Install ipmitool package.")

        output.render(opts.format, "Monitor IPMI sensor readings")
        return 2

    # Get sensor readings
    try:
        result = context.run(["ipmitool", "sensor", "list"], check=False)
        sensor_output = result.stdout
    except Exception as e:
        output.error(f"Failed to run ipmitool: {e}")

        output.render(opts.format, "Monitor IPMI sensor readings")
        return 2

    if not sensor_output.strip():
        output.error("No sensor data available. Check IPMI/BMC access.")

        output.render(opts.format, "Monitor IPMI sensor readings")
        return 2

    # Parse sensors
    sensors = []
    for line in sensor_output.strip().split("\n"):
        sensor = parse_sensor_line(line)
        if sensor:
            sensors.append(sensor)

    if not sensors:
        output.error("No sensor data available. Check IPMI/BMC access.")

        output.render(opts.format, "Monitor IPMI sensor readings")
        return 2

    # Filter by type if specified
    if opts.type:
        sensors = [s for s in sensors if s.get("type") in opts.type]

    # Add severity to each sensor
    for sensor in sensors:
        sensor["severity"] = determine_severity(
            sensor.get("status", ""),
            sensor.get("type", ""),
            sensor.get("value"),
            opts.temp_warn,
            opts.temp_crit
        )

    # Filter if warn-only
    if opts.warn_only:
        sensors = [s for s in sensors if s.get("severity") != "ok"]

    # Count by severity
    critical_count = sum(1 for s in sensors if s.get("severity") == "critical")
    warning_count = sum(1 for s in sensors if s.get("severity") == "warning")
    ok_count = sum(1 for s in sensors if s.get("severity") == "ok")

    # Emit data
    output.emit({
        "sensors": sensors,
        "summary": {
            "total": len(sensors),
            "ok": ok_count,
            "warning": warning_count,
            "critical": critical_count
        }
    })

    # Set summary
    if critical_count > 0:
        output.set_summary(f"{critical_count} critical, {warning_count} warning sensors")
    elif warning_count > 0:
        output.set_summary(f"{warning_count} warning sensors")
    else:
        output.set_summary(f"{len(sensors)} sensors OK")

    # Return code
    if critical_count > 0 or warning_count > 0:

        output.render(opts.format, "Monitor IPMI sensor readings")
        return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
