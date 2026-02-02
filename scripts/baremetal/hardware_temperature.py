#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, temperature, sensors, thermal, lm-sensors]
#   requires: [sensors]
#   privilege: user
#   related: [thermal_zone, thermal_throttle, ipmi_sensor]
#   brief: Monitor hardware temperature sensors using lm-sensors

"""
Monitor hardware temperature sensors on baremetal systems.

Checks CPU temperatures, fan speeds, and other thermal sensors using
lm-sensors (sensors command). Useful for detecting thermal issues in
datacenter environments before they cause hardware failures.

Returns exit code 1 if any sensor is at warning or critical level.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_sensors_output(output: str) -> list[dict[str, Any]]:
    """Parse sensors command output into structured data."""
    sensors = []
    current_chip = None

    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Detect chip name (e.g., "coretemp-isa-0000")
        if line and not line.startswith(' ') and ':' not in line:
            current_chip = line
            continue

        # Parse temperature lines
        temp_match = re.match(
            r'^([^:]+):\s+\+?([0-9.]+)\s*[°]?C\s*(?:\(high = \+?([0-9.]+)[°]?C)?(?:, crit = \+?([0-9.]+)[°]?C\))?',
            line
        )
        fan_match = re.match(
            r'^([^:]+):\s+([0-9]+)\s*RPM\s*(?:\(min\s*=\s*([0-9]+)\s*RPM\))?',
            line
        )

        if temp_match:
            label = temp_match.group(1).strip()
            current = float(temp_match.group(2))
            high = float(temp_match.group(3)) if temp_match.group(3) else None
            crit = float(temp_match.group(4)) if temp_match.group(4) else None

            status = 'healthy'
            if crit and current >= crit:
                status = 'critical'
            elif high and current >= high:
                status = 'warning'

            sensors.append({
                'chip': current_chip,
                'label': label,
                'type': 'temperature',
                'value': current,
                'unit': 'C',
                'high': high,
                'critical': crit,
                'status': status
            })
        elif fan_match:
            label = fan_match.group(1).strip()
            current = int(fan_match.group(2))
            min_rpm = int(fan_match.group(3)) if fan_match.group(3) else None

            status = 'healthy'
            if min_rpm and current < min_rpm:
                status = 'warning'
            if current == 0:
                status = 'critical'

            sensors.append({
                'chip': current_chip,
                'label': label,
                'type': 'fan',
                'value': current,
                'unit': 'RPM',
                'min': min_rpm,
                'status': status
            })

    return sensors


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
        description="Monitor hardware temperature sensors"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show sensors with warnings or critical status"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed threshold information"
    )

    opts = parser.parse_args(args)

    # Check if sensors command is available
    if not context.check_tool("sensors"):
        output.error("sensors command not found. Install lm-sensors package.")
        return 2

    # Run sensors command
    try:
        result = context.run(['sensors'], check=True)
    except Exception as e:
        output.error(f"Failed to run sensors: {e}")
        return 2

    # Parse output
    sensors = parse_sensors_output(result.stdout)

    if not sensors:
        output.warning("No sensors found. Run 'sensors-detect' to configure.")
        output.emit({"sensors": []})
        return 0

    # Filter for warn-only mode
    filtered = sensors
    if opts.warn_only:
        filtered = [s for s in sensors if s['status'] != 'healthy']

    # Remove verbose fields if not requested
    if not opts.verbose:
        for sensor in filtered:
            if sensor['type'] == 'temperature':
                sensor.pop('high', None)
                sensor.pop('critical', None)
            elif sensor['type'] == 'fan':
                sensor.pop('min', None)

    output.emit({"sensors": filtered})

    # Set summary
    healthy = sum(1 for s in sensors if s['status'] == 'healthy')
    warning = sum(1 for s in sensors if s['status'] == 'warning')
    critical = sum(1 for s in sensors if s['status'] == 'critical')
    output.set_summary(f"{healthy} healthy, {warning} warning, {critical} critical")

    # Return 1 if any issues
    has_issues = warning > 0 or critical > 0
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
