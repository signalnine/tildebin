#!/usr/bin/env python3
"""
Monitor hardware temperature sensors on baremetal systems.

Checks CPU temperatures, fan speeds, and other thermal sensors using
lm-sensors (sensors command). Useful for detecting thermal issues in
datacenter environments before they cause hardware failures.

Exit codes:
  0 - Success (all temperatures normal)
  1 - Warning/Critical temperatures detected
  2 - Usage error or missing dependencies
"""

import argparse
import json
import re
import subprocess
import sys


def check_sensors_available():
    """Check if sensors command is available."""
    try:
        subprocess.run(
            ['sensors', '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def parse_sensors_output(output):
    """
    Parse sensors command output into structured data.

    Returns list of sensor readings with chip, label, current temp,
    high threshold, and critical threshold.
    """
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
        # Example: "Core 0:        +45.0°C  (high = +80.0°C, crit = +100.0°C)"
        # Example: "fan1:         1234 RPM  (min =  600 RPM)"
        temp_match = re.match(
            r'^([^:]+):\s+\+?([0-9.]+)°C\s*(?:\(high = \+?([0-9.]+)°C)?(?:, crit = \+?([0-9.]+)°C\))?',
            line
        )
        fan_match = re.match(
            r'^([^:]+):\s+([0-9]+) RPM\s*(?:\(min\s*=\s*([0-9]+) RPM\))?',
            line
        )

        if temp_match:
            label = temp_match.group(1).strip()
            current = float(temp_match.group(2))
            high = float(temp_match.group(3)) if temp_match.group(3) else None
            crit = float(temp_match.group(4)) if temp_match.group(4) else None

            status = 'OK'
            if crit and current >= crit:
                status = 'CRITICAL'
            elif high and current >= high:
                status = 'WARNING'

            sensors.append({
                'chip': current_chip,
                'label': label,
                'type': 'temperature',
                'value': current,
                'unit': '°C',
                'high': high,
                'critical': crit,
                'status': status
            })
        elif fan_match:
            label = fan_match.group(1).strip()
            current = int(fan_match.group(2))
            min_rpm = int(fan_match.group(3)) if fan_match.group(3) else None

            status = 'OK'
            if min_rpm and current < min_rpm:
                status = 'WARNING'
            if current == 0:
                status = 'CRITICAL'

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


def get_sensor_data():
    """Run sensors command and return parsed data."""
    try:
        result = subprocess.run(
            ['sensors'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        return parse_sensors_output(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running sensors command: {e}", file=sys.stderr)
        return []


def format_plain(sensors, warn_only=False, verbose=False):
    """Format sensor data as plain text."""
    output = []

    if warn_only:
        sensors = [s for s in sensors if s['status'] != 'OK']

    if not sensors:
        if warn_only:
            output.append("No temperature warnings or critical conditions detected.")
        else:
            output.append("No sensors found.")
        return '\n'.join(output)

    current_chip = None
    for sensor in sensors:
        if sensor['chip'] != current_chip:
            current_chip = sensor['chip']
            if verbose or warn_only:
                output.append(f"\n{current_chip}:")

        if sensor['type'] == 'temperature':
            temp_str = f"  {sensor['label']:<20} {sensor['value']:>6.1f}{sensor['unit']}"

            if verbose:
                if sensor['high']:
                    temp_str += f"  (high: {sensor['high']:.1f}{sensor['unit']}"
                    if sensor['critical']:
                        temp_str += f", crit: {sensor['critical']:.1f}{sensor['unit']})"
                    else:
                        temp_str += ")"

            if sensor['status'] != 'OK':
                temp_str += f"  [{sensor['status']}]"

            output.append(temp_str)

        elif sensor['type'] == 'fan':
            fan_str = f"  {sensor['label']:<20} {sensor['value']:>6} {sensor['unit']}"

            if verbose and sensor['min']:
                fan_str += f"  (min: {sensor['min']} {sensor['unit']})"

            if sensor['status'] != 'OK':
                fan_str += f"  [{sensor['status']}]"

            output.append(fan_str)

    return '\n'.join(output)


def format_json(sensors, warn_only=False):
    """Format sensor data as JSON."""
    if warn_only:
        sensors = [s for s in sensors if s['status'] != 'OK']

    return json.dumps(sensors, indent=2)


def format_table(sensors, warn_only=False):
    """Format sensor data as a table."""
    if warn_only:
        sensors = [s for s in sensors if s['status'] != 'OK']

    if not sensors:
        return "No sensors found." if not warn_only else "No warnings detected."

    # Header
    header = f"{'CHIP':<25} {'SENSOR':<20} {'VALUE':<12} {'THRESHOLDS':<25} {'STATUS':<10}"
    separator = '-' * len(header)
    rows = [header, separator]

    for sensor in sensors:
        chip = sensor['chip'] or 'Unknown'
        label = sensor['label']
        value = f"{sensor['value']:.1f} {sensor['unit']}" if sensor['type'] == 'temperature' else f"{sensor['value']} {sensor['unit']}"

        thresholds = ''
        if sensor['type'] == 'temperature':
            if sensor.get('high'):
                thresholds = f"High: {sensor['high']:.1f}"
                if sensor.get('critical'):
                    thresholds += f", Crit: {sensor['critical']:.1f}"
        elif sensor['type'] == 'fan' and sensor.get('min'):
            thresholds = f"Min: {sensor['min']}"

        status = sensor['status']

        row = f"{chip:<25} {label:<20} {value:<12} {thresholds:<25} {status:<10}"
        rows.append(row)

    return '\n'.join(rows)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor hardware temperature sensors on baremetal systems.',
        epilog='''
Examples:
  # Show all sensor readings
  hardware_temperature_monitor.py

  # Show only warnings and critical temperatures
  hardware_temperature_monitor.py --warn-only

  # Output as JSON for monitoring systems
  hardware_temperature_monitor.py --format json

  # Verbose output with all thresholds
  hardware_temperature_monitor.py --verbose

  # Table format with warnings only
  hardware_temperature_monitor.py --format table --warn-only

Exit codes:
  0 - All temperatures normal
  1 - Warning or critical temperatures detected
  2 - Usage error or missing dependencies
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show sensors with warnings or critical status'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed threshold information'
    )

    args = parser.parse_args()

    # Check if sensors command is available
    if not check_sensors_available():
        print("Error: 'sensors' command not found.", file=sys.stderr)
        print("Install lm-sensors package (e.g., 'apt install lm-sensors' or 'yum install lm_sensors')", file=sys.stderr)
        print("Run 'sensors-detect' to configure sensors after installation.", file=sys.stderr)
        return 2

    # Get sensor data
    sensors = get_sensor_data()

    # Format output
    if args.format == 'json':
        output = format_json(sensors, args.warn_only)
    elif args.format == 'table':
        output = format_table(sensors, args.warn_only)
    else:
        output = format_plain(sensors, args.warn_only, args.verbose)

    print(output)

    # Determine exit code based on sensor status
    has_warnings = any(s['status'] == 'WARNING' for s in sensors)
    has_critical = any(s['status'] == 'CRITICAL' for s in sensors)

    if has_critical or has_warnings:
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
