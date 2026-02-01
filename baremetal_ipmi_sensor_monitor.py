#!/usr/bin/env python3
"""
Monitor IPMI sensor readings for baremetal systems.

Retrieves and analyzes real-time sensor data from IPMI including:
- Temperature sensors (CPU, system, memory, inlet/outlet)
- Fan speeds and status
- Voltage readings (CPU, memory, system rails)
- Power consumption and PSU status
- Intrusion and physical security sensors

Complements ipmi_sel_monitor.py which monitors historical events.
This script provides real-time sensor health for proactive monitoring.

Exit codes:
    0 - All sensors within normal thresholds
    1 - Sensors in warning or critical state
    2 - Usage error or ipmitool not available
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple


def check_ipmitool_available() -> bool:
    """Check if ipmitool command is available."""
    try:
        subprocess.run(
            ['ipmitool', '-V'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def run_ipmitool(args: List[str]) -> Optional[str]:
    """Execute ipmitool command and return stdout."""
    try:
        result = subprocess.run(
            ['ipmitool'] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        print("Error: ipmitool command timed out", file=sys.stderr)
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error running ipmitool: {e.stderr}", file=sys.stderr)
        return None
    except FileNotFoundError:
        return None


def parse_sensor_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single line from 'ipmitool sensor list' output.

    Format: Name | Value | Units | Status | Lower NR | Lower C | Lower NC | Upper NC | Upper C | Upper NR
    Example: CPU Temp | 45.000 | degrees C | ok | 0.000 | 0.000 | 0.000 | 85.000 | 90.000 | 95.000
    """
    if not line.strip() or '|' not in line:
        return None

    parts = [p.strip() for p in line.split('|')]
    if len(parts) < 4:
        return None

    name = parts[0]
    value_str = parts[1]
    units = parts[2] if len(parts) > 2 else ''
    status = parts[3] if len(parts) > 3 else 'unknown'

    # Parse numeric value
    value = None
    if value_str and value_str not in ('na', 'n/a', 'disabled', ''):
        try:
            value = float(value_str)
        except ValueError:
            pass

    # Parse thresholds if available
    thresholds = {}
    threshold_names = ['lower_nr', 'lower_c', 'lower_nc', 'upper_nc', 'upper_c', 'upper_nr']
    for i, thresh_name in enumerate(threshold_names):
        if len(parts) > 4 + i:
            thresh_str = parts[4 + i]
            if thresh_str and thresh_str not in ('na', 'n/a', ''):
                try:
                    thresholds[thresh_name] = float(thresh_str)
                except ValueError:
                    pass

    # Determine sensor type based on units and name
    sensor_type = categorize_sensor(name, units)

    return {
        'name': name,
        'value': value,
        'units': units,
        'status': status.lower(),
        'type': sensor_type,
        'thresholds': thresholds,
    }


def categorize_sensor(name: str, units: str) -> str:
    """Categorize sensor type based on name and units."""
    name_lower = name.lower()
    units_lower = units.lower()

    if 'degrees' in units_lower or 'temp' in name_lower:
        return 'temperature'
    elif 'rpm' in units_lower or 'fan' in name_lower:
        return 'fan'
    elif 'volts' in units_lower or 'voltage' in name_lower:
        return 'voltage'
    elif 'watts' in units_lower or 'power' in name_lower or 'pwr' in name_lower:
        return 'power'
    elif 'amps' in units_lower or 'current' in name_lower:
        return 'current'
    elif 'intrusion' in name_lower or 'chassis' in name_lower:
        return 'intrusion'
    elif 'psu' in name_lower or 'ps' in name_lower or 'supply' in name_lower:
        return 'psu'
    else:
        return 'other'


def get_sensor_readings() -> List[Dict[str, Any]]:
    """Get all IPMI sensor readings."""
    output = run_ipmitool(['sensor', 'list'])
    if output is None:
        return []

    sensors = []
    for line in output.strip().split('\n'):
        sensor = parse_sensor_line(line)
        if sensor:
            sensors.append(sensor)

    return sensors


def get_sdr_data() -> List[Dict[str, Any]]:
    """Get SDR (Sensor Data Record) readings as alternative/supplement."""
    output = run_ipmitool(['sdr', 'list', 'full'])
    if output is None:
        return []

    sensors = []
    for line in output.strip().split('\n'):
        if not line.strip() or '|' not in line:
            continue

        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 3:
            name = parts[0]
            value_str = parts[1]
            status = parts[2] if len(parts) > 2 else 'unknown'

            # Parse value and units
            value = None
            units = ''
            if value_str and value_str not in ('na', 'n/a', 'disabled', 'no reading'):
                # Extract numeric value and units from strings like "45 degrees C"
                match = re.match(r'([\d.]+)\s*(.*)$', value_str)
                if match:
                    try:
                        value = float(match.group(1))
                        units = match.group(2).strip()
                    except ValueError:
                        pass

            sensor_type = categorize_sensor(name, units)

            sensors.append({
                'name': name,
                'value': value,
                'units': units,
                'status': status.lower(),
                'type': sensor_type,
                'thresholds': {},
            })

    return sensors


def determine_severity(status: str) -> str:
    """Map IPMI status to severity level."""
    status_lower = status.lower()

    if status_lower in ('ok', 'ns', 'na'):
        return 'ok'
    elif 'cr' in status_lower or 'critical' in status_lower:
        return 'critical'
    elif 'nr' in status_lower or 'non-recoverable' in status_lower:
        return 'critical'
    elif 'nc' in status_lower or 'non-critical' in status_lower:
        return 'warning'
    elif 'lnr' in status_lower or 'unr' in status_lower:
        return 'critical'
    elif 'lcr' in status_lower or 'ucr' in status_lower:
        return 'critical'
    elif 'lnc' in status_lower or 'unc' in status_lower:
        return 'warning'
    elif status_lower in ('disabled', 'not available'):
        return 'ok'
    else:
        # Unknown status - treat as warning
        return 'warning' if status_lower and status_lower != 'ok' else 'ok'


def analyze_sensors(sensors: List[Dict[str, Any]],
                    temp_warn: float = 75.0,
                    temp_crit: float = 85.0) -> List[Dict[str, Any]]:
    """Analyze sensors and add severity assessment."""
    for sensor in sensors:
        status = sensor.get('status', '')
        value = sensor.get('value')
        sensor_type = sensor.get('type', '')

        # Start with status-based severity
        severity = determine_severity(status)

        # Override with value-based checks for temperature sensors
        if sensor_type == 'temperature' and value is not None:
            if value >= temp_crit:
                severity = 'critical'
            elif value >= temp_warn:
                severity = 'warning'
            elif severity == 'ok':
                severity = 'ok'

        # Check fan sensors - 0 RPM is usually bad
        if sensor_type == 'fan' and value is not None:
            if value == 0 and 'ok' not in status.lower():
                severity = 'critical'

        sensor['severity'] = severity

    return sensors


def format_value(value: Optional[float], units: str) -> str:
    """Format sensor value with units for display."""
    if value is None:
        return 'N/A'

    # Format based on units
    if 'degrees' in units.lower():
        return f"{value:.1f}°C"
    elif 'rpm' in units.lower():
        return f"{value:.0f} RPM"
    elif 'volts' in units.lower():
        return f"{value:.3f}V"
    elif 'watts' in units.lower():
        return f"{value:.1f}W"
    elif 'amps' in units.lower():
        return f"{value:.2f}A"
    else:
        return f"{value:.2f} {units}"


def output_plain(sensors: List[Dict[str, Any]], warn_only: bool, verbose: bool):
    """Output in plain text format."""
    if warn_only:
        sensors = [s for s in sensors if s.get('severity') != 'ok']

    if not sensors:
        print("All sensors within normal thresholds." if warn_only else "No sensors found.")
        return

    # Group by type
    by_type = defaultdict(list)
    for sensor in sensors:
        by_type[sensor['type']].append(sensor)

    type_order = ['temperature', 'fan', 'voltage', 'power', 'current', 'psu', 'intrusion', 'other']

    for sensor_type in type_order:
        type_sensors = by_type.get(sensor_type, [])
        if not type_sensors:
            continue

        # Filter for this type
        if warn_only:
            type_sensors = [s for s in type_sensors if s.get('severity') != 'ok']
            if not type_sensors:
                continue

        print(f"\n=== {sensor_type.upper()} SENSORS ===")

        for sensor in type_sensors:
            severity = sensor.get('severity', 'unknown').upper()
            status_icon = '✓' if severity == 'OK' else '⚠' if severity == 'WARNING' else '✗'

            value_str = format_value(sensor.get('value'), sensor.get('units', ''))
            print(f"{status_icon} {sensor['name']}: {value_str} [{severity}]")

            if verbose and sensor.get('thresholds'):
                thresh = sensor['thresholds']
                if 'upper_c' in thresh:
                    print(f"    Critical threshold: {thresh['upper_c']}")
                if 'upper_nc' in thresh:
                    print(f"    Warning threshold: {thresh['upper_nc']}")


def output_json(sensors: List[Dict[str, Any]], warn_only: bool, verbose: bool):
    """Output in JSON format."""
    if warn_only:
        sensors = [s for s in sensors if s.get('severity') != 'ok']

    # Summary stats
    summary = {
        'total': len(sensors),
        'ok': sum(1 for s in sensors if s.get('severity') == 'ok'),
        'warning': sum(1 for s in sensors if s.get('severity') == 'warning'),
        'critical': sum(1 for s in sensors if s.get('severity') == 'critical'),
    }

    # Group by type for summary
    by_type = defaultdict(int)
    for sensor in sensors:
        by_type[sensor['type']] += 1

    output = {
        'summary': summary,
        'by_type': dict(by_type),
        'sensors': sensors,
    }

    print(json.dumps(output, indent=2))


def output_table(sensors: List[Dict[str, Any]], warn_only: bool, verbose: bool):
    """Output in table format."""
    if warn_only:
        sensors = [s for s in sensors if s.get('severity') != 'ok']

    if not sensors:
        print("No sensors to display.")
        return

    # Header
    print(f"{'Severity':<10} {'Type':<12} {'Name':<30} {'Value':<15} {'Status':<10}")
    print("=" * 80)

    # Sort by severity (critical first)
    severity_order = {'critical': 0, 'warning': 1, 'ok': 2}
    sensors.sort(key=lambda s: severity_order.get(s.get('severity', 'ok'), 3))

    for sensor in sensors:
        severity = sensor.get('severity', 'unknown').upper()
        sensor_type = sensor.get('type', 'unknown')[:11]
        name = sensor.get('name', 'unknown')[:29]
        value_str = format_value(sensor.get('value'), sensor.get('units', ''))[:14]
        status = sensor.get('status', 'unknown')[:9]

        print(f"{severity:<10} {sensor_type:<12} {name:<30} {value_str:<15} {status:<10}")

    # Summary
    print()
    critical = sum(1 for s in sensors if s.get('severity') == 'critical')
    warning = sum(1 for s in sensors if s.get('severity') == 'warning')
    print(f"Total: {len(sensors)} | Critical: {critical} | Warning: {warning}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor IPMI sensor readings for baremetal systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show all sensor readings
  %(prog)s

  # Show only sensors with warnings or critical status
  %(prog)s --warn-only

  # Output as JSON for monitoring integration
  %(prog)s --format json

  # Table format with custom temperature thresholds
  %(prog)s --format table --temp-warn 70 --temp-crit 80

  # Filter by sensor type
  %(prog)s --type temperature
  %(prog)s --type fan --type power

  # Verbose output with threshold information
  %(prog)s --verbose

Exit codes:
  0 - All sensors within normal thresholds
  1 - Sensors in warning or critical state
  2 - Usage error or ipmitool not available
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show sensors with warnings or critical status'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show additional details including thresholds'
    )

    parser.add_argument(
        '--type', '-t',
        action='append',
        choices=['temperature', 'fan', 'voltage', 'power', 'current', 'psu', 'intrusion', 'other'],
        help='Filter by sensor type (can be specified multiple times)'
    )

    parser.add_argument(
        '--temp-warn',
        type=float,
        default=75.0,
        metavar='CELSIUS',
        help='Temperature warning threshold in Celsius (default: %(default)s)'
    )

    parser.add_argument(
        '--temp-crit',
        type=float,
        default=85.0,
        metavar='CELSIUS',
        help='Temperature critical threshold in Celsius (default: %(default)s)'
    )

    parser.add_argument(
        '--use-sdr',
        action='store_true',
        help='Use SDR (Sensor Data Record) instead of sensor list'
    )

    args = parser.parse_args()

    # Check for ipmitool
    if not check_ipmitool_available():
        print("Error: 'ipmitool' command not found.", file=sys.stderr)
        print("Install ipmitool package:", file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt-get install ipmitool", file=sys.stderr)
        print("  RHEL/CentOS: sudo yum install ipmitool", file=sys.stderr)
        print("\nNote: IPMI requires proper BMC access and permissions.", file=sys.stderr)
        sys.exit(2)

    # Get sensor readings
    if args.use_sdr:
        sensors = get_sdr_data()
    else:
        sensors = get_sensor_readings()

    if not sensors:
        print("No sensor data available. Check IPMI/BMC access.", file=sys.stderr)
        sys.exit(1)

    # Filter by type if specified
    if args.type:
        sensors = [s for s in sensors if s.get('type') in args.type]

    # Analyze sensors
    sensors = analyze_sensors(sensors, args.temp_warn, args.temp_crit)

    # Output results
    if args.format == 'json':
        output_json(sensors, args.warn_only, args.verbose)
    elif args.format == 'table':
        output_table(sensors, args.warn_only, args.verbose)
    else:
        output_plain(sensors, args.warn_only, args.verbose)

    # Determine exit code
    has_critical = any(s.get('severity') == 'critical' for s in sensors)
    has_warning = any(s.get('severity') == 'warning' for s in sensors)

    if has_critical or has_warning:
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
