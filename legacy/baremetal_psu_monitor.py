#!/usr/bin/env python3
"""
Monitor Power Supply Unit (PSU) health on baremetal systems via IPMI.

Checks PSU status including:
- Power supply presence and operational state
- Input/output voltage and current
- Power supply redundancy status
- Fan and thermal status within PSUs
- Wattage and power consumption

Critical for large-scale datacenter environments where PSU failures can
cause unexpected outages. Supports proactive alerting before failures occur.

Exit codes:
    0 - Success (all PSUs healthy)
    1 - Warning/Critical PSU conditions detected
    2 - Usage error or missing dependencies
"""

import argparse
import json
import re
import subprocess
import sys


def check_ipmitool_available():
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


def run_command(cmd):
    """Execute command and return stdout."""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return None


def get_sdr_psu_sensors():
    """Get PSU-related sensor data from SDR."""
    output = run_command(['ipmitool', 'sdr', 'type', 'Power Supply'])
    if output is None:
        return []

    sensors = []
    for line in output.strip().split('\n'):
        if not line.strip():
            continue

        # Parse SDR format: Name | ID | Status | Entity | Reading
        # Example: "PS1 Status       | 60h | ok  |  10.1 | Presence detected"
        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 4:
            sensor = {
                'name': parts[0],
                'id': parts[1] if len(parts) > 1 else '',
                'status': parts[2] if len(parts) > 2 else '',
                'entity': parts[3] if len(parts) > 3 else '',
                'reading': parts[4] if len(parts) > 4 else '',
                'type': 'power_supply'
            }
            sensors.append(sensor)

    return sensors


def get_sdr_voltage_sensors():
    """Get voltage sensor data that may relate to PSUs."""
    output = run_command(['ipmitool', 'sdr', 'type', 'Voltage'])
    if output is None:
        return []

    sensors = []
    for line in output.strip().split('\n'):
        if not line.strip():
            continue

        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 4:
            # Filter for PSU-related voltage sensors
            name_lower = parts[0].lower()
            if any(kw in name_lower for kw in ['ps', 'psu', 'power', 'input', '12v', '5v', '3.3v']):
                sensor = {
                    'name': parts[0],
                    'id': parts[1] if len(parts) > 1 else '',
                    'status': parts[2] if len(parts) > 2 else '',
                    'entity': parts[3] if len(parts) > 3 else '',
                    'reading': parts[4] if len(parts) > 4 else '',
                    'type': 'voltage'
                }
                sensors.append(sensor)

    return sensors


def get_sdr_current_sensors():
    """Get current sensor data that may relate to PSUs."""
    output = run_command(['ipmitool', 'sdr', 'type', 'Current'])
    if output is None:
        return []

    sensors = []
    for line in output.strip().split('\n'):
        if not line.strip():
            continue

        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 4:
            sensor = {
                'name': parts[0],
                'id': parts[1] if len(parts) > 1 else '',
                'status': parts[2] if len(parts) > 2 else '',
                'entity': parts[3] if len(parts) > 3 else '',
                'reading': parts[4] if len(parts) > 4 else '',
                'type': 'current'
            }
            sensors.append(sensor)

    return sensors


def get_fru_psu_info():
    """Get PSU information from FRU data."""
    output = run_command(['ipmitool', 'fru', 'print'])
    if output is None:
        return []

    psus = []
    current_fru = None
    current_data = {}

    for line in output.split('\n'):
        # FRU Device Description line starts a new FRU
        if 'FRU Device Description' in line:
            if current_fru and 'power' in current_fru.lower():
                psus.append(current_data.copy())
            match = re.search(r'FRU Device Description\s*:\s*(.+)', line)
            if match:
                current_fru = match.group(1).strip()
                current_data = {'fru_name': current_fru}
            continue

        # Parse key-value pairs
        if ':' in line and current_fru:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            if value:
                current_data[key] = value

    # Don't forget last FRU
    if current_fru and 'power' in current_fru.lower():
        psus.append(current_data)

    return psus


def get_dcmi_power_reading():
    """Get DCMI power reading if supported."""
    output = run_command(['ipmitool', 'dcmi', 'power', 'reading'])
    if output is None:
        return None

    power_data = {}
    for line in output.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            power_data[key.strip()] = value.strip()

    return power_data if power_data else None


def categorize_sensor_status(status_str, reading_str):
    """Categorize sensor health based on status and reading."""
    status_lower = status_str.lower()
    reading_lower = reading_str.lower() if reading_str else ''

    # Critical conditions
    critical_keywords = [
        'failure', 'failed', 'fault', 'critical', 'non-recoverable',
        'not present', 'power off', 'predictive failure', 'ac lost'
    ]
    for kw in critical_keywords:
        if kw in status_lower or kw in reading_lower:
            return 'CRITICAL'

    # Warning conditions
    warning_keywords = [
        'degraded', 'redundancy lost', 'warning', 'non-critical',
        'power cycle', 'config error', 'mismatch'
    ]
    for kw in warning_keywords:
        if kw in status_lower or kw in reading_lower:
            return 'WARNING'

    # OK conditions
    ok_keywords = ['ok', 'presence detected', 'fully redundant', 'normal']
    for kw in ok_keywords:
        if kw in status_lower or kw in reading_lower:
            return 'OK'

    # If status contains 'ns' or 'na', it's not available
    if status_lower in ['ns', 'na', 'disabled']:
        return 'UNKNOWN'

    # Default to unknown for unparseable status
    return 'UNKNOWN'


def collect_psu_data():
    """Collect all PSU-related data from various IPMI sources."""
    data = {
        'psu_sensors': [],
        'voltage_sensors': [],
        'current_sensors': [],
        'fru_info': [],
        'power_reading': None,
        'summary': {
            'total_psus': 0,
            'healthy': 0,
            'warning': 0,
            'critical': 0,
            'unknown': 0
        }
    }

    # Get PSU sensors
    psu_sensors = get_sdr_psu_sensors()
    for sensor in psu_sensors:
        sensor['health'] = categorize_sensor_status(
            sensor.get('status', ''),
            sensor.get('reading', '')
        )
    data['psu_sensors'] = psu_sensors

    # Get voltage sensors
    data['voltage_sensors'] = get_sdr_voltage_sensors()
    for sensor in data['voltage_sensors']:
        sensor['health'] = categorize_sensor_status(
            sensor.get('status', ''),
            sensor.get('reading', '')
        )

    # Get current sensors
    data['current_sensors'] = get_sdr_current_sensors()
    for sensor in data['current_sensors']:
        sensor['health'] = categorize_sensor_status(
            sensor.get('status', ''),
            sensor.get('reading', '')
        )

    # Get FRU info
    data['fru_info'] = get_fru_psu_info()

    # Get DCMI power reading
    data['power_reading'] = get_dcmi_power_reading()

    # Calculate summary
    all_sensors = psu_sensors + data['voltage_sensors'] + data['current_sensors']
    data['summary']['total_psus'] = len(psu_sensors)

    for sensor in all_sensors:
        health = sensor.get('health', 'UNKNOWN')
        if health == 'OK':
            data['summary']['healthy'] += 1
        elif health == 'WARNING':
            data['summary']['warning'] += 1
        elif health == 'CRITICAL':
            data['summary']['critical'] += 1
        else:
            data['summary']['unknown'] += 1

    return data


def format_plain(data, warn_only=False, verbose=False):
    """Format PSU data as plain text."""
    output = []

    psu_sensors = data['psu_sensors']
    voltage_sensors = data['voltage_sensors']
    current_sensors = data['current_sensors']
    fru_info = data['fru_info']
    power_reading = data['power_reading']
    summary = data['summary']

    # Filter if warn_only
    if warn_only:
        psu_sensors = [s for s in psu_sensors if s.get('health') in ['WARNING', 'CRITICAL']]
        voltage_sensors = [s for s in voltage_sensors if s.get('health') in ['WARNING', 'CRITICAL']]
        current_sensors = [s for s in current_sensors if s.get('health') in ['WARNING', 'CRITICAL']]

    # Summary line
    if summary['critical'] > 0:
        output.append(f"PSU Status: CRITICAL ({summary['critical']} critical issues)")
    elif summary['warning'] > 0:
        output.append(f"PSU Status: WARNING ({summary['warning']} warnings)")
    else:
        output.append(f"PSU Status: OK ({summary['healthy']} sensors healthy)")
    output.append("")

    # Power Supply Sensors
    if psu_sensors:
        output.append("Power Supply Units:")
        for sensor in psu_sensors:
            health_indicator = ""
            if sensor['health'] == 'CRITICAL':
                health_indicator = " [CRITICAL]"
            elif sensor['health'] == 'WARNING':
                health_indicator = " [WARNING]"

            output.append(f"  {sensor['name']}: {sensor['reading']}{health_indicator}")
        output.append("")

    # Voltage sensors (if verbose or warn_only with issues)
    if voltage_sensors and (verbose or warn_only):
        output.append("Voltage Sensors:")
        for sensor in voltage_sensors:
            health_indicator = ""
            if sensor['health'] == 'CRITICAL':
                health_indicator = " [CRITICAL]"
            elif sensor['health'] == 'WARNING':
                health_indicator = " [WARNING]"

            output.append(f"  {sensor['name']}: {sensor['reading']}{health_indicator}")
        output.append("")

    # Current sensors (if verbose or warn_only with issues)
    if current_sensors and (verbose or warn_only):
        output.append("Current Sensors:")
        for sensor in current_sensors:
            health_indicator = ""
            if sensor['health'] == 'CRITICAL':
                health_indicator = " [CRITICAL]"
            elif sensor['health'] == 'WARNING':
                health_indicator = " [WARNING]"

            output.append(f"  {sensor['name']}: {sensor['reading']}{health_indicator}")
        output.append("")

    # FRU info (verbose only)
    if fru_info and verbose:
        output.append("PSU FRU Information:")
        for fru in fru_info:
            output.append(f"  {fru.get('fru_name', 'Unknown PSU')}:")
            for key, value in fru.items():
                if key != 'fru_name':
                    output.append(f"    {key}: {value}")
        output.append("")

    # Power reading (verbose only)
    if power_reading and verbose:
        output.append("System Power Reading:")
        for key, value in power_reading.items():
            output.append(f"  {key}: {value}")
        output.append("")

    if not psu_sensors and not voltage_sensors and not current_sensors:
        if warn_only:
            output.append("No PSU warnings or critical conditions detected.")
        else:
            output.append("No PSU sensors found. IPMI may not support PSU monitoring on this system.")

    return '\n'.join(output)


def format_json(data, warn_only=False):
    """Format PSU data as JSON."""
    if warn_only:
        data = data.copy()
        data['psu_sensors'] = [s for s in data['psu_sensors']
                               if s.get('health') in ['WARNING', 'CRITICAL']]
        data['voltage_sensors'] = [s for s in data['voltage_sensors']
                                   if s.get('health') in ['WARNING', 'CRITICAL']]
        data['current_sensors'] = [s for s in data['current_sensors']
                                   if s.get('health') in ['WARNING', 'CRITICAL']]

    return json.dumps(data, indent=2)


def format_table(data, warn_only=False):
    """Format PSU data as a table."""
    all_sensors = (data['psu_sensors'] +
                   data['voltage_sensors'] +
                   data['current_sensors'])

    if warn_only:
        all_sensors = [s for s in all_sensors if s.get('health') in ['WARNING', 'CRITICAL']]

    if not all_sensors:
        return "No PSU sensors found." if not warn_only else "No PSU warnings detected."

    # Header
    header = f"{'NAME':<25} {'TYPE':<15} {'STATUS':<10} {'READING':<25} {'HEALTH':<10}"
    separator = '-' * len(header)
    rows = [header, separator]

    for sensor in all_sensors:
        name = sensor.get('name', '')[:24]
        sensor_type = sensor.get('type', '')[:14]
        status = sensor.get('status', '')[:9]
        reading = sensor.get('reading', '')[:24]
        health = sensor.get('health', 'UNKNOWN')

        row = f"{name:<25} {sensor_type:<15} {status:<10} {reading:<25} {health:<10}"
        rows.append(row)

    return '\n'.join(rows)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Power Supply Unit (PSU) health on baremetal systems.',
        epilog='''
Examples:
  # Show PSU status
  baremetal_psu_monitor.py

  # Show only warnings and critical issues
  baremetal_psu_monitor.py --warn-only

  # Output as JSON for monitoring systems
  baremetal_psu_monitor.py --format json

  # Verbose output with FRU and power reading
  baremetal_psu_monitor.py --verbose

  # Table format for quick overview
  baremetal_psu_monitor.py --format table

Exit codes:
  0 - All PSUs healthy
  1 - Warning or critical PSU conditions detected
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
        help='Only show warning and critical conditions'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed PSU information including FRU data'
    )

    args = parser.parse_args()

    # Check if ipmitool is available
    if not check_ipmitool_available():
        print("Error: 'ipmitool' command not found.", file=sys.stderr)
        print("Install ipmitool package:", file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt-get install ipmitool", file=sys.stderr)
        print("  RHEL/CentOS: sudo yum install ipmitool", file=sys.stderr)
        print("\nNote: IPMI requires root privileges or proper user permissions.",
              file=sys.stderr)
        return 2

    # Collect PSU data
    data = collect_psu_data()

    # Format output
    if args.format == 'json':
        output = format_json(data, args.warn_only)
    elif args.format == 'table':
        output = format_table(data, args.warn_only)
    else:
        output = format_plain(data, args.warn_only, args.verbose)

    print(output)

    # Determine exit code based on health status
    if data['summary']['critical'] > 0:
        return 1
    if data['summary']['warning'] > 0:
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
