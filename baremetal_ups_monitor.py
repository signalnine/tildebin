#!/usr/bin/env python3
"""
Monitor UPS (Uninterruptible Power Supply) status on baremetal systems.

Checks UPS health using Network UPS Tools (NUT) or APC apcaccess including:
- Battery charge level and runtime remaining
- Input/output voltage and frequency
- UPS load percentage
- Battery status (charging, discharging, on battery)
- Alarms and fault conditions

Critical for datacenter environments where power failures can cause data loss
and unexpected outages. Supports proactive alerting before battery depletion.

Exit codes:
    0 - Success (UPS healthy, on line power)
    1 - Warning/Critical conditions (low battery, on battery, faults)
    2 - Usage error or missing dependencies
"""

import argparse
import json
import subprocess
import sys


def check_tool_available(tool_name):
    """Check if a command-line tool is available."""
    try:
        subprocess.run(
            ['which', tool_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def run_command(cmd):
    """Execute command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode == 0, result.stdout, result.stderr
    except FileNotFoundError:
        return False, '', f'Command not found: {cmd[0]}'
    except Exception as e:
        return False, '', str(e)


def get_nut_ups_list():
    """Get list of UPS devices from NUT."""
    success, stdout, stderr = run_command(['upsc', '-l'])
    if not success:
        return []

    ups_list = []
    for line in stdout.strip().split('\n'):
        if line.strip():
            ups_list.append(line.strip())

    return ups_list


def get_nut_ups_data(ups_name):
    """Get UPS data from NUT for a specific UPS."""
    success, stdout, stderr = run_command(['upsc', ups_name])
    if not success:
        return None

    data = {'name': ups_name, 'source': 'nut'}
    for line in stdout.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            data[key.strip()] = value.strip()

    return data


def get_apcaccess_data():
    """Get UPS data from apcaccess (APC UPS)."""
    success, stdout, stderr = run_command(['apcaccess'])
    if not success:
        return None

    data = {'name': 'apc', 'source': 'apcaccess'}
    for line in stdout.strip().split('\n'):
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                data[key] = value

    return data


def parse_numeric(value_str):
    """Parse a numeric value from a string, removing units."""
    if not value_str:
        return None

    # Remove common units and whitespace
    clean = value_str.split()[0] if value_str else ''
    try:
        return float(clean)
    except (ValueError, TypeError):
        return None


def analyze_ups_health(ups_data):
    """Analyze UPS data and determine health status."""
    health = {
        'status': 'OK',
        'issues': [],
        'warnings': [],
        'battery_charge': None,
        'runtime_minutes': None,
        'load_percent': None,
        'on_battery': False,
        'input_voltage': None,
        'output_voltage': None
    }

    if not ups_data:
        health['status'] = 'UNKNOWN'
        health['issues'].append('No UPS data available')
        return health

    source = ups_data.get('source', '')

    # Parse based on data source
    if source == 'nut':
        # NUT variable names
        status = ups_data.get('ups.status', '')
        health['battery_charge'] = parse_numeric(ups_data.get('battery.charge'))
        health['runtime_minutes'] = parse_numeric(ups_data.get('battery.runtime'))
        if health['runtime_minutes']:
            health['runtime_minutes'] = health['runtime_minutes'] / 60  # Convert to minutes
        health['load_percent'] = parse_numeric(ups_data.get('ups.load'))
        health['input_voltage'] = parse_numeric(ups_data.get('input.voltage'))
        health['output_voltage'] = parse_numeric(ups_data.get('output.voltage'))

        # Check status flags
        if 'OB' in status:
            health['on_battery'] = True
        if 'LB' in status:
            health['issues'].append('Low battery')
        if 'RB' in status:
            health['warnings'].append('Replace battery')
        if 'ALARM' in status:
            health['issues'].append('UPS alarm active')
        if 'FSD' in status:
            health['issues'].append('Forced shutdown in progress')

    elif source == 'apcaccess':
        # apcaccess variable names
        status = ups_data.get('STATUS', '')
        health['battery_charge'] = parse_numeric(ups_data.get('BCHARGE'))
        health['runtime_minutes'] = parse_numeric(ups_data.get('TIMELEFT'))
        health['load_percent'] = parse_numeric(ups_data.get('LOADPCT'))
        health['input_voltage'] = parse_numeric(ups_data.get('LINEV'))
        health['output_voltage'] = parse_numeric(ups_data.get('OUTPUTV'))

        # Check status
        if 'ONBATT' in status:
            health['on_battery'] = True
        if 'LOWBATT' in status:
            health['issues'].append('Low battery')
        if 'REPLACEBATT' in status:
            health['warnings'].append('Replace battery')
        if 'CAL' in status:
            health['warnings'].append('Calibration in progress')
        if 'OVERLOAD' in status:
            health['issues'].append('UPS overloaded')

    # Evaluate thresholds
    if health['on_battery']:
        health['warnings'].append('Running on battery power')

    if health['battery_charge'] is not None:
        if health['battery_charge'] < 20:
            health['issues'].append(f"Critical battery level: {health['battery_charge']:.0f}%")
        elif health['battery_charge'] < 50:
            health['warnings'].append(f"Low battery level: {health['battery_charge']:.0f}%")

    if health['runtime_minutes'] is not None:
        if health['runtime_minutes'] < 5:
            health['issues'].append(f"Critical runtime remaining: {health['runtime_minutes']:.1f} min")
        elif health['runtime_minutes'] < 15:
            health['warnings'].append(f"Low runtime remaining: {health['runtime_minutes']:.1f} min")

    if health['load_percent'] is not None:
        if health['load_percent'] > 90:
            health['issues'].append(f"UPS near capacity: {health['load_percent']:.0f}% load")
        elif health['load_percent'] > 75:
            health['warnings'].append(f"High UPS load: {health['load_percent']:.0f}%")

    # Determine overall status
    if health['issues']:
        health['status'] = 'CRITICAL'
    elif health['warnings']:
        health['status'] = 'WARNING'
    else:
        health['status'] = 'OK'

    return health


def collect_all_ups_data():
    """Collect UPS data from all available sources."""
    ups_units = []

    # Try NUT first
    if check_tool_available('upsc'):
        nut_list = get_nut_ups_list()
        for ups_name in nut_list:
            data = get_nut_ups_data(ups_name)
            if data:
                data['health'] = analyze_ups_health(data)
                ups_units.append(data)

    # Try apcaccess if no NUT devices or as fallback
    if check_tool_available('apcaccess'):
        apc_data = get_apcaccess_data()
        if apc_data and apc_data.get('STATUS'):
            apc_data['health'] = analyze_ups_health(apc_data)
            ups_units.append(apc_data)

    return ups_units


def format_plain(ups_units, warn_only=False, verbose=False):
    """Format UPS data as plain text."""
    output = []

    if not ups_units:
        output.append("No UPS devices found.")
        output.append("")
        output.append("Ensure NUT (upsc) or apcaccess is installed and configured:")
        output.append("  NUT: sudo apt-get install nut-client")
        output.append("  APC: sudo apt-get install apcupsd")
        return '\n'.join(output)

    # Summary
    critical_count = sum(1 for u in ups_units if u.get('health', {}).get('status') == 'CRITICAL')
    warning_count = sum(1 for u in ups_units if u.get('health', {}).get('status') == 'WARNING')

    if critical_count > 0:
        output.append(f"UPS Status: CRITICAL ({critical_count} critical issues)")
    elif warning_count > 0:
        output.append(f"UPS Status: WARNING ({warning_count} warnings)")
    else:
        output.append(f"UPS Status: OK ({len(ups_units)} UPS unit(s) healthy)")
    output.append("")

    for ups in ups_units:
        health = ups.get('health', {})

        # Filter if warn_only
        if warn_only and health.get('status') == 'OK':
            continue

        ups_name = ups.get('name', 'Unknown')
        source = ups.get('source', 'unknown')
        status = health.get('status', 'UNKNOWN')

        status_indicator = ""
        if status == 'CRITICAL':
            status_indicator = " [CRITICAL]"
        elif status == 'WARNING':
            status_indicator = " [WARNING]"

        output.append(f"UPS: {ups_name} ({source}){status_indicator}")

        # Key metrics
        if health.get('battery_charge') is not None:
            output.append(f"  Battery: {health['battery_charge']:.0f}%")

        if health.get('runtime_minutes') is not None:
            output.append(f"  Runtime: {health['runtime_minutes']:.1f} min")

        if health.get('load_percent') is not None:
            output.append(f"  Load: {health['load_percent']:.0f}%")

        if health.get('on_battery'):
            output.append("  Power: ON BATTERY")
        else:
            output.append("  Power: Online")

        if verbose:
            if health.get('input_voltage') is not None:
                output.append(f"  Input Voltage: {health['input_voltage']:.1f}V")
            if health.get('output_voltage') is not None:
                output.append(f"  Output Voltage: {health['output_voltage']:.1f}V")

        # Show issues and warnings
        for issue in health.get('issues', []):
            output.append(f"  CRITICAL: {issue}")

        for warning in health.get('warnings', []):
            output.append(f"  WARNING: {warning}")

        # Verbose: show all raw data
        if verbose:
            output.append("  Raw data:")
            for key, value in ups.items():
                if key not in ['health', 'name', 'source']:
                    output.append(f"    {key}: {value}")

        output.append("")

    return '\n'.join(output)


def format_json(ups_units, warn_only=False):
    """Format UPS data as JSON."""
    if warn_only:
        ups_units = [u for u in ups_units
                     if u.get('health', {}).get('status') != 'OK']

    summary = {
        'total_ups': len(ups_units),
        'critical': sum(1 for u in ups_units if u.get('health', {}).get('status') == 'CRITICAL'),
        'warning': sum(1 for u in ups_units if u.get('health', {}).get('status') == 'WARNING'),
        'ok': sum(1 for u in ups_units if u.get('health', {}).get('status') == 'OK')
    }

    return json.dumps({
        'ups_units': ups_units,
        'summary': summary
    }, indent=2)


def format_table(ups_units, warn_only=False):
    """Format UPS data as a table."""
    if warn_only:
        ups_units = [u for u in ups_units
                     if u.get('health', {}).get('status') != 'OK']

    if not ups_units:
        return "No UPS devices found." if not warn_only else "No UPS warnings detected."

    # Header
    header = f"{'NAME':<15} {'SOURCE':<12} {'BATTERY':<10} {'RUNTIME':<12} {'LOAD':<8} {'POWER':<12} {'STATUS':<10}"
    separator = '-' * len(header)
    rows = [header, separator]

    for ups in ups_units:
        health = ups.get('health', {})
        name = ups.get('name', 'Unknown')[:14]
        source = ups.get('source', 'unknown')[:11]

        battery = f"{health['battery_charge']:.0f}%" if health.get('battery_charge') is not None else 'N/A'
        runtime = f"{health['runtime_minutes']:.1f} min" if health.get('runtime_minutes') is not None else 'N/A'
        load = f"{health['load_percent']:.0f}%" if health.get('load_percent') is not None else 'N/A'
        power = 'ON BATTERY' if health.get('on_battery') else 'Online'
        status = health.get('status', 'UNKNOWN')

        row = f"{name:<15} {source:<12} {battery:<10} {runtime:<12} {load:<8} {power:<12} {status:<10}"
        rows.append(row)

    return '\n'.join(rows)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor UPS (Uninterruptible Power Supply) status on baremetal systems.',
        epilog='''
Examples:
  # Show UPS status
  baremetal_ups_monitor.py

  # Show only warnings and critical issues
  baremetal_ups_monitor.py --warn-only

  # Output as JSON for monitoring systems
  baremetal_ups_monitor.py --format json

  # Verbose output with all UPS data
  baremetal_ups_monitor.py --verbose

  # Table format for quick overview
  baremetal_ups_monitor.py --format table

Supported UPS software:
  - Network UPS Tools (NUT): upsc command
  - APC UPS Daemon: apcaccess command

Exit codes:
  0 - All UPS units healthy and on line power
  1 - Warning or critical conditions detected
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
        help='Show detailed UPS information including raw data'
    )

    args = parser.parse_args()

    # Check if any UPS tools are available
    has_nut = check_tool_available('upsc')
    has_apc = check_tool_available('apcaccess')

    if not has_nut and not has_apc:
        print("Error: No UPS monitoring tools found.", file=sys.stderr)
        print("", file=sys.stderr)
        print("Install one of the following:", file=sys.stderr)
        print("  NUT (Network UPS Tools):", file=sys.stderr)
        print("    Ubuntu/Debian: sudo apt-get install nut-client", file=sys.stderr)
        print("    RHEL/CentOS: sudo yum install nut-client", file=sys.stderr)
        print("", file=sys.stderr)
        print("  APC UPS Daemon:", file=sys.stderr)
        print("    Ubuntu/Debian: sudo apt-get install apcupsd", file=sys.stderr)
        print("    RHEL/CentOS: sudo yum install apcupsd", file=sys.stderr)
        return 2

    # Collect UPS data
    ups_units = collect_all_ups_data()

    # Format output
    if args.format == 'json':
        output = format_json(ups_units, args.warn_only)
    elif args.format == 'table':
        output = format_table(ups_units, args.warn_only)
    else:
        output = format_plain(ups_units, args.warn_only, args.verbose)

    print(output)

    # Determine exit code
    has_critical = any(u.get('health', {}).get('status') == 'CRITICAL' for u in ups_units)
    has_warning = any(u.get('health', {}).get('status') == 'WARNING' for u in ups_units)

    if has_critical or has_warning:
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
