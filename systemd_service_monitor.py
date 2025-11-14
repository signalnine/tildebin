#!/usr/bin/env python3
"""
Systemd Service Health Monitor

Monitors systemd services and reports on their health status. Identifies failed,
degraded, or problematic units across the system.

Exit codes:
    0 - All services are healthy (active/running)
    1 - One or more services are failed, degraded, or in problematic states
    2 - systemctl not available or usage error

Use cases:
    - Automated monitoring of service health in baremetal fleets
    - Pre-deployment health checks
    - Troubleshooting systemd service issues
    - Identifying services requiring manual intervention
    - Integration with monitoring systems (Prometheus, Nagios, etc.)

Examples:
    # Check all services, show only problems
    systemd_service_monitor.py --warn-only

    # Check specific service types
    systemd_service_monitor.py --type service

    # Get JSON output for monitoring integration
    systemd_service_monitor.py --format json

    # Verbose output with details
    systemd_service_monitor.py --verbose

    # Check specific units matching a pattern
    systemd_service_monitor.py --filter "nginx*"
"""

import argparse
import json
import subprocess
import sys
from typing import List, Dict, Any


def run_command(cmd: List[str]) -> str:
    """
    Execute a shell command and return output.

    Args:
        cmd: Command and arguments as list

    Returns:
        Command stdout as string

    Raises:
        SystemExit: If command fails
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        print(f"Error: {cmd[0]} not found", file=sys.stderr)
        print("This tool requires systemd/systemctl", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        # systemctl list-units can return non-zero even in normal operation
        # Return the output anyway
        return e.stdout if e.stdout else ""


def check_systemctl_available() -> bool:
    """
    Check if systemctl is available.

    Returns:
        True if available, exits otherwise
    """
    try:
        subprocess.run(
            ['systemctl', '--version'],
            capture_output=True,
            check=True
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("Error: systemctl not found or not functional", file=sys.stderr)
        print("This tool requires systemd", file=sys.stderr)
        sys.exit(2)


def get_systemd_units(unit_type: str = None, pattern: str = None) -> List[Dict[str, str]]:
    """
    Get list of systemd units with their status.

    Args:
        unit_type: Filter by unit type (service, timer, socket, etc.)
        pattern: Filter units matching pattern (e.g., "nginx*")

    Returns:
        List of unit dictionaries with name, load, active, sub, description
    """
    cmd = ['systemctl', 'list-units', '--all', '--no-pager', '--plain', '--no-legend']

    if unit_type:
        cmd.append(f'--type={unit_type}')

    if pattern:
        cmd.append(pattern)

    output = run_command(cmd)
    units = []

    for line in output.strip().split('\n'):
        if not line.strip():
            continue

        # systemctl list-units output format:
        # UNIT LOAD ACTIVE SUB DESCRIPTION...
        parts = line.split(None, 4)
        if len(parts) >= 4:
            unit = {
                'name': parts[0],
                'load': parts[1],
                'active': parts[2],
                'sub': parts[3],
                'description': parts[4] if len(parts) > 4 else ''
            }
            units.append(unit)

    return units


def get_failed_units() -> List[str]:
    """
    Get list of failed unit names.

    Returns:
        List of failed unit names
    """
    cmd = ['systemctl', 'list-units', '--failed', '--no-pager', '--plain', '--no-legend']
    output = run_command(cmd)

    failed = []
    for line in output.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if parts:
            failed.append(parts[0])

    return failed


def is_problematic_unit(unit: Dict[str, str]) -> bool:
    """
    Determine if a unit is in a problematic state.

    Args:
        unit: Unit dictionary

    Returns:
        True if unit has issues
    """
    # Failed states - these are always problems
    if unit['active'] == 'failed':
        return True

    # Load errors (but not not-found units which are just references)
    # error and masked are actual problems with loaded units
    if unit['load'] in ['error']:
        return True

    # Substate failed is always a problem
    if unit['sub'] == 'failed':
        return True

    # Inactive services are only a problem if they failed
    # (inactive/dead is normal for services that haven't been started)
    # not-found units are references and not actual problems

    return False


def get_unit_details(unit_name: str) -> Dict[str, Any]:
    """
    Get detailed information about a unit.

    Args:
        unit_name: Name of the unit

    Returns:
        Dictionary with detailed unit information
    """
    cmd = ['systemctl', 'show', unit_name, '--no-pager']
    output = run_command(cmd)

    details = {}
    for line in output.strip().split('\n'):
        if '=' in line:
            key, value = line.split('=', 1)
            details[key] = value

    return details


def format_plain_output(units: List[Dict[str, str]], verbose: bool = False, warn_only: bool = False) -> str:
    """
    Format output as plain text.

    Args:
        units: List of unit dictionaries
        verbose: Include detailed information
        warn_only: Only show problematic units

    Returns:
        Formatted string
    """
    output_lines = []

    problematic = [u for u in units if is_problematic_unit(u)]
    healthy = [u for u in units if not is_problematic_unit(u)]

    if warn_only:
        units_to_show = problematic
    else:
        units_to_show = units

    if not warn_only:
        output_lines.append(f"Systemd Service Health Summary")
        output_lines.append(f"Total units: {len(units)}")
        output_lines.append(f"Problematic: {len(problematic)}")
        output_lines.append(f"Healthy: {len(healthy)}")
        output_lines.append("")

    if units_to_show:
        if problematic and not warn_only:
            output_lines.append("Problematic Units:")
            output_lines.append("-" * 80)

        for unit in units_to_show:
            status_symbol = "✗" if is_problematic_unit(unit) else "✓"
            output_lines.append(
                f"{status_symbol} {unit['name']:40} {unit['active']:10} {unit['sub']:10}"
            )

            if verbose:
                details = get_unit_details(unit['name'])
                if 'LoadError' in details and details['LoadError']:
                    output_lines.append(f"  Load Error: {details['LoadError']}")
                if 'Result' in details and details['Result'] != 'success':
                    output_lines.append(f"  Result: {details['Result']}")
                output_lines.append("")
    else:
        if warn_only:
            output_lines.append("All units are healthy")

    return '\n'.join(output_lines)


def format_json_output(units: List[Dict[str, str]], verbose: bool = False) -> str:
    """
    Format output as JSON.

    Args:
        units: List of unit dictionaries
        verbose: Include detailed information

    Returns:
        JSON string
    """
    problematic = [u for u in units if is_problematic_unit(u)]
    healthy = [u for u in units if not is_problematic_unit(u)]

    result = {
        'summary': {
            'total': len(units),
            'problematic': len(problematic),
            'healthy': len(healthy)
        },
        'units': []
    }

    for unit in units:
        unit_data = {
            'name': unit['name'],
            'load': unit['load'],
            'active': unit['active'],
            'sub': unit['sub'],
            'description': unit['description'],
            'problematic': is_problematic_unit(unit)
        }

        if verbose and is_problematic_unit(unit):
            details = get_unit_details(unit['name'])
            unit_data['details'] = {
                'result': details.get('Result', ''),
                'load_error': details.get('LoadError', ''),
                'active_enter_timestamp': details.get('ActiveEnterTimestamp', ''),
                'active_exit_timestamp': details.get('ActiveExitTimestamp', '')
            }

        result['units'].append(unit_data)

    return json.dumps(result, indent=2)


def format_table_output(units: List[Dict[str, str]], warn_only: bool = False) -> str:
    """
    Format output as a table.

    Args:
        units: List of unit dictionaries
        warn_only: Only show problematic units

    Returns:
        Formatted table string
    """
    output_lines = []

    problematic = [u for u in units if is_problematic_unit(u)]

    if warn_only:
        units_to_show = problematic
    else:
        units_to_show = units

    # Header
    output_lines.append(f"{'STATUS':<8} {'UNIT':<45} {'ACTIVE':<12} {'SUB':<12} {'DESCRIPTION':<30}")
    output_lines.append("-" * 120)

    for unit in units_to_show:
        status = "PROBLEM" if is_problematic_unit(unit) else "OK"
        desc = unit['description'][:30] if len(unit['description']) > 30 else unit['description']
        output_lines.append(
            f"{status:<8} {unit['name']:<45} {unit['active']:<12} {unit['sub']:<12} {desc:<30}"
        )

    output_lines.append("")
    output_lines.append(f"Total: {len(units)} | Problematic: {len(problematic)} | Healthy: {len(units) - len(problematic)}")

    return '\n'.join(output_lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor systemd service health and identify problematic units',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  systemd_service_monitor.py                    # Check all units
  systemd_service_monitor.py --warn-only        # Show only problems
  systemd_service_monitor.py --type service     # Check only services
  systemd_service_monitor.py --format json      # JSON output
  systemd_service_monitor.py --filter "nginx*"  # Filter by pattern
  systemd_service_monitor.py -v                 # Verbose output

Exit codes:
  0 - All services healthy
  1 - One or more services have issues
  2 - systemctl not available or usage error
        """
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
        help='Only show problematic units'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )
    parser.add_argument(
        '-t', '--type',
        help='Filter by unit type (service, timer, socket, etc.)'
    )
    parser.add_argument(
        '--filter',
        help='Filter units by pattern (e.g., "nginx*")'
    )

    args = parser.parse_args()

    # Check dependencies
    check_systemctl_available()

    # Get units
    units = get_systemd_units(unit_type=args.type, pattern=args.filter)

    if not units:
        print("No units found matching criteria", file=sys.stderr)
        sys.exit(0)

    # Format output
    if args.format == 'json':
        print(format_json_output(units, verbose=args.verbose))
    elif args.format == 'table':
        print(format_table_output(units, warn_only=args.warn_only))
    else:
        print(format_plain_output(units, verbose=args.verbose, warn_only=args.warn_only))

    # Determine exit code
    problematic_count = sum(1 for u in units if is_problematic_unit(u))
    sys.exit(1 if problematic_count > 0 else 0)


if __name__ == '__main__':
    main()
