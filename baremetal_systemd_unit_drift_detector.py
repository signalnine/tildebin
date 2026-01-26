#!/usr/bin/env python3
"""
Systemd Unit Drift Detector

Detects systemd unit files that have local overrides, drop-ins, or modifications
from their package-installed versions. Useful for security auditing, configuration
management, and ensuring fleet consistency.

Checks:
- Units with drop-in files (.d/*.conf overrides)
- Units masked locally
- Units with custom symlinks
- Package-installed units vs local modifications

Exit codes:
    0 - No drift detected (all units match package defaults)
    1 - Drift detected (overrides, drop-ins, or modifications found)
    2 - systemctl not available or usage error

Examples:
    # Check all services for drift
    baremetal_systemd_unit_drift_detector.py

    # Check specific unit types
    baremetal_systemd_unit_drift_detector.py --type service

    # Show only units with overrides
    baremetal_systemd_unit_drift_detector.py --warn-only

    # JSON output for automation
    baremetal_systemd_unit_drift_detector.py --format json

    # Check specific unit
    baremetal_systemd_unit_drift_detector.py --unit sshd.service
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Dict, List, Any, Optional


# Standard systemd unit paths in priority order
UNIT_PATHS = [
    '/etc/systemd/system',      # Local admin config (highest priority)
    '/run/systemd/system',      # Runtime config
    '/usr/local/lib/systemd/system',  # Local packages
    '/usr/lib/systemd/system',  # Distribution packages
    '/lib/systemd/system',      # Distribution packages (legacy)
]


def run_command(cmd: List[str], check: bool = True) -> tuple:
    """
    Execute a command and return (returncode, stdout, stderr).

    Args:
        cmd: Command and arguments as list
        check: If False, don't exit on failure

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        if check:
            print(f"Error: {cmd[0]} not found", file=sys.stderr)
            print("This tool requires systemd/systemctl", file=sys.stderr)
            sys.exit(2)
        return -1, "", f"{cmd[0]} not found"


def check_systemctl_available() -> bool:
    """Check if systemctl is available."""
    returncode, _, _ = run_command(['systemctl', '--version'], check=False)
    if returncode != 0:
        print("Error: systemctl not found or not functional", file=sys.stderr)
        print("This tool requires systemd", file=sys.stderr)
        sys.exit(2)
    return True


def get_unit_file_state(unit_name: str) -> Dict[str, str]:
    """
    Get the file state information for a unit.

    Args:
        unit_name: Name of the systemd unit

    Returns:
        Dictionary with unit file information
    """
    returncode, stdout, _ = run_command(
        ['systemctl', 'show', unit_name,
         '--property=UnitFileState,UnitFilePreset,FragmentPath,DropInPaths'],
        check=False
    )

    info = {
        'unit_file_state': '',
        'unit_file_preset': '',
        'fragment_path': '',
        'drop_in_paths': []
    }

    if returncode == 0:
        for line in stdout.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                if key == 'UnitFileState':
                    info['unit_file_state'] = value
                elif key == 'UnitFilePreset':
                    info['unit_file_preset'] = value
                elif key == 'FragmentPath':
                    info['fragment_path'] = value
                elif key == 'DropInPaths':
                    if value:
                        info['drop_in_paths'] = value.split()

    return info


def get_all_units(unit_type: Optional[str] = None) -> List[str]:
    """
    Get list of all unit files.

    Args:
        unit_type: Filter by unit type (service, timer, etc.)

    Returns:
        List of unit names
    """
    cmd = ['systemctl', 'list-unit-files', '--no-pager', '--no-legend']
    if unit_type:
        cmd.append(f'--type={unit_type}')

    returncode, stdout, _ = run_command(cmd)
    if returncode != 0:
        return []

    units = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if parts:
            units.append(parts[0])

    return units


def find_unit_file_locations(unit_name: str) -> Dict[str, str]:
    """
    Find all locations where a unit file exists.

    Args:
        unit_name: Name of the unit

    Returns:
        Dictionary mapping path type to full path
    """
    locations = {}

    for base_path in UNIT_PATHS:
        full_path = os.path.join(base_path, unit_name)
        if os.path.exists(full_path):
            if base_path == '/etc/systemd/system':
                locations['local_admin'] = full_path
            elif base_path == '/run/systemd/system':
                locations['runtime'] = full_path
            elif 'local' in base_path:
                locations['local_package'] = full_path
            else:
                locations['package'] = full_path

    return locations


def find_drop_in_files(unit_name: str) -> List[Dict[str, str]]:
    """
    Find all drop-in configuration files for a unit.

    Args:
        unit_name: Name of the unit

    Returns:
        List of drop-in file info dictionaries
    """
    drop_ins = []

    for base_path in UNIT_PATHS:
        drop_in_dir = os.path.join(base_path, f'{unit_name}.d')
        if os.path.isdir(drop_in_dir):
            try:
                for filename in sorted(os.listdir(drop_in_dir)):
                    if filename.endswith('.conf'):
                        full_path = os.path.join(drop_in_dir, filename)
                        drop_ins.append({
                            'path': full_path,
                            'filename': filename,
                            'base': base_path,
                            'is_local': base_path in ['/etc/systemd/system', '/run/systemd/system']
                        })
            except PermissionError:
                pass

    return drop_ins


def check_if_masked(unit_name: str) -> Dict[str, Any]:
    """
    Check if a unit is masked and how.

    Args:
        unit_name: Name of the unit

    Returns:
        Dictionary with mask information
    """
    result = {
        'is_masked': False,
        'mask_type': None,
        'mask_path': None
    }

    # Check common mask locations
    for base_path in ['/etc/systemd/system', '/run/systemd/system']:
        unit_path = os.path.join(base_path, unit_name)
        if os.path.islink(unit_path):
            target = os.readlink(unit_path)
            if target == '/dev/null':
                result['is_masked'] = True
                result['mask_type'] = 'runtime' if 'run' in base_path else 'persistent'
                result['mask_path'] = unit_path
                break

    return result


def analyze_unit_drift(unit_name: str) -> Dict[str, Any]:
    """
    Analyze a unit for configuration drift.

    Args:
        unit_name: Name of the unit

    Returns:
        Dictionary with drift analysis
    """
    analysis = {
        'unit': unit_name,
        'has_drift': False,
        'drift_reasons': [],
        'details': {}
    }

    # Get systemctl's view of the unit
    state_info = get_unit_file_state(unit_name)
    analysis['details']['state'] = state_info

    # Find all file locations
    locations = find_unit_file_locations(unit_name)
    analysis['details']['locations'] = locations

    # Check for local admin overrides
    if 'local_admin' in locations:
        if 'package' in locations:
            analysis['has_drift'] = True
            analysis['drift_reasons'].append('local_override')
        else:
            # Local-only unit (not from package)
            analysis['details']['is_local_only'] = True

    # Find drop-in files
    drop_ins = find_drop_in_files(unit_name)
    analysis['details']['drop_ins'] = drop_ins

    local_drop_ins = [d for d in drop_ins if d['is_local']]
    if local_drop_ins:
        analysis['has_drift'] = True
        analysis['drift_reasons'].append('has_drop_ins')
        analysis['details']['local_drop_in_count'] = len(local_drop_ins)

    # Check if masked
    mask_info = check_if_masked(unit_name)
    analysis['details']['mask_info'] = mask_info

    if mask_info['is_masked']:
        analysis['has_drift'] = True
        analysis['drift_reasons'].append('masked')

    # Check unit file state
    if state_info['unit_file_state'] == 'masked':
        if 'masked' not in analysis['drift_reasons']:
            analysis['has_drift'] = True
            analysis['drift_reasons'].append('masked')

    return analysis


def format_plain_output(results: List[Dict[str, Any]], verbose: bool = False,
                        warn_only: bool = False) -> str:
    """Format output as plain text."""
    lines = []

    drifted = [r for r in results if r['has_drift']]
    clean = [r for r in results if not r['has_drift']]

    if not warn_only:
        lines.append("Systemd Unit Drift Analysis")
        lines.append("=" * 60)
        lines.append(f"Total units checked: {len(results)}")
        lines.append(f"Units with drift: {len(drifted)}")
        lines.append(f"Clean units: {len(clean)}")
        lines.append("")

    if warn_only:
        units_to_show = drifted
    else:
        units_to_show = results

    if drifted and not warn_only:
        lines.append("Units with Configuration Drift:")
        lines.append("-" * 60)

    for result in units_to_show:
        if warn_only and not result['has_drift']:
            continue

        symbol = "!" if result['has_drift'] else " "
        reasons = ', '.join(result['drift_reasons']) if result['drift_reasons'] else 'none'

        lines.append(f"{symbol} {result['unit']}")
        if result['has_drift']:
            lines.append(f"    Drift: {reasons}")

            if verbose:
                details = result['details']

                # Show fragment path
                if details.get('state', {}).get('fragment_path'):
                    lines.append(f"    Path: {details['state']['fragment_path']}")

                # Show locations
                locations = details.get('locations', {})
                if 'local_admin' in locations:
                    lines.append(f"    Local override: {locations['local_admin']}")
                if 'package' in locations:
                    lines.append(f"    Package file: {locations['package']}")

                # Show drop-ins
                drop_ins = details.get('drop_ins', [])
                if drop_ins:
                    lines.append(f"    Drop-ins ({len(drop_ins)}):")
                    for d in drop_ins:
                        local_marker = " [local]" if d['is_local'] else ""
                        lines.append(f"      - {d['path']}{local_marker}")

                # Show mask info
                mask_info = details.get('mask_info', {})
                if mask_info.get('is_masked'):
                    lines.append(f"    Masked: {mask_info['mask_type']} at {mask_info['mask_path']}")

                lines.append("")

    if not drifted and warn_only:
        lines.append("No configuration drift detected")

    return '\n'.join(lines)


def format_json_output(results: List[Dict[str, Any]]) -> str:
    """Format output as JSON."""
    drifted = [r for r in results if r['has_drift']]

    output = {
        'summary': {
            'total_checked': len(results),
            'units_with_drift': len(drifted),
            'clean_units': len(results) - len(drifted)
        },
        'units': results
    }

    return json.dumps(output, indent=2)


def format_table_output(results: List[Dict[str, Any]], warn_only: bool = False) -> str:
    """Format output as a table."""
    lines = []

    drifted = [r for r in results if r['has_drift']]

    if warn_only:
        units_to_show = drifted
    else:
        units_to_show = results

    # Header
    lines.append(f"{'STATUS':<8} {'UNIT':<40} {'DRIFT REASONS':<30}")
    lines.append("-" * 80)

    for result in units_to_show:
        status = "DRIFT" if result['has_drift'] else "OK"
        reasons = ', '.join(result['drift_reasons']) if result['drift_reasons'] else '-'
        unit_name = result['unit'][:38] if len(result['unit']) > 38 else result['unit']
        lines.append(f"{status:<8} {unit_name:<40} {reasons:<30}")

    lines.append("-" * 80)
    lines.append(f"Total: {len(results)} | Drifted: {len(drifted)} | Clean: {len(results) - len(drifted)}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Detect systemd unit files with local overrides or modifications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  baremetal_systemd_unit_drift_detector.py                    # Check all units
  baremetal_systemd_unit_drift_detector.py --warn-only        # Show only drifted units
  baremetal_systemd_unit_drift_detector.py --type service     # Check only services
  baremetal_systemd_unit_drift_detector.py --format json      # JSON output
  baremetal_systemd_unit_drift_detector.py --unit sshd.service  # Check specific unit
  baremetal_systemd_unit_drift_detector.py -v                 # Verbose output

Drift types detected:
  local_override - Unit file exists in /etc/systemd/system overriding package version
  has_drop_ins   - Unit has drop-in configuration files (.d/*.conf)
  masked         - Unit is masked (symlinked to /dev/null)

Exit codes:
  0 - No drift detected
  1 - Configuration drift detected
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
        help='Only show units with drift'
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
        '-u', '--unit',
        help='Check a specific unit'
    )

    args = parser.parse_args()

    # Check dependencies
    check_systemctl_available()

    # Get units to check
    if args.unit:
        units = [args.unit]
    else:
        units = get_all_units(unit_type=args.type)

    if not units:
        print("No units found matching criteria", file=sys.stderr)
        sys.exit(0)

    # Analyze each unit
    results = []
    for unit in units:
        analysis = analyze_unit_drift(unit)
        results.append(analysis)

    # Format output
    if args.format == 'json':
        print(format_json_output(results))
    elif args.format == 'table':
        print(format_table_output(results, warn_only=args.warn_only))
    else:
        print(format_plain_output(results, verbose=args.verbose, warn_only=args.warn_only))

    # Determine exit code
    drift_count = sum(1 for r in results if r['has_drift'])
    sys.exit(1 if drift_count > 0 else 0)


if __name__ == '__main__':
    main()
