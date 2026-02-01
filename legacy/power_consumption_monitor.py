#!/usr/bin/env python3
"""
Monitor power consumption on baremetal systems.

Monitors server power consumption using IPMI sensors and turbostat (for Intel CPUs).
Useful for tracking datacenter energy usage, detecting anomalies, and capacity planning.

Exit codes:
  0 - Success (all power metrics retrieved)
  1 - Warning/Critical power levels detected
  2 - Usage error or missing dependencies
"""

import argparse
import json
import re
import subprocess
import sys


def check_tool_available(tool_name):
    """Check if a system tool is available."""
    try:
        result = subprocess.run(
            ['which', tool_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_ipmi_power():
    """
    Get power consumption from IPMI sensors.

    Returns list of power sensor readings.
    """
    readings = []

    try:
        result = subprocess.run(
            ['ipmitool', 'sensor', 'list'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return readings

        # Parse IPMI sensor output
        # Format: Sensor Name | Value | Units | Status | LNR | LC | LNC | UNC | UC | UNR
        for line in result.stdout.split('\n'):
            if not line.strip():
                continue

            # Look for power-related sensors (Watts or Amps)
            if 'Watts' in line or 'Amps' in line or 'Power' in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 3:
                    name = parts[0]
                    value_str = parts[1]
                    unit = parts[2]
                    status = parts[3] if len(parts) > 3 else 'ok'

                    # Parse numeric value
                    try:
                        value = float(value_str)
                    except (ValueError, TypeError):
                        continue

                    # Determine status
                    sensor_status = 'OK'
                    if 'nr' in status.lower() or 'nc' in status.lower():
                        sensor_status = 'CRITICAL'
                    elif 'cr' in status.lower():
                        sensor_status = 'WARNING'

                    readings.append({
                        'source': 'ipmi',
                        'sensor': name,
                        'value': value,
                        'unit': unit,
                        'status': sensor_status
                    })

    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return readings


def get_turbostat_power():
    """
    Get CPU package power from turbostat (Intel CPUs).

    Returns list of CPU package power readings.
    """
    readings = []

    try:
        # Run turbostat for 1 second to get power measurement
        result = subprocess.run(
            ['turbostat', '--quiet', '--show', 'PkgWatt', '--num_iterations', '1'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return readings

        # Parse turbostat output
        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:
            return readings

        # Find PkgWatt column
        headers = lines[0].split()
        if 'PkgWatt' not in headers:
            return readings

        pkgwatt_idx = headers.index('PkgWatt')

        # Parse data lines
        for line in lines[1:]:
            parts = line.split()
            if len(parts) > pkgwatt_idx:
                try:
                    value = float(parts[pkgwatt_idx])
                    readings.append({
                        'source': 'turbostat',
                        'sensor': 'CPU Package Power',
                        'value': value,
                        'unit': 'Watts',
                        'status': 'OK'
                    })
                except (ValueError, IndexError):
                    continue

    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return readings


def get_sysfs_power():
    """
    Get power readings from sysfs (RAPL - Running Average Power Limit).

    Returns list of power readings from /sys/class/powercap.
    """
    readings = []

    try:
        import os
        import glob

        # Find RAPL power zones
        rapl_dirs = glob.glob('/sys/class/powercap/intel-rapl/intel-rapl:*')

        for rapl_dir in rapl_dirs:
            try:
                # Read name
                name_file = os.path.join(rapl_dir, 'name')
                if not os.path.exists(name_file):
                    continue

                with open(name_file, 'r') as f:
                    name = f.read().strip()

                # Read energy counter (in microjoules)
                energy_file = os.path.join(rapl_dir, 'energy_uj')
                if not os.path.exists(energy_file):
                    continue

                with open(energy_file, 'r') as f:
                    energy_uj = int(f.read().strip())

                # Read max energy range to detect wraparound
                max_energy_file = os.path.join(rapl_dir, 'max_energy_range_uj')
                if os.path.exists(max_energy_file):
                    with open(max_energy_file, 'r') as f:
                        max_energy = int(f.read().strip())
                else:
                    max_energy = None

                readings.append({
                    'source': 'rapl',
                    'sensor': name,
                    'value': energy_uj / 1000000.0,  # Convert to Joules
                    'unit': 'Joules',
                    'max_range': max_energy / 1000000.0 if max_energy else None,
                    'status': 'OK'
                })

            except (IOError, ValueError, PermissionError):
                continue

    except Exception:
        pass

    return readings


def output_plain(readings, warn_only, verbose):
    """Output readings in plain text format."""
    has_warnings = False

    for reading in readings:
        if warn_only and reading['status'] == 'OK':
            continue

        if reading['status'] != 'OK':
            has_warnings = True

        status_indicator = ''
        if reading['status'] == 'WARNING':
            status_indicator = '[WARN] '
        elif reading['status'] == 'CRITICAL':
            status_indicator = '[CRIT] '

        if verbose:
            print(f"{status_indicator}{reading['source']:12} {reading['sensor']:30} {reading['value']:8.2f} {reading['unit']}")
        else:
            print(f"{status_indicator}{reading['sensor']:30} {reading['value']:8.2f} {reading['unit']}")

    return has_warnings


def output_json(readings):
    """Output readings in JSON format."""
    print(json.dumps(readings, indent=2))

    # Check for warnings
    has_warnings = any(r['status'] != 'OK' for r in readings)
    return has_warnings


def output_table(readings, warn_only):
    """Output readings in table format."""
    if warn_only:
        readings = [r for r in readings if r['status'] != 'OK']

    has_warnings = any(r['status'] != 'OK' for r in readings)

    # Print header
    print(f"{'Source':<12} {'Sensor':<30} {'Value':>10} {'Unit':<10} {'Status':<10}")
    print("-" * 74)

    # Print rows
    for reading in readings:
        print(f"{reading['source']:<12} {reading['sensor']:<30} "
              f"{reading['value']:>10.2f} {reading['unit']:<10} {reading['status']:<10}")

    return has_warnings


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor power consumption on baremetal systems",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including source'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings or critical readings'
    )

    parser.add_argument(
        '--skip-ipmi',
        action='store_true',
        help='Skip IPMI sensor checks'
    )

    parser.add_argument(
        '--skip-turbostat',
        action='store_true',
        help='Skip turbostat checks (requires root)'
    )

    parser.add_argument(
        '--skip-rapl',
        action='store_true',
        help='Skip RAPL/sysfs checks'
    )

    args = parser.parse_args()

    # Collect all power readings
    all_readings = []

    # Get IPMI power readings
    if not args.skip_ipmi:
        if check_tool_available('ipmitool'):
            ipmi_readings = get_ipmi_power()
            all_readings.extend(ipmi_readings)

    # Get turbostat readings (requires root)
    if not args.skip_turbostat:
        if check_tool_available('turbostat'):
            turbostat_readings = get_turbostat_power()
            all_readings.extend(turbostat_readings)

    # Get RAPL/sysfs readings
    if not args.skip_rapl:
        rapl_readings = get_sysfs_power()
        all_readings.extend(rapl_readings)

    # Check if we got any readings
    if not all_readings:
        print("Error: No power sensors found", file=sys.stderr)
        print("", file=sys.stderr)
        print("Ensure one of the following is available:", file=sys.stderr)
        print("  - ipmitool (install: apt-get install ipmitool)", file=sys.stderr)
        print("  - turbostat (part of linux-tools, requires root)", file=sys.stderr)
        print("  - RAPL sysfs (/sys/class/powercap/intel-rapl)", file=sys.stderr)
        sys.exit(2)

    # Output results
    has_warnings = False

    if args.format == 'json':
        has_warnings = output_json(all_readings)
    elif args.format == 'table':
        has_warnings = output_table(all_readings, args.warn_only)
    else:  # plain
        has_warnings = output_plain(all_readings, args.warn_only, args.verbose)

    # Exit with appropriate code
    sys.exit(1 if has_warnings else 0)


if __name__ == '__main__':
    main()
