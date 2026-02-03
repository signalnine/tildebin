#!/usr/bin/env python3
# boxctl:
#   category: baremetal/power
#   tags: [health, power, energy, ipmi, rapl]
#   requires: []
#   privilege: root
#   related: [ipmi_sensor, psu_monitor]
#   brief: Monitor power consumption using IPMI and RAPL

"""
Monitor power consumption on baremetal systems.

Monitors server power consumption using IPMI sensors and RAPL (Intel).
Useful for tracking datacenter energy usage, detecting anomalies, and
capacity planning.

Returns exit code 1 if any power reading shows warning or critical status.
"""

import argparse
import glob
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_ipmi_power(context: Context) -> list[dict[str, Any]]:
    """Get power consumption from IPMI sensors."""
    readings = []

    if not context.check_tool("ipmitool"):
        return readings

    try:
        result = context.run(['ipmitool', 'sensor', 'list'], check=False, timeout=10)
        if result.returncode != 0:
            return readings

        for line in result.stdout.split('\n'):
            if not line.strip():
                continue

            # Look for power-related sensors
            if 'Watts' in line or 'Amps' in line or 'Power' in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 3:
                    name = parts[0]
                    value_str = parts[1]
                    unit = parts[2]
                    status_str = parts[3] if len(parts) > 3 else 'ok'

                    try:
                        value = float(value_str)
                    except (ValueError, TypeError):
                        continue

                    # Determine status
                    sensor_status = 'healthy'
                    if 'nr' in status_str.lower() or 'nc' in status_str.lower():
                        sensor_status = 'critical'
                    elif 'cr' in status_str.lower():
                        sensor_status = 'warning'

                    readings.append({
                        'source': 'ipmi',
                        'sensor': name,
                        'value': value,
                        'unit': unit,
                        'status': sensor_status
                    })
    except Exception:
        pass

    return readings


def get_rapl_power(context: Context) -> list[dict[str, Any]]:
    """Get power readings from RAPL (Intel)."""
    readings = []

    try:
        rapl_dirs = glob.glob('/sys/class/powercap/intel-rapl/intel-rapl:*')

        for rapl_dir in rapl_dirs:
            try:
                name_file = os.path.join(rapl_dir, 'name')
                if not os.path.exists(name_file):
                    continue

                with open(name_file, 'r') as f:
                    name = f.read().strip()

                energy_file = os.path.join(rapl_dir, 'energy_uj')
                if not os.path.exists(energy_file):
                    continue

                with open(energy_file, 'r') as f:
                    energy_uj = int(f.read().strip())

                readings.append({
                    'source': 'rapl',
                    'sensor': name,
                    'value': energy_uj / 1000000.0,  # Convert to Joules
                    'unit': 'Joules',
                    'status': 'healthy'
                })

            except (IOError, ValueError, PermissionError):
                continue

    except Exception:
        pass

    return readings


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
        description="Monitor power consumption"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including source"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings or critical readings"
    )
    parser.add_argument(
        "--skip-ipmi",
        action="store_true",
        help="Skip IPMI sensor checks"
    )
    parser.add_argument(
        "--skip-rapl",
        action="store_true",
        help="Skip RAPL/sysfs checks"
    )

    opts = parser.parse_args(args)

    # Collect all power readings
    all_readings = []

    if not opts.skip_ipmi:
        ipmi_readings = get_ipmi_power(context)
        all_readings.extend(ipmi_readings)

    if not opts.skip_rapl:
        rapl_readings = get_rapl_power(context)
        all_readings.extend(rapl_readings)

    if not all_readings:
        output.warning("No power sensors found")
        output.emit({"readings": []})

        output.render(opts.format, "Monitor power consumption using IPMI and RAPL")
        return 0

    # Filter for warn-only mode
    filtered = all_readings
    if opts.warn_only:
        filtered = [r for r in all_readings if r['status'] != 'healthy']

    # Remove source field if not verbose
    if not opts.verbose:
        for r in filtered:
            r.pop('source', None)

    output.emit({"readings": filtered})

    # Set summary
    total_power = sum(r['value'] for r in all_readings if r['unit'] == 'Watts')
    warnings = sum(1 for r in all_readings if r['status'] == 'warning')
    critical = sum(1 for r in all_readings if r['status'] == 'critical')

    if total_power > 0:
        output.set_summary(f"Total: {total_power:.1f}W, {warnings} warnings, {critical} critical")
    else:
        output.set_summary(f"{len(all_readings)} sensors, {warnings} warnings, {critical} critical")

    # Return 1 if any issues
    has_issues = warnings > 0 or critical > 0

    output.render(opts.format, "Monitor power consumption using IPMI and RAPL")
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
