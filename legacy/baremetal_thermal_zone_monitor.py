#!/usr/bin/env python3
"""
Monitor Linux kernel thermal zones and cooling devices on baremetal systems.

Reads thermal zone information from /sys/class/thermal/ to report:
- Current temperatures and thermal zone types
- Trip point temperatures (passive, active, critical, hot)
- Cooling device states and effectiveness
- Temperature trends (if run multiple times)

This complements hardware_temperature_monitor.py (which uses lm-sensors) by
providing kernel-level thermal management data including trip points that
trigger throttling or emergency shutdown.

Exit codes:
    0 - Success (all temperatures below warning thresholds)
    1 - Warning or critical conditions detected
    2 - Usage error or missing thermal zones
"""

import argparse
import json
import os
import sys
from pathlib import Path


THERMAL_BASE = Path('/sys/class/thermal')


def read_sysfs(path):
    """Read a sysfs file and return contents stripped, or None if not readable."""
    try:
        return path.read_text().strip()
    except (IOError, OSError, PermissionError):
        return None


def get_thermal_zones():
    """
    Enumerate all thermal zones and their properties.

    Returns list of dicts with zone info including temperature,
    type, trip points, and associated cooling devices.
    """
    zones = []

    if not THERMAL_BASE.exists():
        return zones

    for zone_path in sorted(THERMAL_BASE.glob('thermal_zone*')):
        zone_name = zone_path.name

        # Read basic zone info
        temp_raw = read_sysfs(zone_path / 'temp')
        zone_type = read_sysfs(zone_path / 'type') or 'unknown'
        mode = read_sysfs(zone_path / 'mode')
        policy = read_sysfs(zone_path / 'policy')

        # Temperature is in millidegrees Celsius
        if temp_raw is not None:
            try:
                temp_c = int(temp_raw) / 1000.0
            except ValueError:
                temp_c = None
        else:
            temp_c = None

        # Read trip points
        trip_points = []
        trip_idx = 0
        while True:
            trip_temp_path = zone_path / f'trip_point_{trip_idx}_temp'
            trip_type_path = zone_path / f'trip_point_{trip_idx}_type'

            if not trip_temp_path.exists():
                break

            trip_temp_raw = read_sysfs(trip_temp_path)
            trip_type = read_sysfs(trip_type_path) or 'unknown'

            if trip_temp_raw is not None:
                try:
                    trip_temp_c = int(trip_temp_raw) / 1000.0
                    trip_points.append({
                        'index': trip_idx,
                        'type': trip_type,
                        'temp': trip_temp_c
                    })
                except ValueError:
                    pass

            trip_idx += 1

        # Determine status based on trip points
        status = 'OK'
        triggered_trip = None

        if temp_c is not None:
            for trip in trip_points:
                if temp_c >= trip['temp']:
                    if trip['type'] == 'critical':
                        status = 'CRITICAL'
                        triggered_trip = trip
                    elif trip['type'] == 'hot' and status != 'CRITICAL':
                        status = 'HOT'
                        triggered_trip = trip
                    elif trip['type'] in ('passive', 'active') and status == 'OK':
                        status = 'THROTTLING'
                        triggered_trip = trip

        # Calculate headroom to critical
        critical_trip = next((t for t in trip_points if t['type'] == 'critical'), None)
        headroom = None
        if temp_c is not None and critical_trip:
            headroom = critical_trip['temp'] - temp_c

        zones.append({
            'name': zone_name,
            'type': zone_type,
            'temp': temp_c,
            'mode': mode,
            'policy': policy,
            'trip_points': trip_points,
            'status': status,
            'triggered_trip': triggered_trip,
            'headroom_to_critical': headroom
        })

    return zones


def get_cooling_devices():
    """
    Enumerate all cooling devices and their states.

    Returns list of dicts with device info including current and max state.
    """
    devices = []

    if not THERMAL_BASE.exists():
        return devices

    for dev_path in sorted(THERMAL_BASE.glob('cooling_device*')):
        dev_name = dev_path.name

        dev_type = read_sysfs(dev_path / 'type') or 'unknown'
        cur_state_raw = read_sysfs(dev_path / 'cur_state')
        max_state_raw = read_sysfs(dev_path / 'max_state')

        cur_state = None
        max_state = None

        if cur_state_raw is not None:
            try:
                cur_state = int(cur_state_raw)
            except ValueError:
                pass

        if max_state_raw is not None:
            try:
                max_state = int(max_state_raw)
            except ValueError:
                pass

        # Determine if cooling device is active
        active = cur_state is not None and cur_state > 0
        utilization = None
        if cur_state is not None and max_state is not None and max_state > 0:
            utilization = (cur_state / max_state) * 100

        devices.append({
            'name': dev_name,
            'type': dev_type,
            'cur_state': cur_state,
            'max_state': max_state,
            'active': active,
            'utilization_pct': utilization
        })

    return devices


def format_plain(zones, cooling_devices, warn_only=False, verbose=False):
    """Format output as plain text."""
    lines = []

    # Filter if warn_only
    if warn_only:
        zones = [z for z in zones if z['status'] != 'OK']
        cooling_devices = [d for d in cooling_devices if d['active']]

    if not zones and not cooling_devices:
        if warn_only:
            return "No thermal warnings detected."
        return "No thermal zones found."

    # Thermal zones section
    if zones:
        lines.append("Thermal Zones:")
        for zone in zones:
            temp_str = f"{zone['temp']:.1f}C" if zone['temp'] is not None else "N/A"
            status_str = f"  [{zone['status']}]" if zone['status'] != 'OK' else ""

            line = f"  {zone['name']:<16} {zone['type']:<20} {temp_str:>8}{status_str}"

            if verbose and zone['headroom_to_critical'] is not None:
                line += f"  (headroom: {zone['headroom_to_critical']:.1f}C)"

            lines.append(line)

            if verbose and zone['trip_points']:
                for trip in zone['trip_points']:
                    marker = " <--" if zone['triggered_trip'] == trip else ""
                    lines.append(f"      trip {trip['index']}: {trip['type']:<12} {trip['temp']:.1f}C{marker}")

    # Cooling devices section
    if cooling_devices:
        lines.append("")
        lines.append("Cooling Devices:")
        for dev in cooling_devices:
            state_str = f"{dev['cur_state']}/{dev['max_state']}" if dev['max_state'] is not None else str(dev['cur_state'])
            active_str = " [ACTIVE]" if dev['active'] else ""
            util_str = ""
            if verbose and dev['utilization_pct'] is not None:
                util_str = f" ({dev['utilization_pct']:.0f}%)"

            lines.append(f"  {dev['name']:<20} {dev['type']:<20} state: {state_str}{util_str}{active_str}")

    return '\n'.join(lines)


def format_json(zones, cooling_devices, warn_only=False):
    """Format output as JSON."""
    if warn_only:
        zones = [z for z in zones if z['status'] != 'OK']
        cooling_devices = [d for d in cooling_devices if d['active']]

    return json.dumps({
        'thermal_zones': zones,
        'cooling_devices': cooling_devices
    }, indent=2)


def format_table(zones, cooling_devices, warn_only=False):
    """Format output as a table."""
    if warn_only:
        zones = [z for z in zones if z['status'] != 'OK']
        cooling_devices = [d for d in cooling_devices if d['active']]

    lines = []

    if zones:
        header = f"{'ZONE':<16} {'TYPE':<20} {'TEMP':<10} {'HEADROOM':<12} {'STATUS':<12}"
        lines.append(header)
        lines.append('-' * len(header))

        for zone in zones:
            temp_str = f"{zone['temp']:.1f}C" if zone['temp'] is not None else "N/A"
            headroom_str = f"{zone['headroom_to_critical']:.1f}C" if zone['headroom_to_critical'] is not None else "N/A"
            lines.append(f"{zone['name']:<16} {zone['type']:<20} {temp_str:<10} {headroom_str:<12} {zone['status']:<12}")

    if cooling_devices:
        if lines:
            lines.append("")
        header = f"{'DEVICE':<20} {'TYPE':<20} {'STATE':<12} {'UTIL':<10} {'ACTIVE':<8}"
        lines.append(header)
        lines.append('-' * len(header))

        for dev in cooling_devices:
            state_str = f"{dev['cur_state']}/{dev['max_state']}" if dev['max_state'] is not None else str(dev['cur_state'] or 'N/A')
            util_str = f"{dev['utilization_pct']:.0f}%" if dev['utilization_pct'] is not None else "N/A"
            active_str = "Yes" if dev['active'] else "No"
            lines.append(f"{dev['name']:<20} {dev['type']:<20} {state_str:<12} {util_str:<10} {active_str:<8}")

    if not lines:
        return "No thermal data found." if not warn_only else "No thermal warnings."

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Linux kernel thermal zones and cooling devices.',
        epilog='''
Examples:
  # Show all thermal zones and cooling devices
  baremetal_thermal_zone_monitor.py

  # Show only zones with warnings/throttling
  baremetal_thermal_zone_monitor.py --warn-only

  # Verbose output with trip points
  baremetal_thermal_zone_monitor.py --verbose

  # JSON output for monitoring systems
  baremetal_thermal_zone_monitor.py --format json

  # Table format
  baremetal_thermal_zone_monitor.py --format table

Exit codes:
  0 - All temperatures below warning thresholds
  1 - Warning, throttling, or critical conditions detected
  2 - Usage error or no thermal zones found
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
        help='Only show zones with warnings or active cooling'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed trip point and utilization information'
    )

    args = parser.parse_args()

    # Check if thermal sysfs exists
    if not THERMAL_BASE.exists():
        print("Error: /sys/class/thermal not found.", file=sys.stderr)
        print("This system may not have kernel thermal zone support.", file=sys.stderr)
        return 2

    # Get thermal data
    zones = get_thermal_zones()
    cooling_devices = get_cooling_devices()

    if not zones:
        print("Error: No thermal zones found.", file=sys.stderr)
        print("Check kernel configuration for CONFIG_THERMAL.", file=sys.stderr)
        return 2

    # Format output
    if args.format == 'json':
        output = format_json(zones, cooling_devices, args.warn_only)
    elif args.format == 'table':
        output = format_table(zones, cooling_devices, args.warn_only)
    else:
        output = format_plain(zones, cooling_devices, args.warn_only, args.verbose)

    print(output)

    # Determine exit code
    has_issues = any(z['status'] != 'OK' for z in zones)

    return 1 if has_issues else 0


if __name__ == '__main__':
    sys.exit(main())
