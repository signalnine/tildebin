#!/usr/bin/env python3
# boxctl:
#   category: baremetal/time
#   tags: [health, ntp, chrony, time, drift]
#   requires: []
#   privilege: user
#   related: [hwclock_drift]
#   brief: Monitor NTP/Chrony time synchronization and clock drift

"""
Monitor NTP/Chrony time synchronization and clock drift on baremetal systems.

Checks time synchronization status using chronyc or ntpq/ntpstat depending on
what's available. Critical for distributed systems, databases, and K8s clusters
where time drift can cause serious issues.

Returns exit code 1 if time sync is degraded or offset exceeds thresholds.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_chrony_tracking(output: str) -> dict[str, Any]:
    """Parse chronyc tracking output."""
    data = {
        'source': 'chrony',
        'synchronized': False,
        'reference_id': None,
        'stratum': None,
        'system_time_offset': None,
        'last_offset': None,
        'rms_offset': None,
        'frequency': None,
        'root_delay': None,
        'root_dispersion': None,
        'leap_status': None,
    }

    for line in output.split('\n'):
        line = line.strip()

        # Reference ID
        match = re.match(r'Reference ID\s+:\s+(\S+)', line)
        if match:
            data['reference_id'] = match.group(1)
            if match.group(1) not in ['127.127.1.0', '0.0.0.0']:
                data['synchronized'] = True

        # Stratum
        match = re.match(r'Stratum\s+:\s+(\d+)', line)
        if match:
            data['stratum'] = int(match.group(1))

        # System time offset
        match = re.match(r'System time\s+:\s+([-+]?[0-9.]+)\s+seconds', line)
        if match:
            data['system_time_offset'] = float(match.group(1))

        # Last offset
        match = re.match(r'Last offset\s+:\s+([-+]?[0-9.]+)\s+seconds', line)
        if match:
            data['last_offset'] = float(match.group(1))

        # RMS offset
        match = re.match(r'RMS offset\s+:\s+([0-9.]+)\s+seconds', line)
        if match:
            data['rms_offset'] = float(match.group(1))

        # Frequency
        match = re.match(r'Frequency\s+:\s+([-+]?[0-9.]+)\s+ppm', line)
        if match:
            data['frequency'] = float(match.group(1))

        # Root delay
        match = re.match(r'Root delay\s+:\s+([0-9.]+)\s+seconds', line)
        if match:
            data['root_delay'] = float(match.group(1))

        # Root dispersion
        match = re.match(r'Root dispersion\s+:\s+([0-9.]+)\s+seconds', line)
        if match:
            data['root_dispersion'] = float(match.group(1))

        # Leap status
        match = re.match(r'Leap status\s+:\s+(.+)', line)
        if match:
            data['leap_status'] = match.group(1).strip()

    return data


def assess_status(data: dict, warn_threshold: float, crit_threshold: float) -> str:
    """Assess the time sync status."""
    if not data:
        return 'unknown'

    if not data.get('synchronized'):
        return 'critical'

    # Check system time offset
    offset = data.get('system_time_offset') or data.get('last_offset')
    if offset is not None:
        abs_offset = abs(offset)
        if abs_offset >= crit_threshold:
            return 'critical'
        elif abs_offset >= warn_threshold:
            return 'warning'

    # Check stratum (16 means unsynchronized)
    if data.get('stratum') and data['stratum'] >= 16:
        return 'critical'

    return 'healthy'


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor NTP/Chrony time synchronization"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed synchronization information"
    )
    parser.add_argument(
        "-w", "--warn-threshold",
        type=float,
        default=0.100,
        help="Warning threshold in seconds (default: 0.100 = 100ms)"
    )
    parser.add_argument(
        "-c", "--crit-threshold",
        type=float,
        default=1.000,
        help="Critical threshold in seconds (default: 1.000 = 1s)"
    )

    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn_threshold <= 0 or opts.crit_threshold <= 0:
        output.error("Thresholds must be positive numbers")
        return 2

    if opts.warn_threshold >= opts.crit_threshold:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    # Try chrony first, fall back to ntp
    data = None
    if context.check_tool("chronyc"):
        try:
            result = context.run(['chronyc', 'tracking'], check=False)
            if result.returncode == 0:
                data = parse_chrony_tracking(result.stdout)
        except Exception:
            pass

    if data is None and context.check_tool("ntpq"):
        # Simple NTP check - just get sync status
        data = {
            'source': 'ntp',
            'synchronized': False,
            'reference_id': None,
            'stratum': None,
            'system_time_offset': None,
        }
        try:
            result = context.run(['ntpq', '-p', '-n'], check=False)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('*'):
                        parts = line.split()
                        if len(parts) >= 9:
                            data['synchronized'] = True
                            data['reference_id'] = parts[0][1:]
                            data['stratum'] = int(parts[2]) if parts[2].isdigit() else None
                            try:
                                data['system_time_offset'] = float(parts[8]) / 1000.0
                            except ValueError:
                                pass
                        break
        except Exception:
            pass

    if data is None:
        output.error("Neither chrony nor ntp is available")
        return 2

    # Assess status
    status = assess_status(data, opts.warn_threshold, opts.crit_threshold)
    data['status'] = status

    # Calculate offset in ms for display
    offset = data.get('system_time_offset') or data.get('last_offset')
    offset_ms = offset * 1000 if offset is not None else None

    # Remove verbose fields if not requested
    if not opts.verbose:
        data.pop('rms_offset', None)
        data.pop('frequency', None)
        data.pop('root_delay', None)
        data.pop('root_dispersion', None)
        data.pop('leap_status', None)

    output.emit(data)

    # Set summary
    sync_str = "synchronized" if data.get('synchronized') else "NOT synchronized"
    offset_str = f", offset: {offset_ms:+.3f}ms" if offset_ms is not None else ""
    output.set_summary(f"{sync_str}{offset_str}")

    # Return 1 if any issues
    return 1 if status in ['warning', 'critical', 'unknown'] else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
