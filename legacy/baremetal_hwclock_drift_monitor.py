#!/usr/bin/env python3
"""
Monitor hardware clock (RTC) drift against system time on baremetal systems.

Compares the hardware clock (RTC/CMOS) to system time to detect drift that could
cause time jumps on reboot. Useful for detecting failing CMOS batteries, clock
crystal degradation, or misconfigured RTC settings.

This complements ntp_drift_monitor.py - while NTP monitors sync to external time
sources, this script monitors the local hardware clock accuracy.

Exit codes:
    0 - Success (hardware clock within acceptable drift)
    1 - Warning/Critical drift detected or RTC issues
    2 - Usage error or missing dependencies (hwclock not found or no permissions)
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime


def check_hwclock_available():
    """Check if hwclock command is available."""
    try:
        result = subprocess.run(
            ['which', 'hwclock'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return result.returncode == 0
    except Exception:
        return False


def get_hwclock_time():
    """
    Get the current hardware clock time using hwclock.

    Returns a dict with hwclock data or None on error.
    """
    try:
        # Try to read hardware clock - may require root
        result = subprocess.run(
            ['hwclock', '--show', '--verbose'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            # Check if permission denied
            if 'permission denied' in result.stderr.lower() or \
               'operation not permitted' in result.stderr.lower():
                return {'error': 'permission_denied'}
            return {'error': 'hwclock_failed', 'stderr': result.stderr}

        return parse_hwclock_output(result.stdout, result.stderr)

    except FileNotFoundError:
        return {'error': 'hwclock_not_found'}
    except Exception as e:
        return {'error': 'exception', 'message': str(e)}


def parse_hwclock_output(stdout, stderr):
    """
    Parse hwclock --show --verbose output.

    Example output:
    hwclock from util-linux 2.37.2
    System Time: 1699900800.123456
    Trying to open: /dev/rtc0
    Using the rtc interface to the clock.
    Last drift adjustment done at 1699900000 seconds after 1969
    Last calibration done at 1699900000 seconds after 1969
    Hardware clock is on UTC time
    Assuming hardware clock is kept in UTC time.
    Waiting for clock tick...
    ...got clock tick
    Time read from Hardware Clock: 2023/11/13 15:00:01
    Hw clock time : 2023/11/13 15:00:01 = 1699887601 seconds since 1969
    Time since last adjustment is 87601 seconds
    Calculated Hardware Clock drift is 0.000000 seconds
    2023-11-13 15:00:01.123456+00:00
    """
    data = {
        'rtc_device': None,
        'rtc_time': None,
        'rtc_epoch': None,
        'system_time_at_read': None,
        'drift_seconds': None,
        'is_utc': None,
        'raw_output': stdout
    }

    combined = stdout + stderr

    # Parse RTC device
    match = re.search(r'Trying to open: (/dev/\S+)', combined)
    if match:
        data['rtc_device'] = match.group(1)

    # Parse if clock is UTC
    if 'hardware clock is on utc' in combined.lower() or \
       'kept in utc' in combined.lower():
        data['is_utc'] = True
    elif 'local time' in combined.lower():
        data['is_utc'] = False

    # Parse hardware clock time
    match = re.search(r'Time read from Hardware Clock:\s*(.+)', combined)
    if match:
        data['rtc_time'] = match.group(1).strip()

    # Parse epoch time
    match = re.search(r'=\s*(\d+)\s+seconds since 1969', combined)
    if match:
        data['rtc_epoch'] = int(match.group(1))

    # Parse calculated drift
    match = re.search(r'Calculated Hardware Clock drift is\s+([-+]?[\d.]+)\s+seconds', combined)
    if match:
        data['drift_seconds'] = float(match.group(1))

    # Get current system time for comparison
    data['system_time_at_read'] = datetime.now().isoformat()

    return data


def calculate_drift(hwclock_data):
    """
    Calculate the drift between hardware clock and system time.

    Returns drift in seconds (positive = RTC ahead, negative = RTC behind).
    """
    if not hwclock_data or 'error' in hwclock_data:
        return None

    # If hwclock reported drift, use that
    if hwclock_data.get('drift_seconds') is not None:
        return hwclock_data['drift_seconds']

    # Otherwise calculate from epoch if available
    if hwclock_data.get('rtc_epoch'):
        rtc_epoch = hwclock_data['rtc_epoch']
        system_epoch = datetime.now().timestamp()
        return rtc_epoch - system_epoch

    return None


def get_rtc_info():
    """
    Get additional RTC information from /sys/class/rtc/rtc0/ if available.
    """
    info = {}

    try:
        # Check if RTC device exists
        with open('/sys/class/rtc/rtc0/name', 'r') as f:
            info['rtc_name'] = f.read().strip()
    except Exception:
        pass

    try:
        with open('/sys/class/rtc/rtc0/hctosys', 'r') as f:
            info['hctosys'] = f.read().strip() == '1'
    except Exception:
        pass

    try:
        with open('/sys/class/rtc/rtc0/since_epoch', 'r') as f:
            info['since_epoch'] = int(f.read().strip())
    except Exception:
        pass

    return info


def assess_status(drift_seconds, warn_threshold, crit_threshold):
    """
    Assess the drift status.

    Returns: 'OK', 'WARNING', 'CRITICAL', or 'UNKNOWN'
    """
    if drift_seconds is None:
        return 'UNKNOWN'

    abs_drift = abs(drift_seconds)

    if abs_drift >= crit_threshold:
        return 'CRITICAL'
    elif abs_drift >= warn_threshold:
        return 'WARNING'
    else:
        return 'OK'


def format_drift(seconds):
    """Format drift in human-readable form."""
    if seconds is None:
        return "unknown"

    abs_seconds = abs(seconds)
    direction = "ahead" if seconds > 0 else "behind"

    if abs_seconds < 0.001:
        return f"{abs_seconds * 1000000:.1f} microseconds {direction}"
    elif abs_seconds < 1:
        return f"{abs_seconds * 1000:.1f} milliseconds {direction}"
    elif abs_seconds < 60:
        return f"{abs_seconds:.2f} seconds {direction}"
    elif abs_seconds < 3600:
        return f"{abs_seconds / 60:.1f} minutes {direction}"
    else:
        return f"{abs_seconds / 3600:.1f} hours {direction}"


def format_plain(hwclock_data, rtc_info, drift, status, verbose=False):
    """Format output as plain text."""
    output = []

    if hwclock_data.get('error'):
        error = hwclock_data['error']
        if error == 'permission_denied':
            output.append("Error: Permission denied reading hardware clock")
            output.append("Run with sudo or as root to access RTC")
        elif error == 'hwclock_not_found':
            output.append("Error: hwclock command not found")
        else:
            output.append(f"Error: {hwclock_data.get('message', error)}")
        return '\n'.join(output)

    output.append(f"Hardware Clock (RTC) Status: [{status}]")
    output.append("")

    if hwclock_data.get('rtc_device'):
        output.append(f"  RTC Device: {hwclock_data['rtc_device']}")

    if rtc_info.get('rtc_name'):
        output.append(f"  RTC Name: {rtc_info['rtc_name']}")

    if hwclock_data.get('rtc_time'):
        output.append(f"  RTC Time: {hwclock_data['rtc_time']}")

    if hwclock_data.get('is_utc') is not None:
        tz_mode = "UTC" if hwclock_data['is_utc'] else "Local Time"
        output.append(f"  RTC Mode: {tz_mode}")

    if drift is not None:
        drift_str = format_drift(drift)
        status_indicator = ""
        if status == 'WARNING':
            status_indicator = " [WARNING]"
        elif status == 'CRITICAL':
            status_indicator = " [CRITICAL]"
        output.append(f"  Drift: {drift_str}{status_indicator}")

    if verbose:
        output.append("")
        output.append("  Detailed Information:")

        if hwclock_data.get('rtc_epoch'):
            output.append(f"    RTC Epoch: {hwclock_data['rtc_epoch']}")

        if rtc_info.get('hctosys') is not None:
            hctosys_str = "Yes" if rtc_info['hctosys'] else "No"
            output.append(f"    Set system time at boot: {hctosys_str}")

        if rtc_info.get('since_epoch'):
            output.append(f"    Kernel RTC epoch: {rtc_info['since_epoch']}")

    return '\n'.join(output)


def format_json(hwclock_data, rtc_info, drift, status):
    """Format output as JSON."""
    result = {
        'status': status,
        'drift_seconds': drift,
        'drift_human': format_drift(drift) if drift else None,
        'rtc_device': hwclock_data.get('rtc_device'),
        'rtc_time': hwclock_data.get('rtc_time'),
        'rtc_epoch': hwclock_data.get('rtc_epoch'),
        'is_utc': hwclock_data.get('is_utc'),
        'rtc_name': rtc_info.get('rtc_name'),
        'hctosys': rtc_info.get('hctosys'),
    }

    if hwclock_data.get('error'):
        result['error'] = hwclock_data['error']

    return json.dumps(result, indent=2)


def format_table(hwclock_data, rtc_info, drift, status):
    """Format output as a table."""
    output = []

    header = f"{'METRIC':<25} {'VALUE':<35} {'STATUS':<10}"
    separator = '-' * len(header)
    output.append(header)
    output.append(separator)

    output.append(f"{'Overall Status':<25} {status:<35} {'':<10}")

    if hwclock_data.get('rtc_device'):
        output.append(f"{'RTC Device':<25} {hwclock_data['rtc_device']:<35} {'':<10}")

    if rtc_info.get('rtc_name'):
        output.append(f"{'RTC Name':<25} {rtc_info['rtc_name']:<35} {'':<10}")

    if hwclock_data.get('rtc_time'):
        output.append(f"{'RTC Time':<25} {hwclock_data['rtc_time']:<35} {'':<10}")

    if hwclock_data.get('is_utc') is not None:
        tz_mode = "UTC" if hwclock_data['is_utc'] else "Local Time"
        output.append(f"{'RTC Mode':<25} {tz_mode:<35} {'':<10}")

    if drift is not None:
        drift_str = format_drift(drift)
        output.append(f"{'Drift':<25} {drift_str:<35} {status:<10}")

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor hardware clock (RTC) drift against system time.',
        epilog='''
Examples:
  # Check hardware clock drift (requires root)
  sudo baremetal_hwclock_drift_monitor.py

  # Show detailed information
  sudo baremetal_hwclock_drift_monitor.py --verbose

  # Output as JSON for monitoring systems
  sudo baremetal_hwclock_drift_monitor.py --format json

  # Custom thresholds (warn at 1s, critical at 60s)
  sudo baremetal_hwclock_drift_monitor.py --warn-threshold 1.0 --crit-threshold 60.0

Exit codes:
  0 - Hardware clock within acceptable drift
  1 - Warning or critical drift detected
  2 - Usage error or missing dependencies/permissions
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
        '-v', '--verbose',
        action='store_true',
        help='Show detailed RTC information'
    )
    parser.add_argument(
        '-w', '--warn-threshold',
        type=float,
        default=5.0,
        help='Warning threshold for drift in seconds (default: 5.0)'
    )
    parser.add_argument(
        '-c', '--crit-threshold',
        type=float,
        default=60.0,
        help='Critical threshold for drift in seconds (default: 60.0)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn_threshold <= 0 or args.crit_threshold <= 0:
        print("Error: Thresholds must be positive numbers", file=sys.stderr)
        return 2

    if args.warn_threshold >= args.crit_threshold:
        print("Error: Warning threshold must be less than critical threshold",
              file=sys.stderr)
        return 2

    # Check if hwclock is available
    if not check_hwclock_available():
        print("Error: hwclock command not found", file=sys.stderr)
        print("Install util-linux: 'apt install util-linux' or 'yum install util-linux'",
              file=sys.stderr)
        return 2

    # Get hardware clock data
    hwclock_data = get_hwclock_time()

    if hwclock_data.get('error'):
        error = hwclock_data['error']
        if error == 'permission_denied':
            print("Error: Permission denied reading hardware clock",
                  file=sys.stderr)
            print("Run with sudo or as root to access RTC", file=sys.stderr)
            return 2

    # Get additional RTC info
    rtc_info = get_rtc_info()

    # Calculate drift
    drift = calculate_drift(hwclock_data)

    # Assess status
    status = assess_status(drift, args.warn_threshold, args.crit_threshold)

    # Format output
    if args.format == 'json':
        output = format_json(hwclock_data, rtc_info, drift, status)
    elif args.format == 'table':
        output = format_table(hwclock_data, rtc_info, drift, status)
    else:
        output = format_plain(hwclock_data, rtc_info, drift, status, args.verbose)

    print(output)

    # Return exit code based on status
    if status in ('CRITICAL', 'WARNING', 'UNKNOWN'):
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
