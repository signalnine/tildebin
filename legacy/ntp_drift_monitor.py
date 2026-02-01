#!/usr/bin/env python3
"""
Monitor NTP/Chrony time synchronization and clock drift on baremetal systems.

Checks time synchronization status using chronyc or ntpq/ntpstat depending on
what's available. Critical for distributed systems, databases, and K8s clusters
where time drift can cause serious issues.

Exit codes:
  0 - Success (time synchronized within acceptable limits)
  1 - Warning/Critical drift detected or sync issues
  2 - Usage error or missing dependencies
"""

import argparse
import json
import re
import subprocess
import sys


def check_chrony_available():
    """Check if chrony/chronyc is available."""
    try:
        subprocess.run(
            ['chronyc', '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_ntp_available():
    """Check if ntp/ntpq is available."""
    try:
        subprocess.run(
            ['ntpq', '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_chrony_tracking():
    """Get time sync data from chronyc tracking."""
    try:
        result = subprocess.run(
            ['chronyc', 'tracking'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        return parse_chrony_tracking(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running chronyc tracking: {e}", file=sys.stderr)
        return None


def parse_chrony_tracking(output):
    """
    Parse chronyc tracking output.

    Example output:
    Reference ID    : A9FEA97B (ntp.ubuntu.com)
    Stratum         : 3
    Ref time (UTC)  : Thu Nov 06 12:34:56 2025
    System time     : 0.000123456 seconds fast of NTP time
    Last offset     : +0.000001234 seconds
    RMS offset      : 0.000012345 seconds
    Frequency       : 23.456 ppm slow
    Residual freq   : +0.001 ppm
    Skew            : 0.123 ppm
    Root delay      : 0.012345678 seconds
    Root dispersion : 0.001234567 seconds
    Update interval : 64.5 seconds
    Leap status     : Normal
    """
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
            # If we have a reference, we're likely synchronized
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


def get_ntp_status():
    """Get time sync data from ntpq and ntpstat."""
    data = {
        'source': 'ntp',
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

    # Try ntpstat first for sync status
    try:
        result = subprocess.run(
            ['ntpstat'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            data['synchronized'] = True
            # Parse offset from ntpstat output
            # Example: "time correct to within 12 ms"
            match = re.search(r'within (\d+) ms', result.stdout)
            if match:
                data['system_time_offset'] = float(match.group(1)) / 1000.0
    except FileNotFoundError:
        pass

    # Get detailed info from ntpq
    try:
        result = subprocess.run(
            ['ntpq', '-p', '-n'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )

        # Parse ntpq peer output to find the current sync source (*)
        for line in result.stdout.split('\n'):
            if line.startswith('*'):
                parts = line.split()
                if len(parts) >= 9:
                    data['reference_id'] = parts[0][1:]  # Remove the *
                    data['stratum'] = int(parts[2]) if parts[2].isdigit() else None
                    data['last_offset'] = float(parts[8]) / 1000.0 if parts[8] != '-' else None
                    data['root_delay'] = float(parts[7]) / 1000.0 if parts[7] != '-' else None
                break
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        pass

    return data


def assess_status(data, warn_threshold, crit_threshold):
    """
    Assess the time sync status and return status indicator.

    Returns: 'OK', 'WARNING', 'CRITICAL', or 'UNKNOWN'
    """
    if not data:
        return 'UNKNOWN'

    if not data['synchronized']:
        return 'CRITICAL'

    # Check system time offset
    offset = data.get('system_time_offset') or data.get('last_offset')
    if offset is not None:
        abs_offset = abs(offset)
        if abs_offset >= crit_threshold:
            return 'CRITICAL'
        elif abs_offset >= warn_threshold:
            return 'WARNING'

    # Check stratum (16 means unsynchronized)
    if data.get('stratum') and data['stratum'] >= 16:
        return 'CRITICAL'

    return 'OK'


def format_plain(data, status, verbose=False):
    """Format time sync data as plain text."""
    output = []

    if not data:
        output.append("Unable to get time synchronization data")
        return '\n'.join(output)

    source_name = "Chrony" if data['source'] == 'chrony' else "NTP"
    output.append(f"Time Synchronization Status ({source_name}): [{status}]")
    output.append("")

    if data['synchronized']:
        output.append("  Synchronized: Yes")
    else:
        output.append("  Synchronized: No [CRITICAL]")

    if data.get('reference_id'):
        output.append(f"  Reference ID: {data['reference_id']}")

    if data.get('stratum') is not None:
        stratum_str = f"  Stratum: {data['stratum']}"
        if data['stratum'] >= 16:
            stratum_str += " [UNSYNCHRONIZED]"
        output.append(stratum_str)

    # Show offset
    offset = data.get('system_time_offset') or data.get('last_offset')
    if offset is not None:
        offset_ms = offset * 1000
        offset_str = f"  Time Offset: {offset_ms:+.3f} ms"
        output.append(offset_str)

    if verbose:
        if data.get('rms_offset') is not None:
            output.append(f"  RMS Offset: {data['rms_offset'] * 1000:.3f} ms")

        if data.get('frequency') is not None:
            output.append(f"  Frequency: {data['frequency']:+.3f} ppm")

        if data.get('root_delay') is not None:
            output.append(f"  Root Delay: {data['root_delay'] * 1000:.3f} ms")

        if data.get('root_dispersion') is not None:
            output.append(f"  Root Dispersion: {data['root_dispersion'] * 1000:.3f} ms")

        if data.get('leap_status'):
            output.append(f"  Leap Status: {data['leap_status']}")

    return '\n'.join(output)


def format_json(data, status):
    """Format time sync data as JSON."""
    output = {
        'status': status,
        **data
    }
    return json.dumps(output, indent=2)


def format_table(data, status):
    """Format time sync data as a table."""
    output = []

    header = f"{'METRIC':<25} {'VALUE':<30} {'STATUS':<10}"
    separator = '-' * len(header)
    output.append(header)
    output.append(separator)

    source_name = "Chrony" if data['source'] == 'chrony' else "NTP"
    output.append(f"{'Source':<25} {source_name:<30} {status:<10}")

    sync_val = "Yes" if data.get('synchronized') else "No"
    sync_status = "" if data.get('synchronized') else "CRITICAL"
    output.append(f"{'Synchronized':<25} {sync_val:<30} {sync_status:<10}")

    if data.get('reference_id'):
        output.append(f"{'Reference ID':<25} {data['reference_id']:<30} {'':<10}")

    if data.get('stratum') is not None:
        stratum_status = "CRITICAL" if data['stratum'] >= 16 else ""
        output.append(f"{'Stratum':<25} {str(data['stratum']):<30} {stratum_status:<10}")

    offset = data.get('system_time_offset') or data.get('last_offset')
    if offset is not None:
        offset_ms = f"{offset * 1000:+.3f} ms"
        output.append(f"{'Time Offset':<25} {offset_ms:<30} {'':<10}")

    if data.get('rms_offset') is not None:
        rms_ms = f"{data['rms_offset'] * 1000:.3f} ms"
        output.append(f"{'RMS Offset':<25} {rms_ms:<30} {'':<10}")

    if data.get('frequency') is not None:
        freq_ppm = f"{data['frequency']:+.3f} ppm"
        output.append(f"{'Frequency':<25} {freq_ppm:<30} {'':<10}")

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor NTP/Chrony time synchronization and clock drift.',
        epilog='''
Examples:
  # Check time synchronization status
  ntp_drift_monitor.py

  # Show detailed information
  ntp_drift_monitor.py --verbose

  # Output as JSON for monitoring systems
  ntp_drift_monitor.py --format json

  # Custom thresholds (warn at 50ms, critical at 500ms)
  ntp_drift_monitor.py --warn-threshold 0.050 --crit-threshold 0.500

Exit codes:
  0 - Time synchronized within acceptable limits
  1 - Warning or critical drift detected
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
        '-v', '--verbose',
        action='store_true',
        help='Show detailed synchronization information'
    )
    parser.add_argument(
        '-w', '--warn-threshold',
        type=float,
        default=0.100,
        help='Warning threshold for time offset in seconds (default: 0.100 = 100ms)'
    )
    parser.add_argument(
        '-c', '--crit-threshold',
        type=float,
        default=1.000,
        help='Critical threshold for time offset in seconds (default: 1.000 = 1s)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn_threshold <= 0 or args.crit_threshold <= 0:
        print("Error: Thresholds must be positive numbers", file=sys.stderr)
        return 2

    if args.warn_threshold >= args.crit_threshold:
        print("Error: Warning threshold must be less than critical threshold", file=sys.stderr)
        return 2

    # Check for chrony first, fall back to ntp
    data = None
    if check_chrony_available():
        data = get_chrony_tracking()
    elif check_ntp_available():
        data = get_ntp_status()
    else:
        print("Error: Neither chrony nor ntp is available.", file=sys.stderr)
        print("Install chrony (recommended): 'apt install chrony' or 'yum install chrony'", file=sys.stderr)
        print("Or install ntp: 'apt install ntp' or 'yum install ntp'", file=sys.stderr)
        return 2

    if not data:
        print("Error: Unable to get time synchronization data", file=sys.stderr)
        return 2

    # Assess status
    status = assess_status(data, args.warn_threshold, args.crit_threshold)

    # Format output
    if args.format == 'json':
        output = format_json(data, status)
    elif args.format == 'table':
        output = format_table(data, status)
    else:
        output = format_plain(data, status, args.verbose)

    print(output)

    # Return exit code based on status
    if status == 'CRITICAL':
        return 1
    elif status == 'WARNING':
        return 1
    elif status == 'UNKNOWN':
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
