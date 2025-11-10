#!/usr/bin/env python3
"""
Monitor IPMI System Event Log (SEL) for hardware errors on baremetal systems.

Checks the IPMI SEL for critical hardware events such as:
- Power supply failures
- Memory ECC errors
- Fan failures
- Temperature threshold violations
- Voltage anomalies
- System event log overflow

Useful for proactive hardware failure detection in large-scale baremetal
datacenter environments before issues cause system downtime.

Exit codes:
  0 - Success (no critical events or only informational events)
  1 - Warning/Critical events detected in SEL
  2 - Usage error or missing dependencies
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta


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
        print(f"Error running command {' '.join(cmd)}: {e.stderr}", file=sys.stderr)
        return None


def get_sel_list():
    """Retrieve IPMI SEL entries."""
    output = run_command(['ipmitool', 'sel', 'list'])
    if output is None:
        return []

    entries = []
    for line in output.strip().split('\n'):
        if not line.strip():
            continue

        # Parse SEL entry format:
        # ID | Date | Time | Sensor | Event | Status
        # Example: "1 | 01/15/2025 | 14:23:45 | Memory | Correctable ECC | Asserted"
        parts = [p.strip() for p in line.split('|')]

        if len(parts) < 5:
            continue

        entry = {
            'id': parts[0],
            'date': parts[1] if len(parts) > 1 else '',
            'time': parts[2] if len(parts) > 2 else '',
            'sensor': parts[3] if len(parts) > 3 else '',
            'event': parts[4] if len(parts) > 4 else '',
            'status': parts[5] if len(parts) > 5 else '',
            'raw_line': line
        }

        entries.append(entry)

    return entries


def get_sel_info():
    """Get SEL information (capacity, free space, etc)."""
    output = run_command(['ipmitool', 'sel', 'info'])
    if output is None:
        return {}

    info = {}
    for line in output.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            info[key.strip()] = value.strip()

    return info


def categorize_event_severity(event_text, status_text):
    """
    Categorize event severity based on event description and status.

    Returns: 'CRITICAL', 'WARNING', 'INFO'
    """
    event_lower = event_text.lower()
    status_lower = status_text.lower()

    # Critical events
    critical_keywords = [
        'uncorrectable',
        'failed',
        'failure',
        'critical',
        'non-recoverable',
        'fatal',
        'panic',
        'emergency',
        'power supply failure',
        'power unit failure',
        'chassis intrusion',
        'drive fault',
        'disk fault',
        'hardware failure',
        'predictive failure',
        'thermal trip',
        'voltage out of range'
    ]

    for keyword in critical_keywords:
        if keyword in event_lower:
            return 'CRITICAL'

    # Warning events
    warning_keywords = [
        'correctable',
        'warning',
        'threshold',
        'deasserted',
        'lower critical',
        'upper critical',
        'lower non-critical',
        'upper non-critical',
        'redundancy lost',
        'degraded',
        'ecc',
        'sensor failure'
    ]

    for keyword in warning_keywords:
        if keyword in event_lower:
            return 'WARNING'

    # Informational events (typically deasserted/cleared conditions)
    if 'deasserted' in status_lower or 'ok' in status_lower:
        return 'INFO'

    # Default to WARNING for unknown events
    return 'WARNING'


def filter_by_time(entries, hours):
    """Filter entries to only those within the last N hours."""
    if hours is None or hours <= 0:
        return entries

    cutoff = datetime.now() - timedelta(hours=hours)
    filtered = []

    for entry in entries:
        try:
            # Parse date and time
            date_str = entry.get('date', '')
            time_str = entry.get('time', '')

            if not date_str or not time_str:
                # If we can't parse time, include it to be safe
                filtered.append(entry)
                continue

            # Try different date formats
            datetime_str = f"{date_str} {time_str}"
            entry_time = None

            for fmt in ['%m/%d/%Y %H:%M:%S', '%d/%m/%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S']:
                try:
                    entry_time = datetime.strptime(datetime_str, fmt)
                    break
                except ValueError:
                    continue

            if entry_time is None:
                # If we can't parse, include it to be safe
                filtered.append(entry)
                continue

            if entry_time >= cutoff:
                filtered.append(entry)

        except Exception:
            # If any parsing fails, include the entry to be safe
            filtered.append(entry)

    return filtered


def analyze_entries(entries):
    """Add severity categorization to entries."""
    for entry in entries:
        event = entry.get('event', '')
        status = entry.get('status', '')
        entry['severity'] = categorize_event_severity(event, status)

    return entries


def format_plain(entries, sel_info, warn_only=False, verbose=False):
    """Format SEL data as plain text."""
    output = []

    # Show SEL info if verbose
    if verbose and sel_info:
        output.append("SEL Information:")
        for key, value in sel_info.items():
            output.append(f"  {key}: {value}")
        output.append("")

    # Filter to warnings/critical only if requested
    if warn_only:
        entries = [e for e in entries if e.get('severity') in ['WARNING', 'CRITICAL']]

    if not entries:
        if warn_only:
            output.append("No warning or critical events found in SEL.")
        else:
            output.append("No entries found in SEL.")
        return '\n'.join(output)

    output.append(f"Found {len(entries)} SEL entries:")
    output.append("")

    # Group by severity
    critical_entries = [e for e in entries if e.get('severity') == 'CRITICAL']
    warning_entries = [e for e in entries if e.get('severity') == 'WARNING']
    info_entries = [e for e in entries if e.get('severity') == 'INFO']

    if critical_entries:
        output.append(f"CRITICAL Events ({len(critical_entries)}):")
        for entry in critical_entries:
            output.append(f"  [{entry['id']}] {entry['date']} {entry['time']}")
            output.append(f"      {entry['sensor']}: {entry['event']} - {entry['status']}")
        output.append("")

    if warning_entries:
        output.append(f"WARNING Events ({len(warning_entries)}):")
        for entry in warning_entries:
            output.append(f"  [{entry['id']}] {entry['date']} {entry['time']}")
            output.append(f"      {entry['sensor']}: {entry['event']} - {entry['status']}")
        output.append("")

    if info_entries and not warn_only:
        output.append(f"INFO Events ({len(info_entries)}):")
        for entry in info_entries:
            output.append(f"  [{entry['id']}] {entry['date']} {entry['time']}")
            output.append(f"      {entry['sensor']}: {entry['event']} - {entry['status']}")
        output.append("")

    return '\n'.join(output)


def format_json(entries, sel_info, warn_only=False):
    """Format SEL data as JSON."""
    if warn_only:
        entries = [e for e in entries if e.get('severity') in ['WARNING', 'CRITICAL']]

    return json.dumps({
        'sel_info': sel_info,
        'entries': entries,
        'summary': {
            'total': len(entries),
            'critical': len([e for e in entries if e.get('severity') == 'CRITICAL']),
            'warning': len([e for e in entries if e.get('severity') == 'WARNING']),
            'info': len([e for e in entries if e.get('severity') == 'INFO'])
        }
    }, indent=2)


def format_table(entries, sel_info, warn_only=False):
    """Format SEL data as a table."""
    if warn_only:
        entries = [e for e in entries if e.get('severity') in ['WARNING', 'CRITICAL']]

    if not entries:
        return "No entries found." if not warn_only else "No warnings detected."

    # Header
    header = f"{'ID':<6} {'DATE':<12} {'TIME':<10} {'SEVERITY':<10} {'SENSOR':<20} {'EVENT':<30}"
    separator = '-' * len(header)
    rows = [header, separator]

    for entry in entries:
        row = f"{entry['id']:<6} {entry['date']:<12} {entry['time']:<10} {entry.get('severity', 'UNKNOWN'):<10} {entry['sensor']:<20} {entry['event']:<30}"
        rows.append(row)

    return '\n'.join(rows)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor IPMI System Event Log (SEL) for hardware errors.',
        epilog='''
Examples:
  # Show all SEL entries
  ipmi_sel_monitor.py

  # Show only warnings and critical events
  ipmi_sel_monitor.py --warn-only

  # Show events from last 24 hours
  ipmi_sel_monitor.py --hours 24

  # Output as JSON for monitoring systems
  ipmi_sel_monitor.py --format json

  # Verbose output with SEL information
  ipmi_sel_monitor.py --verbose

  # Table format with recent warnings
  ipmi_sel_monitor.py --format table --warn-only --hours 48

Exit codes:
  0 - No critical events or only informational events
  1 - Warning or critical events detected
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
        help='Only show warning and critical events'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed SEL information'
    )
    parser.add_argument(
        '--hours',
        type=int,
        help='Only show events from the last N hours'
    )
    parser.add_argument(
        '--clear',
        action='store_true',
        help='Clear SEL after displaying (requires root privileges)'
    )

    args = parser.parse_args()

    # Check if ipmitool is available
    if not check_ipmitool_available():
        print("Error: 'ipmitool' command not found.", file=sys.stderr)
        print("Install ipmitool package:", file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt-get install ipmitool", file=sys.stderr)
        print("  RHEL/CentOS: sudo yum install ipmitool", file=sys.stderr)
        print("\nNote: IPMI requires root privileges or proper user permissions.", file=sys.stderr)
        return 2

    # Get SEL information
    sel_info = get_sel_info() if args.verbose else {}

    # Get SEL entries
    entries = get_sel_list()

    # Filter by time if requested
    if args.hours:
        entries = filter_by_time(entries, args.hours)

    # Analyze and categorize entries
    entries = analyze_entries(entries)

    # Format output
    if args.format == 'json':
        output = format_json(entries, sel_info, args.warn_only)
    elif args.format == 'table':
        output = format_table(entries, sel_info, args.warn_only)
    else:
        output = format_plain(entries, sel_info, args.warn_only, args.verbose)

    print(output)

    # Clear SEL if requested
    if args.clear:
        print("\nClearing SEL...", file=sys.stderr)
        clear_output = run_command(['ipmitool', 'sel', 'clear'])
        if clear_output:
            print("SEL cleared successfully.", file=sys.stderr)

    # Determine exit code based on severity
    has_critical = any(e.get('severity') == 'CRITICAL' for e in entries)
    has_warnings = any(e.get('severity') == 'WARNING' for e in entries)

    if has_critical or has_warnings:
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
