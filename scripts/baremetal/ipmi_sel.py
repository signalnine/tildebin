#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, ipmi, sel, hardware, bmc]
#   requires: [ipmitool]
#   privilege: root
#   related: [ipmi_sensor, psu_monitor]
#   brief: Monitor IPMI System Event Log for hardware errors

"""
Monitor IPMI System Event Log (SEL) for hardware errors on baremetal systems.

Checks the IPMI SEL for critical hardware events such as:
- Power supply failures
- Memory ECC errors
- Fan failures
- Temperature threshold violations
- Voltage anomalies
- System event log overflow

Returns exit code 1 if warning or critical events are detected.
"""

import argparse
from datetime import datetime, timedelta
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def categorize_event_severity(event_text: str, status_text: str) -> str:
    """Categorize event severity based on event description and status."""
    event_lower = event_text.lower()
    status_lower = status_text.lower()

    # Critical events
    critical_keywords = [
        'uncorrectable', 'failed', 'failure', 'critical',
        'non-recoverable', 'fatal', 'panic', 'emergency',
        'power supply failure', 'power unit failure',
        'chassis intrusion', 'drive fault', 'disk fault',
        'hardware failure', 'predictive failure', 'thermal trip',
        'voltage out of range'
    ]

    for keyword in critical_keywords:
        if keyword in event_lower:
            return 'critical'

    # Warning events
    warning_keywords = [
        'correctable', 'warning', 'threshold',
        'lower critical', 'upper critical',
        'lower non-critical', 'upper non-critical',
        'redundancy lost', 'degraded', 'ecc', 'sensor failure'
    ]

    for keyword in warning_keywords:
        if keyword in event_lower:
            return 'warning'

    # Informational events
    if 'deasserted' in status_lower or 'ok' in status_lower:
        return 'info'

    return 'warning'


def parse_sel_entry(line: str) -> dict[str, Any] | None:
    """Parse a single SEL entry line."""
    if not line.strip():
        return None

    # Parse SEL entry format: ID | Date | Time | Sensor | Event | Status
    parts = [p.strip() for p in line.split('|')]

    if len(parts) < 5:
        return None

    entry = {
        'id': parts[0],
        'date': parts[1] if len(parts) > 1 else '',
        'time': parts[2] if len(parts) > 2 else '',
        'sensor': parts[3] if len(parts) > 3 else '',
        'event': parts[4] if len(parts) > 4 else '',
        'status': parts[5] if len(parts) > 5 else '',
    }

    entry['severity'] = categorize_event_severity(entry['event'], entry['status'])
    return entry


def filter_by_time(entries: list[dict], hours: int) -> list[dict]:
    """Filter entries to only those within the last N hours."""
    if hours <= 0:
        return entries

    cutoff = datetime.now() - timedelta(hours=hours)
    filtered = []

    for entry in entries:
        try:
            date_str = entry.get('date', '')
            time_str = entry.get('time', '')

            if not date_str or not time_str:
                filtered.append(entry)
                continue

            datetime_str = f"{date_str} {time_str}"
            entry_time = None

            for fmt in ['%m/%d/%Y %H:%M:%S', '%d/%m/%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S']:
                try:
                    entry_time = datetime.strptime(datetime_str, fmt)
                    break
                except ValueError:
                    continue

            if entry_time is None or entry_time >= cutoff:
                filtered.append(entry)

        except Exception:
            filtered.append(entry)

    return filtered


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = warnings/critical found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor IPMI System Event Log for hardware errors"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warning and critical events"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed SEL information"
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=0,
        help="Only show events from the last N hours"
    )

    opts = parser.parse_args(args)

    # Check if ipmitool is available
    if not context.check_tool("ipmitool"):
        output.error("ipmitool not found. Install ipmitool package.")
        return 2

    # Get SEL info if verbose
    sel_info = {}
    if opts.verbose:
        try:
            result = context.run(['ipmitool', 'sel', 'info'], check=False)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        sel_info[key.strip()] = value.strip()
        except Exception:
            pass

    # Get SEL entries
    try:
        result = context.run(['ipmitool', 'sel', 'list'], check=False)
        if result.returncode != 0:
            output.error(f"Failed to read SEL: {result.stderr}")
            return 2
    except Exception as e:
        output.error(f"Failed to run ipmitool: {e}")
        return 2

    # Parse entries
    entries = []
    for line in result.stdout.strip().split('\n'):
        entry = parse_sel_entry(line)
        if entry:
            entries.append(entry)

    # Filter by time
    if opts.hours > 0:
        entries = filter_by_time(entries, opts.hours)

    # Filter for warn-only mode
    filtered = entries
    if opts.warn_only:
        filtered = [e for e in entries if e['severity'] in ['warning', 'critical']]

    # Emit data
    data = {
        "entries": filtered,
        "summary": {
            "total": len(entries),
            "critical": sum(1 for e in entries if e['severity'] == 'critical'),
            "warning": sum(1 for e in entries if e['severity'] == 'warning'),
            "info": sum(1 for e in entries if e['severity'] == 'info')
        }
    }

    if opts.verbose:
        data['sel_info'] = sel_info

    output.emit(data)

    # Set summary
    critical = data['summary']['critical']
    warning = data['summary']['warning']
    output.set_summary(f"{critical} critical, {warning} warning, {len(entries)} total")

    # Return 1 if any issues
    has_issues = critical > 0 or warning > 0
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
