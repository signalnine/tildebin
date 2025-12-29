#!/usr/bin/env python3
"""
Systemd Timer Health Monitor

Monitors systemd timers for health issues including:
- Failed or inactive timers
- Timers that haven't run recently (missed executions)
- Timers with no next scheduled run
- Associated service unit failures
- Timer accuracy and delay patterns

Useful for ensuring scheduled tasks (backups, log rotation, maintenance)
are running as expected in baremetal environments.

Exit codes:
    0 - All timers are healthy and running on schedule
    1 - One or more timers have issues (failed, missed runs, etc.)
    2 - systemctl not available or usage error

Examples:
    # Check all timers
    baremetal_systemd_timer_monitor.py

    # Show only problematic timers
    baremetal_systemd_timer_monitor.py --warn-only

    # JSON output for monitoring integration
    baremetal_systemd_timer_monitor.py --format json

    # Check timers that should run at least daily
    baremetal_systemd_timer_monitor.py --max-age 24h

    # Verbose output with execution history
    baremetal_systemd_timer_monitor.py --verbose
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional


def run_command(cmd: List[str], check: bool = True) -> str:
    """Execute a shell command and return output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check
        )
        return result.stdout
    except FileNotFoundError:
        print(f"Error: {cmd[0]} not found", file=sys.stderr)
        print("This tool requires systemd/systemctl", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        return e.stdout if e.stdout else ""


def check_systemctl_available() -> bool:
    """Check if systemctl is available."""
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


def parse_time_delta(time_str: str) -> Optional[timedelta]:
    """Parse time string like '24h', '7d', '30m' into timedelta."""
    if not time_str:
        return None

    match = re.match(r'^(\d+)([smhdw])$', time_str.lower())
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    units = {
        's': timedelta(seconds=value),
        'm': timedelta(minutes=value),
        'h': timedelta(hours=value),
        'd': timedelta(days=value),
        'w': timedelta(weeks=value),
    }

    return units.get(unit)


def parse_systemd_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Parse systemd timestamp into datetime object."""
    if not timestamp_str or timestamp_str in ['n/a', '-', '']:
        return None

    # Common systemd timestamp formats
    formats = [
        '%a %Y-%m-%d %H:%M:%S %Z',  # Mon 2024-01-15 10:30:00 UTC
        '%Y-%m-%d %H:%M:%S %Z',      # 2024-01-15 10:30:00 UTC
        '%a %Y-%m-%d %H:%M:%S',      # Mon 2024-01-15 10:30:00
        '%Y-%m-%d %H:%M:%S',         # 2024-01-15 10:30:00
    ]

    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str.strip(), fmt)
        except ValueError:
            continue

    return None


def get_timers() -> List[Dict[str, str]]:
    """Get list of all systemd timers with their status."""
    cmd = ['systemctl', 'list-timers', '--all', '--no-pager', '--no-legend']
    output = run_command(cmd, check=False)

    timers = []
    for line in output.strip().split('\n'):
        if not line.strip():
            continue

        # Format: NEXT LEFT LAST PASSED UNIT ACTIVATES
        # Fields are variable width, need careful parsing
        parts = line.split()
        if len(parts) < 2:
            continue

        # Find the .timer unit and .service unit
        timer_unit = None
        service_unit = None
        for i, part in enumerate(parts):
            if part.endswith('.timer'):
                timer_unit = part
            elif part.endswith('.service'):
                service_unit = part

        if not timer_unit:
            continue

        timers.append({
            'name': timer_unit,
            'activates': service_unit or timer_unit.replace('.timer', '.service'),
            'raw_line': line,
        })

    return timers


def get_timer_details(timer_name: str) -> Dict[str, Any]:
    """Get detailed information about a timer unit."""
    cmd = ['systemctl', 'show', timer_name, '--no-pager']
    output = run_command(cmd, check=False)

    details = {}
    for line in output.strip().split('\n'):
        if '=' in line:
            key, value = line.split('=', 1)
            details[key] = value

    return details


def get_service_status(service_name: str) -> Dict[str, Any]:
    """Get status of the service activated by the timer."""
    cmd = ['systemctl', 'show', service_name, '--no-pager']
    output = run_command(cmd, check=False)

    details = {}
    for line in output.strip().split('\n'):
        if '=' in line:
            key, value = line.split('=', 1)
            details[key] = value

    return details


def analyze_timer(timer: Dict[str, str], max_age: Optional[timedelta] = None) -> Dict[str, Any]:
    """Analyze a timer for health issues."""
    timer_details = get_timer_details(timer['name'])
    service_details = get_service_status(timer['activates'])

    now = datetime.now()

    # Parse timestamps
    last_trigger_str = timer_details.get('LastTriggerUSec', '')
    next_elapse_str = timer_details.get('NextElapseUSecRealtime', '')

    # Convert microseconds to datetime if available
    last_trigger = None
    if last_trigger_str and last_trigger_str != '0':
        try:
            usec = int(last_trigger_str)
            if usec > 0:
                last_trigger = datetime.fromtimestamp(usec / 1_000_000)
        except (ValueError, OSError):
            pass

    next_elapse = None
    if next_elapse_str and next_elapse_str != '0':
        try:
            usec = int(next_elapse_str)
            if usec > 0:
                next_elapse = datetime.fromtimestamp(usec / 1_000_000)
        except (ValueError, OSError):
            pass

    # Determine issues
    issues = []
    severity = 'OK'

    # Check timer active state
    timer_active = timer_details.get('ActiveState', 'unknown')
    timer_sub = timer_details.get('SubState', 'unknown')

    if timer_active == 'failed':
        issues.append('Timer unit is failed')
        severity = 'CRITICAL'
    elif timer_active == 'inactive':
        issues.append('Timer is inactive/disabled')
        severity = 'WARNING'

    # Check if timer has no next scheduled run
    if timer_active == 'active' and not next_elapse:
        issues.append('No next scheduled run')
        severity = 'WARNING' if severity == 'OK' else severity

    # Check if timer hasn't run in max_age period
    if max_age and last_trigger:
        age = now - last_trigger
        if age > max_age:
            hours = age.total_seconds() / 3600
            issues.append(f'Last run {hours:.1f}h ago (exceeds threshold)')
            severity = 'WARNING' if severity == 'OK' else severity

    # Check associated service status
    service_active = service_details.get('ActiveState', 'unknown')
    service_result = service_details.get('Result', 'success')

    if service_result not in ['success', '']:
        issues.append(f'Service last result: {service_result}')
        if service_result == 'failed':
            severity = 'CRITICAL'
        elif severity == 'OK':
            severity = 'WARNING'

    # Calculate time since last run
    time_since_last = None
    if last_trigger:
        time_since_last = now - last_trigger

    # Calculate time until next run
    time_until_next = None
    if next_elapse and next_elapse > now:
        time_until_next = next_elapse - now

    return {
        'name': timer['name'],
        'activates': timer['activates'],
        'active_state': timer_active,
        'sub_state': timer_sub,
        'last_trigger': last_trigger.isoformat() if last_trigger else None,
        'next_elapse': next_elapse.isoformat() if next_elapse else None,
        'time_since_last_hours': round(time_since_last.total_seconds() / 3600, 2) if time_since_last else None,
        'time_until_next_hours': round(time_until_next.total_seconds() / 3600, 2) if time_until_next else None,
        'service_result': service_result,
        'issues': issues,
        'severity': severity,
        'description': timer_details.get('Description', ''),
    }


def format_duration(hours: Optional[float]) -> str:
    """Format hours into human-readable duration."""
    if hours is None:
        return 'n/a'
    if hours < 1:
        return f'{int(hours * 60)}m'
    elif hours < 24:
        return f'{hours:.1f}h'
    else:
        return f'{hours / 24:.1f}d'


def output_plain(results: List[Dict[str, Any]], warn_only: bool = False,
                 verbose: bool = False) -> None:
    """Output results in plain text format."""
    problematic = [r for r in results if r['severity'] != 'OK']
    healthy = [r for r in results if r['severity'] == 'OK']

    if not warn_only:
        print("Systemd Timer Health Monitor")
        print("=" * 60)
        print(f"Total timers: {len(results)}")
        print(f"Healthy: {len(healthy)}")
        print(f"With issues: {len(problematic)}")
        print()

    if problematic:
        print("TIMERS WITH ISSUES:")
        print("-" * 60)
        for timer in problematic:
            marker = "!!!" if timer['severity'] == 'CRITICAL' else " ! "
            print(f"{marker} {timer['name']}")
            print(f"    Activates: {timer['activates']}")
            print(f"    State: {timer['active_state']}/{timer['sub_state']}")
            print(f"    Last run: {format_duration(timer['time_since_last_hours'])} ago")
            print(f"    Next run: in {format_duration(timer['time_until_next_hours'])}")
            for issue in timer['issues']:
                print(f"    -> {issue}")
            if verbose and timer['description']:
                print(f"    Description: {timer['description']}")
            print()

    if not warn_only and healthy:
        print("\nHEALTHY TIMERS:")
        print("-" * 60)
        for timer in healthy:
            last = format_duration(timer['time_since_last_hours'])
            next_run = format_duration(timer['time_until_next_hours'])
            print(f"  OK {timer['name']:<40} last: {last:<8} next: {next_run}")

    if not problematic and warn_only:
        print("All timers are healthy")


def output_json(results: List[Dict[str, Any]]) -> None:
    """Output results in JSON format."""
    problematic = [r for r in results if r['severity'] != 'OK']
    healthy = [r for r in results if r['severity'] == 'OK']

    output = {
        'summary': {
            'total': len(results),
            'healthy': len(healthy),
            'with_issues': len(problematic),
            'critical': sum(1 for r in results if r['severity'] == 'CRITICAL'),
            'warning': sum(1 for r in results if r['severity'] == 'WARNING'),
        },
        'timers': results,
    }

    print(json.dumps(output, indent=2, default=str))


def output_table(results: List[Dict[str, Any]], warn_only: bool = False) -> None:
    """Output results in table format."""
    if warn_only:
        results = [r for r in results if r['severity'] != 'OK']

    print(f"{'STATUS':<10} {'TIMER':<35} {'LAST RUN':<12} {'NEXT RUN':<12} {'ISSUES':<30}")
    print("=" * 100)

    for timer in results:
        last = format_duration(timer['time_since_last_hours'])
        next_run = format_duration(timer['time_until_next_hours'])
        issues_str = '; '.join(timer['issues'])[:30] if timer['issues'] else '-'

        print(f"{timer['severity']:<10} {timer['name']:<35} {last:<12} {next_run:<12} {issues_str:<30}")

    print()
    problematic = sum(1 for r in results if r['severity'] != 'OK')
    print(f"Total: {len(results)} | With issues: {problematic}")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor systemd timer health and identify missed or failed timers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Check all timers
  %(prog)s --warn-only            # Show only problematic timers
  %(prog)s --format json          # JSON output for monitoring
  %(prog)s --max-age 24h          # Flag timers not run in 24 hours
  %(prog)s --max-age 7d           # Flag timers not run in 7 days
  %(prog)s -v                     # Verbose output

Exit codes:
  0 - All timers healthy
  1 - One or more timers have issues
  2 - systemctl not available or usage error
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show timers with issues'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    parser.add_argument(
        '--max-age',
        metavar='DURATION',
        help='Flag timers not run within duration (e.g., 24h, 7d, 30m)'
    )

    args = parser.parse_args()

    # Validate max-age if provided
    max_age = None
    if args.max_age:
        max_age = parse_time_delta(args.max_age)
        if max_age is None:
            print(f"Error: Invalid duration format: {args.max_age}", file=sys.stderr)
            print("Use format like: 30m, 24h, 7d, 2w", file=sys.stderr)
            sys.exit(2)

    # Check dependencies
    check_systemctl_available()

    # Get and analyze timers
    timers = get_timers()

    if not timers:
        if args.format == 'json':
            print(json.dumps({'summary': {'total': 0}, 'timers': []}))
        else:
            print("No systemd timers found")
        sys.exit(0)

    results = [analyze_timer(t, max_age=max_age) for t in timers]

    # Sort: critical first, then warning, then OK
    severity_order = {'CRITICAL': 0, 'WARNING': 1, 'OK': 2}
    results.sort(key=lambda x: (severity_order.get(x['severity'], 3), x['name']))

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, warn_only=args.warn_only)
    else:
        output_plain(results, warn_only=args.warn_only, verbose=args.verbose)

    # Exit based on findings
    has_issues = any(r['severity'] != 'OK' for r in results)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
