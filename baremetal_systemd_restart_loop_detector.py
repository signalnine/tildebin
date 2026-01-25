#!/usr/bin/env python3
"""
Detect systemd services stuck in restart loops.

Monitors systemd services for excessive restart activity that may indicate
a service is crashing repeatedly. This is a common issue in production
environments where a misconfigured or broken service enters a restart loop,
consuming resources and potentially affecting dependent services.

Exit codes:
    0 - No restart loops detected
    1 - One or more services detected in restart loop
    2 - Usage error or systemctl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta


def check_systemctl_available():
    """Check if systemctl is available."""
    try:
        result = subprocess.run(
            ['systemctl', '--version'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def get_failed_services():
    """Get list of currently failed services."""
    try:
        result = subprocess.run(
            ['systemctl', 'list-units', '--state=failed', '--no-pager',
             '--no-legend', '--plain'],
            capture_output=True,
            text=True
        )
        failed = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                parts = line.split()
                if parts:
                    failed.append(parts[0])
        return failed
    except Exception:
        return []


def get_service_restart_count(service_name, since_hours=1):
    """
    Get the number of times a service has restarted in the given time window.

    Uses journalctl to count service start events.
    """
    since_time = datetime.now() - timedelta(hours=since_hours)
    since_str = since_time.strftime('%Y-%m-%d %H:%M:%S')

    try:
        # Count "Started" messages for this service
        result = subprocess.run(
            ['journalctl', '-u', service_name, '--since', since_str,
             '--no-pager', '-o', 'short-unix', '--grep=Started'],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return 0

        # Count non-empty lines
        lines = [l for l in result.stdout.strip().split('\n') if l.strip()]
        return len(lines)
    except Exception:
        return 0


def get_service_status(service_name):
    """Get current status of a service."""
    try:
        result = subprocess.run(
            ['systemctl', 'show', service_name,
             '--property=ActiveState,SubState,MainPID,NRestarts,'
             'ExecMainStartTimestamp,Result'],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return None

        status = {}
        for line in result.stdout.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                status[key] = value

        return status
    except Exception:
        return None


def get_all_services():
    """Get list of all loaded services."""
    try:
        result = subprocess.run(
            ['systemctl', 'list-units', '--type=service', '--all',
             '--no-pager', '--no-legend', '--plain'],
            capture_output=True,
            text=True
        )

        services = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                parts = line.split()
                if parts:
                    # Service name is first column
                    service = parts[0]
                    if service.endswith('.service'):
                        services.append(service)
        return services
    except Exception:
        return []


def get_recent_service_logs(service_name, lines=5):
    """Get recent log entries for a service."""
    try:
        result = subprocess.run(
            ['journalctl', '-u', service_name, '-n', str(lines),
             '--no-pager', '-o', 'short'],
            capture_output=True,
            text=True
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def detect_restart_loops(hours=1, threshold=3, check_all=False):
    """
    Detect services that are in restart loops.

    Args:
        hours: Time window to check for restarts
        threshold: Minimum restarts to consider a loop
        check_all: Check all services, not just failed ones

    Returns:
        List of dicts with service info for services in restart loops
    """
    loops = []

    if check_all:
        services = get_all_services()
    else:
        # Start with failed services, they're most likely to be looping
        services = get_failed_services()

        # Also check services that might be in activating state
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service',
                 '--state=activating,reloading', '--no-pager',
                 '--no-legend', '--plain'],
                capture_output=True,
                text=True
            )
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if parts and parts[0] not in services:
                        services.append(parts[0])
        except Exception:
            pass

    for service in services:
        restart_count = get_service_restart_count(service, hours)

        if restart_count >= threshold:
            status = get_service_status(service) or {}

            # Get NRestarts if available (systemd tracks this)
            n_restarts = status.get('NRestarts', '0')
            try:
                n_restarts = int(n_restarts)
            except ValueError:
                n_restarts = 0

            loop_info = {
                'service': service,
                'restarts_in_window': restart_count,
                'total_restarts': n_restarts,
                'hours_checked': hours,
                'active_state': status.get('ActiveState', 'unknown'),
                'sub_state': status.get('SubState', 'unknown'),
                'result': status.get('Result', 'unknown'),
                'main_pid': status.get('MainPID', '0'),
                'last_start': status.get('ExecMainStartTimestamp', 'unknown'),
            }
            loops.append(loop_info)

    # Sort by restart count descending
    loops.sort(key=lambda x: x['restarts_in_window'], reverse=True)

    return loops


def format_plain(loops, threshold, hours, verbose=False):
    """Format results as plain text."""
    output = []

    output.append("Systemd Service Restart Loop Detector")
    output.append("=" * 50)
    output.append(f"Time window: {hours} hour(s)")
    output.append(f"Restart threshold: {threshold}")
    output.append(f"Services in restart loop: {len(loops)}")
    output.append("")

    if not loops:
        output.append("No services detected in restart loops.")
        return '\n'.join(output)

    output.append("SERVICES IN RESTART LOOP:")
    output.append("-" * 50)

    for loop in loops:
        status_icon = "[CRITICAL]" if loop['restarts_in_window'] >= threshold * 2 else "[WARNING]"
        output.append(f"{status_icon} {loop['service']}")
        output.append(f"  Restarts in last {hours}h: {loop['restarts_in_window']}")
        output.append(f"  Current state: {loop['active_state']}/{loop['sub_state']}")
        output.append(f"  Last result: {loop['result']}")

        if verbose:
            output.append(f"  Total restarts (session): {loop['total_restarts']}")
            output.append(f"  Last start: {loop['last_start']}")
            output.append(f"  Main PID: {loop['main_pid']}")

            # Get recent logs
            logs = get_recent_service_logs(loop['service'], lines=3)
            if logs:
                output.append("  Recent logs:")
                for line in logs.split('\n')[:3]:
                    output.append(f"    {line[:100]}")

        output.append("")

    # Summary
    critical = sum(1 for l in loops if l['restarts_in_window'] >= threshold * 2)
    warning = len(loops) - critical

    output.append("-" * 50)
    output.append(f"Summary: {critical} critical, {warning} warning")

    if loops:
        output.append("")
        output.append("Recommended actions:")
        output.append("  - Check service logs: journalctl -u <service> -n 50")
        output.append("  - Check service status: systemctl status <service>")
        output.append("  - Review service configuration and dependencies")

    return '\n'.join(output)


def format_json(loops, threshold, hours):
    """Format results as JSON."""
    critical = sum(1 for l in loops if l['restarts_in_window'] >= threshold * 2)

    result = {
        'summary': {
            'time_window_hours': hours,
            'restart_threshold': threshold,
            'services_in_loop': len(loops),
            'critical_count': critical,
            'warning_count': len(loops) - critical,
        },
        'services': loops,
    }

    return json.dumps(result, indent=2, default=str)


def format_table(loops, threshold):
    """Format results as a table."""
    output = []

    header = f"{'SERVICE':<40} {'RESTARTS':<10} {'STATE':<15} {'RESULT':<12} {'STATUS':<10}"
    output.append(header)
    output.append("-" * len(header))

    for loop in loops:
        service = loop['service'][:39]
        restarts = loop['restarts_in_window']
        state = f"{loop['active_state']}/{loop['sub_state']}"[:14]
        result = loop['result'][:11]
        status = "CRITICAL" if restarts >= threshold * 2 else "WARNING"

        output.append(f"{service:<40} {restarts:<10} {state:<15} {result:<12} {status:<10}")

    if not loops:
        output.append("No services in restart loops detected.")

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Detect systemd services stuck in restart loops.',
        epilog='''
Examples:
  # Check for restart loops in the last hour
  baremetal_systemd_restart_loop_detector.py

  # Check last 6 hours with custom threshold
  baremetal_systemd_restart_loop_detector.py --hours 6 --threshold 5

  # Check all services (not just failed ones)
  baremetal_systemd_restart_loop_detector.py --all

  # Output as JSON for monitoring systems
  baremetal_systemd_restart_loop_detector.py --format json

  # Verbose output with recent logs
  baremetal_systemd_restart_loop_detector.py --verbose

Exit codes:
  0 - No restart loops detected
  1 - One or more services in restart loop
  2 - Usage error or systemctl not available
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
        help='Show detailed information including recent logs'
    )
    parser.add_argument(
        '-H', '--hours',
        type=float,
        default=1,
        help='Time window in hours to check for restarts (default: 1)'
    )
    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=3,
        help='Minimum restarts to consider a loop (default: 3)'
    )
    parser.add_argument(
        '-a', '--all',
        action='store_true',
        help='Check all services, not just failed/activating ones'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if restart loops are detected'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.hours <= 0:
        print("Error: Hours must be a positive number", file=sys.stderr)
        return 2

    if args.threshold <= 0:
        print("Error: Threshold must be a positive number", file=sys.stderr)
        return 2

    # Check for systemctl
    if not check_systemctl_available():
        print("Error: systemctl not found", file=sys.stderr)
        print("This script requires systemd", file=sys.stderr)
        return 2

    # Detect restart loops
    loops = detect_restart_loops(
        hours=args.hours,
        threshold=args.threshold,
        check_all=args.all
    )

    # Handle warn-only mode
    if args.warn_only and not loops:
        return 0

    # Format output
    if args.format == 'json':
        output = format_json(loops, args.threshold, args.hours)
    elif args.format == 'table':
        output = format_table(loops, args.threshold)
    else:
        output = format_plain(loops, args.threshold, args.hours, args.verbose)

    print(output)

    # Return 1 if any loops detected
    return 1 if loops else 0


if __name__ == '__main__':
    sys.exit(main())
