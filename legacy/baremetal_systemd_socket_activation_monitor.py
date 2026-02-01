#!/usr/bin/env python3
"""
Monitor systemd socket activation units for health and connection status.

Socket activation is a systemd feature where services start on-demand when
connections arrive at a listening socket. This script monitors:

- Socket unit status (active, listening, failed)
- Socket-to-service associations
- Connection queues and accepted connections
- Failed socket activations
- Orphaned sockets (no associated service)

Common issues detected:
- Failed socket units preventing service activation
- Socket units stuck in non-listening state
- Services failing to start on socket activation
- Connection backlog buildup indicating performance issues

Exit codes:
    0 - All socket units healthy
    1 - Warnings or errors detected (failed sockets, issues found)
    2 - Usage error or systemctl not available
"""

import argparse
import json
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple


def check_systemctl_available() -> bool:
    """Check if systemctl is available."""
    try:
        result = subprocess.run(
            ['which', 'systemctl'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def run_systemctl(args: List[str]) -> Tuple[int, str, str]:
    """Run systemctl command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            ['systemctl'] + args,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def get_socket_units() -> List[Dict[str, str]]:
    """Get list of all socket units with their status."""
    sockets = []

    # List all socket units
    returncode, stdout, stderr = run_systemctl([
        'list-units', '--type=socket', '--all', '--no-legend', '--no-pager'
    ])

    if returncode != 0:
        return sockets

    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue

        # Parse: UNIT LOAD ACTIVE SUB DESCRIPTION
        parts = line.split(None, 4)
        if len(parts) >= 4:
            sockets.append({
                'unit': parts[0],
                'load': parts[1],
                'active': parts[2],
                'sub': parts[3],
                'description': parts[4] if len(parts) > 4 else ''
            })

    return sockets


def get_socket_details(unit: str) -> Dict[str, Any]:
    """Get detailed information about a socket unit."""
    details = {
        'unit': unit,
        'listen': [],
        'triggers': [],
        'accepted': 0,
        'connections': 0,
        'n_refused': 0,
    }

    # Get socket show properties
    returncode, stdout, stderr = run_systemctl([
        'show', unit,
        '--property=Listen',
        '--property=Triggers',
        '--property=NAccepted',
        '--property=NConnections',
        '--property=NRefused',
        '--property=ActiveState',
        '--property=SubState',
        '--property=Result',
        '--property=BindIPv6Only',
        '--property=Backlog',
        '--property=MaxConnections',
        '--property=MaxConnectionsPerSource',
        '--property=Accept',
    ])

    if returncode == 0:
        for line in stdout.strip().split('\n'):
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()

            if key == 'Listen':
                # Parse listen addresses
                # Format: Stream: /path or Stream: [::]:port or Stream: 0.0.0.0:port
                if value:
                    for addr in value.split():
                        if addr and addr not in ['Stream:', 'Datagram:', 'Sequential:']:
                            details['listen'].append(addr)
            elif key == 'Triggers':
                if value:
                    details['triggers'] = [t.strip() for t in value.split() if t.strip()]
            elif key == 'NAccepted':
                try:
                    details['accepted'] = int(value)
                except ValueError:
                    pass
            elif key == 'NConnections':
                try:
                    details['connections'] = int(value)
                except ValueError:
                    pass
            elif key == 'NRefused':
                try:
                    details['n_refused'] = int(value)
                except ValueError:
                    pass
            elif key == 'ActiveState':
                details['active_state'] = value
            elif key == 'SubState':
                details['sub_state'] = value
            elif key == 'Result':
                details['result'] = value
            elif key == 'Backlog':
                try:
                    details['backlog'] = int(value)
                except ValueError:
                    pass
            elif key == 'MaxConnections':
                try:
                    details['max_connections'] = int(value)
                except ValueError:
                    pass
            elif key == 'Accept':
                details['accept'] = value.lower() == 'yes'

    return details


def check_triggered_service_status(triggers: List[str]) -> Dict[str, str]:
    """Check the status of triggered services."""
    service_status = {}

    for service in triggers:
        returncode, stdout, stderr = run_systemctl([
            'show', service, '--property=ActiveState', '--property=SubState'
        ])

        if returncode == 0:
            active_state = 'unknown'
            sub_state = 'unknown'
            for line in stdout.strip().split('\n'):
                if line.startswith('ActiveState='):
                    active_state = line.split('=', 1)[1]
                elif line.startswith('SubState='):
                    sub_state = line.split('=', 1)[1]
            service_status[service] = f"{active_state}/{sub_state}"
        else:
            service_status[service] = 'unknown'

    return service_status


def analyze_socket(socket_info: Dict[str, str], details: Dict[str, Any],
                   refuse_warn: int) -> Dict[str, Any]:
    """Analyze a socket unit and identify issues."""
    result = {
        'unit': socket_info['unit'],
        'status': 'healthy',
        'issues': [],
        'warnings': [],
        'listen': details.get('listen', []),
        'triggers': details.get('triggers', []),
        'metrics': {
            'accepted': details.get('accepted', 0),
            'connections': details.get('connections', 0),
            'refused': details.get('n_refused', 0),
        }
    }

    active = socket_info.get('active', 'unknown')
    sub = socket_info.get('sub', 'unknown')
    load = socket_info.get('load', 'unknown')

    result['active'] = active
    result['sub'] = sub
    result['load'] = load

    # Check for failed state
    if active == 'failed' or sub == 'failed':
        result['status'] = 'critical'
        result['issues'].append({
            'type': 'socket_failed',
            'message': f'Socket unit is in failed state: {active}/{sub}'
        })

    # Check for inactive state (not listening)
    elif active == 'inactive':
        result['status'] = 'warning'
        result['warnings'].append({
            'type': 'socket_inactive',
            'message': 'Socket unit is inactive (not listening)'
        })

    # Check load state
    if load == 'not-found':
        result['status'] = 'critical'
        result['issues'].append({
            'type': 'unit_not_found',
            'message': 'Socket unit file not found'
        })
    elif load == 'error':
        result['status'] = 'critical'
        result['issues'].append({
            'type': 'unit_load_error',
            'message': 'Error loading socket unit file'
        })

    # Check for refused connections
    refused = details.get('n_refused', 0)
    if refused > 0 and refused >= refuse_warn:
        if result['status'] == 'healthy':
            result['status'] = 'warning'
        result['warnings'].append({
            'type': 'connections_refused',
            'value': refused,
            'message': f'{refused} connections refused (indicates overload or misconfiguration)'
        })

    # Check for no triggered service
    triggers = details.get('triggers', [])
    if not triggers and active == 'active':
        if result['status'] == 'healthy':
            result['status'] = 'warning'
        result['warnings'].append({
            'type': 'no_triggered_service',
            'message': 'Socket has no associated service to trigger'
        })

    # Check triggered service status
    if triggers:
        service_status = check_triggered_service_status(triggers)
        result['service_status'] = service_status

        for service, status in service_status.items():
            if 'failed' in status:
                if result['status'] != 'critical':
                    result['status'] = 'critical'
                result['issues'].append({
                    'type': 'triggered_service_failed',
                    'service': service,
                    'message': f'Triggered service {service} is in failed state: {status}'
                })

    # Check result field (for sockets that ran and stopped)
    socket_result = details.get('result', 'success')
    if socket_result not in ['success', '']:
        if result['status'] == 'healthy':
            result['status'] = 'warning'
        result['warnings'].append({
            'type': 'socket_result',
            'value': socket_result,
            'message': f'Socket activation result: {socket_result}'
        })

    return result


def output_plain(results: List[Dict[str, Any]], verbose: bool, warn_only: bool) -> None:
    """Output results in plain text format."""
    if warn_only:
        results = [r for r in results if r['status'] != 'healthy']
        if not results:
            print("All systemd socket units healthy")
            return

    print("Systemd Socket Activation Monitor")
    print("=" * 70)
    print()

    for socket in results:
        status_icon = '✓' if socket['status'] == 'healthy' else '!' if socket['status'] == 'warning' else '✗'
        print(f"[{status_icon}] {socket['unit']}: {socket['status'].upper()}")
        print(f"    State: {socket['active']}/{socket['sub']}")

        if socket.get('listen'):
            print(f"    Listen: {', '.join(socket['listen'])}")

        if socket.get('triggers'):
            print(f"    Triggers: {', '.join(socket['triggers'])}")

        metrics = socket.get('metrics', {})
        if verbose or metrics.get('accepted', 0) > 0:
            print(f"    Accepted: {metrics.get('accepted', 0)} connections")
        if verbose or metrics.get('connections', 0) > 0:
            print(f"    Current: {metrics.get('connections', 0)} connections")
        if metrics.get('refused', 0) > 0:
            print(f"    Refused: {metrics.get('refused', 0)} connections")

        if verbose and socket.get('service_status'):
            for service, status in socket['service_status'].items():
                print(f"    Service {service}: {status}")

        for issue in socket.get('issues', []):
            print(f"    [CRITICAL] {issue['message']}")

        for warning in socket.get('warnings', []):
            print(f"    [WARNING] {warning['message']}")

        print()

    # Summary
    total = len(results)
    healthy = sum(1 for r in results if r['status'] == 'healthy')
    warning = sum(1 for r in results if r['status'] == 'warning')
    critical = sum(1 for r in results if r['status'] == 'critical')

    total_accepted = sum(r.get('metrics', {}).get('accepted', 0) for r in results)
    total_refused = sum(r.get('metrics', {}).get('refused', 0) for r in results)

    print(f"Summary: {total} sockets - {healthy} healthy, {warning} warning, {critical} critical")
    if verbose:
        print(f"Total connections: {total_accepted} accepted, {total_refused} refused")


def output_json(results: List[Dict[str, Any]]) -> None:
    """Output results in JSON format."""
    total = len(results)
    healthy = sum(1 for r in results if r['status'] == 'healthy')
    warning = sum(1 for r in results if r['status'] == 'warning')
    critical = sum(1 for r in results if r['status'] == 'critical')

    if critical > 0:
        overall_status = 'critical'
    elif warning > 0:
        overall_status = 'warning'
    else:
        overall_status = 'healthy'

    total_accepted = sum(r.get('metrics', {}).get('accepted', 0) for r in results)
    total_connections = sum(r.get('metrics', {}).get('connections', 0) for r in results)
    total_refused = sum(r.get('metrics', {}).get('refused', 0) for r in results)

    output = {
        'status': overall_status,
        'summary': {
            'total_sockets': total,
            'healthy': healthy,
            'warning': warning,
            'critical': critical,
            'total_accepted': total_accepted,
            'total_connections': total_connections,
            'total_refused': total_refused,
        },
        'sockets': results,
    }

    print(json.dumps(output, indent=2))


def output_table(results: List[Dict[str, Any]], warn_only: bool) -> None:
    """Output results in table format."""
    if warn_only:
        results = [r for r in results if r['status'] != 'healthy']
        if not results:
            print("All systemd socket units healthy")
            return

    print(f"{'Socket Unit':<35} {'State':<15} {'Accepted':>10} {'Refused':>10} {'Status':<10}")
    print("=" * 90)

    for socket in results:
        unit = socket['unit'][:35]
        state = f"{socket['active']}/{socket['sub']}"[:15]
        metrics = socket.get('metrics', {})
        accepted = metrics.get('accepted', 0)
        refused = metrics.get('refused', 0)

        print(f"{unit:<35} {state:<15} {accepted:>10} {refused:>10} {socket['status'].upper():<10}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor systemd socket activation units for health and connection status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Check all socket units
  %(prog)s --unit ssh.socket      Check specific socket
  %(prog)s --format json          Output in JSON for monitoring
  %(prog)s --warn-only            Only show sockets with issues
  %(prog)s --verbose              Show detailed metrics

What is socket activation?
  Socket activation is a systemd feature where services start on-demand
  when connections arrive at a listening socket. This improves boot time
  and resource usage, but failures can cause subtle availability issues.

Key issues detected:
  - Failed socket units preventing service activation
  - Sockets not in listening state
  - High connection refusal rates
  - Triggered services in failed state

Exit codes:
  0 - All socket units healthy
  1 - Warnings or critical issues detected
  2 - Usage error or systemctl not available
"""
    )

    parser.add_argument(
        '-u', '--unit',
        metavar='NAME',
        help='Specific socket unit to check (e.g., ssh.socket)'
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
        help='Show detailed metrics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show sockets with warnings or issues'
    )

    parser.add_argument(
        '--refuse-warn',
        type=int,
        default=10,
        metavar='COUNT',
        help='Warn if refused connections exceed this count (default: 10)'
    )

    parser.add_argument(
        '--include-inactive',
        action='store_true',
        help='Include inactive socket units in output'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.refuse_warn < 0:
        print("Error: --refuse-warn must be non-negative", file=sys.stderr)
        return 2

    # Check for systemctl
    if not check_systemctl_available():
        print("Error: systemctl not found", file=sys.stderr)
        print("This tool requires systemd to be running", file=sys.stderr)
        return 2

    # Get sockets to check
    if args.unit:
        # Check specific unit
        unit = args.unit
        if not unit.endswith('.socket'):
            unit = f"{unit}.socket"

        # Verify unit exists
        returncode, stdout, stderr = run_systemctl(['show', unit, '--property=LoadState'])
        if 'LoadState=not-found' in stdout:
            print(f"Error: Socket unit {unit} not found", file=sys.stderr)
            return 2

        sockets = [{
            'unit': unit,
            'load': 'loaded',
            'active': 'unknown',
            'sub': 'unknown',
            'description': ''
        }]

        # Get actual status
        returncode, stdout, stderr = run_systemctl([
            'show', unit, '--property=LoadState', '--property=ActiveState', '--property=SubState'
        ])
        if returncode == 0:
            for line in stdout.strip().split('\n'):
                if line.startswith('LoadState='):
                    sockets[0]['load'] = line.split('=', 1)[1]
                elif line.startswith('ActiveState='):
                    sockets[0]['active'] = line.split('=', 1)[1]
                elif line.startswith('SubState='):
                    sockets[0]['sub'] = line.split('=', 1)[1]
    else:
        sockets = get_socket_units()

    if not sockets:
        if args.format == 'json':
            print(json.dumps({'status': 'ok', 'message': 'No socket units found', 'sockets': []}))
        else:
            print("No socket units found")
        return 0

    # Filter inactive if not requested
    if not args.include_inactive and not args.unit:
        sockets = [s for s in sockets if s['active'] != 'inactive' or s['load'] == 'error']
        # Always include failed sockets
        inactive_failed = [s for s in get_socket_units() if s['active'] == 'inactive' and s['sub'] == 'failed']
        for s in inactive_failed:
            if s not in sockets:
                sockets.append(s)

    if not sockets:
        if args.format == 'json':
            print(json.dumps({'status': 'ok', 'message': 'No active socket units', 'sockets': []}))
        else:
            print("No active socket units (use --include-inactive to see all)")
        return 0

    # Analyze each socket
    results = []
    for socket in sockets:
        details = get_socket_details(socket['unit'])
        result = analyze_socket(socket, details, args.refuse_warn)
        results.append(result)

    # Sort by status (critical first, then warning, then healthy)
    status_order = {'critical': 0, 'warning': 1, 'healthy': 2}
    results.sort(key=lambda x: (status_order.get(x['status'], 3), x['unit']))

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.verbose, args.warn_only)

    # Determine exit code
    has_critical = any(r['status'] == 'critical' for r in results)
    has_warning = any(r['status'] == 'warning' for r in results)

    if has_critical or has_warning:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
