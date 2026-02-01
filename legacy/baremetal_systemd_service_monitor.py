#!/usr/bin/env python3
"""
Monitor systemd service health and detect failed or degraded services.

This script checks the status of systemd services to identify failed units,
services in degraded state, and services that have been restarting frequently.
Useful for proactive monitoring in large baremetal environments.

Key features:
- Detect failed systemd units
- Identify services that have restarted recently
- Check for masked or disabled critical services
- Monitor service resource usage patterns

Exit codes:
    0 - All monitored services healthy
    1 - One or more services have warnings or failures
    2 - Missing dependencies or usage error
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime


def run_command(cmd):
    """Execute a command and return output."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def check_systemctl_available():
    """Check if systemctl is available."""
    returncode, _, _ = run_command(['which', 'systemctl'])
    return returncode == 0


def get_failed_units():
    """Get list of failed systemd units."""
    returncode, stdout, _ = run_command(
        ['systemctl', '--failed', '--no-legend', '--no-pager']
    )

    if returncode != 0:
        return []

    failed = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            unit = parts[0]
            load = parts[1]
            active = parts[2]
            sub = parts[3]
            description = ' '.join(parts[4:]) if len(parts) > 4 else ''

            failed.append({
                'unit': unit,
                'load': load,
                'active': active,
                'sub': sub,
                'description': description
            })

    return failed


def get_system_state():
    """Get overall system state (running, degraded, etc.)."""
    returncode, stdout, _ = run_command(['systemctl', 'is-system-running'])
    return stdout.strip()


def get_service_status(service_name):
    """Get detailed status of a specific service."""
    returncode, stdout, _ = run_command(
        ['systemctl', 'show', service_name, '--no-pager']
    )

    if returncode != 0:
        return None

    status = {}
    for line in stdout.split('\n'):
        if '=' in line:
            key, _, value = line.partition('=')
            status[key] = value

    return status


def get_service_restart_count(service_name):
    """Get restart count for a service (if available)."""
    status = get_service_status(service_name)
    if status:
        restart_count = status.get('NRestarts', '0')
        try:
            return int(restart_count)
        except ValueError:
            return 0
    return 0


def get_all_services(state_filter=None):
    """Get list of all services with their states."""
    cmd = ['systemctl', 'list-units', '--type=service', '--no-legend', '--no-pager', '--all']
    if state_filter:
        cmd.extend(['--state={}'.format(state_filter)])

    returncode, stdout, _ = run_command(cmd)

    if returncode != 0:
        return []

    services = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 4:
            unit = parts[0]
            load = parts[1]
            active = parts[2]
            sub = parts[3]
            description = ' '.join(parts[4:]) if len(parts) > 4 else ''

            services.append({
                'unit': unit,
                'load': load,
                'active': active,
                'sub': sub,
                'description': description
            })

    return services


def check_critical_services(critical_list):
    """Check if critical services are running."""
    issues = []

    for service in critical_list:
        # Ensure service name ends with .service
        if not service.endswith('.service'):
            service_name = service + '.service'
        else:
            service_name = service

        returncode, stdout, _ = run_command(
            ['systemctl', 'is-active', service_name]
        )
        state = stdout.strip()

        if state != 'active':
            # Get more details
            status = get_service_status(service_name)
            load_state = status.get('LoadState', 'unknown') if status else 'unknown'

            issues.append({
                'service': service_name,
                'state': state,
                'load_state': load_state,
                'issue': 'Critical service not active'
            })

    return issues


def get_recently_restarted_services(threshold_restarts=3):
    """Find services that have restarted multiple times."""
    services = get_all_services()
    restarted = []

    for svc in services:
        unit = svc['unit']
        restart_count = get_service_restart_count(unit)

        if restart_count >= threshold_restarts:
            restarted.append({
                'unit': unit,
                'restart_count': restart_count,
                'active': svc['active'],
                'sub': svc['sub']
            })

    return restarted


def get_masked_services():
    """Get list of masked services."""
    services = get_all_services()
    masked = []

    for svc in services:
        if svc['load'] == 'masked':
            masked.append(svc)

    return masked


def main():
    parser = argparse.ArgumentParser(
        description='Monitor systemd service health and detect failures',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         # Check for failed services
  %(prog)s --critical sshd,docker  # Check specific critical services
  %(prog)s --restart-threshold 5   # Warn on services restarted 5+ times
  %(prog)s --format json           # JSON output for monitoring systems

Exit codes:
  0 - All services healthy
  1 - Warnings or failures detected
  2 - Missing dependencies or usage error
"""
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed service information'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--warn-only',
        action='store_true',
        help='Only show services with warnings or failures'
    )
    parser.add_argument(
        '--critical',
        metavar='SERVICES',
        help='Comma-separated list of critical services to check'
    )
    parser.add_argument(
        '--restart-threshold',
        type=int,
        default=3,
        metavar='N',
        help='Warn if service has restarted N or more times (default: 3)'
    )
    parser.add_argument(
        '--show-masked',
        action='store_true',
        help='Include masked services in output'
    )

    args = parser.parse_args()

    # Check if systemctl is available
    if not check_systemctl_available():
        print("Error: systemctl not found. This script requires systemd.",
              file=sys.stderr)
        print("This system may not be using systemd as the init system.",
              file=sys.stderr)
        sys.exit(2)

    results = {
        'system_state': get_system_state(),
        'failed_units': [],
        'critical_issues': [],
        'restart_warnings': [],
        'masked_services': [],
        'timestamp': datetime.now().isoformat()
    }

    has_issues = False

    # Get system state
    system_state = results['system_state']
    if system_state not in ['running', 'initializing', 'starting']:
        has_issues = True

    # Get failed units
    failed_units = get_failed_units()
    results['failed_units'] = failed_units
    if failed_units:
        has_issues = True

    # Check critical services
    if args.critical:
        critical_list = [s.strip() for s in args.critical.split(',')]
        critical_issues = check_critical_services(critical_list)
        results['critical_issues'] = critical_issues
        if critical_issues:
            has_issues = True

    # Check for frequently restarted services
    restart_warnings = get_recently_restarted_services(args.restart_threshold)
    results['restart_warnings'] = restart_warnings
    if restart_warnings:
        has_issues = True

    # Get masked services
    if args.show_masked:
        masked_services = get_masked_services()
        results['masked_services'] = masked_services

    # Output results
    if args.format == 'json':
        output = {
            'system_state': results['system_state'],
            'failed_units': results['failed_units'],
            'critical_issues': results['critical_issues'],
            'restart_warnings': results['restart_warnings'],
            'masked_services': results['masked_services'],
            'summary': {
                'failed_count': len(results['failed_units']),
                'critical_issues_count': len(results['critical_issues']),
                'restart_warnings_count': len(results['restart_warnings']),
                'masked_count': len(results['masked_services']),
                'has_issues': has_issues
            },
            'timestamp': results['timestamp']
        }
        print(json.dumps(output, indent=2))

    elif args.format == 'table':
        # System state
        print("System State: {}".format(system_state))
        print()

        # Failed units table
        if failed_units or not args.warn_only:
            print("{:<40} {:<10} {:<10} {:<10}".format(
                'FAILED UNIT', 'LOAD', 'ACTIVE', 'SUB'
            ))
            print("-" * 70)
            if failed_units:
                for unit in failed_units:
                    print("{:<40} {:<10} {:<10} {:<10}".format(
                        unit['unit'][:40],
                        unit['load'],
                        unit['active'],
                        unit['sub']
                    ))
            else:
                print("(none)")
            print()

        # Critical issues
        if results['critical_issues']:
            print("{:<40} {:<15} {:<15}".format(
                'CRITICAL SERVICE', 'STATE', 'LOAD STATE'
            ))
            print("-" * 70)
            for issue in results['critical_issues']:
                print("{:<40} {:<15} {:<15}".format(
                    issue['service'][:40],
                    issue['state'],
                    issue['load_state']
                ))
            print()

        # Restart warnings
        if restart_warnings:
            print("{:<40} {:<10} {:<10} {:<10}".format(
                'SERVICE', 'RESTARTS', 'ACTIVE', 'SUB'
            ))
            print("-" * 70)
            for svc in restart_warnings:
                print("{:<40} {:<10} {:<10} {:<10}".format(
                    svc['unit'][:40],
                    svc['restart_count'],
                    svc['active'],
                    svc['sub']
                ))
            print()

    else:  # plain format
        # System state
        state_symbol = '[OK]' if system_state == 'running' else '[WARN]'
        print("{} System state: {}".format(state_symbol, system_state))
        print()

        # Failed units
        if failed_units:
            print("Failed Units ({} found):".format(len(failed_units)))
            for unit in failed_units:
                print("  [FAIL] {} - {}".format(unit['unit'], unit['sub']))
                if args.verbose and unit['description']:
                    print("         {}".format(unit['description']))
            print()
        elif not args.warn_only:
            print("[OK] No failed units")
            print()

        # Critical service issues
        if results['critical_issues']:
            print("Critical Service Issues:")
            for issue in results['critical_issues']:
                print("  [CRIT] {} is {} (load: {})".format(
                    issue['service'],
                    issue['state'],
                    issue['load_state']
                ))
            print()

        # Restart warnings
        if restart_warnings:
            print("Services with frequent restarts (>={} restarts):".format(
                args.restart_threshold
            ))
            for svc in restart_warnings:
                print("  [WARN] {} - {} restarts (currently: {}/{})".format(
                    svc['unit'],
                    svc['restart_count'],
                    svc['active'],
                    svc['sub']
                ))
            print()

        # Masked services
        if args.show_masked and results['masked_services']:
            print("Masked Services:")
            for svc in results['masked_services']:
                print("  [INFO] {} (masked)".format(svc['unit']))
            print()

        # Summary
        if not has_issues:
            print("[OK] All services healthy")

    # Exit code
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
