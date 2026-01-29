#!/usr/bin/env python3
"""
Monitor Linux audit daemon (auditd) health and configuration.

This script checks the health and status of the Linux audit daemon,
verifying that audit logging is active, rules are loaded, and the
audit log is not experiencing issues. Essential for security compliance
monitoring in enterprise baremetal environments.

Key features:
- Check auditd service status
- Verify audit rules are loaded
- Monitor audit log disk usage and rotation
- Detect lost or backlog events
- Check audit configuration settings

Exit codes:
    0 - Audit daemon healthy, all checks pass
    1 - Warnings or issues detected
    2 - Missing dependencies or usage error
"""

import argparse
import json
import os
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


def check_auditd_available():
    """Check if auditd tools are available."""
    # Check for auditctl (primary tool)
    returncode, _, _ = run_command(['which', 'auditctl'])
    return returncode == 0


def check_auditd_service_status():
    """Check if auditd service is running."""
    # Try systemctl first
    returncode, stdout, _ = run_command(['systemctl', 'is-active', 'auditd'])
    if returncode == 0 and stdout.strip() == 'active':
        return {
            'running': True,
            'method': 'systemctl',
            'status': 'active'
        }

    # Try checking for auditd process directly
    returncode, stdout, _ = run_command(['pgrep', '-x', 'auditd'])
    if returncode == 0 and stdout.strip():
        return {
            'running': True,
            'method': 'pgrep',
            'status': 'running',
            'pid': stdout.strip().split('\n')[0]
        }

    return {
        'running': False,
        'method': 'systemctl',
        'status': 'inactive'
    }


def get_audit_status():
    """Get audit subsystem status from auditctl."""
    returncode, stdout, stderr = run_command(['auditctl', '-s'])

    if returncode != 0:
        return None

    status = {}
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue
        # Parse lines like "enabled 1" or "backlog 0"
        parts = line.split()
        if len(parts) >= 2:
            key = parts[0]
            value = parts[1]
            # Try to convert numeric values
            try:
                status[key] = int(value)
            except ValueError:
                status[key] = value

    return status


def get_audit_rules():
    """Get loaded audit rules."""
    returncode, stdout, stderr = run_command(['auditctl', '-l'])

    if returncode != 0:
        return None

    rules = []
    for line in stdout.strip().split('\n'):
        line = line.strip()
        if line and line != 'No rules':
            rules.append(line)

    return rules


def get_audit_log_info():
    """Get information about the audit log file."""
    log_path = '/var/log/audit/audit.log'
    log_dir = '/var/log/audit'

    info = {
        'log_path': log_path,
        'exists': False,
        'size_bytes': 0,
        'size_human': '0B',
        'dir_exists': False,
        'dir_size_bytes': 0,
        'dir_size_human': '0B',
        'file_count': 0
    }

    # Check log file
    if os.path.exists(log_path):
        info['exists'] = True
        try:
            stat_info = os.stat(log_path)
            info['size_bytes'] = stat_info.st_size
            info['size_human'] = format_size(stat_info.st_size)
        except OSError:
            pass

    # Check log directory
    if os.path.isdir(log_dir):
        info['dir_exists'] = True
        total_size = 0
        file_count = 0
        try:
            for entry in os.listdir(log_dir):
                full_path = os.path.join(log_dir, entry)
                if os.path.isfile(full_path):
                    file_count += 1
                    try:
                        total_size += os.path.getsize(full_path)
                    except OSError:
                        pass
            info['dir_size_bytes'] = total_size
            info['dir_size_human'] = format_size(total_size)
            info['file_count'] = file_count
        except OSError:
            pass

    return info


def format_size(size_bytes):
    """Format bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return "{:.1f}{}".format(size_bytes, unit)
        size_bytes /= 1024
    return "{:.1f}PB".format(size_bytes)


def get_audit_config():
    """Parse audit daemon configuration."""
    config_path = '/etc/audit/auditd.conf'
    config = {
        'config_path': config_path,
        'exists': False,
        'settings': {}
    }

    if not os.path.exists(config_path):
        return config

    config['exists'] = True

    try:
        with open(config_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Parse key = value
                if '=' in line:
                    key, _, value = line.partition('=')
                    config['settings'][key.strip()] = value.strip()
    except (OSError, IOError):
        pass

    return config


def analyze_status(status):
    """Analyze audit status for issues."""
    issues = []

    if status is None:
        issues.append({
            'severity': 'critical',
            'message': 'Cannot retrieve audit status (auditctl -s failed)'
        })
        return issues

    # Check if audit is enabled
    enabled = status.get('enabled', 0)
    if enabled == 0:
        issues.append({
            'severity': 'critical',
            'message': 'Audit subsystem is disabled (enabled=0)'
        })
    elif enabled == 2:
        issues.append({
            'severity': 'info',
            'message': 'Audit rules are locked (enabled=2, immutable mode)'
        })

    # Check for lost events
    lost = status.get('lost', 0)
    if lost > 0:
        issues.append({
            'severity': 'warning',
            'message': 'Audit events lost: {} events'.format(lost)
        })

    # Check backlog
    backlog = status.get('backlog', 0)
    backlog_limit = status.get('backlog_limit', 8192)
    if backlog_limit > 0 and backlog > backlog_limit * 0.8:
        issues.append({
            'severity': 'warning',
            'message': 'Audit backlog high: {}/{} ({:.0f}%)'.format(
                backlog, backlog_limit, (backlog / backlog_limit) * 100
            )
        })

    # Check failure mode
    failure = status.get('failure', 1)
    if failure == 0:
        issues.append({
            'severity': 'warning',
            'message': 'Audit failure mode is silent (failure=0)'
        })
    elif failure == 2:
        issues.append({
            'severity': 'info',
            'message': 'Audit failure mode is panic (failure=2)'
        })

    return issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Linux audit daemon (auditd) health and configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Basic health check
  %(prog)s --format json      # JSON output for monitoring systems
  %(prog)s --show-rules       # Include loaded audit rules in output
  %(prog)s --show-config      # Include auditd.conf settings
  %(prog)s -v                 # Verbose output with all details

Exit codes:
  0 - Audit daemon healthy
  1 - Warnings or issues detected
  2 - Missing dependencies or usage error
"""
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
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
        help='Only show warnings or issues'
    )
    parser.add_argument(
        '--show-rules',
        action='store_true',
        help='Include loaded audit rules in output'
    )
    parser.add_argument(
        '--show-config',
        action='store_true',
        help='Include auditd.conf settings in output'
    )
    parser.add_argument(
        '--min-rules',
        type=int,
        default=0,
        metavar='N',
        help='Warn if fewer than N audit rules are loaded (default: 0)'
    )

    args = parser.parse_args()

    # Check if auditd tools are available
    if not check_auditd_available():
        print("Error: auditctl not found. Install audit tools.", file=sys.stderr)
        print("  Debian/Ubuntu: sudo apt-get install auditd", file=sys.stderr)
        print("  RHEL/CentOS:   sudo yum install audit", file=sys.stderr)
        sys.exit(2)

    # Gather information
    results = {
        'timestamp': datetime.now().isoformat(),
        'service_status': check_auditd_service_status(),
        'audit_status': get_audit_status(),
        'audit_rules': get_audit_rules() if args.show_rules or args.verbose else None,
        'log_info': get_audit_log_info(),
        'config': get_audit_config() if args.show_config or args.verbose else None,
        'issues': []
    }

    has_issues = False

    # Check service status
    if not results['service_status']['running']:
        results['issues'].append({
            'severity': 'critical',
            'message': 'Audit daemon is not running'
        })
        has_issues = True

    # Analyze audit status
    status_issues = analyze_status(results['audit_status'])
    results['issues'].extend(status_issues)
    if any(i['severity'] in ['critical', 'warning'] for i in status_issues):
        has_issues = True

    # Check log file
    if not results['log_info']['exists']:
        results['issues'].append({
            'severity': 'warning',
            'message': 'Audit log file does not exist: {}'.format(
                results['log_info']['log_path']
            )
        })
        has_issues = True

    # Check minimum rules
    if args.min_rules > 0:
        rules = get_audit_rules()
        rule_count = len(rules) if rules else 0
        if rule_count < args.min_rules:
            results['issues'].append({
                'severity': 'warning',
                'message': 'Only {} audit rules loaded (minimum: {})'.format(
                    rule_count, args.min_rules
                )
            })
            has_issues = True

    # Output
    if args.format == 'json':
        output = {
            'service_status': results['service_status'],
            'audit_status': results['audit_status'],
            'log_info': results['log_info'],
            'issues': results['issues'],
            'summary': {
                'service_running': results['service_status']['running'],
                'audit_enabled': (results['audit_status'] or {}).get('enabled', 0) > 0,
                'rules_loaded': len(results['audit_rules'] or []),
                'log_size': results['log_info']['size_human'],
                'issue_count': len(results['issues']),
                'has_issues': has_issues
            },
            'timestamp': results['timestamp']
        }
        if args.show_rules or args.verbose:
            output['audit_rules'] = results['audit_rules']
        if args.show_config or args.verbose:
            output['config'] = results['config']
        print(json.dumps(output, indent=2))

    elif args.format == 'table':
        print("{:<25} {:<40}".format('CHECK', 'STATUS'))
        print("-" * 65)

        # Service status
        svc_status = 'Running' if results['service_status']['running'] else 'NOT RUNNING'
        print("{:<25} {:<40}".format('Audit Service', svc_status))

        # Audit enabled
        if results['audit_status']:
            enabled = results['audit_status'].get('enabled', 0)
            enabled_str = 'Yes' if enabled > 0 else 'No'
            if enabled == 2:
                enabled_str = 'Yes (locked)'
            print("{:<25} {:<40}".format('Audit Enabled', enabled_str))

            # Lost events
            lost = results['audit_status'].get('lost', 0)
            print("{:<25} {:<40}".format('Lost Events', str(lost)))

            # Backlog
            backlog = results['audit_status'].get('backlog', 0)
            backlog_limit = results['audit_status'].get('backlog_limit', 0)
            print("{:<25} {:<40}".format(
                'Backlog',
                "{}/{}".format(backlog, backlog_limit)
            ))

        # Rules
        rules = results['audit_rules'] or get_audit_rules() or []
        print("{:<25} {:<40}".format('Rules Loaded', str(len(rules))))

        # Log size
        print("{:<25} {:<40}".format('Log Size', results['log_info']['size_human']))
        print("{:<25} {:<40}".format(
            'Log Directory Size',
            results['log_info']['dir_size_human']
        ))

        # Issues
        if results['issues']:
            print()
            print("Issues:")
            print("-" * 65)
            for issue in results['issues']:
                print("[{:^8}] {}".format(
                    issue['severity'].upper(),
                    issue['message']
                ))

    else:  # plain format
        # Service status
        if results['service_status']['running']:
            if not args.warn_only:
                print("[OK] Audit daemon is running")
        else:
            print("[CRIT] Audit daemon is NOT running")

        # Audit status
        if results['audit_status']:
            enabled = results['audit_status'].get('enabled', 0)
            if enabled > 0:
                if not args.warn_only:
                    status_msg = 'enabled'
                    if enabled == 2:
                        status_msg = 'enabled (rules locked)'
                    print("[OK] Audit subsystem is {}".format(status_msg))
            else:
                print("[CRIT] Audit subsystem is DISABLED")

            # Lost events
            lost = results['audit_status'].get('lost', 0)
            if lost > 0:
                print("[WARN] {} audit events have been lost".format(lost))
            elif not args.warn_only:
                print("[OK] No audit events lost")

            # Backlog
            backlog = results['audit_status'].get('backlog', 0)
            backlog_limit = results['audit_status'].get('backlog_limit', 8192)
            if backlog_limit > 0 and backlog > backlog_limit * 0.8:
                print("[WARN] Audit backlog high: {}/{} ({:.0f}%)".format(
                    backlog, backlog_limit, (backlog / backlog_limit) * 100
                ))
            elif not args.warn_only and args.verbose:
                print("[OK] Audit backlog: {}/{}".format(backlog, backlog_limit))

        # Rules
        rules = results['audit_rules'] or get_audit_rules() or []
        if not args.warn_only:
            print("[INFO] {} audit rules loaded".format(len(rules)))
        if args.show_rules and rules:
            print()
            print("Loaded Rules:")
            for rule in rules:
                print("  {}".format(rule))

        # Log info
        if not args.warn_only:
            print("[INFO] Audit log: {} ({} files in directory, {})".format(
                results['log_info']['size_human'],
                results['log_info']['file_count'],
                results['log_info']['dir_size_human']
            ))

        # Config
        if args.show_config and results['config'] and results['config']['exists']:
            print()
            print("Configuration ({})".format(results['config']['config_path']))
            for key, value in sorted(results['config']['settings'].items()):
                print("  {} = {}".format(key, value))

        # Issues summary
        if results['issues']:
            print()
            for issue in results['issues']:
                if issue['severity'] == 'info' and args.warn_only:
                    continue
                severity_map = {
                    'critical': 'CRIT',
                    'warning': 'WARN',
                    'info': 'INFO'
                }
                print("[{}] {}".format(
                    severity_map.get(issue['severity'], 'INFO'),
                    issue['message']
                ))

        # Summary
        if not has_issues and not args.warn_only:
            print()
            print("[OK] Audit daemon healthy")

    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
