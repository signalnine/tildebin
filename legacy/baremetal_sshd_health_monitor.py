#!/usr/bin/env python3
"""
Monitor SSH daemon health, configuration, and connection limits.

Checks sshd service status, current connection counts, MaxSessions/MaxStartups
limits, authentication settings, and identifies potential security or
capacity issues. Useful for monitoring bastion hosts and jump servers
in large baremetal environments.

Exit codes:
    0 - SSH daemon healthy, no issues detected
    1 - Warnings or errors found
    2 - sshd not installed or not running
"""

import argparse
import subprocess
import sys
import json
import os
import re


def run_command(cmd, timeout=10):
    """Execute a command and return output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def check_sshd_installed():
    """Check if sshd is installed"""
    returncode, _, _ = run_command("which sshd")
    return returncode == 0


def check_sshd_running():
    """Check if sshd service is running"""
    # Try systemctl first
    returncode, stdout, _ = run_command("systemctl is-active sshd ssh 2>/dev/null")
    if returncode == 0 and 'active' in stdout:
        return True

    # Fall back to process check
    returncode, stdout, _ = run_command("pgrep -x sshd")
    return returncode == 0


def get_sshd_config():
    """Parse sshd configuration"""
    config = {}

    # Get effective configuration
    returncode, stdout, stderr = run_command("sshd -T 2>/dev/null")

    if returncode != 0:
        # Try reading config file directly
        config_file = '/etc/ssh/sshd_config'
        if os.path.exists(config_file):
            returncode, stdout, _ = run_command(f"cat {config_file}")
            if returncode == 0:
                for line in stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            config[parts[0].lower()] = parts[1]
        return config

    # Parse sshd -T output
    for line in stdout.split('\n'):
        line = line.strip()
        if line:
            parts = line.split(None, 1)
            if len(parts) == 2:
                config[parts[0].lower()] = parts[1]

    return config


def get_active_connections():
    """Get count of active SSH connections"""
    connections = {
        'total': 0,
        'established': 0,
        'by_user': {}
    }

    # Count established SSH connections
    returncode, stdout, _ = run_command(
        "ss -tn state established '( dport = :22 or sport = :22 )' 2>/dev/null | tail -n +2 | wc -l"
    )
    if returncode == 0:
        try:
            connections['established'] = int(stdout.strip())
        except ValueError:
            pass

    # Count sshd processes (each session has a child sshd)
    returncode, stdout, _ = run_command("pgrep -c sshd 2>/dev/null")
    if returncode == 0:
        try:
            # Subtract 1 for the main sshd process
            total = max(0, int(stdout.strip()) - 1)
            connections['total'] = total
        except ValueError:
            pass

    # Get connections by user from who command
    returncode, stdout, _ = run_command("who 2>/dev/null")
    if returncode == 0:
        for line in stdout.split('\n'):
            if line.strip():
                parts = line.split()
                if parts:
                    user = parts[0]
                    connections['by_user'][user] = connections['by_user'].get(user, 0) + 1

    return connections


def get_connection_attempts():
    """Get recent connection attempt statistics from auth log"""
    attempts = {
        'failed_24h': 0,
        'successful_24h': 0,
        'top_failed_ips': []
    }

    # Check auth log (try multiple locations)
    log_files = ['/var/log/auth.log', '/var/log/secure']

    for log_file in log_files:
        if os.path.exists(log_file):
            # Count failed attempts in last 24 hours
            returncode, stdout, _ = run_command(
                f"grep -c 'sshd.*Failed' {log_file} 2>/dev/null || echo 0"
            )
            if returncode == 0:
                try:
                    attempts['failed_24h'] = int(stdout.strip())
                except ValueError:
                    pass

            # Count successful logins
            returncode, stdout, _ = run_command(
                f"grep -c 'sshd.*Accepted' {log_file} 2>/dev/null || echo 0"
            )
            if returncode == 0:
                try:
                    attempts['successful_24h'] = int(stdout.strip())
                except ValueError:
                    pass

            # Get top failed IPs
            returncode, stdout, _ = run_command(
                f"grep 'sshd.*Failed' {log_file} 2>/dev/null | "
                f"grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | "
                f"sort | uniq -c | sort -rn | head -5"
            )
            if returncode == 0 and stdout.strip():
                for line in stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        attempts['top_failed_ips'].append({
                            'ip': parts[1],
                            'count': int(parts[0])
                        })
            break

    return attempts


def analyze_config(config, connections):
    """Analyze configuration for issues"""
    issues = []

    # Check MaxSessions limit
    max_sessions = int(config.get('maxsessions', 10))
    if connections['total'] > max_sessions * 0.8:
        issues.append({
            'severity': 'warning',
            'message': f"Approaching MaxSessions limit: {connections['total']}/{max_sessions} sessions"
        })

    # Check MaxStartups (format: start:rate:full or just a number)
    max_startups = config.get('maxstartups', '10:30:100')
    if ':' in str(max_startups):
        parts = max_startups.split(':')
        max_full = int(parts[2]) if len(parts) >= 3 else 100
    else:
        max_full = int(max_startups)

    # Security checks
    if config.get('permitrootlogin', 'no') in ['yes', 'without-password', 'prohibit-password']:
        root_login = config.get('permitrootlogin')
        if root_login == 'yes':
            issues.append({
                'severity': 'warning',
                'message': 'PermitRootLogin is set to yes (password auth allowed for root)'
            })

    if config.get('passwordauthentication', 'yes') == 'yes':
        issues.append({
            'severity': 'info',
            'message': 'PasswordAuthentication is enabled (consider key-only auth)'
        })

    if config.get('permitemptypasswords', 'no') == 'yes':
        issues.append({
            'severity': 'critical',
            'message': 'PermitEmptyPasswords is enabled (security risk!)'
        })

    # Check X11 forwarding
    if config.get('x11forwarding', 'no') == 'yes':
        issues.append({
            'severity': 'info',
            'message': 'X11Forwarding is enabled'
        })

    # Check TCP keepalive
    client_alive_interval = int(config.get('clientaliveinterval', 0))
    client_alive_count = int(config.get('clientalivecountmax', 3))

    if client_alive_interval == 0:
        issues.append({
            'severity': 'info',
            'message': 'ClientAliveInterval not set (zombie sessions may persist)'
        })

    return issues


def output_plain(result, verbose=False, warn_only=False):
    """Output results in plain text format"""
    print("SSH Daemon Health Monitor")
    print("=" * 60)
    print()

    status_symbol = "[ok]" if result['running'] else "[FAIL]"
    print(f"{status_symbol} sshd daemon: {'running' if result['running'] else 'not running'}")

    if not result['running']:
        print()
        return

    if verbose:
        config = result['config']
        print(f"\nConfiguration:")
        print(f"  Port: {config.get('port', '22')}")
        print(f"  MaxSessions: {config.get('maxsessions', '10')}")
        print(f"  MaxStartups: {config.get('maxstartups', '10:30:100')}")
        print(f"  PermitRootLogin: {config.get('permitrootlogin', 'not set')}")
        print(f"  PasswordAuthentication: {config.get('passwordauthentication', 'yes')}")

    connections = result['connections']
    print(f"\nActive Connections:")
    print(f"  Total sessions: {connections['total']}")
    print(f"  Established: {connections['established']}")

    if verbose and connections['by_user']:
        print(f"  By user:")
        for user, count in sorted(connections['by_user'].items()):
            print(f"    {user}: {count}")

    if verbose and result.get('attempts'):
        attempts = result['attempts']
        print(f"\nConnection Attempts (from logs):")
        print(f"  Successful: {attempts['successful_24h']}")
        print(f"  Failed: {attempts['failed_24h']}")
        if attempts['top_failed_ips']:
            print(f"  Top failed IPs:")
            for entry in attempts['top_failed_ips'][:3]:
                print(f"    {entry['ip']}: {entry['count']} attempts")

    if result['issues']:
        print(f"\nIssues:")
        for issue in result['issues']:
            if warn_only and issue['severity'] == 'info':
                continue
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")

    print()


def output_json(result):
    """Output results in JSON format"""
    print(json.dumps(result, indent=2))


def output_table(result, warn_only=False):
    """Output results in table format"""
    print(f"{'Metric':<30} {'Value':<40}")
    print("-" * 70)

    print(f"{'Daemon Status':<30} {'Running' if result['running'] else 'Not Running':<40}")

    if result['running']:
        conn = result['connections']
        print(f"{'Active Sessions':<30} {conn['total']:<40}")
        print(f"{'Established Connections':<30} {conn['established']:<40}")

        config = result['config']
        print(f"{'MaxSessions Limit':<30} {config.get('maxsessions', '10'):<40}")
        print(f"{'PermitRootLogin':<30} {config.get('permitrootlogin', 'not set'):<40}")

    if result['issues']:
        print()
        print("Issues:")
        for issue in result['issues']:
            if warn_only and issue['severity'] == 'info':
                continue
            print(f"  [{issue['severity'].upper()}] {issue['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor SSH daemon health, configuration, and connection limits",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including auth logs"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="Only show warnings or issues, suppress info messages"
    )

    args = parser.parse_args()

    # Check if sshd is installed
    if not check_sshd_installed():
        print("Error: sshd not found", file=sys.stderr)
        print("Install OpenSSH server:", file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt-get install openssh-server", file=sys.stderr)
        print("  RHEL/CentOS: sudo yum install openssh-server", file=sys.stderr)
        sys.exit(2)

    result = {
        'running': check_sshd_running(),
        'config': {},
        'connections': {'total': 0, 'established': 0, 'by_user': {}},
        'attempts': {},
        'issues': []
    }

    if result['running']:
        result['config'] = get_sshd_config()
        result['connections'] = get_active_connections()

        if args.verbose:
            result['attempts'] = get_connection_attempts()

        result['issues'] = analyze_config(result['config'], result['connections'])
    else:
        result['issues'].append({
            'severity': 'critical',
            'message': 'sshd daemon is not running'
        })

    # Output results
    if args.format == "json":
        output_json(result)
    elif args.format == "table":
        output_table(result, args.warn_only)
    else:
        output_plain(result, args.verbose, args.warn_only)

    # Determine exit code
    if not result['running']:
        sys.exit(2)

    has_issues = any(i['severity'] in ['warning', 'critical'] for i in result['issues'])
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
