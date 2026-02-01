#!/usr/bin/env python3
"""
Monitor failed login attempts on baremetal systems.

Parses auth logs (/var/log/auth.log or /var/log/secure) to detect failed SSH
and other login attempts. Useful for detecting brute-force attacks and
unauthorized access attempts.

Exit codes:
    0 - No issues (or below threshold)
    1 - Failed login attempts detected above threshold
    2 - Usage error or missing log file
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta


def find_auth_log():
    """Find the authentication log file."""
    # Common locations for auth logs
    log_paths = [
        '/var/log/auth.log',      # Debian/Ubuntu
        '/var/log/secure',        # RHEL/CentOS/Fedora
        '/var/log/authlog',       # Some BSD systems
    ]

    for path in log_paths:
        if os.path.exists(path):
            return path

    return None


def parse_failed_logins(log_file, hours=24):
    """
    Parse auth log for failed login attempts.

    Returns a list of failed login records.
    """
    failed_logins = []

    # Calculate cutoff time
    cutoff_time = datetime.now() - timedelta(hours=hours)

    # Patterns for failed logins
    patterns = [
        # SSH failed password
        re.compile(
            r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
            r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
            r'Failed password for (?:invalid user )?(?P<user>\S+)\s+'
            r'from\s+(?P<ip>[\d.]+)'
        ),
        # SSH invalid user
        re.compile(
            r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
            r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
            r'Invalid user (?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)'
        ),
        # PAM authentication failure
        re.compile(
            r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
            r'(?P<host>\S+)\s+\S+\[\d+\]:\s+pam_unix\(\S+:auth\):\s+'
            r'authentication failure;.*user=(?P<user>\S+).*rhost=(?P<ip>[\d.]+)?'
        ),
        # Connection closed by authenticating user (preauth)
        re.compile(
            r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
            r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
            r'Connection closed by authenticating user (?P<user>\S+)\s+'
            r'(?P<ip>[\d.]+)'
        ),
        # Too many authentication failures
        re.compile(
            r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
            r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
            r'Disconnecting authenticating user (?P<user>\S+)\s+'
            r'(?P<ip>[\d.]+).*Too many authentication failures'
        ),
    ]

    # Month name to number mapping
    months = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }

    try:
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                for pattern in patterns:
                    match = pattern.search(line)
                    if match:
                        groups = match.groupdict()

                        # Parse timestamp
                        try:
                            month_num = months.get(groups['month'], 1)
                            day = int(groups['day'])
                            time_parts = groups['time'].split(':')
                            hour = int(time_parts[0])
                            minute = int(time_parts[1])
                            second = int(time_parts[2])

                            # Use current year (logs don't include year)
                            year = datetime.now().year
                            log_time = datetime(
                                year, month_num, day, hour, minute, second
                            )

                            # Handle year wrap-around (December logs in January)
                            if log_time > datetime.now():
                                log_time = log_time.replace(year=year - 1)

                            # Skip if before cutoff
                            if log_time < cutoff_time:
                                continue

                        except (ValueError, KeyError):
                            # If we can't parse the time, include the entry
                            log_time = datetime.now()

                        failed_logins.append({
                            'timestamp': log_time.isoformat(),
                            'host': groups.get('host', 'unknown'),
                            'user': groups.get('user', 'unknown'),
                            'source_ip': groups.get('ip', 'unknown'),
                            'raw_line': line.strip()[:200]  # Truncate for safety
                        })
                        break  # Don't match same line with multiple patterns

    except PermissionError:
        print(f"Error: Permission denied reading {log_file}", file=sys.stderr)
        print("Try running with sudo or as root", file=sys.stderr)
        sys.exit(2)
    except FileNotFoundError:
        print(f"Error: Log file not found: {log_file}", file=sys.stderr)
        sys.exit(2)

    return failed_logins


def aggregate_by_ip(failed_logins):
    """Aggregate failed logins by source IP."""
    by_ip = defaultdict(lambda: {'count': 0, 'users': set(), 'timestamps': []})

    for login in failed_logins:
        ip = login['source_ip']
        by_ip[ip]['count'] += 1
        by_ip[ip]['users'].add(login['user'])
        by_ip[ip]['timestamps'].append(login['timestamp'])

    # Convert sets to lists for JSON serialization
    result = {}
    for ip, data in by_ip.items():
        result[ip] = {
            'count': data['count'],
            'users': sorted(list(data['users'])),
            'first_seen': min(data['timestamps']) if data['timestamps'] else None,
            'last_seen': max(data['timestamps']) if data['timestamps'] else None,
        }

    return result


def aggregate_by_user(failed_logins):
    """Aggregate failed logins by target user."""
    by_user = defaultdict(lambda: {'count': 0, 'source_ips': set()})

    for login in failed_logins:
        user = login['user']
        by_user[user]['count'] += 1
        by_user[user]['source_ips'].add(login['source_ip'])

    # Convert sets to lists
    result = {}
    for user, data in by_user.items():
        result[user] = {
            'count': data['count'],
            'source_ips': sorted(list(data['source_ips'])),
        }

    return result


def format_plain(failed_logins, by_ip, by_user, threshold, verbose=False):
    """Format results as plain text."""
    output = []

    total = len(failed_logins)
    unique_ips = len(by_ip)
    unique_users = len(by_user)

    output.append(f"Failed Login Monitor Report")
    output.append("=" * 50)
    output.append(f"Total failed attempts: {total}")
    output.append(f"Unique source IPs: {unique_ips}")
    output.append(f"Unique target users: {unique_users}")
    output.append("")

    if total == 0:
        output.append("No failed login attempts detected.")
        return '\n'.join(output)

    # Top offending IPs
    output.append("Top Source IPs by Failed Attempts:")
    output.append("-" * 50)
    sorted_ips = sorted(by_ip.items(), key=lambda x: x[1]['count'], reverse=True)
    for ip, data in sorted_ips[:10]:
        status = "[CRITICAL]" if data['count'] >= threshold else ""
        output.append(f"  {ip}: {data['count']} attempts {status}")
        if verbose:
            output.append(f"    Users tried: {', '.join(data['users'][:5])}")
            output.append(f"    First seen: {data['first_seen']}")
            output.append(f"    Last seen: {data['last_seen']}")
    output.append("")

    # Most targeted users
    output.append("Most Targeted Users:")
    output.append("-" * 50)
    sorted_users = sorted(by_user.items(), key=lambda x: x[1]['count'], reverse=True)
    for user, data in sorted_users[:10]:
        output.append(f"  {user}: {data['count']} attempts from {len(data['source_ips'])} IPs")
    output.append("")

    # Check for potential brute force attacks
    brute_force_ips = [ip for ip, data in by_ip.items() if data['count'] >= threshold]
    if brute_force_ips:
        output.append(f"ALERT: {len(brute_force_ips)} IP(s) exceeded threshold of {threshold}:")
        for ip in brute_force_ips:
            output.append(f"  - {ip}: {by_ip[ip]['count']} attempts")

    return '\n'.join(output)


def format_json(failed_logins, by_ip, by_user, threshold):
    """Format results as JSON."""
    brute_force_ips = [ip for ip, data in by_ip.items() if data['count'] >= threshold]

    result = {
        'summary': {
            'total_attempts': len(failed_logins),
            'unique_source_ips': len(by_ip),
            'unique_target_users': len(by_user),
            'threshold': threshold,
            'ips_exceeding_threshold': len(brute_force_ips),
        },
        'by_source_ip': by_ip,
        'by_target_user': by_user,
        'brute_force_alerts': brute_force_ips,
    }

    return json.dumps(result, indent=2, default=str)


def format_table(by_ip, threshold):
    """Format results as a table."""
    output = []

    header = f"{'SOURCE IP':<20} {'ATTEMPTS':<10} {'USERS':<30} {'STATUS':<10}"
    output.append(header)
    output.append("-" * len(header))

    sorted_ips = sorted(by_ip.items(), key=lambda x: x[1]['count'], reverse=True)
    for ip, data in sorted_ips[:20]:
        users = ', '.join(data['users'][:3])
        if len(data['users']) > 3:
            users += f" (+{len(data['users']) - 3})"
        status = "ALERT" if data['count'] >= threshold else "OK"
        output.append(f"{ip:<20} {data['count']:<10} {users:<30} {status:<10}")

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor failed login attempts on baremetal systems.',
        epilog='''
Examples:
  # Check failed logins in last 24 hours
  baremetal_failed_login_monitor.py

  # Check last 6 hours with custom threshold
  baremetal_failed_login_monitor.py --hours 6 --threshold 20

  # Output as JSON for monitoring systems
  baremetal_failed_login_monitor.py --format json

  # Use specific log file
  baremetal_failed_login_monitor.py --log-file /var/log/secure

Exit codes:
  0 - No failed logins or below threshold
  1 - Failed logins detected above threshold
  2 - Usage error or log file not accessible
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
        help='Show detailed information'
    )
    parser.add_argument(
        '-l', '--log-file',
        help='Path to auth log file (auto-detected if not specified)'
    )
    parser.add_argument(
        '-H', '--hours',
        type=int,
        default=24,
        help='Number of hours to look back (default: 24)'
    )
    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=10,
        help='Alert threshold for failed attempts per IP (default: 10)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show IPs that exceed the threshold'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.hours <= 0:
        print("Error: Hours must be a positive number", file=sys.stderr)
        return 2

    if args.threshold <= 0:
        print("Error: Threshold must be a positive number", file=sys.stderr)
        return 2

    # Find or use specified log file
    log_file = args.log_file
    if not log_file:
        log_file = find_auth_log()
        if not log_file:
            print("Error: Could not find auth log file.", file=sys.stderr)
            print("Tried: /var/log/auth.log, /var/log/secure", file=sys.stderr)
            print("Specify path with --log-file", file=sys.stderr)
            return 2

    # Parse failed logins
    failed_logins = parse_failed_logins(log_file, args.hours)

    # Aggregate data
    by_ip = aggregate_by_ip(failed_logins)
    by_user = aggregate_by_user(failed_logins)

    # Filter if warn-only mode
    if args.warn_only:
        by_ip = {ip: data for ip, data in by_ip.items()
                 if data['count'] >= args.threshold}
        by_user = {user: data for user, data in by_user.items()
                   if data['count'] >= args.threshold}

    # Format output
    if args.format == 'json':
        output = format_json(failed_logins, by_ip, by_user, args.threshold)
    elif args.format == 'table':
        output = format_table(by_ip, args.threshold)
    else:
        output = format_plain(failed_logins, by_ip, by_user, args.threshold,
                              args.verbose)

    print(output)

    # Determine exit code
    brute_force_detected = any(
        data['count'] >= args.threshold for data in by_ip.values()
    )

    return 1 if brute_force_detected else 0


if __name__ == '__main__':
    sys.exit(main())
