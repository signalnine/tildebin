#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, monitoring, ssh, authentication, login, brute-force]
#   privilege: root
#   brief: Monitor failed login attempts for brute-force detection

"""
Monitor failed login attempts on baremetal systems.

Parses auth logs (/var/log/auth.log or /var/log/secure) to detect failed SSH
and other login attempts. Useful for detecting brute-force attacks and
unauthorized access attempts.

Returns exit code 1 if failed attempts exceed threshold.
"""

import argparse
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Patterns for failed logins
FAILED_PATTERNS = [
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
    # Too many authentication failures
    re.compile(
        r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
        r'Disconnecting authenticating user (?P<user>\S+)\s+'
        r'(?P<ip>[\d.]+).*Too many authentication failures'
    ),
]

# Month name to number mapping
MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}


def parse_timestamp(groups: dict[str, str]) -> datetime | None:
    """Parse syslog timestamp from regex groups."""
    try:
        month_num = MONTHS.get(groups['month'], 1)
        day = int(groups['day'])
        time_parts = groups['time'].split(':')
        hour = int(time_parts[0])
        minute = int(time_parts[1])
        second = int(time_parts[2])

        year = datetime.now().year
        log_time = datetime(year, month_num, day, hour, minute, second)

        # Handle year wrap-around
        if log_time > datetime.now():
            log_time = log_time.replace(year=year - 1)

        return log_time
    except (ValueError, KeyError):
        return None


def parse_auth_log(content: str, hours: int = 24, ignore_time: bool = False) -> list[dict[str, Any]]:
    """Parse auth log content for failed login attempts."""
    failed_logins = []
    cutoff_time = datetime.now() - timedelta(hours=hours) if not ignore_time else None

    for line in content.split('\n'):
        for pattern in FAILED_PATTERNS:
            match = pattern.search(line)
            if match:
                groups = match.groupdict()
                log_time = parse_timestamp(groups)

                # Skip entries older than cutoff (unless ignore_time is set)
                if cutoff_time and log_time and log_time < cutoff_time:
                    continue

                failed_logins.append({
                    'timestamp': log_time.isoformat() if log_time else None,
                    'host': groups.get('host', 'unknown'),
                    'user': groups.get('user', 'unknown'),
                    'source_ip': groups.get('ip', 'unknown'),
                })
                break

    return failed_logins


def aggregate_by_ip(failed_logins: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Aggregate failed logins by source IP."""
    by_ip: dict[str, dict[str, Any]] = defaultdict(
        lambda: {'count': 0, 'users': set(), 'timestamps': []}
    )

    for login in failed_logins:
        ip = login['source_ip']
        by_ip[ip]['count'] += 1
        by_ip[ip]['users'].add(login['user'])
        if login['timestamp']:
            by_ip[ip]['timestamps'].append(login['timestamp'])

    result = {}
    for ip, data in by_ip.items():
        result[ip] = {
            'count': data['count'],
            'users': sorted(list(data['users'])),
            'first_seen': min(data['timestamps']) if data['timestamps'] else None,
            'last_seen': max(data['timestamps']) if data['timestamps'] else None,
        }

    return result


def aggregate_by_user(failed_logins: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Aggregate failed logins by target user."""
    by_user: dict[str, dict[str, Any]] = defaultdict(
        lambda: {'count': 0, 'source_ips': set()}
    )

    for login in failed_logins:
        user = login['user']
        by_user[user]['count'] += 1
        by_user[user]['source_ips'].add(login['source_ip'])

    result = {}
    for user, data in by_user.items():
        result[user] = {
            'count': data['count'],
            'source_ips': sorted(list(data['source_ips'])),
        }

    return result


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = below threshold, 1 = above threshold, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor failed login attempts for brute-force detection"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-l", "--log-file",
                        help="Path to auth log file (auto-detected if not specified)")
    parser.add_argument("-H", "--hours", type=int, default=24,
                        help="Number of hours to look back (default: 24)")
    parser.add_argument("--all", action="store_true",
                        help="Scan all log entries regardless of time")
    parser.add_argument("-t", "--threshold", type=int, default=10,
                        help="Alert threshold for failed attempts per IP (default: 10)")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show IPs that exceed the threshold")
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.hours <= 0:
        output.error("Hours must be a positive number")
        return 2

    if opts.threshold <= 0:
        output.error("Threshold must be a positive number")
        return 2

    # Find auth log file
    log_file = opts.log_file
    if not log_file:
        log_paths = ['/var/log/auth.log', '/var/log/secure']
        for path in log_paths:
            if context.file_exists(path):
                log_file = path
                break

    if not log_file:
        output.error("Could not find auth log file. Specify with --log-file")
        return 2

    # Read and parse log
    try:
        content = context.read_file(log_file)
    except PermissionError:
        output.error(f"Permission denied reading {log_file}")
        return 2
    except FileNotFoundError:
        output.error(f"Log file not found: {log_file}")
        return 2

    failed_logins = parse_auth_log(content, opts.hours, ignore_time=opts.all)
    by_ip = aggregate_by_ip(failed_logins)
    by_user = aggregate_by_user(failed_logins)

    # Find IPs exceeding threshold
    brute_force_ips = [ip for ip, data in by_ip.items() if data['count'] >= opts.threshold]

    # Filter if warn-only
    if opts.warn_only:
        by_ip = {ip: data for ip, data in by_ip.items() if data['count'] >= opts.threshold}
        by_user = {user: data for user, data in by_user.items() if data['count'] >= opts.threshold}

    output.emit({
        'total_attempts': len(failed_logins),
        'unique_source_ips': len(by_ip) if not opts.warn_only else len(brute_force_ips),
        'unique_target_users': len(by_user),
        'threshold': opts.threshold,
        'ips_exceeding_threshold': len(brute_force_ips),
        'brute_force_alerts': brute_force_ips,
        'by_source_ip': by_ip if opts.verbose else {},
        'by_target_user': by_user if opts.verbose else {},
    })

    # Set summary
    if brute_force_ips:
        output.set_summary(f"{len(brute_force_ips)} IPs exceed threshold of {opts.threshold}")
    elif len(failed_logins) > 0:
        output.set_summary(f"{len(failed_logins)} failed attempts from {len(by_ip)} IPs")
    else:
        output.set_summary("No failed login attempts detected")

    # Return 1 if brute force detected
    return 1 if brute_force_ips else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
