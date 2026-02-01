#!/usr/bin/env python3
"""
Monitor system uptime and reboot history for baremetal servers.

This script analyzes system uptime, recent reboots, and reboot patterns to identify
unstable or flapping servers. Critical for large-scale baremetal environments where
unexpected reboots indicate hardware failures, kernel panics, or configuration issues.

Key features:
- Current system uptime
- Reboot count within configurable time windows
- Detection of frequent reboots (flapping servers)
- Analysis of reboot reasons from wtmp/last command
- Uptime thresholds for alerting on recently rebooted systems

Exit codes:
    0 - System is stable (uptime meets threshold, no excessive reboots)
    1 - Issues detected (low uptime, frequent reboots)
    2 - Usage error or required tools not available
"""

import argparse
import sys
import subprocess
import json
import os
from datetime import datetime, timedelta

# Default thresholds
DEFAULT_MIN_UPTIME_HOURS = 1  # Warn if uptime less than 1 hour
DEFAULT_MAX_REBOOTS_24H = 2   # Warn if more than 2 reboots in 24 hours
DEFAULT_MAX_REBOOTS_7D = 5    # Warn if more than 5 reboots in 7 days


def run_command(cmd):
    """Execute shell command and return result."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}"
    except Exception as e:
        return -1, "", str(e)


def get_uptime():
    """Get system uptime in seconds from /proc/uptime."""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])
            return uptime_seconds, None
    except (IOError, ValueError) as e:
        return None, f"Failed to read /proc/uptime: {e}"


def format_uptime(seconds):
    """Format uptime in human-readable format."""
    if seconds is None:
        return "Unknown"

    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)

    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"


def get_boot_time():
    """Get the last boot time from /proc/stat."""
    try:
        with open('/proc/stat', 'r') as f:
            for line in f:
                if line.startswith('btime'):
                    boot_timestamp = int(line.split()[1])
                    return datetime.fromtimestamp(boot_timestamp), None
    except (IOError, ValueError, IndexError) as e:
        pass

    # Fallback: calculate from uptime
    uptime_seconds, error = get_uptime()
    if uptime_seconds is not None:
        boot_time = datetime.now() - timedelta(seconds=uptime_seconds)
        return boot_time, None

    return None, "Failed to determine boot time"


def get_reboot_history():
    """Get reboot history from last command."""
    reboots = []

    # Try 'last reboot' command
    returncode, stdout, stderr = run_command(['last', 'reboot', '-F'])

    if returncode != 0:
        # Try without -F flag (some systems don't support it)
        returncode, stdout, stderr = run_command(['last', 'reboot'])

    if returncode != 0:
        return reboots, f"Failed to get reboot history: {stderr}"

    for line in stdout.strip().split('\n'):
        if not line or line.startswith('wtmp begins'):
            continue

        # Parse the reboot line
        # Format varies by system, but typically:
        # reboot   system boot  5.15.0-generic   Mon Jan 20 10:30   still running
        # reboot   system boot  5.15.0-generic   Mon Jan 20 10:30 - Mon Jan 20 11:00 (00:30)
        parts = line.split()
        if len(parts) < 5:
            continue

        if parts[0] != 'reboot':
            continue

        try:
            # Find the date portion - look for day name
            date_idx = None
            for i, part in enumerate(parts):
                if part in ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']:
                    date_idx = i
                    break

            if date_idx is None:
                continue

            # Extract date string (varies by format)
            # Try to parse various formats
            date_parts = parts[date_idx:date_idx + 4]
            date_str = ' '.join(date_parts)

            # Try multiple date formats
            boot_time = None
            current_year = datetime.now().year

            # First try formats with explicit year
            for fmt in [
                '%a %b %d %H:%M:%S %Y',  # Mon Jan 20 10:30:00 2025
            ]:
                try:
                    boot_time = datetime.strptime(date_str, fmt)
                    break
                except ValueError:
                    continue

            # If no year in date, try formats without year and add current year
            if boot_time is None:
                for fmt in [
                    '%a %b %d %H:%M',         # Mon Jan 20 10:30 (no year)
                    '%a %b %d %H:%M:%S',      # Mon Jan 20 10:30:00 (no year)
                ]:
                    try:
                        # Prepend year to avoid deprecation warning
                        date_with_year = f"{current_year} {date_str}"
                        boot_time = datetime.strptime(date_with_year, f"%Y {fmt}")
                        # If date is in future, it's from previous year
                        if boot_time > datetime.now():
                            boot_time = boot_time.replace(year=current_year - 1)
                        break
                    except ValueError:
                        continue

            if boot_time is None:
                # Try shorter format
                date_str = ' '.join(parts[date_idx:date_idx + 3])
                for fmt in ['%a %b %d', '%b %d %H:%M']:
                    try:
                        date_with_year = f"{current_year} {date_str}"
                        boot_time = datetime.strptime(date_with_year, f"%Y {fmt}")
                        if boot_time > datetime.now():
                            boot_time = boot_time.replace(year=current_year - 1)
                        break
                    except ValueError:
                        continue

            if boot_time:
                # Get kernel version if present
                kernel = parts[2] if len(parts) > 2 and parts[1] == 'system' else 'unknown'

                reboots.append({
                    'time': boot_time,
                    'kernel': kernel,
                    'still_running': 'still running' in line.lower()
                })

        except (IndexError, ValueError):
            continue

    return reboots, None


def count_reboots_in_period(reboots, hours):
    """Count reboots within the last N hours."""
    cutoff = datetime.now() - timedelta(hours=hours)
    count = 0
    for reboot in reboots:
        if reboot['time'] >= cutoff:
            count += 1
    return count


def check_thresholds(uptime_seconds, reboots, min_uptime_hours, max_reboots_24h, max_reboots_7d):
    """Check uptime and reboot counts against thresholds."""
    issues = []

    # Check uptime
    uptime_hours = uptime_seconds / 3600 if uptime_seconds else 0
    if uptime_hours < min_uptime_hours:
        issues.append({
            'severity': 'WARNING',
            'type': 'low_uptime',
            'message': f"System uptime ({format_uptime(uptime_seconds)}) is below threshold ({min_uptime_hours}h)"
        })

    # Count reboots in time windows
    reboots_24h = count_reboots_in_period(reboots, 24)
    reboots_7d = count_reboots_in_period(reboots, 24 * 7)

    if reboots_24h > max_reboots_24h:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'frequent_reboots_24h',
            'message': f"System rebooted {reboots_24h} times in last 24 hours (threshold: {max_reboots_24h})"
        })

    if reboots_7d > max_reboots_7d:
        issues.append({
            'severity': 'WARNING',
            'type': 'frequent_reboots_7d',
            'message': f"System rebooted {reboots_7d} times in last 7 days (threshold: {max_reboots_7d})"
        })

    return issues, reboots_24h, reboots_7d


def get_hostname():
    """Get system hostname."""
    try:
        with open('/etc/hostname', 'r') as f:
            return f.read().strip()
    except IOError:
        pass

    returncode, stdout, stderr = run_command(['hostname'])
    if returncode == 0:
        return stdout.strip()

    return os.uname().nodename


def output_plain(data, verbose=False):
    """Output results in plain text format."""
    print(f"Hostname: {data['hostname']}")
    print(f"Uptime: {data['uptime_formatted']}")
    print(f"Boot Time: {data['boot_time']}")
    print(f"Reboots (24h): {data['reboots_24h']}")
    print(f"Reboots (7d): {data['reboots_7d']}")

    if data['issues']:
        print("\nIssues:")
        for issue in data['issues']:
            print(f"  [{issue['severity']}] {issue['message']}")

    if verbose and data['reboot_history']:
        print("\nRecent Reboot History:")
        for reboot in data['reboot_history'][:10]:
            status = " (current)" if reboot.get('still_running') else ""
            print(f"  {reboot['time_str']} - kernel: {reboot['kernel']}{status}")


def output_json(data):
    """Output results in JSON format."""
    print(json.dumps(data, indent=2, default=str))


def output_table(data, verbose=False):
    """Output results in table format."""
    print("=" * 60)
    print(f"System Uptime Report: {data['hostname']}")
    print("=" * 60)
    print(f"{'Metric':<25} {'Value':<35}")
    print("-" * 60)
    print(f"{'Uptime':<25} {data['uptime_formatted']:<35}")
    print(f"{'Boot Time':<25} {data['boot_time']:<35}")
    print(f"{'Reboots (24h)':<25} {data['reboots_24h']:<35}")
    print(f"{'Reboots (7d)':<25} {data['reboots_7d']:<35}")
    print("=" * 60)

    if data['issues']:
        print("\nIssues Detected:")
        print("-" * 60)
        for issue in data['issues']:
            print(f"[{issue['severity']}] {issue['message']}")

    if verbose and data['reboot_history']:
        print("\nRecent Reboot History:")
        print("-" * 60)
        print(f"{'Time':<25} {'Kernel':<25} {'Status':<10}")
        print("-" * 60)
        for reboot in data['reboot_history'][:10]:
            status = "current" if reboot.get('still_running') else ""
            print(f"{reboot['time_str']:<25} {reboot['kernel']:<25} {status:<10}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor system uptime and reboot history for baremetal servers",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed reboot history"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if issues are detected"
    )

    parser.add_argument(
        "--min-uptime",
        type=float,
        default=DEFAULT_MIN_UPTIME_HOURS,
        help=f"Minimum acceptable uptime in hours (default: {DEFAULT_MIN_UPTIME_HOURS})"
    )

    parser.add_argument(
        "--max-reboots-24h",
        type=int,
        default=DEFAULT_MAX_REBOOTS_24H,
        help=f"Maximum acceptable reboots in 24 hours (default: {DEFAULT_MAX_REBOOTS_24H})"
    )

    parser.add_argument(
        "--max-reboots-7d",
        type=int,
        default=DEFAULT_MAX_REBOOTS_7D,
        help=f"Maximum acceptable reboots in 7 days (default: {DEFAULT_MAX_REBOOTS_7D})"
    )

    args = parser.parse_args()

    # Get uptime
    uptime_seconds, error = get_uptime()
    if error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    # Get boot time
    boot_time, error = get_boot_time()
    if error:
        boot_time_str = "Unknown"
    else:
        boot_time_str = boot_time.strftime("%Y-%m-%d %H:%M:%S")

    # Get reboot history
    reboots, error = get_reboot_history()
    if error:
        # Non-fatal - we can continue without history
        reboots = []

    # Check thresholds
    issues, reboots_24h, reboots_7d = check_thresholds(
        uptime_seconds,
        reboots,
        args.min_uptime,
        args.max_reboots_24h,
        args.max_reboots_7d
    )

    # Prepare output data
    data = {
        'hostname': get_hostname(),
        'uptime_seconds': uptime_seconds,
        'uptime_formatted': format_uptime(uptime_seconds),
        'boot_time': boot_time_str,
        'reboots_24h': reboots_24h,
        'reboots_7d': reboots_7d,
        'issues': issues,
        'reboot_history': [
            {
                'time_str': r['time'].strftime("%Y-%m-%d %H:%M:%S"),
                'kernel': r['kernel'],
                'still_running': r.get('still_running', False)
            }
            for r in reboots[:20]  # Limit history in output
        ]
    }

    # Handle warn-only mode
    if args.warn_only and not issues:
        sys.exit(0)

    # Output results
    if args.format == "json":
        output_json(data)
    elif args.format == "table":
        output_table(data, args.verbose)
    else:  # plain
        output_plain(data, args.verbose)

    # Exit based on findings
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
