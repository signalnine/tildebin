#!/usr/bin/env python3
"""
Monitor process ages to identify long-running processes that may need attention.

Tracks how long processes have been running and identifies those that exceed
configurable age thresholds. Useful for detecting processes that may need
restart for security patches, identifying memory-leaking services, or finding
stale/orphaned processes in large-scale baremetal environments.

Key features:
- Reports process age in human-readable format
- Filters by minimum age threshold
- Supports filtering by user or command pattern
- Groups processes by service/command name
- Identifies processes running since before last boot (suspicious)

Use cases:
- Finding services that haven't been restarted after package updates
- Identifying potentially stale or orphaned processes
- Audit of long-running daemon processes
- Pre-maintenance process inventory
- Security patch compliance verification

Exit codes:
    0 - No processes exceed warning thresholds
    1 - One or more processes exceed warning thresholds
    2 - Usage error or unable to read process information
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


def read_proc_file(path: str) -> Optional[str]:
    """Read a /proc file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError, PermissionError):
        return None


def get_boot_time() -> Optional[float]:
    """Get system boot time from /proc/stat."""
    content = read_proc_file('/proc/stat')
    if not content:
        return None

    for line in content.split('\n'):
        if line.startswith('btime '):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                pass
    return None


def get_clock_ticks() -> int:
    """Get system clock ticks per second (usually 100)."""
    try:
        return os.sysconf(os.sysconf_names['SC_CLK_TCK'])
    except (ValueError, KeyError, AttributeError):
        return 100  # Common default


def get_process_start_time(pid: int) -> Optional[float]:
    """Get process start time as Unix timestamp."""
    stat_content = read_proc_file(f'/proc/{pid}/stat')
    if not stat_content:
        return None

    # Parse /proc/[pid]/stat - field 22 is starttime
    # Format is tricky because comm can contain spaces and parens
    # Find the last ) to split properly
    try:
        last_paren = stat_content.rfind(')')
        if last_paren == -1:
            return None

        fields_after_comm = stat_content[last_paren + 2:].split()
        if len(fields_after_comm) < 20:
            return None

        # Field 22 is starttime (0-indexed from after comm, so index 19)
        starttime_ticks = int(fields_after_comm[19])

        boot_time = get_boot_time()
        if boot_time is None:
            return None

        clock_ticks = get_clock_ticks()
        start_time = boot_time + (starttime_ticks / clock_ticks)
        return start_time

    except (ValueError, IndexError):
        return None


def get_process_info(pid: int) -> Optional[Dict[str, Any]]:
    """Get detailed information about a process."""
    # Get command name
    comm = read_proc_file(f'/proc/{pid}/comm')
    if not comm:
        return None

    # Get full command line
    cmdline_raw = read_proc_file(f'/proc/{pid}/cmdline')
    if cmdline_raw:
        cmdline = cmdline_raw.replace('\x00', ' ').strip()
        if len(cmdline) > 100:
            cmdline = cmdline[:97] + '...'
    else:
        cmdline = comm

    # Get status info
    status_content = read_proc_file(f'/proc/{pid}/status')
    uid = None
    ppid = None
    state = None
    threads = 1

    if status_content:
        for line in status_content.split('\n'):
            if line.startswith('Uid:'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        uid = int(parts[1])
                    except ValueError:
                        pass
            elif line.startswith('PPid:'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        ppid = int(parts[1])
                    except ValueError:
                        pass
            elif line.startswith('State:'):
                parts = line.split()
                if len(parts) >= 2:
                    state = parts[1]
            elif line.startswith('Threads:'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        threads = int(parts[1])
                    except ValueError:
                        pass

    # Resolve username
    username = None
    if uid is not None:
        try:
            import pwd
            username = pwd.getpwuid(uid).pw_name
        except (KeyError, ImportError):
            username = str(uid)

    # Get start time
    start_time = get_process_start_time(pid)
    if start_time is None:
        return None

    # Calculate age
    now = time.time()
    age_seconds = now - start_time

    return {
        'pid': pid,
        'comm': comm,
        'cmdline': cmdline,
        'user': username or 'unknown',
        'uid': uid,
        'ppid': ppid,
        'state': state,
        'threads': threads,
        'start_time': start_time,
        'start_datetime': datetime.fromtimestamp(start_time).isoformat(),
        'age_seconds': age_seconds,
    }


def scan_processes(user_filter: Optional[str] = None,
                   cmd_filter: Optional[str] = None,
                   min_age_hours: float = 0) -> List[Dict[str, Any]]:
    """Scan all processes and gather age information."""
    processes = []
    min_age_seconds = min_age_hours * 3600

    cmd_pattern = re.compile(cmd_filter, re.IGNORECASE) if cmd_filter else None

    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pid = int(entry)
                info = get_process_info(pid)
                if info:
                    # Apply filters
                    if user_filter and info['user'] != user_filter:
                        continue
                    if cmd_pattern and not cmd_pattern.search(info['comm']):
                        continue
                    if info['age_seconds'] < min_age_seconds:
                        continue
                    processes.append(info)
    except OSError:
        pass

    return processes


def format_age(seconds: float) -> str:
    """Format age in seconds to human-readable format."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes}m"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"
    else:
        days = int(seconds / 86400)
        hours = int((seconds % 86400) / 3600)
        return f"{days}d {hours}h"


def format_age_long(seconds: float) -> str:
    """Format age in seconds to detailed human-readable format."""
    days = int(seconds / 86400)
    hours = int((seconds % 86400) / 3600)
    minutes = int((seconds % 3600) / 60)

    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0 and days == 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

    return ', '.join(parts) if parts else 'less than a minute'


def analyze_processes(processes: List[Dict], warn_age_days: float,
                      crit_age_days: float) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Analyze processes and categorize by age thresholds."""
    warn_seconds = warn_age_days * 86400
    crit_seconds = crit_age_days * 86400

    critical = []
    warnings = []
    normal = []

    for proc in processes:
        age = proc['age_seconds']
        if age >= crit_seconds:
            proc['status'] = 'critical'
            critical.append(proc)
        elif age >= warn_seconds:
            proc['status'] = 'warning'
            warnings.append(proc)
        else:
            proc['status'] = 'ok'
            normal.append(proc)

    return critical, warnings, normal


def group_by_command(processes: List[Dict]) -> Dict[str, List[Dict]]:
    """Group processes by command name."""
    groups = {}
    for proc in processes:
        comm = proc['comm']
        if comm not in groups:
            groups[comm] = []
        groups[comm].append(proc)
    return groups


def output_plain(processes: List[Dict], critical: List[Dict],
                 warnings: List[Dict], warn_only: bool,
                 verbose: bool, group_by_cmd: bool) -> None:
    """Output in plain text format."""
    if critical:
        print("CRITICAL - Processes exceeding critical age threshold:")
        for proc in sorted(critical, key=lambda x: x['age_seconds'], reverse=True):
            print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                  f"age {format_age(proc['age_seconds']):>10} "
                  f"user={proc['user']}")
            if verbose:
                print(f"           Started: {proc['start_datetime']}")
                print(f"           Command: {proc['cmdline'][:60]}")
        print()

    if warnings:
        print("WARNING - Processes exceeding warning age threshold:")
        for proc in sorted(warnings, key=lambda x: x['age_seconds'], reverse=True):
            print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                  f"age {format_age(proc['age_seconds']):>10} "
                  f"user={proc['user']}")
            if verbose:
                print(f"           Started: {proc['start_datetime']}")
        print()

    if not warn_only:
        if not critical and not warnings:
            print("OK - No processes exceed age thresholds")
            print()

        if group_by_cmd and processes:
            groups = group_by_command(processes)
            print(f"Process Summary by Command ({len(processes)} total processes):")
            print(f"{'Command':<20} {'Count':>6} {'Oldest':>12} {'User':<12}")
            print("-" * 54)

            for comm in sorted(groups.keys()):
                procs = groups[comm]
                oldest = max(procs, key=lambda x: x['age_seconds'])
                print(f"{comm:<20} {len(procs):>6} "
                      f"{format_age(oldest['age_seconds']):>12} "
                      f"{oldest['user']:<12}")
            print()

        elif verbose and processes:
            print(f"All Monitored Processes ({len(processes)} total):")
            for proc in sorted(processes, key=lambda x: x['age_seconds'], reverse=True)[:20]:
                status_marker = '*' if proc.get('status') in ('critical', 'warning') else ' '
                print(f"{status_marker} PID {proc['pid']:>7} ({proc['comm']:<15}): "
                      f"age {format_age(proc['age_seconds']):>10}")


def output_json(processes: List[Dict], critical: List[Dict],
                warnings: List[Dict], boot_time: Optional[float]) -> None:
    """Output in JSON format."""
    # Add formatted age to each process
    for proc in processes:
        proc['age_formatted'] = format_age_long(proc['age_seconds'])

    status = 'critical' if critical else ('warning' if warnings else 'ok')

    result = {
        'status': status,
        'summary': {
            'total_processes': len(processes),
            'critical_count': len(critical),
            'warning_count': len(warnings),
            'oldest_age_seconds': max((p['age_seconds'] for p in processes), default=0),
            'boot_time': boot_time,
            'boot_datetime': datetime.fromtimestamp(boot_time).isoformat() if boot_time else None,
        },
        'critical': critical,
        'warnings': warnings,
        'all_processes': processes,
    }
    print(json.dumps(result, indent=2))


def output_table(processes: List[Dict], critical: List[Dict],
                 warnings: List[Dict], warn_only: bool, top_n: int) -> None:
    """Output in table format."""
    if warn_only:
        display = critical + warnings
    else:
        display = processes

    display = sorted(display, key=lambda x: x['age_seconds'], reverse=True)
    if top_n > 0:
        display = display[:top_n]

    if not display:
        print("No processes to display")
        return

    # Header
    print(f"{'PID':>7} {'Command':<15} {'User':<12} {'Age':>12} "
          f"{'Started':>20} {'Status':<10}")
    print("-" * 82)

    for proc in display:
        status = proc.get('status', 'ok').upper()
        started = proc['start_datetime'][:16] if proc.get('start_datetime') else 'unknown'
        print(f"{proc['pid']:>7} {proc['comm']:<15} {proc['user']:<12} "
              f"{format_age(proc['age_seconds']):>12} {started:>20} {status:<10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor process ages to identify long-running processes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         Show all processes with default thresholds
  %(prog)s --min-age 24            Only show processes older than 24 hours
  %(prog)s --warn-days 7           Warn on processes older than 7 days
  %(prog)s --user www-data         Monitor only www-data processes
  %(prog)s --cmd nginx             Monitor processes matching 'nginx'
  %(prog)s --format json           JSON output for monitoring systems
  %(prog)s --group                 Group output by command name

Exit codes:
  0 - No processes exceed warning thresholds
  1 - One or more processes exceed warning thresholds
  2 - Usage error or unable to read process information
"""
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
        '-w', '--warn-only',
        action='store_true',
        help='Only show processes exceeding thresholds'
    )

    parser.add_argument(
        '--min-age',
        type=float,
        default=1.0,
        metavar='HOURS',
        help='Minimum process age in hours to include (default: 1.0)'
    )

    parser.add_argument(
        '--warn-days',
        type=float,
        default=30.0,
        metavar='DAYS',
        help='Age threshold in days for warning (default: 30.0)'
    )

    parser.add_argument(
        '--crit-days',
        type=float,
        default=90.0,
        metavar='DAYS',
        help='Age threshold in days for critical (default: 90.0)'
    )

    parser.add_argument(
        '--top',
        type=int,
        default=0,
        metavar='N',
        help='Show only top N oldest processes (default: all)'
    )

    parser.add_argument(
        '--user',
        type=str,
        metavar='USERNAME',
        help='Only monitor processes owned by this user'
    )

    parser.add_argument(
        '--cmd',
        type=str,
        metavar='PATTERN',
        help='Only monitor processes matching command pattern (regex)'
    )

    parser.add_argument(
        '--group',
        action='store_true',
        help='Group output by command name'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.min_age < 0:
        print("Error: --min-age must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.warn_days < 0:
        print("Error: --warn-days must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.crit_days < 0:
        print("Error: --crit-days must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.crit_days < args.warn_days:
        print("Error: --crit-days must be >= --warn-days", file=sys.stderr)
        sys.exit(2)
    if args.top < 0:
        print("Error: --top must be non-negative", file=sys.stderr)
        sys.exit(2)

    # Validate regex pattern
    if args.cmd:
        try:
            re.compile(args.cmd)
        except re.error as e:
            print(f"Error: Invalid command pattern: {e}", file=sys.stderr)
            sys.exit(2)

    # Check if we can read /proc
    if not os.path.isdir('/proc'):
        print("Error: /proc not available", file=sys.stderr)
        print("This script requires the procfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Get boot time for reference
    boot_time = get_boot_time()

    # Scan processes
    processes = scan_processes(args.user, args.cmd, args.min_age)

    if not processes:
        if args.format == 'json':
            print(json.dumps({
                'status': 'ok',
                'summary': {
                    'total_processes': 0,
                    'critical_count': 0,
                    'warning_count': 0,
                },
                'message': 'No matching processes found'
            }, indent=2))
        else:
            print("No matching processes found")
        sys.exit(0)

    # Analyze processes
    critical, warnings, normal = analyze_processes(
        processes, args.warn_days, args.crit_days
    )

    # Output based on format
    if args.format == 'json':
        output_json(processes, critical, warnings, boot_time)
    elif args.format == 'table':
        output_table(processes, critical, warnings, args.warn_only, args.top)
    else:
        output_plain(processes, critical, warnings, args.warn_only,
                     args.verbose, args.group)

    # Exit code based on findings
    if critical:
        sys.exit(1)
    elif warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
