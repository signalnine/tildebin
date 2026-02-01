#!/usr/bin/env python3
"""
Monitor kernel resource limits and their current usage.

Monitors critical kernel limits that can cause system instability when exhausted:
- PID limit (kernel.pid_max)
- Threads limit (kernel.threads-max)
- Open file limit (fs.file-max)
- Inotify watches (fs.inotify.max_user_watches)
- Message queue limits (kernel.msgmni, kernel.msgmax)
- Semaphore limits (kernel.sem)
- Shared memory limits (kernel.shmmax, kernel.shmall)

Essential for high-density baremetal environments running many containers or
services where resource exhaustion can cause cascading failures.

Exit codes:
    0 - All limits within safe thresholds
    1 - One or more limits approaching exhaustion (warnings)
    2 - Usage error or unable to read kernel parameters
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple


def read_proc_file(path: str) -> Optional[str]:
    """Read a /proc or /sys file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError):
        return None


def read_sysctl(param: str) -> Optional[str]:
    """Read a sysctl parameter value."""
    path = f"/proc/sys/{param.replace('.', '/')}"
    return read_proc_file(path)


def count_processes() -> int:
    """Count current number of processes."""
    try:
        # Count directories in /proc that are numeric (PIDs)
        count = 0
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                count += 1
        return count
    except OSError:
        return 0


def count_threads() -> int:
    """Count current number of threads (tasks)."""
    try:
        # Read from /proc/loadavg last field shows running/total tasks
        content = read_proc_file('/proc/loadavg')
        if content:
            # Format: "0.00 0.01 0.05 1/123 4567"
            parts = content.split()
            if len(parts) >= 4:
                task_info = parts[3]  # e.g., "1/123"
                if '/' in task_info:
                    return int(task_info.split('/')[1])
    except (ValueError, IndexError):
        pass

    # Fallback: count all tasks
    count = 0
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                task_dir = f'/proc/{entry}/task'
                if os.path.isdir(task_dir):
                    count += len(os.listdir(task_dir))
    except OSError:
        pass
    return count


def count_open_files() -> int:
    """Count current number of open file descriptors system-wide."""
    content = read_proc_file('/proc/sys/fs/file-nr')
    if content:
        # Format: "allocated  free  maximum"
        parts = content.split()
        if len(parts) >= 1:
            try:
                return int(parts[0])
            except ValueError:
                pass
    return 0


def count_inotify_watches() -> int:
    """Estimate current inotify watch usage."""
    # This is tricky - inotify watches are per-process
    # We'll sum up watches across all processes
    total = 0
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                fd_path = f'/proc/{entry}/fd'
                try:
                    for fd in os.listdir(fd_path):
                        link = os.readlink(f'{fd_path}/{fd}')
                        if 'inotify' in link:
                            # Each inotify instance can have multiple watches
                            # but we count instances as approximation
                            total += 1
                except (OSError, PermissionError):
                    continue
    except OSError:
        pass
    return total


def get_limit_info() -> List[Dict[str, Any]]:
    """Gather information about kernel limits and usage."""
    limits = []

    # PID limit
    pid_max = read_sysctl('kernel.pid_max')
    if pid_max:
        current_pids = count_processes()
        limits.append({
            'name': 'kernel.pid_max',
            'description': 'Maximum process ID',
            'limit': int(pid_max),
            'current': current_pids,
            'unit': 'processes',
        })

    # Threads limit
    threads_max = read_sysctl('kernel.threads-max')
    if threads_max:
        current_threads = count_threads()
        limits.append({
            'name': 'kernel.threads-max',
            'description': 'Maximum number of threads',
            'limit': int(threads_max),
            'current': current_threads,
            'unit': 'threads',
        })

    # File descriptor limit
    file_max = read_sysctl('fs.file-max')
    if file_max:
        current_files = count_open_files()
        limits.append({
            'name': 'fs.file-max',
            'description': 'Maximum open files system-wide',
            'limit': int(file_max),
            'current': current_files,
            'unit': 'files',
        })

    # Inotify watches limit
    inotify_max = read_sysctl('fs.inotify.max_user_watches')
    if inotify_max:
        current_watches = count_inotify_watches()
        limits.append({
            'name': 'fs.inotify.max_user_watches',
            'description': 'Maximum inotify watches per user',
            'limit': int(inotify_max),
            'current': current_watches,
            'unit': 'watches',
            'note': 'Approximate count of inotify instances',
        })

    # Message queue limit
    msgmni = read_sysctl('kernel.msgmni')
    if msgmni:
        limits.append({
            'name': 'kernel.msgmni',
            'description': 'Maximum message queue identifiers',
            'limit': int(msgmni),
            'current': None,  # Hard to count without parsing ipcs
            'unit': 'queues',
        })

    # Max message size
    msgmax = read_sysctl('kernel.msgmax')
    if msgmax:
        limits.append({
            'name': 'kernel.msgmax',
            'description': 'Maximum message size (bytes)',
            'limit': int(msgmax),
            'current': None,
            'unit': 'bytes',
        })

    # Semaphore limits
    sem = read_sysctl('kernel.sem')
    if sem:
        # Format: SEMMSL SEMMNS SEMOPM SEMMNI
        parts = sem.split()
        if len(parts) >= 4:
            limits.append({
                'name': 'kernel.sem (SEMMNI)',
                'description': 'Maximum semaphore sets',
                'limit': int(parts[3]),
                'current': None,
                'unit': 'sets',
            })

    # Shared memory max
    shmmax = read_sysctl('kernel.shmmax')
    if shmmax:
        limits.append({
            'name': 'kernel.shmmax',
            'description': 'Maximum shared memory segment size',
            'limit': int(shmmax),
            'current': None,
            'unit': 'bytes',
        })

    # Shared memory pages
    shmall = read_sysctl('kernel.shmall')
    if shmall:
        limits.append({
            'name': 'kernel.shmall',
            'description': 'Maximum shared memory pages',
            'limit': int(shmall),
            'current': None,
            'unit': 'pages',
        })

    # AIO requests
    aio_max = read_sysctl('fs.aio-max-nr')
    aio_nr = read_sysctl('fs.aio-nr')
    if aio_max and aio_nr:
        limits.append({
            'name': 'fs.aio-max-nr',
            'description': 'Maximum async I/O requests',
            'limit': int(aio_max),
            'current': int(aio_nr),
            'unit': 'requests',
        })

    # Calculate usage percentage where possible
    for limit in limits:
        if limit['current'] is not None and limit['limit'] > 0:
            limit['usage_pct'] = round(
                (limit['current'] / limit['limit']) * 100, 1
            )
        else:
            limit['usage_pct'] = None

    return limits


def analyze_limits(limits: List[Dict], warn_threshold: int,
                   critical_threshold: int) -> Tuple[List[Dict], List[Dict]]:
    """Analyze limits and return warnings and critical issues."""
    warnings = []
    critical = []

    for limit in limits:
        if limit['usage_pct'] is not None:
            if limit['usage_pct'] >= critical_threshold:
                critical.append(limit)
            elif limit['usage_pct'] >= warn_threshold:
                warnings.append(limit)

    return warnings, critical


def output_plain(limits: List[Dict], warnings: List[Dict],
                 critical: List[Dict], warn_only: bool, verbose: bool) -> None:
    """Output in plain text format."""
    if critical:
        print("CRITICAL - Kernel limits approaching exhaustion:")
        for limit in critical:
            print(f"  {limit['name']}: {limit['current']}/{limit['limit']} "
                  f"({limit['usage_pct']}%) - {limit['description']}")
        print()

    if warnings:
        print("WARNING - Kernel limits elevated:")
        for limit in warnings:
            print(f"  {limit['name']}: {limit['current']}/{limit['limit']} "
                  f"({limit['usage_pct']}%) - {limit['description']}")
        print()

    if not warn_only:
        if not critical and not warnings:
            print("OK - All kernel limits within safe thresholds")
            print()

        if verbose:
            print("All monitored limits:")
            for limit in limits:
                current = limit['current'] if limit['current'] is not None else 'N/A'
                usage = f"{limit['usage_pct']}%" if limit['usage_pct'] is not None else 'N/A'
                print(f"  {limit['name']:<35} {current:>12} / {limit['limit']:<12} ({usage})")
                if 'note' in limit:
                    print(f"    Note: {limit['note']}")


def output_json(limits: List[Dict], warnings: List[Dict],
                critical: List[Dict]) -> None:
    """Output in JSON format."""
    result = {
        'status': 'critical' if critical else ('warning' if warnings else 'ok'),
        'critical_count': len(critical),
        'warning_count': len(warnings),
        'limits': limits,
        'critical': critical,
        'warnings': warnings,
    }
    print(json.dumps(result, indent=2))


def output_table(limits: List[Dict], warnings: List[Dict],
                 critical: List[Dict], warn_only: bool) -> None:
    """Output in table format."""
    # Filter if warn_only
    if warn_only:
        display_limits = warnings + critical
    else:
        display_limits = limits

    if not display_limits:
        print("No limits to display")
        return

    # Header
    print(f"{'Parameter':<35} {'Current':>12} {'Limit':>12} {'Usage':>8} {'Status':<10}")
    print("-" * 80)

    for limit in display_limits:
        current = str(limit['current']) if limit['current'] is not None else 'N/A'
        usage = f"{limit['usage_pct']}%" if limit['usage_pct'] is not None else 'N/A'

        if limit in critical:
            status = 'CRITICAL'
        elif limit in warnings:
            status = 'WARNING'
        else:
            status = 'OK'

        print(f"{limit['name']:<35} {current:>12} {limit['limit']:>12} {usage:>8} {status:<10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor kernel resource limits and their current usage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    Show all limits with current usage
  %(prog)s --warn-only        Only show limits approaching thresholds
  %(prog)s --format json      Output in JSON format for monitoring systems
  %(prog)s --warn 70 --crit 90  Custom warning and critical thresholds

Exit codes:
  0 - All limits within safe thresholds
  1 - One or more limits approaching exhaustion
  2 - Usage error or unable to read kernel parameters
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
        help='Show detailed information for all limits'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show limits with warnings or critical status'
    )

    parser.add_argument(
        '--warn',
        type=int,
        default=80,
        metavar='PCT',
        help='Warning threshold percentage (default: 80)'
    )

    parser.add_argument(
        '--crit',
        type=int,
        default=95,
        metavar='PCT',
        help='Critical threshold percentage (default: 95)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn < 0 or args.warn > 100:
        print("Error: Warning threshold must be 0-100", file=sys.stderr)
        sys.exit(2)
    if args.crit < 0 or args.crit > 100:
        print("Error: Critical threshold must be 0-100", file=sys.stderr)
        sys.exit(2)
    if args.warn >= args.crit:
        print("Error: Warning threshold must be less than critical",
              file=sys.stderr)
        sys.exit(2)

    # Check if we can read /proc
    if not os.path.isdir('/proc/sys'):
        print("Error: /proc/sys not available", file=sys.stderr)
        print("This script requires the procfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Gather limit information
    limits = get_limit_info()

    if not limits:
        print("Error: Unable to read any kernel limits", file=sys.stderr)
        sys.exit(2)

    # Analyze for warnings and critical issues
    warnings, critical = analyze_limits(limits, args.warn, args.crit)

    # Output based on format
    if args.format == 'json':
        output_json(limits, warnings, critical)
    elif args.format == 'table':
        output_table(limits, warnings, critical, args.warn_only)
    else:
        output_plain(limits, warnings, critical, args.warn_only, args.verbose)

    # Exit code based on findings
    if critical:
        sys.exit(1)
    elif warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
