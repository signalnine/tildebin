#!/usr/bin/env python3
"""
Monitor per-process file descriptor usage and identify processes at risk.

Scans running processes to identify those approaching their file descriptor
limits. This is critical for large-scale baremetal environments where
individual services can exhaust their fd limits, causing cascading failures.

Unlike system-wide file descriptor monitoring (fs.file-max), this script
focuses on per-process limits (RLIMIT_NOFILE) which are often the actual
bottleneck for applications like databases, web servers, and proxies.

Key features:
- Identifies processes using high percentage of their fd limit
- Shows top fd consumers
- Detects processes with very low limits that may cause issues
- Groups by user or command for fleet analysis

Exit codes:
    0 - All processes within safe thresholds
    1 - One or more processes approaching fd exhaustion
    2 - Usage error or unable to read process information
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple


def read_proc_file(path: str) -> Optional[str]:
    """Read a /proc file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError, PermissionError):
        return None


def get_process_fd_info(pid: int) -> Optional[Dict[str, Any]]:
    """Get file descriptor information for a process."""
    fd_path = f'/proc/{pid}/fd'
    limits_path = f'/proc/{pid}/limits'
    comm_path = f'/proc/{pid}/comm'
    cmdline_path = f'/proc/{pid}/cmdline'
    status_path = f'/proc/{pid}/status'

    try:
        # Count open file descriptors
        fd_count = len(os.listdir(fd_path))
    except (OSError, PermissionError):
        return None

    # Get fd limit from /proc/PID/limits
    fd_limit = None
    limits_content = read_proc_file(limits_path)
    if limits_content:
        for line in limits_content.split('\n'):
            if 'Max open files' in line:
                parts = line.split()
                # Format: "Max open files            1024                 1048576              files"
                # Soft limit is what matters for the process
                try:
                    fd_limit = int(parts[3])  # Soft limit
                except (IndexError, ValueError):
                    pass
                break

    if fd_limit is None or fd_limit == 0:
        return None

    # Get command name
    comm = read_proc_file(comm_path) or 'unknown'

    # Get full command line (for more context)
    cmdline_raw = read_proc_file(cmdline_path)
    if cmdline_raw:
        # Arguments are null-separated
        cmdline = cmdline_raw.replace('\x00', ' ').strip()
        # Truncate long command lines
        if len(cmdline) > 100:
            cmdline = cmdline[:97] + '...'
    else:
        cmdline = comm

    # Get user info from status
    uid = None
    username = None
    status_content = read_proc_file(status_path)
    if status_content:
        for line in status_content.split('\n'):
            if line.startswith('Uid:'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        uid = int(parts[1])
                    except ValueError:
                        pass
                break

    # Resolve username
    if uid is not None:
        try:
            import pwd
            username = pwd.getpwuid(uid).pw_name
        except (KeyError, ImportError):
            username = str(uid)

    usage_pct = round((fd_count / fd_limit) * 100, 1) if fd_limit > 0 else 0

    return {
        'pid': pid,
        'comm': comm,
        'cmdline': cmdline,
        'user': username or 'unknown',
        'uid': uid,
        'fd_count': fd_count,
        'fd_limit': fd_limit,
        'usage_pct': usage_pct,
    }


def scan_processes() -> List[Dict[str, Any]]:
    """Scan all processes and gather fd information."""
    processes = []

    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pid = int(entry)
                info = get_process_fd_info(pid)
                if info:
                    processes.append(info)
    except OSError:
        pass

    return processes


def analyze_processes(processes: List[Dict], warn_threshold: int,
                      critical_threshold: int, min_limit: int) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Analyze processes and return warnings, critical issues, and low-limit processes."""
    warnings = []
    critical = []
    low_limit = []

    for proc in processes:
        if proc['usage_pct'] >= critical_threshold:
            critical.append(proc)
        elif proc['usage_pct'] >= warn_threshold:
            warnings.append(proc)

        # Check for dangerously low fd limits
        if proc['fd_limit'] < min_limit:
            low_limit.append(proc)

    return warnings, critical, low_limit


def output_plain(processes: List[Dict], warnings: List[Dict],
                 critical: List[Dict], low_limit: List[Dict],
                 warn_only: bool, verbose: bool, top_n: int) -> None:
    """Output in plain text format."""
    if critical:
        print("CRITICAL - Processes approaching fd exhaustion:")
        for proc in sorted(critical, key=lambda x: x['usage_pct'], reverse=True):
            print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                  f"{proc['fd_count']:>6}/{proc['fd_limit']:<6} ({proc['usage_pct']}%) "
                  f"user={proc['user']}")
        print()

    if warnings:
        print("WARNING - Processes with elevated fd usage:")
        for proc in sorted(warnings, key=lambda x: x['usage_pct'], reverse=True):
            print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                  f"{proc['fd_count']:>6}/{proc['fd_limit']:<6} ({proc['usage_pct']}%) "
                  f"user={proc['user']}")
        print()

    if low_limit:
        print("NOTICE - Processes with low fd limits:")
        for proc in sorted(low_limit, key=lambda x: x['fd_limit'])[:10]:
            print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                  f"limit={proc['fd_limit']} (may be insufficient for workload)")
        print()

    if not warn_only:
        if not critical and not warnings:
            print("OK - All processes within safe fd thresholds")
            print()

        if verbose or top_n > 0:
            # Show top fd consumers
            sorted_procs = sorted(processes, key=lambda x: x['fd_count'], reverse=True)
            display_count = top_n if top_n > 0 else 10
            print(f"Top {display_count} file descriptor consumers:")
            for proc in sorted_procs[:display_count]:
                print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                      f"{proc['fd_count']:>6} fds ({proc['usage_pct']}% of {proc['fd_limit']}) "
                      f"user={proc['user']}")


def output_json(processes: List[Dict], warnings: List[Dict],
                critical: List[Dict], low_limit: List[Dict], top_n: int) -> None:
    """Output in JSON format."""
    sorted_procs = sorted(processes, key=lambda x: x['fd_count'], reverse=True)
    top_consumers = sorted_procs[:top_n] if top_n > 0 else sorted_procs[:10]

    result = {
        'status': 'critical' if critical else ('warning' if warnings else 'ok'),
        'summary': {
            'total_processes': len(processes),
            'critical_count': len(critical),
            'warning_count': len(warnings),
            'low_limit_count': len(low_limit),
            'total_fds': sum(p['fd_count'] for p in processes),
        },
        'critical': critical,
        'warnings': warnings,
        'low_limit_processes': low_limit,
        'top_consumers': top_consumers,
    }
    print(json.dumps(result, indent=2))


def output_table(processes: List[Dict], warnings: List[Dict],
                 critical: List[Dict], warn_only: bool, top_n: int) -> None:
    """Output in table format."""
    if warn_only:
        display_procs = critical + warnings
        display_procs.sort(key=lambda x: x['usage_pct'], reverse=True)
    else:
        display_procs = sorted(processes, key=lambda x: x['fd_count'], reverse=True)
        if top_n > 0:
            display_procs = display_procs[:top_n]

    if not display_procs:
        print("No processes to display")
        return

    # Header
    print(f"{'PID':>7} {'Command':<15} {'User':<12} {'FDs':>6} {'Limit':>7} {'Usage':>7} {'Status':<10}")
    print("-" * 75)

    for proc in display_procs:
        if proc in critical:
            status = 'CRITICAL'
        elif proc in warnings:
            status = 'WARNING'
        else:
            status = 'OK'

        print(f"{proc['pid']:>7} {proc['comm']:<15} {proc['user']:<12} "
              f"{proc['fd_count']:>6} {proc['fd_limit']:>7} {proc['usage_pct']:>6}% {status:<10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor per-process file descriptor usage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    Show processes with high fd usage
  %(prog)s --top 20           Show top 20 fd consumers
  %(prog)s --warn-only        Only show processes approaching limits
  %(prog)s --format json      Output in JSON format for monitoring
  %(prog)s --warn 70 --crit 90  Custom warning and critical thresholds
  %(prog)s --min-limit 4096   Flag processes with limits below 4096

Exit codes:
  0 - All processes within safe thresholds
  1 - One or more processes approaching fd exhaustion
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
        help='Show detailed information including top consumers'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show processes with warnings or critical status'
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

    parser.add_argument(
        '--top',
        type=int,
        default=0,
        metavar='N',
        help='Show top N file descriptor consumers (default: 10 with --verbose)'
    )

    parser.add_argument(
        '--min-limit',
        type=int,
        default=1024,
        metavar='N',
        help='Flag processes with fd limit below this value (default: 1024)'
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
    if args.top < 0:
        print("Error: --top must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.min_limit < 0:
        print("Error: --min-limit must be non-negative", file=sys.stderr)
        sys.exit(2)

    # Check if we can read /proc
    if not os.path.isdir('/proc'):
        print("Error: /proc not available", file=sys.stderr)
        print("This script requires the procfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Scan processes
    processes = scan_processes()

    if not processes:
        print("Error: Unable to read any process information", file=sys.stderr)
        print("This may require elevated privileges to read /proc/PID/fd",
              file=sys.stderr)
        sys.exit(2)

    # Analyze for warnings and critical issues
    warnings, critical, low_limit = analyze_processes(
        processes, args.warn, args.crit, args.min_limit
    )

    # Output based on format
    if args.format == 'json':
        output_json(processes, warnings, critical, low_limit, args.top)
    elif args.format == 'table':
        output_table(processes, warnings, critical, args.warn_only, args.top)
    else:
        output_plain(processes, warnings, critical, low_limit,
                     args.warn_only, args.verbose, args.top)

    # Exit code based on findings
    if critical:
        sys.exit(1)
    elif warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
