#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [process, fd, file-descriptor, limits, exhaustion]
#   requires: []
#   privilege: none
#   related: [process_accounting, fd_exhaustion_monitor, fd_leak_detector]
#   brief: Monitor per-process file descriptor usage

"""
Monitor per-process file descriptor usage and identify processes at risk.

Scans running processes to identify those approaching their file descriptor
limits. Critical for large-scale environments where individual services can
exhaust their fd limits, causing cascading failures.

Key features:
- Identifies processes using high percentage of their fd limit
- Shows top fd consumers
- Detects processes with very low limits that may cause issues
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_file(path: str, context: Context) -> str | None:
    """Read a /proc file and return contents."""
    try:
        return context.read_file(path)
    except (OSError, IOError, PermissionError, FileNotFoundError):
        return None


def get_uid_name(uid: int) -> str:
    """Convert UID to username."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


def get_process_fd_info(pid: int, context: Context) -> dict[str, Any] | None:
    """Get file descriptor information for a process."""
    fd_path = f'/proc/{pid}/fd'

    # Count open file descriptors by listing fd directory
    try:
        fd_entries = context.glob('[0-9]*', root=fd_path)
        fd_count = len(fd_entries)
    except (OSError, PermissionError):
        return None

    # Get fd limit from /proc/PID/limits
    fd_limit = None
    limits_content = read_file(f'/proc/{pid}/limits', context)
    if limits_content:
        for line in limits_content.split('\n'):
            if 'Max open files' in line:
                parts = line.split()
                try:
                    fd_limit = int(parts[3])  # Soft limit
                except (IndexError, ValueError):
                    pass
                break

    if fd_limit is None or fd_limit == 0:
        return None

    # Get command name
    comm = read_file(f'/proc/{pid}/comm', context)
    comm = comm.strip() if comm else 'unknown'

    # Get user info from status
    uid = None
    username = None
    status_content = read_file(f'/proc/{pid}/status', context)
    if status_content:
        for line in status_content.split('\n'):
            if line.startswith('Uid:'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        uid = int(parts[1])
                        username = get_uid_name(uid)
                    except ValueError:
                        pass
                break

    usage_pct = round((fd_count / fd_limit) * 100, 1) if fd_limit > 0 else 0

    return {
        'pid': pid,
        'comm': comm,
        'user': username or 'unknown',
        'uid': uid,
        'fd_count': fd_count,
        'fd_limit': fd_limit,
        'usage_pct': usage_pct,
    }


def scan_processes(context: Context) -> list[dict[str, Any]]:
    """Scan all processes and gather fd information."""
    processes = []

    try:
        proc_entries = context.glob('[0-9]*', root='/proc')
        for proc_path in proc_entries:
            pid_str = proc_path.split('/')[-1]
            if pid_str.isdigit():
                pid = int(pid_str)
                info = get_process_fd_info(pid, context)
                if info:
                    processes.append(info)
    except OSError:
        pass

    return processes


def analyze_processes(
    processes: list[dict],
    warn_threshold: int,
    critical_threshold: int,
    min_limit: int
) -> tuple[list[dict], list[dict], list[dict]]:
    """Analyze processes and return warnings, critical issues, and low-limit processes."""
    warnings = []
    critical = []
    low_limit = []

    for proc in processes:
        if proc['usage_pct'] >= critical_threshold:
            critical.append(proc)
        elif proc['usage_pct'] >= warn_threshold:
            warnings.append(proc)

        if proc['fd_limit'] < min_limit:
            low_limit.append(proc)

    return warnings, critical, low_limit


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor per-process file descriptor usage")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--warn", type=int, default=80, help="Warning threshold percentage")
    parser.add_argument("--crit", type=int, default=95, help="Critical threshold percentage")
    parser.add_argument("--top", type=int, default=10, help="Show top N fd consumers")
    parser.add_argument("--min-limit", type=int, default=1024,
                        help="Flag processes with fd limit below this")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0 or opts.warn > 100:
        output.error("Warning threshold must be 0-100")
        return 2
    if opts.crit < 0 or opts.crit > 100:
        output.error("Critical threshold must be 0-100")
        return 2
    if opts.warn >= opts.crit:
        output.error("Warning threshold must be less than critical")
        return 2

    # Check if /proc is available
    if not context.file_exists('/proc'):
        output.error("/proc not available")
        return 2

    # Scan processes
    processes = scan_processes(context)

    if not processes:
        output.error("Unable to read any process information")
        return 2

    # Analyze for warnings and critical issues
    warnings, critical, low_limit = analyze_processes(
        processes, opts.warn, opts.crit, opts.min_limit
    )

    # Sort by fd count for top consumers
    sorted_procs = sorted(processes, key=lambda x: x['fd_count'], reverse=True)
    top_consumers = sorted_procs[:opts.top]

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
        'top_consumers': top_consumers,
    }

    if opts.verbose:
        result['low_limit_processes'] = low_limit

    output.emit(result)

    # Set summary
    if critical:
        output.set_summary(f"CRITICAL: {len(critical)} process(es) approaching fd exhaustion")
        return 1
    elif warnings:
        output.set_summary(f"WARNING: {len(warnings)} process(es) with elevated fd usage")
        return 1
    else:
        output.set_summary(f"All {len(processes)} processes within safe fd thresholds")
        return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
