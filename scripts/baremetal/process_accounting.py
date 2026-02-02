#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [process, accounting, io, cpu, memory, resources]
#   requires: []
#   privilege: none
#   related: [process_fd, process_priority, proc_pressure]
#   brief: Monitor process resource accounting from /proc

"""
Monitor process resource accounting from /proc to identify resource hogs.

Analyzes per-process I/O statistics, CPU time, and memory usage to identify
processes consuming disproportionate system resources.

Features:
- Per-process I/O read/write statistics from /proc/[pid]/io
- CPU time accounting (user, system) from /proc/[pid]/stat
- Memory usage tracking (RSS, VMS)
- Sort by various metrics (io_read, io_write, cpu_time, memory)
- Filter by user, command pattern, or minimum thresholds
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_file(path: str, context: Context) -> str | None:
    """Read file contents, return None if unavailable."""
    try:
        return context.read_file(path)
    except (IOError, OSError, PermissionError, FileNotFoundError):
        return None


def get_uid_name(uid: int) -> str:
    """Convert UID to username."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError, OverflowError):
        return str(uid)


def parse_proc_io(pid: int, context: Context) -> dict[str, int] | None:
    """Parse /proc/[pid]/io for I/O statistics."""
    content = read_file(f'/proc/{pid}/io', context)
    if not content:
        return None

    io_stats = {}
    for line in content.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            try:
                io_stats[key.strip()] = int(value.strip())
            except ValueError:
                continue

    return io_stats


def parse_proc_stat(pid: int, context: Context) -> dict[str, Any] | None:
    """Parse /proc/[pid]/stat for process statistics."""
    content = read_file(f'/proc/{pid}/stat', context)
    if not content:
        return None

    match = re.match(r'(\d+) \((.+)\) (\S+) (.+)', content)
    if not match:
        return None

    try:
        fields = match.group(4).split()
        return {
            'pid': int(match.group(1)),
            'comm': match.group(2),
            'state': match.group(3),
            'ppid': int(fields[0]),
            'utime': int(fields[10]),
            'stime': int(fields[11]),
            'vsize': int(fields[19]),
            'rss': int(fields[20]),
        }
    except (IndexError, ValueError):
        return None


def parse_proc_status(pid: int, context: Context) -> dict[str, Any] | None:
    """Parse /proc/[pid]/status for additional info."""
    content = read_file(f'/proc/{pid}/status', context)
    if not content:
        return None

    status = {}
    for line in content.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            status[key.strip()] = value.strip()

    result = {}

    if 'Uid' in status:
        try:
            result['uid'] = int(status['Uid'].split()[0])
        except (IndexError, ValueError):
            pass

    for key in ['VmRSS', 'VmSize', 'VmSwap']:
        if key in status:
            try:
                result[key.lower()] = int(status[key].split()[0])
            except (IndexError, ValueError):
                pass

    return result


def get_process_info(pid: int, context: Context) -> dict[str, Any] | None:
    """Gather all available information for a process."""
    stat = parse_proc_stat(pid, context)
    if not stat:
        return None

    io = parse_proc_io(pid, context)
    status = parse_proc_status(pid, context)

    # Get clock ticks per second for CPU time calculation
    clock_ticks = 100  # Common default
    page_size = 4096   # Common default

    info = {
        'pid': pid,
        'comm': stat['comm'],
        'state': stat['state'],
        'ppid': stat['ppid'],
        'cpu_user_ticks': stat['utime'],
        'cpu_sys_ticks': stat['stime'],
        'cpu_total_ticks': stat['utime'] + stat['stime'],
        'cpu_total_secs': (stat['utime'] + stat['stime']) / clock_ticks,
        'vsize_bytes': stat['vsize'],
        'rss_pages': stat['rss'],
        'rss_bytes': stat['rss'] * page_size,
    }

    if io:
        info['io_read_bytes'] = io.get('read_bytes', 0)
        info['io_write_bytes'] = io.get('write_bytes', 0)
    else:
        info['io_read_bytes'] = 0
        info['io_write_bytes'] = 0

    if status:
        info['uid'] = status.get('uid', 0)
        info['user'] = get_uid_name(status.get('uid', 0))
        info['vmrss_kb'] = status.get('vmrss', info['rss_bytes'] // 1024)
        info['vmsize_kb'] = status.get('vmsize', info['vsize_bytes'] // 1024)
    else:
        info['uid'] = 0
        info['user'] = 'unknown'
        info['vmrss_kb'] = info['rss_bytes'] // 1024
        info['vmsize_kb'] = info['vsize_bytes'] // 1024

    return info


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_val) < 1024.0:
            return f'{bytes_val:.1f}{unit}'
        bytes_val /= 1024.0
    return f'{bytes_val:.1f}PB'


def format_time(seconds: float) -> str:
    """Format seconds to human-readable time."""
    if seconds < 60:
        return f'{seconds:.1f}s'
    elif seconds < 3600:
        return f'{seconds / 60:.1f}m'
    else:
        return f'{seconds / 3600:.1f}h'


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = success, 1 = warnings exceed threshold, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor process resource accounting")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--top", "-n", type=int, default=10, help="Show top N processes")
    parser.add_argument("--sort", "-s", choices=['cpu', 'io_read', 'io_write', 'memory'],
                        default='cpu', help="Sort by metric")
    parser.add_argument("--user", "-u", help="Only show processes owned by user")
    parser.add_argument("--command", "-c", help="Only show processes matching pattern")
    parser.add_argument("--warn-cpu", type=float, help="Warn if CPU time exceeds seconds")
    parser.add_argument("--warn-memory", type=int, help="Warn if memory RSS exceeds KB")
    opts = parser.parse_args(args)

    if opts.top < 1:
        output.error("--top must be at least 1")
        return 2

    # Check /proc availability
    if not context.file_exists('/proc'):
        output.error("/proc filesystem not available")
        return 2

    # Gather process information
    processes = []
    proc_entries = context.glob('[0-9]*', root='/proc')

    for proc_path in proc_entries:
        pid_str = proc_path.split('/')[-1]
        if not pid_str.isdigit():
            continue

        pid = int(pid_str)
        info = get_process_info(pid, context)
        if info:
            processes.append(info)

    if not processes:
        output.error("Could not read any process information")
        return 2

    # Filter processes
    if opts.user:
        processes = [p for p in processes if p['user'] == opts.user]

    if opts.command:
        processes = [p for p in processes
                     if re.search(opts.command, p['comm'], re.IGNORECASE)]

    # Sort processes
    sort_keys = {
        'cpu': 'cpu_total_secs',
        'io_read': 'io_read_bytes',
        'io_write': 'io_write_bytes',
        'memory': 'vmrss_kb',
    }
    key = sort_keys.get(opts.sort, 'cpu_total_secs')
    processes = sorted(processes, key=lambda x: x.get(key, 0), reverse=True)

    # Check warning thresholds
    warnings = []
    for proc in processes:
        issues = []
        if opts.warn_cpu is not None and proc['cpu_total_secs'] >= opts.warn_cpu:
            issues.append(f"CPU time {format_time(proc['cpu_total_secs'])} >= {format_time(opts.warn_cpu)}")
        if opts.warn_memory is not None and proc['vmrss_kb'] >= opts.warn_memory:
            issues.append(f"Memory {proc['vmrss_kb']}KB >= {opts.warn_memory}KB")

        if issues:
            warnings.append({
                'pid': proc['pid'],
                'comm': proc['comm'],
                'user': proc['user'],
                'issues': issues,
            })

    # Build result
    top_processes = processes[:opts.top]

    result = {
        'summary': {
            'total_processes_scanned': len(processes),
            'processes_with_warnings': len(warnings),
            'top_n': opts.top,
        },
        'warnings': warnings,
        'top_processes': [
            {
                'pid': p['pid'],
                'comm': p['comm'],
                'user': p['user'],
                'cpu_secs': round(p['cpu_total_secs'], 2),
                'io_read': format_bytes(p['io_read_bytes']),
                'io_write': format_bytes(p['io_write_bytes']),
                'memory_kb': p['vmrss_kb'],
            }
            for p in top_processes
        ],
    }

    output.emit(result)

    # Set summary
    if warnings:
        output.set_summary(f"{len(warnings)} process(es) exceed warning thresholds")
        return 1
    else:
        output.set_summary(f"Top {len(top_processes)} processes by {opts.sort}")
        return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
