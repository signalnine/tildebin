#!/usr/bin/env python3
"""
Monitor process resource accounting from /proc to identify resource hogs.

Analyzes per-process I/O statistics, CPU time, and memory usage to identify
processes consuming disproportionate system resources. Useful for capacity
planning, troubleshooting performance issues, and detecting runaway processes.

Features:
- Per-process I/O read/write statistics from /proc/[pid]/io
- CPU time accounting (user, system, wait) from /proc/[pid]/stat
- Memory usage tracking (RSS, VMS, shared)
- Sort by various metrics (io_read, io_write, cpu_time, memory)
- Filter by user, command pattern, or minimum thresholds
- Top-N reporting for quick identification of resource hogs

Use cases:
- Identify processes with excessive disk I/O
- Find CPU-intensive background tasks
- Detect memory leaks over time
- Audit resource usage by user or application
- Baseline resource consumption for capacity planning

Exit codes:
    0 - Success, no processes exceed warning thresholds
    1 - One or more processes exceed warning thresholds
    2 - Usage error or insufficient permissions
"""

import argparse
import json
import os
import pwd
import re
import sys
from collections import defaultdict


def read_file(path):
    """Read file contents, return None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError, PermissionError):
        return None


def get_process_list():
    """Get list of PIDs from /proc."""
    pids = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pids.append(int(entry))
    except (IOError, OSError):
        pass
    return pids


def get_uid_name(uid):
    """Convert UID to username."""
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError):
        return str(uid)


def parse_proc_io(pid):
    """Parse /proc/[pid]/io for I/O statistics."""
    content = read_file(f'/proc/{pid}/io')
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


def parse_proc_stat(pid):
    """Parse /proc/[pid]/stat for process statistics."""
    content = read_file(f'/proc/{pid}/stat')
    if not content:
        return None

    # The command name is in parentheses and may contain spaces
    # Format: pid (comm) state ppid ...
    match = re.match(r'(\d+) \((.+)\) (\S+) (.+)', content)
    if not match:
        return None

    try:
        fields = match.group(4).split()
        # Fields are 0-indexed from after (comm) state
        # utime is field 11 (index 10 after split)
        # stime is field 12 (index 11 after split)
        # From man proc(5):
        # (14) utime - CPU time in user mode (clock ticks)
        # (15) stime - CPU time in kernel mode (clock ticks)
        # (23) vsize - Virtual memory size in bytes
        # (24) rss - Resident set size (pages)
        return {
            'pid': int(match.group(1)),
            'comm': match.group(2),
            'state': match.group(3),
            'ppid': int(fields[0]),
            'utime': int(fields[10]),  # Field 14 in stat
            'stime': int(fields[11]),  # Field 15 in stat
            'vsize': int(fields[19]),  # Field 23 in stat
            'rss': int(fields[20]),    # Field 24 in stat (pages)
        }
    except (IndexError, ValueError):
        return None


def parse_proc_status(pid):
    """Parse /proc/[pid]/status for additional info."""
    content = read_file(f'/proc/{pid}/status')
    if not content:
        return None

    status = {}
    for line in content.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            status[key.strip()] = value.strip()

    result = {}

    # Get UID
    if 'Uid' in status:
        try:
            result['uid'] = int(status['Uid'].split()[0])
        except (IndexError, ValueError):
            pass

    # Get memory info in kB
    for key in ['VmRSS', 'VmSize', 'VmSwap', 'RssFile', 'RssShmem']:
        if key in status:
            try:
                # Format: "12345 kB"
                result[key.lower()] = int(status[key].split()[0])
            except (IndexError, ValueError):
                pass

    return result


def get_process_info(pid):
    """Gather all available information for a process."""
    stat = parse_proc_stat(pid)
    if not stat:
        return None

    io = parse_proc_io(pid)
    status = parse_proc_status(pid)

    # Get clock ticks per second for CPU time calculation
    try:
        clock_ticks = os.sysconf('SC_CLK_TCK')
    except (ValueError, OSError):
        clock_ticks = 100  # Common default

    # Get page size for memory calculation
    try:
        page_size = os.sysconf('SC_PAGE_SIZE')
    except (ValueError, OSError):
        page_size = 4096  # Common default

    info = {
        'pid': pid,
        'comm': stat['comm'],
        'state': stat['state'],
        'ppid': stat['ppid'],
        'cpu_user_ticks': stat['utime'],
        'cpu_sys_ticks': stat['stime'],
        'cpu_total_ticks': stat['utime'] + stat['stime'],
        'cpu_user_secs': stat['utime'] / clock_ticks,
        'cpu_sys_secs': stat['stime'] / clock_ticks,
        'cpu_total_secs': (stat['utime'] + stat['stime']) / clock_ticks,
        'vsize_bytes': stat['vsize'],
        'rss_pages': stat['rss'],
        'rss_bytes': stat['rss'] * page_size,
    }

    # Add I/O stats if available
    if io:
        info['io_read_bytes'] = io.get('read_bytes', 0)
        info['io_write_bytes'] = io.get('write_bytes', 0)
        info['io_read_chars'] = io.get('rchar', 0)
        info['io_write_chars'] = io.get('wchar', 0)
        info['io_syscalls_read'] = io.get('syscr', 0)
        info['io_syscalls_write'] = io.get('syscw', 0)
    else:
        info['io_read_bytes'] = 0
        info['io_write_bytes'] = 0
        info['io_read_chars'] = 0
        info['io_write_chars'] = 0
        info['io_syscalls_read'] = 0
        info['io_syscalls_write'] = 0

    # Add status info if available
    if status:
        info['uid'] = status.get('uid', 0)
        info['user'] = get_uid_name(status.get('uid', 0))
        info['vmrss_kb'] = status.get('vmrss', info['rss_bytes'] // 1024)
        info['vmsize_kb'] = status.get('vmsize', info['vsize_bytes'] // 1024)
        info['vmswap_kb'] = status.get('vmswap', 0)
    else:
        info['uid'] = 0
        info['user'] = 'unknown'
        info['vmrss_kb'] = info['rss_bytes'] // 1024
        info['vmsize_kb'] = info['vsize_bytes'] // 1024
        info['vmswap_kb'] = 0

    return info


def format_bytes(bytes_val):
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_val) < 1024.0:
            return f'{bytes_val:.1f}{unit}'
        bytes_val /= 1024.0
    return f'{bytes_val:.1f}PB'


def format_time(seconds):
    """Format seconds to human-readable time."""
    if seconds < 60:
        return f'{seconds:.1f}s'
    elif seconds < 3600:
        minutes = seconds / 60
        return f'{minutes:.1f}m'
    else:
        hours = seconds / 3600
        return f'{hours:.1f}h'


def filter_processes(processes, user=None, command=None, min_cpu=None,
                     min_io_read=None, min_io_write=None, min_memory=None):
    """Filter processes based on criteria."""
    filtered = []

    for proc in processes:
        # Filter by user
        if user and proc['user'] != user:
            continue

        # Filter by command pattern
        if command and not re.search(command, proc['comm'], re.IGNORECASE):
            continue

        # Filter by minimum CPU time (seconds)
        if min_cpu is not None and proc['cpu_total_secs'] < min_cpu:
            continue

        # Filter by minimum I/O read (bytes)
        if min_io_read is not None and proc['io_read_bytes'] < min_io_read:
            continue

        # Filter by minimum I/O write (bytes)
        if min_io_write is not None and proc['io_write_bytes'] < min_io_write:
            continue

        # Filter by minimum memory (KB)
        if min_memory is not None and proc['vmrss_kb'] < min_memory:
            continue

        filtered.append(proc)

    return filtered


def sort_processes(processes, sort_by):
    """Sort processes by specified metric."""
    sort_keys = {
        'cpu': 'cpu_total_secs',
        'io_read': 'io_read_bytes',
        'io_write': 'io_write_bytes',
        'memory': 'vmrss_kb',
        'pid': 'pid',
    }

    key = sort_keys.get(sort_by, 'cpu_total_secs')
    return sorted(processes, key=lambda x: x.get(key, 0), reverse=(sort_by != 'pid'))


def check_thresholds(processes, warn_cpu=None, warn_io_read=None,
                     warn_io_write=None, warn_memory=None):
    """Check processes against warning thresholds."""
    warnings = []

    for proc in processes:
        issues = []

        if warn_cpu is not None and proc['cpu_total_secs'] >= warn_cpu:
            issues.append(f"CPU time {format_time(proc['cpu_total_secs'])} >= {format_time(warn_cpu)}")

        if warn_io_read is not None and proc['io_read_bytes'] >= warn_io_read:
            issues.append(f"I/O read {format_bytes(proc['io_read_bytes'])} >= {format_bytes(warn_io_read)}")

        if warn_io_write is not None and proc['io_write_bytes'] >= warn_io_write:
            issues.append(f"I/O write {format_bytes(proc['io_write_bytes'])} >= {format_bytes(warn_io_write)}")

        if warn_memory is not None and proc['vmrss_kb'] >= warn_memory:
            issues.append(f"Memory {proc['vmrss_kb']}KB >= {warn_memory}KB")

        if issues:
            warnings.append({
                'process': proc,
                'issues': issues,
            })

    return warnings


def output_plain(processes, warnings, top_n, verbose=False, warn_only=False):
    """Output results in plain text format."""
    lines = []

    if warnings:
        lines.append("WARNING - Processes exceeding thresholds:")
        lines.append("-" * 60)
        for w in warnings:
            proc = w['process']
            lines.append(f"  PID {proc['pid']} ({proc['comm']}) - {proc['user']}")
            for issue in w['issues']:
                lines.append(f"    - {issue}")
        lines.append("")

    if not warn_only:
        lines.append(f"Top {min(top_n, len(processes))} Processes by Resource Usage:")
        lines.append("-" * 80)
        lines.append(f"{'PID':<8} {'USER':<12} {'COMMAND':<20} {'CPU':<10} {'IO_R':<10} {'IO_W':<10} {'MEM':<10}")
        lines.append("-" * 80)

        for proc in processes[:top_n]:
            comm = proc['comm'][:19] if len(proc['comm']) > 19 else proc['comm']
            user = proc['user'][:11] if len(proc['user']) > 11 else proc['user']

            lines.append(
                f"{proc['pid']:<8} "
                f"{user:<12} "
                f"{comm:<20} "
                f"{format_time(proc['cpu_total_secs']):<10} "
                f"{format_bytes(proc['io_read_bytes']):<10} "
                f"{format_bytes(proc['io_write_bytes']):<10} "
                f"{format_bytes(proc['vmrss_kb'] * 1024):<10}"
            )

        if verbose:
            lines.append("")
            lines.append("Legend: CPU=total CPU time, IO_R=bytes read, IO_W=bytes written, MEM=RSS")

    if not warnings and not warn_only:
        lines.append("")
        lines.append("No processes exceed warning thresholds.")

    return '\n'.join(lines)


def output_json(processes, warnings, top_n, verbose=False):
    """Output results in JSON format."""
    result = {
        'summary': {
            'total_processes_scanned': len(processes),
            'processes_with_warnings': len(warnings),
            'top_n': top_n,
        },
        'warnings': [
            {
                'pid': w['process']['pid'],
                'comm': w['process']['comm'],
                'user': w['process']['user'],
                'issues': w['issues'],
            }
            for w in warnings
        ],
        'top_processes': processes[:top_n],
    }

    if verbose:
        result['all_processes'] = processes

    return json.dumps(result, indent=2)


def output_table(processes, warnings, top_n, warn_only=False):
    """Output results in table format."""
    lines = []

    if warnings:
        lines.append("=" * 90)
        lines.append("PROCESSES EXCEEDING THRESHOLDS")
        lines.append("=" * 90)
        lines.append(f"{'PID':<8} {'USER':<12} {'COMMAND':<20} {'ISSUE':<48}")
        lines.append("-" * 90)
        for w in warnings:
            proc = w['process']
            comm = proc['comm'][:19]
            user = proc['user'][:11]
            for i, issue in enumerate(w['issues']):
                if i == 0:
                    lines.append(f"{proc['pid']:<8} {user:<12} {comm:<20} {issue:<48}")
                else:
                    lines.append(f"{'':<8} {'':<12} {'':<20} {issue:<48}")
        lines.append("=" * 90)
        lines.append("")

    if not warn_only:
        lines.append(f"{'PID':<8} {'USER':<12} {'COMMAND':<20} {'CPU TIME':<12} {'IO READ':<12} {'IO WRITE':<12} {'MEMORY':<10}")
        lines.append("-" * 90)

        for proc in processes[:top_n]:
            comm = proc['comm'][:19]
            user = proc['user'][:11]
            lines.append(
                f"{proc['pid']:<8} "
                f"{user:<12} "
                f"{comm:<20} "
                f"{format_time(proc['cpu_total_secs']):<12} "
                f"{format_bytes(proc['io_read_bytes']):<12} "
                f"{format_bytes(proc['io_write_bytes']):<12} "
                f"{format_bytes(proc['vmrss_kb'] * 1024):<10}"
            )

    return '\n'.join(lines)


def parse_size(size_str):
    """Parse size string like '100MB' to bytes."""
    if not size_str:
        return None

    size_str = size_str.upper().strip()

    multipliers = {
        'B': 1,
        'K': 1024,
        'KB': 1024,
        'M': 1024 * 1024,
        'MB': 1024 * 1024,
        'G': 1024 * 1024 * 1024,
        'GB': 1024 * 1024 * 1024,
    }

    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if size_str.endswith(suffix):
            try:
                return int(float(size_str[:-len(suffix)]) * mult)
            except ValueError:
                return None

    # Try parsing as plain number (bytes)
    try:
        return int(size_str)
    except ValueError:
        return None


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor process resource accounting from /proc',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Show top 10 processes by CPU time
  %(prog)s --sort io_write --top 20  # Top 20 by I/O writes
  %(prog)s --user root               # Only show root processes
  %(prog)s --command python          # Only show Python processes
  %(prog)s --warn-cpu 3600           # Warn if CPU time > 1 hour
  %(prog)s --warn-io-write 1GB       # Warn if I/O writes > 1GB
  %(prog)s --min-cpu 60              # Only show processes with >60s CPU
  %(prog)s --format json             # JSON output for automation

Sort options:
  cpu       - Total CPU time (user + system)
  io_read   - Bytes read from storage
  io_write  - Bytes written to storage
  memory    - Resident set size (RSS)
  pid       - Process ID (ascending)

Exit codes:
  0 - Success, no processes exceed warning thresholds
  1 - One or more processes exceed warning thresholds
  2 - Usage error or insufficient permissions
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show processes exceeding warning thresholds'
    )

    parser.add_argument(
        '--top', '-n',
        type=int,
        default=10,
        metavar='N',
        help='Show top N processes (default: %(default)s)'
    )

    parser.add_argument(
        '--sort', '-s',
        choices=['cpu', 'io_read', 'io_write', 'memory', 'pid'],
        default='cpu',
        help='Sort by metric (default: %(default)s)'
    )

    # Filters
    parser.add_argument(
        '--user', '-u',
        metavar='USERNAME',
        help='Only show processes owned by user'
    )

    parser.add_argument(
        '--command', '-c',
        metavar='PATTERN',
        help='Only show processes matching command pattern (regex)'
    )

    parser.add_argument(
        '--min-cpu',
        type=float,
        metavar='SECONDS',
        help='Minimum CPU time in seconds'
    )

    parser.add_argument(
        '--min-io-read',
        metavar='SIZE',
        help='Minimum I/O read bytes (e.g., 100MB, 1GB)'
    )

    parser.add_argument(
        '--min-io-write',
        metavar='SIZE',
        help='Minimum I/O write bytes (e.g., 100MB, 1GB)'
    )

    parser.add_argument(
        '--min-memory',
        type=int,
        metavar='KB',
        help='Minimum memory RSS in KB'
    )

    # Warning thresholds
    parser.add_argument(
        '--warn-cpu',
        type=float,
        metavar='SECONDS',
        help='Warn if CPU time exceeds seconds'
    )

    parser.add_argument(
        '--warn-io-read',
        metavar='SIZE',
        help='Warn if I/O read exceeds size (e.g., 1GB)'
    )

    parser.add_argument(
        '--warn-io-write',
        metavar='SIZE',
        help='Warn if I/O write exceeds size (e.g., 1GB)'
    )

    parser.add_argument(
        '--warn-memory',
        type=int,
        metavar='KB',
        help='Warn if memory RSS exceeds KB'
    )

    args = parser.parse_args()

    # Validate top N
    if args.top < 1:
        print("Error: --top must be at least 1", file=sys.stderr)
        sys.exit(2)

    # Parse size arguments
    min_io_read = parse_size(args.min_io_read) if args.min_io_read else None
    min_io_write = parse_size(args.min_io_write) if args.min_io_write else None
    warn_io_read = parse_size(args.warn_io_read) if args.warn_io_read else None
    warn_io_write = parse_size(args.warn_io_write) if args.warn_io_write else None

    # Validate parsed sizes
    if args.min_io_read and min_io_read is None:
        print(f"Error: Invalid size format: {args.min_io_read}", file=sys.stderr)
        sys.exit(2)
    if args.min_io_write and min_io_write is None:
        print(f"Error: Invalid size format: {args.min_io_write}", file=sys.stderr)
        sys.exit(2)
    if args.warn_io_read and warn_io_read is None:
        print(f"Error: Invalid size format: {args.warn_io_read}", file=sys.stderr)
        sys.exit(2)
    if args.warn_io_write and warn_io_write is None:
        print(f"Error: Invalid size format: {args.warn_io_write}", file=sys.stderr)
        sys.exit(2)

    # Check /proc availability
    if not os.path.exists('/proc'):
        print("Error: /proc filesystem not available", file=sys.stderr)
        sys.exit(2)

    # Gather process information
    pids = get_process_list()
    if not pids:
        print("Error: No processes found in /proc", file=sys.stderr)
        sys.exit(2)

    processes = []
    for pid in pids:
        info = get_process_info(pid)
        if info:
            processes.append(info)

    if not processes:
        print("Error: Could not read any process information", file=sys.stderr)
        print("This may require elevated privileges", file=sys.stderr)
        sys.exit(2)

    # Filter processes
    processes = filter_processes(
        processes,
        user=args.user,
        command=args.command,
        min_cpu=args.min_cpu,
        min_io_read=min_io_read,
        min_io_write=min_io_write,
        min_memory=args.min_memory,
    )

    # Sort processes
    processes = sort_processes(processes, args.sort)

    # Check warning thresholds
    warnings = check_thresholds(
        processes,
        warn_cpu=args.warn_cpu,
        warn_io_read=warn_io_read,
        warn_io_write=warn_io_write,
        warn_memory=args.warn_memory,
    )

    # Output results
    if args.format == 'json':
        output = output_json(processes, warnings, args.top, verbose=args.verbose)
    elif args.format == 'table':
        output = output_table(processes, warnings, args.top, warn_only=args.warn_only)
    else:
        output = output_plain(processes, warnings, args.top,
                              verbose=args.verbose, warn_only=args.warn_only)

    if output:
        print(output)

    # Exit based on warnings
    if warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
