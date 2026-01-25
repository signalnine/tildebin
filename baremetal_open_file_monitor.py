#!/usr/bin/env python3
"""
Monitor open file handles across the system.

Identifies processes with high file descriptor counts, detects potential FD leaks,
and finds processes holding deleted files open (common after log rotation).
Useful for troubleshooting file descriptor exhaustion, disk space issues from
deleted-but-open files, and identifying resource leaks in long-running services.

Key features:
- Lists processes with highest open file descriptor counts
- Detects processes holding deleted files open (disk space leaks)
- Identifies file types (regular files, sockets, pipes, devices)
- Shows per-process FD usage vs limits
- Supports filtering by process name, user, or minimum FD count
- Outputs in plain, JSON, or table format

Exit codes:
    0 - No issues detected (all processes within thresholds)
    1 - Warnings detected (high FD usage or deleted files held open)
    2 - Usage error or missing dependency
"""

import argparse
import os
import sys
import json
import pwd
from collections import defaultdict


def get_process_list():
    """Get list of all process IDs"""
    pids = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pids.append(int(entry))
    except OSError:
        pass
    return pids


def get_process_info(pid):
    """Get basic process information"""
    info = {
        'pid': pid,
        'name': 'unknown',
        'user': 'unknown',
        'uid': -1,
        'cmdline': ''
    }

    # Get process name from comm
    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            info['name'] = f.read().strip()
    except (IOError, OSError):
        pass

    # Get command line
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            info['cmdline'] = cmdline[:200] if cmdline else info['name']
    except (IOError, OSError):
        pass

    # Get user from status
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('Uid:'):
                    uid = int(line.split()[1])
                    info['uid'] = uid
                    try:
                        info['user'] = pwd.getpwuid(uid).pw_name
                    except KeyError:
                        info['user'] = str(uid)
                    break
    except (IOError, OSError):
        pass

    return info


def get_fd_limits(pid):
    """Get file descriptor limits for a process"""
    limits = {
        'soft': 0,
        'hard': 0
    }

    try:
        with open(f'/proc/{pid}/limits', 'r') as f:
            for line in f:
                if 'Max open files' in line:
                    parts = line.split()
                    # Format: "Max open files            1024                 1048576              files"
                    # Find the numeric values
                    nums = [p for p in parts if p.isdigit()]
                    if len(nums) >= 2:
                        limits['soft'] = int(nums[0])
                        limits['hard'] = int(nums[1])
                    break
    except (IOError, OSError):
        pass

    return limits


def get_open_files(pid):
    """Get list of open file descriptors for a process"""
    files = []
    fd_path = f'/proc/{pid}/fd'

    try:
        for fd in os.listdir(fd_path):
            try:
                link = os.readlink(os.path.join(fd_path, fd))

                # Determine file type
                file_type = 'unknown'
                deleted = False

                if link.startswith('/'):
                    if ' (deleted)' in link:
                        deleted = True
                        link = link.replace(' (deleted)', '')
                    file_type = 'file'
                elif link.startswith('socket:'):
                    file_type = 'socket'
                elif link.startswith('pipe:'):
                    file_type = 'pipe'
                elif link.startswith('anon_inode:'):
                    file_type = 'anon_inode'
                    # Extract the type (e.g., [eventfd], [eventpoll])
                    if '[' in link:
                        file_type = link.split('[')[1].rstrip(']')
                elif link.startswith('/dev/'):
                    file_type = 'device'

                files.append({
                    'fd': int(fd),
                    'path': link,
                    'type': file_type,
                    'deleted': deleted
                })
            except (OSError, ValueError):
                continue
    except OSError:
        pass

    return files


def analyze_process(pid, min_fds=10, warn_percent=80):
    """Analyze a single process for file descriptor usage"""
    proc_info = get_process_info(pid)
    limits = get_fd_limits(pid)
    open_files = get_open_files(pid)

    fd_count = len(open_files)

    # Skip if below minimum
    if fd_count < min_fds:
        return None

    # Count by type
    type_counts = defaultdict(int)
    deleted_files = []

    for f in open_files:
        type_counts[f['type']] += 1
        if f['deleted']:
            deleted_files.append(f['path'])

    # Calculate usage percentage
    usage_percent = 0
    if limits['soft'] > 0:
        usage_percent = (fd_count / limits['soft']) * 100

    # Determine if there are warnings
    warnings = []
    if usage_percent >= warn_percent:
        warnings.append(f"High FD usage: {usage_percent:.1f}% of soft limit")
    if deleted_files:
        warnings.append(f"Holding {len(deleted_files)} deleted file(s) open")

    return {
        'pid': pid,
        'name': proc_info['name'],
        'user': proc_info['user'],
        'cmdline': proc_info['cmdline'],
        'fd_count': fd_count,
        'fd_limit_soft': limits['soft'],
        'fd_limit_hard': limits['hard'],
        'usage_percent': round(usage_percent, 1),
        'type_breakdown': dict(type_counts),
        'deleted_files': deleted_files,
        'warnings': warnings
    }


def collect_data(min_fds=10, warn_percent=80, filter_name=None,
                 filter_user=None, show_deleted_only=False, top_n=None):
    """Collect open file data across all processes"""
    data = {
        'hostname': '',
        'processes': [],
        'summary': {
            'total_processes_checked': 0,
            'processes_reported': 0,
            'total_open_fds': 0,
            'processes_with_warnings': 0,
            'processes_with_deleted_files': 0,
            'total_deleted_files_held': 0
        }
    }

    # Get hostname
    try:
        with open('/proc/sys/kernel/hostname', 'r') as f:
            data['hostname'] = f.read().strip()
    except IOError:
        data['hostname'] = 'unknown'

    pids = get_process_list()

    for pid in pids:
        data['summary']['total_processes_checked'] += 1

        result = analyze_process(pid, min_fds, warn_percent)
        if result is None:
            continue

        # Apply filters
        if filter_name and filter_name.lower() not in result['name'].lower():
            continue
        if filter_user and result['user'] != filter_user:
            continue
        if show_deleted_only and not result['deleted_files']:
            continue

        data['processes'].append(result)
        data['summary']['total_open_fds'] += result['fd_count']

        if result['warnings']:
            data['summary']['processes_with_warnings'] += 1
        if result['deleted_files']:
            data['summary']['processes_with_deleted_files'] += 1
            data['summary']['total_deleted_files_held'] += len(result['deleted_files'])

    # Sort by FD count descending
    data['processes'].sort(key=lambda p: p['fd_count'], reverse=True)

    # Apply top_n limit
    if top_n and top_n > 0:
        data['processes'] = data['processes'][:top_n]

    data['summary']['processes_reported'] = len(data['processes'])

    return data


def format_output_plain(data, verbose=False):
    """Format output as plain text"""
    lines = []

    lines.append("Open File Handle Monitor")
    lines.append("=" * 70)
    lines.append(f"Host: {data['hostname']}")
    lines.append("")

    # Summary
    lines.append("Summary:")
    lines.append(f"  Processes checked: {data['summary']['total_processes_checked']}")
    lines.append(f"  Processes reported: {data['summary']['processes_reported']}")
    lines.append(f"  Total open FDs (reported): {data['summary']['total_open_fds']}")
    lines.append(f"  Processes with warnings: {data['summary']['processes_with_warnings']}")
    lines.append(f"  Processes holding deleted files: {data['summary']['processes_with_deleted_files']}")
    lines.append(f"  Total deleted files held open: {data['summary']['total_deleted_files_held']}")
    lines.append("")

    if not data['processes']:
        lines.append("No processes match the criteria.")
        return '\n'.join(lines)

    lines.append("Process Details:")
    lines.append("-" * 70)

    for proc in data['processes']:
        # Basic info line
        usage_str = f"{proc['usage_percent']}%" if proc['fd_limit_soft'] > 0 else "N/A"
        lines.append(f"{proc['name']} (PID {proc['pid']}) - {proc['user']}")
        lines.append(f"  Open FDs: {proc['fd_count']} / {proc['fd_limit_soft']} ({usage_str})")

        if verbose:
            # Type breakdown
            types = proc['type_breakdown']
            type_str = ', '.join(f"{k}:{v}" for k, v in sorted(types.items()))
            lines.append(f"  Types: {type_str}")
            lines.append(f"  Command: {proc['cmdline'][:60]}...")

        # Warnings
        for warning in proc['warnings']:
            lines.append(f"  [!] {warning}")

        # Deleted files (show first few)
        if proc['deleted_files']:
            for df in proc['deleted_files'][:3]:
                lines.append(f"      Deleted: {df}")
            if len(proc['deleted_files']) > 3:
                lines.append(f"      ... and {len(proc['deleted_files']) - 3} more")

        lines.append("")

    return '\n'.join(lines)


def format_output_table(data):
    """Format output as table"""
    lines = []

    header = f"{'PID':<8} {'Name':<20} {'User':<12} {'FDs':<8} {'Limit':<8} {'Usage%':<8} {'Warnings'}"
    lines.append(header)
    lines.append("-" * 90)

    for proc in data['processes']:
        usage_str = f"{proc['usage_percent']}%" if proc['fd_limit_soft'] > 0 else "N/A"
        warn_count = len(proc['warnings'])
        warn_str = f"{warn_count} warning(s)" if warn_count else "ok"

        lines.append(f"{proc['pid']:<8} {proc['name'][:20]:<20} {proc['user'][:12]:<12} "
                    f"{proc['fd_count']:<8} {proc['fd_limit_soft']:<8} {usage_str:<8} {warn_str}")

    return '\n'.join(lines)


def format_output_json(data):
    """Format output as JSON"""
    return json.dumps(data, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor open file handles across the system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         # Show top processes by open FD count
  %(prog)s --min-fds 100           # Only show processes with 100+ FDs
  %(prog)s --deleted-only          # Only show processes holding deleted files
  %(prog)s --name nginx            # Filter by process name
  %(prog)s --user www-data         # Filter by user
  %(prog)s --top 10 --format table # Top 10 in table format
  %(prog)s --warn-percent 50       # Warn at 50%% FD usage

Common Use Cases:
  - Find processes holding deleted log files (disk space leak)
  - Identify processes approaching FD limits
  - Debug "too many open files" errors
  - Monitor long-running services for FD leaks
"""
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
        help="Show detailed information including file type breakdown"
    )

    parser.add_argument(
        "--min-fds",
        type=int,
        default=10,
        metavar="N",
        help="Minimum open FD count to report (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-percent",
        type=int,
        default=80,
        metavar="PCT",
        help="Warn when FD usage exceeds this percentage (default: %(default)s)"
    )

    parser.add_argument(
        "--top",
        type=int,
        default=20,
        metavar="N",
        help="Show only top N processes by FD count (default: %(default)s, 0=all)"
    )

    parser.add_argument(
        "--name",
        metavar="PATTERN",
        help="Filter by process name (case-insensitive substring match)"
    )

    parser.add_argument(
        "--user",
        metavar="USER",
        help="Filter by username"
    )

    parser.add_argument(
        "--deleted-only",
        action="store_true",
        help="Only show processes holding deleted files open"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show processes with warnings"
    )

    args = parser.parse_args()

    # Check for /proc filesystem
    if not os.path.exists('/proc'):
        print("Error: /proc filesystem not available", file=sys.stderr)
        print("This tool requires a Linux system with procfs mounted", file=sys.stderr)
        sys.exit(2)

    # Collect data
    data = collect_data(
        min_fds=args.min_fds,
        warn_percent=args.warn_percent,
        filter_name=args.name,
        filter_user=args.user,
        show_deleted_only=args.deleted_only,
        top_n=args.top if args.top > 0 else None
    )

    # Filter to warn-only if requested
    if args.warn_only:
        data['processes'] = [p for p in data['processes'] if p['warnings']]
        data['summary']['processes_reported'] = len(data['processes'])

    # Format output
    if args.format == "json":
        output = format_output_json(data)
    elif args.format == "table":
        output = format_output_table(data)
    else:
        output = format_output_plain(data, args.verbose)

    print(output)

    # Exit code based on warnings
    has_warnings = data['summary']['processes_with_warnings'] > 0
    has_deleted = data['summary']['processes_with_deleted_files'] > 0
    sys.exit(1 if (has_warnings or has_deleted) else 0)


if __name__ == "__main__":
    main()
