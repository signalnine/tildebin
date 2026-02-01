#!/usr/bin/env python3
"""
Monitor file descriptor usage across system and per-process.

This script monitors file descriptor (FD) consumption to prevent resource exhaustion
and identify processes approaching their limits. Useful for detecting FD leaks and
preventing "too many open files" errors in production environments.

Features:
- System-wide FD usage vs. limits
- Per-process FD consumption analysis
- Detection of processes approaching ulimits (>80% usage)
- Top FD consumers identification
- Filter by process name or user
- Multiple output formats (plain, JSON, table)

Exit codes:
    0 - No issues detected (all processes below 80% FD limit)
    1 - Warnings found (processes using >80% of FD limit)
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import pwd
import json
from collections import defaultdict


def get_system_fd_stats():
    """
    Get system-wide file descriptor statistics.

    Returns:
        dict: System FD stats with allocated, free, and max values
    """
    try:
        with open('/proc/sys/fs/file-nr', 'r') as f:
            line = f.read().strip()
            parts = line.split()
            if len(parts) >= 3:
                allocated = int(parts[0])
                # parts[1] is allocated-but-unused (usually 0 in modern kernels)
                max_fds = int(parts[2])
                free = max_fds - allocated
                return {
                    'allocated': allocated,
                    'free': free,
                    'max': max_fds,
                    'usage_percent': round((allocated / max_fds) * 100, 2) if max_fds > 0 else 0
                }
    except (IOError, ValueError) as e:
        print(f"Warning: Could not read system FD stats: {e}", file=sys.stderr)

    return None


def get_process_fd_info(pid):
    """
    Get file descriptor info for a specific process.

    Args:
        pid: Process ID

    Returns:
        dict: Process FD info or None if unavailable
    """
    try:
        # Get process name
        with open(f'/proc/{pid}/comm', 'r') as f:
            name = f.read().strip()

        # Get FD limit from limits file
        soft_limit = None
        hard_limit = None
        with open(f'/proc/{pid}/limits', 'r') as f:
            for line in f:
                if 'open files' in line.lower():
                    parts = line.split()
                    # Format: "Max open files    1024    4096    files"
                    if len(parts) >= 5:
                        soft_limit = parts[3]
                        hard_limit = parts[4]
                        # Handle "unlimited"
                        if soft_limit != 'unlimited':
                            soft_limit = int(soft_limit)
                        if hard_limit != 'unlimited':
                            hard_limit = int(hard_limit)
                    break

        # Count actual FDs
        fd_dir = f'/proc/{pid}/fd'
        if os.path.exists(fd_dir):
            try:
                fd_count = len(os.listdir(fd_dir))
            except PermissionError:
                # Can't read FDs for this process
                return None
        else:
            return None

        # Get process owner
        stat_info = os.stat(f'/proc/{pid}')
        try:
            username = pwd.getpwuid(stat_info.st_uid).pw_name
        except KeyError:
            username = str(stat_info.st_uid)

        # Calculate usage percentage
        usage_percent = 0
        if soft_limit and soft_limit != 'unlimited' and soft_limit > 0:
            usage_percent = round((fd_count / soft_limit) * 100, 2)

        return {
            'pid': pid,
            'name': name,
            'user': username,
            'fd_count': fd_count,
            'soft_limit': soft_limit,
            'hard_limit': hard_limit,
            'usage_percent': usage_percent
        }

    except (IOError, OSError, ValueError):
        return None


def get_all_process_fds(filter_name=None, filter_user=None, threshold=80.0):
    """
    Get FD info for all processes.

    Args:
        filter_name: Only include processes matching this name
        filter_user: Only include processes owned by this user
        threshold: Only include processes above this usage percentage

    Returns:
        list: List of process FD info dicts
    """
    processes = []

    try:
        pids = [int(d) for d in os.listdir('/proc') if d.isdigit()]
    except OSError as e:
        print(f"Error: Could not list /proc: {e}", file=sys.stderr)
        return processes

    for pid in pids:
        info = get_process_fd_info(pid)
        if info:
            # Apply filters
            if filter_name and filter_name.lower() not in info['name'].lower():
                continue
            if filter_user and filter_user != info['user']:
                continue
            if threshold and info['usage_percent'] < threshold:
                continue

            processes.append(info)

    return processes


def output_plain(system_stats, processes, show_all, verbose):
    """Output in plain text format."""
    if system_stats:
        print(f"System FD Usage: {system_stats['allocated']}/{system_stats['max']} ({system_stats['usage_percent']}%)")
        print(f"System FDs Free: {system_stats['free']}")
        print()

    if not processes:
        if show_all or verbose:
            print("No processes found matching criteria")
        else:
            print("No processes using >80% of FD limit")
        return

    # Sort by usage percentage descending
    processes.sort(key=lambda x: x['usage_percent'], reverse=True)

    print(f"Processes with High FD Usage (>80% of limit):")
    print(f"{'PID':<8} {'User':<12} {'Name':<20} {'FDs':<8} {'Limit':<10} {'Usage':<8}")
    print("-" * 76)

    for proc in processes:
        limit_str = str(proc['soft_limit']) if proc['soft_limit'] != 'unlimited' else 'unlimited'
        print(f"{proc['pid']:<8} {proc['user']:<12} {proc['name']:<20} "
              f"{proc['fd_count']:<8} {limit_str:<10} {proc['usage_percent']:<8}%")

    if verbose:
        print(f"\nTotal processes checked: {len(processes)}")


def output_json(system_stats, processes):
    """Output in JSON format."""
    output = {
        'system': system_stats,
        'processes': processes
    }
    print(json.dumps(output, indent=2))


def output_table(system_stats, processes, show_all, verbose):
    """Output in table format."""
    # Similar to plain but with more visual formatting
    if system_stats:
        print("=" * 80)
        print(f"{'System-Wide File Descriptor Statistics':^80}")
        print("=" * 80)
        print(f"  Allocated: {system_stats['allocated']:>10}")
        print(f"  Free:      {system_stats['free']:>10}")
        print(f"  Maximum:   {system_stats['max']:>10}")
        print(f"  Usage:     {system_stats['usage_percent']:>9.2f}%")
        print("=" * 80)
        print()

    if not processes:
        if show_all or verbose:
            print("│ No processes found matching criteria")
        else:
            print("│ No processes using >80% of FD limit (healthy)")
        return

    processes.sort(key=lambda x: x['usage_percent'], reverse=True)

    print("┌" + "─" * 78 + "┐")
    print("│ " + f"{'Processes with High File Descriptor Usage':^76}" + " │")
    print("├" + "─" * 78 + "┤")
    print(f"│ {'PID':<6} │ {'User':<10} │ {'Name':<18} │ {'FDs':<6} │ {'Limit':<8} │ {'Usage':<6} │")
    print("├" + "─" * 78 + "┤")

    for proc in processes:
        limit_str = str(proc['soft_limit']) if proc['soft_limit'] != 'unlimited' else 'unlim'
        print(f"│ {proc['pid']:<6} │ {proc['user']:<10} │ {proc['name']:<18} │ "
              f"{proc['fd_count']:<6} │ {limit_str:<8} │ {proc['usage_percent']:<6.1f}% │")

    print("└" + "─" * 78 + "┘")

    if verbose:
        print(f"\nTotal processes shown: {len(processes)}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor file descriptor usage across system and per-process",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show all processes using >80%% of FD limit
  baremetal_fd_limit_monitor.py

  # Show all processes with FDs (no threshold)
  baremetal_fd_limit_monitor.py --all

  # Show only processes matching name
  baremetal_fd_limit_monitor.py --name nginx

  # Show only processes owned by user
  baremetal_fd_limit_monitor.py --user www-data

  # Set custom warning threshold
  baremetal_fd_limit_monitor.py --threshold 70

  # JSON output for scripting
  baremetal_fd_limit_monitor.py --format json

  # Verbose table output
  baremetal_fd_limit_monitor.py --format table --verbose

Exit codes:
  0 - No issues (all processes below threshold)
  1 - Warnings (processes above threshold)
  2 - Usage error or missing dependencies
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-a', '--all',
        action='store_true',
        help='Show all processes, not just those above threshold'
    )

    parser.add_argument(
        '-t', '--threshold',
        type=float,
        default=80.0,
        help='Warning threshold percentage (default: %(default)s)'
    )

    parser.add_argument(
        '-n', '--name',
        help='Filter by process name (case-insensitive substring match)'
    )

    parser.add_argument(
        '-u', '--user',
        help='Filter by process owner username'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    parser.add_argument(
        '--warn-only',
        action='store_true',
        help='Only show processes above threshold (same as default)'
    )

    args = parser.parse_args()

    # Validate threshold
    if args.threshold < 0 or args.threshold > 100:
        print("Error: Threshold must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    # Get system stats
    system_stats = get_system_fd_stats()

    # Get process stats
    threshold = None if args.all else args.threshold
    processes = get_all_process_fds(
        filter_name=args.name,
        filter_user=args.user,
        threshold=threshold
    )

    # Output results
    if args.format == 'json':
        output_json(system_stats, processes)
    elif args.format == 'table':
        output_table(system_stats, processes, args.all, args.verbose)
    else:  # plain
        output_plain(system_stats, processes, args.all, args.verbose)

    # Exit code based on findings
    has_warnings = any(p['usage_percent'] >= args.threshold for p in processes)
    sys.exit(1 if has_warnings else 0)


if __name__ == '__main__':
    main()
