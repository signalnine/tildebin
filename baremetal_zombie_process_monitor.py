#!/usr/bin/env python3
"""
Monitor zombie (defunct) processes on baremetal systems.

Zombie processes are processes that have completed execution but still have
entries in the process table. While individual zombies consume minimal resources,
large numbers indicate parent processes not properly reaping child processes,
which can lead to PID exhaustion and process table bloat.

Features:
- Detect all zombie processes system-wide
- Identify parent processes responsible for zombies
- Track zombie age (time since creation)
- Group zombies by parent for easy identification of problem processes
- Multiple output formats (plain, JSON, table)

Exit codes:
    0 - No zombie processes detected
    1 - Zombie processes found (warning)
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import pwd
from datetime import datetime
from collections import defaultdict


def get_boot_time():
    """Get system boot time in seconds since epoch."""
    try:
        with open('/proc/stat', 'r') as f:
            for line in f:
                if line.startswith('btime'):
                    return int(line.split()[1])
    except (IOError, ValueError, IndexError):
        pass
    return None


def get_clock_ticks():
    """Get clock ticks per second (usually 100)."""
    try:
        return os.sysconf('SC_CLK_TCK')
    except (ValueError, OSError):
        return 100  # Common default


def get_process_info(pid):
    """
    Get detailed information about a process.

    Args:
        pid: Process ID

    Returns:
        dict: Process info or None if unavailable
    """
    try:
        # Read stat file for process state and timing
        with open(f'/proc/{pid}/stat', 'r') as f:
            stat_line = f.read()

        # Parse stat file - handle process names with spaces/parentheses
        # Format: pid (comm) state ppid ...
        first_paren = stat_line.index('(')
        last_paren = stat_line.rindex(')')

        name = stat_line[first_paren + 1:last_paren]
        rest = stat_line[last_paren + 2:].split()

        state = rest[0]
        ppid = int(rest[1])
        starttime = int(rest[19])  # Start time in clock ticks since boot

        # Get process owner
        stat_info = os.stat(f'/proc/{pid}')
        try:
            username = pwd.getpwuid(stat_info.st_uid).pw_name
        except KeyError:
            username = str(stat_info.st_uid)

        # Calculate process age
        boot_time = get_boot_time()
        clock_ticks = get_clock_ticks()

        age_seconds = None
        start_datetime = None
        if boot_time and clock_ticks:
            start_epoch = boot_time + (starttime / clock_ticks)
            start_datetime = datetime.fromtimestamp(start_epoch)
            age_seconds = int(datetime.now().timestamp() - start_epoch)

        # Try to get command line (usually empty for zombies)
        cmdline = ''
        try:
            with open(f'/proc/{pid}/cmdline', 'r') as f:
                cmdline = f.read().replace('\x00', ' ').strip()
        except IOError:
            pass

        return {
            'pid': pid,
            'name': name,
            'state': state,
            'ppid': ppid,
            'user': username,
            'cmdline': cmdline if cmdline else f'[{name}]',
            'age_seconds': age_seconds,
            'start_time': start_datetime.isoformat() if start_datetime else None
        }

    except (IOError, OSError, ValueError, IndexError):
        return None


def get_parent_name(ppid):
    """Get the name of a parent process."""
    try:
        with open(f'/proc/{ppid}/comm', 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return '<unknown>'


def format_age(seconds):
    """Format age in human-readable format."""
    if seconds is None:
        return 'unknown'

    if seconds < 60:
        return f'{seconds}s'
    elif seconds < 3600:
        return f'{seconds // 60}m {seconds % 60}s'
    elif seconds < 86400:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f'{hours}h {mins}m'
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f'{days}d {hours}h'


def find_zombie_processes():
    """
    Find all zombie processes in the system.

    Returns:
        list: List of zombie process info dicts
    """
    zombies = []

    try:
        pids = [int(d) for d in os.listdir('/proc') if d.isdigit()]
    except OSError as e:
        print(f"Error: Could not list /proc: {e}", file=sys.stderr)
        return zombies

    for pid in pids:
        info = get_process_info(pid)
        if info and info['state'] == 'Z':
            # Add parent process name
            info['parent_name'] = get_parent_name(info['ppid'])
            zombies.append(info)

    return zombies


def group_by_parent(zombies):
    """
    Group zombie processes by their parent.

    Args:
        zombies: List of zombie process info dicts

    Returns:
        dict: Mapping of (ppid, parent_name) to list of zombie children
    """
    groups = defaultdict(list)
    for zombie in zombies:
        key = (zombie['ppid'], zombie['parent_name'])
        groups[key].append(zombie)
    return dict(groups)


def output_plain(zombies, verbose, group_output):
    """Output in plain text format."""
    if not zombies:
        print("No zombie processes detected")
        return

    print(f"Found {len(zombies)} zombie process(es)")
    print()

    if group_output:
        groups = group_by_parent(zombies)
        print(f"Grouped by {len(groups)} parent process(es):")
        print()

        for (ppid, parent_name), children in sorted(groups.items(), key=lambda x: -len(x[1])):
            print(f"Parent: {parent_name} (PID {ppid}) - {len(children)} zombie(s)")
            for z in children:
                age_str = format_age(z['age_seconds'])
                print(f"  └─ PID {z['pid']}: {z['name']} (age: {age_str}, user: {z['user']})")
            print()
    else:
        print(f"{'PID':<8} {'Name':<16} {'PPID':<8} {'Parent':<16} {'User':<12} {'Age':<10}")
        print("-" * 78)

        for z in sorted(zombies, key=lambda x: x['pid']):
            age_str = format_age(z['age_seconds'])
            print(f"{z['pid']:<8} {z['name']:<16} {z['ppid']:<8} "
                  f"{z['parent_name']:<16} {z['user']:<12} {age_str:<10}")

    if verbose:
        print()
        print("Recommendations:")
        print("- Investigate parent processes not reaping children")
        print("- Check for signal handling issues in parent processes")
        print("- Consider restarting problematic parent processes")


def output_json(zombies):
    """Output in JSON format."""
    groups = group_by_parent(zombies)

    output = {
        'total_zombies': len(zombies),
        'parent_count': len(groups),
        'zombies': zombies,
        'by_parent': {
            f"{ppid}:{parent_name}": {
                'ppid': ppid,
                'parent_name': parent_name,
                'zombie_count': len(children),
                'zombies': children
            }
            for (ppid, parent_name), children in groups.items()
        }
    }
    print(json.dumps(output, indent=2, default=str))


def output_table(zombies, verbose, group_output):
    """Output in table format."""
    if not zombies:
        print("┌" + "─" * 50 + "┐")
        print("│" + " No zombie processes detected".center(50) + "│")
        print("└" + "─" * 50 + "┘")
        return

    groups = group_by_parent(zombies)

    print("┌" + "─" * 70 + "┐")
    print("│" + f" Zombie Process Report: {len(zombies)} zombie(s) ".center(70) + "│")
    print("├" + "─" * 70 + "┤")

    if group_output:
        for (ppid, parent_name), children in sorted(groups.items(), key=lambda x: -len(x[1])):
            print(f"│ Parent: {parent_name} (PID {ppid})".ljust(70) + " │")
            print(f"│ {'─' * 68} │")
            for z in children:
                age_str = format_age(z['age_seconds'])
                line = f"   PID {z['pid']}: {z['name'][:20]} | Age: {age_str} | User: {z['user']}"
                print(f"│ {line:<68} │")
            print("├" + "─" * 70 + "┤")
    else:
        header = f"{'PID':<7} {'Name':<14} {'PPID':<7} {'Parent':<14} {'User':<10} {'Age':<10}"
        print(f"│ {header:<68} │")
        print("├" + "─" * 70 + "┤")

        for z in sorted(zombies, key=lambda x: x['pid']):
            age_str = format_age(z['age_seconds'])
            line = f"{z['pid']:<7} {z['name'][:14]:<14} {z['ppid']:<7} {z['parent_name'][:14]:<14} {z['user'][:10]:<10} {age_str:<10}"
            print(f"│ {line:<68} │")

    print("└" + "─" * 70 + "┘")

    if verbose:
        print()
        print("To investigate: ps -ef | grep defunct")
        print("To find parent: ps -p <PPID> -o comm=")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor zombie (defunct) processes on baremetal systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check for zombie processes
  baremetal_zombie_process_monitor.py

  # Group output by parent process
  baremetal_zombie_process_monitor.py --group

  # JSON output for scripting
  baremetal_zombie_process_monitor.py --format json

  # Verbose table output
  baremetal_zombie_process_monitor.py --format table --verbose

  # Filter by minimum age (seconds)
  baremetal_zombie_process_monitor.py --min-age 3600

Exit codes:
  0 - No zombie processes detected
  1 - Zombie processes found (warning)
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
        '-g', '--group',
        action='store_true',
        help='Group zombies by parent process'
    )

    parser.add_argument(
        '--min-age',
        type=int,
        default=0,
        help='Only show zombies older than N seconds (default: 0)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information and recommendations'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if zombies are found'
    )

    args = parser.parse_args()

    # Find zombie processes
    zombies = find_zombie_processes()

    # Filter by age if specified
    if args.min_age > 0:
        zombies = [z for z in zombies if z['age_seconds'] and z['age_seconds'] >= args.min_age]

    # Handle warn-only mode
    if args.warn_only and not zombies:
        sys.exit(0)

    # Output results
    if args.format == 'json':
        output_json(zombies)
    elif args.format == 'table':
        output_table(zombies, args.verbose, args.group)
    else:  # plain
        output_plain(zombies, args.verbose, args.group)

    # Exit code based on findings
    sys.exit(1 if zombies else 0)


if __name__ == '__main__':
    main()
