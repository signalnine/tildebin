#!/usr/bin/env python3
"""
Monitor processes in uninterruptible sleep (D-state) on baremetal systems.

Processes in uninterruptible sleep (state 'D') are waiting for I/O or holding
kernel locks. While brief D-state is normal, processes stuck in D-state for
extended periods indicate:
- Storage subsystem issues (failing disks, hung NFS mounts)
- Kernel lock contention
- Driver bugs or hardware failures
- Network filesystem hangs

This script detects D-state processes and helps identify the root cause before
they lead to cascading system failures.

Features:
- Detect all processes in uninterruptible sleep
- Track time spent in D-state (via process start time)
- Identify wait channel (kernel function where process is blocked)
- Correlate with I/O or mount information when possible
- Multiple output formats (plain, JSON, table)

Exit codes:
    0 - No D-state processes detected (or all below threshold)
    1 - D-state processes found (warning)
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


def get_wait_channel(pid):
    """
    Get the kernel wait channel for a process.

    The wait channel indicates which kernel function the process is blocked on.
    This helps diagnose what the process is waiting for.
    """
    try:
        with open(f'/proc/{pid}/wchan', 'r') as f:
            wchan = f.read().strip()
            return wchan if wchan and wchan != '0' else None
    except (IOError, OSError):
        return None


def get_io_stats(pid):
    """
    Get I/O statistics for a process.

    Returns dict with read/write bytes if available.
    """
    try:
        with open(f'/proc/{pid}/io', 'r') as f:
            stats = {}
            for line in f:
                key, value = line.strip().split(': ')
                stats[key] = int(value)
            return {
                'read_bytes': stats.get('read_bytes', 0),
                'write_bytes': stats.get('write_bytes', 0),
                'syscr': stats.get('syscr', 0),  # read syscalls
                'syscw': stats.get('syscw', 0),  # write syscalls
            }
    except (IOError, OSError, ValueError, KeyError):
        return None


def get_cwd(pid):
    """Get the current working directory of a process."""
    try:
        return os.readlink(f'/proc/{pid}/cwd')
    except (IOError, OSError):
        return None


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

        # Get command line
        cmdline = ''
        try:
            with open(f'/proc/{pid}/cmdline', 'r') as f:
                cmdline = f.read().replace('\x00', ' ').strip()
        except IOError:
            pass

        # Get wait channel (what the process is blocked on)
        wchan = get_wait_channel(pid)

        # Get I/O stats
        io_stats = get_io_stats(pid)

        # Get current working directory
        cwd = get_cwd(pid)

        return {
            'pid': pid,
            'name': name,
            'state': state,
            'ppid': ppid,
            'user': username,
            'cmdline': cmdline if cmdline else f'[{name}]',
            'age_seconds': age_seconds,
            'start_time': start_datetime.isoformat() if start_datetime else None,
            'wait_channel': wchan,
            'io_stats': io_stats,
            'cwd': cwd
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


def format_bytes(n):
    """Format bytes in human-readable format."""
    if n is None:
        return 'N/A'
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"


def categorize_wait_channel(wchan):
    """
    Categorize wait channel to help identify the type of blocking.

    Returns a tuple of (category, description).
    """
    if wchan is None:
        return ('unknown', 'Unknown wait state')

    wchan_lower = wchan.lower()

    # NFS-related waits
    if 'nfs' in wchan_lower or 'rpc' in wchan_lower:
        return ('nfs', 'NFS/RPC operation')

    # Disk I/O waits
    if any(x in wchan_lower for x in ['blk', 'bio', 'io_schedule', 'wait_on_page']):
        return ('disk_io', 'Disk I/O operation')

    # Filesystem waits
    if any(x in wchan_lower for x in ['ext4', 'xfs', 'btrfs', 'jbd2']):
        return ('filesystem', 'Filesystem operation')

    # Lock waits
    if any(x in wchan_lower for x in ['mutex', 'semaphore', 'rwsem', 'lock']):
        return ('lock', 'Kernel lock contention')

    # Memory waits
    if any(x in wchan_lower for x in ['page', 'mem', 'swap', 'reclaim']):
        return ('memory', 'Memory/page operation')

    # Network waits (non-NFS)
    if any(x in wchan_lower for x in ['sock', 'tcp', 'inet', 'net']):
        return ('network', 'Network operation')

    # SCSI/storage driver waits
    if any(x in wchan_lower for x in ['scsi', 'ata', 'sd_', 'nvme']):
        return ('storage_driver', 'Storage driver operation')

    return ('other', f'Kernel function: {wchan}')


def find_dstate_processes():
    """
    Find all processes in uninterruptible sleep (D-state).

    Returns:
        list: List of D-state process info dicts
    """
    dstate_procs = []

    try:
        pids = [int(d) for d in os.listdir('/proc') if d.isdigit()]
    except OSError as e:
        print(f"Error: Could not list /proc: {e}", file=sys.stderr)
        return dstate_procs

    for pid in pids:
        info = get_process_info(pid)
        if info and info['state'] == 'D':
            # Add parent process name
            info['parent_name'] = get_parent_name(info['ppid'])
            # Categorize the wait channel
            category, description = categorize_wait_channel(info['wait_channel'])
            info['wait_category'] = category
            info['wait_description'] = description
            dstate_procs.append(info)

    return dstate_procs


def group_by_wait_category(procs):
    """
    Group D-state processes by their wait category.

    Args:
        procs: List of D-state process info dicts

    Returns:
        dict: Mapping of category to list of processes
    """
    groups = defaultdict(list)
    for proc in procs:
        groups[proc['wait_category']].append(proc)
    return dict(groups)


def output_plain(procs, verbose, group_output):
    """Output in plain text format."""
    if not procs:
        print("No processes in uninterruptible sleep (D-state) detected")
        return

    print(f"Found {len(procs)} process(es) in uninterruptible sleep (D-state)")
    print()

    if group_output:
        groups = group_by_wait_category(procs)
        print(f"Grouped by {len(groups)} wait category(ies):")
        print()

        for category, members in sorted(groups.items(), key=lambda x: -len(x[1])):
            desc = members[0]['wait_description'] if members else category
            print(f"Category: {category.upper()} ({desc}) - {len(members)} process(es)")
            for p in members:
                age_str = format_age(p['age_seconds'])
                wchan = p['wait_channel'] or 'unknown'
                print(f"  └─ PID {p['pid']}: {p['name']} (age: {age_str}, wchan: {wchan})")
                if verbose and p['cmdline']:
                    print(f"     Command: {p['cmdline'][:60]}...")
            print()
    else:
        print(f"{'PID':<8} {'Name':<16} {'User':<10} {'Age':<10} {'Wait Channel':<20}")
        print("-" * 70)

        for p in sorted(procs, key=lambda x: -(x['age_seconds'] or 0)):
            age_str = format_age(p['age_seconds'])
            wchan = (p['wait_channel'] or 'unknown')[:20]
            print(f"{p['pid']:<8} {p['name'][:16]:<16} {p['user'][:10]:<10} "
                  f"{age_str:<10} {wchan:<20}")

    if verbose:
        print()
        print("Wait Category Summary:")
        groups = group_by_wait_category(procs)
        for category, members in sorted(groups.items(), key=lambda x: -len(x[1])):
            print(f"  {category}: {len(members)} process(es)")

        print()
        print("Recommendations:")
        if 'nfs' in groups:
            print("- NFS hangs detected: Check NFS server and network connectivity")
            print("  Try: showmount -e <nfs-server>, mount | grep nfs")
        if 'disk_io' in groups:
            print("- Disk I/O blocks detected: Check disk health and I/O scheduler")
            print("  Try: iostat -x 1, smartctl -a /dev/sdX")
        if 'lock' in groups:
            print("- Lock contention detected: May indicate kernel or driver issues")
            print("  Try: dmesg | tail -50, check for kernel bugs")
        if 'storage_driver' in groups:
            print("- Storage driver issues: Check dmesg for driver errors")
            print("  Try: dmesg | grep -i 'error\\|fail\\|timeout'")


def output_json(procs):
    """Output in JSON format."""
    groups = group_by_wait_category(procs)

    output = {
        'total_dstate': len(procs),
        'category_count': len(groups),
        'processes': procs,
        'by_category': {
            category: {
                'count': len(members),
                'description': members[0]['wait_description'] if members else category,
                'processes': members
            }
            for category, members in groups.items()
        }
    }
    print(json.dumps(output, indent=2, default=str))


def output_table(procs, verbose, group_output):
    """Output in table format."""
    if not procs:
        print("┌" + "─" * 58 + "┐")
        print("│" + " No D-state processes detected".center(58) + "│")
        print("└" + "─" * 58 + "┘")
        return

    groups = group_by_wait_category(procs)

    print("┌" + "─" * 74 + "┐")
    print("│" + f" Uninterruptible Sleep (D-state) Report: {len(procs)} process(es) ".center(74) + "│")
    print("├" + "─" * 74 + "┤")

    if group_output:
        for category, members in sorted(groups.items(), key=lambda x: -len(x[1])):
            desc = members[0]['wait_description'] if members else category
            print(f"│ {category.upper()}: {desc}".ljust(74) + " │")
            print(f"│ {'─' * 72} │")
            for p in members:
                age_str = format_age(p['age_seconds'])
                wchan = (p['wait_channel'] or 'unknown')[:25]
                line = f"   PID {p['pid']}: {p['name'][:15]} | Age: {age_str} | {wchan}"
                print(f"│ {line:<72} │")
            print("├" + "─" * 74 + "┤")
    else:
        header = f"{'PID':<7} {'Name':<14} {'User':<9} {'Age':<9} {'Wait Channel':<25}"
        print(f"│ {header:<72} │")
        print("├" + "─" * 74 + "┤")

        for p in sorted(procs, key=lambda x: -(x['age_seconds'] or 0)):
            age_str = format_age(p['age_seconds'])
            wchan = (p['wait_channel'] or 'unknown')[:25]
            line = f"{p['pid']:<7} {p['name'][:14]:<14} {p['user'][:9]:<9} {age_str:<9} {wchan:<25}"
            print(f"│ {line:<72} │")

    print("└" + "─" * 74 + "┘")

    if verbose:
        print()
        print("Common wait channels and their meanings:")
        print("  blk_* / io_schedule - Waiting for block device I/O")
        print("  nfs_* / rpc_*       - Waiting for NFS/RPC operations")
        print("  mutex_* / rwsem_*   - Waiting for kernel locks")
        print("  wait_on_page_*      - Waiting for page I/O completion")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor processes in uninterruptible sleep (D-state) on baremetal systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check for D-state processes
  baremetal_uninterruptible_process_monitor.py

  # Group output by wait category
  baremetal_uninterruptible_process_monitor.py --group

  # JSON output for scripting
  baremetal_uninterruptible_process_monitor.py --format json

  # Only show processes stuck for more than 30 seconds
  baremetal_uninterruptible_process_monitor.py --min-age 30

  # Verbose table output with recommendations
  baremetal_uninterruptible_process_monitor.py --format table --verbose

  # Silent unless problems found
  baremetal_uninterruptible_process_monitor.py --warn-only

Exit codes:
  0 - No D-state processes detected (or all below threshold)
  1 - D-state processes found (warning)
  2 - Usage error or missing dependencies

Common wait channels:
  blk_*, io_schedule   - Block device I/O (disk operations)
  nfs_*, rpc_*         - NFS/RPC operations (network storage)
  mutex_*, rwsem_*     - Kernel lock contention
  wait_on_page_*       - Memory page I/O operations
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
        help='Group processes by wait category'
    )

    parser.add_argument(
        '--min-age',
        type=int,
        default=0,
        help='Only show processes in D-state longer than N seconds (default: 0)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information and recommendations'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if D-state processes are found'
    )

    args = parser.parse_args()

    # Find D-state processes
    dstate_procs = find_dstate_processes()

    # Filter by age if specified
    if args.min_age > 0:
        dstate_procs = [p for p in dstate_procs
                        if p['age_seconds'] and p['age_seconds'] >= args.min_age]

    # Handle warn-only mode
    if args.warn_only and not dstate_procs:
        sys.exit(0)

    # Output results
    if args.format == 'json':
        output_json(dstate_procs)
    elif args.format == 'table':
        output_table(dstate_procs, args.verbose, args.group)
    else:  # plain
        output_plain(dstate_procs, args.verbose, args.group)

    # Exit code based on findings
    sys.exit(1 if dstate_procs else 0)


if __name__ == '__main__':
    main()
