#!/usr/bin/env python3
"""
Monitor per-process swap usage to identify processes contributing to swap pressure.

When system swap usage is high, administrators need to know which processes
are swapped out to make informed decisions about restarts, memory allocation,
or workload distribution. This script identifies the top swap consumers by
reading VmSwap from /proc/[pid]/status.

Key features:
- Lists processes sorted by swap usage
- Shows top N swap consumers
- Identifies processes with high swap-to-RSS ratio (thrashing candidates)
- Supports filtering by user or process name
- Useful for troubleshooting memory pressure situations

Exit codes:
    0 - No significant per-process swap usage detected
    1 - Processes with high swap usage found
    2 - Usage error or /proc filesystem not available
"""

import argparse
import json
import os
import pwd
import sys
from typing import Any, Dict, List, Optional


def read_proc_file(path: str) -> Optional[str]:
    """Read a /proc file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (OSError, IOError, PermissionError):
        return None


def parse_status_value(value: str) -> int:
    """Parse a value from /proc/[pid]/status, handling 'kB' suffix."""
    parts = value.strip().split()
    if parts:
        try:
            return int(parts[0])
        except ValueError:
            return 0
    return 0


def get_process_swap_info(pid: int) -> Optional[Dict[str, Any]]:
    """Get swap and memory information for a process.

    Args:
        pid: Process ID to examine

    Returns:
        Dictionary with process swap info or None if process is inaccessible
    """
    status_path = f'/proc/{pid}/status'
    comm_path = f'/proc/{pid}/comm'
    cmdline_path = f'/proc/{pid}/cmdline'

    status_content = read_proc_file(status_path)
    if not status_content:
        return None

    # Parse status file
    info = {
        'pid': pid,
        'name': 'unknown',
        'cmdline': '',
        'user': 'unknown',
        'uid': -1,
        'vm_swap_kb': 0,
        'vm_rss_kb': 0,
        'vm_size_kb': 0,
    }

    for line in status_content.split('\n'):
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()

        if key == 'Name':
            info['name'] = value.strip()
        elif key == 'Uid':
            parts = value.split()
            if parts:
                try:
                    info['uid'] = int(parts[0])
                except ValueError:
                    pass
        elif key == 'VmSwap':
            info['vm_swap_kb'] = parse_status_value(value)
        elif key == 'VmRSS':
            info['vm_rss_kb'] = parse_status_value(value)
        elif key == 'VmSize':
            info['vm_size_kb'] = parse_status_value(value)

    # Get command line for more context
    cmdline_content = read_proc_file(cmdline_path)
    if cmdline_content:
        cmdline = cmdline_content.replace('\x00', ' ').strip()
        info['cmdline'] = cmdline[:200] if cmdline else info['name']
    else:
        info['cmdline'] = info['name']

    # Resolve username
    if info['uid'] >= 0:
        try:
            info['user'] = pwd.getpwuid(info['uid']).pw_name
        except KeyError:
            info['user'] = str(info['uid'])

    # Calculate swap ratio (swap / (swap + rss))
    total_mem = info['vm_swap_kb'] + info['vm_rss_kb']
    if total_mem > 0:
        info['swap_ratio'] = round((info['vm_swap_kb'] / total_mem) * 100, 1)
    else:
        info['swap_ratio'] = 0.0

    return info


def scan_processes() -> List[Dict[str, Any]]:
    """Scan all processes and gather swap information.

    Returns:
        List of process info dictionaries
    """
    processes = []

    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pid = int(entry)
                info = get_process_swap_info(pid)
                if info and info['vm_swap_kb'] > 0:
                    processes.append(info)
    except OSError:
        pass

    return processes


def format_size(kb: int) -> str:
    """Format size in KB to human-readable format."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb} KB"


def output_plain(processes: List[Dict], total_swap_kb: int, warn_only: bool,
                 verbose: bool, top_n: int, swap_threshold_kb: int,
                 ratio_threshold: float) -> None:
    """Output results in plain text format."""
    # Sort by swap usage
    sorted_procs = sorted(processes, key=lambda x: x['vm_swap_kb'], reverse=True)

    # Apply top N limit
    if top_n > 0:
        display_procs = sorted_procs[:top_n]
    else:
        display_procs = sorted_procs

    # Filter by thresholds if warn_only
    if warn_only:
        display_procs = [
            p for p in display_procs
            if p['vm_swap_kb'] >= swap_threshold_kb or p['swap_ratio'] >= ratio_threshold
        ]

    if not display_procs:
        if not warn_only:
            print("No processes with significant swap usage found")
        return

    # Calculate totals
    total_process_swap = sum(p['vm_swap_kb'] for p in processes)

    print(f"Per-Process Swap Usage Monitor")
    print(f"=" * 70)
    print(f"Total swap used by processes: {format_size(total_process_swap)}")
    print(f"Processes with swap: {len(processes)}")
    print()

    # Header
    print(f"{'PID':>8}  {'Name':<20}  {'User':<12}  {'Swap':>10}  {'RSS':>10}  {'Ratio':>7}")
    print("-" * 75)

    for proc in display_procs:
        swap_str = format_size(proc['vm_swap_kb'])
        rss_str = format_size(proc['vm_rss_kb'])
        ratio_str = f"{proc['swap_ratio']:.1f}%"

        # Mark high swap ratio (potential thrashing)
        marker = ""
        if proc['swap_ratio'] >= ratio_threshold:
            marker = " [!]"
        elif proc['vm_swap_kb'] >= swap_threshold_kb:
            marker = " [*]"

        print(f"{proc['pid']:>8}  {proc['name']:<20}  {proc['user']:<12}  "
              f"{swap_str:>10}  {rss_str:>10}  {ratio_str:>7}{marker}")

        if verbose:
            print(f"          Command: {proc['cmdline'][:60]}")

    print()
    print("Legend: [!] = High swap ratio (thrashing candidate), [*] = High swap usage")


def output_json(processes: List[Dict], total_swap_kb: int, top_n: int,
                swap_threshold_kb: int, ratio_threshold: float) -> None:
    """Output results in JSON format."""
    sorted_procs = sorted(processes, key=lambda x: x['vm_swap_kb'], reverse=True)

    if top_n > 0:
        top_procs = sorted_procs[:top_n]
    else:
        top_procs = sorted_procs

    # Identify issues
    high_swap = [p for p in processes if p['vm_swap_kb'] >= swap_threshold_kb]
    high_ratio = [p for p in processes if p['swap_ratio'] >= ratio_threshold]

    total_process_swap = sum(p['vm_swap_kb'] for p in processes)

    result = {
        'status': 'warning' if (high_swap or high_ratio) else 'ok',
        'summary': {
            'processes_with_swap': len(processes),
            'total_process_swap_kb': total_process_swap,
            'high_swap_count': len(high_swap),
            'high_ratio_count': len(high_ratio),
            'swap_threshold_kb': swap_threshold_kb,
            'ratio_threshold_pct': ratio_threshold,
        },
        'top_consumers': top_procs,
        'high_swap_processes': high_swap,
        'high_ratio_processes': high_ratio,
    }

    print(json.dumps(result, indent=2))


def output_table(processes: List[Dict], warn_only: bool, top_n: int,
                 swap_threshold_kb: int, ratio_threshold: float) -> None:
    """Output results in table format."""
    sorted_procs = sorted(processes, key=lambda x: x['vm_swap_kb'], reverse=True)

    if top_n > 0:
        display_procs = sorted_procs[:top_n]
    else:
        display_procs = sorted_procs

    if warn_only:
        display_procs = [
            p for p in display_procs
            if p['vm_swap_kb'] >= swap_threshold_kb or p['swap_ratio'] >= ratio_threshold
        ]

    if not display_procs:
        print("No processes match the criteria")
        return

    # Header
    print(f"{'PID':>8} {'Name':<20} {'User':<12} {'Swap (KB)':>12} "
          f"{'RSS (KB)':>12} {'Ratio':>8} {'Status':<10}")
    print("-" * 90)

    for proc in display_procs:
        if proc['swap_ratio'] >= ratio_threshold:
            status = 'THRASHING'
        elif proc['vm_swap_kb'] >= swap_threshold_kb:
            status = 'HIGH'
        else:
            status = 'ok'

        print(f"{proc['pid']:>8} {proc['name']:<20} {proc['user']:<12} "
              f"{proc['vm_swap_kb']:>12} {proc['vm_rss_kb']:>12} "
              f"{proc['swap_ratio']:>7.1f}% {status:<10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor per-process swap usage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Show top processes by swap usage
  %(prog)s --top 20               Show top 20 swap consumers
  %(prog)s --warn-only            Only show processes above thresholds
  %(prog)s --format json          Output in JSON format for monitoring
  %(prog)s --user postgres        Filter by username
  %(prog)s --name java            Filter by process name
  %(prog)s --swap-threshold 100   Set swap threshold to 100MB

Why per-process swap matters:
  When system swap is high, this script identifies which processes are
  swapped out. Processes with high swap-to-RSS ratio are likely thrashing
  (constantly swapping in/out), causing performance degradation.

Exit codes:
  0 - No significant swap usage detected
  1 - Processes with high swap or thrashing detected
  2 - Usage error or /proc filesystem unavailable
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
        help='Show detailed information including command lines'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show processes exceeding thresholds'
    )

    parser.add_argument(
        '--top',
        type=int,
        default=20,
        metavar='N',
        help='Show top N swap consumers (default: 20, 0=all)'
    )

    parser.add_argument(
        '--swap-threshold',
        type=int,
        default=100 * 1024,  # 100 MB default
        metavar='KB',
        help='Threshold in KB for high swap warning (default: 102400 = 100MB)'
    )

    parser.add_argument(
        '--ratio-threshold',
        type=float,
        default=50.0,
        metavar='PCT',
        help='Swap ratio threshold for thrashing warning (default: 50%%)'
    )

    parser.add_argument(
        '--user',
        metavar='USER',
        help='Filter by username'
    )

    parser.add_argument(
        '--name',
        metavar='PATTERN',
        help='Filter by process name (case-insensitive substring match)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.top < 0:
        print("Error: --top must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.swap_threshold < 0:
        print("Error: --swap-threshold must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.ratio_threshold < 0 or args.ratio_threshold > 100:
        print("Error: --ratio-threshold must be 0-100", file=sys.stderr)
        sys.exit(2)

    # Check for /proc filesystem
    if not os.path.isdir('/proc'):
        print("Error: /proc filesystem not available", file=sys.stderr)
        print("This script requires a Linux system with procfs", file=sys.stderr)
        sys.exit(2)

    # Scan processes
    processes = scan_processes()

    # Apply filters
    if args.user:
        processes = [p for p in processes if p['user'] == args.user]

    if args.name:
        pattern = args.name.lower()
        processes = [p for p in processes if pattern in p['name'].lower()]

    # Get system swap total for context
    total_swap_kb = 0
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('SwapTotal:'):
                    total_swap_kb = int(line.split()[1])
                    break
    except (OSError, ValueError):
        pass

    # Output results
    if args.format == 'json':
        output_json(processes, total_swap_kb, args.top,
                    args.swap_threshold, args.ratio_threshold)
    elif args.format == 'table':
        output_table(processes, args.warn_only, args.top,
                     args.swap_threshold, args.ratio_threshold)
    else:
        output_plain(processes, total_swap_kb, args.warn_only, args.verbose,
                     args.top, args.swap_threshold, args.ratio_threshold)

    # Determine exit code
    high_swap = [p for p in processes if p['vm_swap_kb'] >= args.swap_threshold]
    high_ratio = [p for p in processes if p['swap_ratio'] >= args.ratio_threshold]

    if high_swap or high_ratio:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
