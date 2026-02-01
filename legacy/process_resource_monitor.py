#!/usr/bin/env python3
"""
Monitor process resource consumption and detect resource-hungry or problematic processes.

This script identifies processes consuming high CPU or memory, detects zombie processes,
and checks process count limits. Useful for troubleshooting performance issues on
baremetal systems or identifying runaway processes.

Exit codes:
    0 - No issues detected
    1 - Resource thresholds exceeded or problematic processes found
    2 - Usage error or missing dependency
"""

import argparse
import sys
import os
import json
from collections import defaultdict


def get_process_info():
    """
    Parse /proc filesystem to get process information.

    Returns:
        list: List of process dictionaries with pid, user, cpu, mem, state, command
    """
    processes = []

    try:
        # Get list of process directories
        proc_dirs = [d for d in os.listdir('/proc') if d.isdigit()]
    except Exception as e:
        print(f"Error: Unable to read /proc: {e}", file=sys.stderr)
        return processes

    # Get total memory for percentage calculations
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    total_mem_kb = int(line.split()[1])
                    break
    except Exception:
        total_mem_kb = 1  # Avoid division by zero

    for pid in proc_dirs:
        try:
            # Read process status
            stat_path = f'/proc/{pid}/stat'
            status_path = f'/proc/{pid}/status'
            cmdline_path = f'/proc/{pid}/cmdline'

            # Parse stat file for CPU and state
            with open(stat_path, 'r') as f:
                stat_data = f.read()
                # Handle process names with spaces/parentheses
                comm_start = stat_data.index('(') + 1
                comm_end = stat_data.rindex(')')
                stat_parts = stat_data[comm_end + 2:].split()

                state = stat_parts[0]  # Process state
                utime = int(stat_parts[11])  # User time
                stime = int(stat_parts[12])  # System time
                total_time = utime + stime

            # Parse status file for memory and user
            mem_kb = 0
            uid = 0
            with open(status_path, 'r') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        mem_kb = int(line.split()[1])
                    elif line.startswith('Uid:'):
                        uid = int(line.split()[1])

            # Get username from UID
            try:
                import pwd
                username = pwd.getpwuid(uid).pw_name
            except (ImportError, KeyError):
                username = str(uid)

            # Get command line
            try:
                with open(cmdline_path, 'r') as f:
                    cmdline = f.read().replace('\x00', ' ').strip()
                    if not cmdline:
                        # Kernel thread - get name from stat
                        cmdline = f"[{stat_data[comm_start:comm_end]}]"
            except Exception:
                cmdline = "unknown"

            # Calculate memory percentage
            mem_percent = (mem_kb / total_mem_kb * 100) if total_mem_kb > 0 else 0

            processes.append({
                'pid': int(pid),
                'user': username,
                'cpu_time': total_time,
                'mem_kb': mem_kb,
                'mem_percent': mem_percent,
                'state': state,
                'command': cmdline[:200]  # Truncate long commands
            })

        except (FileNotFoundError, ProcessLookupError, ValueError, IndexError):
            # Process terminated or parsing error - skip it
            continue
        except Exception as e:
            # Unexpected error - log but continue
            continue

    return processes


def detect_zombies(processes):
    """
    Identify zombie processes.

    Args:
        processes: List of process dictionaries

    Returns:
        list: List of zombie process dictionaries
    """
    return [p for p in processes if p['state'] == 'Z']


def get_top_consumers(processes, by='cpu', limit=10):
    """
    Get top N resource consuming processes.

    Args:
        processes: List of process dictionaries
        by: Sort by 'cpu' or 'mem'
        limit: Number of top processes to return

    Returns:
        list: Top N processes sorted by resource usage
    """
    if by == 'cpu':
        sorted_procs = sorted(processes, key=lambda p: p['cpu_time'], reverse=True)
    else:  # mem
        sorted_procs = sorted(processes, key=lambda p: p['mem_kb'], reverse=True)

    return sorted_procs[:limit]


def check_thresholds(processes, cpu_threshold=None, mem_threshold=None):
    """
    Find processes exceeding resource thresholds.

    Args:
        processes: List of process dictionaries
        cpu_threshold: CPU time threshold (jiffies)
        mem_threshold: Memory threshold (percentage)

    Returns:
        dict: Dictionary with 'cpu_exceeded' and 'mem_exceeded' lists
    """
    exceeded = {
        'cpu_exceeded': [],
        'mem_exceeded': []
    }

    if cpu_threshold:
        exceeded['cpu_exceeded'] = [
            p for p in processes if p['cpu_time'] > cpu_threshold
        ]

    if mem_threshold:
        exceeded['mem_exceeded'] = [
            p for p in processes if p['mem_percent'] > mem_threshold
        ]

    return exceeded


def get_process_count_by_user(processes):
    """
    Count processes per user.

    Args:
        processes: List of process dictionaries

    Returns:
        dict: User -> process count mapping
    """
    counts = defaultdict(int)
    for p in processes:
        counts[p['user']] += 1
    return dict(counts)


def output_plain(processes, top_cpu, top_mem, zombies, user_counts, exceeded, args):
    """Plain text output format"""
    print(f"Total processes: {len(processes)}")
    print()

    if zombies and not args.warn_only:
        print(f"ZOMBIE PROCESSES: {len(zombies)}")
        for z in zombies[:10]:
            print(f"  PID {z['pid']:>7} User: {z['user']:<12} Command: {z['command']}")
        print()

    if args.mem_threshold and exceeded['mem_exceeded']:
        print(f"MEMORY THRESHOLD EXCEEDED (>{args.mem_threshold}%):")
        for p in exceeded['mem_exceeded'][:10]:
            print(f"  PID {p['pid']:>7} User: {p['user']:<12} Mem: {p['mem_percent']:>5.1f}% Command: {p['command']}")
        print()

    if not args.warn_only or (args.mem_threshold and exceeded['mem_exceeded']):
        print(f"Top {args.top_n} Memory Consumers:")
        print(f"{'PID':>7} {'User':<12} {'Mem %':>7} {'Mem KB':>12} Command")
        print("-" * 80)
        for p in top_mem:
            print(f"{p['pid']:>7} {p['user']:<12} {p['mem_percent']:>6.1f}% {p['mem_kb']:>12,} {p['command'][:40]}")
        print()

    if not args.warn_only:
        print(f"Top {args.top_n} CPU Time Consumers:")
        print(f"{'PID':>7} {'User':<12} {'CPU Time':>12} Command")
        print("-" * 80)
        for p in top_cpu:
            print(f"{p['pid']:>7} {p['user']:<12} {p['cpu_time']:>12} {p['command'][:40]}")
        print()

    if args.by_user and not args.warn_only:
        print("Process Count by User:")
        sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)
        for user, count in sorted_users[:20]:
            print(f"  {user:<20} {count:>5} processes")


def output_json(processes, top_cpu, top_mem, zombies, user_counts, exceeded, args):
    """JSON output format"""
    data = {
        'total_processes': len(processes),
        'zombie_count': len(zombies),
        'zombies': zombies[:20],  # Limit to avoid huge output
        'top_cpu': top_cpu,
        'top_memory': top_mem,
        'thresholds_exceeded': exceeded,
        'process_count_by_user': user_counts
    }
    print(json.dumps(data, indent=2))


def output_table(processes, top_cpu, top_mem, zombies, user_counts, exceeded, args):
    """Tabular output format"""
    print("=" * 100)
    print(f"PROCESS RESOURCE MONITOR - Total Processes: {len(processes)}")
    print("=" * 100)
    print()

    if zombies:
        print(f"ZOMBIE PROCESSES: {len(zombies)}")
        print(f"{'PID':>7} {'User':<15} {'Command':<60}")
        print("-" * 100)
        for z in zombies[:10]:
            print(f"{z['pid']:>7} {z['user']:<15} {z['command'][:60]}")
        print()

    if exceeded['mem_exceeded']:
        print(f"MEMORY THRESHOLD EXCEEDED (>{args.mem_threshold}%): {len(exceeded['mem_exceeded'])}")
        print(f"{'PID':>7} {'User':<15} {'Mem %':>8} {'Mem KB':>12} {'Command':<40}")
        print("-" * 100)
        for p in exceeded['mem_exceeded'][:10]:
            print(f"{p['pid']:>7} {p['user']:<15} {p['mem_percent']:>7.1f}% {p['mem_kb']:>12,} {p['command'][:40]}")
        print()

    print(f"TOP {args.top_n} MEMORY CONSUMERS")
    print(f"{'PID':>7} {'User':<15} {'Mem %':>8} {'Mem KB':>12} {'Command':<40}")
    print("-" * 100)
    for p in top_mem:
        print(f"{p['pid']:>7} {p['user']:<15} {p['mem_percent']:>7.1f}% {p['mem_kb']:>12,} {p['command'][:40]}")
    print()

    print(f"TOP {args.top_n} CPU TIME CONSUMERS")
    print(f"{'PID':>7} {'User':<15} {'CPU Time':>12} {'Command':<40}")
    print("-" * 100)
    for p in top_cpu:
        print(f"{p['pid']:>7} {p['user']:<15} {p['cpu_time']:>12} {p['command'][:40]}")
    print()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Monitor process resource consumption and detect problematic processes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Show top consumers
  %(prog)s --top-n 20               # Show top 20 consumers
  %(prog)s --mem-threshold 10       # Alert on processes using >10%% memory
  %(prog)s --by-user                # Show process counts by user
  %(prog)s --warn-only              # Only show warnings/issues
  %(prog)s --format json            # Output in JSON format

Exit codes:
  0 - No issues detected
  1 - Zombies found or thresholds exceeded
  2 - Usage error
        """
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        metavar="N",
        help="Number of top processes to show (default: %(default)s)"
    )

    parser.add_argument(
        "--mem-threshold",
        type=float,
        metavar="PCT",
        help="Alert on processes exceeding this memory percentage"
    )

    parser.add_argument(
        "--by-user",
        action="store_true",
        help="Show process count by user"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues (zombies, threshold violations)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.top_n < 1:
        print("Error: --top-n must be at least 1", file=sys.stderr)
        sys.exit(2)

    if args.mem_threshold and (args.mem_threshold < 0 or args.mem_threshold > 100):
        print("Error: --mem-threshold must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    # Get process information
    processes = get_process_info()

    if not processes:
        print("Error: Unable to read process information", file=sys.stderr)
        sys.exit(1)

    # Analyze processes
    zombies = detect_zombies(processes)
    top_cpu = get_top_consumers(processes, by='cpu', limit=args.top_n)
    top_mem = get_top_consumers(processes, by='mem', limit=args.top_n)
    user_counts = get_process_count_by_user(processes)
    exceeded = check_thresholds(
        processes,
        mem_threshold=args.mem_threshold
    )

    # Output results
    if args.format == "json":
        output_json(processes, top_cpu, top_mem, zombies, user_counts, exceeded, args)
    elif args.format == "table":
        output_table(processes, top_cpu, top_mem, zombies, user_counts, exceeded, args)
    else:  # plain
        output_plain(processes, top_cpu, top_mem, zombies, user_counts, exceeded, args)

    # Determine exit code
    has_issues = len(zombies) > 0 or len(exceeded['mem_exceeded']) > 0
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
