#!/usr/bin/env python3
"""
Monitor per-process I/O usage to identify processes causing I/O bottlenecks.

This script reads /proc/[pid]/io to show which processes are responsible for
disk I/O load. Unlike system-wide I/O monitoring (iostat, diskstats), this
identifies the specific processes generating read/write traffic.

Critical for troubleshooting:
- Database servers with unexpected I/O patterns
- Backup jobs consuming excessive bandwidth
- Runaway log writers
- Memory-mapped file thrashing
- Identifying which container/service is causing I/O wait

Metrics tracked per process:
- rchar/wchar: Characters read/written (includes page cache)
- read_bytes/write_bytes: Actual disk I/O (bypasses cache accounting)
- syscr/syscw: Read/write syscall counts
- cancelled_write_bytes: Bytes not written due to truncation

Exit codes:
    0 - Successfully collected I/O statistics
    1 - Warnings detected (high I/O processes)
    2 - Usage error or unable to read process information
"""

import argparse
import json
import os
import pwd
import sys
import time
from typing import Any, Dict, List, Optional


def read_proc_file(path: str) -> Optional[str]:
    """Read a /proc file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError, PermissionError):
        return None


def parse_proc_io(content: str) -> Optional[Dict[str, int]]:
    """Parse /proc/[pid]/io content into a dict."""
    if not content:
        return None

    result = {}
    for line in content.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            try:
                result[key.strip()] = int(value.strip())
            except ValueError:
                continue

    return result if result else None


def get_process_info(pid: int) -> Optional[Dict[str, Any]]:
    """Get process information including I/O stats."""
    io_path = f'/proc/{pid}/io'
    comm_path = f'/proc/{pid}/comm'
    cmdline_path = f'/proc/{pid}/cmdline'
    status_path = f'/proc/{pid}/status'

    # Read I/O stats
    io_content = read_proc_file(io_path)
    io_stats = parse_proc_io(io_content)
    if not io_stats:
        return None

    # Get command name
    comm = read_proc_file(comm_path) or 'unknown'

    # Get full command line
    cmdline_raw = read_proc_file(cmdline_path)
    if cmdline_raw:
        cmdline = cmdline_raw.replace('\x00', ' ').strip()
        if len(cmdline) > 80:
            cmdline = cmdline[:77] + '...'
    else:
        cmdline = comm

    # Get user info
    uid = None
    username = 'unknown'
    status_content = read_proc_file(status_path)
    if status_content:
        for line in status_content.split('\n'):
            if line.startswith('Uid:'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        uid = int(parts[1])
                        username = pwd.getpwuid(uid).pw_name
                    except (ValueError, KeyError):
                        username = str(uid) if uid else 'unknown'
                break

    return {
        'pid': pid,
        'comm': comm,
        'cmdline': cmdline,
        'user': username,
        'uid': uid,
        'rchar': io_stats.get('rchar', 0),
        'wchar': io_stats.get('wchar', 0),
        'syscr': io_stats.get('syscr', 0),
        'syscw': io_stats.get('syscw', 0),
        'read_bytes': io_stats.get('read_bytes', 0),
        'write_bytes': io_stats.get('write_bytes', 0),
        'cancelled_write_bytes': io_stats.get('cancelled_write_bytes', 0),
    }


def scan_processes() -> List[Dict[str, Any]]:
    """Scan all processes and gather I/O information."""
    processes = []

    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pid = int(entry)
                info = get_process_info(pid)
                if info:
                    processes.append(info)
    except OSError:
        pass

    return processes


def calculate_io_rates(before: List[Dict], after: List[Dict],
                       interval: float) -> List[Dict[str, Any]]:
    """Calculate I/O rates between two samples."""
    before_map = {p['pid']: p for p in before}
    results = []

    for proc in after:
        pid = proc['pid']
        if pid not in before_map:
            continue

        prev = before_map[pid]

        # Calculate deltas
        read_bytes_delta = proc['read_bytes'] - prev['read_bytes']
        write_bytes_delta = proc['write_bytes'] - prev['write_bytes']
        rchar_delta = proc['rchar'] - prev['rchar']
        wchar_delta = proc['wchar'] - prev['wchar']
        syscr_delta = proc['syscr'] - prev['syscr']
        syscw_delta = proc['syscw'] - prev['syscw']

        # Handle counter wraparound or process restart
        if read_bytes_delta < 0 or write_bytes_delta < 0:
            continue

        # Calculate rates (bytes per second)
        read_rate = read_bytes_delta / interval if interval > 0 else 0
        write_rate = write_bytes_delta / interval if interval > 0 else 0
        total_rate = read_rate + write_rate

        results.append({
            'pid': pid,
            'comm': proc['comm'],
            'cmdline': proc['cmdline'],
            'user': proc['user'],
            'read_bytes': read_bytes_delta,
            'write_bytes': write_bytes_delta,
            'read_rate': read_rate,
            'write_rate': write_rate,
            'total_rate': total_rate,
            'rchar': rchar_delta,
            'wchar': wchar_delta,
            'syscr': syscr_delta,
            'syscw': syscw_delta,
            'total_io_bytes': proc['read_bytes'] + proc['write_bytes'],
        })

    return results


def format_bytes(num_bytes: float) -> str:
    """Format bytes into human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f}PB"


def format_rate(bytes_per_sec: float) -> str:
    """Format bytes/sec into human-readable string."""
    return format_bytes(bytes_per_sec) + "/s"


def output_plain(processes: List[Dict], top_n: int, warn_only: bool,
                 verbose: bool, warn_threshold: float) -> List[Dict]:
    """Output in plain text format. Returns processes with warnings."""
    if not processes:
        if not warn_only:
            print("No I/O activity detected during sampling interval")
        return []

    # Sort by total I/O rate
    sorted_procs = sorted(processes, key=lambda x: x['total_rate'], reverse=True)

    # Filter to only those with activity
    active_procs = [p for p in sorted_procs if p['total_rate'] > 0]

    # Identify high I/O processes
    warnings = [p for p in active_procs if p['total_rate'] >= warn_threshold]

    if warnings:
        print(f"WARNING - High I/O processes (>= {format_rate(warn_threshold)}):")
        for proc in warnings[:top_n]:
            print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                  f"read={format_rate(proc['read_rate']):>10} "
                  f"write={format_rate(proc['write_rate']):>10} "
                  f"total={format_rate(proc['total_rate']):>10} "
                  f"user={proc['user']}")
        print()

    if not warn_only:
        if not warnings:
            print("OK - No processes exceeding I/O threshold")
            print()

        display_procs = active_procs[:top_n] if active_procs else sorted_procs[:top_n]
        if display_procs:
            print(f"Top {min(top_n, len(display_procs))} I/O consumers:")
            for proc in display_procs:
                print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                      f"read={format_rate(proc['read_rate']):>10} "
                      f"write={format_rate(proc['write_rate']):>10} "
                      f"total={format_rate(proc['total_rate']):>10} "
                      f"user={proc['user']}")

            if verbose:
                print()
                print("Detailed syscall counts:")
                for proc in display_procs:
                    if proc['syscr'] > 0 or proc['syscw'] > 0:
                        print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                              f"read_syscalls={proc['syscr']:>8} "
                              f"write_syscalls={proc['syscw']:>8}")

    return warnings


def output_json(processes: List[Dict], top_n: int, warn_threshold: float) -> List[Dict]:
    """Output in JSON format. Returns processes with warnings."""
    sorted_procs = sorted(processes, key=lambda x: x['total_rate'], reverse=True)
    active_procs = [p for p in sorted_procs if p['total_rate'] > 0]
    warnings = [p for p in active_procs if p['total_rate'] >= warn_threshold]

    result = {
        'status': 'warning' if warnings else 'ok',
        'warn_threshold_bytes_sec': warn_threshold,
        'summary': {
            'total_processes_sampled': len(processes),
            'processes_with_io': len(active_procs),
            'warning_count': len(warnings),
            'total_read_rate': sum(p['read_rate'] for p in processes),
            'total_write_rate': sum(p['write_rate'] for p in processes),
        },
        'warnings': warnings[:top_n],
        'top_consumers': active_procs[:top_n],
    }
    print(json.dumps(result, indent=2))
    return warnings


def output_table(processes: List[Dict], top_n: int, warn_only: bool,
                 warn_threshold: float) -> List[Dict]:
    """Output in table format. Returns processes with warnings."""
    sorted_procs = sorted(processes, key=lambda x: x['total_rate'], reverse=True)
    active_procs = [p for p in sorted_procs if p['total_rate'] > 0]
    warnings = [p for p in active_procs if p['total_rate'] >= warn_threshold]

    if warn_only:
        display_procs = warnings[:top_n]
    else:
        display_procs = active_procs[:top_n] if active_procs else sorted_procs[:top_n]

    if not display_procs:
        print("No processes to display")
        return warnings

    print(f"{'PID':>7} {'Command':<15} {'User':<10} {'Read/s':>12} "
          f"{'Write/s':>12} {'Total/s':>12} {'Status':<8}")
    print("-" * 85)

    for proc in display_procs:
        status = 'WARNING' if proc in warnings else 'OK'
        print(f"{proc['pid']:>7} {proc['comm']:<15} {proc['user']:<10} "
              f"{format_rate(proc['read_rate']):>12} "
              f"{format_rate(proc['write_rate']):>12} "
              f"{format_rate(proc['total_rate']):>12} {status:<8}")

    return warnings


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor per-process I/O usage to identify I/O bottlenecks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                       Sample for 1 second and show top I/O consumers
  %(prog)s --interval 5          Sample for 5 seconds (more accurate rates)
  %(prog)s --top 20              Show top 20 I/O consumers
  %(prog)s --warn-only           Only show processes exceeding threshold
  %(prog)s --format json         Output in JSON format for monitoring
  %(prog)s --warn-threshold 10M  Warn on processes doing > 10MB/s

I/O rate interpretation:
  < 1 MB/s   - Low I/O (typical idle process)
  1-10 MB/s  - Moderate I/O (active application)
  10-100 MB/s - High I/O (database, backup, build)
  > 100 MB/s - Very high I/O (bulk copy, rebuild)

Notes:
  - Requires read access to /proc/[pid]/io (may need root for all processes)
  - read_bytes/write_bytes show actual disk I/O
  - rchar/wchar include cached I/O (useful for seeing total app activity)
  - Short sample intervals may miss bursty I/O patterns

Exit codes:
  0 - Successfully collected statistics, no warnings
  1 - Warnings detected (high I/O processes found)
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
        help='Show detailed information including syscall counts'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show processes exceeding I/O threshold'
    )

    parser.add_argument(
        '--interval',
        type=float,
        default=1.0,
        metavar='SECS',
        help='Sampling interval in seconds (default: 1.0)'
    )

    parser.add_argument(
        '--top',
        type=int,
        default=10,
        metavar='N',
        help='Show top N I/O consumers (default: 10)'
    )

    parser.add_argument(
        '--warn-threshold',
        type=str,
        default='10M',
        metavar='RATE',
        help='Warn threshold as bytes/sec with optional K/M/G suffix (default: 10M)'
    )

    args = parser.parse_args()

    # Validate interval
    if args.interval <= 0:
        print("Error: Interval must be positive", file=sys.stderr)
        sys.exit(2)
    if args.interval > 300:
        print("Error: Interval cannot exceed 300 seconds", file=sys.stderr)
        sys.exit(2)

    # Validate top
    if args.top < 1:
        print("Error: --top must be at least 1", file=sys.stderr)
        sys.exit(2)

    # Parse warn threshold
    threshold_str = args.warn_threshold.upper().strip()
    multiplier = 1
    if threshold_str.endswith('K'):
        multiplier = 1024
        threshold_str = threshold_str[:-1]
    elif threshold_str.endswith('M'):
        multiplier = 1024 * 1024
        threshold_str = threshold_str[:-1]
    elif threshold_str.endswith('G'):
        multiplier = 1024 * 1024 * 1024
        threshold_str = threshold_str[:-1]

    try:
        warn_threshold = float(threshold_str) * multiplier
    except ValueError:
        print(f"Error: Invalid threshold value: {args.warn_threshold}",
              file=sys.stderr)
        sys.exit(2)

    if warn_threshold <= 0:
        print("Error: Threshold must be positive", file=sys.stderr)
        sys.exit(2)

    # Check if we can read /proc
    if not os.path.isdir('/proc'):
        print("Error: /proc not available", file=sys.stderr)
        print("This script requires the procfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Take first sample
    before = scan_processes()

    if not before:
        print("Error: Unable to read any process I/O information", file=sys.stderr)
        print("This may require elevated privileges to read /proc/[pid]/io",
              file=sys.stderr)
        sys.exit(2)

    # Wait for interval
    time.sleep(args.interval)

    # Take second sample
    after = scan_processes()

    if not after:
        print("Error: Unable to read process I/O for second sample", file=sys.stderr)
        sys.exit(2)

    # Calculate rates
    processes = calculate_io_rates(before, after, args.interval)

    # Output based on format
    if args.format == 'json':
        warnings = output_json(processes, args.top, warn_threshold)
    elif args.format == 'table':
        warnings = output_table(processes, args.top, args.warn_only, warn_threshold)
    else:
        warnings = output_plain(processes, args.top, args.warn_only,
                                args.verbose, warn_threshold)

    # Exit code based on findings
    sys.exit(1 if warnings else 0)


if __name__ == '__main__':
    main()
