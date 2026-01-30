#!/usr/bin/env python3
"""
Monitor processes for memory growth over time to detect potential memory leaks.

Samples process memory usage at intervals and identifies processes showing
significant memory growth. This is critical for detecting memory leaks in
long-running services before they exhaust system resources.

Key features:
- Tracks RSS (resident set size) growth over configurable intervals
- Calculates growth rate per sample period
- Identifies top memory growers
- Filters by minimum growth threshold
- Supports filtering by user or command pattern

Use cases:
- Detecting memory leaks in production services
- Monitoring long-running batch jobs
- Identifying processes that may need restart
- Pre-emptive capacity planning

Exit codes:
    0 - No significant memory growth detected
    1 - One or more processes showing concerning growth
    2 - Usage error or unable to read process information
"""

import argparse
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


def read_proc_file(path: str) -> Optional[str]:
    """Read a /proc file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError, PermissionError):
        return None


def get_process_memory_info(pid: int) -> Optional[Dict[str, Any]]:
    """Get memory information for a process."""
    status_path = f'/proc/{pid}/status'
    comm_path = f'/proc/{pid}/comm'
    cmdline_path = f'/proc/{pid}/cmdline'

    status_content = read_proc_file(status_path)
    if not status_content:
        return None

    # Parse memory values from status
    rss_kb = None
    vsize_kb = None
    uid = None

    for line in status_content.split('\n'):
        if line.startswith('VmRSS:'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    rss_kb = int(parts[1])
                except ValueError:
                    pass
        elif line.startswith('VmSize:'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    vsize_kb = int(parts[1])
                except ValueError:
                    pass
        elif line.startswith('Uid:'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    uid = int(parts[1])
                except ValueError:
                    pass

    if rss_kb is None:
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

    # Resolve username
    username = None
    if uid is not None:
        try:
            import pwd
            username = pwd.getpwuid(uid).pw_name
        except (KeyError, ImportError):
            username = str(uid)

    return {
        'pid': pid,
        'comm': comm,
        'cmdline': cmdline,
        'user': username or 'unknown',
        'rss_kb': rss_kb,
        'vsize_kb': vsize_kb or 0,
    }


def scan_processes(user_filter: Optional[str] = None,
                   cmd_filter: Optional[str] = None) -> Dict[int, Dict[str, Any]]:
    """Scan all processes and gather memory information."""
    processes = {}

    cmd_pattern = re.compile(cmd_filter, re.IGNORECASE) if cmd_filter else None

    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pid = int(entry)
                info = get_process_memory_info(pid)
                if info:
                    # Apply filters
                    if user_filter and info['user'] != user_filter:
                        continue
                    if cmd_pattern and not cmd_pattern.search(info['comm']):
                        continue
                    processes[pid] = info
    except OSError:
        pass

    return processes


def calculate_growth(samples: List[Dict[int, Dict]], interval: float) -> List[Dict[str, Any]]:
    """Calculate memory growth for processes that appear in all samples."""
    if len(samples) < 2:
        return []

    first_sample = samples[0]
    last_sample = samples[-1]
    total_time = interval * (len(samples) - 1)

    results = []

    # Find processes that exist in both first and last samples
    common_pids = set(first_sample.keys()) & set(last_sample.keys())

    for pid in common_pids:
        first = first_sample[pid]
        last = last_sample[pid]

        rss_start = first['rss_kb']
        rss_end = last['rss_kb']
        growth_kb = rss_end - rss_start

        # Calculate growth rate (KB per minute)
        if total_time > 0:
            growth_rate = (growth_kb / total_time) * 60  # KB/min
        else:
            growth_rate = 0

        # Calculate percentage growth
        if rss_start > 0:
            growth_pct = ((rss_end - rss_start) / rss_start) * 100
        else:
            growth_pct = 0 if rss_end == 0 else 100

        results.append({
            'pid': pid,
            'comm': last['comm'],
            'cmdline': last['cmdline'],
            'user': last['user'],
            'rss_start_kb': rss_start,
            'rss_end_kb': rss_end,
            'growth_kb': growth_kb,
            'growth_pct': round(growth_pct, 1),
            'growth_rate_kb_min': round(growth_rate, 1),
        })

    return results


def analyze_growth(results: List[Dict], min_growth_kb: int,
                   min_growth_pct: float) -> Tuple[List[Dict], List[Dict]]:
    """Analyze growth results and identify concerning processes."""
    warnings = []
    critical = []

    for proc in results:
        # Skip processes with negligible absolute growth
        if proc['growth_kb'] < min_growth_kb:
            continue

        # Categorize by growth percentage
        if proc['growth_pct'] >= 50:
            critical.append(proc)
        elif proc['growth_pct'] >= min_growth_pct:
            warnings.append(proc)

    return warnings, critical


def format_size(kb: int) -> str:
    """Format size in KB to human-readable format."""
    if kb < 1024:
        return f"{kb} KB"
    elif kb < 1024 * 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb / (1024 * 1024):.1f} GB"


def output_plain(results: List[Dict], warnings: List[Dict],
                 critical: List[Dict], warn_only: bool,
                 verbose: bool, top_n: int) -> None:
    """Output in plain text format."""
    if critical:
        print("CRITICAL - Processes with significant memory growth:")
        for proc in sorted(critical, key=lambda x: x['growth_kb'], reverse=True):
            print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                  f"{format_size(proc['rss_start_kb'])} -> {format_size(proc['rss_end_kb'])} "
                  f"(+{format_size(proc['growth_kb'])}, +{proc['growth_pct']}%)")
        print()

    if warnings:
        print("WARNING - Processes with elevated memory growth:")
        for proc in sorted(warnings, key=lambda x: x['growth_kb'], reverse=True):
            print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                  f"{format_size(proc['rss_start_kb'])} -> {format_size(proc['rss_end_kb'])} "
                  f"(+{format_size(proc['growth_kb'])}, +{proc['growth_pct']}%)")
        print()

    if not warn_only:
        if not critical and not warnings:
            print("OK - No significant memory growth detected")
            print()

        if verbose or top_n > 0:
            # Show top growers (even if below threshold)
            sorted_results = sorted(results, key=lambda x: x['growth_kb'], reverse=True)
            display_count = top_n if top_n > 0 else 10
            growers = [r for r in sorted_results if r['growth_kb'] > 0][:display_count]

            if growers:
                print(f"Top {len(growers)} memory growers (by absolute growth):")
                for proc in growers:
                    print(f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                          f"+{format_size(proc['growth_kb'])} "
                          f"({proc['growth_rate_kb_min']:.1f} KB/min) "
                          f"user={proc['user']}")


def output_json(results: List[Dict], warnings: List[Dict],
                critical: List[Dict], top_n: int, total_time: float) -> None:
    """Output in JSON format."""
    sorted_results = sorted(results, key=lambda x: x['growth_kb'], reverse=True)
    top_growers = sorted_results[:top_n] if top_n > 0 else sorted_results[:10]

    total_growth = sum(r['growth_kb'] for r in results if r['growth_kb'] > 0)

    result = {
        'status': 'critical' if critical else ('warning' if warnings else 'ok'),
        'summary': {
            'total_processes_tracked': len(results),
            'critical_count': len(critical),
            'warning_count': len(warnings),
            'total_growth_kb': total_growth,
            'monitoring_duration_sec': round(total_time, 1),
        },
        'critical': critical,
        'warnings': warnings,
        'top_growers': top_growers,
    }
    print(json.dumps(result, indent=2))


def output_table(results: List[Dict], warnings: List[Dict],
                 critical: List[Dict], warn_only: bool, top_n: int) -> None:
    """Output in table format."""
    if warn_only:
        display = critical + warnings
        display.sort(key=lambda x: x['growth_kb'], reverse=True)
    else:
        display = sorted(results, key=lambda x: x['growth_kb'], reverse=True)
        if top_n > 0:
            display = display[:top_n]

    if not display:
        print("No processes to display")
        return

    # Header
    print(f"{'PID':>7} {'Command':<15} {'User':<10} {'Start':>10} {'End':>10} "
          f"{'Growth':>10} {'Pct':>7} {'Status':<10}")
    print("-" * 90)

    for proc in display:
        if proc in critical:
            status = 'CRITICAL'
        elif proc in warnings:
            status = 'WARNING'
        else:
            status = 'OK'

        print(f"{proc['pid']:>7} {proc['comm']:<15} {proc['user']:<10} "
              f"{format_size(proc['rss_start_kb']):>10} {format_size(proc['rss_end_kb']):>10} "
              f"{format_size(proc['growth_kb']):>10} {proc['growth_pct']:>6}% {status:<10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor processes for memory growth over time",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                       Sample 3 times over 10 seconds
  %(prog)s -s 5 -i 5             5 samples, 5 seconds apart (25 sec total)
  %(prog)s --user www-data       Monitor only www-data processes
  %(prog)s --cmd nginx           Monitor processes matching 'nginx'
  %(prog)s --min-growth 1024     Only report growth > 1MB
  %(prog)s --format json         JSON output for monitoring systems

Exit codes:
  0 - No significant memory growth detected
  1 - One or more processes showing concerning growth
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
        help='Show detailed information including top growers'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show processes with warnings or critical growth'
    )

    parser.add_argument(
        '-s', '--samples',
        type=int,
        default=3,
        metavar='N',
        help='Number of samples to take (default: 3, min: 2)'
    )

    parser.add_argument(
        '-i', '--interval',
        type=float,
        default=5.0,
        metavar='SEC',
        help='Interval between samples in seconds (default: 5.0)'
    )

    parser.add_argument(
        '--min-growth',
        type=int,
        default=512,
        metavar='KB',
        help='Minimum growth in KB to report (default: 512)'
    )

    parser.add_argument(
        '--min-pct',
        type=float,
        default=10.0,
        metavar='PCT',
        help='Minimum growth percentage for warning (default: 10.0)'
    )

    parser.add_argument(
        '--top',
        type=int,
        default=0,
        metavar='N',
        help='Show top N growers (default: 10 with --verbose)'
    )

    parser.add_argument(
        '--user',
        type=str,
        metavar='USERNAME',
        help='Only monitor processes owned by this user'
    )

    parser.add_argument(
        '--cmd',
        type=str,
        metavar='PATTERN',
        help='Only monitor processes matching command pattern (regex)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.samples < 2:
        print("Error: Must take at least 2 samples", file=sys.stderr)
        sys.exit(2)
    if args.interval <= 0:
        print("Error: Interval must be positive", file=sys.stderr)
        sys.exit(2)
    if args.min_growth < 0:
        print("Error: --min-growth must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.min_pct < 0:
        print("Error: --min-pct must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.top < 0:
        print("Error: --top must be non-negative", file=sys.stderr)
        sys.exit(2)

    # Validate regex pattern
    if args.cmd:
        try:
            re.compile(args.cmd)
        except re.error as e:
            print(f"Error: Invalid command pattern: {e}", file=sys.stderr)
            sys.exit(2)

    # Check if we can read /proc
    if not os.path.isdir('/proc'):
        print("Error: /proc not available", file=sys.stderr)
        print("This script requires the procfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Collect samples
    samples = []
    total_time = args.interval * (args.samples - 1)

    if args.format == 'plain' and not args.warn_only:
        print(f"Monitoring memory growth ({args.samples} samples, "
              f"{args.interval}s interval, {total_time}s total)...")
        print()

    for i in range(args.samples):
        sample = scan_processes(args.user, args.cmd)
        samples.append(sample)

        if i < args.samples - 1:
            time.sleep(args.interval)

    if not samples or not samples[0]:
        print("Error: Unable to read any process information", file=sys.stderr)
        print("This may require elevated privileges", file=sys.stderr)
        sys.exit(2)

    # Calculate growth
    results = calculate_growth(samples, args.interval)

    if not results:
        if args.format == 'json':
            print(json.dumps({
                'status': 'ok',
                'summary': {
                    'total_processes_tracked': 0,
                    'critical_count': 0,
                    'warning_count': 0,
                    'total_growth_kb': 0,
                    'monitoring_duration_sec': total_time,
                },
                'message': 'No processes persisted across all samples'
            }, indent=2))
        else:
            print("No processes persisted across all samples")
        sys.exit(0)

    # Analyze growth
    warnings, critical = analyze_growth(results, args.min_growth, args.min_pct)

    # Output based on format
    if args.format == 'json':
        output_json(results, warnings, critical, args.top, total_time)
    elif args.format == 'table':
        output_table(results, warnings, critical, args.warn_only, args.top)
    else:
        output_plain(results, warnings, critical, args.warn_only,
                     args.verbose, args.top)

    # Exit code based on findings
    if critical:
        sys.exit(1)
    elif warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
