#!/usr/bin/env python3
"""
Detect file descriptor leaks in long-running processes.

This script identifies processes that may have file descriptor leaks by
comparing current FD counts against historical baselines. It's designed
for detecting gradual FD accumulation in services that should maintain
stable FD counts over time.

Checks performed:
- Processes with FD counts exceeding baseline thresholds
- Processes with unusually high FD counts for their type
- Rapid FD growth rate detection
- System-wide FD pressure assessment

Exit codes:
    0 - No FD leak indicators detected
    1 - Potential FD leaks or warnings found
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import time
from collections import defaultdict


# Default thresholds
DEFAULT_FD_WARNING = 1000      # Warn if process has more than this many FDs
DEFAULT_FD_CRITICAL = 5000    # Critical if process has more than this many FDs
DEFAULT_GROWTH_THRESHOLD = 100  # FDs gained in monitoring period to flag as growing


def get_process_list():
    """Get list of all process PIDs from /proc."""
    pids = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pids.append(int(entry))
    except OSError:
        pass
    return pids


def get_process_comm(pid):
    """Get process name (comm) for a PID."""
    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def get_process_cmdline(pid):
    """Get process command line for a PID."""
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read()
            return cmdline.replace('\x00', ' ').strip()
    except (IOError, OSError):
        return None


def get_process_fd_count(pid):
    """Get count of open file descriptors for a process."""
    try:
        fd_path = f'/proc/{pid}/fd'
        return len(os.listdir(fd_path))
    except (OSError, PermissionError):
        return None


def get_process_fd_details(pid, max_fds=50):
    """Get details about open file descriptors for a process.

    Returns list of dicts with fd number and target (what it points to).
    Limited to max_fds to avoid excessive overhead.
    """
    fds = []
    try:
        fd_path = f'/proc/{pid}/fd'
        fd_list = os.listdir(fd_path)

        for fd_num in fd_list[:max_fds]:
            try:
                target = os.readlink(os.path.join(fd_path, fd_num))
                fds.append({
                    'fd': int(fd_num),
                    'target': target
                })
            except (OSError, ValueError):
                pass
    except (OSError, PermissionError):
        pass

    return fds


def categorize_fds(fds):
    """Categorize file descriptors by type."""
    categories = defaultdict(int)

    for fd in fds:
        target = fd.get('target', '')

        if target.startswith('socket:'):
            categories['sockets'] += 1
        elif target.startswith('pipe:'):
            categories['pipes'] += 1
        elif target.startswith('anon_inode:'):
            if 'eventfd' in target:
                categories['eventfds'] += 1
            elif 'eventpoll' in target:
                categories['epoll'] += 1
            elif 'inotify' in target:
                categories['inotify'] += 1
            elif 'timerfd' in target:
                categories['timerfds'] += 1
            else:
                categories['anon_inodes'] += 1
        elif target.startswith('/dev/'):
            categories['devices'] += 1
        elif target.startswith('/proc/') or target.startswith('/sys/'):
            categories['proc_sys'] += 1
        elif '/' in target:
            categories['files'] += 1
        else:
            categories['other'] += 1

    return dict(categories)


def get_process_uid(pid):
    """Get UID of process owner."""
    try:
        stat_info = os.stat(f'/proc/{pid}')
        return stat_info.st_uid
    except OSError:
        return None


def get_username(uid):
    """Get username for a UID."""
    if uid is None:
        return None
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


def get_process_start_time(pid):
    """Get process start time in seconds since boot."""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            stat = f.read()
            # Start time is field 22 (0-indexed: 21)
            # Skip past comm field which may contain parens
            last_paren = stat.rfind(')')
            if last_paren == -1:
                return None
            fields = stat[last_paren + 2:].split()
            if len(fields) > 19:
                # Field 19 after ')' is starttime (in clock ticks)
                starttime = int(fields[19])
                # Convert to seconds (assuming 100 Hz clock)
                return starttime / 100
    except (IOError, OSError, ValueError, IndexError):
        pass
    return None


def get_system_uptime():
    """Get system uptime in seconds."""
    try:
        with open('/proc/uptime', 'r') as f:
            return float(f.read().split()[0])
    except (IOError, OSError, ValueError):
        return None


def get_system_fd_limits():
    """Get system-wide file descriptor limits and usage."""
    try:
        with open('/proc/sys/fs/file-nr', 'r') as f:
            parts = f.read().strip().split()
            return {
                'allocated': int(parts[0]),
                'free': int(parts[1]) if len(parts) > 1 else 0,
                'max': int(parts[2]) if len(parts) > 2 else 0
            }
    except (IOError, OSError, ValueError, IndexError):
        return None


def get_process_fd_limit(pid):
    """Get per-process file descriptor limit."""
    try:
        with open(f'/proc/{pid}/limits', 'r') as f:
            for line in f:
                if 'Max open files' in line:
                    parts = line.split()
                    # Format: Max open files  <soft>  <hard>  files
                    soft_limit = int(parts[3])
                    return soft_limit
    except (IOError, OSError, ValueError, IndexError):
        pass
    return None


def analyze_process(pid, fd_warning=1000, fd_critical=5000, include_details=False):
    """Analyze a single process for FD leak indicators.

    Returns dict with process info and potential issues, or None if not accessible.
    """
    comm = get_process_comm(pid)
    if comm is None:
        return None

    fd_count = get_process_fd_count(pid)
    if fd_count is None:
        return None

    fd_limit = get_process_fd_limit(pid)
    uid = get_process_uid(pid)
    username = get_username(uid)
    cmdline = get_process_cmdline(pid)
    start_time = get_process_start_time(pid)
    uptime = get_system_uptime()

    # Calculate process age in seconds
    process_age = None
    if start_time is not None and uptime is not None:
        process_age = uptime - start_time

    info = {
        'pid': pid,
        'comm': comm,
        'cmdline': cmdline[:200] if cmdline else '',
        'fd_count': fd_count,
        'fd_limit': fd_limit,
        'fd_usage_pct': round(fd_count * 100 / fd_limit, 1) if fd_limit else None,
        'uid': uid,
        'user': username,
        'age_seconds': int(process_age) if process_age else None,
        'issues': []
    }

    # Add FD details if requested
    if include_details:
        fds = get_process_fd_details(pid, max_fds=100)
        info['fd_categories'] = categorize_fds(fds)

    # Check for issues
    if fd_count >= fd_critical:
        info['issues'].append({
            'severity': 'CRITICAL',
            'type': 'high_fd_count',
            'message': f'Process has {fd_count} open FDs (critical threshold: {fd_critical})'
        })
    elif fd_count >= fd_warning:
        info['issues'].append({
            'severity': 'WARNING',
            'type': 'elevated_fd_count',
            'message': f'Process has {fd_count} open FDs (warning threshold: {fd_warning})'
        })

    # Check FD limit proximity
    if fd_limit and fd_count > fd_limit * 0.8:
        pct = round(fd_count * 100 / fd_limit, 1)
        info['issues'].append({
            'severity': 'WARNING',
            'type': 'approaching_limit',
            'message': f'Process using {pct}% of FD limit ({fd_count}/{fd_limit})'
        })

    return info


def get_all_processes_fd_info(fd_warning=1000, fd_critical=5000,
                               min_fds=10, user_filter=None, comm_filter=None,
                               include_details=False):
    """Get FD information for all processes.

    Args:
        fd_warning: FD count threshold for warnings
        fd_critical: FD count threshold for critical alerts
        min_fds: Minimum FDs to include in results
        user_filter: Only include processes owned by this user
        comm_filter: Only include processes matching this name pattern
        include_details: Include FD category breakdown

    Returns:
        list of process info dicts, sorted by FD count descending
    """
    processes = []
    pids = get_process_list()

    for pid in pids:
        info = analyze_process(pid, fd_warning, fd_critical, include_details)
        if info is None:
            continue

        # Apply filters
        if info['fd_count'] < min_fds:
            continue
        if user_filter and info['user'] != user_filter:
            continue
        if comm_filter and comm_filter.lower() not in info['comm'].lower():
            continue

        processes.append(info)

    # Sort by FD count, highest first
    processes.sort(key=lambda p: p['fd_count'], reverse=True)

    return processes


def monitor_fd_growth(duration=10, interval=2, fd_warning=1000):
    """Monitor FD growth over time to detect leaks.

    Args:
        duration: Total monitoring duration in seconds
        interval: Sampling interval in seconds
        fd_warning: Only track processes with at least this many FDs

    Returns:
        list of processes with significant FD growth
    """
    # Take initial snapshot
    initial = {}
    for pid in get_process_list():
        comm = get_process_comm(pid)
        fd_count = get_process_fd_count(pid)
        if comm and fd_count and fd_count >= fd_warning / 2:
            initial[pid] = {'comm': comm, 'fd_count': fd_count, 'time': time.time()}

    # Wait and sample
    samples = int(duration / interval)
    for _ in range(samples):
        time.sleep(interval)

    # Take final snapshot and compare
    growing = []
    for pid in get_process_list():
        if pid not in initial:
            continue

        comm = get_process_comm(pid)
        fd_count = get_process_fd_count(pid)

        if not comm or not fd_count:
            continue

        # Verify same process (comm should match)
        if comm != initial[pid]['comm']:
            continue

        growth = fd_count - initial[pid]['fd_count']
        elapsed = time.time() - initial[pid]['time']

        if growth > 0:
            rate = growth / elapsed if elapsed > 0 else 0
            growing.append({
                'pid': pid,
                'comm': comm,
                'initial_fds': initial[pid]['fd_count'],
                'current_fds': fd_count,
                'growth': growth,
                'growth_rate_per_min': round(rate * 60, 2),
                'elapsed_seconds': round(elapsed, 1)
            })

    # Sort by growth rate
    growing.sort(key=lambda p: p['growth'], reverse=True)

    return growing


def generate_summary(processes, system_fd_info):
    """Generate summary statistics."""
    summary = {
        'total_processes_analyzed': len(processes),
        'processes_with_issues': sum(1 for p in processes if p['issues']),
        'critical_count': sum(1 for p in processes
                             for i in p['issues'] if i['severity'] == 'CRITICAL'),
        'warning_count': sum(1 for p in processes
                            for i in p['issues'] if i['severity'] == 'WARNING'),
        'total_fds_tracked': sum(p['fd_count'] for p in processes),
        'top_fd_consumer': processes[0]['comm'] if processes else None,
        'top_fd_count': processes[0]['fd_count'] if processes else 0,
    }

    if system_fd_info:
        summary['system_fd_allocated'] = system_fd_info['allocated']
        summary['system_fd_max'] = system_fd_info['max']
        summary['system_fd_usage_pct'] = round(
            system_fd_info['allocated'] * 100 / system_fd_info['max'], 1
        ) if system_fd_info['max'] else None

    return summary


def output_plain(processes, summary, verbose=False, warn_only=False, top_n=20):
    """Output results in plain text format."""
    if warn_only and summary['processes_with_issues'] == 0:
        return

    print("File Descriptor Leak Detector")
    print("=" * 60)
    print(f"Processes analyzed: {summary['total_processes_analyzed']}")
    print(f"Processes with issues: {summary['processes_with_issues']}")
    print(f"  Critical: {summary['critical_count']}")
    print(f"  Warning: {summary['warning_count']}")
    print()

    if summary.get('system_fd_allocated'):
        print(f"System FD usage: {summary['system_fd_allocated']}/{summary['system_fd_max']} "
              f"({summary['system_fd_usage_pct']}%)")
        print()

    if processes:
        print(f"Top {min(top_n, len(processes))} processes by FD count:")
        print("-" * 60)

        for proc in processes[:top_n]:
            limit_str = f"/{proc['fd_limit']}" if proc['fd_limit'] else ""
            age_str = ""
            if proc['age_seconds']:
                hours = proc['age_seconds'] // 3600
                mins = (proc['age_seconds'] % 3600) // 60
                if hours > 0:
                    age_str = f" (uptime: {hours}h {mins}m)"
                else:
                    age_str = f" (uptime: {mins}m)"

            print(f"PID {proc['pid']}: {proc['comm']}")
            print(f"  FDs: {proc['fd_count']}{limit_str}, User: {proc['user']}{age_str}")

            if verbose and proc['cmdline']:
                print(f"  Cmd: {proc['cmdline'][:60]}...")

            if verbose and proc.get('fd_categories'):
                cats = proc['fd_categories']
                cat_str = ", ".join(f"{k}:{v}" for k, v in sorted(cats.items(),
                                                                   key=lambda x: -x[1]))
                print(f"  FD types: {cat_str}")

            for issue in proc['issues']:
                print(f"  [{issue['severity']}] {issue['message']}")

            print()


def output_json(processes, summary, growing=None):
    """Output results in JSON format."""
    output = {
        'summary': summary,
        'processes': processes
    }
    if growing:
        output['growing_processes'] = growing
    print(json.dumps(output, indent=2))


def output_table(processes, summary, warn_only=False, top_n=20):
    """Output results in table format."""
    if warn_only and summary['processes_with_issues'] == 0:
        return

    print("=" * 90)
    print("FILE DESCRIPTOR LEAK DETECTOR REPORT")
    print("=" * 90)
    print()

    # Summary table
    print(f"{'Metric':<40} {'Value':<20}")
    print("-" * 60)
    print(f"{'Processes analyzed':<40} {summary['total_processes_analyzed']:<20}")
    print(f"{'Processes with issues':<40} {summary['processes_with_issues']:<20}")
    print(f"{'Critical alerts':<40} {summary['critical_count']:<20}")
    print(f"{'Warning alerts':<40} {summary['warning_count']:<20}")

    if summary.get('system_fd_allocated'):
        print(f"{'System FD usage':<40} {summary['system_fd_allocated']}/{summary['system_fd_max']} "
              f"({summary['system_fd_usage_pct']}%)")
    print()

    if processes:
        print("=" * 90)
        print(f"{'PID':<8} {'FDs':<8} {'Limit':<8} {'Usage%':<8} {'User':<12} "
              f"{'Process':<20} {'Status':<16}")
        print("-" * 90)

        for proc in processes[:top_n]:
            limit_str = str(proc['fd_limit']) if proc['fd_limit'] else 'N/A'
            usage_str = f"{proc['fd_usage_pct']}%" if proc['fd_usage_pct'] else 'N/A'

            status = 'OK'
            for issue in proc['issues']:
                if issue['severity'] == 'CRITICAL':
                    status = 'CRITICAL'
                    break
                elif issue['severity'] == 'WARNING':
                    status = 'WARNING'

            print(f"{proc['pid']:<8} {proc['fd_count']:<8} {limit_str:<8} {usage_str:<8} "
                  f"{(proc['user'] or 'N/A')[:12]:<12} {proc['comm'][:20]:<20} {status:<16}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Detect file descriptor leaks in running processes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Show top FD consumers with issues
  %(prog)s --top 50            # Show top 50 processes by FD count
  %(prog)s --monitor 30        # Monitor FD growth for 30 seconds
  %(prog)s --format json       # JSON output for automation
  %(prog)s --details           # Include FD type breakdown
  %(prog)s --user nginx        # Filter by user

Exit codes:
  0 - No FD leak indicators detected
  1 - Potential leaks or warnings found
  2 - Usage error

Notes:
  - Processes with >1000 FDs generate warnings
  - Processes with >5000 FDs generate critical alerts
  - Approaching FD limit (>80%%) generates warnings
  - Use --monitor to detect FD growth over time
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
        help='Show detailed information including command lines'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only produce output if issues are found'
    )

    parser.add_argument(
        '--top',
        type=int,
        default=20,
        help='Number of top processes to show (default: %(default)s)'
    )

    parser.add_argument(
        '--min-fds',
        type=int,
        default=10,
        help='Minimum FD count to include in analysis (default: %(default)s)'
    )

    parser.add_argument(
        '--fd-warning',
        type=int,
        default=DEFAULT_FD_WARNING,
        help=f'FD count warning threshold (default: {DEFAULT_FD_WARNING})'
    )

    parser.add_argument(
        '--fd-critical',
        type=int,
        default=DEFAULT_FD_CRITICAL,
        help=f'FD count critical threshold (default: {DEFAULT_FD_CRITICAL})'
    )

    parser.add_argument(
        '-u', '--user',
        help='Only show processes owned by specified user'
    )

    parser.add_argument(
        '-c', '--comm',
        help='Only show processes matching this name pattern'
    )

    parser.add_argument(
        '--details',
        action='store_true',
        help='Include FD type breakdown (sockets, files, pipes, etc.)'
    )

    parser.add_argument(
        '--monitor',
        type=int,
        metavar='SECONDS',
        help='Monitor FD growth for specified duration'
    )

    args = parser.parse_args()

    # Check if /proc is accessible
    if not os.path.isdir('/proc'):
        print("Error: /proc filesystem not accessible", file=sys.stderr)
        print("This tool requires Linux with procfs mounted", file=sys.stderr)
        sys.exit(2)

    # Get system FD info
    system_fd_info = get_system_fd_limits()

    # If monitoring mode, do that first
    growing = None
    if args.monitor:
        if args.format != 'json':
            print(f"Monitoring FD growth for {args.monitor} seconds...")
        growing = monitor_fd_growth(
            duration=args.monitor,
            interval=2,
            fd_warning=args.fd_warning
        )
        if args.format != 'json' and growing:
            print(f"Found {len(growing)} process(es) with FD growth")
            print()

    # Get process information
    processes = get_all_processes_fd_info(
        fd_warning=args.fd_warning,
        fd_critical=args.fd_critical,
        min_fds=args.min_fds,
        user_filter=args.user,
        comm_filter=args.comm,
        include_details=args.details or args.verbose
    )

    # Generate summary
    summary = generate_summary(processes, system_fd_info)

    # Add growth info to summary if available
    if growing:
        summary['processes_with_growth'] = len(growing)
        summary['max_growth_rate'] = max((g['growth_rate_per_min'] for g in growing), default=0)

    # Check warn-only mode
    has_issues = summary['critical_count'] > 0 or summary['warning_count'] > 0
    if growing:
        has_issues = has_issues or len(growing) > 0

    if args.warn_only and not has_issues:
        sys.exit(0)

    # Output results
    if args.format == 'json':
        output_json(processes, summary, growing)
    elif args.format == 'table':
        output_table(processes, summary, args.warn_only, args.top)
        if growing and args.format != 'json':
            print()
            print("Processes with FD growth during monitoring:")
            for g in growing[:10]:
                print(f"  PID {g['pid']} ({g['comm']}): {g['initial_fds']} -> {g['current_fds']} "
                      f"(+{g['growth']}, {g['growth_rate_per_min']}/min)")
    else:
        output_plain(processes, summary, args.verbose, args.warn_only, args.top)
        if growing:
            print("Processes with FD growth during monitoring:")
            print("-" * 60)
            for g in growing[:10]:
                print(f"  PID {g['pid']} ({g['comm']}): {g['initial_fds']} -> {g['current_fds']} "
                      f"(+{g['growth']}, {g['growth_rate_per_min']}/min)")

    # Exit code based on findings
    if summary['critical_count'] > 0:
        sys.exit(1)
    elif summary['warning_count'] > 0:
        sys.exit(1)
    elif growing and len(growing) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
