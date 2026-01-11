#!/usr/bin/env python3
"""
Monitor per-process resource limits (ulimits) and detect processes at risk.

This script checks individual processes for resource limit consumption and
identifies processes that are approaching their configured limits. Critical for:

- High-connection servers (web servers, databases, proxies) hitting fd limits
- Worker processes approaching memory/stack limits
- Long-running processes with accumulating file handles
- Processes with restrictive limits inherited from parent shells

Monitors:
- Open file descriptors vs RLIMIT_NOFILE
- Virtual memory size vs RLIMIT_AS (address space)
- Stack size vs RLIMIT_STACK
- Number of threads vs RLIMIT_NPROC (per-user process limit)

Use cases:
- Detect processes before they hit "too many open files" errors
- Find processes with misconfigured limits (too low for workload)
- Identify resource-hungry processes consuming limits
- Pre-flight checks before increasing workload

Exit codes:
    0 - All processes within safe limits
    1 - Processes found at risk (above warning threshold)
    2 - Usage error or /proc filesystem not available
"""

import argparse
import os
import sys
import json
import pwd


def read_proc_file(path, default=None):
    """Read content from a /proc file.

    Args:
        path: Full path to the /proc file
        default: Default value if file cannot be read

    Returns:
        str: File contents or default
    """
    try:
        with open(path, 'r') as f:
            return f.read()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return default
    except Exception:
        return default


def get_process_name(pid):
    """Get process name (comm) for a PID.

    Args:
        pid: Process ID

    Returns:
        str: Process name or 'unknown'
    """
    content = read_proc_file(f'/proc/{pid}/comm')
    return content.strip() if content else 'unknown'


def get_process_cmdline(pid):
    """Get process command line for a PID.

    Args:
        pid: Process ID

    Returns:
        str: Command line or empty string
    """
    content = read_proc_file(f'/proc/{pid}/cmdline')
    if content:
        # Replace null bytes with spaces
        return content.replace('\x00', ' ').strip()
    return ''


def get_process_user(pid):
    """Get username owning a process.

    Args:
        pid: Process ID

    Returns:
        str: Username or 'unknown'
    """
    try:
        stat_info = os.stat(f'/proc/{pid}')
        return pwd.getpwuid(stat_info.st_uid).pw_name
    except (FileNotFoundError, KeyError, PermissionError):
        return 'unknown'


def get_fd_count(pid):
    """Count open file descriptors for a process.

    Args:
        pid: Process ID

    Returns:
        int: Number of open file descriptors, or -1 on error
    """
    fd_path = f'/proc/{pid}/fd'
    try:
        return len(os.listdir(fd_path))
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return -1


def get_thread_count(pid):
    """Count threads for a process.

    Args:
        pid: Process ID

    Returns:
        int: Number of threads, or -1 on error
    """
    task_path = f'/proc/{pid}/task'
    try:
        return len(os.listdir(task_path))
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return -1


def parse_limits(pid):
    """Parse /proc/[pid]/limits file.

    Args:
        pid: Process ID

    Returns:
        dict: Limits parsed from the file, keyed by limit name
    """
    limits_content = read_proc_file(f'/proc/{pid}/limits')
    if not limits_content:
        return {}

    limits = {}
    lines = limits_content.strip().split('\n')

    # The limits file has fixed-width columns:
    # Limit                     Soft Limit           Hard Limit           Units
    # Column positions are consistent: name (0-25), soft (26-45), hard (46-65), units (66+)
    for line in lines[1:]:  # Skip header line
        if len(line) < 50:
            continue

        # Extract the limit name (first 25 chars)
        name = line[:25].strip()

        # Extract soft limit (chars 26-45)
        soft_str = line[26:46].strip() if len(line) > 26 else ''

        # Extract hard limit (chars 46-65)
        hard_str = line[46:66].strip() if len(line) > 46 else ''

        if not name or not soft_str:
            continue

        try:
            soft = None if soft_str == 'unlimited' else int(soft_str)
            hard = None if hard_str == 'unlimited' else int(hard_str)
            limits[name] = {'soft': soft, 'hard': hard}
        except ValueError:
            # Skip lines we can't parse
            continue

    return limits


def parse_status(pid):
    """Parse /proc/[pid]/status for memory/thread info.

    Args:
        pid: Process ID

    Returns:
        dict: Status values (VmSize, VmStk, Threads)
    """
    status_content = read_proc_file(f'/proc/{pid}/status')
    if not status_content:
        return {}

    status = {}
    for line in status_content.strip().split('\n'):
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()
        value = value.strip()

        # Parse memory values (in kB)
        if key in ('VmSize', 'VmStk', 'VmRSS', 'VmData'):
            parts = value.split()
            if parts and parts[0].isdigit():
                status[key] = int(parts[0]) * 1024  # Convert to bytes
        elif key == 'Threads':
            if value.isdigit():
                status[key] = int(value)

    return status


def get_all_pids():
    """Get list of all process IDs.

    Returns:
        list: List of integer PIDs
    """
    pids = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pids.append(int(entry))
    except Exception:
        pass
    return pids


def analyze_process(pid, warn_pct, crit_pct):
    """Analyze a single process for limit issues.

    Args:
        pid: Process ID
        warn_pct: Warning threshold percentage
        crit_pct: Critical threshold percentage

    Returns:
        dict: Process analysis results with issues list
    """
    limits = parse_limits(pid)
    status = parse_status(pid)

    if not limits:
        return None

    process_info = {
        'pid': pid,
        'name': get_process_name(pid),
        'user': get_process_user(pid),
        'issues': [],
        'metrics': {}
    }

    # Check open file descriptors
    fd_count = get_fd_count(pid)
    if fd_count >= 0 and 'Max open files' in limits:
        limit = limits['Max open files']
        soft_limit = limit['soft']
        if soft_limit is not None and soft_limit > 0:
            pct_used = (fd_count / soft_limit) * 100
            process_info['metrics']['open_files'] = {
                'current': fd_count,
                'soft_limit': soft_limit,
                'hard_limit': limit['hard'],
                'percent_used': round(pct_used, 1)
            }

            if pct_used >= crit_pct:
                process_info['issues'].append({
                    'severity': 'CRITICAL',
                    'resource': 'open_files',
                    'message': f'Open files at {pct_used:.1f}% of limit '
                              f'({fd_count}/{soft_limit})'
                })
            elif pct_used >= warn_pct:
                process_info['issues'].append({
                    'severity': 'WARNING',
                    'resource': 'open_files',
                    'message': f'Open files at {pct_used:.1f}% of limit '
                              f'({fd_count}/{soft_limit})'
                })

    # Check virtual memory (address space)
    if 'VmSize' in status and 'Max address space' in limits:
        vm_size = status['VmSize']
        limit = limits['Max address space']
        soft_limit = limit['soft']
        if soft_limit is not None and soft_limit > 0:
            pct_used = (vm_size / soft_limit) * 100
            process_info['metrics']['address_space'] = {
                'current': vm_size,
                'soft_limit': soft_limit,
                'hard_limit': limit['hard'],
                'percent_used': round(pct_used, 1)
            }

            if pct_used >= crit_pct:
                process_info['issues'].append({
                    'severity': 'CRITICAL',
                    'resource': 'address_space',
                    'message': f'Address space at {pct_used:.1f}% of limit '
                              f'({vm_size // (1024*1024)}MB/'
                              f'{soft_limit // (1024*1024)}MB)'
                })
            elif pct_used >= warn_pct:
                process_info['issues'].append({
                    'severity': 'WARNING',
                    'resource': 'address_space',
                    'message': f'Address space at {pct_used:.1f}% of limit '
                              f'({vm_size // (1024*1024)}MB/'
                              f'{soft_limit // (1024*1024)}MB)'
                })

    # Check stack size
    if 'VmStk' in status and 'Max stack size' in limits:
        stack_size = status['VmStk']
        limit = limits['Max stack size']
        soft_limit = limit['soft']
        if soft_limit is not None and soft_limit > 0:
            pct_used = (stack_size / soft_limit) * 100
            process_info['metrics']['stack_size'] = {
                'current': stack_size,
                'soft_limit': soft_limit,
                'hard_limit': limit['hard'],
                'percent_used': round(pct_used, 1)
            }

            if pct_used >= crit_pct:
                process_info['issues'].append({
                    'severity': 'CRITICAL',
                    'resource': 'stack_size',
                    'message': f'Stack size at {pct_used:.1f}% of limit '
                              f'({stack_size // 1024}KB/'
                              f'{soft_limit // 1024}KB)'
                })
            elif pct_used >= warn_pct:
                process_info['issues'].append({
                    'severity': 'WARNING',
                    'resource': 'stack_size',
                    'message': f'Stack size at {pct_used:.1f}% of limit '
                              f'({stack_size // 1024}KB/'
                              f'{soft_limit // 1024}KB)'
                })

    # Check thread count (stored per-process from /proc/[pid]/status)
    thread_count = status.get('Threads', get_thread_count(pid))
    if thread_count and thread_count > 0 and 'Max processes' in limits:
        limit = limits['Max processes']
        soft_limit = limit['soft']
        # Note: RLIMIT_NPROC is per-user, not per-process, so this is approximate
        if soft_limit is not None and soft_limit > 0:
            # For thread count, we track but don't alarm on per-process basis
            # since NPROC is user-wide
            process_info['metrics']['threads'] = {
                'current': thread_count,
                'nproc_limit': soft_limit
            }

    return process_info


def filter_by_name(processes, name_filter):
    """Filter processes by name pattern.

    Args:
        processes: List of process info dicts
        name_filter: Name to match (case-insensitive, partial match)

    Returns:
        list: Filtered processes
    """
    name_lower = name_filter.lower()
    return [p for p in processes if name_lower in p['name'].lower()]


def output_plain(results, verbose=False, warn_only=False):
    """Output results in plain text format."""
    processes = results['processes']
    issues_found = results['issues_found']

    if not warn_only:
        print(f"Process Limits Monitor")
        print(f"=" * 60)
        print(f"Processes scanned: {results['total_scanned']}")
        print(f"Processes with issues: {results['processes_with_issues']}")
        print()

    if warn_only:
        # Only show processes with issues
        processes = [p for p in processes if p['issues']]

    for proc in processes:
        if not proc['issues'] and warn_only:
            continue

        print(f"PID {proc['pid']} ({proc['name']}) - User: {proc['user']}")

        if proc['issues']:
            for issue in proc['issues']:
                print(f"  [{issue['severity']}] {issue['message']}")
        elif verbose:
            # Show metrics even without issues
            for metric, data in proc['metrics'].items():
                if 'percent_used' in data:
                    print(f"  {metric}: {data['percent_used']}% "
                          f"({data['current']}/{data['soft_limit']})")
        print()

    if not processes and warn_only:
        print("No processes at risk.")

    if issues_found:
        print("Status: ISSUES DETECTED")
    else:
        print("Status: OK")


def output_json(results):
    """Output results in JSON format."""
    print(json.dumps(results, indent=2))


def output_table(results, warn_only=False):
    """Output results in table format."""
    processes = results['processes']

    if warn_only:
        processes = [p for p in processes if p['issues']]

    if not processes:
        print("No processes with limit concerns found.")
        return

    print(f"{'PID':<8} {'Name':<20} {'User':<12} {'FD%':<8} "
          f"{'VM%':<8} {'Stack%':<8} {'Issues':<10}")
    print("-" * 80)

    for proc in processes:
        fd_pct = proc['metrics'].get('open_files', {}).get('percent_used', '-')
        vm_pct = proc['metrics'].get('address_space', {}).get('percent_used', '-')
        stk_pct = proc['metrics'].get('stack_size', {}).get('percent_used', '-')

        fd_str = f"{fd_pct}" if fd_pct != '-' else '-'
        vm_str = f"{vm_pct}" if vm_pct != '-' else '-'
        stk_str = f"{stk_pct}" if stk_pct != '-' else '-'
        issue_count = len(proc['issues'])

        print(f"{proc['pid']:<8} {proc['name']:<20} {proc['user']:<12} "
              f"{fd_str:<8} {vm_str:<8} {stk_str:<8} {issue_count:<10}")

    print()
    print(f"Total: {len(processes)} processes shown")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor per-process resource limits and detect at-risk processes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         # Check all processes
  %(prog)s --name nginx            # Check only nginx processes
  %(prog)s --warn 70 --crit 90     # Custom thresholds
  %(prog)s --format json           # JSON output for monitoring
  %(prog)s --warn-only             # Only show processes with issues
  %(prog)s --top 10                # Show top 10 by resource usage

Monitored limits:
  - Open files (RLIMIT_NOFILE)
  - Address space (RLIMIT_AS)
  - Stack size (RLIMIT_STACK)

Note: Requires read access to /proc/[pid]/ directories.
      Run as root to check all processes.

Exit codes:
  0 - All processes within safe limits
  1 - Processes found at risk
  2 - Usage error or /proc not available
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
        help='Show detailed metrics for all processes'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show processes with warnings or critical issues'
    )

    parser.add_argument(
        '--warn',
        type=int,
        default=80,
        metavar='PCT',
        help='Warning threshold percentage (default: 80)'
    )

    parser.add_argument(
        '--crit',
        type=int,
        default=95,
        metavar='PCT',
        help='Critical threshold percentage (default: 95)'
    )

    parser.add_argument(
        '--name',
        type=str,
        metavar='PATTERN',
        help='Filter processes by name (case-insensitive partial match)'
    )

    parser.add_argument(
        '--top',
        type=int,
        metavar='N',
        help='Show only top N processes by file descriptor usage'
    )

    args = parser.parse_args()

    # Validate thresholds
    if not (0 < args.warn < 100):
        print("Error: --warn must be between 1 and 99", file=sys.stderr)
        sys.exit(2)

    if not (0 < args.crit <= 100):
        print("Error: --crit must be between 1 and 100", file=sys.stderr)
        sys.exit(2)

    if args.crit <= args.warn:
        print("Error: --crit must be greater than --warn", file=sys.stderr)
        sys.exit(2)

    # Check /proc availability
    if not os.path.isdir('/proc'):
        print("Error: /proc filesystem not available (non-Linux system?)",
              file=sys.stderr)
        sys.exit(2)

    # Get all PIDs
    pids = get_all_pids()
    if not pids:
        print("Error: No processes found in /proc", file=sys.stderr)
        sys.exit(2)

    # Analyze processes
    processes = []
    for pid in pids:
        proc_info = analyze_process(pid, args.warn, args.crit)
        if proc_info:
            processes.append(proc_info)

    # Apply filters
    if args.name:
        processes = filter_by_name(processes, args.name)

    # Sort by file descriptor usage (highest first)
    processes.sort(
        key=lambda p: p['metrics'].get('open_files', {}).get('percent_used', 0),
        reverse=True
    )

    # Apply top N filter
    if args.top:
        processes = processes[:args.top]

    # Build results
    processes_with_issues = sum(1 for p in processes if p['issues'])
    results = {
        'total_scanned': len(pids),
        'processes_shown': len(processes),
        'processes_with_issues': processes_with_issues,
        'warn_threshold': args.warn,
        'crit_threshold': args.crit,
        'processes': processes,
        'issues_found': processes_with_issues > 0
    }

    # Output
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.verbose, args.warn_only)

    # Exit code
    sys.exit(1 if results['issues_found'] else 0)


if __name__ == '__main__':
    main()
