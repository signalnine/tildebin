#!/usr/bin/env python3
"""
Monitor file descriptor usage to detect exhaustion risk.

This script monitors system-wide and per-process file descriptor usage, which
is critical for preventing service failures caused by fd exhaustion. Running
out of file descriptors causes:

- "Too many open files" errors
- Failed network connections (each socket = 1 fd)
- Failed file operations
- Application crashes and service unavailability
- Database connection failures

The script checks:
- System-wide fd usage vs kernel limit (file-max)
- Per-process fd usage vs ulimit (for high consumers)
- Processes approaching their limits

Warning signs:
- System usage > 75%: Investigate high consumers
- System usage > 90%: Critical - new connections/files may fail
- Process using > 80% of its limit: Will soon hit ulimit
- Rapid fd growth: Possible fd leak

Remediation:
- Increase system limit: sysctl -w fs.file-max=2097152
- Increase process limit: ulimit -n 65535 (or /etc/security/limits.conf)
- Fix fd leaks in applications (unclosed files/sockets)
- Review and optimize connection pooling

Exit codes:
    0 - File descriptor usage is healthy
    1 - High usage detected (warning or critical)
    2 - Usage error or cannot read fd information
"""

import argparse
import sys
import json
import os
import glob


def read_proc_value(path, required=True, default=None):
    """Read a single value from /proc or /sys.

    Args:
        path: Full path to the file to read
        required: If True, exit on missing file; if False, return default
        default: Default value to return if file missing and not required

    Returns:
        str or int: Value read from the file, or default if not required and missing
    """
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        if required:
            print(f"Error: {path} not found", file=sys.stderr)
            sys.exit(2)
        return default
    except PermissionError:
        if required:
            print(f"Error: Permission denied reading {path}", file=sys.stderr)
            sys.exit(2)
        return default
    except Exception as e:
        if required:
            print(f"Error reading {path}: {e}", file=sys.stderr)
            sys.exit(2)
        return default


def get_system_fd_stats():
    """Get system-wide file descriptor statistics.

    Returns:
        dict: System fd statistics
    """
    # Read file-nr: allocated, unused (legacy), max
    file_nr = read_proc_value('/proc/sys/fs/file-nr')
    parts = file_nr.split()

    if len(parts) < 3:
        print("Error: Unexpected format in /proc/sys/fs/file-nr", file=sys.stderr)
        sys.exit(2)

    try:
        allocated = int(parts[0])
        # parts[1] is unused (always 0 in modern kernels)
        file_max = int(parts[2])
    except ValueError as e:
        print(f"Error: Invalid value in file-nr: {e}", file=sys.stderr)
        sys.exit(2)

    usage_percent = (allocated / file_max * 100) if file_max > 0 else 0
    available = file_max - allocated

    return {
        'allocated': allocated,
        'max': file_max,
        'available': available,
        'usage_percent': usage_percent
    }


def get_process_fd_info(pid):
    """Get file descriptor information for a specific process.

    Args:
        pid: Process ID

    Returns:
        dict or None: Process fd info, or None if process not accessible
    """
    try:
        # Count open fds
        fd_path = f'/proc/{pid}/fd'
        fd_count = len(os.listdir(fd_path))

        # Get process limits
        limits_path = f'/proc/{pid}/limits'
        limits_content = read_proc_value(limits_path, required=False)

        soft_limit = None
        hard_limit = None

        if limits_content:
            for line in limits_content.split('\n'):
                if 'Max open files' in line:
                    parts = line.split()
                    # Format: "Max open files" <soft> <hard> <units>
                    try:
                        soft_limit = int(parts[-3])
                        hard_limit = int(parts[-2])
                    except (ValueError, IndexError):
                        pass
                    break

        # Get command name
        comm_path = f'/proc/{pid}/comm'
        comm = read_proc_value(comm_path, required=False, default='unknown')

        # Get cmdline for more context
        cmdline_path = f'/proc/{pid}/cmdline'
        cmdline_raw = read_proc_value(cmdline_path, required=False, default='')
        cmdline = cmdline_raw.replace('\x00', ' ').strip()[:100] if cmdline_raw else comm

        usage_percent = None
        if soft_limit and soft_limit > 0:
            usage_percent = (fd_count / soft_limit * 100)

        return {
            'pid': pid,
            'comm': comm,
            'cmdline': cmdline,
            'fd_count': fd_count,
            'soft_limit': soft_limit,
            'hard_limit': hard_limit,
            'usage_percent': usage_percent
        }

    except PermissionError:
        return None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def get_top_fd_consumers(limit=10):
    """Get the top file descriptor consuming processes.

    Args:
        limit: Maximum number of processes to return

    Returns:
        list: List of process fd info dicts, sorted by fd count
    """
    processes = []

    try:
        for proc_dir in glob.glob('/proc/[0-9]*'):
            pid = int(os.path.basename(proc_dir))
            info = get_process_fd_info(pid)
            if info:
                processes.append(info)
    except Exception:
        pass

    # Sort by fd count descending
    processes.sort(key=lambda x: x['fd_count'], reverse=True)

    return processes[:limit]


def analyze_fd_usage(system_stats, processes, warn_threshold, crit_threshold,
                     process_warn_threshold):
    """Analyze file descriptor usage and return issues.

    Args:
        system_stats: System-wide fd statistics
        processes: List of process fd info
        warn_threshold: System warning threshold (percentage)
        crit_threshold: System critical threshold (percentage)
        process_warn_threshold: Process warning threshold (percentage)

    Returns:
        list: List of issue dictionaries
    """
    issues = []
    usage = system_stats['usage_percent']

    # Check system-wide thresholds
    if usage >= crit_threshold:
        issues.append({
            'severity': 'CRITICAL',
            'scope': 'system',
            'metric': 'system_fd_usage',
            'value': round(usage, 2),
            'threshold': crit_threshold,
            'message': f'System file descriptor usage critical: {usage:.1f}% '
                      f'({system_stats["allocated"]}/{system_stats["max"]}) - '
                      f'new files/sockets may fail to open'
        })
    elif usage >= warn_threshold:
        issues.append({
            'severity': 'WARNING',
            'scope': 'system',
            'metric': 'system_fd_usage',
            'value': round(usage, 2),
            'threshold': warn_threshold,
            'message': f'System file descriptor usage high: {usage:.1f}% '
                      f'({system_stats["allocated"]}/{system_stats["max"]}) - '
                      f'consider increasing fs.file-max'
        })

    # Check per-process thresholds
    for proc in processes:
        if proc['usage_percent'] and proc['usage_percent'] >= process_warn_threshold:
            severity = 'CRITICAL' if proc['usage_percent'] >= 95 else 'WARNING'
            issues.append({
                'severity': severity,
                'scope': 'process',
                'metric': 'process_fd_usage',
                'pid': proc['pid'],
                'comm': proc['comm'],
                'value': round(proc['usage_percent'], 2),
                'threshold': process_warn_threshold,
                'message': f'Process {proc["comm"]} (PID {proc["pid"]}) using '
                          f'{proc["usage_percent"]:.1f}% of fd limit '
                          f'({proc["fd_count"]}/{proc["soft_limit"]})'
            })

    return issues


def output_plain(system_stats, processes, issues, verbose, warn_only, top_n):
    """Output results in plain text format."""
    if not warn_only or issues:
        print(f"System FDs: {system_stats['allocated']} / {system_stats['max']} "
              f"({system_stats['usage_percent']:.1f}% used)")
        print(f"Available: {system_stats['available']} file descriptors")
        print()

        if verbose or not warn_only:
            print(f"Top {min(top_n, len(processes))} FD consumers:")
            for proc in processes[:top_n]:
                limit_info = ""
                if proc['soft_limit']:
                    limit_info = f" (limit: {proc['soft_limit']}, {proc['usage_percent']:.1f}%)"
                print(f"  PID {proc['pid']:>7}: {proc['fd_count']:>6} fds - {proc['comm']}{limit_info}")
            print()

    # Print issues
    for issue in issues:
        severity = issue['severity']
        message = issue['message']

        prefix = {
            'CRITICAL': '[CRITICAL]',
            'WARNING': '[WARNING]',
            'INFO': '[INFO]'
        }.get(severity, '[UNKNOWN]')

        print(f"{prefix} {message}")


def output_json(system_stats, processes, issues, verbose, top_n):
    """Output results in JSON format."""
    result = {
        'system': {
            'allocated': system_stats['allocated'],
            'max': system_stats['max'],
            'available': system_stats['available'],
            'usage_percent': round(system_stats['usage_percent'], 2)
        },
        'issues': issues
    }

    if verbose:
        result['top_consumers'] = [
            {
                'pid': p['pid'],
                'comm': p['comm'],
                'fd_count': p['fd_count'],
                'soft_limit': p['soft_limit'],
                'usage_percent': round(p['usage_percent'], 2) if p['usage_percent'] else None
            }
            for p in processes[:top_n]
        ]

    print(json.dumps(result, indent=2))


def output_table(system_stats, processes, issues, verbose, warn_only, top_n):
    """Output results in table format."""
    if not warn_only or issues:
        print("=" * 75)
        print("FILE DESCRIPTOR USAGE STATUS")
        print("=" * 75)
        print(f"{'Metric':<30} {'Value':<25} {'Status':<15}")
        print("-" * 75)

        # Determine status
        usage = system_stats['usage_percent']
        if usage >= 90:
            status = "CRITICAL"
        elif usage >= 75:
            status = "WARNING"
        else:
            status = "OK"

        print(f"{'Allocated FDs':<30} {system_stats['allocated']:<25} {status:<15}")
        print(f"{'Maximum FDs (file-max)':<30} {system_stats['max']:<25}")
        print(f"{'Available FDs':<30} {system_stats['available']:<25}")
        print(f"{'Usage':<30} {usage:.1f}%{'':<20}")
        print("=" * 75)
        print()

        if verbose or not warn_only:
            print(f"TOP {min(top_n, len(processes))} FILE DESCRIPTOR CONSUMERS")
            print("=" * 75)
            print(f"{'PID':<10} {'FD Count':<12} {'Limit':<12} {'Usage %':<12} {'Command':<25}")
            print("-" * 75)

            for proc in processes[:top_n]:
                limit_str = str(proc['soft_limit']) if proc['soft_limit'] else 'N/A'
                usage_str = f"{proc['usage_percent']:.1f}%" if proc['usage_percent'] else 'N/A'
                print(f"{proc['pid']:<10} {proc['fd_count']:<12} {limit_str:<12} "
                      f"{usage_str:<12} {proc['comm'][:25]:<25}")

            print("=" * 75)
            print()

    # Print issues
    if issues:
        print("ISSUES DETECTED")
        print("=" * 75)
        for issue in issues:
            print(f"[{issue['severity']}] {issue['message']}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor file descriptor usage to detect exhaustion risk',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check fd usage with default thresholds
  %(prog)s --warn 80 --crit 95  # Custom thresholds
  %(prog)s --format json        # JSON output for monitoring tools
  %(prog)s --verbose            # Show top fd consumers
  %(prog)s --top 20             # Show top 20 consumers
  %(prog)s --warn-only          # Only show warnings/errors

Thresholds:
  --warn: System usage percentage to trigger warning (default: 75)
  --crit: System usage percentage to trigger critical alert (default: 90)
  --process-warn: Per-process usage percentage to warn (default: 80)

Common remediation:
  # Increase system-wide limit
  sysctl -w fs.file-max=2097152

  # Make permanent in /etc/sysctl.conf
  fs.file-max = 2097152

  # Increase per-process limit (in /etc/security/limits.conf)
  * soft nofile 65535
  * hard nofile 65535

  # Check for fd leaks in a process
  ls -la /proc/<pid>/fd | wc -l
  lsof -p <pid> | wc -l

Exit codes:
  0 - File descriptor usage is healthy
  1 - High usage detected
  2 - Usage error or cannot read fd information
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
        help='Show top file descriptor consumers'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--warn',
        type=float,
        default=75.0,
        metavar='PERCENT',
        help='System warning threshold for usage percentage (default: 75)'
    )

    parser.add_argument(
        '--crit',
        type=float,
        default=90.0,
        metavar='PERCENT',
        help='System critical threshold for usage percentage (default: 90)'
    )

    parser.add_argument(
        '--process-warn',
        type=float,
        default=80.0,
        metavar='PERCENT',
        help='Per-process warning threshold for usage percentage (default: 80)'
    )

    parser.add_argument(
        '--top',
        type=int,
        default=10,
        metavar='N',
        help='Number of top fd consumers to show (default: 10)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn < 0 or args.warn > 100:
        print("Error: --warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.crit < 0 or args.crit > 100:
        print("Error: --crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.crit <= args.warn:
        print("Error: --crit must be greater than --warn", file=sys.stderr)
        sys.exit(2)

    if args.process_warn < 0 or args.process_warn > 100:
        print("Error: --process-warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.top < 1:
        print("Error: --top must be at least 1", file=sys.stderr)
        sys.exit(2)

    # Gather information
    system_stats = get_system_fd_stats()
    processes = get_top_fd_consumers(limit=max(args.top, 20))  # Get extra for analysis

    # Analyze usage
    issues = analyze_fd_usage(
        system_stats, processes,
        args.warn, args.crit, args.process_warn
    )

    # Output results
    if args.format == 'json':
        output_json(system_stats, processes, issues, args.verbose, args.top)
    elif args.format == 'table':
        output_table(system_stats, processes, issues, args.verbose, args.warn_only, args.top)
    else:  # plain
        output_plain(system_stats, processes, issues, args.verbose, args.warn_only, args.top)

    # Determine exit code based on issues
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
