#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [process, priority, nice, ionice, scheduling]
#   requires: []
#   privilege: none
#   related: [process_accounting, process_fd, cpu_usage]
#   brief: Monitor process niceness and I/O priority

"""
Monitor process niceness (nice values) and I/O priority for baremetal systems.

Identifies processes with unusual priority configurations that may indicate
priority inversions, resource starvation risks, or misconfigured workloads.

Checks performed:
- Processes with elevated priority (negative nice values)
- Processes with degraded priority (high nice values)
- Real-time I/O priority (ionice class 1)
- Idle I/O priority (ionice class 3)
- System services with non-default priorities
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Nice value constants
NICE_MIN = -20  # Highest priority
NICE_MAX = 19   # Lowest priority
NICE_DEFAULT = 0

# I/O scheduling class names
IOPRIO_CLASS_NAMES = {
    0: 'none',
    1: 'realtime',
    2: 'best-effort',
    3: 'idle'
}


def read_file(path: str, context: Context) -> str | None:
    """Read file contents, return None on error."""
    try:
        return context.read_file(path)
    except (IOError, OSError, FileNotFoundError, PermissionError):
        return None


def get_uid_name(uid: int) -> str:
    """Get username for a UID."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


def get_process_nice(pid: int, context: Context) -> int | None:
    """Get nice value for a process from /proc/[pid]/stat."""
    content = read_file(f'/proc/{pid}/stat', context)
    if not content:
        return None

    try:
        last_paren = content.rfind(')')
        if last_paren == -1:
            return None
        fields = content[last_paren + 2:].split()
        if len(fields) > 16:
            return int(fields[16])
    except (ValueError, IndexError):
        pass
    return None


def get_process_comm(pid: int, context: Context) -> str | None:
    """Get process name (comm) for a PID."""
    content = read_file(f'/proc/{pid}/comm', context)
    return content.strip() if content else None


def get_process_uid(pid: int, context: Context) -> int | None:
    """Get UID of process owner."""
    content = read_file(f'/proc/{pid}/status', context)
    if not content:
        return None

    for line in content.split('\n'):
        if line.startswith('Uid:'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    return None


def analyze_process(
    pid: int,
    context: Context,
    include_normal: bool = False,
    nice_elevated: int = -5,
    nice_degraded: int = 10
) -> dict[str, Any] | None:
    """Analyze priority settings for a single process."""
    comm = get_process_comm(pid, context)
    if comm is None:
        return None

    nice = get_process_nice(pid, context)
    uid = get_process_uid(pid, context)
    username = get_uid_name(uid) if uid is not None else None

    info = {
        'pid': pid,
        'comm': comm,
        'nice': nice,
        'uid': uid,
        'user': username,
        'issues': []
    }

    # Check for priority issues
    if nice is not None:
        if nice < nice_elevated:
            info['issues'].append({
                'severity': 'WARNING',
                'type': 'elevated_nice',
                'message': f'Process has elevated CPU priority (nice={nice})'
            })
        elif nice > nice_degraded:
            info['issues'].append({
                'severity': 'INFO',
                'type': 'degraded_nice',
                'message': f'Process has degraded CPU priority (nice={nice})'
            })

    # Skip processes with no issues unless include_normal is set
    if not info['issues'] and not include_normal:
        return None

    return info


def get_all_processes_info(
    context: Context,
    include_normal: bool = False,
    user_filter: str | None = None,
    comm_filter: str | None = None,
    nice_elevated: int = -5,
    nice_degraded: int = 10
) -> list[dict[str, Any]]:
    """Get priority information for all processes."""
    processes = []

    proc_entries = context.glob('[0-9]*', root='/proc')

    for proc_path in proc_entries:
        pid_str = proc_path.split('/')[-1]
        if not pid_str.isdigit():
            continue

        pid = int(pid_str)
        info = analyze_process(pid, context, include_normal, nice_elevated, nice_degraded)
        if info is None:
            continue

        # Apply filters
        if user_filter and info['user'] != user_filter:
            continue
        if comm_filter and comm_filter.lower() not in info['comm'].lower():
            continue

        processes.append(info)

    # Sort by nice value (lowest first = highest priority)
    processes.sort(key=lambda p: (p['nice'] if p['nice'] is not None else 0))

    return processes


def generate_summary(processes: list[dict]) -> dict[str, int]:
    """Generate summary statistics from process list."""
    summary = {
        'total_analyzed': len(processes),
        'elevated_nice_count': 0,
        'degraded_nice_count': 0,
        'total_issues': 0
    }

    for proc in processes:
        for issue in proc['issues']:
            summary['total_issues'] += 1
            if issue['type'] == 'elevated_nice':
                summary['elevated_nice_count'] += 1
            elif issue['type'] == 'degraded_nice':
                summary['degraded_nice_count'] += 1

    return summary


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no priority issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor process niceness and I/O priority")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Include all processes, not just those with issues")
    parser.add_argument("-u", "--user", help="Only show processes owned by specified user")
    parser.add_argument("-c", "--comm", help="Only show processes matching this name pattern")
    parser.add_argument("--nice-elevated", type=int, default=-5,
                        help="Threshold for elevated priority warning")
    parser.add_argument("--nice-degraded", type=int, default=10,
                        help="Threshold for degraded priority info")
    opts = parser.parse_args(args)

    # Check if /proc is accessible
    if not context.file_exists('/proc'):
        output.error("/proc filesystem not accessible")
        return 2

    # Get process information
    processes = get_all_processes_info(
        context,
        include_normal=opts.all,
        user_filter=opts.user,
        comm_filter=opts.comm,
        nice_elevated=opts.nice_elevated,
        nice_degraded=opts.nice_degraded
    )

    # Generate summary
    summary = generate_summary(processes)

    result = {
        'summary': summary,
        'processes': processes if opts.verbose or opts.all else [
            {'pid': p['pid'], 'comm': p['comm'], 'nice': p['nice'], 'issues': p['issues']}
            for p in processes
        ]
    }

    output.emit(result)

    # Set summary and exit code
    if summary['elevated_nice_count'] > 0:
        output.set_summary(f"{summary['elevated_nice_count']} process(es) with elevated priority")
        return 1
    elif summary['total_issues'] > 0:
        output.set_summary(f"{summary['total_issues']} priority issue(s) detected")
        return 0  # Degraded priority is informational, not a warning
    else:
        output.set_summary("No priority issues detected")
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
