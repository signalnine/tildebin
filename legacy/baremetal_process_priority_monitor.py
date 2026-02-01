#!/usr/bin/env python3
"""
Monitor process niceness (nice values) and I/O priority for baremetal systems.

This script identifies processes with unusual priority configurations that may
indicate priority inversions, resource starvation risks, or misconfigured
workloads. Essential for systems running mixed workloads (batch + interactive)
where priority settings directly impact performance.

Checks performed:
- Processes with elevated priority (negative nice values)
- Processes with degraded priority (high nice values)
- Real-time I/O priority (ionice class 1)
- Idle I/O priority (ionice class 3)
- Processes that may starve or be starved
- System services with non-default priorities

Exit codes:
    0 - No priority issues detected
    1 - Priority warnings or issues found
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import glob


# Nice value constants
NICE_MIN = -20  # Highest priority
NICE_MAX = 19   # Lowest priority
NICE_DEFAULT = 0

# I/O scheduling class constants (from linux/ioprio.h)
IOPRIO_CLASS_NONE = 0
IOPRIO_CLASS_RT = 1      # Real-time
IOPRIO_CLASS_BE = 2      # Best-effort (default)
IOPRIO_CLASS_IDLE = 3    # Idle

IOPRIO_CLASS_NAMES = {
    0: 'none',
    1: 'realtime',
    2: 'best-effort',
    3: 'idle'
}

# Thresholds for warnings
NICE_ELEVATED_THRESHOLD = -5   # Nice values below this are elevated priority
NICE_DEGRADED_THRESHOLD = 10   # Nice values above this are degraded priority


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
            # Replace null bytes with spaces
            return cmdline.replace('\x00', ' ').strip()
    except (IOError, OSError):
        return None


def get_process_nice(pid):
    """Get nice value for a process from /proc/[pid]/stat."""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            stat = f.read()
            # Format: pid (comm) state ... nice ...
            # Nice value is field 19 (0-indexed: 18)
            # Need to handle comm which may contain spaces/parens
            # Find the last ')' to skip the comm field
            last_paren = stat.rfind(')')
            if last_paren == -1:
                return None
            fields = stat[last_paren + 2:].split()
            # Nice is field 16 after the closing paren (fields index 16)
            if len(fields) > 16:
                return int(fields[16])
    except (IOError, OSError, ValueError, IndexError):
        pass
    return None


def get_process_ioprio(pid, use_ionice=False):
    """Get I/O priority for a process.

    Returns tuple of (class, priority) or (None, None) on error.
    Class: 0=none, 1=realtime, 2=best-effort, 3=idle
    Priority: 0-7 within class (0=highest)

    Args:
        pid: Process ID
        use_ionice: If True, use ionice command (slower but more reliable)
    """
    try:
        # Read from /proc/[pid]/io_priority if available (custom kernels)
        ioprio_path = f'/proc/{pid}/ioprio'
        if os.path.exists(ioprio_path):
            with open(ioprio_path, 'r') as f:
                val = int(f.read().strip())
                ioprio_class = (val >> 13) & 0x3
                ioprio_data = val & 0x1fff
                return ioprio_class, ioprio_data

        # Only use ionice if explicitly requested (it's slow)
        if use_ionice:
            import subprocess
            result = subprocess.run(
                ['ionice', '-p', str(pid)],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                # Parse output like "best-effort: prio 4" or "realtime: prio 0"
                if ':' in output:
                    class_part = output.split(':')[0].strip().lower()
                    prio_part = output.split(':')[1] if ':' in output else ''

                    # Map class name to number
                    class_map = {
                        'none': 0,
                        'realtime': 1,
                        'best-effort': 2,
                        'idle': 3
                    }
                    ioprio_class = class_map.get(class_part, 2)

                    # Extract priority number
                    ioprio_data = 4  # default
                    if 'prio' in prio_part:
                        try:
                            ioprio_data = int(prio_part.split()[-1])
                        except (ValueError, IndexError):
                            pass

                    return ioprio_class, ioprio_data

    except (IOError, OSError, ValueError, FileNotFoundError):
        pass
    except Exception:
        # Catch subprocess exceptions if ionice was used
        pass

    return None, None


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


def analyze_process(pid, include_normal=False, nice_elevated=-5, nice_degraded=10,
                    check_ioprio=False):
    """Analyze priority settings for a single process.

    Args:
        pid: Process ID
        include_normal: Include processes with normal priority settings
        nice_elevated: Threshold for elevated priority warning
        nice_degraded: Threshold for degraded priority info
        check_ioprio: If True, check I/O priority (slower)

    Returns:
        dict with process info and any issues, or None if process not accessible
    """
    comm = get_process_comm(pid)
    if comm is None:
        return None

    nice = get_process_nice(pid)
    ioprio_class, ioprio_data = get_process_ioprio(pid, use_ionice=check_ioprio)
    uid = get_process_uid(pid)
    username = get_username(uid)
    cmdline = get_process_cmdline(pid)

    info = {
        'pid': pid,
        'comm': comm,
        'cmdline': cmdline[:100] if cmdline else '',
        'nice': nice,
        'ioprio_class': ioprio_class,
        'ioprio_class_name': IOPRIO_CLASS_NAMES.get(ioprio_class, 'unknown'),
        'ioprio_data': ioprio_data,
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

    if ioprio_class is not None:
        if ioprio_class == IOPRIO_CLASS_RT:
            info['issues'].append({
                'severity': 'WARNING',
                'type': 'realtime_io',
                'message': f'Process has real-time I/O priority (class={ioprio_class}, prio={ioprio_data})'
            })
        elif ioprio_class == IOPRIO_CLASS_IDLE:
            info['issues'].append({
                'severity': 'INFO',
                'type': 'idle_io',
                'message': f'Process has idle I/O priority'
            })

    # Skip processes with no issues unless include_normal is set
    if not info['issues'] and not include_normal:
        return None

    return info


def get_all_processes_info(include_normal=False, user_filter=None,
                           comm_filter=None, nice_elevated=-5, nice_degraded=10,
                           check_ioprio=False):
    """Get priority information for all processes.

    Args:
        include_normal: Include processes with normal priority
        user_filter: Only include processes owned by this user
        comm_filter: Only include processes matching this name pattern
        nice_elevated: Threshold for elevated priority warning
        nice_degraded: Threshold for degraded priority info
        check_ioprio: If True, check I/O priority (slower)

    Returns:
        list of process info dicts
    """
    processes = []
    pids = get_process_list()

    for pid in pids:
        info = analyze_process(pid, include_normal, nice_elevated, nice_degraded,
                               check_ioprio)
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


def generate_summary(processes):
    """Generate summary statistics from process list."""
    summary = {
        'total_analyzed': len(processes),
        'elevated_nice_count': 0,
        'degraded_nice_count': 0,
        'realtime_io_count': 0,
        'idle_io_count': 0,
        'total_issues': 0
    }

    for proc in processes:
        for issue in proc['issues']:
            summary['total_issues'] += 1
            if issue['type'] == 'elevated_nice':
                summary['elevated_nice_count'] += 1
            elif issue['type'] == 'degraded_nice':
                summary['degraded_nice_count'] += 1
            elif issue['type'] == 'realtime_io':
                summary['realtime_io_count'] += 1
            elif issue['type'] == 'idle_io':
                summary['idle_io_count'] += 1

    return summary


def output_plain(processes, summary, verbose=False, warn_only=False):
    """Output results in plain text format."""
    if warn_only and not processes:
        return

    print("Process Priority Monitor")
    print("=" * 60)
    print(f"Processes with priority issues: {len(processes)}")
    print(f"  Elevated CPU priority (nice < {NICE_ELEVATED_THRESHOLD}): "
          f"{summary['elevated_nice_count']}")
    print(f"  Degraded CPU priority (nice > {NICE_DEGRADED_THRESHOLD}): "
          f"{summary['degraded_nice_count']}")
    print(f"  Real-time I/O: {summary['realtime_io_count']}")
    print(f"  Idle I/O: {summary['idle_io_count']}")
    print()

    if processes:
        print("Process Details:")
        print("-" * 60)

        for proc in processes:
            nice_str = str(proc['nice']) if proc['nice'] is not None else 'N/A'
            ioprio_str = f"{proc['ioprio_class_name']}"
            if proc['ioprio_data'] is not None:
                ioprio_str += f":{proc['ioprio_data']}"

            print(f"PID {proc['pid']}: {proc['comm']}")
            print(f"  User: {proc['user']}, Nice: {nice_str}, I/O: {ioprio_str}")

            if verbose and proc['cmdline']:
                print(f"  Cmd: {proc['cmdline'][:60]}...")

            for issue in proc['issues']:
                print(f"  [{issue['severity']}] {issue['message']}")

            print()


def output_json(processes, summary):
    """Output results in JSON format."""
    output = {
        'summary': summary,
        'processes': processes
    }
    print(json.dumps(output, indent=2))


def output_table(processes, summary, warn_only=False):
    """Output results in table format."""
    if warn_only and not processes:
        return

    print("=" * 80)
    print("PROCESS PRIORITY REPORT")
    print("=" * 80)
    print()

    # Summary table
    print(f"{'Metric':<40} {'Count':<10}")
    print("-" * 50)
    print(f"{'Processes with priority issues':<40} {len(processes):<10}")
    print(f"{'Elevated CPU priority':<40} {summary['elevated_nice_count']:<10}")
    print(f"{'Degraded CPU priority':<40} {summary['degraded_nice_count']:<10}")
    print(f"{'Real-time I/O priority':<40} {summary['realtime_io_count']:<10}")
    print(f"{'Idle I/O priority':<40} {summary['idle_io_count']:<10}")
    print()

    if processes:
        print("=" * 80)
        print(f"{'PID':<8} {'Nice':<6} {'I/O Class':<12} {'User':<12} {'Process':<20} {'Issues':<20}")
        print("-" * 80)

        for proc in processes:
            nice_str = str(proc['nice']) if proc['nice'] is not None else 'N/A'
            issue_count = len(proc['issues'])
            issue_str = f"{issue_count} issue(s)" if issue_count else "OK"

            print(f"{proc['pid']:<8} {nice_str:<6} {proc['ioprio_class_name']:<12} "
                  f"{(proc['user'] or 'N/A')[:12]:<12} {proc['comm'][:20]:<20} {issue_str:<20}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor process niceness and I/O priority settings',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Show processes with priority issues
  %(prog)s --all               # Show all processes including normal priority
  %(prog)s --user root         # Filter by user
  %(prog)s --format json       # JSON output for automation
  %(prog)s --warn-only         # Only output if issues found

Exit codes:
  0 - No priority issues detected
  1 - Priority warnings or issues found
  2 - Usage error

Priority Reference:
  Nice values: -20 (highest priority) to 19 (lowest priority), default 0
  I/O classes: realtime > best-effort > idle

Notes:
  - Elevated priority (nice < -5) may starve other processes
  - Real-time I/O priority can cause I/O starvation
  - Some priority queries require root or ionice command
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
        help='Show detailed process information including command line'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only produce output if priority issues are found'
    )

    parser.add_argument(
        '-a', '--all',
        action='store_true',
        help='Include all processes, not just those with priority issues'
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
        '--check-ioprio',
        action='store_true',
        help='Check I/O priority using ionice (slower, requires ionice command)'
    )

    parser.add_argument(
        '--nice-elevated',
        type=int,
        default=NICE_ELEVATED_THRESHOLD,
        help=f'Threshold for elevated priority warning (default: {NICE_ELEVATED_THRESHOLD})'
    )

    parser.add_argument(
        '--nice-degraded',
        type=int,
        default=NICE_DEGRADED_THRESHOLD,
        help=f'Threshold for degraded priority info (default: {NICE_DEGRADED_THRESHOLD})'
    )

    args = parser.parse_args()

    # Check if /proc is accessible
    if not os.path.isdir('/proc'):
        print("Error: /proc filesystem not accessible", file=sys.stderr)
        print("This tool requires Linux with procfs mounted", file=sys.stderr)
        sys.exit(2)

    # Get process information
    processes = get_all_processes_info(
        include_normal=args.all,
        user_filter=args.user,
        comm_filter=args.comm,
        nice_elevated=args.nice_elevated,
        nice_degraded=args.nice_degraded,
        check_ioprio=args.check_ioprio
    )

    # Generate summary
    summary = generate_summary(processes)

    # Check warn-only mode
    has_issues = summary['total_issues'] > 0 or summary['elevated_nice_count'] > 0

    if args.warn_only and not has_issues:
        sys.exit(0)

    # Output results
    if args.format == 'json':
        output_json(processes, summary)
    elif args.format == 'table':
        output_table(processes, summary, args.warn_only)
    else:
        output_plain(processes, summary, args.verbose, args.warn_only)

    # Exit code based on findings
    # Return 1 if elevated priority or realtime I/O found (potential issues)
    if summary['elevated_nice_count'] > 0 or summary['realtime_io_count'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
