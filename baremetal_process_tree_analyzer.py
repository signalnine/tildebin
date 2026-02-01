#!/usr/bin/env python3
"""
Analyze the process tree for anomalies in large-scale baremetal environments.

This script examines the system process hierarchy to detect:
- Orphan processes (reparented to init/systemd)
- Deep process trees (potential fork bombs or runaway spawning)
- Processes with excessive children
- Long-running orphan processes
- Process tree depth distribution

Critical for baremetal environments where runaway process spawning can
exhaust system resources and cause cascading failures.

Exit codes:
    0 - No anomalies detected
    1 - Anomalies or warnings found
    2 - Usage error or missing dependency
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime


def get_boot_time():
    """Get system boot time in seconds since epoch."""
    try:
        with open('/proc/stat', 'r') as f:
            for line in f:
                if line.startswith('btime '):
                    return int(line.split()[1])
    except (IOError, ValueError):
        return 0
    return 0


def get_process_info(pid):
    """Get process information from /proc."""
    try:
        # Read stat file for basic info
        with open(f'/proc/{pid}/stat', 'r') as f:
            stat_line = f.read()

        # Parse carefully - comm can contain spaces and parentheses
        # Format: pid (comm) state ppid ...
        first_paren = stat_line.index('(')
        last_paren = stat_line.rindex(')')
        comm = stat_line[first_paren + 1:last_paren]
        fields = stat_line[last_paren + 2:].split()

        ppid = int(fields[1])  # Parent PID is field 4 (index 1 after state)
        state = fields[0]
        start_time = int(fields[19])  # Start time in jiffies

        # Read cmdline for full command
        try:
            with open(f'/proc/{pid}/cmdline', 'r') as f:
                cmdline = f.read().replace('\x00', ' ').strip()
        except (IOError, PermissionError):
            cmdline = comm

        # Get UID
        try:
            uid = os.stat(f'/proc/{pid}').st_uid
        except (OSError, PermissionError):
            uid = -1

        return {
            'pid': pid,
            'ppid': ppid,
            'comm': comm,
            'cmdline': cmdline[:200] if cmdline else comm,
            'state': state,
            'start_time': start_time,
            'uid': uid
        }
    except (IOError, ValueError, IndexError, PermissionError):
        return None


def get_all_processes():
    """Get information about all running processes."""
    processes = {}
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pid = int(entry)
                info = get_process_info(pid)
                if info:
                    processes[pid] = info
    except (IOError, PermissionError):
        pass
    return processes


def build_process_tree(processes):
    """Build parent-child relationships."""
    children = defaultdict(list)
    for pid, info in processes.items():
        ppid = info['ppid']
        if ppid in processes or ppid == 0:
            children[ppid].append(pid)
    return children


def calculate_tree_depth(pid, children, cache=None):
    """Calculate the maximum depth of a process subtree."""
    if cache is None:
        cache = {}

    if pid in cache:
        return cache[pid]

    if pid not in children or not children[pid]:
        cache[pid] = 0
        return 0

    max_child_depth = 0
    for child_pid in children[pid]:
        child_depth = calculate_tree_depth(child_pid, children, cache)
        max_child_depth = max(max_child_depth, child_depth)

    cache[pid] = max_child_depth + 1
    return cache[pid]


def get_username(uid):
    """Get username from UID."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


def analyze_processes(processes, children, thresholds):
    """Analyze process tree for anomalies."""
    issues = []
    warnings = []
    stats = {
        'total_processes': len(processes),
        'orphan_count': 0,
        'deep_trees': 0,
        'max_depth': 0,
        'max_children': 0,
        'depth_distribution': defaultdict(int)
    }

    boot_time = get_boot_time()
    clock_ticks = os.sysconf('SC_CLK_TCK')
    now = datetime.now().timestamp()

    # Find init process (PID 1)
    init_pid = 1

    # Analyze each process
    depth_cache = {}
    for pid, info in processes.items():
        if pid == init_pid:
            continue

        ppid = info['ppid']

        # Check for orphan processes (reparented to init)
        if ppid == init_pid and pid != init_pid:
            # Calculate process age
            if boot_time > 0 and clock_ticks > 0:
                process_start = boot_time + (info['start_time'] / clock_ticks)
                age_seconds = now - process_start
                age_hours = age_seconds / 3600
            else:
                age_hours = 0

            # Skip kernel threads and known system processes
            if info['comm'].startswith('[') and info['comm'].endswith(']'):
                continue

            # Skip common system daemons
            known_init_children = {
                'systemd', 'init', 'bash', 'sshd', 'cron', 'crond',
                'rsyslogd', 'dbus-daemon', 'polkitd', 'auditd',
                'NetworkManager', 'dockerd', 'containerd', 'kubelet',
                'agetty', 'login', 'getty', 'lightdm', 'gdm',
                'ssh-agent', 'gpg-agent', 'rpcbind', 'smartd',
                'systemd-logind', 'systemd-udevd', 'systemd-journald',
                'watchdog-mux', 'zed', 'ksmtuned', 'lvmetad',
                'pve-lxc-syscall', 'pvedaemon', 'pveproxy', 'pvestatd',
                'spiceproxy', 'corosync', 'pmxcfs', 'lxcfs',
                'ntpd', 'chronyd', 'dhclient', 'acpid', 'atd'
            }
            if info['comm'] in known_init_children:
                continue

            # This looks like an orphan
            if age_hours > thresholds['orphan_age_hours']:
                stats['orphan_count'] += 1
                issues.append({
                    'type': 'orphan_process',
                    'pid': pid,
                    'comm': info['comm'],
                    'cmdline': info['cmdline'],
                    'age_hours': round(age_hours, 1),
                    'user': get_username(info['uid'])
                })
            elif age_hours > thresholds['orphan_warn_hours']:
                warnings.append({
                    'type': 'potential_orphan',
                    'pid': pid,
                    'comm': info['comm'],
                    'age_hours': round(age_hours, 1)
                })

        # Calculate subtree depth for this process
        depth = calculate_tree_depth(pid, children, depth_cache)
        stats['depth_distribution'][depth] += 1
        stats['max_depth'] = max(stats['max_depth'], depth)

        # Check for deep process trees
        if depth >= thresholds['max_depth']:
            stats['deep_trees'] += 1
            issues.append({
                'type': 'deep_tree',
                'pid': pid,
                'comm': info['comm'],
                'depth': depth,
                'cmdline': info['cmdline']
            })

        # Check for processes with too many children
        child_count = len(children.get(pid, []))
        stats['max_children'] = max(stats['max_children'], child_count)

        if child_count >= thresholds['max_children']:
            issues.append({
                'type': 'excessive_children',
                'pid': pid,
                'comm': info['comm'],
                'child_count': child_count,
                'cmdline': info['cmdline']
            })

    return issues, warnings, stats


def print_plain(issues, warnings, stats, verbose):
    """Print results in plain text format."""
    print(f"Process Tree Analysis")
    print(f"=====================")
    print(f"Total processes: {stats['total_processes']}")
    print(f"Maximum tree depth: {stats['max_depth']}")
    print(f"Maximum children per process: {stats['max_children']}")
    print()

    if issues:
        print("Issues Found:")
        print("-" * 40)
        for issue in issues:
            if issue['type'] == 'orphan_process':
                print(f"[ORPHAN] PID {issue['pid']}: {issue['comm']} "
                      f"(running {issue['age_hours']}h, user: {issue['user']})")
                if verbose:
                    print(f"  Command: {issue['cmdline']}")
            elif issue['type'] == 'deep_tree':
                print(f"[DEEP] PID {issue['pid']}: {issue['comm']} "
                      f"(depth: {issue['depth']})")
                if verbose:
                    print(f"  Command: {issue['cmdline']}")
            elif issue['type'] == 'excessive_children':
                print(f"[CHILDREN] PID {issue['pid']}: {issue['comm']} "
                      f"({issue['child_count']} children)")
                if verbose:
                    print(f"  Command: {issue['cmdline']}")
        print()

    if warnings:
        print("Warnings:")
        print("-" * 40)
        for warning in warnings:
            if warning['type'] == 'potential_orphan':
                print(f"[WARN] PID {warning['pid']}: {warning['comm']} "
                      f"(running {warning['age_hours']}h)")
        print()

    if verbose:
        print("Depth Distribution:")
        print("-" * 40)
        for depth in sorted(stats['depth_distribution'].keys()):
            count = stats['depth_distribution'][depth]
            print(f"  Depth {depth}: {count} processes")
        print()

    # Summary
    issue_count = len(issues)
    warning_count = len(warnings)
    if issue_count == 0 and warning_count == 0:
        print("Status: OK - No anomalies detected")
    else:
        print(f"Status: {issue_count} issue(s), {warning_count} warning(s)")


def print_json(issues, warnings, stats):
    """Print results in JSON format."""
    output = {
        'issues': issues,
        'warnings': warnings,
        'stats': {
            'total_processes': stats['total_processes'],
            'orphan_count': stats['orphan_count'],
            'deep_trees': stats['deep_trees'],
            'max_depth': stats['max_depth'],
            'max_children': stats['max_children'],
            'depth_distribution': dict(stats['depth_distribution'])
        },
        'summary': {
            'issue_count': len(issues),
            'warning_count': len(warnings),
            'healthy': len(issues) == 0 and len(warnings) == 0
        }
    }
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description='Analyze the process tree for anomalies',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Analyze process tree with defaults
  %(prog)s --warn-only              # Show only issues and warnings
  %(prog)s --format json            # JSON output for automation
  %(prog)s --max-depth 15           # Custom depth threshold
  %(prog)s --orphan-age 12          # Flag orphans older than 12 hours
  %(prog)s -v                       # Verbose output with depth distribution

Anomalies Detected:
  Orphan processes     - Processes reparented to init (PID 1) that aren't
                        known system services and have been running too long
  Deep process trees   - Process hierarchies exceeding depth threshold
                        (potential fork bombs or runaway spawning)
  Excessive children   - Processes with too many direct child processes

Exit codes:
  0 - No anomalies detected
  1 - Anomalies or warnings found
  2 - Usage error
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show if issues or warnings exist'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed output including depth distribution'
    )

    parser.add_argument(
        '--max-depth',
        type=int,
        default=20,
        metavar='N',
        help='Flag processes with tree depth >= N (default: 20)'
    )

    parser.add_argument(
        '--max-children',
        type=int,
        default=100,
        metavar='N',
        help='Flag processes with >= N children (default: 100)'
    )

    parser.add_argument(
        '--orphan-age',
        type=float,
        default=24.0,
        metavar='HOURS',
        help='Flag orphan processes older than HOURS (default: 24)'
    )

    parser.add_argument(
        '--orphan-warn',
        type=float,
        default=4.0,
        metavar='HOURS',
        help='Warn about orphan processes older than HOURS (default: 4)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.max_depth < 1:
        print("Error: --max-depth must be >= 1", file=sys.stderr)
        sys.exit(2)

    if args.max_children < 1:
        print("Error: --max-children must be >= 1", file=sys.stderr)
        sys.exit(2)

    if args.orphan_age < 0:
        print("Error: --orphan-age must be >= 0", file=sys.stderr)
        sys.exit(2)

    thresholds = {
        'max_depth': args.max_depth,
        'max_children': args.max_children,
        'orphan_age_hours': args.orphan_age,
        'orphan_warn_hours': args.orphan_warn
    }

    # Get process information
    processes = get_all_processes()

    if not processes:
        print("Error: Could not read process information", file=sys.stderr)
        sys.exit(2)

    # Build process tree
    children = build_process_tree(processes)

    # Analyze processes
    issues, warnings, stats = analyze_processes(processes, children, thresholds)

    # Print results
    if args.format == 'json':
        print_json(issues, warnings, stats)
    else:
        if not args.warn_only or issues or warnings:
            print_plain(issues, warnings, stats, args.verbose)
        elif args.warn_only and not issues and not warnings:
            print("No anomalies detected")

    # Determine exit code
    sys.exit(1 if issues or warnings else 0)


if __name__ == '__main__':
    main()
