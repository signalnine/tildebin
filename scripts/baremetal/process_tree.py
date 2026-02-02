#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [process, tree, orphan, fork-bomb]
#   requires: []
#   privilege: user
#   related: [process_tree_depth, process_swap]
#   brief: Analyze process tree for orphans and anomalies

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
"""

import argparse
import os
from collections import defaultdict
from datetime import datetime
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_boot_time() -> int:
    """Get system boot time in seconds since epoch."""
    try:
        with open('/proc/stat', 'r') as f:
            for line in f:
                if line.startswith('btime '):
                    return int(line.split()[1])
    except (IOError, ValueError):
        return 0
    return 0


def get_process_info(pid: int) -> dict[str, Any] | None:
    """Get process information from /proc."""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            stat_line = f.read()

        # Parse carefully - comm can contain spaces and parentheses
        first_paren = stat_line.index('(')
        last_paren = stat_line.rindex(')')
        comm = stat_line[first_paren + 1:last_paren]
        fields = stat_line[last_paren + 2:].split()

        ppid = int(fields[1])
        state = fields[0]
        start_time = int(fields[19])

        try:
            with open(f'/proc/{pid}/cmdline', 'r') as f:
                cmdline = f.read().replace('\x00', ' ').strip()
        except (IOError, PermissionError):
            cmdline = comm

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


def get_all_processes() -> dict[int, dict[str, Any]]:
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


def build_process_tree(processes: dict) -> dict[int, list[int]]:
    """Build parent-child relationships."""
    children = defaultdict(list)
    for pid, info in processes.items():
        ppid = info['ppid']
        if ppid in processes or ppid == 0:
            children[ppid].append(pid)
    return children


def calculate_tree_depth(pid: int, children: dict, cache: dict | None = None) -> int:
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


def get_username(uid: int) -> str:
    """Get username from UID."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


# Known system processes that are expected to have init as parent
KNOWN_INIT_CHILDREN = {
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


def analyze_processes(processes: dict, children: dict, thresholds: dict) -> tuple:
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

    init_pid = 1
    depth_cache = {}

    for pid, info in processes.items():
        if pid == init_pid:
            continue

        ppid = info['ppid']

        # Check for orphan processes (reparented to init)
        if ppid == init_pid and pid != init_pid:
            if boot_time > 0 and clock_ticks > 0:
                process_start = boot_time + (info['start_time'] / clock_ticks)
                age_seconds = now - process_start
                age_hours = age_seconds / 3600
            else:
                age_hours = 0

            # Skip kernel threads
            if info['comm'].startswith('[') and info['comm'].endswith(']'):
                continue

            # Skip common system daemons
            if info['comm'] in KNOWN_INIT_CHILDREN:
                continue

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

        # Calculate subtree depth
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


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no anomalies, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Analyze process tree for anomalies")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output including depth distribution")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--max-depth", type=int, default=20, metavar="N",
                        help="Flag processes with tree depth >= N (default: 20)")
    parser.add_argument("--max-children", type=int, default=100, metavar="N",
                        help="Flag processes with >= N children (default: 100)")
    parser.add_argument("--orphan-age", type=float, default=24.0, metavar="HOURS",
                        help="Flag orphan processes older than HOURS (default: 24)")
    parser.add_argument("--orphan-warn", type=float, default=4.0, metavar="HOURS",
                        help="Warn about orphan processes older than HOURS (default: 4)")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.max_depth < 1:
        output.error("--max-depth must be >= 1")
        return 2

    if opts.max_children < 1:
        output.error("--max-children must be >= 1")
        return 2

    if opts.orphan_age < 0:
        output.error("--orphan-age must be >= 0")
        return 2

    thresholds = {
        'max_depth': opts.max_depth,
        'max_children': opts.max_children,
        'orphan_age_hours': opts.orphan_age,
        'orphan_warn_hours': opts.orphan_warn
    }

    # Get process information
    processes = get_all_processes()

    if not processes:
        output.error("Could not read process information")
        return 2

    # Build process tree
    children = build_process_tree(processes)

    # Analyze processes
    issues, warnings, stats = analyze_processes(processes, children, thresholds)

    # Build output data
    result = {
        'total_processes': stats['total_processes'],
        'orphan_count': stats['orphan_count'],
        'deep_trees': stats['deep_trees'],
        'max_depth': stats['max_depth'],
        'max_children': stats['max_children'],
        'issues': issues,
        'warnings': warnings,
    }

    if opts.verbose:
        result['depth_distribution'] = dict(stats['depth_distribution'])

    output.emit(result)

    # Set summary
    issue_count = len(issues)
    warning_count = len(warnings)
    if issue_count == 0 and warning_count == 0:
        output.set_summary("No anomalies detected")
    else:
        output.set_summary(f"{issue_count} issue(s), {warning_count} warning(s)")

    return 1 if issues or warnings else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
