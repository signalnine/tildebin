#!/usr/bin/env python3
"""
Monitor inotify watch usage to detect exhaustion risk on baremetal systems.

Inotify watches are a limited kernel resource used for file system event
monitoring. When exhausted, applications fail with "No space left on device"
or "Too many open files" errors despite having disk space and file descriptors.

Common consumers of inotify watches:
- Kubernetes kubelet (pod volume mounts, configmaps, secrets)
- File sync tools (Dropbox, syncthing, rsync)
- IDEs and editors (VS Code, IntelliJ, vim with plugins)
- Build tools (webpack, gulp, nodemon)
- Log monitoring (tail -f, logrotate)
- Container runtimes (containerd, dockerd)

This script monitors:
- System-wide inotify watch usage vs kernel limit
- Per-process inotify watch consumption
- Processes approaching their limits
- Top consumers by watch count

Remediation:
- Increase system limit: sysctl -w fs.inotify.max_user_watches=524288
- Make persistent: echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.conf
- Identify and fix watch leaks in applications
- Exclude unnecessary directories from monitoring

Exit codes:
    0 - Inotify usage is healthy
    1 - High usage or issues detected (warning or critical)
    2 - Usage error or cannot read inotify information
"""

import argparse
import sys
import json
import os
import pwd
from collections import defaultdict


def get_inotify_limits():
    """
    Read inotify kernel limits from /proc/sys/fs/inotify.

    Returns:
        dict: Dictionary containing max_user_watches, max_user_instances,
              max_queued_events, or None values if unreadable.
    """
    limits = {
        'max_user_watches': None,
        'max_user_instances': None,
        'max_queued_events': None,
    }

    paths = {
        'max_user_watches': '/proc/sys/fs/inotify/max_user_watches',
        'max_user_instances': '/proc/sys/fs/inotify/max_user_instances',
        'max_queued_events': '/proc/sys/fs/inotify/max_queued_events',
    }

    for key, path in paths.items():
        try:
            with open(path, 'r') as f:
                limits[key] = int(f.read().strip())
        except (FileNotFoundError, PermissionError, ValueError):
            pass

    return limits


def get_process_name(pid):
    """Get the command name for a process ID."""
    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return '<unknown>'


def get_process_cmdline(pid):
    """Get the full command line for a process ID."""
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            return cmdline if cmdline else get_process_name(pid)
    except (FileNotFoundError, PermissionError):
        return get_process_name(pid)


def get_process_user(pid):
    """Get the username owning a process."""
    try:
        stat = os.stat(f'/proc/{pid}')
        try:
            return pwd.getpwuid(stat.st_uid).pw_name
        except KeyError:
            return str(stat.st_uid)
    except (FileNotFoundError, PermissionError):
        return '<unknown>'


def count_inotify_watches_per_process():
    """
    Count inotify watches per process by reading /proc/<pid>/fd/ links.

    Each inotify instance is a file descriptor pointing to anon_inode:inotify.
    The actual watch count per instance requires reading /proc/<pid>/fdinfo/<fd>.

    Returns:
        dict: Mapping of pid -> {'name': str, 'user': str, 'watches': int, 'instances': int}
    """
    process_watches = {}

    try:
        pids = [d for d in os.listdir('/proc') if d.isdigit()]
    except OSError:
        return process_watches

    for pid in pids:
        fd_path = f'/proc/{pid}/fd'
        fdinfo_path = f'/proc/{pid}/fdinfo'

        try:
            fds = os.listdir(fd_path)
        except (PermissionError, FileNotFoundError):
            continue

        total_watches = 0
        inotify_instances = 0

        for fd in fds:
            try:
                link = os.readlink(f'{fd_path}/{fd}')
                if 'inotify' in link:
                    inotify_instances += 1

                    # Count watches in this inotify instance
                    try:
                        with open(f'{fdinfo_path}/{fd}', 'r') as f:
                            for line in f:
                                if line.startswith('inotify wd:'):
                                    total_watches += 1
                    except (FileNotFoundError, PermissionError):
                        # Can't read fdinfo, estimate 1 watch per instance
                        total_watches += 1

            except (FileNotFoundError, PermissionError, OSError):
                continue

        if inotify_instances > 0 or total_watches > 0:
            process_watches[pid] = {
                'name': get_process_name(pid),
                'cmdline': get_process_cmdline(pid),
                'user': get_process_user(pid),
                'watches': total_watches,
                'instances': inotify_instances,
            }

    return process_watches


def get_total_watches(process_watches):
    """Calculate total inotify watches across all processes."""
    return sum(p['watches'] for p in process_watches.values())


def get_total_instances(process_watches):
    """Calculate total inotify instances across all processes."""
    return sum(p['instances'] for p in process_watches.values())


def analyze_usage(limits, process_watches, warn_threshold, crit_threshold):
    """
    Analyze inotify usage and generate issues.

    Args:
        limits: Dictionary of kernel limits
        process_watches: Dictionary of per-process watch counts
        warn_threshold: Warning threshold percentage (0-100)
        crit_threshold: Critical threshold percentage (0-100)

    Returns:
        tuple: (issues list, summary dict)
    """
    issues = []
    summary = {
        'total_watches': get_total_watches(process_watches),
        'total_instances': get_total_instances(process_watches),
        'max_user_watches': limits.get('max_user_watches'),
        'max_user_instances': limits.get('max_user_instances'),
        'usage_percent': None,
        'instance_percent': None,
        'top_consumers': [],
    }

    # Calculate usage percentage
    if limits.get('max_user_watches') and limits['max_user_watches'] > 0:
        summary['usage_percent'] = (summary['total_watches'] / limits['max_user_watches']) * 100

        if summary['usage_percent'] >= crit_threshold:
            issues.append({
                'severity': 'CRITICAL',
                'type': 'high_watch_usage',
                'message': f"Inotify watch usage critical: {summary['usage_percent']:.1f}% "
                          f"({summary['total_watches']}/{limits['max_user_watches']})",
            })
        elif summary['usage_percent'] >= warn_threshold:
            issues.append({
                'severity': 'WARNING',
                'type': 'high_watch_usage',
                'message': f"Inotify watch usage elevated: {summary['usage_percent']:.1f}% "
                          f"({summary['total_watches']}/{limits['max_user_watches']})",
            })

    # Calculate instance usage
    if limits.get('max_user_instances') and limits['max_user_instances'] > 0:
        summary['instance_percent'] = (summary['total_instances'] / limits['max_user_instances']) * 100

        if summary['instance_percent'] >= crit_threshold:
            issues.append({
                'severity': 'CRITICAL',
                'type': 'high_instance_usage',
                'message': f"Inotify instance usage critical: {summary['instance_percent']:.1f}% "
                          f"({summary['total_instances']}/{limits['max_user_instances']})",
            })
        elif summary['instance_percent'] >= warn_threshold:
            issues.append({
                'severity': 'WARNING',
                'type': 'high_instance_usage',
                'message': f"Inotify instance usage elevated: {summary['instance_percent']:.1f}% "
                          f"({summary['total_instances']}/{limits['max_user_instances']})",
            })

    # Check for low limits (common misconfiguration)
    if limits.get('max_user_watches') and limits['max_user_watches'] < 65536:
        issues.append({
            'severity': 'WARNING',
            'type': 'low_limit',
            'message': f"max_user_watches limit is low: {limits['max_user_watches']} "
                      f"(recommend at least 65536 for production)",
        })

    # Identify top consumers
    sorted_procs = sorted(
        process_watches.items(),
        key=lambda x: x[1]['watches'],
        reverse=True
    )

    summary['top_consumers'] = [
        {
            'pid': pid,
            'name': info['name'],
            'user': info['user'],
            'watches': info['watches'],
            'instances': info['instances'],
        }
        for pid, info in sorted_procs[:10]
    ]

    return issues, summary


def format_plain(limits, process_watches, issues, summary, verbose=False, warn_only=False):
    """Format output as plain text."""
    lines = []

    if warn_only and not issues:
        return "No inotify issues detected"

    if not warn_only:
        lines.append("Inotify Watch Usage Monitor")
        lines.append("=" * 60)
        lines.append("")

        # System limits
        lines.append("Kernel Limits:")
        lines.append(f"  max_user_watches:   {limits.get('max_user_watches', 'N/A'):>10}")
        lines.append(f"  max_user_instances: {limits.get('max_user_instances', 'N/A'):>10}")
        lines.append(f"  max_queued_events:  {limits.get('max_queued_events', 'N/A'):>10}")
        lines.append("")

        # Current usage
        lines.append("Current Usage:")
        lines.append(f"  Total watches:   {summary['total_watches']:>10}")
        lines.append(f"  Total instances: {summary['total_instances']:>10}")

        if summary['usage_percent'] is not None:
            lines.append(f"  Watch usage:     {summary['usage_percent']:>9.1f}%")
        if summary['instance_percent'] is not None:
            lines.append(f"  Instance usage:  {summary['instance_percent']:>9.1f}%")
        lines.append("")

        # Top consumers
        if summary['top_consumers']:
            lines.append("Top Consumers:")
            lines.append(f"  {'PID':<8} {'Process':<20} {'User':<12} {'Watches':>10} {'Instances':>10}")
            lines.append("  " + "-" * 62)

            for proc in summary['top_consumers']:
                name = proc['name'][:20]
                user = proc['user'][:12]
                lines.append(f"  {proc['pid']:<8} {name:<20} {user:<12} "
                           f"{proc['watches']:>10} {proc['instances']:>10}")
            lines.append("")

        if verbose and process_watches:
            lines.append("All Processes with Inotify Watches:")
            lines.append(f"  {'PID':<8} {'Process':<25} {'Watches':>10}")
            lines.append("  " + "-" * 45)

            for pid, info in sorted(process_watches.items(),
                                   key=lambda x: x[1]['watches'],
                                   reverse=True):
                if info['watches'] > 0:
                    name = info['name'][:25]
                    lines.append(f"  {pid:<8} {name:<25} {info['watches']:>10}")
            lines.append("")

    # Issues
    if issues:
        lines.append("Issues Detected:")
        lines.append("-" * 60)
        for issue in sorted(issues, key=lambda x: x['severity'] != 'CRITICAL'):
            marker = "!!!" if issue['severity'] == 'CRITICAL' else " ! "
            lines.append(f"{marker} [{issue['severity']}] {issue['message']}")
        lines.append("")

        # Remediation hints
        lines.append("Remediation:")
        lines.append("  Increase limit (temporary):")
        lines.append("    sudo sysctl -w fs.inotify.max_user_watches=524288")
        lines.append("  Make persistent:")
        lines.append("    echo 'fs.inotify.max_user_watches=524288' | sudo tee -a /etc/sysctl.conf")
        lines.append("    sudo sysctl -p")
    elif not warn_only:
        lines.append("Status: Inotify usage is healthy")

    return '\n'.join(lines)


def format_json(limits, process_watches, issues, summary):
    """Format output as JSON."""
    output = {
        'limits': limits,
        'summary': summary,
        'issues': issues,
        'processes': [
            {
                'pid': int(pid),
                'name': info['name'],
                'cmdline': info['cmdline'],
                'user': info['user'],
                'watches': info['watches'],
                'instances': info['instances'],
            }
            for pid, info in sorted(
                process_watches.items(),
                key=lambda x: x[1]['watches'],
                reverse=True
            )
        ],
        'healthy': len([i for i in issues if i['severity'] == 'CRITICAL']) == 0,
    }
    return json.dumps(output, indent=2)


def format_table(limits, process_watches, issues, summary):
    """Format output as a table."""
    lines = []

    lines.append(f"{'Metric':<30} {'Value':>15} {'Limit':>15} {'Usage':>10}")
    lines.append("=" * 70)

    usage_str = f"{summary['usage_percent']:.1f}%" if summary['usage_percent'] else "N/A"
    inst_str = f"{summary['instance_percent']:.1f}%" if summary['instance_percent'] else "N/A"

    lines.append(f"{'Inotify Watches':<30} {summary['total_watches']:>15} "
                f"{limits.get('max_user_watches', 'N/A'):>15} {usage_str:>10}")
    lines.append(f"{'Inotify Instances':<30} {summary['total_instances']:>15} "
                f"{limits.get('max_user_instances', 'N/A'):>15} {inst_str:>10}")

    lines.append("")
    lines.append("Top Consumers:")
    lines.append(f"{'PID':<10} {'Process':<25} {'Watches':>12} {'Instances':>12}")
    lines.append("-" * 60)

    for proc in summary['top_consumers'][:5]:
        name = proc['name'][:25]
        lines.append(f"{proc['pid']:<10} {name:<25} {proc['watches']:>12} {proc['instances']:>12}")

    if issues:
        lines.append("")
        lines.append("Issues:")
        for issue in issues:
            lines.append(f"  [{issue['severity']}] {issue['message']}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor inotify watch usage to detect exhaustion risk',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic inotify monitoring
  %(prog)s -v                       # Show all processes with watches
  %(prog)s --format json            # JSON output for scripting
  %(prog)s --warn-only              # Only show if issues detected
  %(prog)s --warn 60 --crit 80      # Custom thresholds

Common causes of inotify exhaustion:
  - Kubernetes kubelet monitoring many pods
  - IDEs watching large codebases
  - File sync tools (Dropbox, syncthing)
  - Build tools in watch mode (webpack, nodemon)
  - Container runtimes and orchestrators

Exit codes:
  0 - Inotify usage is healthy
  1 - High usage or issues detected
  2 - Cannot read inotify information
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
        help='Show all processes with inotify watches'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if issues are detected'
    )

    parser.add_argument(
        '--warn',
        type=float,
        default=75.0,
        metavar='PCT',
        help='Warning threshold percentage (default: %(default)s)'
    )

    parser.add_argument(
        '--crit',
        type=float,
        default=90.0,
        metavar='PCT',
        help='Critical threshold percentage (default: %(default)s)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if not (0 <= args.warn <= 100) or not (0 <= args.crit <= 100):
        print("Error: Thresholds must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.warn >= args.crit:
        print("Error: Warning threshold must be less than critical threshold", file=sys.stderr)
        sys.exit(2)

    # Get kernel limits
    limits = get_inotify_limits()

    if limits['max_user_watches'] is None:
        print("Error: Cannot read inotify limits from /proc/sys/fs/inotify",
              file=sys.stderr)
        print("This script requires a Linux system with inotify support",
              file=sys.stderr)
        sys.exit(2)

    # Get per-process watch counts
    process_watches = count_inotify_watches_per_process()

    # Analyze usage
    issues, summary = analyze_usage(limits, process_watches, args.warn, args.crit)

    # Handle warn-only mode with no issues
    if args.warn_only and not issues:
        if args.format == 'json':
            print(json.dumps({'healthy': True, 'issues': []}))
        sys.exit(0)

    # Format output
    if args.format == 'json':
        output = format_json(limits, process_watches, issues, summary)
    elif args.format == 'table':
        output = format_table(limits, process_watches, issues, summary)
    else:
        output = format_plain(limits, process_watches, issues, summary,
                             verbose=args.verbose, warn_only=args.warn_only)

    print(output)

    # Exit code based on issues
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
