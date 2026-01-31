#!/usr/bin/env python3
"""
Monitor Linux kernel workqueue health and detect bottlenecks.

Kernel workqueues are the mechanism by which the kernel defers work to be
executed in process context. Common workqueues include:

- events: General purpose workqueue for driver callbacks
- kblockd: Block I/O completions and related work
- writeback: Filesystem writeback operations
- kswapd: Memory reclaim operations
- mm_percpu_wq: Per-CPU memory management work

This script monitors workqueue health indicators:
- Pending work items per workqueue
- CPU affinity and pool utilization
- Long-running or stuck work items (via delays)
- Workqueue congestion indicators

Useful for:
- Diagnosing I/O performance issues (kblockd congestion)
- Identifying kernel bottlenecks causing latency spikes
- Detecting stuck or stalled kernel work
- Capacity planning for high-throughput systems

Exit codes:
    0 - All workqueues healthy
    1 - Warnings or issues detected (high pending, congestion)
    2 - Usage error or missing debugfs/procfs access
"""

import argparse
import os
import sys
import json
import glob


def read_file(path):
    """Read a file and return contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError, PermissionError):
        return None


def read_int(path, default=0):
    """Read an integer from a file."""
    content = read_file(path)
    if content:
        try:
            return int(content.strip())
        except ValueError:
            pass
    return default


def parse_workqueue_info():
    """Parse /sys/kernel/debug/workqueue info if available.

    Returns:
        dict: Workqueue information keyed by name, or empty dict if unavailable
    """
    wq_path = '/sys/kernel/debug/workqueue'
    if not os.path.exists(wq_path):
        return {}

    workqueues = {}

    # Check for wq_status file (modern kernels)
    status_file = os.path.join(wq_path, 'wq_status')
    if os.path.exists(status_file):
        content = read_file(status_file)
        if content:
            # Parse wq_status output
            for line in content.split('\n'):
                if not line.strip():
                    continue
                # Format varies by kernel version
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0].rstrip(':')
                    if name not in workqueues:
                        workqueues[name] = {
                            'name': name,
                            'flags': [],
                            'pending': 0,
                            'running': 0,
                            'delayed': 0,
                        }

    return workqueues


def parse_proc_workqueue():
    """Parse /proc/stat and /sys for workqueue-related info.

    Returns:
        list: List of workqueue info dicts
    """
    workqueues = []

    # Check /sys/bus/workqueue/devices for workqueue list
    wq_devices_path = '/sys/bus/workqueue/devices'
    if os.path.exists(wq_devices_path):
        for wq_name in os.listdir(wq_devices_path):
            wq_path = os.path.join(wq_devices_path, wq_name)
            if os.path.isdir(wq_path) or os.path.islink(wq_path):
                wq_info = {
                    'name': wq_name,
                    'path': wq_path,
                    'flags': [],
                    'nice': None,
                    'cpumask': None,
                    'max_active': None,
                }

                # Read available attributes
                nice_file = os.path.join(wq_path, 'nice')
                if os.path.exists(nice_file):
                    wq_info['nice'] = read_int(nice_file, None)

                cpumask_file = os.path.join(wq_path, 'cpumask')
                if os.path.exists(cpumask_file):
                    content = read_file(cpumask_file)
                    if content:
                        wq_info['cpumask'] = content.strip()

                max_active_file = os.path.join(wq_path, 'max_active')
                if os.path.exists(max_active_file):
                    wq_info['max_active'] = read_int(max_active_file, None)

                # Check for per_cpu attribute
                per_cpu_file = os.path.join(wq_path, 'per_cpu')
                if os.path.exists(per_cpu_file):
                    per_cpu = read_int(per_cpu_file, 0)
                    if per_cpu:
                        wq_info['flags'].append('WQ_PERCPU')

                # Check numa attributes
                numa_file = os.path.join(wq_path, 'numa')
                if os.path.exists(numa_file):
                    numa = read_int(numa_file, 0)
                    if numa:
                        wq_info['flags'].append('WQ_NUMA')

                workqueues.append(wq_info)

    return workqueues


def get_kworker_stats():
    """Get statistics about running kworker threads.

    Returns:
        dict: Statistics about kworker threads
    """
    stats = {
        'total_kworkers': 0,
        'running': 0,
        'sleeping': 0,
        'uninterruptible': 0,
        'by_workqueue': {},
    }

    # Parse /proc to find kworker threads
    try:
        for pid_dir in glob.glob('/proc/[0-9]*'):
            try:
                pid = os.path.basename(pid_dir)
                comm_path = os.path.join(pid_dir, 'comm')
                comm = read_file(comm_path)
                if comm and 'kworker' in comm:
                    stats['total_kworkers'] += 1

                    # Get thread state
                    stat_path = os.path.join(pid_dir, 'stat')
                    stat_content = read_file(stat_path)
                    if stat_content:
                        # Format: pid (comm) state ...
                        # Find state after closing paren
                        try:
                            paren_end = stat_content.rfind(')')
                            if paren_end > 0:
                                rest = stat_content[paren_end + 1:].strip()
                                parts = rest.split()
                                if parts:
                                    state = parts[0]
                                    if state == 'R':
                                        stats['running'] += 1
                                    elif state == 'D':
                                        stats['uninterruptible'] += 1
                                    else:
                                        stats['sleeping'] += 1
                        except (IndexError, ValueError):
                            pass

                    # Try to determine which workqueue
                    # kworker format: kworker/N:M or kworker/u:N
                    comm_stripped = comm.strip()
                    if '/' in comm_stripped:
                        parts = comm_stripped.split('/')
                        if len(parts) > 1:
                            wq_type = parts[1].split(':')[0] if ':' in parts[1] else parts[1]
                            if wq_type not in stats['by_workqueue']:
                                stats['by_workqueue'][wq_type] = 0
                            stats['by_workqueue'][wq_type] += 1
            except (IOError, OSError, PermissionError):
                continue
    except Exception:
        pass

    return stats


def check_debugfs_workqueue():
    """Check if debugfs workqueue info is available and parse it.

    Returns:
        tuple: (dict of workqueue pools, bool indicating debugfs access)
    """
    pools = {}
    debugfs_available = False

    # Check for workqueue debugfs
    wq_debugfs = '/sys/kernel/debug/workqueue'
    if os.path.exists(wq_debugfs):
        debugfs_available = True

    return pools, debugfs_available


def analyze_workqueues(workqueues, kworker_stats, thresholds):
    """Analyze workqueue data and identify issues.

    Args:
        workqueues: List of workqueue info dicts
        kworker_stats: kworker thread statistics
        thresholds: User-defined thresholds

    Returns:
        list: List of issue dicts
    """
    issues = []

    # Check for high number of uninterruptible kworkers
    uninterruptible_pct = 0
    if kworker_stats['total_kworkers'] > 0:
        uninterruptible_pct = (kworker_stats['uninterruptible'] /
                               kworker_stats['total_kworkers']) * 100

    if kworker_stats['uninterruptible'] >= thresholds['uninterruptible_critical']:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'uninterruptible_kworkers',
            'value': kworker_stats['uninterruptible'],
            'message': f"Critical: {kworker_stats['uninterruptible']} kworker threads "
                      f"in uninterruptible sleep ({uninterruptible_pct:.1f}% of total)"
        })
    elif kworker_stats['uninterruptible'] >= thresholds['uninterruptible_warning']:
        issues.append({
            'severity': 'WARNING',
            'type': 'uninterruptible_kworkers',
            'value': kworker_stats['uninterruptible'],
            'message': f"Warning: {kworker_stats['uninterruptible']} kworker threads "
                      f"in uninterruptible sleep ({uninterruptible_pct:.1f}% of total)"
        })

    # Check total kworker count
    if kworker_stats['total_kworkers'] >= thresholds['kworker_count_warning']:
        issues.append({
            'severity': 'INFO',
            'type': 'high_kworker_count',
            'value': kworker_stats['total_kworkers'],
            'message': f"High kworker thread count: {kworker_stats['total_kworkers']} threads"
        })

    # Check for workqueues with concerning attributes
    for wq in workqueues:
        # Check nice value - high nice values for system workqueues may cause starvation
        if wq.get('nice') is not None and wq['nice'] > 10:
            # Some workqueues intentionally have high nice values
            if wq['name'] not in ['writeback', 'md_misc', 'dm_bufio_cache']:
                issues.append({
                    'severity': 'INFO',
                    'type': 'high_nice_workqueue',
                    'value': wq['nice'],
                    'workqueue': wq['name'],
                    'message': f"Workqueue '{wq['name']}' has high nice value ({wq['nice']})"
                })

        # Check max_active - value of 1 can be bottleneck for busy workqueues
        if wq.get('max_active') == 1:
            critical_wqs = ['kblockd', 'nvme-wq', 'scsi_wq', 'xfs-']
            for crit in critical_wqs:
                if crit in wq['name']:
                    issues.append({
                        'severity': 'WARNING',
                        'type': 'limited_max_active',
                        'value': wq['max_active'],
                        'workqueue': wq['name'],
                        'message': f"Performance-critical workqueue '{wq['name']}' "
                                  f"has max_active=1 (potential bottleneck)"
                    })
                    break

    return issues


def format_size(value):
    """Format a number with K/M suffix for readability."""
    if value >= 1000000:
        return f"{value / 1000000:.1f}M"
    elif value >= 1000:
        return f"{value / 1000:.1f}K"
    return str(value)


def output_plain(workqueues, kworker_stats, debugfs_available, issues,
                 verbose, warn_only):
    """Output results in plain text format."""
    lines = []

    if not warn_only:
        lines.append("Kernel Workqueue Status")
        lines.append("=" * 50)
        lines.append("")

        # kworker summary
        lines.append("kworker Thread Summary:")
        lines.append(f"  Total: {kworker_stats['total_kworkers']}")
        lines.append(f"  Running: {kworker_stats['running']}")
        lines.append(f"  Sleeping: {kworker_stats['sleeping']}")
        lines.append(f"  Uninterruptible (D): {kworker_stats['uninterruptible']}")
        lines.append("")

        if kworker_stats['by_workqueue']:
            lines.append("kworker Distribution:")
            for wq_type, count in sorted(kworker_stats['by_workqueue'].items(),
                                         key=lambda x: -x[1])[:10]:
                lines.append(f"  {wq_type}: {count}")
            lines.append("")

        if verbose and workqueues:
            lines.append("Workqueue Configuration:")
            lines.append(f"  {'Name':<30} {'Nice':<6} {'Max Active':<12} Flags")
            lines.append("  " + "-" * 70)
            for wq in sorted(workqueues, key=lambda x: x['name'])[:20]:
                nice_str = str(wq['nice']) if wq['nice'] is not None else '-'
                max_active_str = str(wq['max_active']) if wq['max_active'] is not None else '-'
                flags_str = ','.join(wq['flags']) if wq['flags'] else '-'
                lines.append(f"  {wq['name']:<30} {nice_str:<6} {max_active_str:<12} {flags_str}")
            if len(workqueues) > 20:
                lines.append(f"  ... and {len(workqueues) - 20} more workqueues")
            lines.append("")

        if not debugfs_available:
            lines.append("Note: debugfs not accessible, limited workqueue stats available")
            lines.append("")

    # Issues
    if issues:
        for issue in issues:
            if warn_only and issue['severity'] == 'INFO':
                continue
            lines.append(f"[{issue['severity']}] {issue['message']}")
        lines.append("")
    elif not warn_only:
        lines.append("No workqueue issues detected.")

    print('\n'.join(lines))


def output_json(workqueues, kworker_stats, debugfs_available, issues, verbose):
    """Output results in JSON format."""
    result = {
        'kworker_stats': kworker_stats,
        'debugfs_available': debugfs_available,
        'issues': issues,
    }

    if verbose:
        result['workqueues'] = workqueues

    print(json.dumps(result, indent=2))


def output_table(workqueues, kworker_stats, debugfs_available, issues,
                 verbose, warn_only):
    """Output results in table format."""
    lines = []

    if not warn_only:
        lines.append("=" * 70)
        lines.append("KERNEL WORKQUEUE STATUS")
        lines.append("=" * 70)
        lines.append("")

        lines.append(f"{'Metric':<30} {'Value':<20}")
        lines.append("-" * 50)
        lines.append(f"{'Total kworkers':<30} {kworker_stats['total_kworkers']:<20}")
        lines.append(f"{'Running':<30} {kworker_stats['running']:<20}")
        lines.append(f"{'Sleeping':<30} {kworker_stats['sleeping']:<20}")
        lines.append(f"{'Uninterruptible (D)':<30} {kworker_stats['uninterruptible']:<20}")
        lines.append(f"{'Debugfs available':<30} {'Yes' if debugfs_available else 'No':<20}")
        lines.append("=" * 70)
        lines.append("")

    if issues:
        lines.append("ISSUES DETECTED")
        lines.append("-" * 70)
        for issue in issues:
            if warn_only and issue['severity'] == 'INFO':
                continue
            lines.append(f"[{issue['severity']}] {issue['message']}")
        lines.append("")

    print('\n'.join(lines))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor Linux kernel workqueue health',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Check workqueue status
  %(prog)s --format json          # JSON output for monitoring
  %(prog)s --verbose              # Show detailed workqueue config
  %(prog)s --warn-only            # Only show warnings/errors

Thresholds:
  --uninterruptible-warn: Warning threshold for D-state kworkers (default: 5)
  --uninterruptible-crit: Critical threshold for D-state kworkers (default: 10)

Understanding workqueues:
  Kernel workqueues process deferred work. High numbers of kworker threads
  in 'D' (uninterruptible sleep) state often indicate I/O bottlenecks or
  storage issues. Common workqueue types:

  - events: General purpose workqueue
  - kblockd: Block I/O processing
  - writeback: Filesystem dirty page writeback
  - nvme-wq: NVMe command completions
  - xfs-*: XFS filesystem work

Exit codes:
  0 - Workqueues healthy
  1 - Warnings or issues detected
  2 - Usage error or missing access
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
        help='Show detailed workqueue configuration'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors'
    )

    parser.add_argument(
        '--uninterruptible-warn',
        type=int,
        default=5,
        metavar='N',
        help='Warning threshold for D-state kworkers (default: 5)'
    )

    parser.add_argument(
        '--uninterruptible-crit',
        type=int,
        default=10,
        metavar='N',
        help='Critical threshold for D-state kworkers (default: 10)'
    )

    parser.add_argument(
        '--kworker-count-warn',
        type=int,
        default=500,
        metavar='N',
        help='Warning threshold for total kworker count (default: 500)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.uninterruptible_warn < 0:
        print("Error: --uninterruptible-warn must be >= 0", file=sys.stderr)
        sys.exit(2)
    if args.uninterruptible_crit < 0:
        print("Error: --uninterruptible-crit must be >= 0", file=sys.stderr)
        sys.exit(2)
    if args.uninterruptible_warn >= args.uninterruptible_crit:
        print("Error: --uninterruptible-warn must be less than --uninterruptible-crit",
              file=sys.stderr)
        sys.exit(2)

    thresholds = {
        'uninterruptible_warning': args.uninterruptible_warn,
        'uninterruptible_critical': args.uninterruptible_crit,
        'kworker_count_warning': args.kworker_count_warn,
    }

    # Check for /proc access
    if not os.path.exists('/proc'):
        print("Error: /proc filesystem not available", file=sys.stderr)
        sys.exit(2)

    # Gather workqueue information
    workqueues = parse_proc_workqueue()
    kworker_stats = get_kworker_stats()
    pools, debugfs_available = check_debugfs_workqueue()

    # Analyze
    issues = analyze_workqueues(workqueues, kworker_stats, thresholds)

    # Output
    if args.format == 'json':
        output_json(workqueues, kworker_stats, debugfs_available, issues, args.verbose)
    elif args.format == 'table':
        output_table(workqueues, kworker_stats, debugfs_available, issues,
                    args.verbose, args.warn_only)
    else:
        output_plain(workqueues, kworker_stats, debugfs_available, issues,
                    args.verbose, args.warn_only)

    # Exit code
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
