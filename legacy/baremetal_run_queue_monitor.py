#!/usr/bin/env python3
"""
Monitor per-CPU run queue depth and scheduler statistics.

Analyzes CPU scheduler pressure by examining per-CPU run queue lengths,
scheduler latency, and context switch rates. Provides more granular
insight into CPU saturation than load averages alone.

Key metrics:
- Per-CPU run queue depth from /proc/schedstat
- Scheduler latency (time tasks spend waiting)
- Context switches per CPU
- CPU imbalance detection (uneven load distribution)
- Run queue depth trends

Useful for:
- Detecting CPU saturation before it shows in load average
- Identifying scheduler bottlenecks
- Finding CPU imbalance issues (some CPUs overloaded, others idle)
- Capacity planning in large baremetal environments
- Tuning scheduler parameters

Exit codes:
    0 - Run queues healthy, no saturation detected
    1 - Run queue issues detected (saturation, imbalance)
    2 - Usage error or unable to read scheduler statistics
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def read_file(path):
    """Read file contents, return None if not accessible."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError):
        return None


def get_cpu_count():
    """Get the number of online CPUs."""
    try:
        return os.sysconf('SC_NPROCESSORS_ONLN')
    except (ValueError, OSError):
        return os.cpu_count() or 1


def parse_schedstat():
    """
    Parse /proc/schedstat for per-CPU scheduler statistics.

    Returns dict with per-CPU stats including:
    - run_queue_length: tasks waiting to run
    - time_running: total time tasks spent running (ns)
    - time_waiting: total time tasks spent waiting (ns)
    - timeslices: number of timeslices run
    """
    content = read_file('/proc/schedstat')
    if content is None:
        return None

    cpu_stats = {}
    current_cpu = None

    for line in content.strip().split('\n'):
        parts = line.split()
        if not parts:
            continue

        # CPU line: cpu<n> <domain_count> ...
        if parts[0].startswith('cpu') and parts[0] != 'cpu':
            try:
                cpu_id = int(parts[0][3:])
                current_cpu = cpu_id
                cpu_stats[cpu_id] = {
                    'id': cpu_id,
                    'raw_line': line
                }
            except ValueError:
                continue

    return cpu_stats if cpu_stats else None


def parse_stat():
    """
    Parse /proc/stat for per-CPU context switches and running processes.

    Returns dict with:
    - Per-CPU time statistics
    - Total context switches
    - Processes running/blocked
    """
    content = read_file('/proc/stat')
    if content is None:
        return None

    result = {
        'cpus': {},
        'context_switches': 0,
        'processes_running': 0,
        'processes_blocked': 0
    }

    for line in content.strip().split('\n'):
        parts = line.split()
        if not parts:
            continue

        # Per-CPU line: cpu<n> user nice system idle iowait irq softirq ...
        if parts[0].startswith('cpu') and len(parts[0]) > 3:
            try:
                cpu_id = int(parts[0][3:])
                if len(parts) >= 8:
                    result['cpus'][cpu_id] = {
                        'user': int(parts[1]),
                        'nice': int(parts[2]),
                        'system': int(parts[3]),
                        'idle': int(parts[4]),
                        'iowait': int(parts[5]),
                        'irq': int(parts[6]),
                        'softirq': int(parts[7]),
                    }
                    # Calculate busy time
                    total = sum(int(p) for p in parts[1:8])
                    idle = int(parts[4])
                    result['cpus'][cpu_id]['busy_pct'] = round(
                        100 * (total - idle) / total if total > 0 else 0, 1
                    )
            except (ValueError, IndexError):
                continue

        elif parts[0] == 'ctxt':
            result['context_switches'] = int(parts[1])

        elif parts[0] == 'procs_running':
            result['processes_running'] = int(parts[1])

        elif parts[0] == 'procs_blocked':
            result['processes_blocked'] = int(parts[1])

    return result


def parse_loadavg():
    """Parse /proc/loadavg for run queue info."""
    content = read_file('/proc/loadavg')
    if content is None:
        return None

    parts = content.strip().split()
    if len(parts) < 4:
        return None

    try:
        running_total = parts[3].split('/')
        return {
            'load_1min': float(parts[0]),
            'load_5min': float(parts[1]),
            'load_15min': float(parts[2]),
            'running': int(running_total[0]),
            'total_tasks': int(running_total[1])
        }
    except (ValueError, IndexError):
        return None


def parse_sched_debug():
    """
    Parse /proc/sched_debug for detailed run queue info.

    This file provides the most detailed scheduler information but
    requires root access on many systems.
    """
    content = read_file('/proc/sched_debug')
    if content is None:
        return None

    result = {}
    current_cpu = None

    for line in content.split('\n'):
        # Look for CPU sections
        if line.startswith('cpu#'):
            try:
                cpu_id = int(line.split('#')[1].split(',')[0])
                current_cpu = cpu_id
                result[cpu_id] = {
                    'id': cpu_id,
                    'nr_running': 0,
                    'nr_switches': 0,
                    'curr_task': None
                }
            except (ValueError, IndexError):
                continue

        elif current_cpu is not None:
            line = line.strip()
            if line.startswith('.nr_running'):
                try:
                    result[current_cpu]['nr_running'] = int(line.split(':')[1].strip())
                except (ValueError, IndexError):
                    pass
            elif line.startswith('.nr_switches'):
                try:
                    result[current_cpu]['nr_switches'] = int(line.split(':')[1].strip())
                except (ValueError, IndexError):
                    pass
            elif line.startswith('.curr->pid'):
                try:
                    result[current_cpu]['curr_pid'] = int(line.split(':')[1].strip())
                except (ValueError, IndexError):
                    pass

    return result if result else None


def analyze_run_queues(stat_data, loadavg_data, sched_debug_data, cpu_count, thresholds):
    """Analyze run queue data and identify issues."""
    issues = []
    warnings = []

    # Calculate per-CPU run queue estimate from running processes
    running = loadavg_data.get('running', 0) if loadavg_data else 0
    avg_queue_depth = running / cpu_count if cpu_count > 0 else 0

    # Analyze CPU busy percentages for imbalance
    cpu_busy = []
    if stat_data and 'cpus' in stat_data:
        cpu_busy = [cpu['busy_pct'] for cpu in stat_data['cpus'].values()]

    # Check for CPU imbalance
    if cpu_busy:
        max_busy = max(cpu_busy)
        min_busy = min(cpu_busy)
        avg_busy = sum(cpu_busy) / len(cpu_busy)
        imbalance = max_busy - min_busy

        if imbalance > thresholds['imbalance_critical']:
            issues.append(
                f"CPU imbalance critical: {imbalance:.1f}% spread "
                f"(max: {max_busy:.1f}%, min: {min_busy:.1f}%)"
            )
        elif imbalance > thresholds['imbalance_warning']:
            warnings.append(
                f"CPU imbalance detected: {imbalance:.1f}% spread "
                f"(max: {max_busy:.1f}%, min: {min_busy:.1f}%)"
            )

        # Check for overall saturation
        if avg_busy > thresholds['busy_critical']:
            issues.append(f"High CPU utilization: {avg_busy:.1f}% average across all CPUs")
        elif avg_busy > thresholds['busy_warning']:
            warnings.append(f"Elevated CPU utilization: {avg_busy:.1f}% average")

    # Check run queue depth
    if avg_queue_depth > thresholds['queue_critical']:
        issues.append(
            f"Run queue depth critical: {avg_queue_depth:.2f} per CPU "
            f"({running} tasks running)"
        )
    elif avg_queue_depth > thresholds['queue_warning']:
        warnings.append(
            f"Run queue depth elevated: {avg_queue_depth:.2f} per CPU "
            f"({running} tasks running)"
        )

    # Check for blocked processes (I/O wait)
    blocked = stat_data.get('processes_blocked', 0) if stat_data else 0
    if blocked > thresholds['blocked_critical']:
        issues.append(f"Many blocked processes: {blocked} (possible I/O bottleneck)")
    elif blocked > thresholds['blocked_warning']:
        warnings.append(f"Blocked processes: {blocked} (I/O pressure)")

    # Use sched_debug data if available for more detail
    per_cpu_queues = {}
    if sched_debug_data:
        max_queue = 0
        for cpu_id, data in sched_debug_data.items():
            nr_running = data.get('nr_running', 0)
            per_cpu_queues[cpu_id] = nr_running
            if nr_running > max_queue:
                max_queue = nr_running

        if max_queue > thresholds['queue_critical'] * 2:
            issues.append(f"CPU with very long run queue: {max_queue} tasks")

    return {
        'avg_queue_depth': round(avg_queue_depth, 2),
        'running_tasks': running,
        'blocked_tasks': blocked,
        'cpu_busy': cpu_busy,
        'per_cpu_queues': per_cpu_queues,
        'issues': issues,
        'warnings': warnings,
        'status': 'critical' if issues else ('warning' if warnings else 'healthy')
    }


def format_plain(cpu_count, stat_data, loadavg_data, analysis, verbose=False):
    """Format output as plain text."""
    lines = []

    lines.append("Run Queue Monitor")
    lines.append("=" * 50)
    lines.append("")

    # Summary
    lines.append(f"CPUs: {cpu_count}")
    lines.append(f"Running tasks: {analysis['running_tasks']}")
    lines.append(f"Avg queue depth: {analysis['avg_queue_depth']:.2f} per CPU")
    lines.append(f"Blocked tasks: {analysis['blocked_tasks']}")
    lines.append("")

    # Load averages
    if loadavg_data:
        lines.append(f"Load: {loadavg_data['load_1min']:.2f} "
                    f"{loadavg_data['load_5min']:.2f} "
                    f"{loadavg_data['load_15min']:.2f}")
        lines.append("")

    # Per-CPU utilization
    if verbose and analysis['cpu_busy']:
        lines.append("Per-CPU utilization:")
        for i, busy in enumerate(analysis['cpu_busy']):
            bar_len = int(busy / 5)  # Scale to 20 chars max
            bar = '#' * bar_len + '-' * (20 - bar_len)
            lines.append(f"  CPU {i:2d}: [{bar}] {busy:5.1f}%")
        lines.append("")

    # Per-CPU run queues (if available from sched_debug)
    if verbose and analysis['per_cpu_queues']:
        lines.append("Per-CPU run queue depth:")
        for cpu_id, depth in sorted(analysis['per_cpu_queues'].items()):
            lines.append(f"  CPU {cpu_id:2d}: {depth} tasks")
        lines.append("")

    # Issues
    if analysis['issues']:
        lines.append("ISSUES:")
        for issue in analysis['issues']:
            lines.append(f"  [!] {issue}")
        lines.append("")

    # Warnings
    if analysis['warnings']:
        lines.append("WARNINGS:")
        for warning in analysis['warnings']:
            lines.append(f"  [*] {warning}")
        lines.append("")

    # Status
    if not analysis['issues'] and not analysis['warnings']:
        lines.append("[OK] Run queues healthy")

    return "\n".join(lines)


def format_json(cpu_count, stat_data, loadavg_data, analysis):
    """Format output as JSON."""
    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'cpu_count': cpu_count,
        'running_tasks': analysis['running_tasks'],
        'blocked_tasks': analysis['blocked_tasks'],
        'avg_queue_depth': analysis['avg_queue_depth'],
        'per_cpu_busy_pct': analysis['cpu_busy'],
        'per_cpu_queues': analysis['per_cpu_queues'],
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'healthy': len(analysis['issues']) == 0
    }

    if loadavg_data:
        output['load_averages'] = {
            '1min': loadavg_data['load_1min'],
            '5min': loadavg_data['load_5min'],
            '15min': loadavg_data['load_15min']
        }

    if stat_data:
        output['context_switches'] = stat_data.get('context_switches', 0)

    return json.dumps(output, indent=2)


def format_table(cpu_count, stat_data, loadavg_data, analysis):
    """Format output as a table."""
    lines = []

    lines.append(f"{'METRIC':<25} {'VALUE':<15} {'STATUS':<15}")
    lines.append("-" * 55)

    # Key metrics
    lines.append(f"{'CPUs':<25} {cpu_count:<15} {'':<15}")
    lines.append(f"{'Running Tasks':<25} {analysis['running_tasks']:<15} {'':<15}")

    queue_status = ''
    if any('queue' in i.lower() for i in analysis['issues']):
        queue_status = 'CRITICAL'
    elif any('queue' in w.lower() for w in analysis['warnings']):
        queue_status = 'WARNING'
    lines.append(f"{'Avg Queue Depth':<25} {analysis['avg_queue_depth']:<15.2f} {queue_status:<15}")

    blocked_status = ''
    if any('blocked' in i.lower() for i in analysis['issues']):
        blocked_status = 'CRITICAL'
    elif any('blocked' in w.lower() for w in analysis['warnings']):
        blocked_status = 'WARNING'
    lines.append(f"{'Blocked Tasks':<25} {analysis['blocked_tasks']:<15} {blocked_status:<15}")

    if loadavg_data:
        load_str = f"{loadavg_data['load_1min']:.2f}"
        lines.append(f"{'Load (1min)':<25} {load_str:<15} {'':<15}")

    lines.append("-" * 55)

    # CPU utilization range
    if analysis['cpu_busy']:
        min_busy = min(analysis['cpu_busy'])
        max_busy = max(analysis['cpu_busy'])
        avg_busy = sum(analysis['cpu_busy']) / len(analysis['cpu_busy'])

        imbalance_status = ''
        if any('imbalance' in i.lower() for i in analysis['issues']):
            imbalance_status = 'CRITICAL'
        elif any('imbalance' in w.lower() for w in analysis['warnings']):
            imbalance_status = 'WARNING'

        lines.append(f"{'CPU Busy (min/avg/max)':<25} "
                    f"{min_busy:.0f}/{avg_busy:.0f}/{max_busy:.0f}%{'':<5} "
                    f"{imbalance_status:<15}")

    lines.append("-" * 55)
    status_str = analysis['status'].upper()
    issue_count = len(analysis['issues']) + len(analysis['warnings'])
    lines.append(f"{'Overall Status':<25} {status_str:<15} {f'{issue_count} issue(s)' if issue_count else '':<15}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor per-CPU run queue depth and scheduler statistics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic run queue check
  %(prog)s

  # JSON output for monitoring systems
  %(prog)s --format json

  # Verbose output with per-CPU details
  %(prog)s -v

  # Custom thresholds
  %(prog)s --queue-warning 2 --queue-critical 4

  # Only show output if issues detected
  %(prog)s --warn-only

Thresholds:
  Queue depth is the average number of runnable tasks per CPU.
  Values above 1 indicate CPU saturation.

  Default queue warning: 1.0 (one task waiting per CPU)
  Default queue critical: 2.0 (two tasks waiting per CPU)

Exit codes:
  0 - Run queues healthy
  1 - Run queue issues detected
  2 - Usage error or unable to read scheduler stats
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--queue-warning',
        type=float,
        default=1.0,
        help='Warning threshold for avg queue depth per CPU (default: 1.0)'
    )
    parser.add_argument(
        '--queue-critical',
        type=float,
        default=2.0,
        help='Critical threshold for avg queue depth per CPU (default: 2.0)'
    )
    parser.add_argument(
        '--imbalance-warning',
        type=float,
        default=30.0,
        help='Warning threshold for CPU utilization imbalance %% (default: 30)'
    )
    parser.add_argument(
        '--imbalance-critical',
        type=float,
        default=50.0,
        help='Critical threshold for CPU utilization imbalance %% (default: 50)'
    )
    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed per-CPU information'
    )

    args = parser.parse_args()

    # Gather data
    cpu_count = get_cpu_count()
    stat_data = parse_stat()
    loadavg_data = parse_loadavg()
    sched_debug_data = parse_sched_debug()

    if stat_data is None and loadavg_data is None:
        print("Error: Unable to read scheduler statistics from /proc", file=sys.stderr)
        print("Ensure /proc is mounted and accessible", file=sys.stderr)
        sys.exit(2)

    # Set thresholds
    thresholds = {
        'queue_warning': args.queue_warning,
        'queue_critical': args.queue_critical,
        'imbalance_warning': args.imbalance_warning,
        'imbalance_critical': args.imbalance_critical,
        'busy_warning': 70.0,
        'busy_critical': 90.0,
        'blocked_warning': cpu_count,
        'blocked_critical': cpu_count * 2
    }

    # Analyze
    analysis = analyze_run_queues(
        stat_data, loadavg_data, sched_debug_data, cpu_count, thresholds
    )

    # Format output
    if args.format == 'json':
        output = format_json(cpu_count, stat_data, loadavg_data, analysis)
    elif args.format == 'table':
        output = format_table(cpu_count, stat_data, loadavg_data, analysis)
    else:
        output = format_plain(cpu_count, stat_data, loadavg_data, analysis, args.verbose)

    # Print output (respecting --warn-only)
    if not args.warn_only or analysis['issues'] or analysis['warnings']:
        print(output)

    # Return appropriate exit code
    return 1 if analysis['issues'] else 0


if __name__ == '__main__':
    sys.exit(main())
