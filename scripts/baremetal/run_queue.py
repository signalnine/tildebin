#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [cpu, scheduler, runqueue, saturation, performance]
#   requires: []
#   privilege: user
#   related: [scheduler_affinity, smt_status]
#   brief: Monitor per-CPU run queue depth and scheduler statistics

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

Useful for:
- Detecting CPU saturation before it shows in load average
- Identifying scheduler bottlenecks
- Finding CPU imbalance issues (some CPUs overloaded, others idle)
- Capacity planning in large baremetal environments
"""

import argparse
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_file(path: str) -> str | None:
    """Read file contents, return None if not accessible."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError):
        return None


def get_cpu_count() -> int:
    """Get the number of online CPUs."""
    try:
        return os.sysconf('SC_NPROCESSORS_ONLN')
    except (ValueError, OSError):
        return os.cpu_count() or 1


def parse_stat() -> dict[str, Any] | None:
    """Parse /proc/stat for per-CPU context switches and running processes."""
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

        # Per-CPU line: cpu<n> user nice system idle iowait irq softirq
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


def parse_loadavg() -> dict[str, Any] | None:
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


def parse_sched_debug() -> dict[int, dict] | None:
    """Parse /proc/sched_debug for detailed run queue info."""
    content = read_file('/proc/sched_debug')
    if content is None:
        return None

    result = {}
    current_cpu = None

    for line in content.split('\n'):
        if line.startswith('cpu#'):
            try:
                cpu_id = int(line.split('#')[1].split(',')[0])
                current_cpu = cpu_id
                result[cpu_id] = {
                    'id': cpu_id,
                    'nr_running': 0,
                    'nr_switches': 0,
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

    return result if result else None


def analyze_run_queues(stat_data: dict, loadavg_data: dict,
                       sched_debug_data: dict | None, cpu_count: int,
                       thresholds: dict) -> dict:
    """Analyze run queue data and identify issues."""
    issues = []
    warnings = []

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
            issues.append({
                'type': 'imbalance_critical',
                'message': f"CPU imbalance critical: {imbalance:.1f}% spread",
                'max_busy': max_busy,
                'min_busy': min_busy
            })
        elif imbalance > thresholds['imbalance_warning']:
            warnings.append({
                'type': 'imbalance_warning',
                'message': f"CPU imbalance detected: {imbalance:.1f}% spread",
                'max_busy': max_busy,
                'min_busy': min_busy
            })

        if avg_busy > thresholds['busy_critical']:
            issues.append({
                'type': 'busy_critical',
                'message': f"High CPU utilization: {avg_busy:.1f}% average",
                'avg_busy': avg_busy
            })
        elif avg_busy > thresholds['busy_warning']:
            warnings.append({
                'type': 'busy_warning',
                'message': f"Elevated CPU utilization: {avg_busy:.1f}% average",
                'avg_busy': avg_busy
            })

    # Check run queue depth
    if avg_queue_depth > thresholds['queue_critical']:
        issues.append({
            'type': 'queue_critical',
            'message': f"Run queue depth critical: {avg_queue_depth:.2f} per CPU",
            'avg_queue_depth': avg_queue_depth
        })
    elif avg_queue_depth > thresholds['queue_warning']:
        warnings.append({
            'type': 'queue_warning',
            'message': f"Run queue depth elevated: {avg_queue_depth:.2f} per CPU",
            'avg_queue_depth': avg_queue_depth
        })

    # Check for blocked processes
    blocked = stat_data.get('processes_blocked', 0) if stat_data else 0
    if blocked > thresholds['blocked_critical']:
        issues.append({
            'type': 'blocked_critical',
            'message': f"Many blocked processes: {blocked}",
            'blocked': blocked
        })
    elif blocked > thresholds['blocked_warning']:
        warnings.append({
            'type': 'blocked_warning',
            'message': f"Blocked processes: {blocked}",
            'blocked': blocked
        })

    # Per-CPU queues from sched_debug
    per_cpu_queues = {}
    if sched_debug_data:
        for cpu_id, data in sched_debug_data.items():
            per_cpu_queues[cpu_id] = data.get('nr_running', 0)

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


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor per-CPU run queue depth and scheduler statistics"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed per-CPU information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--queue-warning", type=float, default=1.0,
                        help="Warning threshold for avg queue depth per CPU (default: 1.0)")
    parser.add_argument("--queue-critical", type=float, default=2.0,
                        help="Critical threshold for avg queue depth per CPU (default: 2.0)")
    parser.add_argument("--imbalance-warning", type=float, default=30.0,
                        help="Warning threshold for CPU utilization imbalance %% (default: 30)")
    parser.add_argument("--imbalance-critical", type=float, default=50.0,
                        help="Critical threshold for CPU utilization imbalance %% (default: 50)")
    opts = parser.parse_args(args)

    # Gather data
    cpu_count = get_cpu_count()
    stat_data = parse_stat()
    loadavg_data = parse_loadavg()
    sched_debug_data = parse_sched_debug()

    if stat_data is None and loadavg_data is None:
        output.error("Unable to read scheduler statistics from /proc")
        return 2

    # Set thresholds
    thresholds = {
        'queue_warning': opts.queue_warning,
        'queue_critical': opts.queue_critical,
        'imbalance_warning': opts.imbalance_warning,
        'imbalance_critical': opts.imbalance_critical,
        'busy_warning': 70.0,
        'busy_critical': 90.0,
        'blocked_warning': cpu_count,
        'blocked_critical': cpu_count * 2
    }

    # Analyze
    analysis = analyze_run_queues(
        stat_data, loadavg_data, sched_debug_data, cpu_count, thresholds
    )

    # Build output
    result = {
        'cpu_count': cpu_count,
        'running_tasks': analysis['running_tasks'],
        'blocked_tasks': analysis['blocked_tasks'],
        'avg_queue_depth': analysis['avg_queue_depth'],
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
    }

    if loadavg_data:
        result['load_averages'] = {
            '1min': loadavg_data['load_1min'],
            '5min': loadavg_data['load_5min'],
            '15min': loadavg_data['load_15min']
        }

    if opts.verbose:
        result['per_cpu_busy_pct'] = analysis['cpu_busy']
        result['per_cpu_queues'] = analysis['per_cpu_queues']
        if stat_data:
            result['context_switches'] = stat_data.get('context_switches', 0)

    output.emit(result)

    # Set summary
    if analysis['issues']:
        output.set_summary(f"CRITICAL: {len(analysis['issues'])} issue(s)")
    elif analysis['warnings']:
        output.set_summary(f"WARNING: {len(analysis['warnings'])} warning(s)")
    else:
        output.set_summary(f"Healthy (queue depth: {analysis['avg_queue_depth']:.2f})")

    return 1 if analysis['issues'] else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
