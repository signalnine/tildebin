#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [cpu, scheduler, affinity, realtime, latency]
#   requires: []
#   privilege: user
#   related: [run_queue, smt_status]
#   brief: Audit CPU affinity and scheduler policy configuration

"""
Audit CPU affinity and scheduler policy configuration for processes.

This script analyzes process CPU affinity masks, scheduler policies (SCHED_FIFO,
SCHED_RR, SCHED_OTHER), and identifies misconfigurations that can cause latency
spikes in latency-sensitive workloads.

Useful for:
- Detecting processes not pinned to expected CPUs
- Finding real-time (RT) processes that may starve other workloads
- Identifying CPU isolation violations
- Auditing scheduler class configurations
- Detecting processes with conflicting affinity settings
"""

import argparse
import os
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Scheduler policy constants (from sched.h)
SCHED_POLICIES = {
    0: 'SCHED_OTHER',
    1: 'SCHED_FIFO',
    2: 'SCHED_RR',
    3: 'SCHED_BATCH',
    5: 'SCHED_IDLE',
    6: 'SCHED_DEADLINE'
}


def get_cpu_count() -> int:
    """Get number of CPU cores from /proc/cpuinfo."""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            return sum(1 for line in f if line.startswith('processor'))
    except Exception:
        return os.cpu_count() or 1


def parse_cpu_mask(mask_str: str, num_cpus: int) -> list[int] | None:
    """Parse CPU affinity mask to list of CPU IDs."""
    try:
        mask_str = mask_str.replace(',', '')
        mask = int(mask_str, 16)
        cpus = []
        for i in range(num_cpus):
            if mask & (1 << i):
                cpus.append(i)
        return cpus
    except ValueError:
        return None


def get_isolated_cpus() -> list[int]:
    """Get list of isolated CPUs from kernel cmdline."""
    isolated = []
    try:
        with open('/proc/cmdline', 'r') as f:
            cmdline = f.read()

        for part in cmdline.split():
            if part.startswith('isolcpus='):
                cpu_spec = part.split('=')[1]
                isolated = parse_cpu_list(cpu_spec)
                break
    except Exception:
        pass

    return isolated


def parse_cpu_list(cpu_spec: str) -> list[int]:
    """Parse CPU list specification (e.g., '0,2-4,6' -> [0,2,3,4,6])."""
    cpus = []
    try:
        for part in cpu_spec.split(','):
            if '-' in part:
                start, end = part.split('-')
                cpus.extend(range(int(start), int(end) + 1))
            else:
                cpus.append(int(part))
    except ValueError:
        pass
    return cpus


def get_process_info(pid: int) -> dict[str, Any] | None:
    """Get scheduler and affinity info for a process."""
    info = {
        'pid': pid,
        'name': None,
        'cmdline': None,
        'policy': None,
        'policy_name': None,
        'priority': None,
        'affinity_mask': None,
        'allowed_cpus': [],
    }

    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            info['name'] = f.read().strip()

        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            info['cmdline'] = cmdline[:100] if cmdline else info['name']

        with open(f'/proc/{pid}/sched', 'r') as f:
            for line in f:
                if line.startswith('policy'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        info['policy'] = int(parts[1].strip())
                        info['policy_name'] = SCHED_POLICIES.get(
                            info['policy'], f'UNKNOWN({info["policy"]})'
                        )
                elif line.startswith('prio'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        info['priority'] = int(parts[1].strip())

        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('Cpus_allowed:'):
                    info['affinity_mask'] = line.split(':')[1].strip()
                    break

    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    except Exception:
        return None

    return info


def scan_processes(filter_rt: bool = False, filter_pinned: bool = False,
                   filter_pattern: str | None = None) -> tuple[list, int]:
    """Scan all processes and collect scheduler/affinity info."""
    processes = []
    num_cpus = get_cpu_count()

    for pid_str in os.listdir('/proc'):
        if not pid_str.isdigit():
            continue

        pid = int(pid_str)
        info = get_process_info(pid)
        if not info:
            continue

        if info['affinity_mask']:
            info['allowed_cpus'] = parse_cpu_mask(info['affinity_mask'], num_cpus)

        # Apply filters
        if filter_rt and info['policy'] not in [1, 2, 6]:
            continue

        if filter_pinned:
            if info['allowed_cpus'] and len(info['allowed_cpus']) >= num_cpus:
                continue

        if filter_pattern:
            if filter_pattern.lower() not in (info['name'] or '').lower():
                if filter_pattern.lower() not in (info['cmdline'] or '').lower():
                    continue

        processes.append(info)

    return processes, num_cpus


def analyze_issues(processes: list, num_cpus: int,
                   isolated_cpus: list) -> tuple[list, list]:
    """Analyze processes for scheduler/affinity issues."""
    issues = []
    rt_processes = []

    cpu_rt_count = defaultdict(int)

    for proc in processes:
        if proc['policy'] in [1, 2]:  # SCHED_FIFO or SCHED_RR
            rt_processes.append(proc)

            if proc['priority'] is not None and proc['priority'] >= 90:
                issues.append({
                    'severity': 'INFO',
                    'type': 'high_priority_rt',
                    'pid': proc['pid'],
                    'name': proc['name'],
                    'message': f"High-priority RT: {proc['name']} (PID {proc['pid']}, prio={proc['priority']})",
                    'priority': proc['priority']
                })

            for cpu in proc['allowed_cpus'] or []:
                cpu_rt_count[cpu] += 1

        # Check for isolation violations
        if isolated_cpus and proc['allowed_cpus']:
            violations = set(proc['allowed_cpus']) & set(isolated_cpus)
            if violations and proc['policy'] == 0:
                if len(proc['allowed_cpus']) < num_cpus:
                    issues.append({
                        'severity': 'WARNING',
                        'type': 'isolation_violation',
                        'pid': proc['pid'],
                        'name': proc['name'],
                        'message': f"Process {proc['name']} pinned to isolated CPU(s): {sorted(violations)}",
                        'cpus': sorted(violations)
                    })

        # Check for RT contention
        if proc['allowed_cpus'] and len(proc['allowed_cpus']) == 1:
            if proc['policy'] in [1, 2]:
                cpu = proc['allowed_cpus'][0]
                if cpu_rt_count[cpu] > 1:
                    issues.append({
                        'severity': 'WARNING',
                        'type': 'rt_cpu_contention',
                        'pid': proc['pid'],
                        'name': proc['name'],
                        'message': f"Multiple RT processes on CPU{cpu}",
                        'cpu': cpu
                    })

    # Check for CPUs with many RT processes
    for cpu, count in cpu_rt_count.items():
        if count >= 3:
            issues.append({
                'severity': 'WARNING',
                'type': 'rt_concentration',
                'cpu': cpu,
                'count': count,
                'message': f"CPU{cpu} has {count} RT processes pinned"
            })

    return issues, rt_processes


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = warnings found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit CPU affinity and scheduler policy configuration"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed process lists")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--rt-only", action="store_true",
                        help="Only show real-time (FIFO/RR/DEADLINE) processes")
    parser.add_argument("--pinned-only", action="store_true",
                        help="Only show CPU-pinned processes")
    parser.add_argument("--filter", metavar="PATTERN",
                        help="Filter processes by name pattern")
    opts = parser.parse_args(args)

    # Check for procfs
    if not os.path.exists('/proc'):
        output.error("/proc filesystem not found")

        output.render(opts.format, "Audit CPU affinity and scheduler policy configuration")
        return 2

    # Get isolated CPUs
    isolated_cpus = get_isolated_cpus()

    # Scan processes
    processes, num_cpus = scan_processes(
        filter_rt=opts.rt_only,
        filter_pinned=opts.pinned_only,
        filter_pattern=opts.filter
    )

    if not processes:
        output.emit({
            'cpu_count': num_cpus,
            'isolated_cpus': isolated_cpus,
            'total_processes': 0,
            'rt_processes': 0,
            'issues': [],
        })
        output.set_summary("No processes found matching criteria")

        output.render(opts.format, "Audit CPU affinity and scheduler policy configuration")
        return 0

    # Analyze issues
    issues, rt_processes = analyze_issues(processes, num_cpus, isolated_cpus)

    # Build policy distribution
    policy_counts = defaultdict(int)
    for proc in processes:
        policy_name = proc['policy_name'] or 'SCHED_OTHER'
        policy_counts[policy_name] += 1

    # Build output
    result = {
        'cpu_count': num_cpus,
        'isolated_cpus': sorted(isolated_cpus) if isolated_cpus else [],
        'total_processes': len(processes),
        'rt_process_count': len(rt_processes),
        'issue_count': len(issues),
        'warning_count': sum(1 for i in issues if i['severity'] == 'WARNING'),
        'policy_distribution': dict(policy_counts),
        'issues': issues,
    }

    if opts.verbose:
        result['rt_processes'] = [
            {
                'pid': p['pid'],
                'name': p['name'],
                'policy': p['policy_name'],
                'priority': p['priority'],
                'allowed_cpus': p['allowed_cpus']
            }
            for p in rt_processes
        ]

    output.emit(result)

    # Set summary
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)
    if has_warnings:
        output.set_summary(f"{result['warning_count']} warning(s), {len(rt_processes)} RT processes")
    else:
        output.set_summary(f"No issues, {len(rt_processes)} RT processes")


    output.render(opts.format, "Audit CPU affinity and scheduler policy configuration")
    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
