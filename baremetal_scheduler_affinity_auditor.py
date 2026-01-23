#!/usr/bin/env python3
"""
Audit CPU affinity and scheduler policy configuration for processes.

This script analyzes process CPU affinity masks, scheduler policies (SCHED_FIFO,
SCHED_RR, SCHED_OTHER), and identifies misconfigurations that can cause latency
spikes in latency-sensitive workloads. Useful for:

- Detecting processes not pinned to expected CPUs
- Finding real-time (RT) processes that may starve other workloads
- Identifying CPU isolation violations
- Auditing scheduler class configurations
- Detecting processes with conflicting affinity settings

Exit codes:
    0 - No issues detected (all processes properly configured)
    1 - Warnings or issues detected (misconfigurations found)
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
from collections import defaultdict


# Scheduler policy constants (from sched.h)
SCHED_POLICIES = {
    0: 'SCHED_OTHER',   # Standard time-sharing
    1: 'SCHED_FIFO',    # First-in, first-out real-time
    2: 'SCHED_RR',      # Round-robin real-time
    3: 'SCHED_BATCH',   # Batch processing
    5: 'SCHED_IDLE',    # Very low priority background
    6: 'SCHED_DEADLINE' # Deadline-based scheduling
}


def get_cpu_count():
    """Get number of CPU cores from /proc/cpuinfo"""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            return sum(1 for line in f if line.startswith('processor'))
    except Exception:
        return os.cpu_count() or 1


def parse_cpu_mask(mask_str, num_cpus):
    """Parse CPU affinity mask to list of CPU IDs"""
    try:
        # Remove commas from mask (e.g., "ff,ffffffff" -> "ffffffffff")
        mask_str = mask_str.replace(',', '')
        mask = int(mask_str, 16)
        cpus = []
        for i in range(num_cpus):
            if mask & (1 << i):
                cpus.append(i)
        return cpus
    except ValueError:
        return None


def get_isolated_cpus():
    """Get list of isolated CPUs from kernel cmdline"""
    isolated = []
    try:
        with open('/proc/cmdline', 'r') as f:
            cmdline = f.read()

        # Parse isolcpus= parameter
        for part in cmdline.split():
            if part.startswith('isolcpus='):
                cpu_spec = part.split('=')[1]
                isolated = parse_cpu_list(cpu_spec)
                break
    except Exception:
        pass

    return isolated


def parse_cpu_list(cpu_spec):
    """Parse CPU list specification (e.g., '0,2-4,6' -> [0,2,3,4,6])"""
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


def get_process_info(pid):
    """Get scheduler and affinity info for a process"""
    info = {
        'pid': pid,
        'name': None,
        'cmdline': None,
        'policy': None,
        'policy_name': None,
        'priority': None,
        'affinity_mask': None,
        'allowed_cpus': [],
        'threads': []
    }

    try:
        # Get process name
        with open(f'/proc/{pid}/comm', 'r') as f:
            info['name'] = f.read().strip()

        # Get command line
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            info['cmdline'] = cmdline[:100] if cmdline else info['name']

        # Get scheduler policy and priority from /proc/[pid]/sched
        with open(f'/proc/{pid}/sched', 'r') as f:
            for line in f:
                if line.startswith('policy'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        info['policy'] = int(parts[1].strip())
                        info['policy_name'] = SCHED_POLICIES.get(info['policy'], f'UNKNOWN({info["policy"]})')
                elif line.startswith('prio'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        info['priority'] = int(parts[1].strip())

        # Get CPU affinity mask
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('Cpus_allowed:'):
                    info['affinity_mask'] = line.split(':')[1].strip()
                    break

        # Get thread info
        task_dir = f'/proc/{pid}/task'
        if os.path.isdir(task_dir):
            for tid in os.listdir(task_dir):
                if tid != str(pid):  # Skip main thread (already covered)
                    thread_info = get_thread_info(pid, tid)
                    if thread_info:
                        info['threads'].append(thread_info)

    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    except Exception:
        return None

    return info


def get_thread_info(pid, tid):
    """Get scheduler info for a specific thread"""
    try:
        info = {'tid': int(tid), 'name': None, 'policy': None, 'affinity_mask': None}

        with open(f'/proc/{pid}/task/{tid}/comm', 'r') as f:
            info['name'] = f.read().strip()

        with open(f'/proc/{pid}/task/{tid}/sched', 'r') as f:
            for line in f:
                if line.startswith('policy'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        info['policy'] = int(parts[1].strip())

        with open(f'/proc/{pid}/task/{tid}/status', 'r') as f:
            for line in f:
                if line.startswith('Cpus_allowed:'):
                    info['affinity_mask'] = line.split(':')[1].strip()
                    break

        return info
    except Exception:
        return None


def scan_processes(filter_rt=False, filter_pinned=False, filter_pattern=None):
    """Scan all processes and collect scheduler/affinity info"""
    processes = []
    num_cpus = get_cpu_count()

    for pid_str in os.listdir('/proc'):
        if not pid_str.isdigit():
            continue

        pid = int(pid_str)
        info = get_process_info(pid)
        if not info:
            continue

        # Parse affinity to CPU list
        if info['affinity_mask']:
            info['allowed_cpus'] = parse_cpu_mask(info['affinity_mask'], num_cpus)

        # Apply filters
        if filter_rt and info['policy'] not in [1, 2, 6]:  # FIFO, RR, DEADLINE
            continue

        if filter_pinned:
            # Pinned = not using all CPUs
            if info['allowed_cpus'] and len(info['allowed_cpus']) >= num_cpus:
                continue

        if filter_pattern:
            if filter_pattern.lower() not in (info['name'] or '').lower():
                if filter_pattern.lower() not in (info['cmdline'] or '').lower():
                    continue

        processes.append(info)

    return processes, num_cpus


def analyze_issues(processes, num_cpus, isolated_cpus):
    """Analyze processes for scheduler/affinity issues"""
    issues = []

    # Track RT processes
    rt_processes = []
    high_priority_rt = []

    # Track CPU usage patterns
    cpu_rt_count = defaultdict(int)  # RT processes per CPU

    for proc in processes:
        # Check for real-time processes
        if proc['policy'] in [1, 2]:  # SCHED_FIFO or SCHED_RR
            rt_processes.append(proc)

            # Check for very high priority RT (potential starvation risk)
            if proc['priority'] is not None and proc['priority'] >= 90:
                high_priority_rt.append(proc)

            # Track RT process CPU assignments
            for cpu in proc['allowed_cpus']:
                cpu_rt_count[cpu] += 1

        # Check for processes running on isolated CPUs (violation)
        if isolated_cpus and proc['allowed_cpus']:
            violations = set(proc['allowed_cpus']) & set(isolated_cpus)
            if violations and proc['policy'] == 0:  # Only flag non-RT on isolated
                # Only flag if process is specifically pinned to isolated CPUs
                if len(proc['allowed_cpus']) < num_cpus:
                    issues.append({
                        'severity': 'WARNING',
                        'type': 'isolation_violation',
                        'pid': proc['pid'],
                        'name': proc['name'],
                        'message': f"Process {proc['name']} (PID {proc['pid']}) pinned to isolated CPU(s): {sorted(violations)}",
                        'cpus': sorted(violations)
                    })

        # Check for single-CPU pinning (potential bottleneck)
        if proc['allowed_cpus'] and len(proc['allowed_cpus']) == 1:
            if proc['policy'] in [1, 2]:  # RT process pinned to single CPU
                cpu = proc['allowed_cpus'][0]
                if cpu_rt_count[cpu] > 1:
                    issues.append({
                        'severity': 'WARNING',
                        'type': 'rt_cpu_contention',
                        'pid': proc['pid'],
                        'name': proc['name'],
                        'message': f"Multiple RT processes pinned to CPU{cpu}",
                        'cpu': cpu
                    })

    # Flag high-priority RT processes (potential starvation)
    for proc in high_priority_rt:
        issues.append({
            'severity': 'INFO',
            'type': 'high_priority_rt',
            'pid': proc['pid'],
            'name': proc['name'],
            'message': f"High-priority RT process: {proc['name']} (PID {proc['pid']}, {proc['policy_name']}, prio={proc['priority']})",
            'priority': proc['priority']
        })

    # Check for CPUs with many RT processes
    for cpu, count in cpu_rt_count.items():
        if count >= 3:
            issues.append({
                'severity': 'WARNING',
                'type': 'rt_concentration',
                'cpu': cpu,
                'count': count,
                'message': f"CPU{cpu} has {count} RT processes pinned to it"
            })

    return issues, rt_processes


def output_plain(processes, issues, rt_processes, num_cpus, isolated_cpus, verbose=False, warn_only=False):
    """Output results in plain text format"""
    if warn_only and not issues:
        return

    if not warn_only:
        print(f"CPU Count: {num_cpus}")
        print(f"Isolated CPUs: {sorted(isolated_cpus) if isolated_cpus else 'None'}")
        print(f"Total Processes Scanned: {len(processes)}")
        print(f"Real-Time Processes: {len(rt_processes)}")
        print()

    if issues:
        print(f"Found {len(issues)} scheduler/affinity issues:")
        print("=" * 60)
        for issue in sorted(issues, key=lambda x: (x['severity'] != 'WARNING', x['type'])):
            severity_marker = "[!]" if issue['severity'] == 'WARNING' else "[i]"
            print(f"{severity_marker} {issue['message']}")
        print()

    if verbose and not warn_only:
        # Show RT processes summary
        if rt_processes:
            print("Real-Time Processes:")
            print("=" * 80)
            print(f"{'PID':<8} {'Name':<20} {'Policy':<15} {'Prio':>5} {'CPUs':<20}")
            print("-" * 80)
            for proc in sorted(rt_processes, key=lambda x: x['priority'] or 0, reverse=True):
                cpus_str = ','.join(map(str, proc['allowed_cpus'][:5]))
                if len(proc['allowed_cpus']) > 5:
                    cpus_str += '...'
                print(f"{proc['pid']:<8} {proc['name'][:20]:<20} {proc['policy_name']:<15} "
                      f"{proc['priority'] or 0:>5} {cpus_str:<20}")
            print()

        # Show pinned processes
        pinned = [p for p in processes if p['allowed_cpus'] and len(p['allowed_cpus']) < num_cpus]
        if pinned:
            print(f"Pinned Processes ({len(pinned)} total):")
            print("=" * 80)
            print(f"{'PID':<8} {'Name':<20} {'Policy':<15} {'CPUs':<30}")
            print("-" * 80)
            for proc in sorted(pinned, key=lambda x: len(x['allowed_cpus']))[:20]:
                cpus_str = ','.join(map(str, proc['allowed_cpus'][:10]))
                if len(proc['allowed_cpus']) > 10:
                    cpus_str += '...'
                print(f"{proc['pid']:<8} {proc['name'][:20]:<20} {proc['policy_name'] or 'SCHED_OTHER':<15} {cpus_str:<30}")
            if len(pinned) > 20:
                print(f"... and {len(pinned) - 20} more")
            print()

    if not warn_only:
        if not issues:
            print("No scheduler/affinity issues detected.")


def output_json(processes, issues, rt_processes, num_cpus, isolated_cpus):
    """Output results in JSON format"""
    # Summarize by policy
    policy_counts = defaultdict(int)
    for proc in processes:
        policy_name = proc['policy_name'] or 'SCHED_OTHER'
        policy_counts[policy_name] += 1

    output = {
        'summary': {
            'cpu_count': num_cpus,
            'isolated_cpus': sorted(isolated_cpus) if isolated_cpus else [],
            'total_processes': len(processes),
            'rt_processes': len(rt_processes),
            'issue_count': len(issues),
            'warning_count': sum(1 for i in issues if i['severity'] == 'WARNING'),
            'policy_distribution': dict(policy_counts)
        },
        'issues': issues,
        'rt_processes': [
            {
                'pid': p['pid'],
                'name': p['name'],
                'policy': p['policy_name'],
                'priority': p['priority'],
                'allowed_cpus': p['allowed_cpus']
            }
            for p in rt_processes
        ]
    }
    print(json.dumps(output, indent=2))


def output_table(processes, issues, rt_processes, num_cpus, isolated_cpus, warn_only=False):
    """Output results in table format"""
    if warn_only and not issues:
        return

    if not warn_only:
        # Policy distribution table
        policy_counts = defaultdict(int)
        for proc in processes:
            policy_name = proc['policy_name'] or 'SCHED_OTHER'
            policy_counts[policy_name] += 1

        print(f"{'Policy':<20} {'Count':>10}")
        print("=" * 32)
        for policy, count in sorted(policy_counts.items(), key=lambda x: -x[1]):
            print(f"{policy:<20} {count:>10}")
        print()

    if issues:
        print(f"{'Severity':<10} {'Type':<25} {'Details':<45}")
        print("=" * 80)
        for issue in issues:
            details = issue.get('name', '') or ''
            if 'pid' in issue:
                details = f"PID {issue['pid']} ({details[:30]})"
            elif 'cpu' in issue:
                details = f"CPU{issue['cpu']}"
            print(f"{issue['severity']:<10} {issue['type']:<25} {details[:45]:<45}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Audit CPU affinity and scheduler policy configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Full scheduler audit
  %(prog)s --rt-only                # Show only real-time processes
  %(prog)s --pinned-only            # Show only CPU-pinned processes
  %(prog)s --filter nginx           # Filter by process name
  %(prog)s --format json            # JSON output for scripting
  %(prog)s -v                       # Verbose output with process lists

Scheduler policies:
  SCHED_OTHER    - Standard time-sharing (default)
  SCHED_FIFO     - First-in, first-out real-time
  SCHED_RR       - Round-robin real-time
  SCHED_BATCH    - Batch processing (lower priority)
  SCHED_IDLE     - Very low priority background
  SCHED_DEADLINE - Deadline-based scheduling

Issues detected:
  - RT processes with very high priority (starvation risk)
  - Multiple RT processes pinned to same CPU (contention)
  - Non-RT processes on isolated CPUs (isolation violation)
  - CPU oversubscription with RT processes
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
        help='Show detailed process lists'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    parser.add_argument(
        '--rt-only',
        action='store_true',
        help='Only show real-time (FIFO/RR/DEADLINE) processes'
    )

    parser.add_argument(
        '--pinned-only',
        action='store_true',
        help='Only show CPU-pinned processes'
    )

    parser.add_argument(
        '--filter',
        metavar='PATTERN',
        help='Filter processes by name pattern'
    )

    args = parser.parse_args()

    # Check for procfs availability
    if not os.path.exists('/proc'):
        print("Error: /proc filesystem not found", file=sys.stderr)
        print("This script requires Linux procfs", file=sys.stderr)
        sys.exit(2)

    # Get isolated CPUs
    isolated_cpus = get_isolated_cpus()

    # Scan processes
    processes, num_cpus = scan_processes(
        filter_rt=args.rt_only,
        filter_pinned=args.pinned_only,
        filter_pattern=args.filter
    )

    if not processes:
        if args.format == 'json':
            print(json.dumps({'summary': {'total_processes': 0}, 'issues': [], 'rt_processes': []}))
        else:
            print("No processes found matching criteria.")
        sys.exit(0)

    # Analyze issues
    issues, rt_processes = analyze_issues(processes, num_cpus, isolated_cpus)

    # Output results
    if args.format == 'json':
        output_json(processes, issues, rt_processes, num_cpus, isolated_cpus)
    elif args.format == 'table':
        output_table(processes, issues, rt_processes, num_cpus, isolated_cpus, args.warn_only)
    else:  # plain
        output_plain(processes, issues, rt_processes, num_cpus, isolated_cpus, args.verbose, args.warn_only)

    # Exit based on findings
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)
    sys.exit(1 if has_warnings else 0)


if __name__ == "__main__":
    main()
