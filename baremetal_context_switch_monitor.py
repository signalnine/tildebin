#!/usr/bin/env python3
"""
Monitor context switch rates to detect CPU contention and scheduling overhead.

Context switches occur when the CPU switches from one process/thread to another.
High context switch rates can indicate:
- CPU contention (too many runnable processes)
- Excessive thread synchronization (lock contention)
- Poor process affinity (processes bouncing between CPUs)
- Interrupt storms causing frequent preemption

This script reads from /proc/stat and /proc/vmstat to measure:
- System-wide context switches per second
- Per-CPU voluntary vs involuntary context switches
- Interrupt rates that may drive context switches

Exit codes:
    0 - No issues detected (context switch rates within thresholds)
    1 - Warnings or issues detected (high context switch rates)
    2 - Usage error or required files not available
"""

import argparse
import sys
import json
import time
import os


def read_proc_stat():
    """Read context switch and interrupt counts from /proc/stat"""
    try:
        with open('/proc/stat', 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("Error: /proc/stat not found", file=sys.stderr)
        print("This script requires a Linux system", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Permission denied reading /proc/stat", file=sys.stderr)
        sys.exit(2)

    stats = {}
    for line in lines:
        parts = line.split()
        if parts[0] == 'ctxt':
            stats['context_switches'] = int(parts[1])
        elif parts[0] == 'intr':
            # First number is total interrupts, rest are per-interrupt counts
            stats['interrupts'] = int(parts[1])
        elif parts[0] == 'processes':
            stats['processes_created'] = int(parts[1])
        elif parts[0] == 'procs_running':
            stats['procs_running'] = int(parts[1])
        elif parts[0] == 'procs_blocked':
            stats['procs_blocked'] = int(parts[1])

    return stats


def read_proc_vmstat():
    """Read additional scheduling stats from /proc/vmstat"""
    stats = {}
    try:
        with open('/proc/vmstat', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    key, value = parts[0], parts[1]
                    # Look for scheduling-related stats
                    if key in ['nr_running', 'nr_iowait', 'pgfault', 'pgmajfault']:
                        stats[key] = int(value)
    except (FileNotFoundError, PermissionError):
        pass  # /proc/vmstat is optional

    return stats


def read_cpu_count():
    """Get the number of CPUs"""
    try:
        with open('/proc/stat', 'r') as f:
            cpu_count = 0
            for line in f:
                if line.startswith('cpu') and line[3].isdigit():
                    cpu_count += 1
            return cpu_count if cpu_count > 0 else 1
    except (FileNotFoundError, PermissionError):
        return 1


def sample_rates(interval=1.0):
    """Sample context switch rates over an interval"""
    stat1 = read_proc_stat()
    vmstat1 = read_proc_vmstat()
    time.sleep(interval)
    stat2 = read_proc_stat()
    vmstat2 = read_proc_vmstat()

    cpu_count = read_cpu_count()

    # Calculate per-second rates
    ctxt_rate = (stat2['context_switches'] - stat1['context_switches']) / interval
    intr_rate = (stat2['interrupts'] - stat1['interrupts']) / interval
    proc_rate = (stat2.get('processes_created', 0) - stat1.get('processes_created', 0)) / interval

    # Current process states
    procs_running = stat2.get('procs_running', 0)
    procs_blocked = stat2.get('procs_blocked', 0)

    # Per-CPU rates
    ctxt_per_cpu = ctxt_rate / cpu_count
    intr_per_cpu = intr_rate / cpu_count

    # Page fault rates if available
    pgfault_rate = 0
    pgmajfault_rate = 0
    if 'pgfault' in vmstat1 and 'pgfault' in vmstat2:
        pgfault_rate = (vmstat2['pgfault'] - vmstat1['pgfault']) / interval
    if 'pgmajfault' in vmstat1 and 'pgmajfault' in vmstat2:
        pgmajfault_rate = (vmstat2['pgmajfault'] - vmstat1['pgmajfault']) / interval

    return {
        'context_switches_per_sec': round(ctxt_rate, 1),
        'context_switches_per_cpu': round(ctxt_per_cpu, 1),
        'interrupts_per_sec': round(intr_rate, 1),
        'interrupts_per_cpu': round(intr_per_cpu, 1),
        'processes_created_per_sec': round(proc_rate, 1),
        'procs_running': procs_running,
        'procs_blocked': procs_blocked,
        'cpu_count': cpu_count,
        'page_faults_per_sec': round(pgfault_rate, 1),
        'major_page_faults_per_sec': round(pgmajfault_rate, 1),
        'sample_interval': interval,
    }


def analyze_issues(rates, thresholds):
    """Analyze context switch rates for potential issues"""
    issues = []

    # Check context switch rate per CPU
    if rates['context_switches_per_cpu'] >= thresholds['ctxt_per_cpu_critical']:
        issues.append({
            'severity': 'CRITICAL',
            'category': 'context_switches',
            'message': f"Very high context switch rate: {rates['context_switches_per_cpu']:.0f}/s per CPU "
                      f"(threshold: {thresholds['ctxt_per_cpu_critical']})",
            'value': rates['context_switches_per_cpu'],
        })
    elif rates['context_switches_per_cpu'] >= thresholds['ctxt_per_cpu_warning']:
        issues.append({
            'severity': 'WARNING',
            'category': 'context_switches',
            'message': f"Elevated context switch rate: {rates['context_switches_per_cpu']:.0f}/s per CPU "
                      f"(threshold: {thresholds['ctxt_per_cpu_warning']})",
            'value': rates['context_switches_per_cpu'],
        })

    # Check interrupt rate per CPU
    if rates['interrupts_per_cpu'] >= thresholds['intr_per_cpu_critical']:
        issues.append({
            'severity': 'CRITICAL',
            'category': 'interrupts',
            'message': f"Very high interrupt rate: {rates['interrupts_per_cpu']:.0f}/s per CPU "
                      f"(threshold: {thresholds['intr_per_cpu_critical']})",
            'value': rates['interrupts_per_cpu'],
        })
    elif rates['interrupts_per_cpu'] >= thresholds['intr_per_cpu_warning']:
        issues.append({
            'severity': 'WARNING',
            'category': 'interrupts',
            'message': f"Elevated interrupt rate: {rates['interrupts_per_cpu']:.0f}/s per CPU "
                      f"(threshold: {thresholds['intr_per_cpu_warning']})",
            'value': rates['interrupts_per_cpu'],
        })

    # Check runnable process count (run queue depth)
    run_queue_per_cpu = rates['procs_running'] / rates['cpu_count']
    if run_queue_per_cpu >= thresholds['run_queue_critical']:
        issues.append({
            'severity': 'CRITICAL',
            'category': 'run_queue',
            'message': f"High run queue depth: {run_queue_per_cpu:.1f} per CPU "
                      f"({rates['procs_running']} total runnable, threshold: {thresholds['run_queue_critical']})",
            'value': run_queue_per_cpu,
        })
    elif run_queue_per_cpu >= thresholds['run_queue_warning']:
        issues.append({
            'severity': 'WARNING',
            'category': 'run_queue',
            'message': f"Elevated run queue depth: {run_queue_per_cpu:.1f} per CPU "
                      f"({rates['procs_running']} total runnable, threshold: {thresholds['run_queue_warning']})",
            'value': run_queue_per_cpu,
        })

    # Check blocked processes
    if rates['procs_blocked'] >= thresholds['blocked_critical']:
        issues.append({
            'severity': 'CRITICAL',
            'category': 'blocked_processes',
            'message': f"Many blocked processes: {rates['procs_blocked']} "
                      f"(threshold: {thresholds['blocked_critical']})",
            'value': rates['procs_blocked'],
        })
    elif rates['procs_blocked'] >= thresholds['blocked_warning']:
        issues.append({
            'severity': 'WARNING',
            'category': 'blocked_processes',
            'message': f"Blocked processes detected: {rates['procs_blocked']} "
                      f"(threshold: {thresholds['blocked_warning']})",
            'value': rates['procs_blocked'],
        })

    # Check process creation rate (fork storms)
    if rates['processes_created_per_sec'] >= thresholds['fork_rate_critical']:
        issues.append({
            'severity': 'CRITICAL',
            'category': 'fork_rate',
            'message': f"Very high process creation rate: {rates['processes_created_per_sec']:.0f}/s "
                      f"(threshold: {thresholds['fork_rate_critical']})",
            'value': rates['processes_created_per_sec'],
        })
    elif rates['processes_created_per_sec'] >= thresholds['fork_rate_warning']:
        issues.append({
            'severity': 'WARNING',
            'category': 'fork_rate',
            'message': f"Elevated process creation rate: {rates['processes_created_per_sec']:.0f}/s "
                      f"(threshold: {thresholds['fork_rate_warning']})",
            'value': rates['processes_created_per_sec'],
        })

    return issues


def output_plain(rates, issues, verbose=False, warn_only=False):
    """Output results in plain text format"""
    if warn_only and not issues:
        return

    if not warn_only:
        print("Context Switch Monitor")
        print("=" * 50)
        print(f"  CPUs:                    {rates['cpu_count']}")
        print(f"  Sample interval:         {rates['sample_interval']}s")
        print()
        print("Context Switches")
        print("-" * 50)
        print(f"  Total rate:              {rates['context_switches_per_sec']:,.0f}/s")
        print(f"  Per-CPU rate:            {rates['context_switches_per_cpu']:,.0f}/s")
        print()
        print("Interrupts")
        print("-" * 50)
        print(f"  Total rate:              {rates['interrupts_per_sec']:,.0f}/s")
        print(f"  Per-CPU rate:            {rates['interrupts_per_cpu']:,.0f}/s")
        print()
        print("Process Activity")
        print("-" * 50)
        print(f"  Processes running:       {rates['procs_running']}")
        print(f"  Processes blocked:       {rates['procs_blocked']}")
        print(f"  Fork rate:               {rates['processes_created_per_sec']:.0f}/s")

        if verbose and rates['page_faults_per_sec'] > 0:
            print()
            print("Memory Activity")
            print("-" * 50)
            print(f"  Page faults/sec:         {rates['page_faults_per_sec']:,.0f}")
            print(f"  Major page faults/sec:   {rates['major_page_faults_per_sec']:,.0f}")

        print()

    # Show issues
    if issues:
        print("Issues Detected")
        print("=" * 50)
        for issue in sorted(issues, key=lambda x: (x['severity'] != 'CRITICAL', x['category'])):
            marker = "!!!" if issue['severity'] == 'CRITICAL' else "  "
            print(f"{marker} [{issue['severity']}] {issue['message']}")
    elif not warn_only:
        print("No issues detected")


def output_json(rates, issues):
    """Output results in JSON format"""
    output = {
        'summary': {
            'cpu_count': rates['cpu_count'],
            'sample_interval': rates['sample_interval'],
            'issue_count': len(issues),
            'critical_count': sum(1 for i in issues if i['severity'] == 'CRITICAL'),
            'warning_count': sum(1 for i in issues if i['severity'] == 'WARNING'),
        },
        'context_switches': {
            'total_per_sec': rates['context_switches_per_sec'],
            'per_cpu_per_sec': rates['context_switches_per_cpu'],
        },
        'interrupts': {
            'total_per_sec': rates['interrupts_per_sec'],
            'per_cpu_per_sec': rates['interrupts_per_cpu'],
        },
        'processes': {
            'running': rates['procs_running'],
            'blocked': rates['procs_blocked'],
            'created_per_sec': rates['processes_created_per_sec'],
        },
        'memory': {
            'page_faults_per_sec': rates['page_faults_per_sec'],
            'major_page_faults_per_sec': rates['major_page_faults_per_sec'],
        },
        'issues': issues,
    }
    print(json.dumps(output, indent=2))


def output_table(rates, issues, warn_only=False):
    """Output results in table format"""
    if warn_only and not issues:
        return

    if not warn_only:
        print(f"{'Metric':<30} {'Value':>15} {'Per CPU':>15}")
        print("=" * 60)
        print(f"{'Context switches/sec':<30} {rates['context_switches_per_sec']:>15,.0f} {rates['context_switches_per_cpu']:>15,.0f}")
        print(f"{'Interrupts/sec':<30} {rates['interrupts_per_sec']:>15,.0f} {rates['interrupts_per_cpu']:>15,.0f}")
        print(f"{'Processes running':<30} {rates['procs_running']:>15} {rates['procs_running']/rates['cpu_count']:>15.1f}")
        print(f"{'Processes blocked':<30} {rates['procs_blocked']:>15} {'-':>15}")
        print(f"{'Forks/sec':<30} {rates['processes_created_per_sec']:>15,.0f} {'-':>15}")
        print()

    if issues:
        print(f"{'Severity':<10} {'Category':<20} {'Message':<50}")
        print("=" * 80)
        for issue in issues:
            print(f"{issue['severity']:<10} {issue['category']:<20} {issue['message'][:50]:<50}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Monitor context switch rates to detect CPU contention',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic context switch monitoring
  %(prog)s -v                       # Include memory activity stats
  %(prog)s --format json            # JSON output for scripting
  %(prog)s --interval 5             # Sample over 5 seconds
  %(prog)s --warn-only              # Only show issues

What context switches indicate:
  - Normal: 1,000-10,000/s per CPU on a busy server
  - Elevated: 10,000-50,000/s per CPU may indicate contention
  - High: >50,000/s per CPU suggests scheduling problems

Common causes of high context switches:
  - Too many runnable threads competing for CPUs
  - Lock contention causing threads to sleep/wake frequently
  - Interrupt storms (network, disk I/O)
  - Inefficient application design (spinning, polling)
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
        help='Show additional metrics (page faults)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show issues, suppress normal output'
    )

    parser.add_argument(
        '-i', '--interval',
        type=float,
        default=1.0,
        metavar='SECONDS',
        help='Sampling interval in seconds (default: %(default)s)'
    )

    # Threshold arguments
    parser.add_argument(
        '--ctxt-warn',
        type=float,
        default=20000.0,
        metavar='N',
        help='Context switches/sec per CPU warning threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--ctxt-crit',
        type=float,
        default=50000.0,
        metavar='N',
        help='Context switches/sec per CPU critical threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--intr-warn',
        type=float,
        default=50000.0,
        metavar='N',
        help='Interrupts/sec per CPU warning threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--intr-crit',
        type=float,
        default=100000.0,
        metavar='N',
        help='Interrupts/sec per CPU critical threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--run-queue-warn',
        type=float,
        default=2.0,
        metavar='N',
        help='Run queue depth per CPU warning threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--run-queue-crit',
        type=float,
        default=5.0,
        metavar='N',
        help='Run queue depth per CPU critical threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--blocked-warn',
        type=int,
        default=5,
        metavar='N',
        help='Blocked process count warning threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--blocked-crit',
        type=int,
        default=20,
        metavar='N',
        help='Blocked process count critical threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--fork-warn',
        type=float,
        default=500.0,
        metavar='N',
        help='Process creation rate/sec warning threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--fork-crit',
        type=float,
        default=2000.0,
        metavar='N',
        help='Process creation rate/sec critical threshold (default: %(default)s)'
    )

    args = parser.parse_args()

    # Validate interval
    if args.interval <= 0:
        print("Error: Interval must be positive", file=sys.stderr)
        sys.exit(2)
    if args.interval > 60:
        print("Error: Interval must be 60 seconds or less", file=sys.stderr)
        sys.exit(2)

    # Build thresholds dict
    thresholds = {
        'ctxt_per_cpu_warning': args.ctxt_warn,
        'ctxt_per_cpu_critical': args.ctxt_crit,
        'intr_per_cpu_warning': args.intr_warn,
        'intr_per_cpu_critical': args.intr_crit,
        'run_queue_warning': args.run_queue_warn,
        'run_queue_critical': args.run_queue_crit,
        'blocked_warning': args.blocked_warn,
        'blocked_critical': args.blocked_crit,
        'fork_rate_warning': args.fork_warn,
        'fork_rate_critical': args.fork_crit,
    }

    # Sample and analyze
    rates = sample_rates(args.interval)
    issues = analyze_issues(rates, thresholds)

    # Output results
    if args.format == 'json':
        output_json(rates, issues)
    elif args.format == 'table':
        output_table(rates, issues, warn_only=args.warn_only)
    else:  # plain
        output_plain(rates, issues, verbose=args.verbose, warn_only=args.warn_only)

    # Exit based on findings
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
