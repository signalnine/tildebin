#!/usr/bin/env python3
"""
Analyze processes at risk of being killed by the Linux OOM killer.

This script examines the OOM score and memory usage of processes to identify
which processes are most likely to be killed when the system runs out of memory.
Useful for:

- Proactively identifying OOM kill candidates before a crisis
- Understanding why specific processes might be selected for termination
- Tuning oom_score_adj values to protect critical services
- Capacity planning and memory allocation decisions

The OOM killer uses oom_score (0-1000+) to decide which process to kill.
Higher scores = more likely to be killed. Score is based on:
- Memory usage (RSS) relative to total RAM
- oom_score_adj tuning (-1000 to +1000)
- Process age, root privileges, and other factors

Exit codes:
    0 - Analysis complete, no high-risk processes found
    1 - High-risk processes detected (score above threshold)
    2 - Usage error or /proc filesystem not available
"""

import argparse
import sys
import os
import json


def read_proc_meminfo():
    """Read total memory from /proc/meminfo.

    Returns:
        int: Total memory in KB
    """
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    return int(line.split()[1])
        return 0
    except FileNotFoundError:
        print("Error: /proc/meminfo not found (non-Linux system?)", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading /proc/meminfo: {e}", file=sys.stderr)
        sys.exit(2)


def get_process_oom_info(pid):
    """Get OOM-related information for a process.

    Args:
        pid: Process ID

    Returns:
        dict or None: Process OOM information or None if process not accessible
    """
    try:
        proc_path = f'/proc/{pid}'

        # Read OOM score (0-1000+, higher = more likely to be killed)
        with open(f'{proc_path}/oom_score', 'r') as f:
            oom_score = int(f.read().strip())

        # Read OOM score adjustment (-1000 to +1000)
        with open(f'{proc_path}/oom_score_adj', 'r') as f:
            oom_score_adj = int(f.read().strip())

        # Read process status for memory info and name
        status = {}
        with open(f'{proc_path}/status', 'r') as f:
            for line in f:
                if ':' in line:
                    key, value = line.split(':', 1)
                    status[key.strip()] = value.strip()

        # Extract relevant fields
        name = status.get('Name', 'unknown')
        vm_rss = int(status.get('VmRSS', '0 kB').split()[0])
        vm_size = int(status.get('VmSize', '0 kB').split()[0])
        uid = int(status.get('Uid', '0').split()[0])

        # Read command line
        try:
            with open(f'{proc_path}/cmdline', 'r') as f:
                cmdline = f.read().replace('\x00', ' ').strip()
                if not cmdline:
                    cmdline = f'[{name}]'
        except Exception:
            cmdline = f'[{name}]'

        return {
            'pid': pid,
            'name': name,
            'cmdline': cmdline[:200],  # Truncate long command lines
            'oom_score': oom_score,
            'oom_score_adj': oom_score_adj,
            'rss_kb': vm_rss,
            'vsz_kb': vm_size,
            'uid': uid,
            'is_root': uid == 0
        }

    except (FileNotFoundError, PermissionError):
        # Process may have exited or we don't have permission
        return None
    except Exception:
        return None


def get_all_processes_oom_info():
    """Get OOM info for all processes.

    Returns:
        list: List of process OOM information dictionaries
    """
    processes = []

    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pid = int(entry)
                info = get_process_oom_info(pid)
                if info and info['oom_score'] > 0:
                    processes.append(info)
    except FileNotFoundError:
        print("Error: /proc not found (non-Linux system?)", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Permission denied reading /proc", file=sys.stderr)
        sys.exit(2)

    return processes


def analyze_oom_risk(processes, mem_total_kb, warn_threshold, crit_threshold):
    """Analyze OOM risk for processes.

    Args:
        processes: List of process info dictionaries
        mem_total_kb: Total system memory in KB
        warn_threshold: OOM score warning threshold
        crit_threshold: OOM score critical threshold

    Returns:
        tuple: (sorted processes, issues list)
    """
    issues = []

    # Sort by OOM score descending
    sorted_procs = sorted(processes, key=lambda p: p['oom_score'], reverse=True)

    # Add risk assessment to each process
    for proc in sorted_procs:
        score = proc['oom_score']
        rss_kb = proc['rss_kb']
        rss_pct = (rss_kb / mem_total_kb * 100) if mem_total_kb > 0 else 0
        proc['rss_percent'] = rss_pct

        if score >= crit_threshold:
            proc['risk_level'] = 'CRITICAL'
            issues.append({
                'severity': 'CRITICAL',
                'pid': proc['pid'],
                'name': proc['name'],
                'oom_score': score,
                'message': f"Process '{proc['name']}' (PID {proc['pid']}) has critical OOM score {score}"
            })
        elif score >= warn_threshold:
            proc['risk_level'] = 'WARNING'
            issues.append({
                'severity': 'WARNING',
                'pid': proc['pid'],
                'name': proc['name'],
                'oom_score': score,
                'message': f"Process '{proc['name']}' (PID {proc['pid']}) has elevated OOM score {score}"
            })
        else:
            proc['risk_level'] = 'OK'

    return sorted_procs, issues


def format_bytes(kb):
    """Format KB value to human readable format."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb} KB"


def output_plain(processes, issues, mem_total_kb, args):
    """Output results in plain text format."""
    top_n = args.top_n

    if not args.warn_only:
        print(f"System memory: {format_bytes(mem_total_kb)}")
        print(f"Processes analyzed: {len(processes)}")
        print()

        print(f"Top {top_n} processes by OOM score:")
        print("-" * 80)

        for proc in processes[:top_n]:
            score = proc['oom_score']
            adj = proc['oom_score_adj']
            rss = format_bytes(proc['rss_kb'])
            rss_pct = proc['rss_percent']
            risk = proc['risk_level']
            name = proc['name']
            pid = proc['pid']

            adj_str = f"+{adj}" if adj >= 0 else str(adj)
            print(f"[{risk:8}] {name:<20} PID:{pid:<7} Score:{score:<5} "
                  f"Adj:{adj_str:<6} RSS:{rss} ({rss_pct:.1f}%)")

        print()

    # Print issues
    if issues:
        for issue in issues:
            severity = issue['severity']
            message = issue['message']
            print(f"[{severity}] {message}")
    elif not args.warn_only:
        print("No high-risk processes detected.")


def output_json(processes, issues, mem_total_kb, args):
    """Output results in JSON format."""
    top_n = args.top_n

    result = {
        'system': {
            'mem_total_kb': mem_total_kb,
            'processes_analyzed': len(processes)
        },
        'thresholds': {
            'warn': args.warn,
            'crit': args.crit
        },
        'top_processes': processes[:top_n],
        'issues': issues
    }

    print(json.dumps(result, indent=2))


def output_table(processes, issues, mem_total_kb, args):
    """Output results in table format."""
    top_n = args.top_n

    if not args.warn_only:
        print("=" * 100)
        print(f"OOM RISK ANALYSIS - System Memory: {format_bytes(mem_total_kb)}")
        print("=" * 100)
        print()

        print(f"{'Risk':<10} {'Name':<20} {'PID':>8} {'Score':>7} {'Adj':>7} "
              f"{'RSS':>12} {'RSS%':>7}")
        print("-" * 100)

        for proc in processes[:top_n]:
            risk = proc['risk_level']
            name = proc['name'][:20]
            pid = proc['pid']
            score = proc['oom_score']
            adj = proc['oom_score_adj']
            adj_str = f"+{adj}" if adj >= 0 else str(adj)
            rss = format_bytes(proc['rss_kb'])
            rss_pct = proc['rss_percent']

            print(f"{risk:<10} {name:<20} {pid:>8} {score:>7} {adj_str:>7} "
                  f"{rss:>12} {rss_pct:>6.1f}%")

        print()

    if issues:
        print("ISSUES DETECTED")
        print("=" * 100)
        for issue in issues:
            print(f"[{issue['severity']}] {issue['message']}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze processes at risk of being killed by the OOM killer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Show top 20 processes by OOM score
  %(prog)s --top 50             # Show top 50 processes
  %(prog)s --warn 500 --crit 800  # Custom OOM score thresholds
  %(prog)s --format json        # JSON output for monitoring tools
  %(prog)s --warn-only          # Only show warnings/errors

OOM Score:
  The OOM score ranges from 0 to 1000+ (can exceed 1000 with adjustments).
  Higher scores mean the process is more likely to be killed by OOM killer.

  The score is primarily based on:
  - Memory usage (RSS) as a percentage of total RAM
  - The oom_score_adj value (-1000 protects, +1000 targets)

  To protect a critical process:
    echo -1000 > /proc/<pid>/oom_score_adj

  To make a process an OOM target:
    echo 1000 > /proc/<pid>/oom_score_adj

Exit codes:
  0 - No high-risk processes found
  1 - High-risk processes detected (above thresholds)
  2 - Usage error or /proc filesystem unavailable
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
        help='Show additional details'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--top', '-n',
        type=int,
        default=20,
        dest='top_n',
        metavar='N',
        help='Number of top processes to show (default: 20)'
    )

    parser.add_argument(
        '--warn',
        type=int,
        default=500,
        metavar='SCORE',
        help='Warning threshold for OOM score (default: 500)'
    )

    parser.add_argument(
        '--crit',
        type=int,
        default=800,
        metavar='SCORE',
        help='Critical threshold for OOM score (default: 800)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.top_n < 1:
        print("Error: --top must be at least 1", file=sys.stderr)
        sys.exit(2)

    if args.warn < 0:
        print("Error: --warn must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.crit < 0:
        print("Error: --crit must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.warn >= args.crit:
        print("Error: --warn must be less than --crit", file=sys.stderr)
        sys.exit(2)

    # Read system memory
    mem_total_kb = read_proc_meminfo()

    # Get process OOM information
    processes = get_all_processes_oom_info()

    if not processes:
        print("Warning: No processes with OOM scores found", file=sys.stderr)
        sys.exit(0)

    # Analyze OOM risk
    sorted_procs, issues = analyze_oom_risk(
        processes, mem_total_kb, args.warn, args.crit
    )

    # Output results
    if args.format == 'json':
        output_json(sorted_procs, issues, mem_total_kb, args)
    elif args.format == 'table':
        output_table(sorted_procs, issues, mem_total_kb, args)
    else:  # plain
        output_plain(sorted_procs, issues, mem_total_kb, args)

    # Determine exit code
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
