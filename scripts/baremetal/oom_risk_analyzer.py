#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [health, memory, oom, risk, monitoring]
#   related: [oom_kill_history, memory_usage]
#   brief: Analyze processes at risk of being killed by the OOM killer

"""
Analyze processes at risk of being killed by the Linux OOM killer.

This script examines the OOM score and memory usage of processes to identify
which processes are most likely to be killed when the system runs out of memory.

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
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_meminfo(content: str) -> int:
    """Parse MemTotal from /proc/meminfo.

    Returns:
        Total memory in KB
    """
    for line in content.strip().split('\n'):
        if line.startswith('MemTotal:'):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1])
    return 0


def parse_process_status(content: str) -> dict[str, Any]:
    """Parse /proc/<pid>/status into a dictionary."""
    status: dict[str, str] = {}
    for line in content.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            status[key.strip()] = value.strip()
    return status


def get_process_oom_info(
    pid: int,
    context: Context,
    proc_root: str = '/proc'
) -> dict[str, Any] | None:
    """Get OOM-related information for a process.

    Args:
        pid: Process ID
        context: Execution context
        proc_root: Root path for proc filesystem (for testing)

    Returns:
        Process OOM information or None if process not accessible
    """
    try:
        proc_path = f'{proc_root}/{pid}'

        # Read OOM score (0-1000+, higher = more likely to be killed)
        oom_score = int(context.read_file(f'{proc_path}/oom_score').strip())

        # Read OOM score adjustment (-1000 to +1000)
        oom_score_adj = int(context.read_file(f'{proc_path}/oom_score_adj').strip())

        # Read process status for memory info and name
        status_content = context.read_file(f'{proc_path}/status')
        status = parse_process_status(status_content)

        # Extract relevant fields
        name = status.get('Name', 'unknown')
        vm_rss_str = status.get('VmRSS', '0 kB')
        vm_size_str = status.get('VmSize', '0 kB')
        uid_str = status.get('Uid', '0')

        vm_rss = int(vm_rss_str.split()[0]) if vm_rss_str else 0
        vm_size = int(vm_size_str.split()[0]) if vm_size_str else 0
        uid = int(uid_str.split()[0]) if uid_str else 0

        # Read command line
        try:
            cmdline = context.read_file(f'{proc_path}/cmdline')
            cmdline = cmdline.replace('\x00', ' ').strip()
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


def analyze_oom_risk(
    processes: list[dict[str, Any]],
    mem_total_kb: int,
    warn_threshold: int,
    crit_threshold: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Analyze OOM risk for processes.

    Args:
        processes: List of process info dictionaries
        mem_total_kb: Total system memory in KB
        warn_threshold: OOM score warning threshold
        crit_threshold: OOM score critical threshold

    Returns:
        Tuple of (sorted processes, issues list)
    """
    issues: list[dict[str, Any]] = []

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


def format_bytes(kb: int) -> str:
    """Format KB value to human readable format."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb} KB"


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
        description='Analyze processes at risk of being killed by the OOM killer',
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
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
    parser.add_argument(
        '--pids',
        nargs='+',
        type=int,
        help='Specific PIDs to analyze (for testing)'
    )
    parser.add_argument(
        '--proc-root',
        default='/proc',
        help='Root path for proc filesystem (for testing)'
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if opts.top_n < 1:
        output.error("--top must be at least 1")
        return 2

    if opts.warn < 0:
        output.error("--warn must be non-negative")
        return 2

    if opts.crit < 0:
        output.error("--crit must be non-negative")
        return 2

    if opts.warn >= opts.crit:
        output.error("--warn must be less than --crit")
        return 2

    # Read system memory
    try:
        meminfo_content = context.read_file(f'{opts.proc_root}/meminfo')
        mem_total_kb = parse_meminfo(meminfo_content)
    except FileNotFoundError:
        output.error(f"{opts.proc_root}/meminfo not found (non-Linux system?)")
        return 2
    except Exception as e:
        output.error(f"Error reading meminfo: {e}")
        return 2

    if mem_total_kb == 0:
        output.error("Invalid MemTotal value")
        return 2

    # Get process OOM information
    processes: list[dict[str, Any]] = []

    if opts.pids:
        # Use specific PIDs (for testing)
        for pid in opts.pids:
            info = get_process_oom_info(pid, context, opts.proc_root)
            if info and info['oom_score'] > 0:
                processes.append(info)
    else:
        # Scan all processes from /proc
        try:
            result = context.run(['ls', opts.proc_root], check=False)
            for entry in result.stdout.split():
                if entry.isdigit():
                    pid = int(entry)
                    info = get_process_oom_info(pid, context, opts.proc_root)
                    if info and info['oom_score'] > 0:
                        processes.append(info)
        except Exception as e:
            output.error(f"Error scanning processes: {e}")
            return 2

    if not processes:
        if not opts.warn_only:
            print("No processes with OOM scores found")
        output.set_summary("No processes with OOM scores found")
        return 0

    # Analyze OOM risk
    sorted_procs, issues = analyze_oom_risk(
        processes, mem_total_kb, opts.warn, opts.crit
    )

    # Build result
    result = {
        'system': {
            'mem_total_kb': mem_total_kb,
            'processes_analyzed': len(processes)
        },
        'thresholds': {
            'warn': opts.warn,
            'crit': opts.crit
        },
        'top_processes': sorted_procs[:opts.top_n],
        'issues': issues
    }

    output.emit(result)

    # Output results
    if opts.format == 'table':
        lines = []
        if not opts.warn_only:
            lines.append("=" * 100)
            lines.append(f"OOM RISK ANALYSIS - System Memory: {format_bytes(mem_total_kb)}")
            lines.append("=" * 100)
            lines.append("")
            lines.append(f"{'Risk':<10} {'Name':<20} {'PID':>8} {'Score':>7} {'Adj':>7} "
                        f"{'RSS':>12} {'RSS%':>7}")
            lines.append("-" * 100)

            for proc in sorted_procs[:opts.top_n]:
                risk = proc['risk_level']
                name = proc['name'][:20]
                pid = proc['pid']
                score = proc['oom_score']
                adj = proc['oom_score_adj']
                adj_str = f"+{adj}" if adj >= 0 else str(adj)
                rss = format_bytes(proc['rss_kb'])
                rss_pct = proc['rss_percent']

                lines.append(f"{risk:<10} {name:<20} {pid:>8} {score:>7} {adj_str:>7} "
                            f"{rss:>12} {rss_pct:>6.1f}%")
            lines.append("")

        if issues:
            lines.append("ISSUES DETECTED")
            lines.append("=" * 100)
            for issue in issues:
                lines.append(f"[{issue['severity']}] {issue['message']}")
            lines.append("")

        print('\n'.join(lines))
    else:
        output.render(opts.format, "OOM Risk Analyzer", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")
    output.set_summary(f"Analyzed {len(processes)} processes, status={status}")

    # Determine exit code
    if has_critical or has_warning:
        return 1
    else:
        return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
