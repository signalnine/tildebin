#!/usr/bin/env python3
"""
Detect potential memory leaks by monitoring process memory growth over time.

This script samples process memory usage at intervals and identifies processes
whose memory consumption is growing consistently, which may indicate memory leaks.

Unlike simple memory snapshots, this tool tracks growth patterns to distinguish
between normal memory usage fluctuation and genuine leaks. It focuses on:
- RSS (Resident Set Size) growth over sampling period
- Private memory growth (heap + anonymous mappings)
- Growth rate calculation to identify leak severity

Useful for:
- Proactive identification of memory leaks before OOM events
- Validating fixes after deploying memory leak patches
- Capacity planning based on memory growth trends
- Identifying services that need restart scheduling

Exit codes:
    0 - No significant memory growth detected
    1 - Memory growth warnings detected
    2 - Usage error or missing data sources
"""

import argparse
import sys
import os
import json
import time
import re
from collections import defaultdict


def get_process_list():
    """
    Get list of all running process PIDs.
    Returns list of (pid, comm) tuples.
    """
    processes = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                pid = int(entry)
                comm = get_process_comm(pid)
                if comm:
                    processes.append((pid, comm))
    except (PermissionError, FileNotFoundError):
        pass
    return processes


def get_process_comm(pid):
    """Get process command name."""
    try:
        with open(f'/proc/{pid}/comm', 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None


def get_process_cmdline(pid):
    """Get full process command line."""
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            return cmdline if cmdline else None
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None


def get_process_memory(pid):
    """
    Get detailed memory information for a process from /proc/[pid]/status.

    Returns dict with memory metrics in KB, or None if process not accessible.
    """
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            content = f.read()

        memory = {}
        patterns = {
            'VmSize': r'VmSize:\s+(\d+)\s+kB',
            'VmRSS': r'VmRSS:\s+(\d+)\s+kB',
            'VmData': r'VmData:\s+(\d+)\s+kB',
            'VmStk': r'VmStk:\s+(\d+)\s+kB',
            'VmLib': r'VmLib:\s+(\d+)\s+kB',
            'VmSwap': r'VmSwap:\s+(\d+)\s+kB',
            'RssAnon': r'RssAnon:\s+(\d+)\s+kB',
            'RssFile': r'RssFile:\s+(\d+)\s+kB',
            'RssShmem': r'RssShmem:\s+(\d+)\s+kB',
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                memory[key] = int(match.group(1))
            else:
                memory[key] = 0

        return memory

    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None


def get_process_smaps_rollup(pid):
    """
    Get memory info from /proc/[pid]/smaps_rollup for more accurate private memory.
    Falls back to status if smaps_rollup is not available.
    """
    try:
        with open(f'/proc/{pid}/smaps_rollup', 'r') as f:
            content = f.read()

        memory = {}
        patterns = {
            'Rss': r'Rss:\s+(\d+)\s+kB',
            'Pss': r'Pss:\s+(\d+)\s+kB',
            'Private_Clean': r'Private_Clean:\s+(\d+)\s+kB',
            'Private_Dirty': r'Private_Dirty:\s+(\d+)\s+kB',
            'Shared_Clean': r'Shared_Clean:\s+(\d+)\s+kB',
            'Shared_Dirty': r'Shared_Dirty:\s+(\d+)\s+kB',
            'Swap': r'Swap:\s+(\d+)\s+kB',
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                memory[key] = int(match.group(1))
            else:
                memory[key] = 0

        # Calculate total private memory
        memory['Private_Total'] = memory.get('Private_Clean', 0) + memory.get('Private_Dirty', 0)

        return memory

    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None


def sample_process_memory(pids_to_monitor=None, min_rss_kb=10240):
    """
    Sample memory for all processes or specified PIDs.

    Args:
        pids_to_monitor: List of PIDs to monitor, or None for all
        min_rss_kb: Minimum RSS in KB to include process (default 10MB)

    Returns dict of {pid: {memory_info}}
    """
    samples = {}

    if pids_to_monitor:
        processes = [(pid, get_process_comm(pid)) for pid in pids_to_monitor]
    else:
        processes = get_process_list()

    for pid, comm in processes:
        if not comm:
            continue

        memory = get_process_memory(pid)
        if not memory:
            continue

        # Skip processes below minimum RSS threshold
        if memory.get('VmRSS', 0) < min_rss_kb:
            continue

        # Try to get more detailed memory from smaps_rollup
        smaps = get_process_smaps_rollup(pid)

        samples[pid] = {
            'pid': pid,
            'comm': comm,
            'cmdline': get_process_cmdline(pid),
            'rss_kb': memory.get('VmRSS', 0),
            'vm_data_kb': memory.get('VmData', 0),
            'rss_anon_kb': memory.get('RssAnon', 0),
            'swap_kb': memory.get('VmSwap', 0),
            'timestamp': time.time(),
        }

        if smaps:
            samples[pid]['private_kb'] = smaps.get('Private_Total', 0)
            samples[pid]['pss_kb'] = smaps.get('Pss', 0)
        else:
            # Estimate private memory from RssAnon
            samples[pid]['private_kb'] = memory.get('RssAnon', 0)
            samples[pid]['pss_kb'] = memory.get('VmRSS', 0)

    return samples


def analyze_memory_growth(samples_list, min_growth_kb, min_growth_rate):
    """
    Analyze memory samples to identify growing processes.

    Args:
        samples_list: List of sample dicts from sample_process_memory()
        min_growth_kb: Minimum absolute growth in KB to report
        min_growth_rate: Minimum growth rate in KB/min to report

    Returns list of processes with memory growth issues.
    """
    if len(samples_list) < 2:
        return []

    first_sample = samples_list[0]
    last_sample = samples_list[-1]

    time_delta_sec = last_sample.get('_timestamp', 0) - first_sample.get('_timestamp', 0)
    if time_delta_sec <= 0:
        return []

    time_delta_min = time_delta_sec / 60.0

    issues = []

    # Find PIDs that exist in both first and last sample
    common_pids = set(first_sample.keys()) & set(last_sample.keys())
    common_pids.discard('_timestamp')

    for pid in common_pids:
        first = first_sample[pid]
        last = last_sample[pid]

        # Ensure it's the same process (comm should match)
        if first['comm'] != last['comm']:
            continue

        # Calculate growth metrics
        rss_growth = last['rss_kb'] - first['rss_kb']
        private_growth = last['private_kb'] - first['private_kb']
        anon_growth = last['rss_anon_kb'] - first['rss_anon_kb']

        # Use the most relevant growth metric (prefer private memory)
        primary_growth = private_growth if private_growth > 0 else rss_growth

        # Calculate growth rate in KB/min
        growth_rate = primary_growth / time_delta_min if time_delta_min > 0 else 0

        # Check for consistent growth across all samples
        consistent_growth = True
        if len(samples_list) > 2:
            prev_rss = first['rss_kb']
            for sample in samples_list[1:]:
                if pid in sample and sample[pid]['comm'] == first['comm']:
                    if sample[pid]['rss_kb'] < prev_rss:
                        consistent_growth = False
                        break
                    prev_rss = sample[pid]['rss_kb']

        # Report if growth exceeds thresholds
        if primary_growth >= min_growth_kb and growth_rate >= min_growth_rate:
            severity = 'WARNING'
            if growth_rate >= min_growth_rate * 5:
                severity = 'CRITICAL'
            elif growth_rate >= min_growth_rate * 2:
                severity = 'HIGH'

            issues.append({
                'pid': pid,
                'comm': first['comm'],
                'cmdline': first.get('cmdline', ''),
                'severity': severity,
                'start_rss_kb': first['rss_kb'],
                'end_rss_kb': last['rss_kb'],
                'rss_growth_kb': rss_growth,
                'private_growth_kb': private_growth,
                'anon_growth_kb': anon_growth,
                'growth_rate_kb_min': round(growth_rate, 2),
                'consistent_growth': consistent_growth,
                'duration_min': round(time_delta_min, 2),
            })

    # Sort by growth rate (highest first)
    issues.sort(key=lambda x: x['growth_rate_kb_min'], reverse=True)

    return issues


def format_size(kb):
    """Format KB value as human-readable string."""
    if kb >= 1048576:  # 1GB
        return f"{kb / 1048576:.1f}GB"
    elif kb >= 1024:  # 1MB
        return f"{kb / 1024:.1f}MB"
    else:
        return f"{kb}KB"


def output_plain(issues, all_samples, warn_only=False, verbose=False):
    """Output results in plain text format."""
    lines = []

    if not warn_only and verbose:
        # Show current top memory consumers
        last_sample = all_samples[-1] if all_samples else {}
        if last_sample:
            lines.append("Current Top Memory Consumers:")
            procs = [(pid, data) for pid, data in last_sample.items() if pid != '_timestamp']
            procs.sort(key=lambda x: x[1]['rss_kb'], reverse=True)
            for pid, data in procs[:10]:
                lines.append(
                    f"  {data['comm']:<20} PID={pid:<8} "
                    f"RSS={format_size(data['rss_kb']):<10} "
                    f"Private={format_size(data['private_kb']):<10}"
                )
            lines.append("")

    if issues:
        critical = [i for i in issues if i['severity'] == 'CRITICAL']
        high = [i for i in issues if i['severity'] == 'HIGH']
        warnings = [i for i in issues if i['severity'] == 'WARNING']

        if critical:
            lines.append(f"CRITICAL Memory Growth ({len(critical)}):")
            for issue in critical:
                lines.append(
                    f"  {issue['comm']} (PID {issue['pid']}): "
                    f"+{format_size(issue['rss_growth_kb'])} "
                    f"({issue['growth_rate_kb_min']:.1f} KB/min)"
                )
                if verbose:
                    lines.append(f"    Start: {format_size(issue['start_rss_kb'])} -> End: {format_size(issue['end_rss_kb'])}")
                    lines.append(f"    Private growth: +{format_size(issue['private_growth_kb'])}")
                    if issue['cmdline']:
                        lines.append(f"    Cmd: {issue['cmdline'][:80]}")
            lines.append("")

        if high:
            lines.append(f"HIGH Memory Growth ({len(high)}):")
            for issue in high:
                lines.append(
                    f"  {issue['comm']} (PID {issue['pid']}): "
                    f"+{format_size(issue['rss_growth_kb'])} "
                    f"({issue['growth_rate_kb_min']:.1f} KB/min)"
                )
                if verbose and issue['cmdline']:
                    lines.append(f"    Cmd: {issue['cmdline'][:80]}")
            lines.append("")

        if warnings:
            lines.append(f"Memory Growth Warnings ({len(warnings)}):")
            for issue in warnings:
                lines.append(
                    f"  {issue['comm']} (PID {issue['pid']}): "
                    f"+{format_size(issue['rss_growth_kb'])} "
                    f"({issue['growth_rate_kb_min']:.1f} KB/min)"
                )
            lines.append("")

        # Summary
        total_growth = sum(i['rss_growth_kb'] for i in issues)
        lines.append(f"Summary: {len(issues)} processes with memory growth, total +{format_size(total_growth)}")

    elif not warn_only:
        lines.append("No significant memory growth detected.")

    return '\n'.join(lines)


def output_json(issues, all_samples):
    """Output results in JSON format."""
    # Get latest sample for current state
    current_state = {}
    if all_samples:
        last = all_samples[-1]
        for pid, data in last.items():
            if pid != '_timestamp':
                current_state[str(pid)] = data

    result = {
        'issues': issues,
        'current_state': current_state,
        'summary': {
            'total_issues': len(issues),
            'critical_count': len([i for i in issues if i['severity'] == 'CRITICAL']),
            'high_count': len([i for i in issues if i['severity'] == 'HIGH']),
            'warning_count': len([i for i in issues if i['severity'] == 'WARNING']),
            'total_growth_kb': sum(i['rss_growth_kb'] for i in issues),
            'sample_count': len(all_samples),
        }
    }
    return json.dumps(result, indent=2)


def output_table(issues, warn_only=False):
    """Output results in table format."""
    lines = []

    if issues or not warn_only:
        lines.append(
            f"{'Process':<20} {'PID':<8} {'Start':<10} {'End':<10} "
            f"{'Growth':<10} {'Rate':<12} {'Severity':<10}"
        )
        lines.append("-" * 90)

    for issue in issues:
        lines.append(
            f"{issue['comm']:<20} "
            f"{issue['pid']:<8} "
            f"{format_size(issue['start_rss_kb']):<10} "
            f"{format_size(issue['end_rss_kb']):<10} "
            f"{format_size(issue['rss_growth_kb']):<10} "
            f"{issue['growth_rate_kb_min']:<12.1f} "
            f"{issue['severity']:<10}"
        )

    if not issues and not warn_only:
        lines.append("No significant memory growth detected.")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Detect potential memory leaks by monitoring process memory growth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Monitor for 60s with 10s intervals
  %(prog)s --duration 300               # Monitor for 5 minutes
  %(prog)s --interval 30 --duration 600 # 30s intervals over 10 minutes
  %(prog)s --pid 1234,5678              # Monitor specific processes
  %(prog)s --min-growth 50000           # Only report growth > 50MB
  %(prog)s --format json                # JSON output for automation

Growth rate thresholds:
  WARNING:  >= min-rate (default 100 KB/min)
  HIGH:     >= 2x min-rate
  CRITICAL: >= 5x min-rate

Exit codes:
  0 - No significant memory growth detected
  1 - Memory growth warnings detected
  2 - Usage error or missing data sources

Notes:
  - Longer durations provide more accurate leak detection
  - Focus on 'consistent_growth' processes for real leaks
  - Anonymous memory (RssAnon) growth is most indicative of leaks
  - Processes that GC or release caches may show temporary growth
        """
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including top memory consumers"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show processes with memory growth issues"
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Total monitoring duration in seconds (default: %(default)s)"
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Sampling interval in seconds (default: %(default)s)"
    )

    parser.add_argument(
        "--min-rss",
        type=int,
        default=10240,
        help="Minimum RSS in KB to monitor a process (default: %(default)s = 10MB)"
    )

    parser.add_argument(
        "--min-growth",
        type=int,
        default=5120,
        help="Minimum growth in KB to report (default: %(default)s = 5MB)"
    )

    parser.add_argument(
        "--min-rate",
        type=float,
        default=100.0,
        help="Minimum growth rate in KB/min to report (default: %(default)s)"
    )

    parser.add_argument(
        "--pid",
        help="Comma-separated list of PIDs to monitor (default: all)"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.duration <= 0:
        print("Error: Duration must be positive", file=sys.stderr)
        sys.exit(2)

    if args.duration > 3600:
        print("Error: Duration cannot exceed 3600 seconds (1 hour)", file=sys.stderr)
        sys.exit(2)

    if args.interval <= 0:
        print("Error: Interval must be positive", file=sys.stderr)
        sys.exit(2)

    if args.interval > args.duration:
        print("Error: Interval cannot exceed duration", file=sys.stderr)
        sys.exit(2)

    if args.min_rss < 0:
        print("Error: Minimum RSS must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.min_growth < 0:
        print("Error: Minimum growth must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.min_rate < 0:
        print("Error: Minimum rate must be non-negative", file=sys.stderr)
        sys.exit(2)

    # Parse PID list if provided
    pids_to_monitor = None
    if args.pid:
        try:
            pids_to_monitor = [int(p.strip()) for p in args.pid.split(',')]
        except ValueError:
            print("Error: Invalid PID format. Use comma-separated numbers", file=sys.stderr)
            sys.exit(2)

    # Check /proc availability
    if not os.path.exists('/proc'):
        print("Error: /proc filesystem not available", file=sys.stderr)
        sys.exit(2)

    # Collect samples
    all_samples = []
    num_samples = (args.duration // args.interval) + 1

    for i in range(num_samples):
        sample = sample_process_memory(pids_to_monitor, args.min_rss)
        sample['_timestamp'] = time.time()
        all_samples.append(sample)

        # Don't sleep after the last sample
        if i < num_samples - 1:
            time.sleep(args.interval)

    if not all_samples or len(all_samples) < 2:
        print("Error: Insufficient samples collected", file=sys.stderr)
        sys.exit(2)

    # Analyze for memory growth
    issues = analyze_memory_growth(all_samples, args.min_growth, args.min_rate)

    # Output results
    if args.format == "json":
        output = output_json(issues, all_samples)
    elif args.format == "table":
        output = output_table(issues, warn_only=args.warn_only)
    else:
        output = output_plain(issues, all_samples, warn_only=args.warn_only, verbose=args.verbose)

    print(output)

    # Exit based on findings
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_issues = len(issues) > 0

    if has_critical or has_issues:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
