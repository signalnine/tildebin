#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [health, memory, oom, forensics, analysis]
#   related: [oom_risk_analyzer, memory_usage]
#   brief: Analyze OOM kill history from kernel logs

"""
Analyze OOM (Out of Memory) kill history from system logs.

This script parses kernel logs (dmesg or provided content) to identify past OOM
kill events, providing insights into:

- Which processes have been OOM killed
- When OOM kills occurred (time distribution)
- Memory state at the time of kills
- Frequency analysis of killed processes
- Cgroup/container context of killed processes

Exit codes:
    0 - No OOM kills found
    1 - OOM kills detected in history
    2 - Usage error or log source not available
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_oom_events(log_content: str) -> list[dict[str, Any]]:
    """Parse OOM kill events from kernel logs.

    Returns:
        List of OOM event dictionaries
    """
    events = []

    # Pattern for OOM killer invocation
    # Example: "Out of memory: Killed process 12345 (python3) total-vm:1234kB..."
    oom_pattern = re.compile(
        r'(?:Out of memory|oom-kill|oom_kill).*?'
        r'(?:Killed process|Kill process)\s+(\d+)\s+'
        r'\(([^)]+)\)',
        re.IGNORECASE
    )

    # Pattern for memory info at time of OOM
    # Example: "Killed process 12345 (python3) total-vm:1234kB, anon-rss:567kB..."
    mem_pattern = re.compile(
        r'total-vm:(\d+)kB.*?'
        r'(?:anon-rss:(\d+)kB)?.*?'
        r'(?:file-rss:(\d+)kB)?',
        re.IGNORECASE
    )

    # Pattern for cgroup/container context
    cgroup_pattern = re.compile(
        r'(?:memory cgroup|Task in|cgroup)\s+(/[^\s]+)',
        re.IGNORECASE
    )

    # Timestamp patterns
    timestamp_patterns = [
        # dmesg -T format: [Mon Jan 15 10:30:00 2024]
        (re.compile(r'\[([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\d{4})\]'),
         '%a %b %d %H:%M:%S %Y'),
        # journalctl short-iso: 2024-01-15T10:30:00+0000
        (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})'),
         '%Y-%m-%dT%H:%M:%S%z'),
        # journalctl default: Jan 15 10:30:00
        (re.compile(r'([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)'),
         '%b %d %H:%M:%S'),
    ]

    # Process line by line, looking for OOM events
    lines = log_content.split('\n')

    for line in lines:
        # Check for OOM kill line
        oom_match = oom_pattern.search(line)
        if oom_match:
            pid = int(oom_match.group(1))
            process_name = oom_match.group(2)

            # Extract timestamp
            timestamp = None
            timestamp_str = None
            for pattern, fmt in timestamp_patterns:
                ts_match = pattern.search(line)
                if ts_match:
                    timestamp_str = ts_match.group(1)
                    try:
                        timestamp = datetime.strptime(timestamp_str, fmt)
                        # Add current year if missing
                        if timestamp.year == 1900:
                            timestamp = timestamp.replace(year=datetime.now().year)
                        break
                    except ValueError:
                        continue

            # Extract memory info
            total_vm = None
            anon_rss = None
            file_rss = None
            mem_match = mem_pattern.search(line)
            if mem_match:
                total_vm = int(mem_match.group(1)) if mem_match.group(1) else None
                anon_rss = int(mem_match.group(2)) if mem_match.group(2) else None
                file_rss = int(mem_match.group(3)) if mem_match.group(3) else None

            # Extract cgroup if present
            cgroup = None
            cgroup_match = cgroup_pattern.search(line)
            if cgroup_match:
                cgroup = cgroup_match.group(1)

            event = {
                'pid': pid,
                'process': process_name,
                'timestamp': timestamp.isoformat() if timestamp else None,
                'timestamp_raw': timestamp_str,
                'total_vm_kb': total_vm,
                'anon_rss_kb': anon_rss,
                'file_rss_kb': file_rss,
                'cgroup': cgroup,
                'raw_line': line.strip(),
            }

            events.append(event)

    return events


def analyze_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze OOM events for patterns and statistics.

    Returns:
        Analysis dictionary with summary statistics
    """
    if not events:
        return {
            'total_events': 0,
            'unique_processes': 0,
            'process_frequency': {},
            'hourly_distribution': {},
            'memory_stats': {},
        }

    # Process frequency
    process_counts: dict[str, int] = defaultdict(int)
    for event in events:
        process_counts[event['process']] += 1

    # Sort by frequency
    sorted_processes = sorted(
        process_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )

    # Hourly distribution
    hourly_counts: dict[int, int] = defaultdict(int)
    for event in events:
        if event['timestamp']:
            try:
                dt = datetime.fromisoformat(event['timestamp'])
                hourly_counts[dt.hour] += 1
            except (ValueError, TypeError):
                pass

    # Memory statistics
    total_vms = [e['total_vm_kb'] for e in events if e['total_vm_kb']]
    anon_rss_values = [e['anon_rss_kb'] for e in events if e['anon_rss_kb']]

    memory_stats: dict[str, int] = {}
    if total_vms:
        memory_stats['avg_total_vm_kb'] = sum(total_vms) // len(total_vms)
        memory_stats['max_total_vm_kb'] = max(total_vms)
        memory_stats['min_total_vm_kb'] = min(total_vms)
    if anon_rss_values:
        memory_stats['avg_anon_rss_kb'] = sum(anon_rss_values) // len(anon_rss_values)
        memory_stats['max_anon_rss_kb'] = max(anon_rss_values)

    # Cgroup analysis
    cgroup_counts: dict[str, int] = defaultdict(int)
    for event in events:
        if event['cgroup']:
            # Simplify cgroup path for container identification
            cgroup = event['cgroup']
            # Extract container/pod name if present
            if 'docker' in cgroup or 'containerd' in cgroup:
                cgroup_counts['containers'] += 1
            elif 'kubepods' in cgroup:
                cgroup_counts['kubernetes_pods'] += 1
            elif 'system.slice' in cgroup:
                cgroup_counts['system_services'] += 1
            else:
                cgroup_counts['other'] += 1

    # Time range
    timestamps = [e['timestamp'] for e in events if e['timestamp']]
    time_range: dict[str, str] = {}
    if timestamps:
        sorted_ts = sorted(timestamps)
        time_range['first_event'] = sorted_ts[0]
        time_range['last_event'] = sorted_ts[-1]

    return {
        'total_events': len(events),
        'unique_processes': len(process_counts),
        'process_frequency': dict(sorted_processes),
        'top_killed_processes': sorted_processes[:10],
        'hourly_distribution': dict(sorted(hourly_counts.items())),
        'memory_stats': memory_stats,
        'cgroup_distribution': dict(cgroup_counts),
        'time_range': time_range,
    }


def format_kb(kb: int | None) -> str:
    """Format KB value to human-readable size."""
    if kb is None:
        return 'n/a'
    if kb >= 1048576:  # 1 GB
        return f'{kb / 1048576:.1f} GB'
    elif kb >= 1024:  # 1 MB
        return f'{kb / 1024:.1f} MB'
    else:
        return f'{kb} KB'


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no OOM kills, 1 = OOM kills found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Analyze OOM kill history from kernel logs',
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--summary',
        action='store_true',
        help='Only show summary statistics, not individual events'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only produce output if OOM kills were found'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including cgroup paths'
    )
    parser.add_argument(
        '--log-file',
        help='Path to log file (for testing, reads from file instead of dmesg)'
    )

    opts = parser.parse_args(args)

    # Get log content
    try:
        if opts.log_file:
            log_content = context.read_file(opts.log_file)
        else:
            # Try to read from dmesg via command
            result = context.run(['dmesg', '-T'], check=False)
            if result.returncode != 0:
                result = context.run(['dmesg'], check=False)
            if result.returncode != 0:
                output.error("Unable to read dmesg. Try running with sudo.")
                return 2
            log_content = result.stdout
    except FileNotFoundError as e:
        output.error(f"Unable to read log source: {e}")
        return 2
    except Exception as e:
        output.error(f"Error reading logs: {e}")
        return 2

    # Parse OOM events
    events = parse_oom_events(log_content)

    # Analyze events
    analysis = analyze_events(events)

    # Handle warn-only mode
    if opts.warn_only and not events:
        output.set_summary("No OOM kills found")
        return 0

    # Output results
    if opts.format == 'json':
        result = {
            'analysis': analysis,
            'events': events[-100:] if events else [],  # Limit to last 100
        }
        print(json.dumps(result, indent=2, default=str))

    elif opts.format == 'table':
        lines = []
        lines.append(f"{'PROCESS':<30} {'KILLS':>6} {'AVG VM':>12} {'LAST KILLED':<25}")
        lines.append("=" * 80)

        if not events:
            lines.append("No OOM kill events found")
        else:
            # Group by process
            by_process: dict[str, list] = defaultdict(list)
            for event in events:
                by_process[event['process']].append(event)

            # Sort by kill count
            sorted_procs = sorted(by_process.items(), key=lambda x: len(x[1]), reverse=True)

            for process, proc_events in sorted_procs[:20]:
                count = len(proc_events)
                vms = [e['total_vm_kb'] for e in proc_events if e['total_vm_kb']]
                avg_vm = format_kb(sum(vms) // len(vms)) if vms else 'n/a'
                last_ts = proc_events[-1].get('timestamp_raw', 'n/a')
                lines.append(f"{process:<30} {count:>6} {avg_vm:>12} {last_ts:<25}")

            lines.append("")
            lines.append(f"Total events: {len(events)} | Unique processes: {len(by_process)}")

        print('\n'.join(lines))

    else:  # plain
        lines = []
        lines.append("OOM Kill History Analysis")
        lines.append("=" * 60)

        if analysis['total_events'] == 0:
            lines.append("")
            lines.append("No OOM kill events found in logs.")
            lines.append("This is good - no processes were killed due to memory pressure.")
        else:
            lines.append(f"\nTotal OOM kills found: {analysis['total_events']}")
            lines.append(f"Unique processes killed: {analysis['unique_processes']}")

            if analysis.get('time_range'):
                tr = analysis['time_range']
                lines.append(f"Time range: {tr.get('first_event', 'n/a')} to {tr.get('last_event', 'n/a')}")

            # Top killed processes
            lines.append("")
            lines.append("-" * 60)
            lines.append("MOST FREQUENTLY KILLED PROCESSES:")
            lines.append("-" * 60)
            for process, count in analysis.get('top_killed_processes', []):
                bar = '#' * min(count, 30)
                lines.append(f"  {process:<25} {count:>4} kills  {bar}")

            # Memory statistics
            if analysis.get('memory_stats'):
                stats = analysis['memory_stats']
                lines.append("")
                lines.append("-" * 60)
                lines.append("MEMORY STATISTICS (at time of kill):")
                lines.append("-" * 60)
                if 'avg_total_vm_kb' in stats:
                    lines.append(f"  Average total VM:  {format_kb(stats['avg_total_vm_kb'])}")
                    lines.append(f"  Maximum total VM:  {format_kb(stats['max_total_vm_kb'])}")
                if 'avg_anon_rss_kb' in stats:
                    lines.append(f"  Average anon RSS:  {format_kb(stats['avg_anon_rss_kb'])}")
                    lines.append(f"  Maximum anon RSS:  {format_kb(stats['max_anon_rss_kb'])}")

            # Cgroup distribution
            if analysis.get('cgroup_distribution'):
                lines.append("")
                lines.append("-" * 60)
                lines.append("CGROUP/CONTAINER DISTRIBUTION:")
                lines.append("-" * 60)
                for cgroup, count in analysis['cgroup_distribution'].items():
                    lines.append(f"  {cgroup:<25} {count:>4}")

            # Individual events (if not summary only)
            if not opts.summary and events:
                lines.append("")
                lines.append("-" * 60)
                lines.append("RECENT OOM KILL EVENTS:")
                lines.append("-" * 60)
                # Show last 20 events
                for event in events[-20:]:
                    ts = event.get('timestamp_raw', 'unknown time')
                    proc = event['process']
                    pid = event['pid']
                    vm = format_kb(event.get('total_vm_kb'))
                    rss = format_kb(event.get('anon_rss_kb'))
                    lines.append(f"  [{ts}] {proc} (PID {pid})")
                    lines.append(f"      VM: {vm}, RSS: {rss}")
                    if opts.verbose and event.get('cgroup'):
                        lines.append(f"      Cgroup: {event['cgroup']}")

        print('\n'.join(lines))

    # Set summary
    if events:
        output.set_summary(f"Found {len(events)} OOM kills, {analysis['unique_processes']} unique processes")
    else:
        output.set_summary("No OOM kills found")

    # Exit with appropriate code
    return 1 if events else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
