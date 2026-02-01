#!/usr/bin/env python3
"""
Analyze OOM (Out of Memory) kill history from system logs.

This script parses kernel logs (dmesg or journalctl) to identify past OOM
kill events, providing insights into:

- Which processes have been OOM killed
- When OOM kills occurred (time distribution)
- Memory state at the time of kills
- Frequency analysis of killed processes
- Cgroup/container context of killed processes

Useful for:
- Post-incident analysis after OOM events
- Identifying processes that repeatedly get OOM killed
- Understanding memory pressure patterns over time
- Capacity planning based on historical OOM events

Exit codes:
    0 - Analysis complete (may or may not have found OOM kills)
    1 - OOM kills detected in history
    2 - Usage error or log source not available

Examples:
    # Analyze OOM kills from dmesg
    baremetal_oom_kill_history.py

    # Use journalctl for longer history
    baremetal_oom_kill_history.py --source journal

    # Show only summary statistics
    baremetal_oom_kill_history.py --summary

    # JSON output for monitoring integration
    baremetal_oom_kill_history.py --format json

    # Filter by time range (journalctl only)
    baremetal_oom_kill_history.py --source journal --since "24 hours ago"
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple


def run_command(cmd: List[str], check: bool = False) -> Tuple[int, str, str]:
    """Execute a shell command and return result."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout or "", e.stderr or ""


def get_dmesg_logs() -> str:
    """Get kernel logs from dmesg."""
    returncode, stdout, stderr = run_command(['dmesg', '-T'])
    if returncode != 0:
        # Try without timestamp format
        returncode, stdout, stderr = run_command(['dmesg'])
        if returncode != 0:
            print("Error: Unable to read dmesg. Try running with sudo.", file=sys.stderr)
            sys.exit(2)
    return stdout


def get_journal_logs(since: Optional[str] = None) -> str:
    """Get kernel logs from journalctl."""
    cmd = ['journalctl', '-k', '--no-pager', '-o', 'short-iso']
    if since:
        cmd.extend(['--since', since])

    returncode, stdout, stderr = run_command(cmd)
    if returncode != 0:
        # Check if journalctl exists
        check_ret, _, _ = run_command(['which', 'journalctl'])
        if check_ret != 0:
            print("Error: journalctl not found. Use --source dmesg instead.", file=sys.stderr)
            sys.exit(2)
        print(f"Error reading journal: {stderr}", file=sys.stderr)
        sys.exit(2)
    return stdout


def parse_oom_events(log_content: str) -> List[Dict[str, Any]]:
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
    current_event = None

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


def analyze_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
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
    process_counts = defaultdict(int)
    for event in events:
        process_counts[event['process']] += 1

    # Sort by frequency
    sorted_processes = sorted(
        process_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )

    # Hourly distribution
    hourly_counts = defaultdict(int)
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

    memory_stats = {}
    if total_vms:
        memory_stats['avg_total_vm_kb'] = sum(total_vms) // len(total_vms)
        memory_stats['max_total_vm_kb'] = max(total_vms)
        memory_stats['min_total_vm_kb'] = min(total_vms)
    if anon_rss_values:
        memory_stats['avg_anon_rss_kb'] = sum(anon_rss_values) // len(anon_rss_values)
        memory_stats['max_anon_rss_kb'] = max(anon_rss_values)

    # Cgroup analysis
    cgroup_counts = defaultdict(int)
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
    time_range = {}
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


def format_kb(kb: Optional[int]) -> str:
    """Format KB value to human-readable size."""
    if kb is None:
        return 'n/a'
    if kb >= 1048576:  # 1 GB
        return f'{kb / 1048576:.1f} GB'
    elif kb >= 1024:  # 1 MB
        return f'{kb / 1024:.1f} MB'
    else:
        return f'{kb} KB'


def output_plain(events: List[Dict[str, Any]], analysis: Dict[str, Any],
                 summary_only: bool = False, verbose: bool = False) -> None:
    """Output results in plain text format."""
    print("OOM Kill History Analysis")
    print("=" * 60)

    if analysis['total_events'] == 0:
        print("\nNo OOM kill events found in logs.")
        print("This is good - no processes were killed due to memory pressure.")
        return

    print(f"\nTotal OOM kills found: {analysis['total_events']}")
    print(f"Unique processes killed: {analysis['unique_processes']}")

    if analysis.get('time_range'):
        tr = analysis['time_range']
        print(f"Time range: {tr.get('first_event', 'n/a')} to {tr.get('last_event', 'n/a')}")

    # Top killed processes
    print("\n" + "-" * 60)
    print("MOST FREQUENTLY KILLED PROCESSES:")
    print("-" * 60)
    for process, count in analysis.get('top_killed_processes', []):
        bar = '#' * min(count, 30)
        print(f"  {process:<25} {count:>4} kills  {bar}")

    # Memory statistics
    if analysis.get('memory_stats'):
        stats = analysis['memory_stats']
        print("\n" + "-" * 60)
        print("MEMORY STATISTICS (at time of kill):")
        print("-" * 60)
        if 'avg_total_vm_kb' in stats:
            print(f"  Average total VM:  {format_kb(stats['avg_total_vm_kb'])}")
            print(f"  Maximum total VM:  {format_kb(stats['max_total_vm_kb'])}")
        if 'avg_anon_rss_kb' in stats:
            print(f"  Average anon RSS:  {format_kb(stats['avg_anon_rss_kb'])}")
            print(f"  Maximum anon RSS:  {format_kb(stats['max_anon_rss_kb'])}")

    # Hourly distribution
    if analysis.get('hourly_distribution'):
        print("\n" + "-" * 60)
        print("HOURLY DISTRIBUTION:")
        print("-" * 60)
        hours = analysis['hourly_distribution']
        max_count = max(hours.values()) if hours else 1
        for hour in range(24):
            count = hours.get(hour, 0)
            bar_len = int(count / max_count * 20) if max_count > 0 else 0
            bar = '#' * bar_len
            print(f"  {hour:02d}:00  {count:>3}  {bar}")

    # Cgroup distribution
    if analysis.get('cgroup_distribution'):
        print("\n" + "-" * 60)
        print("CGROUP/CONTAINER DISTRIBUTION:")
        print("-" * 60)
        for cgroup, count in analysis['cgroup_distribution'].items():
            print(f"  {cgroup:<25} {count:>4}")

    # Individual events (if not summary only)
    if not summary_only and events:
        print("\n" + "-" * 60)
        print("RECENT OOM KILL EVENTS:")
        print("-" * 60)
        # Show last 20 events
        for event in events[-20:]:
            ts = event.get('timestamp_raw', 'unknown time')
            proc = event['process']
            pid = event['pid']
            vm = format_kb(event.get('total_vm_kb'))
            rss = format_kb(event.get('anon_rss_kb'))
            print(f"  [{ts}] {proc} (PID {pid})")
            print(f"      VM: {vm}, RSS: {rss}")
            if verbose and event.get('cgroup'):
                print(f"      Cgroup: {event['cgroup']}")

    print()


def output_json(events: List[Dict[str, Any]], analysis: Dict[str, Any]) -> None:
    """Output results in JSON format."""
    output = {
        'analysis': analysis,
        'events': events[-100],  # Limit to last 100 events
    }
    print(json.dumps(output, indent=2, default=str))


def output_table(events: List[Dict[str, Any]], analysis: Dict[str, Any],
                 summary_only: bool = False) -> None:
    """Output results in table format."""
    print(f"{'PROCESS':<30} {'KILLS':>6} {'AVG VM':>12} {'LAST KILLED':<25}")
    print("=" * 80)

    if not events:
        print("No OOM kill events found")
        return

    # Group by process
    by_process = defaultdict(list)
    for event in events:
        by_process[event['process']].append(event)

    # Sort by kill count
    sorted_procs = sorted(by_process.items(), key=lambda x: len(x[1]), reverse=True)

    for process, proc_events in sorted_procs[:20]:
        count = len(proc_events)
        vms = [e['total_vm_kb'] for e in proc_events if e['total_vm_kb']]
        avg_vm = format_kb(sum(vms) // len(vms)) if vms else 'n/a'
        last_ts = proc_events[-1].get('timestamp_raw', 'n/a')
        print(f"{process:<30} {count:>6} {avg_vm:>12} {last_ts:<25}")

    print()
    print(f"Total events: {len(events)} | Unique processes: {len(by_process)}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze OOM kill history from kernel logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                            # Analyze from dmesg
  %(prog)s --source journal           # Use journalctl for longer history
  %(prog)s --source journal --since "7 days ago"
  %(prog)s --summary                  # Summary statistics only
  %(prog)s --format json              # JSON output for monitoring
  %(prog)s --warn-only                # Only output if OOM kills found

Exit codes:
  0 - Analysis complete, no OOM kills found
  1 - OOM kills detected in history
  2 - Usage error or log source unavailable
        """
    )

    parser.add_argument(
        '--source',
        choices=['dmesg', 'journal'],
        default='dmesg',
        help='Log source to analyze (default: %(default)s)'
    )

    parser.add_argument(
        '--since',
        metavar='TIME',
        help='Only analyze logs since TIME (journalctl only, e.g., "24 hours ago")'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
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

    args = parser.parse_args()

    # Validate arguments
    if args.since and args.source != 'journal':
        print("Warning: --since only applies to --source journal", file=sys.stderr)

    # Get log content
    if args.source == 'journal':
        log_content = get_journal_logs(since=args.since)
    else:
        log_content = get_dmesg_logs()

    # Parse OOM events
    events = parse_oom_events(log_content)

    # Analyze events
    analysis = analyze_events(events)

    # Handle warn-only mode
    if args.warn_only and not events:
        sys.exit(0)

    # Output results
    if args.format == 'json':
        output_json(events, analysis)
    elif args.format == 'table':
        output_table(events, analysis, summary_only=args.summary)
    else:  # plain
        output_plain(events, analysis, summary_only=args.summary, verbose=args.verbose)

    # Exit with appropriate code
    sys.exit(1 if events else 0)


if __name__ == '__main__':
    main()
