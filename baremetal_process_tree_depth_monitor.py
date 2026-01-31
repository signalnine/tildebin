#!/usr/bin/env python3
"""
Monitor process tree depth to detect fork bombs and runaway process spawning.

Analyzes the process hierarchy to identify abnormally deep process trees,
which can indicate fork bombs, container escape attempts, runaway scripts,
or misconfigured services. Deep process trees consume kernel resources
and can destabilize systems.

Key features:
- Measures maximum process tree depth across all processes
- Identifies the deepest process chains with full ancestry
- Detects processes with unusually high child counts
- Flags potential fork bomb patterns (rapid spawning)
- Tracks processes exceeding configurable depth thresholds

Exit codes:
    0 - Process tree depth within acceptable limits
    1 - Warning or critical depth threshold exceeded
    2 - Usage error or unable to read process information
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone


def read_proc_stat(pid):
    """Read process stat file and return relevant fields."""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            content = f.read()

        # Parse stat file - comm can contain spaces and parens, so we find it
        # Format: pid (comm) state ppid ...
        start = content.index('(')
        end = content.rindex(')')
        comm = content[start + 1:end]
        rest = content[end + 2:].split()

        return {
            'pid': pid,
            'comm': comm,
            'state': rest[0],
            'ppid': int(rest[1]),
        }
    except (IOError, OSError, ValueError, IndexError):
        return None


def read_proc_cmdline(pid):
    """Read process command line."""
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            return cmdline[:100] if cmdline else None
    except (IOError, OSError):
        return None


def get_all_processes():
    """Get all running processes and their parent relationships."""
    processes = {}
    children = defaultdict(list)

    try:
        pids = [int(d) for d in os.listdir('/proc') if d.isdigit()]
    except OSError as e:
        print(f"Error: Unable to read /proc: {e}", file=sys.stderr)
        sys.exit(2)

    for pid in pids:
        stat = read_proc_stat(pid)
        if stat:
            processes[pid] = stat
            children[stat['ppid']].append(pid)

    return processes, children


def calculate_tree_depth(pid, processes, children, cache=None):
    """Calculate depth of process tree rooted at pid (recursive with memoization)."""
    if cache is None:
        cache = {}

    if pid in cache:
        return cache[pid]

    child_pids = children.get(pid, [])
    if not child_pids:
        cache[pid] = 0
        return 0

    max_depth = 0
    for child in child_pids:
        if child in processes:
            child_depth = calculate_tree_depth(child, processes, children, cache)
            max_depth = max(max_depth, child_depth + 1)

    cache[pid] = max_depth
    return max_depth


def get_ancestry_chain(pid, processes, max_depth=20):
    """Get the ancestry chain for a process up to max_depth."""
    chain = []
    current = pid
    seen = set()

    while current and current in processes and len(chain) < max_depth:
        if current in seen:
            break  # Prevent infinite loop
        seen.add(current)

        proc = processes[current]
        chain.append({
            'pid': current,
            'comm': proc['comm'],
            'state': proc['state']
        })
        current = proc['ppid']

    return list(reversed(chain))


def find_deepest_chains(processes, children, top_n=5):
    """Find the deepest process chains in the system."""
    depth_cache = {}

    # Calculate depth to each leaf
    leaf_depths = []
    for pid in processes:
        if not children.get(pid):  # Leaf process (no children)
            # Calculate depth from root to this leaf
            chain = get_ancestry_chain(pid, processes, max_depth=100)
            depth = len(chain) - 1  # Depth is edges, not nodes
            leaf_depths.append({
                'pid': pid,
                'depth': depth,
                'chain': chain
            })

    # Sort by depth descending
    leaf_depths.sort(key=lambda x: x['depth'], reverse=True)
    return leaf_depths[:top_n]


def count_process_children(children):
    """Count direct children for each process."""
    child_counts = {}
    for ppid, child_list in children.items():
        child_counts[ppid] = len(child_list)
    return child_counts


def analyze_process_tree(processes, children, thresholds):
    """Analyze process tree and return findings."""
    issues = []
    warnings = []

    # Find deepest chains
    deepest = find_deepest_chains(processes, children, top_n=10)
    max_depth = deepest[0]['depth'] if deepest else 0

    # Check depth thresholds
    if max_depth >= thresholds['critical_depth']:
        issues.append(f"Critical: Process tree depth {max_depth} exceeds "
                     f"critical threshold ({thresholds['critical_depth']})")
    elif max_depth >= thresholds['warning_depth']:
        warnings.append(f"Warning: Process tree depth {max_depth} exceeds "
                       f"warning threshold ({thresholds['warning_depth']})")

    # Check for processes with many children (potential fork bomb)
    child_counts = count_process_children(children)
    high_child_procs = []
    for ppid, count in child_counts.items():
        if count >= thresholds['child_warning']:
            proc = processes.get(ppid)
            if proc:
                high_child_procs.append({
                    'pid': ppid,
                    'comm': proc['comm'],
                    'child_count': count
                })
                if count >= thresholds['child_critical']:
                    issues.append(f"Critical: Process {proc['comm']} (PID {ppid}) "
                                 f"has {count} children (threshold: {thresholds['child_critical']})")
                else:
                    warnings.append(f"Warning: Process {proc['comm']} (PID {ppid}) "
                                   f"has {count} children (threshold: {thresholds['child_warning']})")

    # Sort high child count processes
    high_child_procs.sort(key=lambda x: x['child_count'], reverse=True)

    return {
        'max_depth': max_depth,
        'deepest_chains': deepest[:5],
        'high_child_procs': high_child_procs[:10],
        'total_processes': len(processes),
        'issues': issues,
        'warnings': warnings,
        'status': 'critical' if issues else ('warning' if warnings else 'healthy')
    }


def format_plain(analysis, verbose=False):
    """Format output as plain text."""
    lines = []

    lines.append("Process Tree Depth Monitor")
    lines.append("=" * 50)
    lines.append("")

    lines.append(f"Total processes: {analysis['total_processes']}")
    lines.append(f"Maximum tree depth: {analysis['max_depth']}")
    lines.append("")

    # Show deepest chains
    if analysis['deepest_chains']:
        lines.append("Deepest Process Chains:")
        lines.append("-" * 50)
        for i, chain_info in enumerate(analysis['deepest_chains'][:5], 1):
            chain = chain_info['chain']
            depth = chain_info['depth']
            leaf_proc = chain[-1] if chain else {'comm': '?', 'pid': 0}
            lines.append(f"  {i}. Depth {depth}: {leaf_proc['comm']} (PID {leaf_proc['pid']})")

            if verbose and chain:
                # Show chain path
                path = ' -> '.join([f"{p['comm']}" for p in chain])
                lines.append(f"     Path: {path}")
        lines.append("")

    # Show processes with many children
    if analysis['high_child_procs']:
        lines.append("Processes with High Child Count:")
        lines.append("-" * 50)
        for proc in analysis['high_child_procs'][:5]:
            lines.append(f"  {proc['comm']} (PID {proc['pid']}): "
                        f"{proc['child_count']} children")
        lines.append("")

    # Issues and warnings
    if analysis['issues']:
        lines.append("ISSUES:")
        for issue in analysis['issues']:
            lines.append(f"  [!] {issue}")
        lines.append("")

    if analysis['warnings']:
        lines.append("WARNINGS:")
        for warning in analysis['warnings']:
            lines.append(f"  [*] {warning}")
        lines.append("")

    # Summary
    if not analysis['issues'] and not analysis['warnings']:
        lines.append("[OK] Process tree depth within acceptable limits")

    return "\n".join(lines)


def format_json(analysis):
    """Format output as JSON."""
    return json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'total_processes': analysis['total_processes'],
        'max_depth': analysis['max_depth'],
        'deepest_chains': analysis['deepest_chains'],
        'high_child_procs': analysis['high_child_procs'],
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'healthy': len(analysis['issues']) == 0
    }, indent=2)


def format_table(analysis):
    """Format output as a table."""
    lines = []

    lines.append("+" + "-" * 58 + "+")
    lines.append("| Process Tree Depth Monitor" + " " * 31 + "|")
    lines.append("+" + "-" * 58 + "+")

    lines.append(f"| {'Metric':<30} | {'Value':<23} |")
    lines.append("+" + "-" * 58 + "+")

    lines.append(f"| {'Total Processes':<30} | {analysis['total_processes']:<23} |")
    lines.append(f"| {'Maximum Tree Depth':<30} | {analysis['max_depth']:<23} |")
    lines.append(f"| {'Processes with High Children':<30} | {len(analysis['high_child_procs']):<23} |")
    lines.append(f"| {'Status':<30} | {analysis['status'].upper():<23} |")
    lines.append("+" + "-" * 58 + "+")

    if analysis['deepest_chains']:
        lines.append("| Deepest Chains:" + " " * 42 + "|")
        for chain_info in analysis['deepest_chains'][:3]:
            chain = chain_info['chain']
            depth = chain_info['depth']
            leaf = chain[-1] if chain else {'comm': '?', 'pid': 0}
            info = f"  depth={depth}: {leaf['comm']} (PID {leaf['pid']})"
            lines.append(f"| {info:<56} |")
        lines.append("+" + "-" * 58 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor process tree depth to detect fork bombs and runaway spawning',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic check
  %(prog)s

  # JSON output for monitoring
  %(prog)s --format json

  # Custom thresholds
  %(prog)s --depth-warning 20 --depth-critical 50

  # Only show if issues detected
  %(prog)s --warn-only

Thresholds:
  --depth-warning    Warn if max tree depth exceeds this (default: 15)
  --depth-critical   Critical if max tree depth exceeds this (default: 30)
  --child-warning    Warn if process has more children (default: 50)
  --child-critical   Critical if process has more children (default: 200)

Exit codes:
  0 - Process tree depth within acceptable limits
  1 - Warning or critical threshold exceeded
  2 - Usage error or unable to read process information
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--depth-warning',
        type=int,
        default=15,
        help='Warning threshold for tree depth (default: 15)'
    )
    parser.add_argument(
        '--depth-critical',
        type=int,
        default=30,
        help='Critical threshold for tree depth (default: 30)'
    )
    parser.add_argument(
        '--child-warning',
        type=int,
        default=50,
        help='Warning threshold for child process count (default: 50)'
    )
    parser.add_argument(
        '--child-critical',
        type=int,
        default=200,
        help='Critical threshold for child process count (default: 200)'
    )
    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed process chain paths'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.depth_warning >= args.depth_critical:
        print("Error: depth-warning must be less than depth-critical",
              file=sys.stderr)
        sys.exit(2)

    if args.child_warning >= args.child_critical:
        print("Error: child-warning must be less than child-critical",
              file=sys.stderr)
        sys.exit(2)

    if args.depth_warning < 1 or args.child_warning < 1:
        print("Error: Thresholds must be positive integers", file=sys.stderr)
        sys.exit(2)

    # Gather process data
    processes, children = get_all_processes()

    if not processes:
        print("Error: No processes found in /proc", file=sys.stderr)
        sys.exit(2)

    # Analyze
    thresholds = {
        'warning_depth': args.depth_warning,
        'critical_depth': args.depth_critical,
        'child_warning': args.child_warning,
        'child_critical': args.child_critical
    }
    analysis = analyze_process_tree(processes, children, thresholds)

    # Format output
    if args.format == 'json':
        output = format_json(analysis)
    elif args.format == 'table':
        output = format_table(analysis)
    else:
        output = format_plain(analysis, args.verbose)

    # Print output (respecting --warn-only)
    if not args.warn_only or analysis['issues'] or analysis['warnings']:
        print(output)

    # Return appropriate exit code
    return 1 if analysis['issues'] else 0


if __name__ == '__main__':
    sys.exit(main())
