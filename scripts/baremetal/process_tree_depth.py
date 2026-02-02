#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [process, tree, depth, fork-bomb, security]
#   requires: []
#   privilege: user
#   related: [process_tree, process_swap]
#   brief: Monitor process tree depth to detect fork bombs

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
"""

import argparse
import os
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_proc_stat(pid: int) -> dict[str, Any] | None:
    """Read process stat file and return relevant fields."""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            content = f.read()

        # Parse stat file - comm can contain spaces and parens
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


def read_proc_cmdline(pid: int) -> str | None:
    """Read process command line."""
    try:
        with open(f'/proc/{pid}/cmdline', 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            return cmdline[:100] if cmdline else None
    except (IOError, OSError):
        return None


def get_all_processes() -> tuple[dict, dict]:
    """Get all running processes and their parent relationships."""
    processes = {}
    children = defaultdict(list)

    try:
        pids = [int(d) for d in os.listdir('/proc') if d.isdigit()]
    except OSError:
        return {}, {}

    for pid in pids:
        stat = read_proc_stat(pid)
        if stat:
            processes[pid] = stat
            children[stat['ppid']].append(pid)

    return processes, children


def calculate_tree_depth(pid: int, processes: dict, children: dict,
                         cache: dict | None = None) -> int:
    """Calculate depth of process tree rooted at pid."""
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


def get_ancestry_chain(pid: int, processes: dict, max_depth: int = 20) -> list[dict]:
    """Get the ancestry chain for a process."""
    chain = []
    current = pid
    seen = set()

    while current and current in processes and len(chain) < max_depth:
        if current in seen:
            break
        seen.add(current)

        proc = processes[current]
        chain.append({
            'pid': current,
            'comm': proc['comm'],
            'state': proc['state']
        })
        current = proc['ppid']

    return list(reversed(chain))


def find_deepest_chains(processes: dict, children: dict, top_n: int = 5) -> list[dict]:
    """Find the deepest process chains in the system."""
    leaf_depths = []
    for pid in processes:
        if not children.get(pid):  # Leaf process
            chain = get_ancestry_chain(pid, processes, max_depth=100)
            depth = len(chain) - 1
            leaf_depths.append({
                'pid': pid,
                'depth': depth,
                'chain': chain
            })

    leaf_depths.sort(key=lambda x: x['depth'], reverse=True)
    return leaf_depths[:top_n]


def count_process_children(children: dict) -> dict[int, int]:
    """Count direct children for each process."""
    return {ppid: len(child_list) for ppid, child_list in children.items()}


def analyze_process_tree(processes: dict, children: dict, thresholds: dict) -> dict:
    """Analyze process tree and return findings."""
    issues = []
    warnings = []

    deepest = find_deepest_chains(processes, children, top_n=10)
    max_depth = deepest[0]['depth'] if deepest else 0

    # Check depth thresholds
    if max_depth >= thresholds['critical_depth']:
        issues.append({
            'type': 'critical_depth',
            'message': f"Process tree depth {max_depth} exceeds critical threshold ({thresholds['critical_depth']})",
            'depth': max_depth
        })
    elif max_depth >= thresholds['warning_depth']:
        warnings.append({
            'type': 'warning_depth',
            'message': f"Process tree depth {max_depth} exceeds warning threshold ({thresholds['warning_depth']})",
            'depth': max_depth
        })

    # Check for processes with many children
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
                    issues.append({
                        'type': 'child_critical',
                        'message': f"Process {proc['comm']} (PID {ppid}) has {count} children",
                        'pid': ppid,
                        'child_count': count
                    })
                else:
                    warnings.append({
                        'type': 'child_warning',
                        'message': f"Process {proc['comm']} (PID {ppid}) has {count} children",
                        'pid': ppid,
                        'child_count': count
                    })

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
        description="Monitor process tree depth to detect fork bombs"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed process chain paths")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--depth-warning", type=int, default=15,
                        help="Warning threshold for tree depth (default: 15)")
    parser.add_argument("--depth-critical", type=int, default=30,
                        help="Critical threshold for tree depth (default: 30)")
    parser.add_argument("--child-warning", type=int, default=50,
                        help="Warning threshold for child process count (default: 50)")
    parser.add_argument("--child-critical", type=int, default=200,
                        help="Critical threshold for child process count (default: 200)")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.depth_warning >= opts.depth_critical:
        output.error("depth-warning must be less than depth-critical")
        return 2

    if opts.child_warning >= opts.child_critical:
        output.error("child-warning must be less than child-critical")
        return 2

    if opts.depth_warning < 1 or opts.child_warning < 1:
        output.error("Thresholds must be positive integers")
        return 2

    # Gather process data
    processes, children = get_all_processes()

    if not processes:
        output.error("No processes found in /proc")
        return 2

    # Analyze
    thresholds = {
        'warning_depth': opts.depth_warning,
        'critical_depth': opts.depth_critical,
        'child_warning': opts.child_warning,
        'child_critical': opts.child_critical
    }
    analysis = analyze_process_tree(processes, children, thresholds)

    # Build output
    result = {
        'total_processes': analysis['total_processes'],
        'max_depth': analysis['max_depth'],
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'high_child_procs': analysis['high_child_procs'],
    }

    if opts.verbose:
        result['deepest_chains'] = analysis['deepest_chains']

    output.emit(result)

    # Set summary
    if analysis['issues']:
        output.set_summary(f"CRITICAL: {len(analysis['issues'])} issue(s)")
    elif analysis['warnings']:
        output.set_summary(f"WARNING: {len(analysis['warnings'])} warning(s)")
    else:
        output.set_summary(f"Healthy (max depth: {analysis['max_depth']})")

    return 1 if analysis['issues'] else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
