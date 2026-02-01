#!/usr/bin/env python3
"""
Monitor NUMA (Non-Uniform Memory Access) topology and memory balance.

This script analyzes NUMA node memory distribution and detects imbalances
that can cause performance degradation on multi-socket systems. NUMA-aware
workload placement is critical for optimal performance on large baremetal
servers.

Checks performed:
- NUMA node memory usage and availability
- Cross-node memory imbalance detection
- Per-node free memory warnings
- NUMA statistics (hits, misses, foreign allocations)
- Memory pressure per NUMA node

Exit codes:
    0 - All NUMA nodes are balanced
    1 - NUMA imbalance detected or memory pressure warnings
    2 - Usage error or missing dependencies (non-NUMA system)
"""

import argparse
import sys
import os
import json
import glob


def check_numa_available():
    """Check if NUMA topology information is available"""
    return os.path.exists('/sys/devices/system/node')


def get_numa_nodes():
    """Get list of NUMA node directories"""
    node_dirs = glob.glob('/sys/devices/system/node/node[0-9]*')
    return sorted(node_dirs, key=lambda x: int(x.split('node')[-1]))


def read_sysfs_file(path):
    """Read a sysfs file and return its contents, or None if unavailable"""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def parse_meminfo_file(path):
    """Parse a meminfo-format file into a dictionary"""
    meminfo = {}
    try:
        with open(path, 'r') as f:
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    key = parts[0].strip()
                    # Extract numeric value (in kB)
                    value_parts = parts[1].strip().split()
                    if value_parts:
                        try:
                            meminfo[key] = int(value_parts[0])
                        except ValueError:
                            meminfo[key] = value_parts[0]
    except (IOError, OSError):
        pass
    return meminfo


def parse_numastat_file(path):
    """Parse NUMA statistics file"""
    stats = {}
    try:
        with open(path, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2:
                    try:
                        stats[parts[0]] = int(parts[1])
                    except ValueError:
                        stats[parts[0]] = parts[1]
    except (IOError, OSError):
        pass
    return stats


def get_node_info(node_path):
    """
    Get detailed information about a NUMA node.

    Returns dict with memory stats, CPU list, and NUMA statistics.
    """
    node_name = os.path.basename(node_path)
    node_id = int(node_name.replace('node', ''))

    info = {
        'node_id': node_id,
        'cpus': [],
        'memory': {},
        'numastat': {},
        'status': 'OK',
        'issues': []
    }

    # Get CPU list for this node
    cpulist = read_sysfs_file(f'{node_path}/cpulist')
    if cpulist:
        info['cpus'] = parse_cpu_list(cpulist)

    # Get memory info
    meminfo_path = f'{node_path}/meminfo'
    meminfo = parse_meminfo_file(meminfo_path)

    # Extract key memory values (values are in kB)
    # The meminfo format has "Node X " prefix, so keys look like "Node 0 MemTotal"
    for key in ['MemTotal', 'MemFree', 'MemUsed', 'Active', 'Inactive',
                'Dirty', 'Writeback', 'FilePages', 'Mapped', 'AnonPages',
                'Shmem', 'KernelStack', 'PageTables', 'Slab']:
        full_key = f'Node {node_id} {key}'
        if full_key in meminfo:
            info['memory'][key] = meminfo[full_key]

    # Calculate derived values
    total = info['memory'].get('MemTotal', 0)
    free = info['memory'].get('MemFree', 0)
    if total > 0:
        info['memory']['MemUsed'] = total - free
        info['memory']['used_percent'] = ((total - free) / total) * 100
        info['memory']['free_percent'] = (free / total) * 100

    # Get NUMA statistics
    numastat_path = f'{node_path}/numastat'
    info['numastat'] = parse_numastat_file(numastat_path)

    return info


def parse_cpu_list(cpulist):
    """Parse CPU list string (e.g., '0-3,8-11') into list of CPU IDs"""
    cpus = []
    if not cpulist:
        return cpus

    for part in cpulist.split(','):
        if '-' in part:
            start, end = part.split('-')
            cpus.extend(range(int(start), int(end) + 1))
        else:
            cpus.append(int(part))
    return cpus


def format_bytes(kb):
    """Convert KB to human-readable format"""
    if kb < 1024:
        return f"{kb} KB"
    elif kb < 1024 * 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb / 1024 / 1024:.1f} GB"


def analyze_numa_balance(nodes, imbalance_threshold=20.0, free_warn_threshold=10.0):
    """
    Analyze NUMA memory balance across nodes.

    Args:
        nodes: List of node info dicts
        imbalance_threshold: Percentage difference to trigger imbalance warning
        free_warn_threshold: Percentage of free memory below which to warn

    Returns:
        Tuple of (issues list, summary dict)
    """
    issues = []

    if len(nodes) < 2:
        return issues, {'single_node': True}

    # Calculate average usage across nodes
    usage_percents = []
    total_memory = 0
    total_used = 0

    for node in nodes:
        mem = node['memory']
        if 'used_percent' in mem:
            usage_percents.append(mem['used_percent'])
        if 'MemTotal' in mem:
            total_memory += mem['MemTotal']
        if 'MemUsed' in mem:
            total_used += mem['MemUsed']

    if not usage_percents:
        return issues, {'no_memory_data': True}

    avg_usage = sum(usage_percents) / len(usage_percents)

    # Check each node for issues
    for node in nodes:
        mem = node['memory']
        node_id = node['node_id']

        # Check for memory imbalance
        if 'used_percent' in mem:
            deviation = abs(mem['used_percent'] - avg_usage)
            if deviation > imbalance_threshold:
                node['status'] = 'WARNING'
                issue = {
                    'type': 'memory_imbalance',
                    'node': node_id,
                    'usage_percent': mem['used_percent'],
                    'avg_usage_percent': avg_usage,
                    'deviation': deviation
                }
                issues.append(issue)
                node['issues'].append(
                    f"Memory imbalance: {mem['used_percent']:.1f}% used vs {avg_usage:.1f}% average"
                )

        # Check for low free memory
        if 'free_percent' in mem:
            if mem['free_percent'] < free_warn_threshold:
                if node['status'] == 'OK':
                    node['status'] = 'WARNING'
                issue = {
                    'type': 'low_free_memory',
                    'node': node_id,
                    'free_percent': mem['free_percent'],
                    'free_kb': mem.get('MemFree', 0)
                }
                issues.append(issue)
                node['issues'].append(
                    f"Low free memory: {mem['free_percent']:.1f}% free"
                )

        # Check NUMA statistics for problems
        numastat = node['numastat']
        if numastat:
            numa_miss = numastat.get('numa_miss', 0)
            numa_hit = numastat.get('numa_hit', 0)
            numa_foreign = numastat.get('numa_foreign', 0)

            # High miss ratio indicates cross-node allocations
            total_allocs = numa_hit + numa_miss
            if total_allocs > 1000:  # Only check if significant allocations
                miss_ratio = numa_miss / total_allocs if total_allocs > 0 else 0
                if miss_ratio > 0.1:  # More than 10% misses
                    if node['status'] == 'OK':
                        node['status'] = 'WARNING'
                    issue = {
                        'type': 'high_numa_miss',
                        'node': node_id,
                        'numa_hit': numa_hit,
                        'numa_miss': numa_miss,
                        'miss_ratio': miss_ratio * 100
                    }
                    issues.append(issue)
                    node['issues'].append(
                        f"High NUMA miss ratio: {miss_ratio * 100:.1f}% ({numa_miss} misses)"
                    )

    summary = {
        'node_count': len(nodes),
        'total_memory_kb': total_memory,
        'total_used_kb': total_used,
        'avg_usage_percent': avg_usage,
        'max_usage_percent': max(usage_percents) if usage_percents else 0,
        'min_usage_percent': min(usage_percents) if usage_percents else 0,
        'issue_count': len(issues)
    }

    return issues, summary


def output_plain(nodes, issues, summary, warn_only=False, verbose=False):
    """Output results in plain text format"""
    lines = []

    if not warn_only:
        lines.append(f"NUMA Nodes: {summary.get('node_count', 0)}")
        lines.append(f"Total Memory: {format_bytes(summary.get('total_memory_kb', 0))}")
        lines.append(f"Average Usage: {summary.get('avg_usage_percent', 0):.1f}%")
        lines.append("")

    if issues:
        lines.append(f"Found {len(issues)} NUMA balance issues:")
        lines.append("")
        for issue in issues:
            if issue['type'] == 'memory_imbalance':
                lines.append(f"[WARNING] Node {issue['node']}: Memory imbalance - "
                           f"{issue['usage_percent']:.1f}% used vs {issue['avg_usage_percent']:.1f}% average "
                           f"(deviation: {issue['deviation']:.1f}%)")
            elif issue['type'] == 'low_free_memory':
                lines.append(f"[WARNING] Node {issue['node']}: Low free memory - "
                           f"{issue['free_percent']:.1f}% free ({format_bytes(issue['free_kb'])})")
            elif issue['type'] == 'high_numa_miss':
                lines.append(f"[WARNING] Node {issue['node']}: High NUMA miss ratio - "
                           f"{issue['miss_ratio']:.1f}% (hits: {issue['numa_hit']}, misses: {issue['numa_miss']})")
        lines.append("")
    elif not warn_only:
        lines.append("No NUMA balance issues detected.")
        lines.append("")

    if verbose and not warn_only:
        lines.append("Per-Node Details:")
        for node in nodes:
            mem = node['memory']
            lines.append(f"  Node {node['node_id']}:")
            cpu_range = f"{node['cpus'][0]}-{node['cpus'][-1]}" if node['cpus'] else "none"
            lines.append(f"    CPUs: {len(node['cpus'])} ({cpu_range})")
            if 'MemTotal' in mem:
                lines.append(f"    Memory: {format_bytes(mem.get('MemUsed', 0))} / {format_bytes(mem['MemTotal'])} "
                           f"({mem.get('used_percent', 0):.1f}% used)")
            if node['numastat']:
                stats = node['numastat']
                lines.append(f"    NUMA stats: hits={stats.get('numa_hit', 0)}, "
                           f"misses={stats.get('numa_miss', 0)}, "
                           f"foreign={stats.get('numa_foreign', 0)}")
            if node['issues']:
                for issue in node['issues']:
                    lines.append(f"    Issue: {issue}")
        lines.append("")

    return '\n'.join(lines)


def output_json(nodes, issues, summary):
    """Output results in JSON format"""
    result = {
        'summary': summary,
        'nodes': nodes,
        'issues': issues
    }
    return json.dumps(result, indent=2)


def output_table(nodes, issues, summary, warn_only=False):
    """Output results in table format"""
    lines = []

    if not warn_only:
        lines.append(f"{'Node':<8} {'CPUs':<10} {'Memory':<15} {'Used':<12} {'Free':<12} {'Status':<10}")
        lines.append("-" * 70)

        for node in nodes:
            mem = node['memory']
            cpu_count = len(node['cpus'])
            cpu_range = f"{node['cpus'][0]}-{node['cpus'][-1]}" if node['cpus'] else "none"
            total = format_bytes(mem.get('MemTotal', 0))
            used_pct = f"{mem.get('used_percent', 0):.1f}%"
            free_pct = f"{mem.get('free_percent', 0):.1f}%"
            status = node['status']

            cpu_str = f"{cpu_count}({cpu_range})"
            lines.append(f"{node['node_id']:<8} {cpu_str:<10} {total:<15} {used_pct:<12} {free_pct:<12} {status:<10}")

        lines.append("")

    if issues:
        lines.append(f"{'Type':<20} {'Node':<8} {'Details':<50}")
        lines.append("-" * 80)

        for issue in issues:
            if issue['type'] == 'memory_imbalance':
                details = f"{issue['deviation']:.1f}% deviation from average"
            elif issue['type'] == 'low_free_memory':
                details = f"{issue['free_percent']:.1f}% free ({format_bytes(issue['free_kb'])})"
            elif issue['type'] == 'high_numa_miss':
                details = f"{issue['miss_ratio']:.1f}% miss ratio"
            else:
                details = str(issue)

            lines.append(f"{issue['type']:<20} {issue['node']:<8} {details:<50}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor NUMA topology and memory balance on multi-socket systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Check NUMA balance
  %(prog)s --verbose           # Show detailed per-node stats
  %(prog)s --format json       # Output in JSON format
  %(prog)s --warn-only         # Only show issues
  %(prog)s --imbalance 15      # Warn if usage differs by 15%% from average

Exit codes:
  0 - All NUMA nodes are balanced
  1 - NUMA imbalance or memory pressure detected
  2 - Usage error or non-NUMA system

Notes:
  - Requires a multi-socket NUMA system
  - Monitors /sys/devices/system/node for topology info
  - High NUMA miss ratios indicate cross-node memory access
  - Memory imbalance can cause performance degradation
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
        help="Show detailed per-node information"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )

    parser.add_argument(
        "--imbalance",
        type=float,
        default=20.0,
        help="Imbalance threshold percentage (default: %(default)s%%)"
    )

    parser.add_argument(
        "--free-warn",
        type=float,
        default=10.0,
        help="Warn when free memory falls below this percentage (default: %(default)s%%)"
    )

    args = parser.parse_args()

    # Validate thresholds
    if not 0.0 <= args.imbalance <= 100.0:
        print("Error: Imbalance threshold must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if not 0.0 <= args.free_warn <= 100.0:
        print("Error: Free memory warning threshold must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    # Check for NUMA availability
    if not check_numa_available():
        print("Error: NUMA topology not found at /sys/devices/system/node", file=sys.stderr)
        print("This system may not have NUMA architecture or sysfs is not mounted", file=sys.stderr)
        sys.exit(2)

    # Get NUMA node information
    node_dirs = get_numa_nodes()
    if not node_dirs:
        print("Error: No NUMA nodes found", file=sys.stderr)
        sys.exit(2)

    if len(node_dirs) < 2:
        # Single NUMA node - not really NUMA
        print("Info: Only one NUMA node found - this is a single-socket system", file=sys.stderr)
        print("NUMA balancing is not applicable", file=sys.stderr)
        sys.exit(2)

    # Collect node information
    nodes = []
    for node_path in node_dirs:
        node_info = get_node_info(node_path)
        nodes.append(node_info)

    # Analyze balance
    issues, summary = analyze_numa_balance(nodes, args.imbalance, args.free_warn)

    # Output results
    if args.format == "json":
        output = output_json(nodes, issues, summary)
    elif args.format == "table":
        output = output_table(nodes, issues, summary, args.warn_only)
    else:  # plain
        output = output_plain(nodes, issues, summary, args.warn_only, args.verbose)

    print(output)

    # Exit based on findings
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
