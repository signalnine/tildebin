#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [numa, latency, memory, performance, topology]
#   requires: []
#   privilege: none
#   related: [numa_locality, memory_usage, numa_balance_monitor]
#   brief: Monitor NUMA memory access latency and topology

"""
Monitor NUMA memory access latency and topology on Linux systems.

Analyzes NUMA characteristics to identify potential performance issues
caused by remote memory access. On multi-socket systems, accessing memory
attached to a remote NUMA node is significantly slower than local access.

Checks performed:
- NUMA node count and memory distribution
- Distance matrix (inter-node latency ratios)
- Per-node memory statistics (free, used, dirty)
- Memory migration statistics (pgmigrate success/failure)
- Zone reclaim and numa_balancing status
- Identification of asymmetric NUMA topologies
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_sysfs_file(path: str, context: Context) -> str | None:
    """Read a sysfs file, returning None on error."""
    try:
        return context.read_file(path)
    except (FileNotFoundError, PermissionError):
        return None


def get_numa_nodes(context: Context) -> list[int] | None:
    """Discover NUMA nodes from /sys/devices/system/node/."""
    node_path = '/sys/devices/system/node'

    if not context.file_exists(node_path):
        return None

    nodes = []
    try:
        entries = context.glob('node[0-9]*', root=node_path)
        for entry in entries:
            # Extract node number from path like /sys/.../node0
            name = entry.split('/')[-1]
            if name.startswith('node') and name[4:].isdigit():
                nodes.append(int(name[4:]))
    except (OSError, PermissionError):
        return None

    return sorted(nodes) if nodes else None


def get_distance_matrix(nodes: list[int], context: Context) -> dict[int, list[int]]:
    """Read NUMA distance matrix from sysfs."""
    distances = {}

    for node in nodes:
        distance_path = f'/sys/devices/system/node/node{node}/distance'
        content = read_sysfs_file(distance_path, context)

        if content:
            try:
                distances[node] = [int(d) for d in content.strip().split()]
            except ValueError:
                distances[node] = []

    return distances


def get_node_meminfo(node: int, context: Context) -> dict[str, int] | None:
    """Read memory statistics for a NUMA node."""
    meminfo_path = f'/sys/devices/system/node/node{node}/meminfo'
    content = read_sysfs_file(meminfo_path, context)

    if not content:
        return None

    stats = {}
    for line in content.strip().split('\n'):
        if ':' not in line:
            continue

        parts = line.split(':')
        if len(parts) != 2:
            continue

        key_parts = parts[0].split()
        if len(key_parts) < 2:
            continue

        key = key_parts[-1]
        value_parts = parts[1].strip().split()

        try:
            value = int(value_parts[0])
            stats[key] = value
        except (ValueError, IndexError):
            continue

    return stats


def get_vmstat_numa(context: Context) -> dict[str, int]:
    """Read NUMA-related statistics from /proc/vmstat."""
    content = read_sysfs_file('/proc/vmstat', context)
    if not content:
        return {}

    stats = {}
    for line in content.strip().split('\n'):
        parts = line.split()
        if len(parts) == 2:
            key = parts[0]
            if any(x in key for x in ['numa', 'pgmigrate', 'compact']):
                try:
                    stats[key] = int(parts[1])
                except ValueError:
                    continue

    return stats


def get_numa_balancing_status(context: Context) -> dict[str, Any]:
    """Check if automatic NUMA balancing is enabled."""
    path = '/proc/sys/kernel/numa_balancing'
    content = read_sysfs_file(path, context)

    if content is None:
        return {'enabled': None, 'mode': 'unknown'}

    try:
        value = int(content.strip())
        return {
            'enabled': value == 1,
            'mode': 'enabled' if value == 1 else 'disabled'
        }
    except ValueError:
        return {'enabled': None, 'mode': 'unknown'}


def analyze_topology(nodes: list[int], distances: dict[int, list[int]]) -> tuple[dict, list[dict]]:
    """Analyze NUMA topology for issues."""
    issues = []
    topology = {
        'node_count': len(nodes),
        'nodes': nodes,
        'max_distance': 10,
        'min_distance': 10,
        'is_symmetric': True,
        'remote_ratio': 1.0,
    }

    if not distances:
        return topology, issues

    all_distances = []
    for node, dists in distances.items():
        all_distances.extend(dists)

    if all_distances:
        topology['max_distance'] = max(all_distances)
        topology['min_distance'] = min(all_distances)

        local_dist = 10
        remote_dists = [d for d in all_distances if d > local_dist]
        if remote_dists:
            topology['remote_ratio'] = sum(remote_dists) / len(remote_dists) / local_dist

    # Check for asymmetric topology
    for node_a in nodes:
        for node_b in nodes:
            if node_a >= node_b:
                continue

            dist_ab = distances.get(node_a, [])[node_b] if node_b < len(distances.get(node_a, [])) else None
            dist_ba = distances.get(node_b, [])[node_a] if node_a < len(distances.get(node_b, [])) else None

            if dist_ab is not None and dist_ba is not None and dist_ab != dist_ba:
                topology['is_symmetric'] = False
                issues.append({
                    'severity': 'WARNING',
                    'type': 'asymmetric_topology',
                    'message': f"Asymmetric distance between node {node_a} and {node_b}: {dist_ab} vs {dist_ba}",
                    'nodes': [node_a, node_b],
                })

    # Warn about high remote access latency
    if topology['max_distance'] > 30:
        issues.append({
            'severity': 'WARNING',
            'type': 'high_latency',
            'message': f"High NUMA distance detected: {topology['max_distance']} ({topology['max_distance']/10:.1f}x local latency)",
            'max_distance': topology['max_distance'],
        })

    return topology, issues


def analyze_memory_distribution(nodes: list[int], context: Context) -> tuple[list[dict], dict, list[dict]]:
    """Analyze memory distribution across NUMA nodes."""
    node_stats = []
    issues = []
    total_mem = 0
    total_free = 0
    mem_per_node = []

    for node in nodes:
        meminfo = get_node_meminfo(node, context)
        if not meminfo:
            continue

        mem_total = meminfo.get('MemTotal', 0)
        mem_free = meminfo.get('MemFree', 0)
        mem_used = meminfo.get('MemUsed', mem_total - mem_free)
        dirty = meminfo.get('Dirty', 0)
        file_pages = meminfo.get('FilePages', 0)
        active = meminfo.get('Active', 0)

        total_mem += mem_total
        total_free += mem_free
        mem_per_node.append(mem_total)

        use_pct = (mem_used / mem_total * 100) if mem_total > 0 else 0

        node_stats.append({
            'node': node,
            'total_kb': mem_total,
            'free_kb': mem_free,
            'used_kb': mem_used,
            'used_pct': round(use_pct, 1),
            'dirty_kb': dirty,
            'file_pages_kb': file_pages,
            'active_kb': active,
        })

        if use_pct > 95:
            issues.append({
                'severity': 'WARNING',
                'type': 'node_memory_pressure',
                'message': f"Node {node} memory usage critical: {use_pct:.1f}%",
                'node': node,
                'used_pct': use_pct,
            })
        elif use_pct > 85:
            issues.append({
                'severity': 'WARNING',
                'type': 'node_memory_high',
                'message': f"Node {node} memory usage high: {use_pct:.1f}%",
                'node': node,
                'used_pct': use_pct,
            })

    # Check for memory imbalance
    if len(mem_per_node) > 1:
        avg_mem = sum(mem_per_node) / len(mem_per_node)
        for i, mem in enumerate(mem_per_node):
            deviation = abs(mem - avg_mem) / avg_mem * 100 if avg_mem > 0 else 0
            if deviation > 20:
                issues.append({
                    'severity': 'WARNING',
                    'type': 'memory_imbalance',
                    'message': f"Node {nodes[i]} has {deviation:.1f}% memory deviation from average",
                    'node': nodes[i],
                    'deviation_pct': deviation,
                })

    summary = {
        'total_memory_kb': total_mem,
        'total_free_kb': total_free,
        'total_used_pct': round((total_mem - total_free) / total_mem * 100, 1) if total_mem > 0 else 0,
        'nodes_analyzed': len(node_stats),
    }

    return node_stats, summary, issues


def analyze_migration_stats(vmstat: dict[str, int]) -> tuple[dict, list[dict]]:
    """Analyze NUMA page migration statistics."""
    issues = []

    migrate_success = vmstat.get('pgmigrate_success', 0)
    migrate_fail = vmstat.get('pgmigrate_fail', 0)
    numa_hit = vmstat.get('numa_hit', 0)
    numa_miss = vmstat.get('numa_miss', 0)
    numa_foreign = vmstat.get('numa_foreign', 0)
    numa_interleave = vmstat.get('numa_interleave', 0)
    numa_local = vmstat.get('numa_local', 0)
    numa_other = vmstat.get('numa_other', 0)

    total_allocs = numa_hit + numa_miss
    miss_ratio = (numa_miss / total_allocs * 100) if total_allocs > 0 else 0

    total_migrate = migrate_success + migrate_fail
    fail_ratio = (migrate_fail / total_migrate * 100) if total_migrate > 0 else 0

    stats = {
        'numa_hit': numa_hit,
        'numa_miss': numa_miss,
        'numa_foreign': numa_foreign,
        'numa_interleave': numa_interleave,
        'numa_local': numa_local,
        'numa_other': numa_other,
        'pgmigrate_success': migrate_success,
        'pgmigrate_fail': migrate_fail,
        'miss_ratio_pct': round(miss_ratio, 2),
        'migrate_fail_ratio_pct': round(fail_ratio, 2),
    }

    if miss_ratio > 10 and total_allocs > 1000:
        issues.append({
            'severity': 'WARNING',
            'type': 'high_numa_miss',
            'message': f"High NUMA miss ratio: {miss_ratio:.1f}% ({numa_miss} of {total_allocs} allocations)",
            'miss_ratio': miss_ratio,
        })

    if fail_ratio > 20 and total_migrate > 100:
        issues.append({
            'severity': 'WARNING',
            'type': 'migration_failures',
            'message': f"High page migration failure rate: {fail_ratio:.1f}%",
            'fail_ratio': fail_ratio,
        })

    return stats, issues


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
    parser = argparse.ArgumentParser(description="Monitor NUMA memory access latency and topology")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Get NUMA nodes
    nodes = get_numa_nodes(context)

    if nodes is None:
        output.error("NUMA information not available")
        return 2

    if len(nodes) == 0:
        output.error("No NUMA nodes found")
        return 2

    if len(nodes) == 1:
        output.emit({
            'topology': {
                'node_count': 1,
                'nodes': nodes,
                'is_uma': True,
                'message': 'Single NUMA node (UMA system)',
            },
            'issues': [],
        })
        output.set_summary("UMA system - no NUMA latency concerns")
        return 0

    # Gather NUMA information
    distances = get_distance_matrix(nodes, context)
    vmstat = get_vmstat_numa(context)
    balancing = get_numa_balancing_status(context)

    # Analyze
    topology, topo_issues = analyze_topology(nodes, distances)
    node_stats, mem_summary, mem_issues = analyze_memory_distribution(nodes, context)
    migration, mig_issues = analyze_migration_stats(vmstat)

    # Combine issues
    all_issues = topo_issues + mem_issues + mig_issues

    # Build output
    result = {
        'topology': topology,
        'memory': {
            'summary': mem_summary,
            'nodes': node_stats if opts.verbose else [],
        },
        'migration': migration if opts.verbose else {
            'miss_ratio_pct': migration['miss_ratio_pct'],
            'migrate_fail_ratio_pct': migration['migrate_fail_ratio_pct'],
        },
        'numa_balancing': balancing,
        'issues': all_issues,
    }

    output.emit(result)

    # Set summary
    if all_issues:
        warning_count = sum(1 for i in all_issues if i['severity'] == 'WARNING')
        output.set_summary(f"{warning_count} NUMA issue(s) detected")
        return 1
    else:
        output.set_summary(f"{topology['node_count']} NUMA nodes, topology healthy")
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
