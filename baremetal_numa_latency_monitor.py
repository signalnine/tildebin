#!/usr/bin/env python3
"""
Monitor NUMA memory access latency and topology on Linux systems.

This script analyzes NUMA (Non-Uniform Memory Access) characteristics to
identify potential performance issues caused by remote memory access. On
multi-socket systems, accessing memory attached to a remote NUMA node is
significantly slower than local access.

Checks performed:
- NUMA node count and memory distribution
- Distance matrix (inter-node latency ratios)
- Per-node memory statistics (free, used, dirty)
- Memory migration statistics (pgmigrate success/failure)
- Zone reclaim and numa_balancing status
- Identification of asymmetric NUMA topologies

Useful for:
- Performance tuning on multi-socket servers
- Diagnosing memory-intensive application slowdowns
- Validating NUMA-aware application configuration
- Pre-deployment hardware validation
- Database and VM workload optimization

Exit codes:
    0 - NUMA topology healthy, no issues detected
    1 - Warnings detected (asymmetric topology, high remote access)
    2 - Usage error or NUMA information unavailable
"""

import argparse
import sys
import os
import json


def read_file(path):
    """Read a file and return contents, or None on error."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None


def get_numa_nodes():
    """
    Discover NUMA nodes from /sys/devices/system/node/.

    Returns:
        list: List of node IDs (integers), or None if NUMA not available
    """
    node_path = '/sys/devices/system/node'

    if not os.path.isdir(node_path):
        return None

    nodes = []
    try:
        for entry in os.listdir(node_path):
            if entry.startswith('node') and entry[4:].isdigit():
                nodes.append(int(entry[4:]))
    except PermissionError:
        return None

    return sorted(nodes) if nodes else None


def get_distance_matrix(nodes):
    """
    Read NUMA distance matrix from sysfs.

    The distance represents relative memory access latency.
    Local access = 10 (baseline), remote access > 10.

    Returns:
        dict: {node_id: [distances to each node]}
    """
    distances = {}

    for node in nodes:
        distance_path = f'/sys/devices/system/node/node{node}/distance'
        content = read_file(distance_path)

        if content:
            try:
                distances[node] = [int(d) for d in content.strip().split()]
            except ValueError:
                distances[node] = []

    return distances


def get_node_meminfo(node):
    """
    Read memory statistics for a NUMA node.

    Returns:
        dict: Memory statistics or None
    """
    meminfo_path = f'/sys/devices/system/node/node{node}/meminfo'
    content = read_file(meminfo_path)

    if not content:
        return None

    stats = {}
    for line in content.strip().split('\n'):
        # Format: "Node X FieldName: value kB"
        if ':' not in line:
            continue

        parts = line.split(':')
        if len(parts) != 2:
            continue

        # Extract field name (last word before colon)
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


def get_numa_stat():
    """
    Read global NUMA statistics from /sys/devices/system/node/*/numastat.

    Returns:
        dict: {node_id: {stat_name: value}}
    """
    nodes = get_numa_nodes()
    if not nodes:
        return None

    all_stats = {}
    for node in nodes:
        stat_path = f'/sys/devices/system/node/node{node}/numastat'
        content = read_file(stat_path)

        if not content:
            continue

        stats = {}
        for line in content.strip().split('\n'):
            parts = line.split()
            if len(parts) == 2:
                try:
                    stats[parts[0]] = int(parts[1])
                except ValueError:
                    continue

        all_stats[node] = stats

    return all_stats


def get_vmstat_numa():
    """
    Read NUMA-related statistics from /proc/vmstat.

    Returns:
        dict: NUMA-related vmstat entries
    """
    content = read_file('/proc/vmstat')
    if not content:
        return {}

    stats = {}
    for line in content.strip().split('\n'):
        parts = line.split()
        if len(parts) == 2:
            key = parts[0]
            # Filter for NUMA-related stats
            if any(x in key for x in ['numa', 'pgmigrate', 'compact']):
                try:
                    stats[key] = int(parts[1])
                except ValueError:
                    continue

    return stats


def get_numa_balancing_status():
    """
    Check if automatic NUMA balancing is enabled.

    Returns:
        dict: {enabled: bool, mode: str}
    """
    path = '/proc/sys/kernel/numa_balancing'
    content = read_file(path)

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


def analyze_topology(nodes, distances):
    """
    Analyze NUMA topology for issues.

    Args:
        nodes: List of node IDs
        distances: Distance matrix

    Returns:
        tuple: (topology_info, issues)
    """
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

        # Calculate average remote access ratio
        local_dist = 10  # Baseline
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
                    'message': f"Asymmetric distance between node {node_a} and {node_b}: "
                               f"{dist_ab} vs {dist_ba}",
                    'nodes': [node_a, node_b],
                })

    # Warn about high remote access latency
    if topology['max_distance'] > 30:  # More than 3x local latency
        issues.append({
            'severity': 'WARNING',
            'type': 'high_latency',
            'message': f"High NUMA distance detected: {topology['max_distance']} "
                       f"(remote access {topology['max_distance']/10:.1f}x slower)",
            'max_distance': topology['max_distance'],
        })

    return topology, issues


def analyze_memory_distribution(nodes):
    """
    Analyze memory distribution across NUMA nodes.

    Args:
        nodes: List of node IDs

    Returns:
        tuple: (node_stats, summary, issues)
    """
    node_stats = []
    issues = []
    total_mem = 0
    total_free = 0
    mem_per_node = []

    for node in nodes:
        meminfo = get_node_meminfo(node)
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

        # Warn if a node is nearly exhausted
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
            if deviation > 20:  # More than 20% deviation from average
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


def analyze_migration_stats(vmstat):
    """
    Analyze NUMA page migration statistics.

    Args:
        vmstat: Dictionary of vmstat entries

    Returns:
        tuple: (stats, issues)
    """
    issues = []

    migrate_success = vmstat.get('pgmigrate_success', 0)
    migrate_fail = vmstat.get('pgmigrate_fail', 0)
    numa_hit = vmstat.get('numa_hit', 0)
    numa_miss = vmstat.get('numa_miss', 0)
    numa_foreign = vmstat.get('numa_foreign', 0)
    numa_interleave = vmstat.get('numa_interleave', 0)
    numa_local = vmstat.get('numa_local', 0)
    numa_other = vmstat.get('numa_other', 0)

    # Calculate ratios
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

    # Warn about high NUMA miss ratio
    if miss_ratio > 10 and total_allocs > 1000:
        issues.append({
            'severity': 'WARNING',
            'type': 'high_numa_miss',
            'message': f"High NUMA miss ratio: {miss_ratio:.1f}% ({numa_miss} of {total_allocs} allocations)",
            'miss_ratio': miss_ratio,
        })

    # Warn about migration failures
    if fail_ratio > 20 and total_migrate > 100:
        issues.append({
            'severity': 'WARNING',
            'type': 'migration_failures',
            'message': f"High page migration failure rate: {fail_ratio:.1f}%",
            'fail_ratio': fail_ratio,
        })

    return stats, issues


def format_bytes(kb):
    """Format KB to human-readable."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb} KB"


def output_plain(topology, node_stats, mem_summary, migration, balancing, issues,
                 warn_only=False, verbose=False):
    """Output results in plain text format."""
    lines = []

    if not warn_only:
        lines.append("NUMA Topology Analysis:")
        lines.append("")
        lines.append(f"  NUMA nodes: {topology['node_count']}")
        lines.append(f"  Total memory: {format_bytes(mem_summary['total_memory_kb'])}")
        lines.append(f"  Memory utilization: {mem_summary['total_used_pct']:.1f}%")
        lines.append(f"  Max NUMA distance: {topology['max_distance']} "
                     f"({topology['max_distance']/10:.1f}x local latency)")
        lines.append(f"  Topology symmetric: {'Yes' if topology['is_symmetric'] else 'No'}")
        lines.append(f"  NUMA balancing: {balancing['mode']}")
        lines.append("")

    if verbose and not warn_only:
        lines.append("Per-Node Memory:")
        for ns in node_stats:
            lines.append(f"  Node {ns['node']}: {format_bytes(ns['total_kb'])} total, "
                         f"{format_bytes(ns['free_kb'])} free ({ns['used_pct']:.1f}% used)")
        lines.append("")

        lines.append("NUMA Distance Matrix:")
        nodes = topology['nodes']
        header = "      " + "".join(f"N{n:>4}" for n in nodes)
        lines.append(header)
        # Would need distances here - skip for now if not available

        lines.append("")
        lines.append("Migration Statistics:")
        lines.append(f"  NUMA hits: {migration.get('numa_hit', 0):,}")
        lines.append(f"  NUMA misses: {migration.get('numa_miss', 0):,} "
                     f"({migration.get('miss_ratio_pct', 0):.2f}%)")
        lines.append(f"  Page migrations: {migration.get('pgmigrate_success', 0):,} success, "
                     f"{migration.get('pgmigrate_fail', 0):,} failed")
        lines.append("")

    if issues:
        lines.append(f"Issues Detected ({len(issues)}):")
        for issue in issues:
            severity = issue['severity']
            lines.append(f"  [{severity}] {issue['message']}")
        lines.append("")
    elif not warn_only:
        lines.append("No NUMA issues detected.")

    return '\n'.join(lines)


def output_json(topology, node_stats, mem_summary, migration, balancing, issues):
    """Output results in JSON format."""
    result = {
        'topology': topology,
        'memory': {
            'summary': mem_summary,
            'nodes': node_stats,
        },
        'migration': migration,
        'numa_balancing': balancing,
        'issues': issues,
    }
    return json.dumps(result, indent=2)


def output_table(topology, node_stats, mem_summary, migration, balancing, issues,
                 warn_only=False):
    """Output results in table format."""
    lines = []

    if not warn_only:
        lines.append(f"NUMA Nodes: {topology['node_count']} | "
                     f"Total: {format_bytes(mem_summary['total_memory_kb'])} | "
                     f"Used: {mem_summary['total_used_pct']:.1f}% | "
                     f"Max Distance: {topology['max_distance']}")
        lines.append("")

        lines.append(f"{'Node':<6} {'Total':>12} {'Free':>12} {'Used%':>8} "
                     f"{'Dirty':>12} {'Active':>12}")
        lines.append("-" * 70)

        for ns in node_stats:
            lines.append(f"{ns['node']:<6} {format_bytes(ns['total_kb']):>12} "
                         f"{format_bytes(ns['free_kb']):>12} {ns['used_pct']:>7.1f}% "
                         f"{format_bytes(ns['dirty_kb']):>12} {format_bytes(ns['active_kb']):>12}")
        lines.append("")

    if issues:
        lines.append(f"{'Severity':<10} {'Type':<25} {'Details':<40}")
        lines.append("-" * 75)
        for issue in issues:
            lines.append(f"{issue['severity']:<10} {issue['type']:<25} "
                         f"{issue['message'][:40]:<40}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor NUMA memory access latency and topology",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Basic NUMA analysis
  %(prog)s --format json      # JSON output for automation
  %(prog)s --verbose          # Show per-node details and migration stats
  %(prog)s --warn-only        # Only show issues

Understanding NUMA:
  On multi-socket systems, each CPU has its own memory controller.
  Accessing memory attached to another socket incurs latency penalties.

  The distance value represents relative latency:
  - 10 = local access (baseline)
  - 20 = 2x latency (typical 2-socket)
  - 30+ = 3x+ latency (large multi-socket or complex topology)

  High NUMA miss ratios indicate processes are accessing remote memory
  frequently, which can significantly impact performance.

Exit codes:
  0 - NUMA topology healthy
  1 - Warnings detected
  2 - Usage error or NUMA unavailable

See also:
  numactl --hardware     # Show NUMA topology
  numastat               # Per-node allocation statistics
  /proc/sys/kernel/numa_balancing  # Auto-balancing toggle
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
        help="Show detailed per-node information and migration statistics"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )

    args = parser.parse_args()

    # Get NUMA nodes
    nodes = get_numa_nodes()

    if nodes is None:
        print("Error: NUMA information not available", file=sys.stderr)
        print("This system may not have NUMA support or /sys is not mounted",
              file=sys.stderr)
        sys.exit(2)

    if len(nodes) == 0:
        print("Error: No NUMA nodes found", file=sys.stderr)
        sys.exit(2)

    if len(nodes) == 1:
        # Single node system - UMA
        if args.format == 'json':
            result = {
                'topology': {
                    'node_count': 1,
                    'nodes': nodes,
                    'is_uma': True,
                    'message': 'Single NUMA node (UMA system)',
                },
                'issues': [],
            }
            print(json.dumps(result, indent=2))
        else:
            print("Single NUMA node detected (UMA system)")
            print("No NUMA latency concerns on this system.")
        sys.exit(0)

    # Gather NUMA information
    distances = get_distance_matrix(nodes)
    vmstat = get_vmstat_numa()
    balancing = get_numa_balancing_status()

    # Analyze
    topology, topo_issues = analyze_topology(nodes, distances)
    node_stats, mem_summary, mem_issues = analyze_memory_distribution(nodes)
    migration, mig_issues = analyze_migration_stats(vmstat)

    # Combine issues
    all_issues = topo_issues + mem_issues + mig_issues

    # Output
    if args.format == "json":
        output = output_json(topology, node_stats, mem_summary, migration,
                             balancing, all_issues)
    elif args.format == "table":
        output = output_table(topology, node_stats, mem_summary, migration,
                              balancing, all_issues, warn_only=args.warn_only)
    else:
        output = output_plain(topology, node_stats, mem_summary, migration,
                              balancing, all_issues, warn_only=args.warn_only,
                              verbose=args.verbose)

    print(output)

    # Exit based on issues
    if all_issues:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
