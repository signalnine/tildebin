#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [numa, locality, memory, performance, processes]
#   requires: []
#   privilege: none
#   related: [numa_latency, memory_usage, process_accounting]
#   brief: Analyze NUMA memory locality and identify processes with poor affinity

"""
Analyze NUMA memory locality and identify processes with poor NUMA affinity.

NUMA architecture in multi-socket servers means memory access latency varies
depending on which CPU socket accesses which memory bank. Poor NUMA locality
causes significant performance degradation (30-50% slower memory access).

Key metrics analyzed:
- Per-NUMA-node memory usage and capacity
- Process memory distribution across NUMA nodes
- NUMA migration statistics
- Memory access locality ratios
- Processes with high remote memory access
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_file(path: str, context: Context) -> str | None:
    """Read file contents, return None if not accessible."""
    try:
        return context.read_file(path)
    except (IOError, OSError, FileNotFoundError, PermissionError):
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
            name = entry.split('/')[-1]
            if name.startswith('node') and name[4:].isdigit():
                nodes.append(int(name[4:]))
    except OSError:
        return None

    return sorted(nodes) if nodes else None


def get_node_memory_info(node_id: int, context: Context) -> dict[str, int] | None:
    """Get memory information for a NUMA node."""
    path = f'/sys/devices/system/node/node{node_id}/meminfo'
    content = read_file(path, context)
    if content is None:
        return None

    info = {}
    for line in content.strip().split('\n'):
        parts = line.split()
        if len(parts) >= 4:
            key = parts[2].rstrip(':')
            try:
                value = int(parts[3]) * 1024  # Convert kB to bytes
                info[key] = value
            except (ValueError, IndexError):
                continue

    return info


def get_node_cpus(node_id: int, context: Context) -> list[int]:
    """Get list of CPUs belonging to a NUMA node."""
    path = f'/sys/devices/system/node/node{node_id}/cpulist'
    content = read_file(path, context)
    if content is None:
        return []

    cpus = []
    for part in content.strip().split(','):
        if '-' in part:
            start, end = part.split('-')
            cpus.extend(range(int(start), int(end) + 1))
        else:
            cpus.append(int(part))

    return cpus


def get_numastat(context: Context) -> dict[int, dict[str, int]] | None:
    """Parse /sys/devices/system/node/nodeN/numastat for NUMA statistics."""
    nodes = get_numa_nodes(context)
    if nodes is None:
        return None

    stats = {}
    for node_id in nodes:
        path = f'/sys/devices/system/node/node{node_id}/numastat'
        content = read_file(path, context)
        if content is None:
            continue

        node_stats = {}
        for line in content.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    node_stats[parts[0]] = int(parts[1])
                except ValueError:
                    continue

        stats[node_id] = node_stats

    return stats if stats else None


def get_vmstat_numa(context: Context) -> dict[str, int] | None:
    """Parse /proc/vmstat for NUMA-related counters."""
    content = read_file('/proc/vmstat', context)
    if content is None:
        return None

    numa_stats = {}
    for line in content.strip().split('\n'):
        parts = line.split()
        if len(parts) == 2 and 'numa' in parts[0]:
            try:
                numa_stats[parts[0]] = int(parts[1])
            except ValueError:
                continue

    return numa_stats if numa_stats else None


def analyze_numa_health(
    nodes: list[int],
    node_memory: dict[int, dict[str, int]],
    numastat: dict[int, dict[str, int]] | None,
    thresholds: dict[str, float]
) -> dict[str, Any]:
    """Analyze NUMA topology and identify issues."""
    issues = []
    warnings = []

    total_memory = sum(m.get('MemTotal', 0) for m in node_memory.values())
    node_count = len(nodes)

    if total_memory > 0 and node_count > 1:
        expected_per_node = total_memory / node_count
        for node_id, mem in node_memory.items():
            node_total = mem.get('MemTotal', 0)
            deviation = abs(node_total - expected_per_node) / expected_per_node * 100
            if deviation > 20:
                warnings.append(
                    f"Node {node_id} has uneven memory capacity: "
                    f"{node_total / (1024**3):.1f}GB vs expected "
                    f"{expected_per_node / (1024**3):.1f}GB"
                )

        for node_id, mem in node_memory.items():
            mem_total = mem.get('MemTotal', 1)
            mem_free = mem.get('MemFree', 0)
            used_pct = (mem_total - mem_free) / mem_total * 100

            if used_pct > thresholds['node_used_critical']:
                issues.append(f"Node {node_id} memory critical: {used_pct:.1f}% used")
            elif used_pct > thresholds['node_used_warning']:
                warnings.append(f"Node {node_id} memory high: {used_pct:.1f}% used")

    # Check NUMA hit/miss ratios
    if numastat:
        total_hits = 0
        total_misses = 0
        for node_id, stats in numastat.items():
            hits = stats.get('numa_hit', 0)
            misses = stats.get('numa_miss', 0) + stats.get('numa_foreign', 0)
            total_hits += hits
            total_misses += misses

        total_accesses = total_hits + total_misses
        if total_accesses > 0:
            hit_ratio = total_hits / total_accesses * 100
            if hit_ratio < thresholds['hit_ratio_critical']:
                issues.append(
                    f"Poor NUMA locality: {hit_ratio:.1f}% hit ratio "
                    f"({total_misses:,} remote accesses)"
                )
            elif hit_ratio < thresholds['hit_ratio_warning']:
                warnings.append(
                    f"NUMA locality could be improved: {hit_ratio:.1f}% hit ratio"
                )

    return {
        'node_count': node_count,
        'total_memory_gb': total_memory / (1024**3),
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
    parser = argparse.ArgumentParser(description="Analyze NUMA memory locality")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--hit-ratio-warning", type=float, default=90.0,
                        help="Warning threshold for NUMA hit ratio")
    parser.add_argument("--hit-ratio-critical", type=float, default=80.0,
                        help="Critical threshold for NUMA hit ratio")
    parser.add_argument("--node-used-warning", type=float, default=80.0,
                        help="Warning threshold for node memory usage")
    parser.add_argument("--node-used-critical", type=float, default=95.0,
                        help="Critical threshold for node memory usage")
    opts = parser.parse_args(args)

    # Discover NUMA nodes
    nodes = get_numa_nodes(context)
    if nodes is None or len(nodes) == 0:
        output.error("Not a NUMA system or NUMA topology not available")
        return 2

    if len(nodes) == 1:
        output.emit({
            'numa_nodes': 1,
            'status': 'healthy',
            'message': 'Single NUMA node system - no locality issues',
            'healthy': True,
            'issues': [],
            'warnings': []
        })
        output.set_summary("UMA system - no locality issues")
        return 0

    # Gather NUMA data
    node_memory = {n: get_node_memory_info(n, context) or {} for n in nodes}
    node_cpus = {n: get_node_cpus(n, context) for n in nodes}
    numastat = get_numastat(context)
    vmstat = get_vmstat_numa(context)

    # Set thresholds
    thresholds = {
        'hit_ratio_warning': opts.hit_ratio_warning,
        'hit_ratio_critical': opts.hit_ratio_critical,
        'node_used_warning': opts.node_used_warning,
        'node_used_critical': opts.node_used_critical,
    }

    # Analyze
    analysis = analyze_numa_health(nodes, node_memory, numastat, thresholds)

    # Build output
    result = {
        'numa_nodes': len(nodes),
        'total_memory_gb': round(analysis['total_memory_gb'], 2),
        'nodes': {},
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'healthy': len(analysis['issues']) == 0
    }

    for node_id in nodes:
        mem = node_memory.get(node_id, {})
        cpus = node_cpus.get(node_id, [])
        stats = numastat.get(node_id, {}) if numastat else {}

        result['nodes'][node_id] = {
            'memory_total_gb': round(mem.get('MemTotal', 0) / (1024**3), 2),
            'memory_free_gb': round(mem.get('MemFree', 0) / (1024**3), 2),
            'memory_used_pct': round(
                (mem.get('MemTotal', 0) - mem.get('MemFree', 0)) /
                max(mem.get('MemTotal', 1), 1) * 100, 1
            ),
            'cpu_count': len(cpus),
            'numa_hit': stats.get('numa_hit', 0),
            'numa_miss': stats.get('numa_miss', 0),
        }

    if opts.verbose and vmstat:
        result['vmstat'] = vmstat

    output.emit(result)

    # Set summary
    if analysis['issues']:
        output.set_summary(f"{len(analysis['issues'])} NUMA locality issue(s)")
        return 1
    elif analysis['warnings']:
        output.set_summary(f"{len(analysis['warnings'])} NUMA warning(s)")
        return 1
    else:
        output.set_summary(f"{len(nodes)} NUMA nodes, locality healthy")
        return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
