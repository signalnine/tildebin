#!/usr/bin/env python3
"""
Analyze NUMA topology and memory locality on baremetal systems.

Examines Non-Uniform Memory Access (NUMA) configuration to identify:
- NUMA node topology and CPU assignments
- Memory distribution across NUMA nodes
- Local vs remote memory access patterns
- NUMA balancing effectiveness
- Potential performance issues from cross-node memory access

Critical for:
- Database servers (PostgreSQL, MySQL) - memory locality affects query performance
- Virtualization hosts (KVM/QEMU) - VM placement and memory pinning
- High-performance computing - memory bandwidth optimization
- Latency-sensitive applications - reducing memory access times
- Large memory systems (>64GB) - avoiding NUMA penalties

Key metrics:
- Memory per NUMA node and utilization
- CPU-to-node mapping
- NUMA hit/miss statistics (local vs remote memory access)
- Memory migration and balancing activity
- Inter-node distance (memory access latency indicator)

Exit codes:
    0 - NUMA topology healthy, good memory locality
    1 - Warnings detected (imbalance, high remote access, etc.)
    2 - Usage error or NUMA info unavailable
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def read_file(path):
    """Read a file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError, PermissionError):
        return None


def parse_memory_info(meminfo_str):
    """Parse meminfo-style output into dict of values in bytes."""
    result = {}
    if not meminfo_str:
        return result

    for line in meminfo_str.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            # Parse value (typically "12345 kB")
            parts = value.split()
            if parts:
                try:
                    num = int(parts[0])
                    if len(parts) > 1 and parts[1].lower() == 'kb':
                        num *= 1024
                    result[key] = num
                except ValueError:
                    result[key] = value
    return result


def get_numa_nodes():
    """Get list of NUMA nodes from sysfs."""
    nodes = []
    numa_path = '/sys/devices/system/node'

    if not os.path.isdir(numa_path):
        return None, "NUMA sysfs not available"

    try:
        for entry in os.listdir(numa_path):
            if entry.startswith('node') and entry[4:].isdigit():
                nodes.append(int(entry[4:]))
    except OSError as e:
        return None, f"Cannot read NUMA nodes: {e}"

    if not nodes:
        return None, "No NUMA nodes found"

    return sorted(nodes), None


def get_node_cpus(node_id):
    """Get CPUs assigned to a NUMA node."""
    cpulist_path = f'/sys/devices/system/node/node{node_id}/cpulist'
    cpulist = read_file(cpulist_path)

    if not cpulist:
        return []

    cpus = []
    for part in cpulist.split(','):
        if '-' in part:
            start, end = part.split('-')
            cpus.extend(range(int(start), int(end) + 1))
        else:
            cpus.append(int(part))
    return cpus


def get_node_memory(node_id):
    """Get memory info for a NUMA node."""
    meminfo_path = f'/sys/devices/system/node/node{node_id}/meminfo'
    meminfo_str = read_file(meminfo_path)

    if not meminfo_str:
        return {}

    result = {}
    for line in meminfo_str.split('\n'):
        # Format: "Node 0 MemTotal:       32767436 kB"
        if ':' in line:
            # Remove "Node X " prefix
            parts = line.split(':')
            if len(parts) >= 2:
                key = parts[0].split()[-1]  # Get last word before ':'
                value_parts = parts[1].strip().split()
                if value_parts:
                    try:
                        num = int(value_parts[0])
                        if len(value_parts) > 1 and value_parts[1].lower() == 'kb':
                            num *= 1024
                        result[key] = num
                    except ValueError:
                        pass
    return result


def get_numa_stats(node_id):
    """Get NUMA statistics for a node (hit/miss counters)."""
    stats_path = f'/sys/devices/system/node/node{node_id}/numastat'
    stats_str = read_file(stats_path)

    if not stats_str:
        return {}

    result = {}
    for line in stats_str.split('\n'):
        parts = line.split()
        if len(parts) >= 2:
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return result


def get_node_distances():
    """Get NUMA node distance matrix."""
    distances = {}
    numa_path = '/sys/devices/system/node'

    try:
        for entry in os.listdir(numa_path):
            if entry.startswith('node') and entry[4:].isdigit():
                node_id = int(entry[4:])
                dist_path = os.path.join(numa_path, entry, 'distance')
                dist_str = read_file(dist_path)
                if dist_str:
                    distances[node_id] = [int(d) for d in dist_str.split()]
    except OSError:
        pass

    return distances


def get_numa_balancing_status():
    """Get NUMA balancing (AutoNUMA) status."""
    enabled = read_file('/proc/sys/kernel/numa_balancing')

    vmstat = read_file('/proc/vmstat')
    stats = {}
    if vmstat:
        for line in vmstat.split('\n'):
            if line.startswith('numa_'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        stats[parts[0]] = int(parts[1])
                    except ValueError:
                        pass

    return {
        'enabled': enabled == '1' if enabled else None,
        'stats': stats,
    }


def bytes_to_human(num_bytes):
    """Convert bytes to human-readable format."""
    if num_bytes is None:
        return "N/A"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def analyze_numa_topology(nodes, node_data, distances, balancing):
    """Analyze NUMA topology and return findings."""
    issues = []
    warnings = []
    info_msgs = []

    if len(nodes) == 1:
        info_msgs.append("Single NUMA node - no cross-node memory access concerns")
        return {
            'status': 'healthy',
            'issues': issues,
            'warnings': warnings,
            'info': info_msgs,
        }

    info_msgs.append(f"Multi-NUMA system with {len(nodes)} nodes")

    # Check memory distribution
    total_mem = 0
    node_mems = []
    for node_id in nodes:
        mem = node_data[node_id].get('memory', {}).get('MemTotal', 0)
        node_mems.append(mem)
        total_mem += mem

    if total_mem > 0 and node_mems:
        avg_mem = total_mem / len(nodes)
        for i, node_id in enumerate(nodes):
            deviation = abs(node_mems[i] - avg_mem) / avg_mem * 100
            if deviation > 20:
                warnings.append(
                    f"Node {node_id} memory ({bytes_to_human(node_mems[i])}) "
                    f"differs {deviation:.0f}% from average"
                )

    # Check CPU distribution
    total_cpus = 0
    for node_id in nodes:
        cpus = len(node_data[node_id].get('cpus', []))
        total_cpus += cpus

    if total_cpus > 0:
        avg_cpus = total_cpus / len(nodes)
        for node_id in nodes:
            cpus = len(node_data[node_id].get('cpus', []))
            if cpus > 0:
                deviation = abs(cpus - avg_cpus) / avg_cpus * 100
                if deviation > 30:
                    warnings.append(
                        f"Node {node_id} has {cpus} CPUs - "
                        f"{deviation:.0f}% deviation from average ({avg_cpus:.0f})"
                    )

    # Analyze NUMA hit/miss ratios
    for node_id in nodes:
        stats = node_data[node_id].get('stats', {})
        hits = stats.get('numa_hit', 0)
        misses = stats.get('numa_miss', 0)
        foreign = stats.get('numa_foreign', 0)

        total_accesses = hits + misses
        if total_accesses > 10000:  # Only analyze if significant activity
            miss_ratio = misses / total_accesses * 100
            if miss_ratio > 30:
                issues.append(
                    f"Node {node_id}: High NUMA miss ratio ({miss_ratio:.1f}%) - "
                    f"significant cross-node memory access"
                )
            elif miss_ratio > 10:
                warnings.append(
                    f"Node {node_id}: Elevated NUMA miss ratio ({miss_ratio:.1f}%)"
                )

        if foreign > misses * 1.5 and foreign > 10000:
            warnings.append(
                f"Node {node_id}: High foreign allocations ({foreign}) - "
                "memory being allocated for remote nodes"
            )

    # Check NUMA distances
    if distances:
        for src_node, dists in distances.items():
            for dst_idx, dist in enumerate(dists):
                if dst_idx != src_node and dist > 20:
                    info_msgs.append(
                        f"Node {src_node} to Node {dst_idx} distance: {dist} "
                        "(higher = more latency)"
                    )

    # Check NUMA balancing
    if balancing['enabled'] is False:
        warnings.append(
            "NUMA balancing (AutoNUMA) is disabled - "
            "memory may not be automatically migrated for locality"
        )
    elif balancing['enabled'] is True:
        info_msgs.append("NUMA balancing (AutoNUMA) is enabled")
        # Check migration activity
        stats = balancing.get('stats', {})
        pages_migrated = stats.get('numa_pages_migrated', 0)
        if pages_migrated > 1000000:
            warnings.append(
                f"High NUMA page migration activity ({pages_migrated} pages) - "
                "consider pinning workloads to NUMA nodes"
            )

    # Determine overall status
    if issues:
        status = 'critical'
    elif warnings:
        status = 'warning'
    else:
        status = 'healthy'

    return {
        'status': status,
        'issues': issues,
        'warnings': warnings,
        'info': info_msgs,
    }


def format_plain(nodes, node_data, distances, balancing, analysis, verbose=False):
    """Format output as plain text."""
    lines = []

    lines.append("NUMA Topology Analyzer")
    lines.append("=" * 50)
    lines.append("")

    # Overview
    lines.append(f"NUMA Nodes: {len(nodes)}")
    total_cpus = sum(len(node_data[n].get('cpus', [])) for n in nodes)
    total_mem = sum(node_data[n].get('memory', {}).get('MemTotal', 0) for n in nodes)
    lines.append(f"Total CPUs: {total_cpus}")
    lines.append(f"Total Memory: {bytes_to_human(total_mem)}")
    lines.append("")

    # Per-node info
    for node_id in nodes:
        data = node_data[node_id]
        cpus = data.get('cpus', [])
        mem = data.get('memory', {})
        stats = data.get('stats', {})

        lines.append(f"Node {node_id}:")
        lines.append(f"  CPUs: {len(cpus)} ({','.join(map(str, cpus[:8]))}{'...' if len(cpus) > 8 else ''})")

        mem_total = mem.get('MemTotal', 0)
        mem_free = mem.get('MemFree', 0)
        mem_used = mem_total - mem_free if mem_total and mem_free else 0
        lines.append(f"  Memory: {bytes_to_human(mem_total)} total, {bytes_to_human(mem_used)} used")

        if verbose and stats:
            hits = stats.get('numa_hit', 0)
            misses = stats.get('numa_miss', 0)
            if hits + misses > 0:
                hit_ratio = hits / (hits + misses) * 100
                lines.append(f"  NUMA hit ratio: {hit_ratio:.1f}% ({hits} hits, {misses} misses)")

        lines.append("")

    # NUMA distances
    if verbose and distances and len(nodes) > 1:
        lines.append("NUMA Distances:")
        header = "     " + " ".join(f"{n:>4}" for n in sorted(distances.keys()))
        lines.append(header)
        for src in sorted(distances.keys()):
            row = f"{src:>4} " + " ".join(f"{d:>4}" for d in distances[src])
            lines.append(row)
        lines.append("")

    # NUMA balancing status
    if balancing['enabled'] is not None:
        status = "enabled" if balancing['enabled'] else "disabled"
        lines.append(f"NUMA Balancing (AutoNUMA): {status}")
        if verbose and balancing['stats']:
            migrated = balancing['stats'].get('numa_pages_migrated', 0)
            if migrated > 0:
                lines.append(f"  Pages migrated: {migrated}")
        lines.append("")

    # Analysis results
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

    if verbose and analysis['info']:
        lines.append("INFO:")
        for info in analysis['info']:
            lines.append(f"  [i] {info}")
        lines.append("")

    # Summary
    if not analysis['issues'] and not analysis['warnings']:
        lines.append("[OK] NUMA topology is healthy")

    return "\n".join(lines)


def format_json(nodes, node_data, distances, balancing, analysis):
    """Format output as JSON."""
    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'numa_nodes': len(nodes),
        'nodes': {},
        'distances': distances,
        'balancing': balancing,
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'info': analysis['info'],
        'healthy': analysis['status'] == 'healthy',
    }

    for node_id in nodes:
        data = node_data[node_id]
        output['nodes'][str(node_id)] = {
            'cpus': data.get('cpus', []),
            'cpu_count': len(data.get('cpus', [])),
            'memory': data.get('memory', {}),
            'stats': data.get('stats', {}),
        }

    return json.dumps(output, indent=2)


def format_table(nodes, node_data, analysis):
    """Format output as table."""
    lines = []

    lines.append("+" + "-" * 62 + "+")
    lines.append("| NUMA Topology Analyzer" + " " * 39 + "|")
    lines.append("+" + "-" * 62 + "+")

    lines.append(f"| {'Node':<6} | {'CPUs':<8} | {'Memory':<14} | {'Used':<14} | {'Hit %':<8} |")
    lines.append("+" + "-" * 62 + "+")

    for node_id in nodes:
        data = node_data[node_id]
        cpus = len(data.get('cpus', []))
        mem = data.get('memory', {})
        stats = data.get('stats', {})

        mem_total = bytes_to_human(mem.get('MemTotal', 0))
        mem_free = mem.get('MemFree', 0)
        mem_total_raw = mem.get('MemTotal', 0)
        mem_used = bytes_to_human(mem_total_raw - mem_free) if mem_total_raw and mem_free else "N/A"

        hits = stats.get('numa_hit', 0)
        misses = stats.get('numa_miss', 0)
        if hits + misses > 0:
            hit_ratio = f"{hits / (hits + misses) * 100:.1f}%"
        else:
            hit_ratio = "N/A"

        lines.append(f"| {node_id:<6} | {cpus:<8} | {mem_total:<14} | {mem_used:<14} | {hit_ratio:<8} |")

    lines.append("+" + "-" * 62 + "+")

    status_str = analysis['status'].upper()
    issue_count = len(analysis['issues']) + len(analysis['warnings'])
    if issue_count > 0:
        status_line = f"Status: {status_str} ({issue_count} finding(s))"
    else:
        status_line = f"Status: {status_str}"
    lines.append(f"| {status_line:<60} |")
    lines.append("+" + "-" * 62 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze NUMA topology and memory locality',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Basic NUMA topology check
  %(prog)s --format json        # JSON output for monitoring systems
  %(prog)s --verbose            # Detailed per-node statistics
  %(prog)s --warn-only          # Only show warnings and errors

NUMA Concepts:
  NUMA node    - Memory region with local CPUs (fast access)
  NUMA hit     - Memory allocated from local node (optimal)
  NUMA miss    - Memory accessed from remote node (slower)
  NUMA foreign - Memory allocated for a remote node's request
  Distance     - Relative memory access latency (10 = local, higher = slower)

Why NUMA Matters:
  - Remote memory access can be 1.5-3x slower than local
  - Database performance heavily depends on memory locality
  - VMs should be pinned to NUMA nodes for consistent performance
  - High miss ratios indicate workloads crossing NUMA boundaries

Exit codes:
  0 - NUMA topology healthy, good memory locality
  1 - Warnings detected (imbalance, high remote access, etc.)
  2 - Usage error or NUMA info unavailable
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including NUMA distances and statistics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if warnings or issues detected'
    )

    args = parser.parse_args()

    # Get NUMA nodes
    nodes, error = get_numa_nodes()
    if nodes is None:
        print(f"Error: {error}", file=sys.stderr)
        print("NUMA may not be available on this system", file=sys.stderr)
        sys.exit(2)

    # Gather per-node data
    node_data = {}
    for node_id in nodes:
        node_data[node_id] = {
            'cpus': get_node_cpus(node_id),
            'memory': get_node_memory(node_id),
            'stats': get_numa_stats(node_id),
        }

    # Get additional info
    distances = get_node_distances()
    balancing = get_numa_balancing_status()

    # Analyze
    analysis = analyze_numa_topology(nodes, node_data, distances, balancing)

    # Check if we should output (respecting --warn-only)
    has_findings = analysis['issues'] or analysis['warnings']
    if args.warn_only and not has_findings:
        sys.exit(0)

    # Format and output
    if args.format == 'json':
        output = format_json(nodes, node_data, distances, balancing, analysis)
    elif args.format == 'table':
        output = format_table(nodes, node_data, analysis)
    else:
        output = format_plain(nodes, node_data, distances, balancing, analysis, args.verbose)

    print(output)

    # Exit code based on findings
    if analysis['issues']:
        sys.exit(1)
    elif analysis['warnings']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
