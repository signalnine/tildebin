#!/usr/bin/env python3
"""
Analyze NUMA memory locality and identify processes with poor NUMA affinity.

NUMA (Non-Uniform Memory Access) architecture in multi-socket servers means
memory access latency varies depending on which CPU socket accesses which
memory bank. Poor NUMA locality causes significant performance degradation
(30-50% slower memory access for remote NUMA nodes).

Key metrics analyzed:
- Per-NUMA-node memory usage and capacity
- Process memory distribution across NUMA nodes
- NUMA migration statistics (page migrations between nodes)
- Memory access locality ratios
- Processes with high remote memory access

Useful for:
- Performance tuning on multi-socket baremetal servers
- Identifying workloads that need NUMA pinning
- Capacity planning across NUMA nodes
- Detecting memory imbalance before it causes problems
- Optimizing VM and container placement

Exit codes:
    0 - NUMA topology healthy, good locality
    1 - NUMA locality issues detected (imbalance, high remote access)
    2 - Usage error, not a NUMA system, or unable to read NUMA stats
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def read_file(path):
    """Read file contents, return None if not accessible."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError):
        return None


def get_numa_nodes():
    """
    Discover NUMA nodes from /sys/devices/system/node/.

    Returns list of node IDs (integers) or None if not a NUMA system.
    """
    node_path = '/sys/devices/system/node'
    if not os.path.isdir(node_path):
        return None

    nodes = []
    try:
        for entry in os.listdir(node_path):
            if entry.startswith('node') and entry[4:].isdigit():
                nodes.append(int(entry[4:]))
    except OSError:
        return None

    return sorted(nodes) if nodes else None


def get_node_memory_info(node_id):
    """
    Get memory information for a NUMA node from /sys/devices/system/node/nodeN/meminfo.

    Returns dict with memory stats in bytes.
    """
    path = f'/sys/devices/system/node/node{node_id}/meminfo'
    content = read_file(path)
    if content is None:
        return None

    info = {}
    for line in content.strip().split('\n'):
        parts = line.split()
        if len(parts) >= 4:
            # Format: "Node X KeyName: VALUE kB"
            key = parts[2].rstrip(':')
            try:
                # Convert from kB to bytes
                value = int(parts[3]) * 1024
                info[key] = value
            except (ValueError, IndexError):
                continue

    return info


def get_node_cpus(node_id):
    """Get list of CPUs belonging to a NUMA node."""
    path = f'/sys/devices/system/node/node{node_id}/cpulist'
    content = read_file(path)
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


def get_numastat():
    """
    Parse /sys/devices/system/node/nodeN/numastat for NUMA hit/miss statistics.

    Returns dict with per-node statistics.
    """
    nodes = get_numa_nodes()
    if nodes is None:
        return None

    stats = {}
    for node_id in nodes:
        path = f'/sys/devices/system/node/node{node_id}/numastat'
        content = read_file(path)
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


def get_vmstat_numa():
    """Parse /proc/vmstat for NUMA-related counters."""
    content = read_file('/proc/vmstat')
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


def get_process_numa_maps(pid):
    """
    Parse /proc/PID/numa_maps for process memory distribution.

    Returns dict with memory on each NUMA node.
    """
    path = f'/proc/{pid}/numa_maps'
    content = read_file(path)
    if content is None:
        return None

    node_pages = {}
    total_pages = 0

    for line in content.strip().split('\n'):
        parts = line.split()
        for part in parts:
            # Look for N0=123 N1=456 patterns
            if part.startswith('N') and '=' in part:
                try:
                    node_str, pages_str = part.split('=')
                    node_id = int(node_str[1:])
                    pages = int(pages_str)
                    node_pages[node_id] = node_pages.get(node_id, 0) + pages
                    total_pages += pages
                except ValueError:
                    continue

    return {
        'node_pages': node_pages,
        'total_pages': total_pages
    } if node_pages else None


def get_process_info(pid):
    """Get basic process info (name, command line)."""
    comm = read_file(f'/proc/{pid}/comm')
    cmdline = read_file(f'/proc/{pid}/cmdline')

    name = comm.strip() if comm else 'unknown'
    cmd = cmdline.replace('\x00', ' ').strip() if cmdline else ''

    return {
        'pid': pid,
        'name': name,
        'cmdline': cmd[:100]  # Truncate for readability
    }


def find_processes_with_numa_spread():
    """
    Find processes with memory spread across multiple NUMA nodes.

    Returns list of processes with their NUMA memory distribution.
    """
    processes = []

    try:
        pids = [int(p) for p in os.listdir('/proc') if p.isdigit()]
    except OSError:
        return processes

    for pid in pids:
        numa_info = get_process_numa_maps(pid)
        if numa_info is None:
            continue

        node_pages = numa_info['node_pages']
        total_pages = numa_info['total_pages']

        # Skip processes with minimal memory
        if total_pages < 256:  # Less than 1MB (assuming 4KB pages)
            continue

        # Check if memory is spread across nodes
        if len(node_pages) > 1:
            proc_info = get_process_info(pid)
            proc_info['node_pages'] = node_pages
            proc_info['total_pages'] = total_pages
            proc_info['total_mb'] = (total_pages * 4096) / (1024 * 1024)

            # Calculate locality ratio (memory on primary node / total)
            max_node_pages = max(node_pages.values())
            proc_info['locality_ratio'] = max_node_pages / total_pages
            proc_info['primary_node'] = max(node_pages.items(), key=lambda x: x[1])[0]

            processes.append(proc_info)

    # Sort by worst locality
    processes.sort(key=lambda x: x['locality_ratio'])

    return processes


def analyze_numa_health(nodes, node_memory, numastat, vmstat, processes, thresholds):
    """Analyze NUMA topology and identify issues."""
    issues = []
    warnings = []

    # Check memory balance across nodes
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

        # Check memory usage balance
        for node_id, mem in node_memory.items():
            mem_total = mem.get('MemTotal', 1)
            mem_free = mem.get('MemFree', 0)
            used_pct = (mem_total - mem_free) / mem_total * 100

            if used_pct > thresholds['node_used_critical']:
                issues.append(
                    f"Node {node_id} memory critical: {used_pct:.1f}% used"
                )
            elif used_pct > thresholds['node_used_warning']:
                warnings.append(
                    f"Node {node_id} memory high: {used_pct:.1f}% used"
                )

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

    # Check for processes with poor locality
    poor_locality_procs = [p for p in processes if p['locality_ratio'] < thresholds['proc_locality_warning']]
    if poor_locality_procs:
        worst = poor_locality_procs[0]
        if worst['locality_ratio'] < thresholds['proc_locality_critical']:
            issues.append(
                f"Process '{worst['name']}' (PID {worst['pid']}) has poor NUMA locality: "
                f"{worst['locality_ratio']*100:.0f}% on primary node"
            )
        else:
            warnings.append(
                f"{len(poor_locality_procs)} processes with memory spread across NUMA nodes"
            )

    # Check vmstat for NUMA migrations
    if vmstat:
        migrations = vmstat.get('numa_pages_migrated', 0)
        if migrations > thresholds['migrations_warning']:
            warnings.append(
                f"High NUMA page migrations: {migrations:,} pages migrated"
            )

    return {
        'node_count': node_count,
        'total_memory_gb': total_memory / (1024**3),
        'issues': issues,
        'warnings': warnings,
        'status': 'critical' if issues else ('warning' if warnings else 'healthy')
    }


def format_plain(nodes, node_memory, node_cpus, numastat, analysis, processes, verbose=False):
    """Format output as plain text."""
    lines = []

    lines.append("NUMA Locality Analyzer")
    lines.append("=" * 50)
    lines.append("")

    # Summary
    lines.append(f"NUMA Nodes: {len(nodes)}")
    lines.append(f"Total Memory: {analysis['total_memory_gb']:.1f} GB")
    lines.append("")

    # Per-node info
    lines.append("Node Memory Status:")
    for node_id in nodes:
        mem = node_memory.get(node_id, {})
        mem_total = mem.get('MemTotal', 0)
        mem_free = mem.get('MemFree', 0)
        mem_used = mem_total - mem_free
        used_pct = (mem_used / mem_total * 100) if mem_total > 0 else 0
        cpus = node_cpus.get(node_id, [])

        lines.append(f"  Node {node_id}: {mem_used/(1024**3):.1f}GB / {mem_total/(1024**3):.1f}GB "
                     f"({used_pct:.0f}% used) - CPUs: {len(cpus)}")
    lines.append("")

    # NUMA statistics
    if numastat:
        lines.append("NUMA Access Statistics:")
        for node_id in sorted(numastat.keys()):
            stats = numastat[node_id]
            hits = stats.get('numa_hit', 0)
            misses = stats.get('numa_miss', 0)
            foreign = stats.get('numa_foreign', 0)
            total = hits + misses + foreign
            hit_pct = (hits / total * 100) if total > 0 else 100

            lines.append(f"  Node {node_id}: {hit_pct:.1f}% local "
                         f"(hits: {hits:,}, miss: {misses:,}, foreign: {foreign:,})")
        lines.append("")

    # Processes with spread memory
    if verbose and processes:
        lines.append("Processes with Memory Spread Across Nodes:")
        lines.append(f"  {'PID':<8} {'NAME':<20} {'MEMORY':<10} {'LOCALITY':<10} {'DISTRIBUTION'}")
        lines.append("  " + "-" * 70)
        for proc in processes[:10]:  # Top 10 worst
            dist = ', '.join(f"N{n}:{p}" for n, p in sorted(proc['node_pages'].items()))
            lines.append(f"  {proc['pid']:<8} {proc['name'][:19]:<20} "
                         f"{proc['total_mb']:.0f}MB{'':<5} "
                         f"{proc['locality_ratio']*100:.0f}%{'':<6} {dist[:30]}")
        lines.append("")

    # Issues
    if analysis['issues']:
        lines.append("ISSUES:")
        for issue in analysis['issues']:
            lines.append(f"  [!] {issue}")
        lines.append("")

    # Warnings
    if analysis['warnings']:
        lines.append("WARNINGS:")
        for warning in analysis['warnings']:
            lines.append(f"  [*] {warning}")
        lines.append("")

    # Status
    if not analysis['issues'] and not analysis['warnings']:
        lines.append("[OK] NUMA locality healthy")

    return "\n".join(lines)


def format_json(nodes, node_memory, node_cpus, numastat, vmstat, analysis, processes):
    """Format output as JSON."""
    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
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

        output['nodes'][node_id] = {
            'memory_total_gb': round(mem.get('MemTotal', 0) / (1024**3), 2),
            'memory_free_gb': round(mem.get('MemFree', 0) / (1024**3), 2),
            'memory_used_pct': round((mem.get('MemTotal', 0) - mem.get('MemFree', 0)) /
                                     max(mem.get('MemTotal', 1), 1) * 100, 1),
            'cpu_count': len(cpus),
            'cpus': cpus,
            'numa_hit': stats.get('numa_hit', 0),
            'numa_miss': stats.get('numa_miss', 0),
            'numa_foreign': stats.get('numa_foreign', 0)
        }

    if vmstat:
        output['vmstat'] = vmstat

    if processes:
        output['spread_processes'] = [
            {
                'pid': p['pid'],
                'name': p['name'],
                'memory_mb': round(p['total_mb'], 1),
                'locality_ratio': round(p['locality_ratio'], 3),
                'primary_node': p['primary_node'],
                'node_distribution': p['node_pages']
            }
            for p in processes[:20]
        ]

    return json.dumps(output, indent=2)


def format_table(nodes, node_memory, node_cpus, numastat, analysis):
    """Format output as a table."""
    lines = []

    lines.append(f"{'NODE':<6} {'MEMORY':<15} {'USED%':<8} {'CPUs':<6} {'HIT%':<8} {'STATUS'}")
    lines.append("-" * 60)

    for node_id in nodes:
        mem = node_memory.get(node_id, {})
        mem_total = mem.get('MemTotal', 0)
        mem_free = mem.get('MemFree', 0)
        used_pct = ((mem_total - mem_free) / mem_total * 100) if mem_total > 0 else 0

        cpus = node_cpus.get(node_id, [])
        stats = numastat.get(node_id, {}) if numastat else {}

        hits = stats.get('numa_hit', 0)
        total = hits + stats.get('numa_miss', 0) + stats.get('numa_foreign', 0)
        hit_pct = (hits / total * 100) if total > 0 else 100

        status = ''
        if used_pct > 90:
            status = 'CRITICAL'
        elif used_pct > 80:
            status = 'WARNING'

        mem_str = f"{mem_total/(1024**3):.1f}GB"
        lines.append(f"{node_id:<6} {mem_str:<15} {used_pct:<7.0f}% {len(cpus):<6} "
                     f"{hit_pct:<7.0f}% {status}")

    lines.append("-" * 60)
    lines.append(f"{'TOTAL':<6} {analysis['total_memory_gb']:<14.1f}GB {'':<8} "
                 f"{sum(len(node_cpus.get(n, [])) for n in nodes):<6} {'':<8} "
                 f"{analysis['status'].upper()}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze NUMA memory locality and identify processes with poor affinity',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic NUMA topology check
  %(prog)s

  # JSON output for monitoring systems
  %(prog)s --format json

  # Verbose output with per-process details
  %(prog)s -v

  # Custom thresholds
  %(prog)s --hit-ratio-warning 95 --hit-ratio-critical 85

  # Only show output if issues detected
  %(prog)s --warn-only

NUMA Locality:
  Good NUMA locality means processes access memory on the same NUMA node
  as the CPU running them. Remote memory access can be 30-50 percent slower.

  Default hit ratio warning: 90 percent (10 percent remote accesses)
  Default hit ratio critical: 80 percent (20 percent remote accesses)

Exit codes:
  0 - NUMA topology healthy
  1 - NUMA locality issues detected
  2 - Not a NUMA system or unable to read stats
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--hit-ratio-warning',
        type=float,
        default=90.0,
        help='Warning threshold for NUMA hit ratio percent (default: 90)'
    )
    parser.add_argument(
        '--hit-ratio-critical',
        type=float,
        default=80.0,
        help='Critical threshold for NUMA hit ratio percent (default: 80)'
    )
    parser.add_argument(
        '--node-used-warning',
        type=float,
        default=80.0,
        help='Warning threshold for node memory used percent (default: 80)'
    )
    parser.add_argument(
        '--node-used-critical',
        type=float,
        default=95.0,
        help='Critical threshold for node memory used percent (default: 95)'
    )
    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed per-process NUMA distribution'
    )

    args = parser.parse_args()

    # Discover NUMA nodes
    nodes = get_numa_nodes()
    if nodes is None or len(nodes) == 0:
        print("Error: Not a NUMA system or NUMA topology not available", file=sys.stderr)
        print("Ensure /sys/devices/system/node is accessible", file=sys.stderr)
        sys.exit(2)

    if len(nodes) == 1:
        # Single NUMA node - no locality issues possible
        if args.format == 'json':
            print(json.dumps({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'numa_nodes': 1,
                'status': 'healthy',
                'message': 'Single NUMA node system - no locality issues',
                'healthy': True,
                'issues': [],
                'warnings': []
            }, indent=2))
        elif not args.warn_only:
            print("Single NUMA node system - no locality issues possible")
        sys.exit(0)

    # Gather NUMA data
    node_memory = {n: get_node_memory_info(n) or {} for n in nodes}
    node_cpus = {n: get_node_cpus(n) for n in nodes}
    numastat = get_numastat()
    vmstat = get_vmstat_numa()

    # Find processes with memory spread
    processes = find_processes_with_numa_spread()

    # Set thresholds
    thresholds = {
        'hit_ratio_warning': args.hit_ratio_warning,
        'hit_ratio_critical': args.hit_ratio_critical,
        'node_used_warning': args.node_used_warning,
        'node_used_critical': args.node_used_critical,
        'proc_locality_warning': 0.8,  # 80% on primary node
        'proc_locality_critical': 0.5,  # 50% on primary node
        'migrations_warning': 100000
    }

    # Analyze
    analysis = analyze_numa_health(nodes, node_memory, numastat, vmstat, processes, thresholds)

    # Format output
    if args.format == 'json':
        output = format_json(nodes, node_memory, node_cpus, numastat, vmstat, analysis, processes)
    elif args.format == 'table':
        output = format_table(nodes, node_memory, node_cpus, numastat, analysis)
    else:
        output = format_plain(nodes, node_memory, node_cpus, numastat, analysis, processes, args.verbose)

    # Print output (respecting --warn-only)
    if not args.warn_only or analysis['issues'] or analysis['warnings']:
        print(output)

    # Return appropriate exit code
    return 1 if analysis['issues'] else 0


if __name__ == '__main__':
    sys.exit(main())
