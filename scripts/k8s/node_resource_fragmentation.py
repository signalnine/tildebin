#!/usr/bin/env python3
# boxctl:
#   category: k8s/resources
#   tags: [nodes, fragmentation, capacity, scheduling]
#   requires: [kubectl]
#   privilege: user
#   related: [node_capacity, extended_resources_audit]
#   brief: Analyze resource fragmentation across cluster nodes

"""
Kubernetes node resource fragmentation analyzer.

Analyzes resource fragmentation on cluster nodes - identifies situations where
aggregate free resources exist but pods cannot be scheduled due to fragmented
allocations across nodes.

Helps answer: "Why can't my pod schedule when the cluster shows free capacity?"

Features:
- Identifies nodes with fragmented CPU/memory allocations
- Detects "phantom capacity" (free resources that can't fit typical pods)
- Reports fragmentation score per node
- Suggests optimal pod sizes based on available gaps

Exit codes:
    0 - No significant fragmentation detected
    1 - Fragmentation issues found
    2 - Usage error or kubectl not available
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_resource_value(value_str: str | None) -> int:
    """Parse Kubernetes resource value to base units."""
    if value_str is None:
        return 0

    value_str = str(value_str).strip()
    if not value_str:
        return 0

    # CPU millicores
    if value_str.endswith('m'):
        try:
            return int(value_str[:-1])
        except ValueError:
            return 0

    # Memory/storage units
    units = {
        'Ki': 1024,
        'Mi': 1024 ** 2,
        'Gi': 1024 ** 3,
        'Ti': 1024 ** 4,
        'Pi': 1024 ** 5,
        'K': 1000,
        'M': 1000 ** 2,
        'G': 1000 ** 3,
        'T': 1000 ** 4,
        'P': 1000 ** 5,
    }

    for unit, multiplier in sorted(units.items(), key=lambda x: len(x[0]), reverse=True):
        if value_str.endswith(unit):
            try:
                return int(float(value_str[:-len(unit)]) * multiplier)
            except ValueError:
                return 0

    # Plain number
    try:
        val = float(value_str)
        if val < 1000:
            return int(val * 1000)  # Assume cores to millicores
        return int(val)
    except ValueError:
        return 0


def format_cpu(millicores: int) -> str:
    """Format CPU millicores for display."""
    if millicores >= 1000:
        return f"{millicores / 1000:.1f} cores"
    return f"{millicores}m"


def format_memory(mem_bytes: int) -> str:
    """Format memory bytes for display."""
    if mem_bytes == 0:
        return "0"
    for unit in ['B', 'Ki', 'Mi', 'Gi', 'Ti']:
        if mem_bytes < 1024:
            return f"{mem_bytes:.1f}{unit}"
        mem_bytes //= 1024
    return f"{mem_bytes:.1f}Pi"


def get_nodes(context: Context) -> dict[str, Any]:
    """Get node information."""
    result = context.run(['kubectl', 'get', 'nodes', '-o', 'json'])
    return json.loads(result.stdout)


def get_pods(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get pod information."""
    args = ['kubectl', 'get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')
    result = context.run(args)
    return json.loads(result.stdout)


def calculate_node_allocations(nodes_data: dict, pods_data: dict) -> dict[str, dict]:
    """Calculate resource allocations per node."""
    node_info = {}

    for node in nodes_data.get('items', []):
        name = node['metadata']['name']
        allocatable = node.get('status', {}).get('allocatable', {})

        taints = node.get('spec', {}).get('taints', [])
        unschedulable = node.get('spec', {}).get('unschedulable', False)
        is_schedulable = not unschedulable

        for taint in taints:
            if taint.get('effect') == 'NoSchedule' and taint.get('key') in [
                'node.kubernetes.io/unschedulable',
                'node.kubernetes.io/not-ready',
            ]:
                is_schedulable = False
                break

        node_info[name] = {
            'cpu_allocatable': parse_resource_value(allocatable.get('cpu', '0')),
            'memory_allocatable': parse_resource_value(allocatable.get('memory', '0')),
            'pods_allocatable': int(allocatable.get('pods', '110')),
            'cpu_requested': 0,
            'memory_requested': 0,
            'pod_count': 0,
            'is_schedulable': is_schedulable,
        }

    for pod in pods_data.get('items', []):
        node_name = pod.get('spec', {}).get('nodeName')
        if not node_name or node_name not in node_info:
            continue

        phase = pod.get('status', {}).get('phase', '')
        if phase not in ['Running', 'Pending']:
            continue

        pod_cpu = 0
        pod_memory = 0

        for container in pod.get('spec', {}).get('containers', []):
            resources = container.get('resources', {})
            requests = resources.get('requests', {})
            pod_cpu += parse_resource_value(requests.get('cpu', '0'))
            pod_memory += parse_resource_value(requests.get('memory', '0'))

        node_info[node_name]['cpu_requested'] += pod_cpu
        node_info[node_name]['memory_requested'] += pod_memory
        node_info[node_name]['pod_count'] += 1

    return node_info


def calculate_fragmentation_metrics(
    node_info: dict,
    reference_pod_cpu: int,
    reference_pod_memory: int
) -> list[dict]:
    """Calculate fragmentation metrics for each node."""
    results = []

    for node_name, info in node_info.items():
        cpu_free = info['cpu_allocatable'] - info['cpu_requested']
        memory_free = info['memory_allocatable'] - info['memory_requested']
        pods_free = info['pods_allocatable'] - info['pod_count']

        # How many reference pods could fit
        if reference_pod_cpu > 0 and reference_pod_memory > 0:
            pods_by_cpu = cpu_free // reference_pod_cpu if reference_pod_cpu > 0 else 0
            pods_by_memory = memory_free // reference_pod_memory if reference_pod_memory > 0 else 0
            pods_by_count = pods_free
            schedulable_pods = min(pods_by_cpu, pods_by_memory, pods_by_count)
        else:
            schedulable_pods = 0

        cpu_free_pct = (cpu_free / info['cpu_allocatable'] * 100) if info['cpu_allocatable'] > 0 else 0
        memory_free_pct = (memory_free / info['memory_allocatable'] * 100) if info['memory_allocatable'] > 0 else 0

        # Calculate fragmentation score
        if cpu_free > 0 and memory_free > 0 and (reference_pod_cpu > 0 or reference_pod_memory > 0):
            usable_cpu_pct = min(100, (schedulable_pods * reference_pod_cpu) / cpu_free * 100) if cpu_free > 0 else 0
            usable_memory_pct = min(100, (schedulable_pods * reference_pod_memory) / memory_free * 100) if memory_free > 0 else 0
            fragmentation_score = 100 - min(usable_cpu_pct, usable_memory_pct)
        else:
            fragmentation_score = 0

        # Determine limiting factor
        if schedulable_pods == 0:
            limiting_factor = 'all'
        elif pods_by_count <= pods_by_cpu and pods_by_count <= pods_by_memory:
            limiting_factor = 'pod_count'
        elif pods_by_cpu <= pods_by_memory:
            limiting_factor = 'cpu'
        else:
            limiting_factor = 'memory'

        # Determine status
        if schedulable_pods == 0 and (cpu_free > 0 or memory_free > 0):
            status = 'PHANTOM_CAPACITY'
        elif fragmentation_score > 50:
            status = 'HIGH_FRAGMENTATION'
        elif fragmentation_score > 25:
            status = 'MODERATE_FRAGMENTATION'
        else:
            status = 'OK'

        results.append({
            'node_name': node_name,
            'is_schedulable': info['is_schedulable'],
            'cpu_allocatable': info['cpu_allocatable'],
            'cpu_requested': info['cpu_requested'],
            'cpu_free': cpu_free,
            'cpu_free_pct': round(cpu_free_pct, 1),
            'memory_allocatable': info['memory_allocatable'],
            'memory_requested': info['memory_requested'],
            'memory_free': memory_free,
            'memory_free_pct': round(memory_free_pct, 1),
            'pods_allocatable': info['pods_allocatable'],
            'pod_count': info['pod_count'],
            'pods_free': pods_free,
            'schedulable_pods': schedulable_pods,
            'fragmentation_score': round(fragmentation_score, 1),
            'limiting_factor': limiting_factor,
            'status': status,
        })

    results.sort(key=lambda x: (-x['fragmentation_score'], x['node_name']))
    return results


def calculate_cluster_summary(results: list, reference_pod_cpu: int, reference_pod_memory: int) -> dict:
    """Calculate cluster-wide fragmentation summary."""
    if not results:
        return {}

    schedulable_nodes = [r for r in results if r['is_schedulable']]

    total_cpu_free = sum(r['cpu_free'] for r in schedulable_nodes)
    total_memory_free = sum(r['memory_free'] for r in schedulable_nodes)
    total_schedulable_pods = sum(r['schedulable_pods'] for r in schedulable_nodes)

    theoretical_pods_cpu = total_cpu_free // reference_pod_cpu if reference_pod_cpu > 0 else 0
    theoretical_pods_memory = total_memory_free // reference_pod_memory if reference_pod_memory > 0 else 0
    theoretical_pods = min(theoretical_pods_cpu, theoretical_pods_memory)

    if theoretical_pods > 0:
        cluster_fragmentation = (1 - total_schedulable_pods / theoretical_pods) * 100
    else:
        cluster_fragmentation = 0

    high_frag_nodes = sum(1 for r in results if r['status'] == 'HIGH_FRAGMENTATION')
    phantom_nodes = sum(1 for r in results if r['status'] == 'PHANTOM_CAPACITY')

    return {
        'total_nodes': len(results),
        'schedulable_nodes': len(schedulable_nodes),
        'total_cpu_free': total_cpu_free,
        'total_memory_free': total_memory_free,
        'total_schedulable_pods': total_schedulable_pods,
        'theoretical_pods': theoretical_pods,
        'cluster_fragmentation_pct': round(cluster_fragmentation, 1),
        'high_fragmentation_nodes': high_frag_nodes,
        'phantom_capacity_nodes': phantom_nodes,
        'reference_pod_cpu': reference_pod_cpu,
        'reference_pod_memory': reference_pod_memory,
    }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = fragmentation issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes node resource fragmentation'
    )
    parser.add_argument('-n', '--namespace', help='Namespace to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show cluster summary')
    parser.add_argument('-w', '--warn-only', action='store_true', help='Only show nodes with issues')
    parser.add_argument('--cpu', default='500m', help='Reference pod CPU request (default: 500m)')
    parser.add_argument('--memory', default='512Mi', help='Reference pod memory request (default: 512Mi)')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    if not context.check_tool('kubectl'):
        output.error('kubectl not found in PATH')
        return 2

    reference_cpu = parse_resource_value(opts.cpu)
    reference_memory = parse_resource_value(opts.memory)

    if reference_cpu <= 0 or reference_memory <= 0:
        output.error('Invalid reference pod size')
        return 2

    try:
        nodes_data = get_nodes(context)
        pods_data = get_pods(context, opts.namespace)
    except Exception as e:
        output.error(f'Failed to get cluster data: {e}')
        return 2

    node_info = calculate_node_allocations(nodes_data, pods_data)
    results = calculate_fragmentation_metrics(node_info, reference_cpu, reference_memory)

    if opts.warn_only:
        results = [r for r in results if r['status'] != 'OK']

    summary = calculate_cluster_summary(results, reference_cpu, reference_memory)

    # Build output
    nodes_output = []
    for r in results:
        node_data = {
            'node': r['node_name'],
            'is_schedulable': r['is_schedulable'],
            'cpu_free': r['cpu_free'],
            'cpu_free_display': format_cpu(r['cpu_free']),
            'cpu_free_pct': r['cpu_free_pct'],
            'memory_free': r['memory_free'],
            'memory_free_display': format_memory(r['memory_free']),
            'memory_free_pct': r['memory_free_pct'],
            'schedulable_pods': r['schedulable_pods'],
            'fragmentation_score': r['fragmentation_score'],
            'limiting_factor': r['limiting_factor'],
            'status': r['status'],
        }
        nodes_output.append(node_data)

    result = {
        'nodes': nodes_output,
        'summary': summary,
    }

    output.emit(result)

    high_frag = summary.get('high_fragmentation_nodes', 0)
    phantom = summary.get('phantom_capacity_nodes', 0)
    output.set_summary(f"{len(results)} nodes, {high_frag} high fragmentation, {phantom} phantom capacity")

    has_issues = any(r['status'] in ('HIGH_FRAGMENTATION', 'PHANTOM_CAPACITY') for r in results)
    return 1 if has_issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
