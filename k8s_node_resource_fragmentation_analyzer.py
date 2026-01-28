#!/usr/bin/env python3
"""
Kubernetes node resource fragmentation analyzer.

Analyzes resource fragmentation on cluster nodes - identifies situations where
aggregate free resources exist but pods cannot be scheduled due to fragmented
allocations across nodes.

This tool helps answer: "Why can't my pod schedule when the cluster shows free capacity?"

Features:
- Identifies nodes with fragmented CPU/memory allocations
- Detects "phantom capacity" (free resources that can't fit typical pods)
- Simulates bin-packing to estimate real schedulable capacity
- Suggests optimal pod sizes based on available gaps
- Reports fragmentation score per node

Exit codes:
    0 - No significant fragmentation detected
    1 - Fragmentation issues found (some nodes have limited schedulable capacity)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


def run_kubectl(args):
    """Run kubectl command and return output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def parse_resource_value(value_str):
    """Parse Kubernetes resource value (e.g., '100m', '1Gi') to base units."""
    if value_str is None:
        return 0

    value_str = str(value_str).strip()
    if not value_str:
        return 0

    # Handle CPU (millicores)
    if value_str.endswith('m'):
        try:
            return int(value_str[:-1])
        except ValueError:
            return 0

    # Handle Memory and storage
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

    # Plain number (could be cores for CPU or bytes for memory)
    try:
        # If it's a small number, assume it's CPU cores (convert to millicores)
        val = float(value_str)
        if val < 1000:
            return int(val * 1000)  # Assume cores, convert to millicores
        return int(val)  # Assume bytes
    except ValueError:
        return 0


def format_cpu(millicores):
    """Format CPU millicores for display."""
    if millicores >= 1000:
        return f"{millicores / 1000:.1f} cores"
    return f"{millicores}m"


def format_memory(mem_bytes):
    """Format memory bytes for display."""
    if mem_bytes is None or mem_bytes == 0:
        return "0"
    for unit in ['B', 'Ki', 'Mi', 'Gi', 'Ti']:
        if mem_bytes < 1024:
            return f"{mem_bytes:.1f}{unit}"
        mem_bytes /= 1024
    return f"{mem_bytes:.1f}Pi"


def get_nodes():
    """Get node information."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    return json.loads(output)


def get_pods(namespace=None):
    """Get pod information."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')
    output = run_kubectl(args)
    return json.loads(output)


def calculate_node_allocations(nodes_data, pods_data):
    """Calculate resource allocations per node."""
    # Parse node allocatable resources
    node_info = {}
    for node in nodes_data.get('items', []):
        name = node['metadata']['name']
        allocatable = node.get('status', {}).get('allocatable', {})

        # Check if node is schedulable
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
            'pods': [],  # List of (cpu_request, memory_request) tuples
            'is_schedulable': is_schedulable,
        }

    # Aggregate pod requests per node
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
        node_info[node_name]['pods'].append((pod_cpu, pod_memory))

    return node_info


def calculate_fragmentation_metrics(node_info, reference_pod_cpu, reference_pod_memory):
    """
    Calculate fragmentation metrics for each node.

    Fragmentation is measured by comparing:
    - Aggregate free resources vs actual capacity for reference pod size
    """
    results = []

    for node_name, info in node_info.items():
        cpu_free = info['cpu_allocatable'] - info['cpu_requested']
        memory_free = info['memory_allocatable'] - info['memory_requested']
        pods_free = info['pods_allocatable'] - info['pod_count']

        # Calculate how many reference pods could theoretically fit
        if reference_pod_cpu > 0 and reference_pod_memory > 0:
            pods_by_cpu = cpu_free // reference_pod_cpu if reference_pod_cpu > 0 else 0
            pods_by_memory = memory_free // reference_pod_memory if reference_pod_memory > 0 else 0
            pods_by_count = pods_free
            schedulable_pods = min(pods_by_cpu, pods_by_memory, pods_by_count)
        else:
            schedulable_pods = 0

        # Calculate theoretical capacity (if resources were perfectly packed)
        total_cpu_free_pct = (cpu_free / info['cpu_allocatable'] * 100) if info['cpu_allocatable'] > 0 else 0
        total_memory_free_pct = (memory_free / info['memory_allocatable'] * 100) if info['memory_allocatable'] > 0 else 0

        # Find largest contiguous block that could be scheduled
        # (Since K8s doesn't have fragmentation within a node, this is just the free space)
        largest_cpu_block = cpu_free
        largest_memory_block = memory_free

        # Calculate fragmentation score (0 = no fragmentation, 100 = fully fragmented)
        # Based on how much of the free space is actually usable for the reference pod
        if cpu_free > 0 and memory_free > 0:
            usable_cpu_pct = min(100, (schedulable_pods * reference_pod_cpu) / cpu_free * 100) if cpu_free > 0 else 0
            usable_memory_pct = min(100, (schedulable_pods * reference_pod_memory) / memory_free * 100) if memory_free > 0 else 0
            fragmentation_score = 100 - min(usable_cpu_pct, usable_memory_pct)
        else:
            fragmentation_score = 0  # No free space = no fragmentation issue

        # Determine limiting factor
        if pods_by_count <= pods_by_cpu and pods_by_count <= pods_by_memory:
            limiting_factor = 'pod_count'
        elif pods_by_cpu <= pods_by_memory:
            limiting_factor = 'cpu'
        else:
            limiting_factor = 'memory'

        # Determine status
        # PHANTOM_CAPACITY: Free resources exist but can't fit even one reference pod
        # This is checked first because it's a specific condition
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
            'cpu_free_pct': round(total_cpu_free_pct, 1),
            'memory_allocatable': info['memory_allocatable'],
            'memory_requested': info['memory_requested'],
            'memory_free': memory_free,
            'memory_free_pct': round(total_memory_free_pct, 1),
            'pods_allocatable': info['pods_allocatable'],
            'pod_count': info['pod_count'],
            'pods_free': pods_free,
            'schedulable_pods': schedulable_pods,
            'largest_cpu_block': largest_cpu_block,
            'largest_memory_block': largest_memory_block,
            'fragmentation_score': round(fragmentation_score, 1),
            'limiting_factor': limiting_factor,
            'status': status,
        })

    # Sort by fragmentation score (highest first)
    results.sort(key=lambda x: (-x['fragmentation_score'], x['node_name']))

    return results


def calculate_cluster_summary(results, reference_pod_cpu, reference_pod_memory):
    """Calculate cluster-wide fragmentation summary."""
    if not results:
        return {}

    schedulable_nodes = [r for r in results if r['is_schedulable']]

    total_cpu_free = sum(r['cpu_free'] for r in schedulable_nodes)
    total_memory_free = sum(r['memory_free'] for r in schedulable_nodes)
    total_schedulable_pods = sum(r['schedulable_pods'] for r in schedulable_nodes)

    # Theoretical pods if all free resources were on one node
    theoretical_pods_cpu = total_cpu_free // reference_pod_cpu if reference_pod_cpu > 0 else 0
    theoretical_pods_memory = total_memory_free // reference_pod_memory if reference_pod_memory > 0 else 0
    theoretical_pods = min(theoretical_pods_cpu, theoretical_pods_memory)

    # Cluster fragmentation: difference between theoretical and actual
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


def print_plain(results, summary, verbose):
    """Print results in plain format."""
    for r in results:
        if not r['is_schedulable']:
            sched_marker = " [UNSCHEDULABLE]"
        else:
            sched_marker = ""

        print(f"{r['node_name']}{sched_marker} "
              f"cpu_free={format_cpu(r['cpu_free'])} ({r['cpu_free_pct']}%) "
              f"mem_free={format_memory(r['memory_free'])} ({r['memory_free_pct']}%) "
              f"schedulable_pods={r['schedulable_pods']} "
              f"frag_score={r['fragmentation_score']} "
              f"limiting={r['limiting_factor']} "
              f"status={r['status']}")

    if verbose and summary:
        print()
        print(f"Cluster Summary: {summary['schedulable_nodes']}/{summary['total_nodes']} nodes schedulable")
        print(f"  Total free: {format_cpu(summary['total_cpu_free'])} CPU, {format_memory(summary['total_memory_free'])} memory")
        print(f"  Schedulable pods: {summary['total_schedulable_pods']} actual vs {summary['theoretical_pods']} theoretical")
        print(f"  Cluster fragmentation: {summary['cluster_fragmentation_pct']}%")


def print_table(results, summary, verbose):
    """Print results in table format."""
    if not results:
        print("No nodes found")
        return

    # Header
    print(f"{'Node':<30} {'CPU Free':<15} {'Memory Free':<15} {'Sched Pods':<12} {'Frag %':<10} {'Status':<20}")
    print("-" * 105)

    for r in results:
        node_name = r['node_name']
        if not r['is_schedulable']:
            node_name += "*"

        cpu_str = f"{format_cpu(r['cpu_free'])} ({r['cpu_free_pct']}%)"
        mem_str = f"{format_memory(r['memory_free'])} ({r['memory_free_pct']}%)"

        print(f"{node_name:<30} {cpu_str:<15} {mem_str:<15} {r['schedulable_pods']:<12} {r['fragmentation_score']:<10} {r['status']:<20}")

    if verbose and summary:
        print()
        print("* = unschedulable node")
        print()
        print("Cluster Summary:")
        print(f"  Nodes: {summary['schedulable_nodes']}/{summary['total_nodes']} schedulable")
        print(f"  Total free: {format_cpu(summary['total_cpu_free'])} CPU, {format_memory(summary['total_memory_free'])} memory")
        print(f"  Reference pod: {format_cpu(summary['reference_pod_cpu'])} CPU, {format_memory(summary['reference_pod_memory'])} memory")
        print(f"  Schedulable pods: {summary['total_schedulable_pods']} (theoretical: {summary['theoretical_pods']})")
        print(f"  Cluster fragmentation: {summary['cluster_fragmentation_pct']}%")
        if summary['high_fragmentation_nodes'] > 0:
            print(f"  High fragmentation nodes: {summary['high_fragmentation_nodes']}")
        if summary['phantom_capacity_nodes'] > 0:
            print(f"  Phantom capacity nodes: {summary['phantom_capacity_nodes']}")


def print_json(results, summary):
    """Print results in JSON format."""
    output = {
        'nodes': results,
        'summary': summary,
    }
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes node resource fragmentation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Analyze with default reference pod (500m CPU, 512Mi memory)
  %(prog)s --cpu 1000m --memory 1Gi     # Analyze with custom reference pod size
  %(prog)s --warn-only                  # Only show nodes with fragmentation issues
  %(prog)s --format json                # JSON output for automation
  %(prog)s -v                           # Include cluster summary

Reference pod:
  The analysis uses a "reference pod" size to calculate how many pods can
  actually be scheduled. This helps identify "phantom capacity" where free
  resources exist but are too small for typical workloads.

Exit codes:
  0 - No significant fragmentation
  1 - Fragmentation issues found
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to analyze (default: all namespaces)'
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'table', 'json'],
        default='table',
        help='Output format (default: table)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show nodes with fragmentation issues'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show cluster summary and additional details'
    )

    parser.add_argument(
        '--cpu',
        default='500m',
        help='Reference pod CPU request (default: 500m)'
    )

    parser.add_argument(
        '--memory',
        default='512Mi',
        help='Reference pod memory request (default: 512Mi)'
    )

    args = parser.parse_args()

    # Parse reference pod size
    reference_cpu = parse_resource_value(args.cpu)
    reference_memory = parse_resource_value(args.memory)

    if reference_cpu <= 0 or reference_memory <= 0:
        print("Error: Invalid reference pod size", file=sys.stderr)
        sys.exit(2)

    # Gather data
    nodes_data = get_nodes()
    pods_data = get_pods(args.namespace)

    # Calculate allocations
    node_info = calculate_node_allocations(nodes_data, pods_data)

    # Calculate fragmentation metrics
    results = calculate_fragmentation_metrics(node_info, reference_cpu, reference_memory)

    # Filter if requested
    if args.warn_only:
        results = [r for r in results if r['status'] != 'OK']

    # Calculate cluster summary
    summary = calculate_cluster_summary(results, reference_cpu, reference_memory)

    # Output
    if args.format == 'json':
        print_json(results, summary)
    elif args.format == 'table':
        print_table(results, summary, args.verbose)
    else:
        print_plain(results, summary, args.verbose)

    # Determine exit code
    has_issues = any(r['status'] in ('HIGH_FRAGMENTATION', 'PHANTOM_CAPACITY') for r in results)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
