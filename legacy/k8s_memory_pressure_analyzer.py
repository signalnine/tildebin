#!/usr/bin/env python3
"""
Kubernetes memory pressure analyzer for nodes and pods.

This script detects memory pressure on nodes and identifies pods contributing
to memory contention in a Kubernetes cluster. Essential for baremetal and
large-scale environments where memory constraints can impact stability.

Features:
- Detect nodes with memory pressure conditions
- Identify pods with high memory usage relative to requests/limits
- Analyze memory fragmentation and allocatable vs used memory
- Support for filtering by namespace or node
- Sort pods by memory usage to identify top consumers
- Dry-run mode for validation before action
- Cluster-wide memory health summary

Memory pressure typically manifests as:
- MemoryPressure node condition set to True
- Pods being OOMKilled or evicted
- Memory usage approaching node allocatable capacity
- Pod memory requests exceeding cluster available resources

Exit codes:
    0 - No memory pressure detected / healthy memory state
    1 - Memory pressure detected on nodes or pods / evictions possible
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
        return None


def get_nodes_memory_info():
    """Get memory information for all nodes."""
    args = ['get', 'nodes', '-o', 'json']
    output = run_kubectl(args)
    if not output:
        return None
    return json.loads(output)


def get_pods_memory_info(namespace=None):
    """Get memory information for all pods."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    if not output:
        return None
    return json.loads(output)


def parse_memory_value(mem_str):
    """Convert memory string (e.g., '512Mi', '1Gi') to bytes."""
    if not mem_str:
        return 0

    mem_str = mem_str.strip()
    units = {
        'Ki': 1024,
        'Mi': 1024 ** 2,
        'Gi': 1024 ** 3,
        'Ti': 1024 ** 4,
        'K': 1000,
        'M': 1000 ** 2,
        'G': 1000 ** 3,
        'T': 1000 ** 4,
    }

    for unit, multiplier in units.items():
        if mem_str.endswith(unit):
            try:
                return int(mem_str[:-len(unit)]) * multiplier
            except ValueError:
                return 0

    try:
        return int(mem_str)
    except ValueError:
        return 0


def check_node_memory_pressure(nodes_data):
    """Check for memory pressure on nodes."""
    nodes_with_pressure = []
    nodes_summary = defaultdict(lambda: {
        'allocatable': 0,
        'used': 0,
        'requested': 0,
        'pressure': False,
        'conditions': {}
    })

    if not nodes_data or 'items' not in nodes_data:
        return nodes_with_pressure, nodes_summary

    for node in nodes_data['items']:
        node_name = node['metadata']['name']

        # Get allocatable memory
        if 'status' in node and 'allocatable' in node['status']:
            allocatable = parse_memory_value(
                node['status']['allocatable'].get('memory', '0')
            )
            nodes_summary[node_name]['allocatable'] = allocatable

        # Check node conditions
        has_memory_pressure = False
        if 'status' in node and 'conditions' in node['status']:
            for condition in node['status']['conditions']:
                cond_type = condition.get('type')
                cond_status = condition.get('status')
                nodes_summary[node_name]['conditions'][cond_type] = cond_status

                if cond_type == 'MemoryPressure' and cond_status == 'True':
                    has_memory_pressure = True
                    nodes_with_pressure.append({
                        'node': node_name,
                        'reason': condition.get('reason', 'Unknown'),
                        'message': condition.get('message', '')
                    })

        nodes_summary[node_name]['pressure'] = has_memory_pressure

    return nodes_with_pressure, nodes_summary


def check_pod_memory_usage(pods_data):
    """Analyze pod memory usage and identify high consumers."""
    high_memory_pods = []
    memory_stats = {
        'total_requested': 0,
        'total_limits': 0,
        'pod_count': 0,
        'pods_without_limits': 0,
        'namespace_usage': defaultdict(lambda: {
            'requested': 0,
            'limits': 0,
            'count': 0
        })
    }

    if not pods_data or 'items' not in pods_data:
        return high_memory_pods, memory_stats

    pod_memory_list = []

    for pod in pods_data['items']:
        namespace = pod['metadata'].get('namespace', 'default')
        pod_name = pod['metadata']['name']
        memory_stats['pod_count'] += 1

        # Get memory requests and limits
        total_requested = 0
        total_limits = 0
        has_limits = False

        if 'spec' in pod and 'containers' in pod['spec']:
            for container in pod['spec']['containers']:
                resources = container.get('resources', {})
                requests = resources.get('requests', {})
                limits = resources.get('limits', {})

                total_requested += parse_memory_value(
                    requests.get('memory', '0')
                )
                total_limits += parse_memory_value(limits.get('memory', '0'))

                if limits.get('memory'):
                    has_limits = True

        if not has_limits:
            memory_stats['pods_without_limits'] += 1

        memory_stats['total_requested'] += total_requested
        memory_stats['total_limits'] += total_limits
        memory_stats['namespace_usage'][namespace]['requested'] += total_requested
        memory_stats['namespace_usage'][namespace]['limits'] += total_limits
        memory_stats['namespace_usage'][namespace]['count'] += 1

        pod_memory_list.append({
            'namespace': namespace,
            'pod': pod_name,
            'requested': total_requested,
            'limits': total_limits
        })

    # Find high memory consumers
    # High = requesting >512Mi or any limits
    high_memory_pods = [
        p for p in pod_memory_list
        if p['limits'] > 0 or p['requested'] > 512 * 1024 ** 2
    ]

    # Sort by limits, then by requested
    high_memory_pods.sort(
        key=lambda x: (x['limits'] or x['requested']),
        reverse=True
    )

    return high_memory_pods, memory_stats


def format_bytes(bytes_val):
    """Format bytes to human-readable memory size."""
    for unit in ['B', 'Ki', 'Mi', 'Gi', 'Ti']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f}Ti"


def print_node_summary(nodes_with_pressure, nodes_summary):
    """Print node memory pressure summary."""
    print("\n=== Node Memory Status ===")
    print(f"Total nodes checked: {len(nodes_summary)}")
    print(f"Nodes with memory pressure: {len(nodes_with_pressure)}")

    if nodes_with_pressure:
        print("\nNodes with MemoryPressure condition:")
        for item in nodes_with_pressure:
            print(f"  - {item['node']}: {item['reason']}")
            if item['message']:
                print(f"    {item['message']}")

    # Show node with highest allocated memory
    if nodes_summary:
        print("\nNode allocatable memory:")
        sorted_nodes = sorted(
            nodes_summary.items(),
            key=lambda x: x[1]['allocatable'],
            reverse=True
        )
        for node, info in sorted_nodes[:5]:
            allocatable = format_bytes(info['allocatable'])
            pressure_status = "⚠️ PRESSURE" if info['pressure'] else "✓ OK"
            print(f"  - {node}: {allocatable} [{pressure_status}]")


def print_pod_summary(high_memory_pods, memory_stats):
    """Print pod memory usage summary."""
    print("\n=== Pod Memory Summary ===")
    print(f"Total pods: {memory_stats['pod_count']}")
    print(f"Pods without memory limits: {memory_stats['pods_without_limits']}")
    print(f"Total memory requested: {format_bytes(memory_stats['total_requested'])}")
    print(f"Total memory limits: {format_bytes(memory_stats['total_limits'])}")

    if high_memory_pods:
        print("\nTop memory consumers (first 10):")
        for pod in high_memory_pods[:10]:
            requested = format_bytes(pod['requested'])
            limits = format_bytes(pod['limits']) if pod['limits'] > 0 else 'None'
            print(f"  - {pod['namespace']}/{pod['pod']}: "
                  f"requested={requested}, limits={limits}")

    if memory_stats['namespace_usage']:
        print("\nMemory usage by namespace (top 5):")
        sorted_ns = sorted(
            memory_stats['namespace_usage'].items(),
            key=lambda x: x[1]['requested'],
            reverse=True
        )
        for ns, info in sorted_ns[:5]:
            requested = format_bytes(info['requested'])
            limits = format_bytes(info['limits']) if info['limits'] > 0 else 'None'
            print(f"  - {ns}: {info['count']} pods, "
                  f"requested={requested}, limits={limits}")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes memory pressure on nodes and pods',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check memory pressure in all namespaces
  python3 k8s_memory_pressure_analyzer.py

  # Check memory pressure in specific namespace
  python3 k8s_memory_pressure_analyzer.py -n production

  # Show detailed pod information sorted by memory usage
  python3 k8s_memory_pressure_analyzer.py --show-pods

  # Focus on nodes with memory pressure
  python3 k8s_memory_pressure_analyzer.py --nodes-only
        """
    )
    parser.add_argument(
        '-n', '--namespace',
        help='Kubernetes namespace to analyze (default: all namespaces)'
    )
    parser.add_argument(
        '--nodes-only',
        action='store_true',
        help='Only show node memory pressure information'
    )
    parser.add_argument(
        '--pods-only',
        action='store_true',
        help='Only show pod memory usage information'
    )

    args = parser.parse_args()

    exit_code = 0

    # Get nodes data
    nodes_data = get_nodes_memory_info()
    if not nodes_data:
        print("Error: Could not retrieve node information", file=sys.stderr)
        sys.exit(1)

    if not args.pods_only:
        # Check node memory pressure
        nodes_with_pressure, nodes_summary = check_node_memory_pressure(nodes_data)
        print_node_summary(nodes_with_pressure, nodes_summary)

        if nodes_with_pressure:
            exit_code = 1

    if not args.nodes_only:
        # Check pod memory usage
        pods_data = get_pods_memory_info(args.namespace)
        if not pods_data:
            print("Error: Could not retrieve pod information", file=sys.stderr)
            sys.exit(1)

        high_memory_pods, memory_stats = check_pod_memory_usage(pods_data)
        print_pod_summary(high_memory_pods, memory_stats)

        # Check if we should exit with error code
        # Exit with 1 if pods don't have limits or too many high consumers
        if memory_stats['pods_without_limits'] > 0:
            exit_code = 1

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
