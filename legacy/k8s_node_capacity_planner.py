#!/usr/bin/env python3
"""
Kubernetes node capacity planner - Analyze cluster capacity and forecast resource allocation.

Helps operators understand:
- Total allocatable resources per node
- Current allocation and utilization
- Nodes approaching capacity thresholds
- Capacity planning recommendations
"""

import argparse
import sys
import json

def try_import_kubectl():
    """Try to import kubernetes client library, return None if not available."""
    try:
        from kubernetes import client, config
        return client, config
    except ImportError:
        return None, None

def format_bytes(num_bytes):
    """Convert bytes to human-readable format."""
    if num_bytes is None:
        return "N/A"
    for unit in ['B', 'Ki', 'Mi', 'Gi', 'Ti']:
        if num_bytes < 1024:
            return f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}Pi"

def parse_resource_value(value_str):
    """Parse Kubernetes resource value (e.g., '100m', '1Gi') to base units."""
    if value_str is None:
        return 0

    value_str = str(value_str).strip()

    # Handle CPU (millicores)
    if value_str.endswith('m'):
        return int(value_str[:-1])

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

    # Plain number (bytes)
    try:
        return int(float(value_str))
    except ValueError:
        return 0

def get_node_capacity(api_instance):
    """Fetch node capacity and allocation data."""
    try:
        nodes = api_instance.list_node()
    except Exception as e:
        print(f"Error: Failed to list nodes: {e}", file=sys.stderr)
        sys.exit(1)

    node_data = []

    for node in nodes.items:
        node_name = node.metadata.name

        # Get allocatable resources
        allocatable = node.status.allocatable or {}
        capacity = node.status.capacity or {}

        # Parse resource values
        cpu_allocatable = parse_resource_value(allocatable.get('cpu', 0))
        mem_allocatable = parse_resource_value(allocatable.get('memory', 0))
        pods_allocatable = parse_resource_value(allocatable.get('pods', 110))

        cpu_capacity = parse_resource_value(capacity.get('cpu', 0))
        mem_capacity = parse_resource_value(capacity.get('memory', 0))

        node_data.append({
            'name': node_name,
            'cpu_allocatable': cpu_allocatable,  # in millicores
            'memory_allocatable': mem_allocatable,  # in bytes
            'pods_allocatable': int(pods_allocatable),
            'cpu_capacity': cpu_capacity,
            'memory_capacity': mem_capacity,
        })

    return node_data

def get_pod_requests(api_instance):
    """Fetch pod resource requests across all namespaces."""
    try:
        pods = api_instance.list_pod_for_all_namespaces()
    except Exception as e:
        print(f"Error: Failed to list pods: {e}", file=sys.stderr)
        sys.exit(1)

    # Aggregate requests by node
    node_requests = {}

    for pod in pods.items:
        node_name = pod.spec.node_name
        if not node_name:
            continue

        if node_name not in node_requests:
            node_requests[node_name] = {'cpu': 0, 'memory': 0, 'pods': 0}

        # Count pod
        node_requests[node_name]['pods'] += 1

        # Sum container requests
        if pod.spec.containers:
            for container in pod.spec.containers:
                if container.resources and container.resources.requests:
                    requests = container.resources.requests
                    node_requests[node_name]['cpu'] += parse_resource_value(requests.get('cpu', 0))
                    node_requests[node_name]['memory'] += parse_resource_value(requests.get('memory', 0))

    return node_requests

def analyze_capacity(nodes, requests):
    """Analyze and compute capacity metrics."""
    analysis = []

    for node in nodes:
        node_name = node['name']
        node_req = requests.get(node_name, {'cpu': 0, 'memory': 0, 'pods': 0})

        # Calculate utilization percentages
        cpu_util = (node_req['cpu'] / node['cpu_allocatable'] * 100) if node['cpu_allocatable'] > 0 else 0
        mem_util = (node_req['memory'] / node['memory_allocatable'] * 100) if node['memory_allocatable'] > 0 else 0
        pods_util = (node_req['pods'] / node['pods_allocatable'] * 100) if node['pods_allocatable'] > 0 else 0

        # Determine capacity status
        max_util = max(cpu_util, mem_util, pods_util)
        if max_util > 90:
            status = "CRITICAL"
        elif max_util > 75:
            status = "WARNING"
        elif max_util > 50:
            status = "MODERATE"
        else:
            status = "OK"

        analysis.append({
            'node_name': node_name,
            'cpu_allocatable_m': node['cpu_allocatable'],
            'cpu_requested_m': node_req['cpu'],
            'cpu_util_pct': round(cpu_util, 1),
            'memory_allocatable_bytes': node['memory_allocatable'],
            'memory_requested_bytes': node_req['memory'],
            'memory_util_pct': round(mem_util, 1),
            'pods_allocatable': node['pods_allocatable'],
            'pods_scheduled': node_req['pods'],
            'pods_util_pct': round(pods_util, 1),
            'max_util_pct': round(max_util, 1),
            'status': status,
        })

    return sorted(analysis, key=lambda x: x['max_util_pct'], reverse=True)

def print_table(analysis):
    """Print capacity analysis in table format."""
    if not analysis:
        print("No nodes found")
        return

    # Header
    print(f"{'Node':<25} {'CPU':<15} {'Memory':<15} {'Pods':<10} {'Max Util':<12} {'Status':<10}")
    print("-" * 90)

    for node in analysis:
        cpu_str = f"{node['cpu_requested_m']}/{node['cpu_allocatable_m']}m ({node['cpu_util_pct']:.0f}%)"
        mem_str = f"{format_bytes(node['memory_requested_bytes'])}/{format_bytes(node['memory_allocatable_bytes'])} ({node['memory_util_pct']:.0f}%)"
        pods_str = f"{node['pods_scheduled']}/{node['pods_allocatable']}"
        max_util_str = f"{node['max_util_pct']:.0f}%"

        print(f"{node['node_name']:<25} {cpu_str:<15} {mem_str:<15} {pods_str:<10} {max_util_str:<12} {node['status']:<10}")

def print_plain(analysis):
    """Print capacity analysis in plain format."""
    for node in analysis:
        print(f"{node['node_name']} "
              f"cpu={node['cpu_requested_m']}/{node['cpu_allocatable_m']}m "
              f"mem={format_bytes(node['memory_requested_bytes'])}/{format_bytes(node['memory_allocatable_bytes'])} "
              f"pods={node['pods_scheduled']}/{node['pods_allocatable']} "
              f"util={node['max_util_pct']:.0f}% "
              f"status={node['status']}")

def print_json(analysis):
    """Print capacity analysis in JSON format."""
    print(json.dumps(analysis, indent=2))

def print_summary(analysis):
    """Print capacity planning summary."""
    if not analysis:
        print("No nodes found")
        return

    critical_nodes = sum(1 for n in analysis if n['status'] == 'CRITICAL')
    warning_nodes = sum(1 for n in analysis if n['status'] == 'WARNING')
    total_cpu = sum(n['cpu_allocatable_m'] for n in analysis)
    total_mem = sum(n['memory_allocatable_bytes'] for n in analysis)
    used_cpu = sum(n['cpu_requested_m'] for n in analysis)
    used_mem = sum(n['memory_requested_bytes'] for n in analysis)

    print(f"Cluster Capacity Summary")
    print(f"========================")
    print(f"Total Nodes: {len(analysis)}")
    print(f"  Critical (>90%): {critical_nodes}")
    print(f"  Warning (>75%): {warning_nodes}")
    print()
    print(f"Total CPU Allocatable: {total_cpu}m")
    print(f"Total CPU Requested: {used_cpu}m ({used_cpu/total_cpu*100:.1f}%)")
    print(f"Total Memory Allocatable: {format_bytes(total_mem)}")
    print(f"Total Memory Requested: {format_bytes(used_mem)} ({used_mem/total_mem*100:.1f}%)")
    print()

    if critical_nodes > 0:
        print(f"⚠ WARNING: {critical_nodes} node(s) approaching capacity limits!")
        critical = [n for n in analysis if n['status'] == 'CRITICAL']
        for node in critical:
            print(f"  - {node['node_name']}: {node['max_util_pct']:.0f}% utilized")

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes cluster node capacity and forecast resource allocation"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["table", "plain", "json", "summary"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show nodes with WARNING or CRITICAL status"
    )

    args = parser.parse_args()

    # Load kubernetes client
    client, config_module = try_import_kubectl()
    if client is None:
        print("Error: kubernetes library not installed", file=sys.stderr)
        print("Install with: pip install kubernetes", file=sys.stderr)
        sys.exit(1)

    try:
        config_module.load_incluster_config()
    except:
        try:
            config_module.load_kube_config()
        except Exception as e:
            print(f"Error: Failed to load kubeconfig: {e}", file=sys.stderr)
            sys.exit(1)

    api = client.CoreV1Api()

    # Gather data
    nodes = get_node_capacity(api)
    requests = get_pod_requests(api)

    # Analyze
    analysis = analyze_capacity(nodes, requests)

    # Filter if requested
    if args.warn_only:
        analysis = [n for n in analysis if n['status'] in ('WARNING', 'CRITICAL')]

    # Output
    if args.format == "table":
        print_table(analysis)
    elif args.format == "plain":
        print_plain(analysis)
    elif args.format == "json":
        print_json(analysis)
    elif args.format == "summary":
        print_summary(analysis)

    sys.exit(0)

if __name__ == "__main__":
    main()
