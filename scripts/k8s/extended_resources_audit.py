#!/usr/bin/env python3
# boxctl:
#   category: k8s/resources
#   tags: [gpu, extended-resources, hardware, capacity]
#   requires: [kubectl]
#   privilege: user
#   related: [pod_resource_audit, node_resource_fragmentation]
#   brief: Audit extended resource (GPU, FPGA) allocation across the cluster

"""
Audit Kubernetes extended resources (GPUs, custom devices) and their allocation.

Identifies:
- Nodes with extended resources (GPUs, FPGAs, custom device plugins)
- Pods requesting extended resources
- Unallocated extended resources (capacity waste)
- Pods pending due to insufficient extended resources
- Mismatched node selectors for hardware-specific workloads

Exit codes:
    0 - No issues detected
    1 - Issues found (underutilization, pending pods, misconfigurations)
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Common extended resource prefixes
EXTENDED_RESOURCE_PREFIXES = [
    'nvidia.com/',
    'amd.com/',
    'intel.com/',
    'habana.ai/',
    'xilinx.com/',
    'smarter-devices/',
    'devices.kubevirt.io/',
    'gpu.intel.com/',
    'fpga.intel.com/',
    'qat.intel.com/',
    'sriov.openshift.io/',
    'openshift.io/',
    'k8s.io/',
    'rdma/',
    'hugepages-',
]

STANDARD_RESOURCES = {'cpu', 'memory', 'ephemeral-storage', 'pods'}


def is_extended_resource(resource_name: str) -> bool:
    """Check if a resource name is an extended resource."""
    if resource_name in STANDARD_RESOURCES:
        return False
    for prefix in EXTENDED_RESOURCE_PREFIXES:
        if resource_name.startswith(prefix):
            return True
    if '/' in resource_name:
        return True
    if resource_name.startswith('hugepages-'):
        return True
    return False


def get_nodes(context: Context) -> dict[str, Any]:
    """Get all nodes with their capacity and allocatable resources."""
    result = context.run(['kubectl', 'get', 'nodes', '-o', 'json'])
    return json.loads(result.stdout)


def get_pods(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get all pods in JSON format."""
    args = ['kubectl', 'get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')
    result = context.run(args)
    return json.loads(result.stdout)


def extract_node_extended_resources(nodes_data: dict) -> dict[str, Any]:
    """Extract extended resources from node capacity/allocatable."""
    node_resources = {}

    for node in nodes_data.get('items', []):
        node_name = node['metadata']['name']
        capacity = node.get('status', {}).get('capacity', {})
        allocatable = node.get('status', {}).get('allocatable', {})

        extended = {}
        for resource, value in allocatable.items():
            if is_extended_resource(resource):
                try:
                    extended[resource] = {
                        'allocatable': int(value),
                        'capacity': int(capacity.get(resource, value)),
                        'requested': 0,
                        'pods': []
                    }
                except ValueError:
                    pass

        if extended:
            node_resources[node_name] = {
                'resources': extended,
                'labels': node['metadata'].get('labels', {}),
            }

    return node_resources


def extract_pod_extended_requests(pods_data: dict) -> list[dict]:
    """Extract extended resource requests from pods."""
    pod_requests = []

    for pod in pods_data.get('items', []):
        pod_name = pod['metadata']['name']
        namespace = pod['metadata'].get('namespace', 'default')
        phase = pod.get('status', {}).get('phase', 'Unknown')
        node_name = pod.get('spec', {}).get('nodeName')

        node_selector = pod.get('spec', {}).get('nodeSelector', {})
        affinity = pod.get('spec', {}).get('affinity', {})

        extended_requests = {}
        containers = pod.get('spec', {}).get('containers', [])
        init_containers = pod.get('spec', {}).get('initContainers', [])

        for container in containers + init_containers:
            resources = container.get('resources', {})
            requests = resources.get('requests', {})
            limits = resources.get('limits', {})

            for resource, value in requests.items():
                if is_extended_resource(resource):
                    try:
                        count = int(value)
                        extended_requests[resource] = extended_requests.get(resource, 0) + count
                    except ValueError:
                        pass

            for resource, value in limits.items():
                if is_extended_resource(resource) and resource not in extended_requests:
                    try:
                        count = int(value)
                        extended_requests[resource] = count
                    except ValueError:
                        pass

        if extended_requests:
            pod_requests.append({
                'name': pod_name,
                'namespace': namespace,
                'phase': phase,
                'node': node_name,
                'requests': extended_requests,
                'node_selector': node_selector,
                'has_affinity': bool(affinity.get('nodeAffinity'))
            })

    return pod_requests


def analyze_allocation(node_resources: dict, pod_requests: list) -> list[dict]:
    """Analyze extended resource allocation and identify issues."""
    issues = []

    # Track allocation per node
    for pod in pod_requests:
        node_name = pod['node']
        if node_name and node_name in node_resources:
            for resource, count in pod['requests'].items():
                if resource in node_resources[node_name]['resources']:
                    node_resources[node_name]['resources'][resource]['requested'] += count
                    node_resources[node_name]['resources'][resource]['pods'].append(
                        f"{pod['namespace']}/{pod['name']}"
                    )

    # Pending pods requesting extended resources
    pending_pods = [p for p in pod_requests if p['phase'] == 'Pending']
    for pod in pending_pods:
        issues.append({
            'type': 'PENDING_POD',
            'severity': 'WARNING',
            'pod': f"{pod['namespace']}/{pod['name']}",
            'resources': pod['requests'],
            'message': f"Pod pending with extended resource requests: {pod['requests']}"
        })

    # Underutilized extended resources
    for node_name, node_data in node_resources.items():
        for resource, data in node_data['resources'].items():
            if data['allocatable'] > 0:
                utilization = (data['requested'] / data['allocatable']) * 100
                if utilization < 50:
                    issues.append({
                        'type': 'UNDERUTILIZED',
                        'severity': 'INFO',
                        'node': node_name,
                        'resource': resource,
                        'allocated': data['requested'],
                        'total': data['allocatable'],
                        'utilization_pct': round(utilization, 1),
                        'message': f"Node {node_name}: {resource} is {utilization:.0f}% utilized"
                    })

    # Pods using extended resources without node constraints
    for pod in pod_requests:
        if pod['phase'] != 'Pending' and not pod['node_selector'] and not pod['has_affinity']:
            resources_requested = set(pod['requests'].keys())
            nodes_with_all_resources = 0
            total_nodes = len(node_resources) if node_resources else 1

            for node_data in node_resources.values():
                if all(r in node_data['resources'] for r in resources_requested):
                    nodes_with_all_resources += 1

            if nodes_with_all_resources < total_nodes and total_nodes > 1:
                issues.append({
                    'type': 'NO_PLACEMENT_CONSTRAINT',
                    'severity': 'INFO',
                    'pod': f"{pod['namespace']}/{pod['name']}",
                    'resources': list(resources_requested),
                    'message': f"Pod uses extended resources but has no nodeSelector/affinity"
                })

    return issues


def get_cluster_summary(node_resources: dict, pod_requests: list) -> dict:
    """Generate cluster-wide extended resource summary."""
    summary: dict[str, Any] = {
        'total_nodes_with_extended': len(node_resources),
        'total_pods_using_extended': len(pod_requests),
        'resources': {}
    }

    resources: dict[str, dict] = defaultdict(lambda: {
        'total_capacity': 0,
        'total_allocatable': 0,
        'total_requested': 0,
        'nodes': 0
    })

    for node_data in node_resources.values():
        for resource, data in node_data['resources'].items():
            resources[resource]['total_capacity'] += data['capacity']
            resources[resource]['total_allocatable'] += data['allocatable']
            resources[resource]['total_requested'] += data['requested']
            resources[resource]['nodes'] += 1

    summary['resources'] = dict(resources)
    return summary


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
    parser = argparse.ArgumentParser(
        description='Audit Kubernetes extended resources (GPUs, custom devices)'
    )
    parser.add_argument('-n', '--namespace', help='Namespace to audit')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-w', '--warn-only', action='store_true', help='Only show warnings')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    if not context.check_tool('kubectl'):
        output.error('kubectl not found in PATH')
        return 2

    try:
        nodes_data = get_nodes(context)
        pods_data = get_pods(context, opts.namespace)
    except Exception as e:
        output.error(f'Failed to get cluster data: {e}')
        return 2

    node_resources = extract_node_extended_resources(nodes_data)
    pod_requests = extract_pod_extended_requests(pods_data)
    issues = analyze_allocation(node_resources, pod_requests)
    summary = get_cluster_summary(node_resources, pod_requests)

    # Filter issues if warn_only
    if opts.warn_only:
        issues = [i for i in issues if i['severity'] == 'WARNING']

    result = {
        'summary': summary,
        'nodes': node_resources if opts.verbose else {},
        'pods': pod_requests if opts.verbose else [],
        'issues': issues
    }

    output.emit(result)

    warnings = sum(1 for i in issues if i['severity'] == 'WARNING')
    info_count = sum(1 for i in issues if i['severity'] == 'INFO')
    output.set_summary(f"{summary['total_nodes_with_extended']} nodes, {warnings} warnings, {info_count} info")

    has_warnings = any(i['severity'] == 'WARNING' for i in issues)
    return 1 if has_warnings else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
