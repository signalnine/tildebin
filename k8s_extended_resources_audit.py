#!/usr/bin/env python3
"""
Audit Kubernetes extended resources (GPUs, custom devices) and their allocation.

This script analyzes extended resource usage across a Kubernetes cluster, identifying:
- Nodes with extended resources (GPUs, FPGAs, custom device plugins)
- Pods requesting extended resources
- Unallocated extended resources (capacity waste)
- Pods pending due to insufficient extended resources
- Mismatched node selectors for hardware-specific workloads

Useful for managing heterogeneous baremetal Kubernetes clusters with specialized
hardware like GPUs, FPGAs, SR-IOV NICs, or custom device plugins.

Exit codes:
    0 - No issues detected
    1 - Issues found (underutilization, pending pods, misconfigurations)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


# Common extended resource prefixes to identify non-standard resources
EXTENDED_RESOURCE_PREFIXES = [
    'nvidia.com/',           # NVIDIA GPUs
    'amd.com/',              # AMD GPUs
    'intel.com/',            # Intel devices (GPUs, FPGAs, QAT)
    'habana.ai/',            # Habana Gaudi accelerators
    'xilinx.com/',           # Xilinx FPGAs
    'smarter-devices/',      # Generic device plugins
    'devices.kubevirt.io/',  # KubeVirt devices
    'gpu.intel.com/',        # Intel GPU plugin
    'fpga.intel.com/',       # Intel FPGA plugin
    'qat.intel.com/',        # Intel QuickAssist
    'sriov.openshift.io/',   # SR-IOV network devices
    'openshift.io/',         # OpenShift extended resources
    'k8s.io/',               # Kubernetes extended resources
    'rdma/',                 # RDMA devices
    'hugepages-',            # Hugepages (special case)
]

# Standard resources to exclude from extended resource analysis
STANDARD_RESOURCES = {'cpu', 'memory', 'ephemeral-storage', 'pods'}


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


def is_extended_resource(resource_name):
    """Check if a resource name is an extended resource (not CPU/memory/pods)."""
    if resource_name in STANDARD_RESOURCES:
        return False
    # Check for known extended resource prefixes
    for prefix in EXTENDED_RESOURCE_PREFIXES:
        if resource_name.startswith(prefix):
            return True
    # Check for domain-prefixed resources (contain '/')
    if '/' in resource_name:
        return True
    # Hugepages special case
    if resource_name.startswith('hugepages-'):
        return True
    return False


def get_nodes():
    """Get all nodes with their capacity and allocatable resources."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    return json.loads(output)


def get_pods(namespace=None):
    """Get all pods in JSON format."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')
    output = run_kubectl(args)
    return json.loads(output)


def extract_node_extended_resources(nodes_data):
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
                    # Skip non-integer resources
                    pass

        if extended:
            node_resources[node_name] = {
                'resources': extended,
                'labels': node['metadata'].get('labels', {}),
                'conditions': {
                    c['type']: c['status']
                    for c in node.get('status', {}).get('conditions', [])
                }
            }

    return node_resources


def extract_pod_extended_requests(pods_data, namespace_filter=None):
    """Extract extended resource requests from pods."""
    pod_requests = []

    for pod in pods_data.get('items', []):
        pod_name = pod['metadata']['name']
        namespace = pod['metadata'].get('namespace', 'default')
        phase = pod.get('status', {}).get('phase', 'Unknown')
        node_name = pod.get('spec', {}).get('nodeName')

        # Get node selector and affinity
        node_selector = pod.get('spec', {}).get('nodeSelector', {})
        affinity = pod.get('spec', {}).get('affinity', {})

        # Collect extended resource requests from all containers
        extended_requests = {}
        containers = pod.get('spec', {}).get('containers', [])
        init_containers = pod.get('spec', {}).get('initContainers', [])

        for container in containers + init_containers:
            resources = container.get('resources', {})
            requests = resources.get('requests', {})
            limits = resources.get('limits', {})

            # Check both requests and limits for extended resources
            for resource, value in requests.items():
                if is_extended_resource(resource):
                    try:
                        count = int(value)
                        if resource not in extended_requests:
                            extended_requests[resource] = 0
                        extended_requests[resource] += count
                    except ValueError:
                        pass

            # Also check limits (some resources only specify limits)
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


def analyze_allocation(node_resources, pod_requests):
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

    # Check for pending pods requesting extended resources
    pending_pods = [p for p in pod_requests if p['phase'] == 'Pending']
    for pod in pending_pods:
        issues.append({
            'type': 'PENDING_POD',
            'severity': 'WARNING',
            'pod': f"{pod['namespace']}/{pod['name']}",
            'resources': pod['requests'],
            'message': f"Pod pending with extended resource requests: {pod['requests']}"
        })

    # Check for underutilized extended resources
    for node_name, node_data in node_resources.items():
        for resource, data in node_data['resources'].items():
            available = data['allocatable'] - data['requested']
            if available > 0 and data['allocatable'] > 0:
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
                        'message': f"Node {node_name}: {resource} is {utilization:.0f}% utilized ({data['requested']}/{data['allocatable']})"
                    })

    # Check for pods requesting extended resources without node constraints
    for pod in pod_requests:
        if pod['phase'] != 'Pending' and not pod['node_selector'] and not pod['has_affinity']:
            # Check if this resource is not available on all nodes
            resources_requested = set(pod['requests'].keys())
            nodes_with_all_resources = 0
            total_nodes = len(node_resources) if node_resources else 1

            for node_data in node_resources.values():
                node_has_all = all(
                    r in node_data['resources'] for r in resources_requested
                )
                if node_has_all:
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


def get_cluster_summary(node_resources, pod_requests):
    """Generate cluster-wide extended resource summary."""
    summary = {
        'total_nodes_with_extended': len(node_resources),
        'total_pods_using_extended': len(pod_requests),
        'resources': defaultdict(lambda: {
            'total_capacity': 0,
            'total_allocatable': 0,
            'total_requested': 0,
            'nodes': 0
        })
    }

    for node_name, node_data in node_resources.items():
        for resource, data in node_data['resources'].items():
            summary['resources'][resource]['total_capacity'] += data['capacity']
            summary['resources'][resource]['total_allocatable'] += data['allocatable']
            summary['resources'][resource]['total_requested'] += data['requested']
            summary['resources'][resource]['nodes'] += 1

    # Convert defaultdict to regular dict for JSON serialization
    summary['resources'] = dict(summary['resources'])

    return summary


def print_plain(node_resources, pod_requests, issues, summary, warn_only, verbose):
    """Print results in plain text format."""
    # Print summary
    print("=== Extended Resources Summary ===")
    print(f"Nodes with extended resources: {summary['total_nodes_with_extended']}")
    print(f"Pods using extended resources: {summary['total_pods_using_extended']}")
    print()

    if summary['resources']:
        print("Cluster-wide resource totals:")
        for resource, data in sorted(summary['resources'].items()):
            util_pct = (data['total_requested'] / data['total_allocatable'] * 100) if data['total_allocatable'] > 0 else 0
            print(f"  {resource}: {data['total_requested']}/{data['total_allocatable']} ({util_pct:.0f}% used) across {data['nodes']} nodes")
        print()

    # Print node details if verbose
    if verbose and node_resources:
        print("=== Node Extended Resources ===")
        for node_name, node_data in sorted(node_resources.items()):
            print(f"\nNode: {node_name}")
            for resource, data in sorted(node_data['resources'].items()):
                available = data['allocatable'] - data['requested']
                print(f"  {resource}: {data['requested']}/{data['allocatable']} (available: {available})")
                if data['pods']:
                    for pod in data['pods']:
                        print(f"    - {pod}")
        print()

    # Print issues
    if issues:
        print("=== Issues Detected ===")
        for issue in issues:
            if warn_only and issue['severity'] == 'INFO':
                continue
            marker = "!" if issue['severity'] == 'WARNING' else "*"
            print(f"[{marker}] {issue['message']}")
        print()

    # Print pending pods
    pending = [p for p in pod_requests if p['phase'] == 'Pending']
    if pending:
        print("=== Pending Pods with Extended Resources ===")
        for pod in pending:
            resources_str = ', '.join(f"{k}={v}" for k, v in pod['requests'].items())
            print(f"  {pod['namespace']}/{pod['name']}: {resources_str}")
        print()

    if not issues:
        print("No issues detected.")


def print_json(node_resources, pod_requests, issues, summary):
    """Print results in JSON format."""
    output = {
        'summary': summary,
        'nodes': node_resources,
        'pods': pod_requests,
        'issues': issues
    }
    print(json.dumps(output, indent=2, default=str))


def print_table(node_resources, pod_requests, issues, summary):
    """Print results in table format."""
    # Resource summary table
    print(f"{'Resource':<40} {'Nodes':<8} {'Requested':<12} {'Allocatable':<12} {'Utilization':<12}")
    print("-" * 84)

    for resource, data in sorted(summary['resources'].items()):
        util_pct = (data['total_requested'] / data['total_allocatable'] * 100) if data['total_allocatable'] > 0 else 0
        print(f"{resource:<40} {data['nodes']:<8} {data['total_requested']:<12} {data['total_allocatable']:<12} {util_pct:.0f}%")

    print()

    # Node resource table
    if node_resources:
        print(f"{'Node':<30} {'Resource':<35} {'Used':<8} {'Total':<8} {'Available':<10}")
        print("-" * 91)

        for node_name, node_data in sorted(node_resources.items()):
            for resource, data in sorted(node_data['resources'].items()):
                available = data['allocatable'] - data['requested']
                print(f"{node_name:<30} {resource:<35} {data['requested']:<8} {data['allocatable']:<8} {available:<10}")


def main():
    parser = argparse.ArgumentParser(
        description='Audit Kubernetes extended resources (GPUs, custom devices) and their allocation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Audit all extended resources cluster-wide
  %(prog)s -n gpu-workloads         # Audit extended resources in specific namespace
  %(prog)s --format json            # JSON output for scripting
  %(prog)s --format table           # Tabular output
  %(prog)s -w                       # Show only warnings (hide INFO)
  %(prog)s -v                       # Verbose output with per-pod details

Extended resources include:
  - NVIDIA GPUs (nvidia.com/gpu)
  - AMD GPUs (amd.com/gpu)
  - Intel devices (intel.com/*)
  - FPGAs (xilinx.com/*, fpga.intel.com/*)
  - SR-IOV devices (sriov.openshift.io/*)
  - Hugepages (hugepages-*)
  - Custom device plugin resources

Exit codes:
  0 - No issues detected
  1 - Issues found (underutilization, pending pods, misconfigurations)
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to audit (default: all namespaces)'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show warnings (hide INFO level issues)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed per-node and per-pod information'
    )

    args = parser.parse_args()

    # Get cluster data
    nodes_data = get_nodes()
    pods_data = get_pods(args.namespace)

    # Extract extended resources
    node_resources = extract_node_extended_resources(nodes_data)
    pod_requests = extract_pod_extended_requests(pods_data, args.namespace)

    # Analyze allocation
    issues = analyze_allocation(node_resources, pod_requests)

    # Generate summary
    summary = get_cluster_summary(node_resources, pod_requests)

    # Output results
    if args.format == 'json':
        print_json(node_resources, pod_requests, issues, summary)
    elif args.format == 'table':
        print_table(node_resources, pod_requests, issues, summary)
    else:
        print_plain(node_resources, pod_requests, issues, args.warn_only, args.verbose)

    # Exit code based on issues
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)
    sys.exit(1 if has_warnings else 0)


if __name__ == '__main__':
    main()
