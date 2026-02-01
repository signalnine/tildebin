#!/usr/bin/env python3
"""
Analyze Kubernetes pending pods and identify scheduling failure root causes.

This script identifies why pods are stuck in Pending state and provides
actionable insights for resolution. It analyzes scheduling conditions,
resource constraints, node selectors, affinity rules, and taints/tolerations.

Common causes detected:
- Insufficient CPU/memory resources
- Node selector mismatches
- Affinity/anti-affinity rule failures
- Taint/toleration issues
- PersistentVolumeClaim binding failures
- Unschedulable nodes

Useful for:
- Troubleshooting delayed pod deployments
- Capacity planning based on unschedulable workloads
- Identifying misconfigured node selectors or affinities
- Detecting resource exhaustion in the cluster

Exit codes:
    0 - No pending pods found
    1 - One or more pending pods detected
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


def get_pending_pods(namespace=None):
    """Get all pods in Pending state."""
    args = ['get', 'pods', '-o', 'json', '--field-selector=status.phase=Pending']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_nodes():
    """Get all nodes with their conditions and resources."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    return json.loads(output)


def get_events_for_pod(namespace, pod_name):
    """Get events related to a specific pod."""
    try:
        output = run_kubectl([
            'get', 'events', '-n', namespace,
            '--field-selector', f'involvedObject.name={pod_name}',
            '-o', 'json'
        ])
        return json.loads(output)
    except subprocess.CalledProcessError:
        return {'items': []}


def parse_resource_value(value_str, resource_type='cpu'):
    """
    Parse Kubernetes resource value to a numeric format.

    For CPU: Returns millicores (e.g., "100m" -> 100, "1" -> 1000)
    For memory: Returns bytes (e.g., "1Gi" -> 1073741824)
    """
    if not value_str:
        return 0

    value_str = str(value_str).strip()

    if resource_type == 'cpu':
        if value_str.endswith('m'):
            return int(value_str[:-1])
        else:
            return int(float(value_str) * 1000)

    # Memory
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

    for suffix, multiplier in sorted(units.items(), key=lambda x: -len(x[0])):
        if value_str.endswith(suffix):
            return int(float(value_str[:-len(suffix)]) * multiplier)

    return int(value_str)


def analyze_scheduling_failure(pod, nodes_data, events):
    """
    Analyze why a pod is pending and identify the root cause.

    Returns:
        dict with 'category', 'reason', 'details', and 'suggestion'
    """
    pod_name = pod.get('metadata', {}).get('name', 'unknown')
    namespace = pod.get('metadata', {}).get('namespace', 'default')
    spec = pod.get('spec', {})
    status = pod.get('status', {})
    conditions = status.get('conditions', [])

    # Check for scheduler events
    scheduler_messages = []
    for event in events.get('items', []):
        if event.get('reason') in ['FailedScheduling', 'Unschedulable']:
            msg = event.get('message', '')
            scheduler_messages.append(msg)

    # Analyze the most recent scheduler message
    latest_message = scheduler_messages[0] if scheduler_messages else ''

    # Check for resource constraints
    containers = spec.get('containers', [])
    total_cpu_request = 0
    total_memory_request = 0

    for container in containers:
        resources = container.get('resources', {})
        requests = resources.get('requests', {})
        total_cpu_request += parse_resource_value(requests.get('cpu', '0'), 'cpu')
        total_memory_request += parse_resource_value(requests.get('memory', '0'), 'memory')

    # Categorize the failure
    if 'Insufficient cpu' in latest_message or 'cpu' in latest_message.lower() and 'insufficient' in latest_message.lower():
        return {
            'category': 'RESOURCES',
            'reason': 'Insufficient CPU',
            'details': f"Requested {total_cpu_request}m CPU; {latest_message[:100]}",
            'suggestion': 'Scale up cluster or reduce CPU requests'
        }

    if 'Insufficient memory' in latest_message or 'memory' in latest_message.lower() and 'insufficient' in latest_message.lower():
        memory_gb = total_memory_request / (1024 ** 3)
        return {
            'category': 'RESOURCES',
            'reason': 'Insufficient memory',
            'details': f"Requested {memory_gb:.2f}Gi memory; {latest_message[:100]}",
            'suggestion': 'Scale up cluster or reduce memory requests'
        }

    # Check for node selector issues
    node_selector = spec.get('nodeSelector', {})
    if node_selector and ('node' in latest_message.lower() and 'match' in latest_message.lower()):
        selector_str = ', '.join(f'{k}={v}' for k, v in node_selector.items())
        return {
            'category': 'NODE_SELECTOR',
            'reason': 'No matching nodes',
            'details': f"nodeSelector: {selector_str}",
            'suggestion': 'Add matching labels to nodes or update nodeSelector'
        }

    # Check for affinity/anti-affinity issues
    affinity = spec.get('affinity', {})
    if affinity and 'affinity' in latest_message.lower():
        affinity_type = 'nodeAffinity' if 'nodeAffinity' in affinity else 'podAffinity/podAntiAffinity'
        return {
            'category': 'AFFINITY',
            'reason': 'Affinity rules not satisfied',
            'details': f"{affinity_type} constraints cannot be met",
            'suggestion': 'Review affinity rules or add nodes matching requirements'
        }

    # Check for taint/toleration issues
    tolerations = spec.get('tolerations', [])
    if 'taint' in latest_message.lower() or 'toleration' in latest_message.lower():
        return {
            'category': 'TAINTS',
            'reason': 'Taint/toleration mismatch',
            'details': f"Pod has {len(tolerations)} tolerations but cannot tolerate node taints",
            'suggestion': 'Add required tolerations or remove taints from nodes'
        }

    # Check for PVC binding issues
    volumes = spec.get('volumes', [])
    pvc_volumes = [v for v in volumes if 'persistentVolumeClaim' in v]
    if pvc_volumes and ('pvc' in latest_message.lower() or 'persistentvolumeclaim' in latest_message.lower() or 'volume' in latest_message.lower()):
        pvc_names = [v['persistentVolumeClaim']['claimName'] for v in pvc_volumes]
        return {
            'category': 'STORAGE',
            'reason': 'PVC binding pending',
            'details': f"Waiting for PVCs: {', '.join(pvc_names)}",
            'suggestion': 'Check PVC status and storage provisioner'
        }

    # Check for unschedulable condition
    for condition in conditions:
        if condition.get('type') == 'PodScheduled' and condition.get('status') == 'False':
            reason = condition.get('reason', 'Unknown')
            message = condition.get('message', '')[:100]
            return {
                'category': 'SCHEDULING',
                'reason': reason,
                'details': message,
                'suggestion': 'Check scheduler logs and node availability'
            }

    # Check node availability
    nodes = nodes_data.get('items', [])
    schedulable_nodes = 0
    for node in nodes:
        node_spec = node.get('spec', {})
        if not node_spec.get('unschedulable', False):
            # Check if node is ready
            node_conditions = node.get('status', {}).get('conditions', [])
            for cond in node_conditions:
                if cond.get('type') == 'Ready' and cond.get('status') == 'True':
                    schedulable_nodes += 1
                    break

    if schedulable_nodes == 0:
        return {
            'category': 'NODES',
            'reason': 'No schedulable nodes',
            'details': 'All nodes are either unschedulable or NotReady',
            'suggestion': 'Check node health and cordoned status'
        }

    # Default case - check for any scheduler message
    if latest_message:
        return {
            'category': 'UNKNOWN',
            'reason': 'Scheduling failed',
            'details': latest_message[:150],
            'suggestion': 'Review scheduler events for more details'
        }

    # No events found
    return {
        'category': 'PENDING',
        'reason': 'Waiting for scheduler',
        'details': 'No scheduling events found yet',
        'suggestion': 'Pod may be newly created; wait or check scheduler health'
    }


def format_output_plain(pending_pods):
    """Format output as plain text."""
    for pod in pending_pods:
        ns = pod['namespace']
        name = pod['name']
        category = pod['analysis']['category']
        reason = pod['analysis']['reason']
        print(f"{ns} {name} {category} {reason}")


def format_output_table(pending_pods):
    """Format output as ASCII table."""
    print(f"{'NAMESPACE':<25} {'POD NAME':<40} {'CATEGORY':<15} {'REASON':<30} {'SUGGESTION':<40}")
    print("-" * 150)

    for pod in pending_pods:
        ns = pod['namespace'][:24]
        name = pod['name'][:39]
        category = pod['analysis']['category'][:14]
        reason = pod['analysis']['reason'][:29]
        suggestion = pod['analysis']['suggestion'][:39]
        print(f"{ns:<25} {name:<40} {category:<15} {reason:<30} {suggestion:<40}")


def format_output_json(pending_pods):
    """Format output as JSON."""
    output = {
        'pending_count': len(pending_pods),
        'by_category': defaultdict(int),
        'pods': pending_pods
    }

    for pod in pending_pods:
        output['by_category'][pod['analysis']['category']] += 1

    output['by_category'] = dict(output['by_category'])
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes pending pods and identify root causes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all pending pods in the cluster
  k8s_pending_pod_analyzer.py

  # Check pending pods in a specific namespace
  k8s_pending_pod_analyzer.py -n production

  # Get JSON output for automation
  k8s_pending_pod_analyzer.py --format json

  # Show summary by category
  k8s_pending_pod_analyzer.py -f json | jq '.by_category'
        """
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed analysis including suggestions"
    )

    args = parser.parse_args()

    # Get pending pods
    pods_data = get_pending_pods(args.namespace)
    pods = pods_data.get('items', [])

    if not pods:
        if args.format == "json":
            print(json.dumps({'pending_count': 0, 'by_category': {}, 'pods': []}, indent=2))
        else:
            print("No pending pods found", file=sys.stderr)
        sys.exit(0)

    # Get nodes for analysis
    nodes_data = get_nodes()

    # Analyze each pending pod
    pending_pods = []

    for pod in pods:
        namespace = pod.get('metadata', {}).get('namespace', 'default')
        pod_name = pod.get('metadata', {}).get('name', 'unknown')

        # Get events for this pod
        events = get_events_for_pod(namespace, pod_name)

        # Analyze scheduling failure
        analysis = analyze_scheduling_failure(pod, nodes_data, events)

        pending_pods.append({
            'namespace': namespace,
            'name': pod_name,
            'age': pod.get('metadata', {}).get('creationTimestamp', 'unknown'),
            'analysis': analysis
        })

    # Sort by category for readability
    pending_pods.sort(key=lambda x: (x['analysis']['category'], x['namespace'], x['name']))

    # Output results
    if args.format == "plain":
        format_output_plain(pending_pods)
    elif args.format == "table":
        format_output_table(pending_pods)
    elif args.format == "json":
        format_output_json(pending_pods)

    # Exit with code 1 if pending pods found
    sys.exit(1)


if __name__ == "__main__":
    main()
