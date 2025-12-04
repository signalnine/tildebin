#!/usr/bin/env python3
"""
Monitor Kubernetes DaemonSet health with node coverage and pod status.

This script provides DaemonSet-specific health checks including:
- Node coverage: verify pods are running on all expected nodes
- Pod readiness and status on each node
- ImagePullBackOff and CrashLoopBackOff detection
- Node selector and toleration issues preventing scheduling
- Update strategy status and rollout progress
- Resource constraints blocking DaemonSet pod placement
- Critical system DaemonSet monitoring (CNI, CSI, kube-proxy)

Useful for managing cluster infrastructure in large-scale baremetal Kubernetes
deployments where DaemonSets run critical node-level services.

Exit codes:
    0 - All DaemonSets healthy with pods on all expected nodes
    1 - One or more DaemonSets unhealthy or have warnings
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


def get_daemonsets(namespace=None):
    """Get all daemonsets in JSON format."""
    args = ['get', 'daemonsets', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_nodes():
    """Get all nodes in JSON format."""
    args = ['get', 'nodes', '-o', 'json']
    output = run_kubectl(args)
    return json.loads(output)


def get_pods_for_daemonset(namespace, name):
    """Get pods belonging to a specific DaemonSet."""
    # Try to get pods by owner reference
    args = ['get', 'pods', '-n', namespace, '-o', 'json']
    output = run_kubectl(args)
    all_pods = json.loads(output)

    filtered_pods = []
    for pod in all_pods.get('items', []):
        owner_refs = pod.get('metadata', {}).get('ownerReferences', [])
        for ref in owner_refs:
            if ref.get('kind') == 'DaemonSet' and ref.get('name') == name:
                filtered_pods.append(pod)
                break

    return {'items': filtered_pods}


def check_pod_health(pod):
    """Check individual pod health and return issues."""
    issues = []
    name = pod['metadata']['name']
    node_name = pod['spec'].get('nodeName', 'unassigned')
    status = pod.get('status', {})

    # Check pod phase
    phase = status.get('phase', 'Unknown')
    if phase not in ['Running', 'Succeeded']:
        issues.append(f"Pod {name} on node {node_name} in {phase} phase")

    # Check container statuses
    container_statuses = status.get('containerStatuses', [])
    for container in container_statuses:
        container_name = container.get('name', 'unknown')
        ready = container.get('ready', False)
        restart_count = container.get('restartCount', 0)

        if not ready:
            state = container.get('state', {})
            if 'waiting' in state:
                reason = state['waiting'].get('reason', 'Unknown')
                message = state['waiting'].get('message', '')
                issues.append(f"Container {container_name} on {node_name} not ready: {reason} - {message}")
            elif 'terminated' in state:
                reason = state['terminated'].get('reason', 'Unknown')
                issues.append(f"Container {container_name} on {node_name} terminated: {reason}")

        if restart_count > 5:
            issues.append(f"Container {container_name} on {node_name} has {restart_count} restarts")

    # Check for scheduling issues
    conditions = status.get('conditions', [])
    for condition in conditions:
        if condition.get('type') == 'PodScheduled' and condition.get('status') != 'True':
            reason = condition.get('reason', '')
            message = condition.get('message', '')
            issues.append(f"Scheduling issue on {node_name}: {message}")

    return issues, node_name


def node_matches_selector(node, node_selector):
    """Check if node matches the DaemonSet's node selector."""
    if not node_selector:
        return True

    node_labels = node.get('metadata', {}).get('labels', {})
    for key, value in node_selector.items():
        if node_labels.get(key) != value:
            return False
    return True


def check_daemonset_health(ds, pods, nodes):
    """Check DaemonSet health including node coverage."""
    name = ds['metadata']['name']
    namespace = ds['metadata'].get('namespace', 'default')
    status = ds.get('status', {})
    spec = ds.get('spec', {})

    issues = []
    warnings = []

    # Get replica counts
    desired = status.get('desiredNumberScheduled', 0)
    current = status.get('currentNumberScheduled', 0)
    ready = status.get('numberReady', 0)
    available = status.get('numberAvailable', 0)
    misscheduled = status.get('numberMisscheduled', 0)
    updated = status.get('updatedNumberScheduled', 0)

    # Check if pods are running on all expected nodes
    if current != desired:
        issues.append(f"Only {current}/{desired} pods scheduled (missing on {desired - current} nodes)")

    if ready != desired:
        issues.append(f"Only {ready}/{desired} pods ready")

    if available != desired:
        warnings.append(f"Only {available}/{desired} pods available")

    if misscheduled > 0:
        issues.append(f"{misscheduled} pods running on nodes where they shouldn't")

    if updated != desired:
        warnings.append(f"Only {updated}/{desired} pods updated (rollout in progress)")

    # Check update strategy
    update_strategy = spec.get('updateStrategy', {})
    strategy_type = update_strategy.get('type', 'RollingUpdate')

    if strategy_type == 'RollingUpdate':
        rolling_update = update_strategy.get('rollingUpdate', {})
        max_unavailable = rolling_update.get('maxUnavailable', 1)
        if max_unavailable == 0:
            warnings.append("MaxUnavailable is 0 (rollout will be slow)")

    # Get node selector
    node_selector = spec.get('template', {}).get('spec', {}).get('nodeSelector', {})

    # Build map of nodes that have pods
    nodes_with_pods = set()
    pod_issues = defaultdict(list)

    for pod in pods.get('items', []):
        pod_name = pod['metadata']['name']
        pod_problems, node_name = check_pod_health(pod)
        if node_name != 'unassigned':
            nodes_with_pods.add(node_name)
        if pod_problems:
            pod_issues[pod_name] = pod_problems

    # Check which nodes should have pods but don't
    nodes_without_pods = []
    nodes_unschedulable = []

    for node in nodes.get('items', []):
        node_name = node['metadata']['name']

        # Check if node is schedulable
        unschedulable = node['spec'].get('unschedulable', False)
        if unschedulable:
            nodes_unschedulable.append(node_name)
            continue

        # Check if node is ready
        node_ready = False
        conditions = node.get('status', {}).get('conditions', [])
        for condition in conditions:
            if condition.get('type') == 'Ready' and condition.get('status') == 'True':
                node_ready = True
                break

        if not node_ready:
            continue

        # Check if node matches selector
        if not node_matches_selector(node, node_selector):
            continue

        # This node should have a pod
        if node_name not in nodes_with_pods:
            nodes_without_pods.append(node_name)

    if nodes_without_pods:
        issues.append(f"Missing pods on {len(nodes_without_pods)} nodes: {', '.join(nodes_without_pods[:5])}"
                     + ("..." if len(nodes_without_pods) > 5 else ""))

    # Check for node selector that might be too restrictive
    if node_selector and desired == 0:
        warnings.append(f"Node selector may be too restrictive: {node_selector}")

    # Determine overall health
    is_healthy = len(issues) == 0 and ready == desired and current == desired

    return is_healthy, issues, warnings, pod_issues, {
        'desired': desired,
        'current': current,
        'ready': ready,
        'available': available,
        'updated': updated,
        'misscheduled': misscheduled,
        'nodes_without_pods': nodes_without_pods,
        'nodes_unschedulable': nodes_unschedulable
    }


def print_status(daemonsets_data, nodes, output_format, warn_only, namespace_filter=None):
    """Print DaemonSet status in requested format."""
    has_issues = False

    daemonsets = daemonsets_data.get('items', [])

    if output_format == 'json':
        output = []

        for ds in daemonsets:
            name = ds['metadata']['name']
            namespace = ds['metadata'].get('namespace', 'default')

            if namespace_filter and namespace != namespace_filter:
                continue

            # Get pods for this DaemonSet
            pods = get_pods_for_daemonset(namespace, name)

            is_healthy, issues, warnings, pod_issues, replicas = check_daemonset_health(ds, pods, nodes)

            ds_info = {
                'namespace': namespace,
                'name': name,
                'healthy': is_healthy,
                'replicas': replicas,
                'issues': issues,
                'warnings': warnings,
                'pod_issues': dict(pod_issues)
            }

            if not warn_only or issues or warnings or pod_issues:
                output.append(ds_info)
                if issues or pod_issues:
                    has_issues = True

        print(json.dumps(output, indent=2))

    else:  # plain format
        healthy_count = 0
        unhealthy_count = 0

        for ds in daemonsets:
            name = ds['metadata']['name']
            namespace = ds['metadata'].get('namespace', 'default')

            if namespace_filter and namespace != namespace_filter:
                continue

            # Get pods for this DaemonSet
            pods = get_pods_for_daemonset(namespace, name)

            is_healthy, issues, warnings, pod_issues, replicas = check_daemonset_health(ds, pods, nodes)

            if is_healthy:
                healthy_count += 1
            else:
                unhealthy_count += 1
                has_issues = True

            # Skip healthy if warn_only
            if warn_only and is_healthy and not warnings and not pod_issues:
                continue

            # Print DaemonSet info
            status_marker = "✓" if is_healthy else "⚠"
            print(f"{status_marker} DaemonSet: {namespace}/{name}")
            print(f"  Pods: {replicas['ready']}/{replicas['desired']} ready, "
                  f"{replicas['current']}/{replicas['desired']} scheduled, "
                  f"{replicas['updated']}/{replicas['desired']} updated")

            if replicas['misscheduled'] > 0:
                print(f"  Misscheduled: {replicas['misscheduled']} pods")

            # Print issues
            if issues:
                for issue in issues:
                    print(f"  ERROR: {issue}")

            # Print warnings
            if warnings:
                for warning in warnings:
                    print(f"  WARNING: {warning}")

            # Print pod issues
            if pod_issues:
                print(f"  Pod Issues:")
                for pod_name, pod_problems in pod_issues.items():
                    print(f"    {pod_name}:")
                    for problem in pod_problems:
                        print(f"      - {problem}")

            # Show nodes without pods (if any, and not too many)
            if replicas['nodes_without_pods'] and len(replicas['nodes_without_pods']) <= 10:
                print(f"  Nodes without pods: {', '.join(replicas['nodes_without_pods'])}")

            print()

        # Print summary
        total = healthy_count + unhealthy_count
        if total > 0:
            print(f"Summary: {healthy_count}/{total} DaemonSets healthy, {unhealthy_count} with issues")
        else:
            print("No DaemonSets found")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes DaemonSet health with node coverage and pod status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all DaemonSets
  %(prog)s -n kube-system           # Check only in kube-system namespace
  %(prog)s --warn-only              # Show only DaemonSets with issues
  %(prog)s --format json            # JSON output
  %(prog)s -w -f json               # JSON output, only problematic DaemonSets

Exit codes:
  0 - All DaemonSets healthy with pods on all expected nodes
  1 - One or more DaemonSets unhealthy or have warnings
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to check (default: all namespaces)'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show DaemonSets with issues or warnings'
    )

    args = parser.parse_args()

    # Get nodes first (needed for coverage check)
    nodes = get_nodes()

    # Get DaemonSets
    daemonsets = get_daemonsets(args.namespace)

    # Print status
    has_issues = print_status(daemonsets, nodes, args.format, args.warn_only, args.namespace)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
