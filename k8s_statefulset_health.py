#!/usr/bin/env python3
"""
Monitor Kubernetes StatefulSet health with detailed pod and PVC status.

This script provides StatefulSet-specific health checks including:
- Pod readiness and ordering (StatefulSets maintain stable pod identities)
- PersistentVolumeClaim binding status for each pod
- Partition rollout status (for staged rollouts)
- Pod restart counts and readiness
- Volume attachment issues
- StatefulSet update strategy validation

Useful for managing stateful applications like databases, message queues,
and distributed systems in large-scale Kubernetes deployments.

Exit codes:
    0 - All StatefulSets healthy with all pods ready
    1 - One or more StatefulSets unhealthy or have warnings
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


def get_statefulsets(namespace=None):
    """Get all statefulsets in JSON format."""
    args = ['get', 'statefulsets', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_pods_for_statefulset(namespace, name):
    """Get pods belonging to a specific StatefulSet."""
    args = ['get', 'pods', '-n', namespace, '-l', f'app.kubernetes.io/name={name}', '-o', 'json']
    output = run_kubectl(args)
    pods_data = json.loads(output)

    # If no pods found with standard label, try controller-revision-hash approach
    if not pods_data.get('items'):
        # Try alternative approach: get all pods and filter by owner reference
        args = ['get', 'pods', '-n', namespace, '-o', 'json']
        output = run_kubectl(args)
        all_pods = json.loads(output)

        filtered_pods = []
        for pod in all_pods.get('items', []):
            owner_refs = pod.get('metadata', {}).get('ownerReferences', [])
            for ref in owner_refs:
                if ref.get('kind') == 'StatefulSet' and ref.get('name') == name:
                    filtered_pods.append(pod)
                    break

        pods_data['items'] = filtered_pods

    return pods_data


def get_pvcs_for_namespace(namespace):
    """Get all PVCs in a namespace."""
    args = ['get', 'pvc', '-n', namespace, '-o', 'json']
    output = run_kubectl(args)
    return json.loads(output)


def check_pod_health(pod):
    """Check individual pod health and return issues."""
    issues = []
    name = pod['metadata']['name']
    status = pod.get('status', {})

    # Check pod phase
    phase = status.get('phase', 'Unknown')
    if phase not in ['Running', 'Succeeded']:
        issues.append(f"Pod {name} in {phase} phase")

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
                issues.append(f"Container {container_name} not ready: {reason} - {message}")
            elif 'terminated' in state:
                reason = state['terminated'].get('reason', 'Unknown')
                issues.append(f"Container {container_name} terminated: {reason}")

        if restart_count > 5:
            issues.append(f"Container {container_name} has {restart_count} restarts")

    # Check for unbound volumes
    conditions = status.get('conditions', [])
    for condition in conditions:
        if condition.get('type') == 'PodScheduled' and condition.get('status') != 'True':
            reason = condition.get('reason', '')
            message = condition.get('message', '')
            if 'volume' in message.lower() or 'pvc' in message.lower():
                issues.append(f"Volume binding issue: {message}")

    return issues


def check_statefulset_health(sts, pods, pvcs):
    """Check StatefulSet health including pods and PVCs."""
    name = sts['metadata']['name']
    namespace = sts['metadata'].get('namespace', 'default')
    status = sts.get('status', {})
    spec = sts.get('spec', {})

    issues = []
    warnings = []

    # Check replica counts
    desired = spec.get('replicas', 0)
    ready = status.get('readyReplicas', 0)
    current = status.get('currentReplicas', 0)
    updated = status.get('updatedReplicas', 0)

    if ready != desired:
        issues.append(f"Only {ready}/{desired} replicas ready")

    if current != desired:
        warnings.append(f"Current replicas: {current}/{desired}")

    if updated != desired:
        warnings.append(f"Updated replicas: {updated}/{desired}")

    # Check update strategy
    update_strategy = spec.get('updateStrategy', {})
    strategy_type = update_strategy.get('type', 'RollingUpdate')

    if strategy_type == 'RollingUpdate':
        rolling_update = update_strategy.get('rollingUpdate', {})
        partition = rolling_update.get('partition', 0)

        if partition > 0:
            warnings.append(f"Partition set to {partition} (staged rollout in progress)")

    # Check for stalled rollout
    observed_generation = status.get('observedGeneration', 0)
    generation = sts['metadata'].get('generation', 0)

    if observed_generation < generation:
        issues.append("StatefulSet generation not yet observed (update pending)")

    # Check individual pods
    pod_issues = defaultdict(list)
    for pod in pods.get('items', []):
        pod_name = pod['metadata']['name']
        pod_problems = check_pod_health(pod)
        if pod_problems:
            pod_issues[pod_name] = pod_problems

    # Check PVC status for volumeClaimTemplates
    volume_claim_templates = spec.get('volumeClaimTemplates', [])
    if volume_claim_templates:
        pvc_map = {}
        for pvc in pvcs.get('items', []):
            pvc_name = pvc['metadata']['name']
            pvc_map[pvc_name] = pvc

        # Check if all expected PVCs exist and are bound
        for i in range(desired):
            for template in volume_claim_templates:
                template_name = template['metadata']['name']
                expected_pvc_name = f"{template_name}-{name}-{i}"

                if expected_pvc_name not in pvc_map:
                    issues.append(f"Missing PVC: {expected_pvc_name}")
                else:
                    pvc = pvc_map[expected_pvc_name]
                    pvc_phase = pvc.get('status', {}).get('phase', 'Unknown')
                    if pvc_phase != 'Bound':
                        issues.append(f"PVC {expected_pvc_name} not bound (phase: {pvc_phase})")

    # Determine overall health
    is_healthy = len(issues) == 0 and ready == desired

    return is_healthy, issues, warnings, pod_issues, {
        'desired': desired,
        'ready': ready,
        'current': current,
        'updated': updated
    }


def print_status(statefulsets_data, output_format, warn_only, namespace_filter=None):
    """Print StatefulSet status in requested format."""
    has_issues = False

    statefulsets = statefulsets_data.get('items', [])

    if output_format == 'json':
        output = []

        for sts in statefulsets:
            name = sts['metadata']['name']
            namespace = sts['metadata'].get('namespace', 'default')

            if namespace_filter and namespace != namespace_filter:
                continue

            # Get pods and PVCs for this StatefulSet
            pods = get_pods_for_statefulset(namespace, name)
            pvcs = get_pvcs_for_namespace(namespace)

            is_healthy, issues, warnings, pod_issues, replicas = check_statefulset_health(sts, pods, pvcs)

            sts_info = {
                'namespace': namespace,
                'name': name,
                'healthy': is_healthy,
                'replicas': replicas,
                'issues': issues,
                'warnings': warnings,
                'pod_issues': dict(pod_issues)
            }

            if not warn_only or issues or warnings or pod_issues:
                output.append(sts_info)
                if issues or pod_issues:
                    has_issues = True

        print(json.dumps(output, indent=2))

    else:  # plain format
        healthy_count = 0
        unhealthy_count = 0

        for sts in statefulsets:
            name = sts['metadata']['name']
            namespace = sts['metadata'].get('namespace', 'default')

            if namespace_filter and namespace != namespace_filter:
                continue

            # Get pods and PVCs for this StatefulSet
            pods = get_pods_for_statefulset(namespace, name)
            pvcs = get_pvcs_for_namespace(namespace)

            is_healthy, issues, warnings, pod_issues, replicas = check_statefulset_health(sts, pods, pvcs)

            if is_healthy:
                healthy_count += 1
            else:
                unhealthy_count += 1
                has_issues = True

            # Skip healthy if warn_only
            if warn_only and is_healthy and not warnings and not pod_issues:
                continue

            # Print StatefulSet info
            status_marker = "✓" if is_healthy else "⚠"
            print(f"{status_marker} StatefulSet: {namespace}/{name}")
            print(f"  Replicas: {replicas['ready']}/{replicas['desired']} ready, "
                  f"{replicas['updated']}/{replicas['desired']} updated, "
                  f"{replicas['current']}/{replicas['desired']} current")

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

            print()

        # Print summary
        total = healthy_count + unhealthy_count
        if total > 0:
            print(f"Summary: {healthy_count}/{total} StatefulSets healthy, {unhealthy_count} with issues")
        else:
            print("No StatefulSets found")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes StatefulSet health with detailed pod and PVC status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all StatefulSets
  %(prog)s -n production            # Check only in production namespace
  %(prog)s --warn-only              # Show only StatefulSets with issues
  %(prog)s --format json            # JSON output
  %(prog)s -w -f json               # JSON output, only problematic StatefulSets

Exit codes:
  0 - All StatefulSets healthy with all pods ready
  1 - One or more StatefulSets unhealthy or have warnings
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
        help='Only show StatefulSets with issues or warnings'
    )

    args = parser.parse_args()

    # Get StatefulSets
    statefulsets = get_statefulsets(args.namespace)

    # Print status
    has_issues = print_status(statefulsets, args.format, args.warn_only, args.namespace)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
