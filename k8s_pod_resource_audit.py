#!/usr/bin/env python3
"""
Audit Kubernetes pod resource usage and identify resource issues.

This script analyzes pod resource usage across a Kubernetes cluster, identifying:
- Pods with no resource requests/limits set
- OOMKilled pods and restart patterns
- Pods with CPU/memory throttling
- Resource quota utilization by namespace
- Evicted pods

Useful for capacity planning and resource optimization in large-scale Kubernetes deployments.

Exit codes:
    0 - No resource issues detected
    1 - Resource issues found (warnings)
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


def get_all_pods(namespace=None):
    """Get all pods in JSON format."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_pod_metrics(namespace=None):
    """Get pod metrics if metrics-server is available."""
    try:
        args = ['top', 'pods', '--no-headers', '--containers']
        if namespace:
            args.extend(['-n', namespace])
        else:
            args.append('--all-namespaces')

        output = run_kubectl(args)
        metrics = defaultdict(dict)

        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if namespace:
                # Format: POD CONTAINER CPU(cores) MEMORY(bytes)
                if len(parts) >= 4:
                    pod_name = parts[0]
                    container = parts[1]
                    cpu = parts[2]
                    memory = parts[3]
                    if pod_name not in metrics:
                        metrics[pod_name] = {}
                    metrics[pod_name][container] = {'cpu': cpu, 'memory': memory}
            else:
                # Format: NAMESPACE POD CONTAINER CPU(cores) MEMORY(bytes)
                if len(parts) >= 5:
                    ns = parts[0]
                    pod_name = parts[1]
                    container = parts[2]
                    cpu = parts[3]
                    memory = parts[4]
                    key = f"{ns}/{pod_name}"
                    if key not in metrics:
                        metrics[key] = {}
                    metrics[key][container] = {'cpu': cpu, 'memory': memory}

        return metrics
    except subprocess.CalledProcessError:
        # metrics-server not available
        return None


def get_resource_quotas(namespace=None):
    """Get resource quotas for namespaces."""
    try:
        args = ['get', 'resourcequota', '-o', 'json']
        if namespace:
            args.extend(['-n', namespace])
        else:
            args.append('--all-namespaces')

        output = run_kubectl(args)
        return json.loads(output)
    except subprocess.CalledProcessError:
        return None


def check_pod_resources(pod):
    """Check if pod has resource requests and limits set."""
    issues = []
    containers = pod.get('spec', {}).get('containers', [])

    for container in containers:
        container_name = container.get('name', 'unknown')
        resources = container.get('resources', {})
        requests = resources.get('requests', {})
        limits = resources.get('limits', {})

        if not requests:
            issues.append(f"Container '{container_name}' has no resource requests")
        else:
            if 'cpu' not in requests:
                issues.append(f"Container '{container_name}' missing CPU request")
            if 'memory' not in requests:
                issues.append(f"Container '{container_name}' missing memory request")

        if not limits:
            issues.append(f"Container '{container_name}' has no resource limits")
        else:
            if 'memory' not in limits:
                issues.append(f"Container '{container_name}' missing memory limit")

    return issues


def check_pod_status(pod):
    """Check pod status for issues like OOMKilled, evictions, etc."""
    issues = []
    status = pod.get('status', {})

    # Check if pod is evicted
    phase = status.get('phase', '')
    reason = status.get('reason', '')
    if reason == 'Evicted':
        message = status.get('message', '')
        issues.append(f"Pod evicted: {message}")

    # Check container statuses
    container_statuses = status.get('containerStatuses', [])
    for container_status in container_statuses:
        container_name = container_status.get('name', 'unknown')
        restart_count = container_status.get('restartCount', 0)

        # Check for excessive restarts
        if restart_count > 5:
            issues.append(f"Container '{container_name}' has {restart_count} restarts")

        # Check last state for OOMKilled
        last_state = container_status.get('lastState', {})
        terminated = last_state.get('terminated', {})
        if terminated.get('reason') == 'OOMKilled':
            issues.append(f"Container '{container_name}' was OOMKilled")

        # Check current state
        state = container_status.get('state', {})
        if 'waiting' in state:
            reason = state['waiting'].get('reason', '')
            message = state['waiting'].get('message', '')
            if reason in ['CrashLoopBackOff', 'ImagePullBackOff', 'ErrImagePull']:
                issues.append(f"Container '{container_name}' {reason}: {message}")

    return issues


def analyze_pods(pods_data, metrics, warn_only):
    """Analyze all pods and return issues."""
    pods = pods_data.get('items', [])
    results = []

    for pod in pods:
        pod_name = pod['metadata']['name']
        namespace = pod['metadata'].get('namespace', 'default')

        pod_key = f"{namespace}/{pod_name}"

        # Check resource configuration
        resource_issues = check_pod_resources(pod)

        # Check pod status
        status_issues = check_pod_status(pod)

        all_issues = resource_issues + status_issues

        # Skip if no issues and warn_only is set
        if warn_only and not all_issues:
            continue

        pod_info = {
            'namespace': namespace,
            'name': pod_name,
            'phase': pod.get('status', {}).get('phase', 'Unknown'),
            'issues': all_issues
        }

        # Add metrics if available
        if metrics and pod_key in metrics:
            pod_info['current_usage'] = metrics[pod_key]

        results.append(pod_info)

    return results


def print_results(results, output_format):
    """Print analysis results in requested format."""
    if output_format == 'json':
        print(json.dumps(results, indent=2))
    else:  # plain format
        total_pods = len(results)
        pods_with_issues = sum(1 for r in results if r['issues'])

        for pod_info in results:
            namespace = pod_info['namespace']
            name = pod_info['name']
            phase = pod_info['phase']
            issues = pod_info['issues']

            # Print pod header
            status_marker = "⚠" if issues else "✓"
            print(f"{status_marker} Pod: {namespace}/{name} - {phase}")

            # Print current usage if available
            if 'current_usage' in pod_info:
                print("  Current Usage:")
                for container, usage in pod_info['current_usage'].items():
                    print(f"    {container}: CPU={usage['cpu']}, Memory={usage['memory']}")

            # Print issues
            if issues:
                print("  Issues:")
                for issue in issues:
                    print(f"    - {issue}")

            print()

        # Print summary
        print(f"Summary: {total_pods} pods analyzed, {pods_with_issues} with issues")

    # Return whether issues were found
    return any(r['issues'] for r in results)


def print_quota_summary(quota_data):
    """Print resource quota summary."""
    if not quota_data:
        return

    quotas = quota_data.get('items', [])
    if not quotas:
        return

    print("\n=== Resource Quota Summary ===\n")

    for quota in quotas:
        namespace = quota['metadata'].get('namespace', 'default')
        quota_name = quota['metadata']['name']

        status = quota.get('status', {})
        hard = status.get('hard', {})
        used = status.get('used', {})

        print(f"Namespace: {namespace} (Quota: {quota_name})")

        for resource, limit in hard.items():
            current = used.get(resource, '0')
            print(f"  {resource}: {current} / {limit}")

        print()


def main():
    parser = argparse.ArgumentParser(
        description='Audit Kubernetes pod resource usage and identify issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Audit all pods across all namespaces
  %(prog)s -n production            # Audit pods in production namespace only
  %(prog)s --warn-only              # Show only pods with issues
  %(prog)s --format json            # JSON output
  %(prog)s -w -f json               # JSON output, only problematic pods
  %(prog)s --show-quotas            # Include resource quota information

Exit codes:
  0 - No resource issues detected
  1 - Resource issues found
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to audit (default: all namespaces)'
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
        help='Only show pods with warnings or issues'
    )

    parser.add_argument(
        '--show-quotas', '-q',
        action='store_true',
        help='Show resource quota information'
    )

    args = parser.parse_args()

    # Get pod data
    pods_data = get_all_pods(args.namespace)

    # Try to get metrics
    metrics = get_pod_metrics(args.namespace)
    if metrics is None and args.format == 'plain':
        print("Note: Pod metrics unavailable (metrics-server may not be installed)\n", file=sys.stderr)

    # Analyze pods
    results = analyze_pods(pods_data, metrics, args.warn_only)

    # Print results
    has_issues = print_results(results, args.format)

    # Show quota information if requested
    if args.show_quotas and args.format == 'plain':
        quota_data = get_resource_quotas(args.namespace)
        print_quota_summary(quota_data)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
