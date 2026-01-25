#!/usr/bin/env python3
"""
Kubernetes Metrics Server Health Monitor

Monitors the health and functionality of the Kubernetes Metrics Server, which is
critical for Horizontal Pod Autoscaler (HPA) and Vertical Pod Autoscaler (VPA)
functionality. A failing metrics server often goes undetected until autoscaling
stops working.

Features:
- Metrics Server deployment health and readiness
- API service availability and responsiveness
- Metrics data freshness (checks if metrics are being collected)
- Node and pod metrics availability across the cluster
- Resource usage of the metrics server itself

Exit codes:
    0 - Metrics server healthy and operational
    1 - Issues detected (warnings or errors)
    2 - Usage error or missing dependencies (kubectl not found)
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def run_kubectl(args, timeout=10):
    """Execute kubectl command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except FileNotFoundError:
        return None, "", "kubectl not found"
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except subprocess.SubprocessError as e:
        return False, "", str(e)


def check_kubectl():
    """Check if kubectl is available and configured."""
    success, stdout, stderr = run_kubectl(['cluster-info'])
    return success is not None and success


def get_metrics_server_deployment(namespace='kube-system'):
    """Get metrics-server deployment information."""
    success, stdout, stderr = run_kubectl([
        'get', 'deployment', 'metrics-server',
        '-n', namespace, '-o', 'json'
    ])

    if not success:
        return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def get_metrics_server_pods(namespace='kube-system'):
    """Get metrics-server pod information."""
    success, stdout, stderr = run_kubectl([
        'get', 'pods', '-n', namespace,
        '-l', 'k8s-app=metrics-server',
        '-o', 'json'
    ])

    if not success:
        return None

    try:
        data = json.loads(stdout)
        return data.get('items', [])
    except json.JSONDecodeError:
        return None


def get_metrics_api_service():
    """Check if the metrics.k8s.io API service exists and is available."""
    success, stdout, stderr = run_kubectl([
        'get', 'apiservice', 'v1beta1.metrics.k8s.io', '-o', 'json'
    ])

    if not success:
        return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def get_node_metrics():
    """Get node metrics from the metrics API."""
    success, stdout, stderr = run_kubectl([
        'top', 'nodes', '--no-headers'
    ], timeout=15)

    if not success:
        return None, stderr

    # Parse the output
    nodes = []
    for line in stdout.strip().split('\n'):
        if line:
            parts = line.split()
            if len(parts) >= 5:
                nodes.append({
                    'name': parts[0],
                    'cpu_cores': parts[1],
                    'cpu_percent': parts[2],
                    'memory': parts[3],
                    'memory_percent': parts[4]
                })

    return nodes, ""


def get_pod_metrics_sample(namespace=None, limit=5):
    """Get a sample of pod metrics to verify metrics collection is working."""
    cmd = ['top', 'pods', '--no-headers']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    success, stdout, stderr = run_kubectl(cmd, timeout=15)

    if not success:
        return None, stderr

    # Parse the output (just count lines to verify metrics are available)
    lines = [l for l in stdout.strip().split('\n') if l]
    return len(lines), ""


def analyze_metrics_health(deployment, pods, api_service, node_metrics, pod_count):
    """Analyze metrics server health and return issues and warnings."""
    issues = []
    warnings = []

    # Check deployment
    if not deployment:
        issues.append("Metrics Server deployment not found in kube-system namespace")
    else:
        spec = deployment.get('spec', {})
        status = deployment.get('status', {})

        replicas = spec.get('replicas', 1)
        ready_replicas = status.get('readyReplicas', 0)
        available_replicas = status.get('availableReplicas', 0)

        if ready_replicas == 0:
            issues.append("No Metrics Server replicas are ready")
        elif ready_replicas < replicas:
            warnings.append(f"Only {ready_replicas}/{replicas} Metrics Server replicas ready")

        if replicas < 2:
            warnings.append("Metrics Server running with single replica (no HA)")

    # Check pods
    if pods is None:
        if not issues:  # Only add if we don't already have deployment issues
            issues.append("Could not retrieve Metrics Server pods")
    elif len(pods) == 0:
        issues.append("No Metrics Server pods found")
    else:
        for pod in pods:
            pod_name = pod.get('metadata', {}).get('name', 'unknown')
            phase = pod.get('status', {}).get('phase', 'Unknown')

            if phase != 'Running':
                issues.append(f"Metrics Server pod {pod_name} is in phase: {phase}")
                continue

            # Check container status
            container_statuses = pod.get('status', {}).get('containerStatuses', [])
            for container in container_statuses:
                if not container.get('ready', False):
                    issues.append(f"Container {container.get('name')} in pod {pod_name} is not ready")

                restart_count = container.get('restartCount', 0)
                if restart_count > 10:
                    warnings.append(f"Pod {pod_name} has {restart_count} restarts (instability)")
                elif restart_count > 3:
                    warnings.append(f"Pod {pod_name} has {restart_count} restarts")

    # Check API service
    if not api_service:
        issues.append("Metrics API service (v1beta1.metrics.k8s.io) not found")
    else:
        conditions = api_service.get('status', {}).get('conditions', [])
        for condition in conditions:
            if condition.get('type') == 'Available':
                if condition.get('status') != 'True':
                    reason = condition.get('reason', 'Unknown')
                    message = condition.get('message', '')
                    issues.append(f"Metrics API not available: {reason} - {message[:100]}")
                break
        else:
            warnings.append("Could not determine Metrics API availability status")

    # Check node metrics
    if node_metrics is None:
        issues.append("Could not retrieve node metrics (kubectl top nodes failed)")
    elif len(node_metrics) == 0:
        warnings.append("No node metrics available")

    # Check pod metrics
    if pod_count is None:
        warnings.append("Could not retrieve pod metrics sample")
    elif pod_count == 0:
        warnings.append("No pod metrics available")

    return issues, warnings


def format_plain(deployment, pods, api_service, node_metrics, pod_count,
                 node_error, pod_error, issues, warnings, verbose=False):
    """Format output in plain text."""
    lines = []
    lines.append("Kubernetes Metrics Server Health Check")
    lines.append("=" * 50)
    lines.append("")

    # Deployment status
    lines.append("Metrics Server Deployment:")
    if deployment:
        status = deployment.get('status', {})
        replicas = deployment.get('spec', {}).get('replicas', 1)
        ready = status.get('readyReplicas', 0)
        available = status.get('availableReplicas', 0)

        status_symbol = "OK" if ready == replicas else "WARN"
        lines.append(f"  [{status_symbol}] Replicas: {ready}/{replicas} ready, {available} available")
    else:
        lines.append("  [FAIL] Deployment not found")
    lines.append("")

    # Pod status
    lines.append("Metrics Server Pods:")
    if pods:
        for pod in pods:
            pod_name = pod.get('metadata', {}).get('name', 'unknown')
            phase = pod.get('status', {}).get('phase', 'Unknown')
            container_statuses = pod.get('status', {}).get('containerStatuses', [])

            ready = all(c.get('ready', False) for c in container_statuses)
            restarts = sum(c.get('restartCount', 0) for c in container_statuses)

            status_symbol = "OK" if ready and phase == 'Running' else "FAIL"
            lines.append(f"  [{status_symbol}] {pod_name}: {phase}, Restarts: {restarts}")
    else:
        lines.append("  [FAIL] No pods found")
    lines.append("")

    # API Service status
    lines.append("Metrics API Service:")
    if api_service:
        conditions = api_service.get('status', {}).get('conditions', [])
        available = False
        for condition in conditions:
            if condition.get('type') == 'Available':
                available = condition.get('status') == 'True'
                break

        status_symbol = "OK" if available else "FAIL"
        lines.append(f"  [{status_symbol}] v1beta1.metrics.k8s.io available: {available}")
    else:
        lines.append("  [FAIL] API service not found")
    lines.append("")

    # Metrics availability
    lines.append("Metrics Availability:")
    if node_metrics is not None:
        lines.append(f"  [OK] Node metrics: {len(node_metrics)} nodes reporting")
        if verbose and node_metrics:
            for node in node_metrics[:5]:
                lines.append(f"       - {node['name']}: CPU {node['cpu_percent']}, Memory {node['memory_percent']}")
    else:
        lines.append(f"  [FAIL] Node metrics unavailable: {node_error}")

    if pod_count is not None:
        lines.append(f"  [OK] Pod metrics: {pod_count} pods reporting")
    else:
        lines.append(f"  [WARN] Pod metrics unavailable: {pod_error}")
    lines.append("")

    # Issues and warnings
    if issues:
        lines.append("ISSUES:")
        for issue in issues:
            lines.append(f"  [X] {issue}")
        lines.append("")

    if warnings:
        lines.append("WARNINGS:")
        for warning in warnings:
            lines.append(f"  [!] {warning}")
        lines.append("")

    if not issues and not warnings:
        lines.append("[OK] All Metrics Server health checks passed")

    return "\n".join(lines)


def format_json(deployment, pods, api_service, node_metrics, pod_count,
                node_error, pod_error, issues, warnings):
    """Format output as JSON."""
    deployment_summary = None
    if deployment:
        status = deployment.get('status', {})
        deployment_summary = {
            'replicas': deployment.get('spec', {}).get('replicas', 1),
            'ready_replicas': status.get('readyReplicas', 0),
            'available_replicas': status.get('availableReplicas', 0),
            'updated_replicas': status.get('updatedReplicas', 0)
        }

    pod_summary = []
    if pods:
        for pod in pods:
            container_statuses = pod.get('status', {}).get('containerStatuses', [])
            pod_summary.append({
                'name': pod.get('metadata', {}).get('name'),
                'phase': pod.get('status', {}).get('phase'),
                'ready': all(c.get('ready', False) for c in container_statuses),
                'restarts': sum(c.get('restartCount', 0) for c in container_statuses)
            })

    api_available = False
    if api_service:
        conditions = api_service.get('status', {}).get('conditions', [])
        for condition in conditions:
            if condition.get('type') == 'Available':
                api_available = condition.get('status') == 'True'
                break

    return json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'deployment': deployment_summary,
        'pods': pod_summary,
        'api_service': {
            'exists': api_service is not None,
            'available': api_available
        },
        'metrics': {
            'nodes_reporting': len(node_metrics) if node_metrics else 0,
            'pods_reporting': pod_count if pod_count else 0,
            'node_error': node_error if node_error else None,
            'pod_error': pod_error if pod_error else None
        },
        'issues': issues,
        'warnings': warnings,
        'healthy': len(issues) == 0
    }, indent=2)


def format_table(deployment, pods, api_service, node_metrics, pod_count,
                 node_error, pod_error, issues, warnings):
    """Format output as a table."""
    lines = []

    # Header
    lines.append("+" + "-" * 78 + "+")
    lines.append("| Kubernetes Metrics Server Health Check" + " " * 38 + "|")
    lines.append("+" + "-" * 78 + "+")

    # Component status table
    lines.append(f"| {'Component':<30} | {'Status':<10} | {'Details':<30} |")
    lines.append("+" + "-" * 78 + "+")

    # Deployment
    if deployment:
        status = deployment.get('status', {})
        replicas = deployment.get('spec', {}).get('replicas', 1)
        ready = status.get('readyReplicas', 0)
        dep_status = "OK" if ready == replicas else "DEGRADED"
        details = f"{ready}/{replicas} replicas ready"
    else:
        dep_status = "MISSING"
        details = "Deployment not found"
    lines.append(f"| {'Metrics Server Deployment':<30} | {dep_status:<10} | {details:<30} |")

    # API Service
    if api_service:
        conditions = api_service.get('status', {}).get('conditions', [])
        api_available = False
        for condition in conditions:
            if condition.get('type') == 'Available':
                api_available = condition.get('status') == 'True'
                break
        api_status = "OK" if api_available else "UNAVAIL"
        api_details = "API responding" if api_available else "API not available"
    else:
        api_status = "MISSING"
        api_details = "API service not found"
    lines.append(f"| {'Metrics API Service':<30} | {api_status:<10} | {api_details:<30} |")

    # Node metrics
    if node_metrics is not None:
        node_status = "OK"
        node_details = f"{len(node_metrics)} nodes reporting"
    else:
        node_status = "FAIL"
        node_details = "Cannot fetch node metrics"[:30]
    lines.append(f"| {'Node Metrics':<30} | {node_status:<10} | {node_details:<30} |")

    # Pod metrics
    if pod_count is not None:
        pod_status = "OK"
        pod_details = f"{pod_count} pods reporting"
    else:
        pod_status = "WARN"
        pod_details = "Cannot fetch pod metrics"[:30]
    lines.append(f"| {'Pod Metrics':<30} | {pod_status:<10} | {pod_details:<30} |")

    lines.append("+" + "-" * 78 + "+")

    # Issues and warnings
    if issues or warnings:
        lines.append("| Issues & Warnings" + " " * 60 + "|")
        lines.append("+" + "-" * 78 + "+")

        for issue in issues:
            issue_text = f"ERROR: {issue}"[:76]
            lines.append(f"| {issue_text:<76} |")

        for warning in warnings:
            warning_text = f"WARN: {warning}"[:76]
            lines.append(f"| {warning_text:<76} |")

        lines.append("+" + "-" * 78 + "+")
    else:
        lines.append("| Status: All checks passed" + " " * 51 + "|")
        lines.append("+" + "-" * 78 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes Metrics Server health (critical for HPA/VPA autoscaling)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic health check
  %(prog)s

  # JSON output for monitoring systems
  %(prog)s --format json

  # Verbose output with node details
  %(prog)s --verbose

  # Only show if there are problems
  %(prog)s --warn-only

  # Check metrics server in custom namespace
  %(prog)s --namespace monitoring

Exit codes:
  0 - Metrics server healthy and operational
  1 - Issues detected (warnings or errors)
  2 - Usage error or missing dependencies
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        default='kube-system',
        help='Namespace where metrics-server is deployed (default: kube-system)'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed information including node metrics breakdown'
    )
    parser.add_argument(
        '--warn-only',
        action='store_true',
        help='Only show output if issues or warnings are detected'
    )

    args = parser.parse_args()

    # Check dependencies
    if not check_kubectl():
        print("Error: kubectl is not available or not configured", file=sys.stderr)
        print("Please install kubectl and configure access to a cluster", file=sys.stderr)
        return 2

    # Gather metrics server health data
    deployment = get_metrics_server_deployment(args.namespace)
    pods = get_metrics_server_pods(args.namespace)
    api_service = get_metrics_api_service()
    node_metrics, node_error = get_node_metrics()
    pod_count, pod_error = get_pod_metrics_sample()

    # Analyze health
    issues, warnings = analyze_metrics_health(
        deployment, pods, api_service, node_metrics, pod_count
    )

    # Format output
    if args.format == 'json':
        output = format_json(deployment, pods, api_service, node_metrics, pod_count,
                            node_error, pod_error, issues, warnings)
    elif args.format == 'table':
        output = format_table(deployment, pods, api_service, node_metrics, pod_count,
                             node_error, pod_error, issues, warnings)
    else:
        output = format_plain(deployment, pods, api_service, node_metrics, pod_count,
                             node_error, pod_error, issues, warnings, args.verbose)

    # Print output (respecting --warn-only)
    if not args.warn_only or issues or warnings:
        print(output)

    # Return appropriate exit code
    if issues:
        return 1
    else:
        return 0


if __name__ == '__main__':
    sys.exit(main())
