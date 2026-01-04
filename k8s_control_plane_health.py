#!/usr/bin/env python3
"""Kubernetes Control Plane Health Monitor

Monitors the health of Kubernetes control plane components:
- API server availability and response time
- etcd cluster health and leader status
- Controller manager operational status
- Scheduler operational status
- Control plane pod health and resource usage

Critical for production clusters where control plane failures cascade
across all cluster operations. Helps identify issues before they
cause widespread service disruption.

Exit codes:
  0: All control plane components healthy
  1: Control plane issues detected (warnings or failures)
  2: Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone


def run_kubectl(args, timeout=10):
    """Run kubectl and return output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"


def check_kubectl_available():
    """Check if kubectl is available and configured."""
    returncode, _, stderr = run_kubectl(['cluster-info'], timeout=5)
    return returncode == 0


def measure_api_server_latency():
    """Measure API server response time."""
    start = time.time()
    returncode, _, _ = run_kubectl(['get', '--raw', '/healthz'], timeout=5)
    latency_ms = (time.time() - start) * 1000

    return {
        'available': returncode == 0,
        'latency_ms': round(latency_ms, 2)
    }


def get_api_server_health():
    """Get detailed API server health status."""
    health_endpoints = [
        '/healthz',
        '/readyz',
        '/livez'
    ]

    results = {}
    for endpoint in health_endpoints:
        returncode, stdout, _ = run_kubectl(['get', '--raw', endpoint], timeout=5)
        results[endpoint] = {
            'healthy': returncode == 0 and stdout.strip() == 'ok',
            'response': stdout.strip() if returncode == 0 else 'unavailable'
        }

    return results


def get_control_plane_pods(namespace='kube-system'):
    """Get control plane pod information."""
    returncode, stdout, stderr = run_kubectl([
        'get', 'pods', '-n', namespace,
        '-l', 'tier=control-plane',
        '-o', 'json'
    ])

    if returncode != 0:
        # Try alternative label used by some clusters
        returncode, stdout, stderr = run_kubectl([
            'get', 'pods', '-n', namespace,
            '-o', 'json'
        ])

        if returncode != 0:
            return None

        # Filter for control plane components manually
        try:
            data = json.loads(stdout)
            cp_components = ['kube-apiserver', 'kube-controller-manager',
                           'kube-scheduler', 'etcd']
            filtered_items = []
            for pod in data.get('items', []):
                pod_name = pod.get('metadata', {}).get('name', '')
                if any(comp in pod_name for comp in cp_components):
                    filtered_items.append(pod)
            data['items'] = filtered_items
            return data
        except json.JSONDecodeError:
            return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def get_component_status():
    """Get component status (deprecated but still useful)."""
    returncode, stdout, stderr = run_kubectl([
        'get', 'componentstatuses', '-o', 'json'
    ])

    if returncode != 0:
        return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def get_etcd_health(namespace='kube-system'):
    """Check etcd pod health."""
    returncode, stdout, _ = run_kubectl([
        'get', 'pods', '-n', namespace,
        '-l', 'component=etcd',
        '-o', 'json'
    ])

    if returncode != 0:
        return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def get_lease_info(namespace='kube-system'):
    """Get leader election lease information."""
    leases = {}

    for component in ['kube-controller-manager', 'kube-scheduler']:
        returncode, stdout, _ = run_kubectl([
            'get', 'lease', component, '-n', namespace, '-o', 'json'
        ])

        if returncode == 0:
            try:
                lease_data = json.loads(stdout)
                holder = lease_data.get('spec', {}).get('holderIdentity', 'unknown')
                renew_time = lease_data.get('spec', {}).get('renewTime', 'unknown')
                leases[component] = {
                    'holder': holder,
                    'renew_time': renew_time,
                    'available': True
                }
            except json.JSONDecodeError:
                leases[component] = {'available': False}
        else:
            leases[component] = {'available': False}

    return leases


def analyze_pod_health(pod):
    """Analyze individual pod health."""
    pod_name = pod.get('metadata', {}).get('name', 'unknown')
    status = pod.get('status', {})
    phase = status.get('phase', 'Unknown')

    issues = []
    warnings = []

    # Check phase
    if phase != 'Running':
        issues.append(f"Pod phase: {phase}")

    # Check container statuses
    container_statuses = status.get('containerStatuses', [])
    for container in container_statuses:
        container_name = container.get('name', 'unknown')

        # Check readiness
        if not container.get('ready', False):
            issues.append(f"Container {container_name} not ready")

        # Check restart count
        restart_count = container.get('restartCount', 0)
        if restart_count > 10:
            issues.append(f"Container {container_name} has {restart_count} restarts")
        elif restart_count > 3:
            warnings.append(f"Container {container_name} has {restart_count} restarts")

        # Check for crash loops
        state = container.get('state', {})
        if 'waiting' in state:
            reason = state['waiting'].get('reason', '')
            if reason in ['CrashLoopBackOff', 'Error', 'ImagePullBackOff']:
                issues.append(f"Container {container_name}: {reason}")

    return {
        'name': pod_name,
        'phase': phase,
        'ready': len(issues) == 0,
        'issues': issues,
        'warnings': warnings,
        'restart_count': sum(c.get('restartCount', 0) for c in container_statuses)
    }


def analyze_control_plane(api_health, api_latency, pods, component_status, etcd_pods, leases):
    """Analyze control plane health and return issues."""
    issues = []
    warnings = []
    component_health = {}

    # API Server analysis
    api_available = api_latency.get('available', False)
    latency = api_latency.get('latency_ms', 0)

    component_health['api-server'] = {
        'available': api_available,
        'latency_ms': latency,
        'health_endpoints': api_health
    }

    if not api_available:
        issues.append("API server is not responding")
    elif latency > 1000:
        issues.append(f"API server latency critical: {latency}ms")
    elif latency > 500:
        warnings.append(f"API server latency high: {latency}ms")

    # Check health endpoints
    for endpoint, status in api_health.items():
        if not status.get('healthy'):
            issues.append(f"API server {endpoint} unhealthy: {status.get('response')}")

    # etcd analysis
    if etcd_pods:
        etcd_items = etcd_pods.get('items', [])
        healthy_etcd = 0
        total_etcd = len(etcd_items)

        for pod in etcd_items:
            pod_health = analyze_pod_health(pod)
            if pod_health['ready']:
                healthy_etcd += 1
            issues.extend(pod_health['issues'])
            warnings.extend(pod_health['warnings'])

        component_health['etcd'] = {
            'healthy': healthy_etcd,
            'total': total_etcd,
            'quorum': healthy_etcd > total_etcd // 2 if total_etcd > 0 else False
        }

        if total_etcd == 0:
            warnings.append("No etcd pods found (may be external)")
        elif healthy_etcd == 0:
            issues.append("No healthy etcd pods - cluster at risk")
        elif healthy_etcd <= total_etcd // 2:
            issues.append(f"etcd quorum at risk: {healthy_etcd}/{total_etcd} healthy")
        elif healthy_etcd < total_etcd:
            warnings.append(f"etcd degraded: {healthy_etcd}/{total_etcd} healthy")
    else:
        component_health['etcd'] = {'healthy': 0, 'total': 0, 'quorum': False}
        warnings.append("Could not check etcd health (may be external)")

    # Control plane pod analysis
    if pods:
        for pod in pods.get('items', []):
            pod_health = analyze_pod_health(pod)
            pod_name = pod_health['name']

            # Categorize by component
            if 'apiserver' in pod_name:
                comp = 'api-server-pod'
            elif 'controller-manager' in pod_name:
                comp = 'controller-manager'
            elif 'scheduler' in pod_name:
                comp = 'scheduler'
            elif 'etcd' in pod_name:
                continue  # Already handled
            else:
                comp = 'other'

            if comp not in component_health:
                component_health[comp] = {'pods': []}
            component_health[comp]['pods'] = component_health.get(comp, {}).get('pods', []) + [pod_health]

            # Add issues/warnings with context
            for issue in pod_health['issues']:
                issues.append(f"{pod_name}: {issue}")
            for warning in pod_health['warnings']:
                warnings.append(f"{pod_name}: {warning}")

    # Lease analysis (leader election)
    if leases:
        component_health['leases'] = leases
        for component, lease_info in leases.items():
            if not lease_info.get('available'):
                warnings.append(f"{component} lease not found")

    # Component status analysis (if available)
    if component_status:
        for item in component_status.get('items', []):
            comp_name = item.get('metadata', {}).get('name', 'unknown')
            conditions = item.get('conditions', [])

            for condition in conditions:
                if condition.get('type') == 'Healthy':
                    if condition.get('status') != 'True':
                        issues.append(f"Component {comp_name} unhealthy: {condition.get('message', 'unknown')}")

    return issues, warnings, component_health


def format_plain(api_health, api_latency, issues, warnings, component_health):
    """Format output in plain text."""
    lines = []
    lines.append("Kubernetes Control Plane Health")
    lines.append("=" * 50)
    lines.append("")

    # API Server
    lines.append("API Server:")
    api_status = "OK" if api_latency.get('available') else "UNAVAILABLE"
    latency = api_latency.get('latency_ms', 0)
    lines.append(f"  Status: {api_status}")
    lines.append(f"  Latency: {latency}ms")

    for endpoint, status in api_health.items():
        symbol = "OK" if status.get('healthy') else "FAIL"
        lines.append(f"  {endpoint}: {symbol}")
    lines.append("")

    # etcd
    if 'etcd' in component_health:
        etcd = component_health['etcd']
        lines.append("etcd:")
        lines.append(f"  Healthy: {etcd.get('healthy', 0)}/{etcd.get('total', 0)}")
        quorum = "YES" if etcd.get('quorum') else "NO"
        lines.append(f"  Quorum: {quorum}")
        lines.append("")

    # Leader Election
    if 'leases' in component_health:
        lines.append("Leader Election:")
        for component, lease in component_health['leases'].items():
            if lease.get('available'):
                lines.append(f"  {component}: {lease.get('holder', 'unknown')}")
            else:
                lines.append(f"  {component}: lease not found")
        lines.append("")

    # Issues
    if issues:
        lines.append("ISSUES:")
        for issue in issues:
            lines.append(f"  [!] {issue}")
        lines.append("")

    if warnings:
        lines.append("WARNINGS:")
        for warning in warnings:
            lines.append(f"  [*] {warning}")
        lines.append("")

    if not issues and not warnings:
        lines.append("[OK] All control plane components healthy")

    return "\n".join(lines)


def format_json(api_health, api_latency, issues, warnings, component_health):
    """Format output as JSON."""
    return json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'api_server': {
            'available': api_latency.get('available'),
            'latency_ms': api_latency.get('latency_ms'),
            'health_endpoints': api_health
        },
        'components': component_health,
        'issues': issues,
        'warnings': warnings,
        'healthy': len(issues) == 0
    }, indent=2)


def format_table(api_health, api_latency, issues, warnings, component_health):
    """Format output as a table."""
    lines = []

    # Header
    lines.append("+" + "-" * 70 + "+")
    lines.append("| Kubernetes Control Plane Health" + " " * 37 + "|")
    lines.append("+" + "-" * 70 + "+")

    # API Server
    api_status = "OK" if api_latency.get('available') else "FAIL"
    latency = api_latency.get('latency_ms', 0)
    lines.append(f"| {'Component':<25} | {'Status':<15} | {'Details':<22} |")
    lines.append("+" + "-" * 70 + "+")
    lines.append(f"| {'API Server':<25} | {api_status:<15} | {f'Latency: {latency}ms':<22} |")

    # Health endpoints
    for endpoint, status in api_health.items():
        ep_status = "OK" if status.get('healthy') else "FAIL"
        lines.append(f"| {f'  {endpoint}':<25} | {ep_status:<15} | {'':<22} |")

    # etcd
    if 'etcd' in component_health:
        etcd = component_health['etcd']
        etcd_status = "OK" if etcd.get('quorum') else "DEGRADED"
        etcd_detail = f"{etcd.get('healthy', 0)}/{etcd.get('total', 0)} healthy"
        lines.append(f"| {'etcd':<25} | {etcd_status:<15} | {etcd_detail:<22} |")

    # Leases
    if 'leases' in component_health:
        for component, lease in component_health['leases'].items():
            lease_status = "OK" if lease.get('available') else "UNKNOWN"
            holder = lease.get('holder', 'N/A')[:22]
            lines.append(f"| {component:<25} | {lease_status:<15} | {holder:<22} |")

    lines.append("+" + "-" * 70 + "+")

    # Issues summary
    if issues or warnings:
        lines.append(f"| {'Issues':<68} |")
        lines.append("+" + "-" * 70 + "+")
        for issue in issues[:5]:  # Limit to 5
            issue_text = f"[!] {issue}"[:68]
            lines.append(f"| {issue_text:<68} |")
        for warning in warnings[:5]:
            warning_text = f"[*] {warning}"[:68]
            lines.append(f"| {warning_text:<68} |")
        lines.append("+" + "-" * 70 + "+")
    else:
        lines.append(f"| {'Status: All components healthy':<68} |")
        lines.append("+" + "-" * 70 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes control plane health',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check control plane health with table output
  %(prog)s

  # JSON output for monitoring systems
  %(prog)s --format json

  # Only show if there are problems
  %(prog)s --warn-only

  # Check control plane in custom namespace
  %(prog)s --namespace kube-system

Exit codes:
  0 - All control plane components healthy
  1 - Control plane issues detected
  2 - Usage error or kubectl not available
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        default='kube-system',
        help='Namespace for control plane components (default: kube-system)'
    )
    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='table',
        help='Output format (default: table)'
    )
    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    args = parser.parse_args()

    # Check dependencies
    if not check_kubectl_available():
        print("Error: kubectl is not available or cluster not reachable", file=sys.stderr)
        print("Ensure kubectl is installed and configured", file=sys.stderr)
        return 2

    # Gather control plane health data
    api_latency = measure_api_server_latency()
    api_health = get_api_server_health()
    pods = get_control_plane_pods(args.namespace)
    component_status = get_component_status()
    etcd_pods = get_etcd_health(args.namespace)
    leases = get_lease_info(args.namespace)

    # Analyze health
    issues, warnings, component_health = analyze_control_plane(
        api_health, api_latency, pods, component_status, etcd_pods, leases
    )

    # Format output
    if args.format == 'json':
        output = format_json(api_health, api_latency, issues, warnings, component_health)
    elif args.format == 'table':
        output = format_table(api_health, api_latency, issues, warnings, component_health)
    else:
        output = format_plain(api_health, api_latency, issues, warnings, component_health)

    # Print output (respecting --warn-only)
    if not args.warn_only or issues or warnings:
        print(output)

    # Return appropriate exit code
    return 1 if issues else 0


if __name__ == '__main__':
    sys.exit(main())
