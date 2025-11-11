#!/usr/bin/env python3
"""
Kubernetes DNS Health Monitor

Monitors the health of DNS resolution in a Kubernetes cluster, including:
- CoreDNS/kube-dns pod health and readiness
- DNS resolution tests from within the cluster
- DNS service endpoint availability
- CoreDNS configuration validation
- Pod restart patterns that might indicate DNS issues

Exit codes:
0 - All DNS components healthy
1 - DNS issues detected (warnings or failures)
2 - Usage error or missing dependencies
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone


def check_kubectl():
    """Check if kubectl is available and configured."""
    try:
        result = subprocess.run(
            ['kubectl', 'cluster-info'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def get_coredns_pods(namespace='kube-system'):
    """Get CoreDNS/kube-dns pod information."""
    try:
        # Try CoreDNS first (most common in modern clusters)
        result = subprocess.run(
            ['kubectl', 'get', 'pods', '-n', namespace,
             '-l', 'k8s-app=kube-dns', '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        data = json.loads(result.stdout)
        return data.get('items', [])
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def get_dns_service(namespace='kube-system'):
    """Get DNS service information."""
    try:
        result = subprocess.run(
            ['kubectl', 'get', 'service', 'kube-dns', '-n', namespace, '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        return json.loads(result.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def get_dns_endpoints(namespace='kube-system'):
    """Get DNS service endpoints."""
    try:
        result = subprocess.run(
            ['kubectl', 'get', 'endpoints', 'kube-dns', '-n', namespace, '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        return json.loads(result.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def test_dns_resolution(namespace='default', test_domain='kubernetes.default.svc.cluster.local'):
    """Test DNS resolution from within a cluster using a temporary pod."""
    try:
        # Create a simple DNS test using kubectl run
        result = subprocess.run(
            ['kubectl', 'run', 'dns-test-pod', '--image=busybox:1.28',
             '--restart=Never', '--rm', '-i', '--namespace', namespace,
             '--command', '--', 'nslookup', test_domain],
            capture_output=True,
            text=True,
            timeout=30
        )

        success = result.returncode == 0 and 'Server:' in result.stdout
        output = result.stdout + result.stderr

        return {
            'success': success,
            'output': output,
            'test_domain': test_domain
        }
    except subprocess.SubprocessError as e:
        return {
            'success': False,
            'output': str(e),
            'test_domain': test_domain
        }


def get_coredns_configmap(namespace='kube-system'):
    """Get CoreDNS ConfigMap."""
    try:
        result = subprocess.run(
            ['kubectl', 'get', 'configmap', 'coredns', '-n', namespace, '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        return json.loads(result.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def analyze_dns_health(pods, service, endpoints, dns_test, configmap):
    """Analyze DNS health and return issues."""
    issues = []
    warnings = []

    # Check pods
    if not pods:
        issues.append("No CoreDNS/kube-dns pods found")
    else:
        ready_pods = 0
        for pod in pods:
            pod_name = pod.get('metadata', {}).get('name', 'unknown')
            status = pod.get('status', {})
            phase = status.get('phase', 'Unknown')

            if phase != 'Running':
                issues.append(f"Pod {pod_name} is in phase: {phase}")
                continue

            # Check container readiness
            container_statuses = status.get('containerStatuses', [])
            for container in container_statuses:
                if not container.get('ready', False):
                    issues.append(f"Pod {pod_name} container {container.get('name')} is not ready")
                else:
                    ready_pods += 1

            # Check restart count
            for container in container_statuses:
                restart_count = container.get('restartCount', 0)
                if restart_count > 10:
                    warnings.append(f"Pod {pod_name} has {restart_count} restarts (possible instability)")
                elif restart_count > 5:
                    warnings.append(f"Pod {pod_name} has {restart_count} restarts")

        if ready_pods == 0:
            issues.append("No ready DNS pods found")
        elif ready_pods < 2:
            warnings.append(f"Only {ready_pods} DNS pod(s) ready (consider scaling for HA)")

    # Check service
    if not service:
        issues.append("DNS service 'kube-dns' not found")
    else:
        cluster_ip = service.get('spec', {}).get('clusterIP')
        if not cluster_ip or cluster_ip == 'None':
            issues.append("DNS service has no ClusterIP")

    # Check endpoints
    if not endpoints:
        issues.append("DNS service endpoints not found")
    else:
        subsets = endpoints.get('subsets', [])
        if not subsets:
            issues.append("DNS service has no endpoint subsets")
        else:
            ready_addresses = sum(len(subset.get('addresses', [])) for subset in subsets)
            not_ready_addresses = sum(len(subset.get('notReadyAddresses', [])) for subset in subsets)

            if ready_addresses == 0:
                issues.append("DNS service has no ready endpoints")

            if not_ready_addresses > 0:
                warnings.append(f"DNS service has {not_ready_addresses} not-ready endpoint(s)")

    # Check DNS resolution test
    if dns_test and not dns_test.get('success'):
        issues.append(f"DNS resolution test failed for {dns_test.get('test_domain')}")

    # Check ConfigMap
    if not configmap:
        warnings.append("CoreDNS ConfigMap not found (might be using kube-dns)")

    return issues, warnings


def format_plain(pods, service, endpoints, dns_test, configmap, issues, warnings):
    """Format output in plain text."""
    lines = []
    lines.append("Kubernetes DNS Health Check")
    lines.append("=" * 50)
    lines.append("")

    # Pod status
    lines.append("DNS Pods:")
    if pods:
        for pod in pods:
            pod_name = pod.get('metadata', {}).get('name', 'unknown')
            phase = pod.get('status', {}).get('phase', 'Unknown')
            container_statuses = pod.get('status', {}).get('containerStatuses', [])

            ready = all(c.get('ready', False) for c in container_statuses)
            restart_count = sum(c.get('restartCount', 0) for c in container_statuses)

            status_symbol = "✓" if ready and phase == 'Running' else "✗"
            lines.append(f"  {status_symbol} {pod_name}: {phase}, Ready: {ready}, Restarts: {restart_count}")
    else:
        lines.append("  No DNS pods found")
    lines.append("")

    # Service status
    lines.append("DNS Service:")
    if service:
        cluster_ip = service.get('spec', {}).get('clusterIP', 'Unknown')
        lines.append(f"  ClusterIP: {cluster_ip}")
    else:
        lines.append("  Service not found")
    lines.append("")

    # Endpoints
    lines.append("DNS Endpoints:")
    if endpoints:
        subsets = endpoints.get('subsets', [])
        ready_addresses = sum(len(subset.get('addresses', [])) for subset in subsets)
        not_ready_addresses = sum(len(subset.get('notReadyAddresses', [])) for subset in subsets)
        lines.append(f"  Ready: {ready_addresses}")
        lines.append(f"  Not Ready: {not_ready_addresses}")
    else:
        lines.append("  Endpoints not found")
    lines.append("")

    # DNS test
    if dns_test:
        lines.append("DNS Resolution Test:")
        status_symbol = "✓" if dns_test.get('success') else "✗"
        lines.append(f"  {status_symbol} Test domain: {dns_test.get('test_domain')}")
        if not dns_test.get('success'):
            lines.append(f"  Error output: {dns_test.get('output', '')[:200]}")
        lines.append("")

    # Issues and warnings
    if issues:
        lines.append("ISSUES:")
        for issue in issues:
            lines.append(f"  ✗ {issue}")
        lines.append("")

    if warnings:
        lines.append("WARNINGS:")
        for warning in warnings:
            lines.append(f"  ⚠ {warning}")
        lines.append("")

    if not issues and not warnings:
        lines.append("✓ All DNS health checks passed")

    return "\n".join(lines)


def format_json(pods, service, endpoints, dns_test, configmap, issues, warnings):
    """Format output as JSON."""
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

    endpoint_summary = {}
    if endpoints:
        subsets = endpoints.get('subsets', [])
        endpoint_summary = {
            'ready': sum(len(subset.get('addresses', [])) for subset in subsets),
            'not_ready': sum(len(subset.get('notReadyAddresses', [])) for subset in subsets)
        }

    return json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'pods': pod_summary,
        'service': {
            'exists': service is not None,
            'cluster_ip': service.get('spec', {}).get('clusterIP') if service else None
        },
        'endpoints': endpoint_summary,
        'dns_test': dns_test if dns_test else {'success': False, 'output': 'Test not run'},
        'configmap_exists': configmap is not None,
        'issues': issues,
        'warnings': warnings,
        'healthy': len(issues) == 0
    }, indent=2)


def format_table(pods, service, endpoints, dns_test, configmap, issues, warnings):
    """Format output as a table."""
    lines = []

    # Header
    lines.append("+" + "-" * 78 + "+")
    lines.append("| Kubernetes DNS Health Check" + " " * 50 + "|")
    lines.append("+" + "-" * 78 + "+")

    # Pods table
    if pods:
        lines.append("| DNS Pods" + " " * 69 + "|")
        lines.append("+" + "-" * 78 + "+")
        lines.append(f"| {'Pod Name':<40} | {'Status':<10} | {'Ready':<8} | {'Restarts':<8} |")
        lines.append("+" + "-" * 78 + "+")

        for pod in pods:
            pod_name = pod.get('metadata', {}).get('name', 'unknown')[:40]
            phase = pod.get('status', {}).get('phase', 'Unknown')[:10]
            container_statuses = pod.get('status', {}).get('containerStatuses', [])
            ready = "Yes" if all(c.get('ready', False) for c in container_statuses) else "No"
            restart_count = sum(c.get('restartCount', 0) for c in container_statuses)

            lines.append(f"| {pod_name:<40} | {phase:<10} | {ready:<8} | {restart_count:<8} |")

        lines.append("+" + "-" * 78 + "+")

    # Service and endpoints
    lines.append("| DNS Service & Endpoints" + " " * 54 + "|")
    lines.append("+" + "-" * 78 + "+")

    if service:
        cluster_ip = service.get('spec', {}).get('clusterIP', 'Unknown')
        lines.append(f"| Service ClusterIP: {cluster_ip:<58} |")

    if endpoints:
        subsets = endpoints.get('subsets', [])
        ready = sum(len(subset.get('addresses', [])) for subset in subsets)
        not_ready = sum(len(subset.get('notReadyAddresses', [])) for subset in subsets)
        lines.append(f"| Ready Endpoints: {ready:<62} |")
        lines.append(f"| Not Ready Endpoints: {not_ready:<58} |")

    lines.append("+" + "-" * 78 + "+")

    # DNS test result
    if dns_test:
        test_status = "PASS" if dns_test.get('success') else "FAIL"
        lines.append(f"| DNS Resolution Test: {test_status:<58} |")
        lines.append("+" + "-" * 78 + "+")

    # Issues and warnings
    if issues or warnings:
        lines.append("| Issues & Warnings" + " " * 60 + "|")
        lines.append("+" + "-" * 78 + "+")

        for issue in issues:
            issue_text = f"ISSUE: {issue}"[:76]
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
        description='Monitor Kubernetes DNS health',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check DNS health with plain output
  %(prog)s

  # JSON output for monitoring systems
  %(prog)s --format json

  # Check DNS in a specific namespace
  %(prog)s --namespace custom-dns

  # Only show problems
  %(prog)s --warn-only

  # Skip DNS resolution test (faster)
  %(prog)s --no-dns-test

Exit codes:
  0 - All DNS components healthy
  1 - DNS issues detected
  2 - Usage error or missing dependencies
        """
    )

    parser.add_argument(
        '--namespace',
        default='kube-system',
        help='Namespace where DNS pods are running (default: kube-system)'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--warn-only',
        action='store_true',
        help='Only show output if issues or warnings are detected'
    )
    parser.add_argument(
        '--no-dns-test',
        action='store_true',
        help='Skip DNS resolution test (faster but less thorough)'
    )
    parser.add_argument(
        '--test-domain',
        default='kubernetes.default.svc.cluster.local',
        help='Domain to test DNS resolution (default: kubernetes.default.svc.cluster.local)'
    )

    args = parser.parse_args()

    # Check dependencies
    if not check_kubectl():
        print("Error: kubectl is not available or not configured", file=sys.stderr)
        print("Please install kubectl and configure access to a cluster", file=sys.stderr)
        return 2

    # Gather DNS health data
    pods = get_coredns_pods(args.namespace)
    service = get_dns_service(args.namespace)
    endpoints = get_dns_endpoints(args.namespace)
    configmap = get_coredns_configmap(args.namespace)

    # Run DNS test if requested
    dns_test = None
    if not args.no_dns_test:
        dns_test = test_dns_resolution(test_domain=args.test_domain)

    # Analyze health
    issues, warnings = analyze_dns_health(pods, service, endpoints, dns_test, configmap)

    # Format output
    if args.format == 'json':
        output = format_json(pods, service, endpoints, dns_test, configmap, issues, warnings)
    elif args.format == 'table':
        output = format_table(pods, service, endpoints, dns_test, configmap, issues, warnings)
    else:
        output = format_plain(pods, service, endpoints, dns_test, configmap, issues, warnings)

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
