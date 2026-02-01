#!/usr/bin/env python3
"""
Kubernetes Service Endpoint Latency Monitor

Monitors network latency to Kubernetes service endpoints by measuring
response times from within the cluster. Useful for detecting:
- Service endpoint degradation
- Network performance issues
- Cross-node communication problems
- Load balancer or kube-proxy issues

Exit codes:
    0 - All services responding within thresholds
    1 - Latency warnings or failures detected
    2 - Usage error or missing dependencies
"""

import argparse
import json
import subprocess
import sys
import re
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


def get_services(namespace=None, label_selector=None):
    """Get services from the cluster."""
    try:
        cmd = ['kubectl', 'get', 'services', '-o', 'json']

        if namespace:
            cmd.extend(['-n', namespace])
        else:
            cmd.append('--all-namespaces')

        if label_selector:
            cmd.extend(['-l', label_selector])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return None

        return json.loads(result.stdout).get('items', [])
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def get_endpoints(service_name, namespace):
    """Get endpoints for a specific service."""
    try:
        result = subprocess.run(
            ['kubectl', 'get', 'endpoints', service_name, '-n', namespace, '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        return json.loads(result.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def measure_service_latency(service_name, namespace, cluster_ip, port, timeout_ms=5000):
    """
    Measure latency to a service endpoint using kubectl exec.
    Returns latency in milliseconds or None if unreachable.
    """
    try:
        # Use wget with timing to measure latency
        # This runs in a temporary pod to test from within the cluster
        cmd = [
            'kubectl', 'run', 'latency-test-tmp',
            '--image=busybox:1.36',
            '--restart=Never',
            '--rm', '-i',
            '--namespace', namespace,
            '--command', '--',
            'sh', '-c',
            f'start=$(date +%s%3N); wget -q -O /dev/null --timeout=5 http://{cluster_ip}:{port}/ 2>/dev/null; end=$(date +%s%3N); echo $((end-start))'
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_ms / 1000 + 10  # Add buffer for pod startup
        )

        # Try to parse the latency from output
        output = result.stdout.strip()
        if output and output.isdigit():
            return int(output)

        return None
    except (subprocess.SubprocessError, ValueError):
        return None


def check_tcp_connectivity(cluster_ip, port, namespace, timeout_seconds=5):
    """
    Check TCP connectivity to a service using nc (netcat).
    Returns (success, latency_ms) tuple.
    """
    try:
        cmd = [
            'kubectl', 'run', 'tcp-test-tmp',
            '--image=busybox:1.36',
            '--restart=Never',
            '--rm', '-i',
            '--namespace', namespace,
            '--command', '--',
            'sh', '-c',
            f'start=$(date +%s%3N); nc -z -w {timeout_seconds} {cluster_ip} {port} 2>/dev/null && echo "OK"; end=$(date +%s%3N); echo $((end-start))'
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 15  # Buffer for pod creation/deletion
        )

        output_lines = result.stdout.strip().split('\n')
        success = 'OK' in result.stdout

        # Try to get latency from last line
        latency = None
        for line in reversed(output_lines):
            if line.strip().isdigit():
                latency = int(line.strip())
                break

        return success, latency
    except (subprocess.SubprocessError, ValueError):
        return False, None


def analyze_service(service, warn_threshold_ms, critical_threshold_ms, skip_system=True):
    """Analyze a single service's latency and health."""
    metadata = service.get('metadata', {})
    spec = service.get('spec', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')

    # Skip system services by default
    if skip_system and namespace in ['kube-system', 'kube-public', 'kube-node-lease']:
        return None

    # Skip headless services (no ClusterIP)
    cluster_ip = spec.get('clusterIP')
    if not cluster_ip or cluster_ip == 'None':
        return {
            'name': name,
            'namespace': namespace,
            'type': 'headless',
            'status': 'skipped',
            'reason': 'Headless service (no ClusterIP)'
        }

    # Skip ExternalName services
    if spec.get('type') == 'ExternalName':
        return {
            'name': name,
            'namespace': namespace,
            'type': 'external',
            'status': 'skipped',
            'reason': 'ExternalName service'
        }

    # Get first port
    ports = spec.get('ports', [])
    if not ports:
        return {
            'name': name,
            'namespace': namespace,
            'cluster_ip': cluster_ip,
            'status': 'skipped',
            'reason': 'No ports defined'
        }

    port = ports[0].get('port')
    port_name = ports[0].get('name', str(port))
    protocol = ports[0].get('protocol', 'TCP')

    # Get endpoint count
    endpoints = get_endpoints(name, namespace)
    endpoint_count = 0
    if endpoints:
        subsets = endpoints.get('subsets', [])
        endpoint_count = sum(len(s.get('addresses', [])) for s in subsets)

    # Check TCP connectivity and measure latency
    success, latency_ms = check_tcp_connectivity(cluster_ip, port, namespace)

    # Determine status
    status = 'healthy'
    issues = []

    if not success:
        status = 'critical'
        issues.append('Service unreachable')
    elif latency_ms is not None:
        if latency_ms >= critical_threshold_ms:
            status = 'critical'
            issues.append(f'Latency {latency_ms}ms exceeds critical threshold {critical_threshold_ms}ms')
        elif latency_ms >= warn_threshold_ms:
            status = 'warning'
            issues.append(f'Latency {latency_ms}ms exceeds warning threshold {warn_threshold_ms}ms')

    if endpoint_count == 0:
        status = 'critical'
        issues.append('No ready endpoints')

    return {
        'name': name,
        'namespace': namespace,
        'cluster_ip': cluster_ip,
        'port': port,
        'port_name': port_name,
        'protocol': protocol,
        'endpoint_count': endpoint_count,
        'latency_ms': latency_ms,
        'reachable': success,
        'status': status,
        'issues': issues
    }


def format_plain(results, warn_only=False):
    """Format results as plain text."""
    lines = []
    lines.append("Kubernetes Service Latency Monitor")
    lines.append("=" * 60)
    lines.append("")

    # Separate by status
    critical = [r for r in results if r and r.get('status') == 'critical']
    warnings = [r for r in results if r and r.get('status') == 'warning']
    healthy = [r for r in results if r and r.get('status') == 'healthy']
    skipped = [r for r in results if r and r.get('status') == 'skipped']

    # Summary
    lines.append(f"Services checked: {len(results) - len(skipped)}")
    lines.append(f"  Healthy:  {len(healthy)}")
    lines.append(f"  Warning:  {len(warnings)}")
    lines.append(f"  Critical: {len(critical)}")
    lines.append(f"  Skipped:  {len(skipped)}")
    lines.append("")

    # Critical issues
    if critical:
        lines.append("CRITICAL:")
        for r in critical:
            latency_str = f"{r.get('latency_ms')}ms" if r.get('latency_ms') is not None else "N/A"
            lines.append(f"  ✗ {r['namespace']}/{r['name']} - {r['cluster_ip']}:{r.get('port', 'N/A')}")
            lines.append(f"    Latency: {latency_str}, Endpoints: {r.get('endpoint_count', 0)}")
            for issue in r.get('issues', []):
                lines.append(f"    - {issue}")
        lines.append("")

    # Warnings
    if warnings:
        lines.append("WARNINGS:")
        for r in warnings:
            latency_str = f"{r.get('latency_ms')}ms" if r.get('latency_ms') is not None else "N/A"
            lines.append(f"  ⚠ {r['namespace']}/{r['name']} - {r['cluster_ip']}:{r.get('port', 'N/A')}")
            lines.append(f"    Latency: {latency_str}, Endpoints: {r.get('endpoint_count', 0)}")
            for issue in r.get('issues', []):
                lines.append(f"    - {issue}")
        lines.append("")

    # Healthy (only if not warn-only)
    if healthy and not warn_only:
        lines.append("HEALTHY:")
        for r in healthy:
            latency_str = f"{r.get('latency_ms')}ms" if r.get('latency_ms') is not None else "N/A"
            lines.append(f"  ✓ {r['namespace']}/{r['name']} - Latency: {latency_str}, Endpoints: {r.get('endpoint_count', 0)}")
        lines.append("")

    if not critical and not warnings:
        lines.append("✓ All services responding within latency thresholds")

    return "\n".join(lines)


def format_json(results):
    """Format results as JSON."""
    # Filter out None results
    filtered = [r for r in results if r is not None]

    critical_count = len([r for r in filtered if r.get('status') == 'critical'])
    warning_count = len([r for r in filtered if r.get('status') == 'warning'])
    healthy_count = len([r for r in filtered if r.get('status') == 'healthy'])

    return json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'summary': {
            'total_checked': len(filtered),
            'healthy': healthy_count,
            'warning': warning_count,
            'critical': critical_count
        },
        'services': filtered,
        'has_issues': critical_count > 0 or warning_count > 0
    }, indent=2)


def format_table(results, warn_only=False):
    """Format results as a table."""
    lines = []

    # Filter results
    filtered = [r for r in results if r is not None and r.get('status') != 'skipped']
    if warn_only:
        filtered = [r for r in filtered if r.get('status') in ['warning', 'critical']]

    # Header
    lines.append("+" + "-" * 88 + "+")
    lines.append("| Kubernetes Service Latency Monitor" + " " * 52 + "|")
    lines.append("+" + "-" * 88 + "+")
    lines.append(f"| {'Namespace':<15} | {'Service':<20} | {'Latency':<10} | {'Endpoints':<9} | {'Status':<10} |")
    lines.append("+" + "-" * 88 + "+")

    for r in filtered:
        namespace = r.get('namespace', 'unknown')[:15]
        name = r.get('name', 'unknown')[:20]
        latency = f"{r.get('latency_ms')}ms" if r.get('latency_ms') is not None else "N/A"
        endpoints = str(r.get('endpoint_count', 0))
        status = r.get('status', 'unknown').upper()[:10]

        lines.append(f"| {namespace:<15} | {name:<20} | {latency:<10} | {endpoints:<9} | {status:<10} |")

    lines.append("+" + "-" * 88 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes service endpoint latency',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all services in default namespace
  %(prog)s -n default

  # Check services across all namespaces (excluding system)
  %(prog)s

  # Include system namespaces
  %(prog)s --include-system

  # JSON output for monitoring integration
  %(prog)s --format json

  # Only show services with issues
  %(prog)s --warn-only

  # Custom latency thresholds
  %(prog)s --warn-threshold 100 --critical-threshold 500

  # Check specific services by label
  %(prog)s -l app=nginx

Exit codes:
  0 - All services responding within thresholds
  1 - Latency warnings or failures detected
  2 - Usage error or missing dependencies
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to check (default: all namespaces)'
    )
    parser.add_argument(
        '-l', '--selector',
        help='Label selector to filter services (e.g., app=nginx)'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show services with warnings or issues'
    )
    parser.add_argument(
        '--warn-threshold',
        type=int,
        default=200,
        help='Latency warning threshold in milliseconds (default: 200)'
    )
    parser.add_argument(
        '--critical-threshold',
        type=int,
        default=1000,
        help='Latency critical threshold in milliseconds (default: 1000)'
    )
    parser.add_argument(
        '--include-system',
        action='store_true',
        help='Include system namespaces (kube-system, etc.)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output including skipped services'
    )

    args = parser.parse_args()

    # Check dependencies
    if not check_kubectl():
        print("Error: kubectl is not available or not configured", file=sys.stderr)
        print("Please install kubectl and configure access to a cluster", file=sys.stderr)
        return 2

    # Validate thresholds
    if args.warn_threshold >= args.critical_threshold:
        print("Error: warn-threshold must be less than critical-threshold", file=sys.stderr)
        return 2

    # Get services
    services = get_services(args.namespace, args.selector)

    if services is None:
        print("Error: Failed to retrieve services from cluster", file=sys.stderr)
        return 2

    if not services:
        if args.format == 'json':
            print(json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(), 'services': [], 'has_issues': False}))
        else:
            print("No services found matching criteria")
        return 0

    # Analyze each service
    results = []
    for service in services:
        result = analyze_service(
            service,
            args.warn_threshold,
            args.critical_threshold,
            skip_system=not args.include_system
        )
        if result is not None:
            results.append(result)

    # Format output
    if args.format == 'json':
        output = format_json(results)
    elif args.format == 'table':
        output = format_table(results, args.warn_only)
    else:
        output = format_plain(results, args.warn_only)

    print(output)

    # Determine exit code
    has_critical = any(r and r.get('status') == 'critical' for r in results)
    has_warning = any(r and r.get('status') == 'warning' for r in results)

    if has_critical or has_warning:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
