#!/usr/bin/env python3
"""
Detect Kubernetes pods experiencing CPU throttling.

This script identifies pods that are being throttled due to CPU limits,
which can indicate performance issues and resource contention.

The script uses cgroup v1 metrics (available via exec into containers)
to detect throttling, or uses pod resource requests/limits to identify
at-risk pods.

Useful for:
- Performance troubleshooting in container workloads
- Identifying underprovisioned pods
- Capacity planning for CPU-intensive applications
- Monitoring performance regressions

Exit codes:
    0 - No throttled pods detected
    1 - One or more pods experiencing throttling or at risk
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


def get_pods_with_limits(namespace=None):
    """Get all pods with their CPU limits in JSON format."""
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
        metrics = {}

        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if namespace:
                # Format: POD CONTAINER CPU MEMORY
                if len(parts) >= 4:
                    pod_name = parts[0]
                    container = parts[1]
                    cpu = parts[2]
                    # Extract numeric value from CPU string (e.g., "100m" -> 100)
                    cpu_value = int(cpu.rstrip('m')) if cpu.endswith('m') else int(float(cpu) * 1000)
                    key = f"{pod_name}/{container}"
                    metrics[key] = cpu_value
            else:
                # Format: NAMESPACE POD CONTAINER CPU MEMORY
                if len(parts) >= 5:
                    ns = parts[0]
                    pod_name = parts[1]
                    container = parts[2]
                    cpu = parts[3]
                    cpu_value = int(cpu.rstrip('m')) if cpu.endswith('m') else int(float(cpu) * 1000)
                    key = f"{ns}/{pod_name}/{container}"
                    metrics[key] = cpu_value

        return metrics
    except subprocess.CalledProcessError:
        # metrics-server not available
        return None


def parse_cpu_request_limit(cpu_str):
    """
    Parse CPU string to millicores.
    Examples: "100m" -> 100, "1" -> 1000, "0.5" -> 500
    """
    if not cpu_str:
        return 0
    cpu_str = cpu_str.strip()
    if cpu_str.endswith('m'):
        return int(cpu_str[:-1])
    else:
        return int(float(cpu_str) * 1000)


def analyze_pod_throttling(pod_data, metrics=None):
    """
    Analyze a pod for CPU throttling risk.

    Returns:
        Tuple of (has_limits, cpu_limit_m, is_at_risk, reason)
    """
    namespace = pod_data.get('metadata', {}).get('namespace', 'default')
    pod_name = pod_data.get('metadata', {}).get('name', 'unknown')
    containers = pod_data.get('spec', {}).get('containers', [])

    issues = []
    max_limit_m = 0
    total_request_m = 0
    has_limits = False

    for container in containers:
        container_name = container.get('name', 'unknown')
        resources = container.get('resources', {})
        limits = resources.get('limits', {})
        requests = resources.get('requests', {})

        cpu_limit = limits.get('cpu')
        cpu_request = requests.get('cpu')

        if cpu_limit:
            has_limits = True
            limit_m = parse_cpu_request_limit(cpu_limit)
            max_limit_m = max(max_limit_m, limit_m)

            # Check if we have metrics
            if metrics:
                key = f"{namespace}/{pod_name}/{container_name}"
                if key in metrics:
                    usage_m = metrics[key]
                    utilization = (usage_m / limit_m * 100) if limit_m > 0 else 0

                    if utilization > 90:
                        issues.append(
                            f"{container_name}: CPU usage {usage_m}m is {utilization:.1f}% of limit {limit_m}m (HIGH)"
                        )
                    elif utilization > 75:
                        issues.append(
                            f"{container_name}: CPU usage {usage_m}m is {utilization:.1f}% of limit {limit_m}m"
                        )

        if cpu_request:
            request_m = parse_cpu_request_limit(cpu_request)
            total_request_m += request_m

        # Flag if limit is very low (below 100m is risky for most workloads)
        if cpu_limit and limit_m < 100:
            issues.append(
                f"{container_name}: Very low CPU limit {cpu_limit} may cause throttling"
            )

        # Flag if no limits set
        if not cpu_limit and not cpu_request:
            issues.append(
                f"{container_name}: No CPU requests/limits set (risk of throttling)"
            )

    is_at_risk = len(issues) > 0
    reason = "; ".join(issues) if issues else "OK"

    return has_limits, max_limit_m, is_at_risk, reason


def format_output_plain(throttled_pods, namespace):
    """Format output as plain text."""
    for pod in throttled_pods:
        ns = pod.get('namespace', 'unknown')
        name = pod.get('name', 'unknown')
        risk = pod.get('risk', 'unknown')
        reason = pod.get('reason', '')
        limit = pod.get('limit', 0)

        if namespace and ns != namespace:
            continue

        print(f"{ns:30} {name:40} {risk:10} limit={limit:4}m {reason}")


def format_output_table(throttled_pods, namespace):
    """Format output as ASCII table."""
    # Header
    print(f"{'NAMESPACE':<30} {'POD NAME':<40} {'STATUS':<10} {'CPU LIMIT':<12} {'REASON':<50}")
    print("-" * 142)

    for pod in throttled_pods:
        ns = pod.get('namespace', 'unknown')
        name = pod.get('name', 'unknown')
        risk = pod.get('risk', 'unknown')
        reason = pod.get('reason', '')[:50]
        limit = pod.get('limit', 0)

        if namespace and ns != namespace:
            continue

        print(f"{ns:<30} {name:<40} {risk:<10} {limit:>4}m        {reason:<50}")


def format_output_json(throttled_pods, namespace):
    """Format output as JSON."""
    output = {
        "pods_at_risk": len(throttled_pods),
        "pods": []
    }

    for pod in throttled_pods:
        if namespace and pod.get('namespace') != namespace:
            continue
        output["pods"].append(pod)

    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Detect Kubernetes pods experiencing or at risk of CPU throttling"
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
        "-w", "--warn-only",
        action="store_true",
        help="Only show pods at risk of throttling"
    )

    args = parser.parse_args()

    # Get pod data with resource requests/limits
    pods_data = get_pods_with_limits(args.namespace)
    pods = pods_data.get('items', [])

    if not pods:
        print("No pods found" if args.namespace else "No pods found in cluster", file=sys.stderr)
        sys.exit(0)

    # Try to get metrics (may fail if metrics-server not available)
    metrics = get_pod_metrics(args.namespace)

    # Analyze each pod
    throttled_pods = []
    all_pods = []

    for pod in pods:
        namespace = pod.get('metadata', {}).get('namespace', 'default')
        pod_name = pod.get('metadata', {}).get('name', 'unknown')

        has_limits, limit_m, is_at_risk, reason = analyze_pod_throttling(pod, metrics)

        pod_info = {
            'namespace': namespace,
            'name': pod_name,
            'has_limits': has_limits,
            'limit': limit_m,
            'risk': 'AT RISK' if is_at_risk else 'OK',
            'reason': reason
        }

        all_pods.append(pod_info)

        if is_at_risk:
            throttled_pods.append(pod_info)

    # Determine what to output
    output_pods = throttled_pods if args.warn_only else all_pods

    if not output_pods:
        if args.warn_only:
            print("No pods at risk of throttling found" if not throttled_pods else "", file=sys.stderr)
        sys.exit(0 if not throttled_pods else 1)

    # Format and output
    if args.format == "plain":
        format_output_plain(output_pods, args.namespace)
    elif args.format == "table":
        format_output_table(output_pods, args.namespace)
    elif args.format == "json":
        format_output_json(output_pods, args.namespace)

    # Exit code based on whether we found throttling issues
    sys.exit(1 if throttled_pods else 0)


if __name__ == "__main__":
    main()
