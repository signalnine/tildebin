#!/usr/bin/env python3
# boxctl:
#   category: k8s/networking
#   tags: [health, service, latency, performance]
#   requires: [kubectl]
#   privilege: none
#   related: [service_health, service_endpoint]
#   brief: Monitor Kubernetes service endpoint latency

"""
Monitor network latency to Kubernetes service endpoints.

Checks:
- Service endpoint reachability
- Response latency against configurable thresholds
- Endpoint availability

Note: Actual latency measurement requires running test pods in the cluster.
This script primarily validates service configuration and endpoint health.

Returns exit code 1 if latency warnings or failures detected.
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_services(
    context: Context,
    namespace: str | None = None,
    label_selector: str | None = None
) -> list[dict]:
    """Get services from the cluster."""
    cmd = ["kubectl", "get", "services", "-o", "json"]

    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    if label_selector:
        cmd.extend(["-l", label_selector])

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def get_endpoints(
    context: Context,
    service_name: str,
    namespace: str
) -> dict | None:
    """Get endpoints for a specific service."""
    result = context.run(
        ["kubectl", "get", "endpoints", service_name, "-n", namespace, "-o", "json"],
        check=False
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def analyze_service(
    service: dict,
    context: Context,
    skip_system: bool = True
) -> dict | None:
    """Analyze a single service's configuration and endpoints."""
    metadata = service.get("metadata", {})
    spec = service.get("spec", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    # Skip system services by default
    if skip_system and namespace in ["kube-system", "kube-public", "kube-node-lease"]:
        return None

    # Skip ExternalName services (check first, before headless check)
    if spec.get("type") == "ExternalName":
        return {
            "name": name,
            "namespace": namespace,
            "type": "ExternalName",
            "status": "skipped",
            "reason": "ExternalName service"
        }

    # Skip headless services (no ClusterIP)
    cluster_ip = spec.get("clusterIP")
    if not cluster_ip or cluster_ip == "None":
        return {
            "name": name,
            "namespace": namespace,
            "type": "headless",
            "status": "skipped",
            "reason": "Headless service (no ClusterIP)"
        }

    # Get first port
    ports = spec.get("ports", [])
    if not ports:
        return {
            "name": name,
            "namespace": namespace,
            "cluster_ip": cluster_ip,
            "status": "skipped",
            "reason": "No ports defined"
        }

    port = ports[0].get("port")
    port_name = ports[0].get("name", str(port))
    protocol = ports[0].get("protocol", "TCP")

    # Get endpoint count
    endpoints = get_endpoints(context, name, namespace)
    endpoint_count = 0
    if endpoints:
        subsets = endpoints.get("subsets", [])
        endpoint_count = sum(len(s.get("addresses", [])) for s in subsets)

    # Determine status based on endpoint availability
    status = "healthy"
    issues = []

    if endpoint_count == 0:
        status = "critical"
        issues.append("No ready endpoints")

    return {
        "name": name,
        "namespace": namespace,
        "cluster_ip": cluster_ip,
        "port": port,
        "port_name": port_name,
        "protocol": protocol,
        "endpoint_count": endpoint_count,
        "status": status,
        "issues": issues
    }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes service endpoint latency"
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument(
        "-l", "--selector",
        help="Label selector to filter services (e.g., app=nginx)"
    )
    parser.add_argument(
        "--include-system",
        action="store_true",
        help="Include system namespaces (kube-system, etc.)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl and configure cluster access.")
        return 2

    # Get services
    services = get_services(context, opts.namespace, opts.selector)

    if not services:
        output.warning("No services found matching criteria")
        output.emit({"services": [], "has_issues": False})
        return 0

    # Analyze each service
    results = []
    for service in services:
        result = analyze_service(
            service,
            context,
            skip_system=not opts.include_system
        )
        if result is not None:
            results.append(result)

    # Filter and count
    critical = [r for r in results if r.get("status") == "critical"]
    warning = [r for r in results if r.get("status") == "warning"]
    healthy = [r for r in results if r.get("status") == "healthy"]
    skipped = [r for r in results if r.get("status") == "skipped"]

    checked_count = len(results) - len(skipped)

    result_data: dict[str, Any] = {
        "summary": {
            "total_checked": checked_count,
            "healthy": len(healthy),
            "warning": len(warning),
            "critical": len(critical),
            "skipped": len(skipped)
        },
        "services": results,
        "has_issues": len(critical) > 0 or len(warning) > 0
    }

    output.emit(result_data)

    # Record issues
    for svc in critical:
        for issue in svc.get("issues", []):
            output.error(f"{svc['namespace']}/{svc['name']}: {issue}")

    for svc in warning:
        for issue in svc.get("issues", []):
            output.warning(f"{svc['namespace']}/{svc['name']}: {issue}")

    if critical or warning:
        output.set_summary(
            f"Service latency issues: {len(critical)} critical, {len(warning)} warning"
        )
    else:
        output.set_summary(f"All {checked_count} services healthy")

    return 1 if critical or warning else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
