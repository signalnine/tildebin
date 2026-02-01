#!/usr/bin/env python3
# boxctl:
#   category: k8s/networking
#   tags: [health, service, endpoint, monitoring]
#   requires: [kubectl]
#   privilege: none
#   related: [service_endpoint, dns_health]
#   brief: Monitor Kubernetes Service health and endpoint availability

"""
Monitor the health of Kubernetes Services by checking endpoint readiness.

Checks:
- Service endpoint availability (ready vs not-ready endpoints)
- Service type and configuration
- Services with zero endpoints (potential issues)

Returns exit code 1 if any services have issues.
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_services(context: Context, namespace: str | None = None) -> list[dict]:
    """Get services in JSON format."""
    cmd = ["kubectl", "get", "services", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def get_endpoints(context: Context, namespace: str | None = None) -> list[dict]:
    """Get endpoints in JSON format."""
    cmd = ["kubectl", "get", "endpoints", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def analyze_service_health(
    services: list[dict],
    endpoints: list[dict],
    verbose: bool = False
) -> tuple[list[dict], list[dict]]:
    """
    Analyze service health by correlating services with their endpoints.

    Returns:
        tuple: (issues, healthy_services)
    """
    issues = []
    healthy_services = []

    # Create endpoint lookup map
    endpoints_map = {}
    for ep in endpoints:
        namespace = ep["metadata"].get("namespace", "default")
        name = ep["metadata"]["name"]
        key = f"{namespace}/{name}"
        endpoints_map[key] = ep

    # Analyze each service
    for svc in services:
        namespace = svc["metadata"].get("namespace", "default")
        name = svc["metadata"]["name"]
        svc_type = svc["spec"].get("type", "ClusterIP")
        key = f"{namespace}/{name}"

        # Skip headless services (ClusterIP: None)
        cluster_ip = svc["spec"].get("clusterIP")
        if cluster_ip == "None":
            if verbose:
                healthy_services.append({
                    "namespace": namespace,
                    "name": name,
                    "type": "Headless",
                    "status": "healthy",
                    "message": "Headless service (no health check needed)"
                })
            continue

        # Get corresponding endpoint
        ep = endpoints_map.get(key)

        if not ep:
            issues.append({
                "namespace": namespace,
                "name": name,
                "type": svc_type,
                "severity": "warning",
                "issue": "No endpoint object found",
                "ready_endpoints": 0,
                "total_endpoints": 0
            })
            continue

        # Count ready and not-ready endpoints
        ready_count = 0
        not_ready_count = 0

        subsets = ep.get("subsets", [])

        if not subsets:
            issues.append({
                "namespace": namespace,
                "name": name,
                "type": svc_type,
                "severity": "error",
                "issue": "No endpoints available (no backing pods)",
                "ready_endpoints": 0,
                "total_endpoints": 0
            })
            continue

        for subset in subsets:
            ready_addresses = subset.get("addresses", [])
            not_ready_addresses = subset.get("notReadyAddresses", [])
            ready_count += len(ready_addresses)
            not_ready_count += len(not_ready_addresses)

        total_endpoints = ready_count + not_ready_count

        if ready_count == 0 and not_ready_count > 0:
            issues.append({
                "namespace": namespace,
                "name": name,
                "type": svc_type,
                "severity": "error",
                "issue": "All endpoints not ready",
                "ready_endpoints": 0,
                "total_endpoints": total_endpoints
            })
        elif ready_count > 0 and not_ready_count > 0:
            issues.append({
                "namespace": namespace,
                "name": name,
                "type": svc_type,
                "severity": "warning",
                "issue": "Some endpoints not ready",
                "ready_endpoints": ready_count,
                "total_endpoints": total_endpoints
            })
        elif ready_count > 0:
            if verbose:
                healthy_services.append({
                    "namespace": namespace,
                    "name": name,
                    "type": svc_type,
                    "status": "healthy",
                    "ready_endpoints": ready_count,
                    "total_endpoints": total_endpoints
                })

    return issues, healthy_services


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
        description="Monitor Kubernetes Service health and endpoint availability"
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl and configure cluster access.")
        return 2

    # Get services and endpoints
    services = get_services(context, opts.namespace)
    endpoints = get_endpoints(context, opts.namespace)

    # Analyze health
    issues, healthy_services = analyze_service_health(
        services, endpoints, verbose=opts.verbose
    )

    # Separate by severity
    errors = [i for i in issues if i["severity"] == "error"]
    warnings = [i for i in issues if i["severity"] == "warning"]

    result_data: dict[str, Any] = {
        "issues": issues,
        "summary": {
            "total_issues": len(issues),
            "errors": len(errors),
            "warnings": len(warnings),
            "services_checked": len(services)
        }
    }

    if opts.verbose:
        result_data["healthy_services"] = healthy_services
        result_data["summary"]["healthy_services"] = len(healthy_services)

    output.emit(result_data)

    # Record issues
    for issue in errors:
        output.error(
            f"{issue['namespace']}/{issue['name']} ({issue['type']}): "
            f"{issue['issue']} ({issue['ready_endpoints']}/{issue['total_endpoints']} ready)"
        )
    for issue in warnings:
        output.warning(
            f"{issue['namespace']}/{issue['name']} ({issue['type']}): "
            f"{issue['issue']} ({issue['ready_endpoints']}/{issue['total_endpoints']} ready)"
        )

    if issues:
        output.set_summary(
            f"Service health issues: {len(errors)} errors, {len(warnings)} warnings"
        )
    else:
        output.set_summary(f"All {len(services)} services healthy")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
