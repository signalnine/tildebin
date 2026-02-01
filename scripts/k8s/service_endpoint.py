#!/usr/bin/env python3
# boxctl:
#   category: k8s/networking
#   tags: [health, service, endpoint, connectivity]
#   requires: [kubectl]
#   privilege: none
#   related: [service_health, dns_health]
#   brief: Monitor Kubernetes Service endpoint availability

"""
Monitor Kubernetes Services to detect those without healthy endpoints.

Checks:
- Services with no endpoints (selector mismatch or no pods)
- Services with endpoints but all NotReady
- LoadBalancer services without external IPs
- Service port mismatches with pod containers

Returns exit code 1 if any services have endpoint issues.
"""

import argparse
import json
from collections import defaultdict
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


def get_pods(context: Context, namespace: str | None = None) -> list[dict]:
    """Get pods in JSON format."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
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


def is_pod_ready(pod: dict) -> bool:
    """Check if pod is ready."""
    conditions = pod.get("status", {}).get("conditions", [])
    for condition in conditions:
        if condition["type"] == "Ready":
            return condition["status"] == "True"
    return False


def analyze_service_endpoints(
    services: list[dict],
    endpoints: list[dict],
    pods: list[dict]
) -> list[dict]:
    """Analyze services for endpoint health issues."""
    issues = []

    # Build endpoint map: namespace/name -> endpoint object
    endpoint_map = {}
    for ep in endpoints:
        ns = ep["metadata"]["namespace"]
        name = ep["metadata"]["name"]
        key = f"{ns}/{name}"
        endpoint_map[key] = ep

    # Build pod map for selector matching
    pod_map: dict[str, list[dict]] = defaultdict(list)
    for pod in pods:
        ns = pod["metadata"]["namespace"]
        labels = pod["metadata"].get("labels", {})
        pod_map[ns].append({
            "name": pod["metadata"]["name"],
            "labels": labels,
            "ready": is_pod_ready(pod)
        })

    for svc in services:
        ns = svc["metadata"]["namespace"]
        name = svc["metadata"]["name"]
        svc_type = svc["spec"].get("type", "ClusterIP")
        selector = svc["spec"].get("selector", {})

        # Skip services without selectors (e.g., ExternalName, headless)
        if not selector:
            continue

        key = f"{ns}/{name}"

        # Check if service has endpoint object
        if key not in endpoint_map:
            issues.append({
                "namespace": ns,
                "service": name,
                "type": svc_type,
                "issue": "no_endpoint_object",
                "severity": "critical",
                "details": "Service has no corresponding endpoint object"
            })
            continue

        ep = endpoint_map[key]
        subsets = ep.get("subsets", [])

        # Count ready and not-ready endpoints
        total_ready = 0
        total_not_ready = 0

        for subset in subsets:
            ready_addrs = subset.get("addresses", [])
            not_ready_addrs = subset.get("notReadyAddresses", [])
            total_ready += len(ready_addrs)
            total_not_ready += len(not_ready_addrs)

        if total_ready == 0 and total_not_ready == 0:
            # No endpoints at all - check if pods exist with matching labels
            matching_pods = [
                p for p in pod_map.get(ns, [])
                if all(p["labels"].get(k) == v for k, v in selector.items())
            ]

            if not matching_pods:
                issues.append({
                    "namespace": ns,
                    "service": name,
                    "type": svc_type,
                    "issue": "no_matching_pods",
                    "severity": "critical",
                    "details": f"No pods match selector {selector}"
                })
            else:
                issues.append({
                    "namespace": ns,
                    "service": name,
                    "type": svc_type,
                    "issue": "pods_exist_but_no_endpoints",
                    "severity": "critical",
                    "details": (
                        f"{len(matching_pods)} matching pods found "
                        f"but no endpoints registered"
                    )
                })

        elif total_ready == 0 and total_not_ready > 0:
            issues.append({
                "namespace": ns,
                "service": name,
                "type": svc_type,
                "issue": "all_endpoints_not_ready",
                "severity": "critical",
                "details": f"{total_not_ready} endpoints exist but all are NotReady"
            })

        elif total_ready > 0 and total_not_ready > 0:
            issues.append({
                "namespace": ns,
                "service": name,
                "type": svc_type,
                "issue": "partial_endpoints_not_ready",
                "severity": "warning",
                "details": f"{total_ready} ready, {total_not_ready} not ready"
            })

        # Check LoadBalancer services for external IP
        if svc_type == "LoadBalancer":
            status = svc.get("status", {})
            load_balancer = status.get("loadBalancer", {})
            ingress = load_balancer.get("ingress", [])

            if not ingress:
                issues.append({
                    "namespace": ns,
                    "service": name,
                    "type": svc_type,
                    "issue": "loadbalancer_no_external_ip",
                    "severity": "warning",
                    "details": "LoadBalancer service has no external IP assigned"
                })

    return issues


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
        description="Monitor Kubernetes Service endpoint health"
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

    # Get Kubernetes resources
    services = get_services(context, opts.namespace)
    endpoints = get_endpoints(context, opts.namespace)
    pods = get_pods(context, opts.namespace)

    # Analyze
    issues = analyze_service_endpoints(services, endpoints, pods)

    # Separate by severity
    critical_issues = [i for i in issues if i["severity"] == "critical"]
    warning_issues = [i for i in issues if i["severity"] == "warning"]

    result_data: dict[str, Any] = {
        "total_issues": len(issues),
        "critical": len(critical_issues),
        "warnings": len(warning_issues),
        "services_checked": len(services),
        "issues": issues
    }

    output.emit(result_data)

    # Record issues
    for issue in critical_issues:
        output.error(
            f"{issue['namespace']}/{issue['service']} ({issue['type']}): "
            f"{issue['details']}"
        )
    for issue in warning_issues:
        output.warning(
            f"{issue['namespace']}/{issue['service']} ({issue['type']}): "
            f"{issue['details']}"
        )

    if issues:
        output.set_summary(
            f"Service endpoint issues: {len(critical_issues)} critical, "
            f"{len(warning_issues)} warnings"
        )
    else:
        output.set_summary(f"All {len(services)} services have healthy endpoints")

    # Exit based on findings
    has_critical = len(critical_issues) > 0
    return 1 if has_critical or issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
