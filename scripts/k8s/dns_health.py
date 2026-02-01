#!/usr/bin/env python3
# boxctl:
#   category: k8s/networking
#   tags: [health, dns, coredns, kube-dns]
#   requires: [kubectl]
#   privilege: none
#   related: [service_health, service_endpoint]
#   brief: Monitor Kubernetes DNS health (CoreDNS/kube-dns)

"""
Monitor the health of DNS resolution in a Kubernetes cluster.

Checks:
- CoreDNS/kube-dns pod health and readiness
- DNS service endpoint availability
- Pod restart patterns that might indicate DNS issues

Returns exit code 1 if DNS issues detected.
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_dns_pods(context: Context, namespace: str = "kube-system") -> list[dict]:
    """Get CoreDNS/kube-dns pod information."""
    result = context.run(
        ["kubectl", "get", "pods", "-n", namespace,
         "-l", "k8s-app=kube-dns", "-o", "json"],
        check=False
    )
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def get_dns_service(context: Context, namespace: str = "kube-system") -> dict | None:
    """Get DNS service information."""
    result = context.run(
        ["kubectl", "get", "service", "kube-dns", "-n", namespace, "-o", "json"],
        check=False
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def get_dns_endpoints(context: Context, namespace: str = "kube-system") -> dict | None:
    """Get DNS service endpoints."""
    result = context.run(
        ["kubectl", "get", "endpoints", "kube-dns", "-n", namespace, "-o", "json"],
        check=False
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def analyze_dns_health(
    pods: list[dict],
    service: dict | None,
    endpoints: dict | None
) -> tuple[list[str], list[str]]:
    """Analyze DNS health and return (issues, warnings)."""
    issues = []
    warnings = []

    # Check pods
    if not pods:
        issues.append("No CoreDNS/kube-dns pods found")
    else:
        ready_pods = 0
        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            status = pod.get("status", {})
            phase = status.get("phase", "Unknown")

            if phase != "Running":
                issues.append(f"Pod {pod_name} is in phase: {phase}")
                continue

            container_statuses = status.get("containerStatuses", [])
            for container in container_statuses:
                if not container.get("ready", False):
                    issues.append(
                        f"Pod {pod_name} container {container.get('name')} is not ready"
                    )
                else:
                    ready_pods += 1

                restart_count = container.get("restartCount", 0)
                if restart_count > 10:
                    warnings.append(
                        f"Pod {pod_name} has {restart_count} restarts (possible instability)"
                    )
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
        cluster_ip = service.get("spec", {}).get("clusterIP")
        if not cluster_ip or cluster_ip == "None":
            issues.append("DNS service has no ClusterIP")

    # Check endpoints
    if not endpoints:
        issues.append("DNS service endpoints not found")
    else:
        subsets = endpoints.get("subsets", [])
        if not subsets:
            issues.append("DNS service has no endpoint subsets")
        else:
            ready_addresses = sum(
                len(subset.get("addresses", [])) for subset in subsets
            )
            not_ready_addresses = sum(
                len(subset.get("notReadyAddresses", [])) for subset in subsets
            )

            if ready_addresses == 0:
                issues.append("DNS service has no ready endpoints")

            if not_ready_addresses > 0:
                warnings.append(
                    f"DNS service has {not_ready_addresses} not-ready endpoint(s)"
                )

    return issues, warnings


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
    parser = argparse.ArgumentParser(description="Monitor Kubernetes DNS health")
    parser.add_argument(
        "-n", "--namespace",
        default="kube-system",
        help="Namespace where DNS pods run (default: kube-system)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl and configure cluster access.")
        return 2

    # Gather DNS health data
    pods = get_dns_pods(context, opts.namespace)
    service = get_dns_service(context, opts.namespace)
    endpoints = get_dns_endpoints(context, opts.namespace)

    # Analyze health
    issues, warnings = analyze_dns_health(pods, service, endpoints)

    # Build pod summaries
    pod_summaries = []
    for pod in pods:
        container_statuses = pod.get("status", {}).get("containerStatuses", [])
        pod_summaries.append({
            "name": pod.get("metadata", {}).get("name"),
            "phase": pod.get("status", {}).get("phase"),
            "ready": all(c.get("ready", False) for c in container_statuses),
            "restarts": sum(c.get("restartCount", 0) for c in container_statuses)
        })

    # Build endpoint summary
    endpoint_summary = {"ready": 0, "not_ready": 0}
    if endpoints:
        subsets = endpoints.get("subsets", [])
        endpoint_summary["ready"] = sum(
            len(s.get("addresses", [])) for s in subsets
        )
        endpoint_summary["not_ready"] = sum(
            len(s.get("notReadyAddresses", [])) for s in subsets
        )

    # Emit data
    result_data: dict[str, Any] = {
        "pods": pod_summaries,
        "service": {
            "exists": service is not None,
            "cluster_ip": service.get("spec", {}).get("clusterIP") if service else None
        },
        "endpoints": endpoint_summary,
        "issues": issues,
        "warnings": warnings,
        "healthy": len(issues) == 0
    }

    output.emit(result_data)

    # Record issues/warnings in output
    for issue in issues:
        output.error(issue)
    for warning in warnings:
        output.warning(warning)

    # Set summary
    ready_count = sum(1 for p in pod_summaries if p.get("ready"))
    total_count = len(pod_summaries)
    if issues:
        output.set_summary(f"DNS unhealthy: {len(issues)} issue(s)")
    elif warnings:
        output.set_summary(f"DNS healthy with warnings: {ready_count}/{total_count} pods ready")
    else:
        output.set_summary(f"DNS healthy: {ready_count}/{total_count} pods ready")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
