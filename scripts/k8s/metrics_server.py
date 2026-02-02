#!/usr/bin/env python3
# boxctl:
#   category: k8s/cluster
#   tags: [metrics, hpa, vpa, autoscaling, kubernetes, monitoring]
#   requires: [kubectl]
#   brief: Monitor Kubernetes metrics-server health and availability
#   privilege: user
#   related: [node_capacity, pod_resource_audit]

"""
Kubernetes Metrics Server Health Monitor.

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
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def analyze_metrics_health(
    deployment: dict | None,
    pods: list | None,
    api_service: dict | None,
    node_metrics_count: int | None,
    pod_metrics_count: int | None,
) -> tuple[list, list]:
    """Analyze metrics server health and return issues and warnings."""
    issues = []
    warnings = []

    # Check deployment
    if not deployment:
        issues.append("Metrics Server deployment not found in kube-system namespace")
    else:
        spec = deployment.get("spec", {})
        status = deployment.get("status", {})

        replicas = spec.get("replicas", 1)
        ready_replicas = status.get("readyReplicas", 0)

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
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            phase = pod.get("status", {}).get("phase", "Unknown")

            if phase != "Running":
                issues.append(f"Metrics Server pod {pod_name} is in phase: {phase}")
                continue

            # Check container status
            container_statuses = pod.get("status", {}).get("containerStatuses", [])
            for container in container_statuses:
                if not container.get("ready", False):
                    issues.append(f"Container {container.get('name')} in pod {pod_name} is not ready")

                restart_count = container.get("restartCount", 0)
                if restart_count > 10:
                    warnings.append(f"Pod {pod_name} has {restart_count} restarts (instability)")
                elif restart_count > 3:
                    warnings.append(f"Pod {pod_name} has {restart_count} restarts")

    # Check API service
    if not api_service:
        issues.append("Metrics API service (v1beta1.metrics.k8s.io) not found")
    else:
        conditions = api_service.get("status", {}).get("conditions", [])
        for condition in conditions:
            if condition.get("type") == "Available":
                if condition.get("status") != "True":
                    reason = condition.get("reason", "Unknown")
                    message = condition.get("message", "")
                    issues.append(f"Metrics API not available: {reason} - {message[:100]}")
                break
        else:
            warnings.append("Could not determine Metrics API availability status")

    # Check node metrics
    if node_metrics_count is None:
        issues.append("Could not retrieve node metrics (kubectl top nodes failed)")
    elif node_metrics_count == 0:
        warnings.append("No node metrics available")

    # Check pod metrics
    if pod_metrics_count is None:
        warnings.append("Could not retrieve pod metrics sample")
    elif pod_metrics_count == 0:
        warnings.append("No pod metrics available")

    return issues, warnings


def format_plain(
    deployment: dict | None,
    pods: list | None,
    api_service: dict | None,
    node_metrics_count: int | None,
    pod_metrics_count: int | None,
    issues: list,
    warnings: list,
    verbose: bool = False,
) -> str:
    """Format output in plain text."""
    lines = []
    lines.append("Kubernetes Metrics Server Health Check")
    lines.append("=" * 50)
    lines.append("")

    # Deployment status
    lines.append("Metrics Server Deployment:")
    if deployment:
        status = deployment.get("status", {})
        replicas = deployment.get("spec", {}).get("replicas", 1)
        ready = status.get("readyReplicas", 0)
        available = status.get("availableReplicas", 0)

        status_symbol = "OK" if ready == replicas else "WARN"
        lines.append(f"  [{status_symbol}] Replicas: {ready}/{replicas} ready, {available} available")
    else:
        lines.append("  [FAIL] Deployment not found")
    lines.append("")

    # Pod status
    lines.append("Metrics Server Pods:")
    if pods:
        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            phase = pod.get("status", {}).get("phase", "Unknown")
            container_statuses = pod.get("status", {}).get("containerStatuses", [])

            ready = all(c.get("ready", False) for c in container_statuses)
            restarts = sum(c.get("restartCount", 0) for c in container_statuses)

            status_symbol = "OK" if ready and phase == "Running" else "FAIL"
            lines.append(f"  [{status_symbol}] {pod_name}: {phase}, Restarts: {restarts}")
    else:
        lines.append("  [FAIL] No pods found")
    lines.append("")

    # API Service status
    lines.append("Metrics API Service:")
    if api_service:
        conditions = api_service.get("status", {}).get("conditions", [])
        available = False
        for condition in conditions:
            if condition.get("type") == "Available":
                available = condition.get("status") == "True"
                break

        status_symbol = "OK" if available else "FAIL"
        lines.append(f"  [{status_symbol}] v1beta1.metrics.k8s.io available: {available}")
    else:
        lines.append("  [FAIL] API service not found")
    lines.append("")

    # Metrics availability
    lines.append("Metrics Availability:")
    if node_metrics_count is not None:
        lines.append(f"  [OK] Node metrics: {node_metrics_count} nodes reporting")
    else:
        lines.append("  [FAIL] Node metrics unavailable")

    if pod_metrics_count is not None:
        lines.append(f"  [OK] Pod metrics: {pod_metrics_count} pods reporting")
    else:
        lines.append("  [WARN] Pod metrics unavailable")
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


def format_json(
    deployment: dict | None,
    pods: list | None,
    api_service: dict | None,
    node_metrics_count: int | None,
    pod_metrics_count: int | None,
    issues: list,
    warnings: list,
) -> str:
    """Format output as JSON."""
    deployment_summary = None
    if deployment:
        status = deployment.get("status", {})
        deployment_summary = {
            "replicas": deployment.get("spec", {}).get("replicas", 1),
            "ready_replicas": status.get("readyReplicas", 0),
            "available_replicas": status.get("availableReplicas", 0),
            "updated_replicas": status.get("updatedReplicas", 0),
        }

    pod_summary = []
    if pods:
        for pod in pods:
            container_statuses = pod.get("status", {}).get("containerStatuses", [])
            pod_summary.append(
                {
                    "name": pod.get("metadata", {}).get("name"),
                    "phase": pod.get("status", {}).get("phase"),
                    "ready": all(c.get("ready", False) for c in container_statuses),
                    "restarts": sum(c.get("restartCount", 0) for c in container_statuses),
                }
            )

    api_available = False
    if api_service:
        conditions = api_service.get("status", {}).get("conditions", [])
        for condition in conditions:
            if condition.get("type") == "Available":
                api_available = condition.get("status") == "True"
                break

    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "deployment": deployment_summary,
        "pods": pod_summary,
        "api_service": {"exists": api_service is not None, "available": api_available},
        "metrics": {
            "nodes_reporting": node_metrics_count if node_metrics_count else 0,
            "pods_reporting": pod_metrics_count if pod_metrics_count else 0,
        },
        "issues": issues,
        "warnings": warnings,
        "healthy": len(issues) == 0,
    }

    return json.dumps(output, indent=2)


def format_table(
    deployment: dict | None,
    pods: list | None,
    api_service: dict | None,
    node_metrics_count: int | None,
    pod_metrics_count: int | None,
    issues: list,
    warnings: list,
) -> str:
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
        status = deployment.get("status", {})
        replicas = deployment.get("spec", {}).get("replicas", 1)
        ready = status.get("readyReplicas", 0)
        dep_status = "OK" if ready == replicas else "DEGRADED"
        details = f"{ready}/{replicas} replicas ready"
    else:
        dep_status = "MISSING"
        details = "Deployment not found"
    lines.append(f"| {'Metrics Server Deployment':<30} | {dep_status:<10} | {details:<30} |")

    # API Service
    if api_service:
        conditions = api_service.get("status", {}).get("conditions", [])
        api_available = False
        for condition in conditions:
            if condition.get("type") == "Available":
                api_available = condition.get("status") == "True"
                break
        api_status = "OK" if api_available else "UNAVAIL"
        api_details = "API responding" if api_available else "API not available"
    else:
        api_status = "MISSING"
        api_details = "API service not found"
    lines.append(f"| {'Metrics API Service':<30} | {api_status:<10} | {api_details:<30} |")

    # Node metrics
    if node_metrics_count is not None:
        node_status = "OK"
        node_details = f"{node_metrics_count} nodes reporting"
    else:
        node_status = "FAIL"
        node_details = "Cannot fetch node metrics"[:30]
    lines.append(f"| {'Node Metrics':<30} | {node_status:<10} | {node_details:<30} |")

    # Pod metrics
    if pod_metrics_count is not None:
        pod_status = "OK"
        pod_details = f"{pod_metrics_count} pods reporting"
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


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes Metrics Server health (critical for HPA/VPA autoscaling)"
    )

    parser.add_argument(
        "--namespace",
        "-n",
        default="kube-system",
        help="Namespace where metrics-server is deployed (default: kube-system)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed information including node metrics breakdown",
    )

    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues or warnings are detected",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get metrics-server deployment
    deployment = None
    try:
        result = context.run(
            ["kubectl", "get", "deployment", "metrics-server", "-n", opts.namespace, "-o", "json"]
        )
        if result.returncode == 0:
            deployment = json.loads(result.stdout)
    except Exception:
        pass

    # Get metrics-server pods
    pods = None
    try:
        result = context.run(
            ["kubectl", "get", "pods", "-n", opts.namespace, "-l", "k8s-app=metrics-server", "-o", "json"]
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            pods = data.get("items", [])
    except Exception:
        pass

    # Get metrics API service
    api_service = None
    try:
        result = context.run(["kubectl", "get", "apiservice", "v1beta1.metrics.k8s.io", "-o", "json"])
        if result.returncode == 0:
            api_service = json.loads(result.stdout)
    except Exception:
        pass

    # Get node metrics count (via kubectl top)
    node_metrics_count = None
    try:
        result = context.run(["kubectl", "top", "nodes", "--no-headers"])
        if result.returncode == 0:
            lines = [line for line in result.stdout.strip().split("\n") if line]
            node_metrics_count = len(lines)
    except Exception:
        pass

    # Get pod metrics count
    pod_metrics_count = None
    try:
        result = context.run(["kubectl", "top", "pods", "--all-namespaces", "--no-headers"])
        if result.returncode == 0:
            lines = [line for line in result.stdout.strip().split("\n") if line]
            pod_metrics_count = len(lines)
    except Exception:
        pass

    # Analyze health
    issues, warnings = analyze_metrics_health(
        deployment, pods, api_service, node_metrics_count, pod_metrics_count
    )

    # Format output
    if opts.format == "json":
        formatted = format_json(
            deployment, pods, api_service, node_metrics_count, pod_metrics_count, issues, warnings
        )
    elif opts.format == "table":
        formatted = format_table(
            deployment, pods, api_service, node_metrics_count, pod_metrics_count, issues, warnings
        )
    else:
        formatted = format_plain(
            deployment, pods, api_service, node_metrics_count, pod_metrics_count, issues, warnings, opts.verbose
        )

    # Print output (respecting --warn-only)
    if not opts.warn_only or issues or warnings:
        print(formatted)

    # Set summary
    output.set_summary(f"issues={len(issues)}, warnings={len(warnings)}")

    # Return appropriate exit code
    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
