#!/usr/bin/env python3
# boxctl:
#   category: k8s/pods
#   tags: [health, kubernetes, pods, resources, limits, oomkill]
#   requires: [kubectl]
#   brief: Audit pod resource usage and identify resource configuration issues

"""
Audit Kubernetes pod resource usage and identify resource issues.

Analyzes pod resource usage across a Kubernetes cluster, identifying:
- Pods with no resource requests/limits set
- OOMKilled pods and restart patterns
- Pods in CrashLoopBackOff state
- Evicted pods

Exit codes:
    0: No resource issues detected
    1: Resource issues found (warnings)
    2: Usage error or kubectl not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_pod_resources(pod: dict) -> list[str]:
    """Check if pod has resource requests and limits set."""
    issues = []
    containers = pod.get("spec", {}).get("containers", [])

    for container in containers:
        container_name = container.get("name", "unknown")
        resources = container.get("resources", {})
        requests = resources.get("requests", {})
        limits = resources.get("limits", {})

        if not requests:
            issues.append(f"Container '{container_name}' has no resource requests")
        else:
            if "cpu" not in requests:
                issues.append(f"Container '{container_name}' missing CPU request")
            if "memory" not in requests:
                issues.append(f"Container '{container_name}' missing memory request")

        if not limits:
            issues.append(f"Container '{container_name}' has no resource limits")
        else:
            if "memory" not in limits:
                issues.append(f"Container '{container_name}' missing memory limit")

    return issues


def check_pod_status(pod: dict) -> list[str]:
    """Check pod status for issues like OOMKilled, evictions, etc."""
    issues = []
    status = pod.get("status", {})

    # Check if pod is evicted
    reason = status.get("reason", "")
    if reason == "Evicted":
        message = status.get("message", "")
        issues.append(f"Pod evicted: {message}")

    # Check container statuses
    container_statuses = status.get("containerStatuses", [])
    for container_status in container_statuses:
        container_name = container_status.get("name", "unknown")
        restart_count = container_status.get("restartCount", 0)

        # Check for excessive restarts
        if restart_count > 5:
            issues.append(f"Container '{container_name}' has {restart_count} restarts")

        # Check last state for OOMKilled
        last_state = container_status.get("lastState", {})
        terminated = last_state.get("terminated", {})
        if terminated.get("reason") == "OOMKilled":
            issues.append(f"Container '{container_name}' was OOMKilled")

        # Check current state
        state = container_status.get("state", {})
        if "waiting" in state:
            waiting_reason = state["waiting"].get("reason", "")
            if waiting_reason in ["CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull"]:
                issues.append(f"Container '{container_name}' {waiting_reason}")

    return issues


def get_pods(context: Context, namespace: str | None = None) -> dict:
    """Get all pods in JSON format."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"kubectl failed: {result.stderr}")
    return json.loads(result.stdout)


def analyze_pods(pods_data: dict, warn_only: bool) -> list[dict]:
    """Analyze all pods and return issues."""
    pods = pods_data.get("items", [])
    results = []

    for pod in pods:
        pod_name = pod["metadata"]["name"]
        namespace = pod["metadata"].get("namespace", "default")

        # Check resource configuration
        resource_issues = check_pod_resources(pod)

        # Check pod status
        status_issues = check_pod_status(pod)

        all_issues = resource_issues + status_issues

        # Skip if no issues and warn_only is set
        if warn_only and not all_issues:
            continue

        pod_info = {
            "namespace": namespace,
            "name": pod_name,
            "phase": pod.get("status", {}).get("phase", "Unknown"),
            "issues": all_issues,
        }

        results.append(pod_info)

    return results


def format_output_plain(results: list[dict]) -> str:
    """Format results as plain text."""
    lines = []
    pods_with_issues = sum(1 for r in results if r["issues"])

    for pod_info in results:
        namespace = pod_info["namespace"]
        name = pod_info["name"]
        phase = pod_info["phase"]
        issues = pod_info["issues"]

        status_marker = "!" if issues else "OK"
        lines.append(f"{status_marker} Pod: {namespace}/{name} - {phase}")

        if issues:
            lines.append("  Issues:")
            for issue in issues:
                lines.append(f"    - {issue}")

        lines.append("")

    lines.append(f"Summary: {len(results)} pods analyzed, {pods_with_issues} with issues")
    return "\n".join(lines)


def format_output_json(results: list[dict]) -> str:
    """Format results as JSON."""
    pods_with_issues = sum(1 for r in results if r["issues"])
    output = {
        "total_pods": len(results),
        "pods_with_issues": pods_with_issues,
        "pods": results,
    }
    return json.dumps(output, indent=2)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit pod resource usage and identify resource configuration issues"
    )
    parser.add_argument(
        "-n", "--namespace", help="Namespace to audit (default: all namespaces)"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show pods with warnings or issues"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get pods
    try:
        pods_data = get_pods(context, opts.namespace)
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    # Analyze pods
    results = analyze_pods(pods_data, opts.warn_only)

    if not results:
        if opts.warn_only:
            print("No pods with issues found")
        else:
            print("No pods found")
        output.set_summary("no issues")
        return 0

    # Output
    if opts.format == "json":
        print(format_output_json(results))
    else:
        print(format_output_plain(results))

    # Check for issues
    has_issues = any(r["issues"] for r in results)
    pods_with_issues = sum(1 for r in results if r["issues"])
    output.set_summary(f"issues={pods_with_issues}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
