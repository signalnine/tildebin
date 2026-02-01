#!/usr/bin/env python3
# boxctl:
#   category: k8s/pods
#   tags: [health, kubernetes, pods, cpu, throttling, performance]
#   requires: [kubectl]
#   brief: Detect pods at risk of CPU throttling due to limits

"""
Detect Kubernetes pods at risk of CPU throttling.

Identifies pods that are being throttled or at risk of throttling due to
CPU limits. This can indicate performance issues and resource contention.

Exit codes:
    0: No throttled pods detected
    1: One or more pods at risk of throttling
    2: Usage error or kubectl not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_cpu_value(cpu_str: str) -> int:
    """
    Parse CPU string to millicores.
    Examples: "100m" -> 100, "1" -> 1000, "0.5" -> 500
    """
    if not cpu_str:
        return 0
    cpu_str = cpu_str.strip()
    if cpu_str.endswith("m"):
        return int(cpu_str[:-1])
    else:
        return int(float(cpu_str) * 1000)


def get_pods(context: Context, namespace: str | None = None) -> dict:
    """Get all pods with their CPU limits in JSON format."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"kubectl failed: {result.stderr}")
    return json.loads(result.stdout)


def analyze_pod_throttling(pod_data: dict) -> tuple[bool, int, bool, str]:
    """
    Analyze a pod for CPU throttling risk.

    Returns:
        Tuple of (has_limits, cpu_limit_m, is_at_risk, reason)
    """
    containers = pod_data.get("spec", {}).get("containers", [])

    issues = []
    max_limit_m = 0
    has_limits = False

    for container in containers:
        container_name = container.get("name", "unknown")
        resources = container.get("resources", {})
        limits = resources.get("limits", {})
        requests = resources.get("requests", {})

        cpu_limit = limits.get("cpu")
        cpu_request = requests.get("cpu")

        if cpu_limit:
            has_limits = True
            limit_m = parse_cpu_value(cpu_limit)
            max_limit_m = max(max_limit_m, limit_m)

            # Flag if limit is very low (below 100m is risky for most workloads)
            if limit_m < 100:
                issues.append(
                    f"{container_name}: Very low CPU limit {cpu_limit} may cause throttling"
                )

        # Flag if no limits set
        if not cpu_limit and not cpu_request:
            issues.append(f"{container_name}: No CPU requests/limits set (unbounded)")

    is_at_risk = len(issues) > 0
    reason = "; ".join(issues) if issues else "OK"

    return has_limits, max_limit_m, is_at_risk, reason


def format_output_plain(throttled_pods: list[dict]) -> str:
    """Format output as plain text."""
    lines = []
    for pod in throttled_pods:
        ns = pod.get("namespace", "unknown")
        name = pod.get("name", "unknown")
        risk = pod.get("risk", "unknown")
        reason = pod.get("reason", "")
        limit = pod.get("limit", 0)

        lines.append(f"{ns:30} {name:40} {risk:10} limit={limit:4}m {reason}")

    return "\n".join(lines)


def format_output_table(throttled_pods: list[dict]) -> str:
    """Format output as ASCII table."""
    lines = []
    lines.append(f"{'NAMESPACE':<30} {'POD NAME':<40} {'STATUS':<10} {'CPU LIMIT':<12} {'REASON':<50}")
    lines.append("-" * 142)

    for pod in throttled_pods:
        ns = pod.get("namespace", "unknown")
        name = pod.get("name", "unknown")
        risk = pod.get("risk", "unknown")
        reason = pod.get("reason", "")[:50]
        limit = pod.get("limit", 0)

        lines.append(f"{ns:<30} {name:<40} {risk:<10} {limit:>4}m        {reason:<50}")

    return "\n".join(lines)


def format_output_json(throttled_pods: list[dict]) -> str:
    """Format output as JSON."""
    output = {
        "pods_at_risk": len([p for p in throttled_pods if p.get("risk") == "AT RISK"]),
        "pods": throttled_pods,
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
        0 = healthy, 1 = throttling risk, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Detect pods at risk of CPU throttling due to limits"
    )
    parser.add_argument(
        "-n", "--namespace", help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show pods at risk of throttling"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get pods
    try:
        pods_data = get_pods(context, opts.namespace)
        pods = pods_data.get("items", [])
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    if not pods:
        print("No pods found")
        output.set_summary("no pods")
        return 0

    # Analyze each pod
    throttled_pods = []
    all_pods = []

    for pod in pods:
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name", "unknown")

        has_limits, limit_m, is_at_risk, reason = analyze_pod_throttling(pod)

        pod_info = {
            "namespace": namespace,
            "name": pod_name,
            "has_limits": has_limits,
            "limit": limit_m,
            "risk": "AT RISK" if is_at_risk else "OK",
            "reason": reason,
        }

        all_pods.append(pod_info)

        if is_at_risk:
            throttled_pods.append(pod_info)

    # Determine what to output
    output_pods = throttled_pods if opts.warn_only else all_pods

    if not output_pods:
        if opts.warn_only:
            print("No pods at risk of throttling found")
        output.set_summary("no throttling risk")
        return 0 if not throttled_pods else 1

    # Output
    if opts.format == "plain":
        print(format_output_plain(output_pods))
    elif opts.format == "table":
        print(format_output_table(output_pods))
    elif opts.format == "json":
        print(format_output_json(output_pods))

    output.set_summary(f"at_risk={len(throttled_pods)}")

    return 1 if throttled_pods else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
