#!/usr/bin/env python3
# boxctl:
#   category: k8s/pods
#   tags: [health, kubernetes, pods, restarts, oomkill, crashloop]
#   requires: [kubectl]
#   brief: Analyze container restart patterns and identify root causes

"""
Analyze Kubernetes container restart patterns and identify root causes.

Identifies chronic restart issues by analyzing restart patterns,
categorizing causes (OOMKills, CrashLoopBackOff, probe failures),
and providing actionable remediation suggestions.

Exit codes:
    0: No restarts or only informational findings
    1: Restarts detected with warnings
    2: Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def categorize_restart_reason(reason: str, exit_code: int | None, waiting_reason: str | None) -> str:
    """Categorize the restart reason into high-level categories."""
    reason_lower = str(reason).lower()
    waiting_lower = str(waiting_reason).lower() if waiting_reason else ""

    if "oomkilled" in reason_lower or exit_code == 137:
        return "OOMKilled"

    if "crashloop" in waiting_lower:
        return "CrashLoopBackOff"

    if exit_code and exit_code != 0 and exit_code != 137:
        return "ApplicationError"

    if "liveness" in reason_lower or "readiness" in reason_lower:
        return "ProbeFailure"

    if "evicted" in reason_lower:
        return "Evicted"

    if exit_code == 143:
        return "SIGTERM"
    elif exit_code == 137 and "oom" not in reason_lower:
        return "SIGKILL"

    return "Unknown"


def get_pods_with_restarts(
    context: Context, namespace: str | None = None
) -> list[dict]:
    """Get all pods with restart information."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"kubectl failed: {result.stderr}")

    pods_data = json.loads(result.stdout)
    pods_with_restarts = []

    for pod in pods_data.get("items", []):
        pod_name = pod["metadata"]["name"]
        pod_namespace = pod["metadata"]["namespace"]
        pod_created = pod["metadata"].get("creationTimestamp", "")

        container_statuses = pod.get("status", {}).get("containerStatuses", [])

        for container in container_statuses:
            restart_count = container.get("restartCount", 0)

            if restart_count > 0:
                last_state = container.get("lastState", {})
                current_state = container.get("state", {})

                reason = "Unknown"
                exit_code = None
                last_restart_time = None

                if "terminated" in last_state:
                    terminated = last_state["terminated"]
                    reason = terminated.get("reason", "Unknown")
                    exit_code = terminated.get("exitCode")
                    last_restart_time = terminated.get("finishedAt", "")

                waiting_reason = None
                if "waiting" in current_state:
                    waiting_reason = current_state["waiting"].get("reason")

                pods_with_restarts.append({
                    "namespace": pod_namespace,
                    "pod_name": pod_name,
                    "container_name": container["name"],
                    "restart_count": restart_count,
                    "reason": reason,
                    "exit_code": exit_code,
                    "waiting_reason": waiting_reason,
                    "last_restart_time": last_restart_time,
                    "pod_created": pod_created,
                    "ready": container.get("ready", False),
                })

    return pods_with_restarts


def analyze_restarts(pods_with_restarts: list[dict]) -> dict:
    """Analyze restart patterns and categorize issues."""
    analysis = {
        "total_pods": len(pods_with_restarts),
        "total_restarts": sum(p["restart_count"] for p in pods_with_restarts),
        "by_category": defaultdict(list),
        "by_namespace": defaultdict(int),
        "flapping_containers": [],
    }

    for pod in pods_with_restarts:
        category = categorize_restart_reason(
            pod["reason"], pod["exit_code"], pod["waiting_reason"]
        )

        analysis["by_category"][category].append(pod)
        analysis["by_namespace"][pod["namespace"]] += pod["restart_count"]

        if pod["restart_count"] >= 5:
            analysis["flapping_containers"].append(pod)

    return analysis


def format_output_plain(analysis: dict, verbose: bool = False, warn_only: bool = False) -> str:
    """Format output in plain text."""
    lines = []

    if not warn_only:
        lines.append("Container Restart Analysis")
        lines.append("=" * 60)
        lines.append(f"Total containers with restarts: {analysis['total_pods']}")
        lines.append(f"Total restart count: {analysis['total_restarts']}")
        lines.append("")

    if analysis["by_category"]:
        lines.append("Restarts by Category:")
        lines.append("-" * 60)
        for category, pods in sorted(
            analysis["by_category"].items(), key=lambda x: len(x[1]), reverse=True
        ):
            restart_sum = sum(p["restart_count"] for p in pods)
            lines.append(f"  {category}: {len(pods)} containers, {restart_sum} total restarts")
        lines.append("")

    if not warn_only and analysis["by_namespace"]:
        lines.append("Restarts by Namespace:")
        lines.append("-" * 60)
        for namespace, count in sorted(
            analysis["by_namespace"].items(), key=lambda x: x[1], reverse=True
        )[:10]:
            lines.append(f"  {namespace}: {count} restarts")
        lines.append("")

    if analysis["flapping_containers"]:
        lines.append("Flapping Containers (5+ restarts):")
        lines.append("-" * 60)
        for pod in sorted(
            analysis["flapping_containers"], key=lambda x: x["restart_count"], reverse=True
        ):
            category = categorize_restart_reason(
                pod["reason"], pod["exit_code"], pod["waiting_reason"]
            )
            lines.append(f"  {pod['namespace']}/{pod['pod_name']}/{pod['container_name']}")
            lines.append(f"    Restarts: {pod['restart_count']}, Category: {category}")
            lines.append(f"    Ready: {pod['ready']}, Last Reason: {pod['reason']}")
            lines.append("")

    return "\n".join(lines)


def format_output_json(analysis: dict) -> str:
    """Format output as JSON."""
    output = {
        "total_pods": analysis["total_pods"],
        "total_restarts": analysis["total_restarts"],
        "by_category": {k: v for k, v in analysis["by_category"].items()},
        "by_namespace": dict(analysis["by_namespace"]),
        "flapping_containers": analysis["flapping_containers"],
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
        0 = healthy, 1 = restarts detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze container restart patterns and identify root causes"
    )
    parser.add_argument(
        "-n", "--namespace", help="Analyze restarts in specific namespace (default: all)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed analysis"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show warnings (flapping containers)"
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get pods with restarts
    try:
        pods_with_restarts = get_pods_with_restarts(context, opts.namespace)
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    if not pods_with_restarts:
        if opts.format == "json":
            print(json.dumps({"total_pods": 0, "total_restarts": 0, "by_category": {}, "flapping_containers": []}, indent=2))
        else:
            print("No container restarts detected.")
        output.set_summary("no restarts")
        return 0

    # Analyze restarts
    analysis = analyze_restarts(pods_with_restarts)

    # Format and print output
    if opts.format == "json":
        print(format_output_json(analysis))
    else:
        print(format_output_plain(analysis, verbose=opts.verbose, warn_only=opts.warn_only))

    # Set summary
    flapping_count = len(analysis["flapping_containers"])
    output.set_summary(f"restarts={analysis['total_restarts']}, flapping={flapping_count}")

    # Exit with appropriate code
    if analysis["flapping_containers"] or analysis["total_restarts"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
