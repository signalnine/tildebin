#!/usr/bin/env python3
# boxctl:
#   category: k8s/nodes
#   tags: [restart, nodes, stability, kubernetes, monitoring]
#   requires: [kubectl]
#   brief: Monitor node restart activity and detect problem nodes
#   privilege: user
#   related: [kubelet_health, node_health, container_restart_analyzer]

"""
Monitor Kubernetes node restart activity and detect problem nodes.

This script analyzes node uptime and restart patterns to identify:
- Nodes with excessive restarts (potential hardware/software issues)
- Nodes that have recently recovered from crashes
- Cluster-wide restart trends

Critical for baremetal deployments where node stability directly impacts
application availability. Helps identify hardware failures, kernel panics,
or configuration issues causing repeated restarts.

Exit codes:
    0 - No restart issues detected
    1 - Nodes with excessive restarts or recent crashes detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


# Thresholds for restart detection
EXCESSIVE_POD_RESTARTS = 5  # Max restarts for any single pod
HIGH_TOTAL_POD_RESTARTS = 20  # Total restarts across all pods


def calculate_uptime(status_data: dict) -> tuple[float | None, str | None]:
    """Extract and calculate node uptime in seconds.

    Returns tuple: (uptime_seconds, boot_time_str)
    """
    try:
        for condition in status_data.get("status", {}).get("conditions", []):
            if condition["type"] == "Ready":
                # When a node transitions to Ready, we know it just booted
                # We'll estimate uptime from the condition timestamp
                transition_time_str = condition.get("lastTransitionTime", "")
                if transition_time_str:
                    boot_time = datetime.fromisoformat(transition_time_str.replace("Z", "+00:00"))
                    current_time = datetime.now(timezone.utc)
                    uptime = (current_time - boot_time).total_seconds()
                    return max(0, uptime), transition_time_str
    except (KeyError, ValueError):
        pass
    return None, None


def parse_container_status(container_status: dict) -> tuple[int, str | None]:
    """Parse container restart count and last state."""
    restart_count = container_status.get("restartCount", 0)
    last_state = container_status.get("lastState", {})
    reason = None

    if last_state and "terminated" in last_state:
        reason = last_state["terminated"].get("reason", "Unknown")

    return restart_count, reason


def get_node_pod_restarts(
    pods_data: dict, node_name: str
) -> tuple[int, int, list[dict]]:
    """Get restart counts for all pods on a node."""
    total_restarts = 0
    max_restarts = 0
    restart_details = []

    for pod in pods_data.get("items", []):
        if pod.get("spec", {}).get("nodeName") != node_name:
            continue

        pod_name = pod["metadata"]["name"]
        namespace = pod["metadata"]["namespace"]

        for container in pod.get("status", {}).get("containerStatuses", []):
            restart_count, reason = parse_container_status(container)
            total_restarts += restart_count
            max_restarts = max(max_restarts, restart_count)

            if restart_count > 0:
                restart_details.append(
                    {
                        "pod": pod_name,
                        "namespace": namespace,
                        "container": container.get("name", "unknown"),
                        "restarts": restart_count,
                        "reason": reason,
                    }
                )

    return total_restarts, max_restarts, restart_details


def assess_node_health(
    node_data: dict, pod_restarts: int, max_pod_restarts: int
) -> tuple[str, str]:
    """Determine node health status based on restart patterns.

    Returns: (status, reason)
    status: "OK", "WARNING", or "CRITICAL"
    """
    issues = []

    # Check for excessive pod restarts (indicates node issues)
    if max_pod_restarts > EXCESSIVE_POD_RESTARTS:
        issues.append(f"Container with {max_pod_restarts} restarts")

    if pod_restarts > HIGH_TOTAL_POD_RESTARTS:
        issues.append(f"Total {pod_restarts} restarts across pods")

    # Check node conditions
    for condition in node_data.get("status", {}).get("conditions", []):
        condition_type = condition.get("type")
        status = condition.get("status")
        reason = condition.get("reason", "Unknown")

        if condition_type == "Ready" and status == "False":
            issues.append(f"Node not ready: {reason}")
        elif condition_type in ["MemoryPressure", "DiskPressure", "PIDPressure"]:
            if status == "True":
                issues.append(f"{condition_type}: {reason}")

    if issues:
        # Determine severity
        if "not ready" in str(issues).lower() or max_pod_restarts > EXCESSIVE_POD_RESTARTS * 2:
            return "CRITICAL", " | ".join(issues)
        else:
            return "WARNING", " | ".join(issues)

    return "OK", "Healthy"


def format_uptime(seconds: float | None) -> str:
    """Format uptime in human-readable format."""
    if seconds is None:
        return "Unknown"

    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)

    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"


def format_plain(nodes_data: dict) -> str:
    """Format output in plain format."""
    lines = []
    for node_name, node_info in sorted(nodes_data.items()):
        status = node_info["status"]
        uptime = format_uptime(node_info["uptime"])
        pod_restarts = node_info["pod_restarts"]
        max_restarts = node_info["max_pod_restarts"]
        reason = node_info["reason"]

        lines.append(f"{node_name} {status} {uptime} {pod_restarts} {max_restarts} {reason}")

    return "\n".join(lines)


def format_table(nodes_data: dict) -> str:
    """Format output in table format."""
    lines = []
    lines.append(f"{'Node':<30} {'Status':<10} {'Uptime':<15} {'Pod Restarts':<12} {'Max Restarts':<12} {'Reason'}")
    lines.append("-" * 120)

    for node_name, node_info in sorted(nodes_data.items()):
        status = node_info["status"]
        uptime = format_uptime(node_info["uptime"])
        pod_restarts = node_info["pod_restarts"]
        max_restarts = node_info["max_pod_restarts"]
        reason = node_info["reason"][:50]  # Truncate long reasons

        lines.append(f"{node_name:<30} {status:<10} {uptime:<15} {pod_restarts:<12} {max_restarts:<12} {reason}")

    return "\n".join(lines)


def format_json(nodes_data: dict) -> str:
    """Format output in JSON format."""
    output = {}
    for node_name, node_info in sorted(nodes_data.items()):
        output[node_name] = {
            "status": node_info["status"],
            "uptime_seconds": node_info["uptime"],
            "uptime_formatted": format_uptime(node_info["uptime"]),
            "pod_restarts": node_info["pod_restarts"],
            "max_pod_restarts": node_info["max_pod_restarts"],
            "reason": node_info["reason"],
            "restart_details": node_info["restart_details"],
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
        0 = healthy, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes node restart activity and detect problem nodes"
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show nodes with issues",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get nodes
    try:
        result = context.run(["kubectl", "get", "nodes", "-o", "json"])
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        nodes = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get nodes: {e}")
        return 2

    # Get all pods for restart analysis
    try:
        result = context.run(["kubectl", "get", "pods", "--all-namespaces", "-o", "json"])
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    # Collect node data
    nodes_result = {}
    has_issues = False

    for node in nodes.get("items", []):
        node_name = node["metadata"]["name"]

        # Calculate uptime
        uptime_seconds, boot_time = calculate_uptime(node)

        # Get pod restart information
        pod_restarts, max_pod_restarts, restart_details = get_node_pod_restarts(pods_data, node_name)

        # Assess health
        status, reason = assess_node_health(node, pod_restarts, max_pod_restarts)

        if status != "OK":
            has_issues = True

        nodes_result[node_name] = {
            "status": status,
            "uptime": uptime_seconds,
            "boot_time": boot_time,
            "pod_restarts": pod_restarts,
            "max_pod_restarts": max_pod_restarts,
            "reason": reason,
            "restart_details": restart_details,
        }

    # Filter output if warn-only
    if opts.warn_only:
        nodes_result = {k: v for k, v in nodes_result.items() if v["status"] != "OK"}

    # Format and print output
    if opts.format == "json":
        print(format_json(nodes_result))
    elif opts.format == "table":
        print(format_table(nodes_result))
    else:  # plain
        print(format_plain(nodes_result))

    # Set summary
    ok_count = sum(1 for v in nodes_result.values() if v["status"] == "OK")
    warning_count = sum(1 for v in nodes_result.values() if v["status"] == "WARNING")
    critical_count = sum(1 for v in nodes_result.values() if v["status"] == "CRITICAL")
    output.set_summary(f"nodes={len(nodes_result)}, ok={ok_count}, warning={warning_count}, critical={critical_count}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
