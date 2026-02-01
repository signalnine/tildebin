#!/usr/bin/env python3
# boxctl:
#   category: k8s/pods
#   tags: [health, kubernetes, pods, scheduling, pending]
#   requires: [kubectl]
#   brief: Analyze pending pods and identify scheduling failure root causes

"""
Analyze Kubernetes pending pods and identify scheduling failure root causes.

Identifies why pods are stuck in Pending state and provides actionable
insights for resolution. Analyzes scheduling conditions, resource constraints,
node selectors, affinity rules, and taints/tolerations.

Exit codes:
    0: No pending pods found
    1: One or more pending pods detected
    2: Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_resource_value(value_str: str, resource_type: str = "cpu") -> int:
    """
    Parse Kubernetes resource value to numeric format.

    For CPU: Returns millicores (e.g., "100m" -> 100, "1" -> 1000)
    For memory: Returns bytes
    """
    if not value_str:
        return 0

    value_str = str(value_str).strip()

    if resource_type == "cpu":
        if value_str.endswith("m"):
            return int(value_str[:-1])
        else:
            return int(float(value_str) * 1000)

    # Memory
    units = {
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
    }

    for suffix, multiplier in sorted(units.items(), key=lambda x: -len(x[0])):
        if value_str.endswith(suffix):
            return int(float(value_str[: -len(suffix)]) * multiplier)

    return int(value_str)


def get_pending_pods(context: Context, namespace: str | None = None) -> dict:
    """Get all pods in Pending state."""
    cmd = ["kubectl", "get", "pods", "-o", "json", "--field-selector=status.phase=Pending"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"kubectl failed: {result.stderr}")

    return json.loads(result.stdout)


def get_nodes(context: Context) -> dict:
    """Get all nodes with their conditions and resources."""
    result = context.run(["kubectl", "get", "nodes", "-o", "json"])
    if result.returncode != 0:
        raise RuntimeError(f"kubectl failed: {result.stderr}")
    return json.loads(result.stdout)


def analyze_scheduling_failure(pod: dict, nodes_data: dict) -> dict:
    """
    Analyze why a pod is pending and identify the root cause.

    Returns dict with category, reason, details, and suggestion.
    """
    spec = pod.get("spec", {})
    status = pod.get("status", {})
    conditions = status.get("conditions", [])

    # Get scheduler message from conditions
    scheduler_message = ""
    for condition in conditions:
        if condition.get("type") == "PodScheduled" and condition.get("status") == "False":
            scheduler_message = condition.get("message", "")
            break

    # Check for resource constraints
    containers = spec.get("containers", [])
    total_cpu_request = 0
    total_memory_request = 0

    for container in containers:
        resources = container.get("resources", {})
        requests = resources.get("requests", {})
        total_cpu_request += parse_resource_value(requests.get("cpu", "0"), "cpu")
        total_memory_request += parse_resource_value(requests.get("memory", "0"), "memory")

    lower_msg = scheduler_message.lower()

    # Categorize the failure
    if "insufficient cpu" in lower_msg:
        return {
            "category": "RESOURCES",
            "reason": "Insufficient CPU",
            "details": f"Requested {total_cpu_request}m CPU; {scheduler_message[:100]}",
            "suggestion": "Scale up cluster or reduce CPU requests",
        }

    if "insufficient memory" in lower_msg:
        memory_gb = total_memory_request / (1024**3)
        return {
            "category": "RESOURCES",
            "reason": "Insufficient memory",
            "details": f"Requested {memory_gb:.2f}Gi memory; {scheduler_message[:100]}",
            "suggestion": "Scale up cluster or reduce memory requests",
        }

    # Check for node selector issues
    node_selector = spec.get("nodeSelector", {})
    if node_selector and "node" in lower_msg and "match" in lower_msg:
        selector_str = ", ".join(f"{k}={v}" for k, v in node_selector.items())
        return {
            "category": "NODE_SELECTOR",
            "reason": "No matching nodes",
            "details": f"nodeSelector: {selector_str}",
            "suggestion": "Add matching labels to nodes or update nodeSelector",
        }

    # Check for taint/toleration issues
    if "taint" in lower_msg or "toleration" in lower_msg:
        tolerations = spec.get("tolerations", [])
        return {
            "category": "TAINTS",
            "reason": "Taint/toleration mismatch",
            "details": f"Pod has {len(tolerations)} tolerations but cannot tolerate node taints",
            "suggestion": "Add required tolerations or remove taints from nodes",
        }

    # Check for PVC binding issues
    volumes = spec.get("volumes", [])
    pvc_volumes = [v for v in volumes if "persistentVolumeClaim" in v]
    if pvc_volumes and ("pvc" in lower_msg or "persistentvolumeclaim" in lower_msg or "volume" in lower_msg):
        pvc_names = [v["persistentVolumeClaim"]["claimName"] for v in pvc_volumes]
        return {
            "category": "STORAGE",
            "reason": "PVC binding pending",
            "details": f"Waiting for PVCs: {', '.join(pvc_names)}",
            "suggestion": "Check PVC status and storage provisioner",
        }

    # Check node availability
    nodes = nodes_data.get("items", [])
    schedulable_nodes = 0
    for node in nodes:
        node_spec = node.get("spec", {})
        if not node_spec.get("unschedulable", False):
            node_conditions = node.get("status", {}).get("conditions", [])
            for cond in node_conditions:
                if cond.get("type") == "Ready" and cond.get("status") == "True":
                    schedulable_nodes += 1
                    break

    if schedulable_nodes == 0:
        return {
            "category": "NODES",
            "reason": "No schedulable nodes",
            "details": "All nodes are either unschedulable or NotReady",
            "suggestion": "Check node health and cordoned status",
        }

    # Default case
    if scheduler_message:
        return {
            "category": "SCHEDULING",
            "reason": "Scheduling failed",
            "details": scheduler_message[:150],
            "suggestion": "Review scheduler events for more details",
        }

    return {
        "category": "PENDING",
        "reason": "Waiting for scheduler",
        "details": "No scheduling events found yet",
        "suggestion": "Pod may be newly created; wait or check scheduler health",
    }


def format_output_plain(pending_pods: list[dict]) -> str:
    """Format output as plain text."""
    lines = []
    for pod in pending_pods:
        ns = pod["namespace"]
        name = pod["name"]
        category = pod["analysis"]["category"]
        reason = pod["analysis"]["reason"]
        lines.append(f"{ns} {name} {category} {reason}")
    return "\n".join(lines)


def format_output_table(pending_pods: list[dict]) -> str:
    """Format output as ASCII table."""
    lines = []
    lines.append(f"{'NAMESPACE':<25} {'POD NAME':<40} {'CATEGORY':<15} {'REASON':<30}")
    lines.append("-" * 110)

    for pod in pending_pods:
        ns = pod["namespace"][:24]
        name = pod["name"][:39]
        category = pod["analysis"]["category"][:14]
        reason = pod["analysis"]["reason"][:29]
        lines.append(f"{ns:<25} {name:<40} {category:<15} {reason:<30}")

    return "\n".join(lines)


def format_output_json(pending_pods: list[dict]) -> str:
    """Format output as JSON."""
    output = {
        "pending_count": len(pending_pods),
        "by_category": defaultdict(int),
        "pods": pending_pods,
    }

    for pod in pending_pods:
        output["by_category"][pod["analysis"]["category"]] += 1

    output["by_category"] = dict(output["by_category"])
    return json.dumps(output, indent=2)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no pending, 1 = pending found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze pending pods and identify scheduling failure root causes"
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
        "-v", "--verbose", action="store_true", help="Show detailed analysis"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get pending pods
    try:
        pods_data = get_pending_pods(context, opts.namespace)
        pods = pods_data.get("items", [])
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    if not pods:
        if opts.format == "json":
            print(json.dumps({"pending_count": 0, "by_category": {}, "pods": []}, indent=2))
        else:
            print("No pending pods found")
        output.set_summary("no pending pods")
        return 0

    # Get nodes for analysis
    try:
        nodes_data = get_nodes(context)
    except Exception as e:
        output.error(f"Failed to get nodes: {e}")
        return 2

    # Analyze each pending pod
    pending_pods = []
    for pod in pods:
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name", "unknown")

        analysis = analyze_scheduling_failure(pod, nodes_data)

        pending_pods.append({
            "namespace": namespace,
            "name": pod_name,
            "age": pod.get("metadata", {}).get("creationTimestamp", "unknown"),
            "analysis": analysis,
        })

    # Sort by category
    pending_pods.sort(key=lambda x: (x["analysis"]["category"], x["namespace"], x["name"]))

    # Output
    if opts.format == "plain":
        print(format_output_plain(pending_pods))
    elif opts.format == "table":
        print(format_output_table(pending_pods))
    elif opts.format == "json":
        print(format_output_json(pending_pods))

    output.set_summary(f"pending_pods={len(pending_pods)}")

    return 1


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
