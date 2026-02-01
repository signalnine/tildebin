#!/usr/bin/env python3
# boxctl:
#   category: k8s/nodes
#   tags: [capacity, kubernetes, nodes, planning, resources]
#   requires: [kubectl]
#   brief: Analyze cluster node capacity and resource allocation

"""
Kubernetes node capacity planner - Analyze cluster capacity and forecast resource allocation.

Helps operators understand:
- Total allocatable resources per node
- Current allocation and utilization
- Nodes approaching capacity thresholds
- Capacity planning recommendations

Exit codes:
    0 - All nodes within capacity thresholds
    1 - One or more nodes approaching capacity limits
    2 - Usage error or kubectl not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def format_bytes(num_bytes: int) -> str:
    """Convert bytes to human-readable format."""
    if num_bytes is None:
        return "N/A"
    for unit in ["B", "Ki", "Mi", "Gi", "Ti"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}Pi"


def parse_resource_value(value_str: str | None) -> int:
    """Parse Kubernetes resource value (e.g., '100m', '1Gi') to base units."""
    if value_str is None:
        return 0

    value_str = str(value_str).strip()

    # Handle CPU (millicores)
    if value_str.endswith("m"):
        return int(value_str[:-1])

    # Handle Memory and storage
    units = {
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "Pi": 1024**5,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
        "P": 1000**5,
    }

    for unit, multiplier in sorted(units.items(), key=lambda x: len(x[0]), reverse=True):
        if value_str.endswith(unit):
            try:
                return int(float(value_str[: -len(unit)]) * multiplier)
            except ValueError:
                return 0

    # Plain number (bytes or cores)
    try:
        return int(float(value_str))
    except ValueError:
        return 0


def get_node_capacity(nodes: list) -> list:
    """Extract node capacity and allocation data."""
    node_data = []

    for node in nodes:
        node_name = node["metadata"]["name"]

        # Get allocatable resources
        status = node.get("status", {})
        allocatable = status.get("allocatable", {})
        capacity = status.get("capacity", {})

        # Parse resource values
        cpu_allocatable = parse_resource_value(allocatable.get("cpu", 0))
        mem_allocatable = parse_resource_value(allocatable.get("memory", 0))
        pods_allocatable = int(allocatable.get("pods", 110))

        cpu_capacity = parse_resource_value(capacity.get("cpu", 0))
        mem_capacity = parse_resource_value(capacity.get("memory", 0))

        # Convert cpu to millicores if it's in cores
        if cpu_allocatable > 0 and cpu_allocatable < 1000:
            cpu_allocatable = cpu_allocatable * 1000
        if cpu_capacity > 0 and cpu_capacity < 1000:
            cpu_capacity = cpu_capacity * 1000

        node_data.append(
            {
                "name": node_name,
                "cpu_allocatable": cpu_allocatable,
                "memory_allocatable": mem_allocatable,
                "pods_allocatable": pods_allocatable,
                "cpu_capacity": cpu_capacity,
                "memory_capacity": mem_capacity,
            }
        )

    return node_data


def get_pod_requests(pods: list) -> dict:
    """Calculate pod resource requests by node."""
    # Aggregate requests by node
    node_requests = {}

    for pod in pods:
        spec = pod.get("spec", {})
        node_name = spec.get("nodeName")
        if not node_name:
            continue

        if node_name not in node_requests:
            node_requests[node_name] = {"cpu": 0, "memory": 0, "pods": 0}

        # Count pod
        node_requests[node_name]["pods"] += 1

        # Sum container requests
        containers = spec.get("containers", [])
        for container in containers:
            resources = container.get("resources", {})
            requests = resources.get("requests", {})
            node_requests[node_name]["cpu"] += parse_resource_value(requests.get("cpu", 0))
            node_requests[node_name]["memory"] += parse_resource_value(
                requests.get("memory", 0)
            )

    return node_requests


def analyze_capacity(nodes: list, requests: dict) -> list:
    """Analyze and compute capacity metrics."""
    analysis = []

    for node in nodes:
        node_name = node["name"]
        node_req = requests.get(node_name, {"cpu": 0, "memory": 0, "pods": 0})

        # Calculate utilization percentages
        cpu_util = (
            (node_req["cpu"] / node["cpu_allocatable"] * 100)
            if node["cpu_allocatable"] > 0
            else 0
        )
        mem_util = (
            (node_req["memory"] / node["memory_allocatable"] * 100)
            if node["memory_allocatable"] > 0
            else 0
        )
        pods_util = (
            (node_req["pods"] / node["pods_allocatable"] * 100)
            if node["pods_allocatable"] > 0
            else 0
        )

        # Determine capacity status
        max_util = max(cpu_util, mem_util, pods_util)
        if max_util > 90:
            status = "CRITICAL"
        elif max_util > 75:
            status = "WARNING"
        elif max_util > 50:
            status = "MODERATE"
        else:
            status = "OK"

        analysis.append(
            {
                "node_name": node_name,
                "cpu_allocatable_m": node["cpu_allocatable"],
                "cpu_requested_m": node_req["cpu"],
                "cpu_util_pct": round(cpu_util, 1),
                "memory_allocatable_bytes": node["memory_allocatable"],
                "memory_requested_bytes": node_req["memory"],
                "memory_util_pct": round(mem_util, 1),
                "pods_allocatable": node["pods_allocatable"],
                "pods_scheduled": node_req["pods"],
                "pods_util_pct": round(pods_util, 1),
                "max_util_pct": round(max_util, 1),
                "status": status,
            }
        )

    return sorted(analysis, key=lambda x: x["max_util_pct"], reverse=True)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all OK, 1 = capacity issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes cluster node capacity and resource allocation"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["table", "plain", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show nodes with WARNING or CRITICAL status",
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
        nodes_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get nodes: {e}")
        return 2

    # Get pods
    try:
        result = context.run(["kubectl", "get", "pods", "--all-namespaces", "-o", "json"])
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    nodes = nodes_data.get("items", [])
    pods = pods_data.get("items", [])

    # Get node capacity info
    node_capacity = get_node_capacity(nodes)

    # Get pod requests
    requests = get_pod_requests(pods)

    # Analyze
    analysis = analyze_capacity(node_capacity, requests)

    # Filter if requested
    if opts.warn_only:
        analysis = [n for n in analysis if n["status"] in ("WARNING", "CRITICAL")]

    # Count issues
    critical_nodes = sum(1 for n in analysis if n["status"] == "CRITICAL")
    warning_nodes = sum(1 for n in analysis if n["status"] == "WARNING")

    # Output
    if opts.format == "json":
        print(json.dumps(analysis, indent=2))
    elif opts.format == "table":
        if analysis:
            print(
                f"{'Node':<25} {'CPU':<15} {'Memory':<15} "
                f"{'Pods':<10} {'Max Util':<12} {'Status':<10}"
            )
            print("-" * 90)

            for node in analysis:
                cpu_str = (
                    f"{node['cpu_requested_m']}/{node['cpu_allocatable_m']}m "
                    f"({node['cpu_util_pct']:.0f}%)"
                )
                mem_str = (
                    f"{format_bytes(node['memory_requested_bytes'])}/"
                    f"{format_bytes(node['memory_allocatable_bytes'])} "
                    f"({node['memory_util_pct']:.0f}%)"
                )
                pods_str = f"{node['pods_scheduled']}/{node['pods_allocatable']}"
                max_util_str = f"{node['max_util_pct']:.0f}%"

                print(
                    f"{node['node_name']:<25} {cpu_str:<15} {mem_str:<15} "
                    f"{pods_str:<10} {max_util_str:<12} {node['status']:<10}"
                )
        else:
            print("No nodes found")
    else:  # plain
        for node in analysis:
            print(
                f"{node['node_name']} "
                f"cpu={node['cpu_requested_m']}/{node['cpu_allocatable_m']}m "
                f"mem={format_bytes(node['memory_requested_bytes'])}/"
                f"{format_bytes(node['memory_allocatable_bytes'])} "
                f"pods={node['pods_scheduled']}/{node['pods_allocatable']} "
                f"util={node['max_util_pct']:.0f}% "
                f"status={node['status']}"
            )

    output.set_summary(
        f"nodes={len(analysis)}, critical={critical_nodes}, warning={warning_nodes}"
    )

    # Exit code based on status
    return 1 if critical_nodes > 0 or warning_nodes > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
