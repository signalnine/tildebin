#!/usr/bin/env python3
# boxctl:
#   category: k8s/nodes
#   tags: [health, kubernetes, nodes, monitoring]
#   requires: [kubectl]
#   brief: Check Kubernetes node health and resource availability

"""
Check Kubernetes node health and resource availability.

Provides a comprehensive health check for Kubernetes nodes in a cluster,
including node status, resource utilization, and problem detection.
Useful for monitoring large-scale baremetal Kubernetes deployments.

Exit codes:
    0 - All nodes healthy
    1 - One or more nodes unhealthy or warnings detected
    2 - Usage error or kubectl not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_quantity(quantity_str: str) -> int:
    """Parse Kubernetes quantity string to bytes or millicores."""
    if not quantity_str:
        return 0

    # Handle millicores (e.g., "1000m" = 1 core)
    if quantity_str.endswith("m"):
        return int(quantity_str[:-1])

    # Handle memory units
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

    for suffix, multiplier in units.items():
        if quantity_str.endswith(suffix):
            return int(quantity_str[: -len(suffix)]) * multiplier

    # Plain number
    try:
        return int(quantity_str)
    except ValueError:
        return 0


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human readable format."""
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}PiB"


def format_cpu(millicores: int) -> str:
    """Format millicores to cores."""
    cores = millicores / 1000.0
    return f"{cores:.2f}"


def check_node_conditions(node: dict) -> tuple[bool, list[str]]:
    """Check node conditions and return status and issues."""
    conditions = node.get("status", {}).get("conditions", [])
    issues = []
    ready = False

    for condition in conditions:
        condition_type = condition.get("type")
        status = condition.get("status")
        reason = condition.get("reason", "")
        message = condition.get("message", "")

        if condition_type == "Ready":
            if status == "True":
                ready = True
            else:
                issues.append(f"NotReady: {reason} - {message}")
        elif status == "True" and condition_type in [
            "MemoryPressure",
            "DiskPressure",
            "PIDPressure",
            "NetworkUnavailable",
        ]:
            issues.append(f"{condition_type}: {reason}")

    return ready, issues


def get_node_allocatable(node: dict) -> dict:
    """Get allocatable resources for a node."""
    allocatable = node.get("status", {}).get("allocatable", {})
    return {
        "cpu": parse_quantity(allocatable.get("cpu", "0")),
        "memory": parse_quantity(allocatable.get("memory", "0")),
        "pods": int(allocatable.get("pods", "0")),
    }


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
        description="Check Kubernetes node health and resource availability"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show nodes with warnings or issues",
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

    nodes = nodes_data.get("items", [])
    has_issues = False
    healthy_count = 0
    unhealthy_count = 0
    results = []

    for node in nodes:
        name = node["metadata"]["name"]
        ready, issues = check_node_conditions(node)
        allocatable = get_node_allocatable(node)

        # Count status
        if ready and not issues:
            healthy_count += 1
        else:
            unhealthy_count += 1
            has_issues = True

        # Skip healthy nodes if warn_only
        if opts.warn_only and ready and not issues:
            continue

        node_info = {
            "name": name,
            "ready": ready,
            "issues": issues,
            "allocatable": {
                "cpu_cores": format_cpu(allocatable["cpu"]),
                "memory": format_bytes(allocatable["memory"]),
                "pods": allocatable["pods"],
            },
        }
        results.append(node_info)

    # Output
    if opts.format == "json":
        print(json.dumps(results, indent=2))
    else:
        for node_info in results:
            status = "READY" if node_info["ready"] else "NOT READY"
            print(f"Node: {node_info['name']} - {status}")

            alloc = node_info["allocatable"]
            print(
                f"  Allocatable: {alloc['cpu_cores']} CPU cores, "
                f"{alloc['memory']} memory, {alloc['pods']} pods"
            )

            if node_info["issues"]:
                for issue in node_info["issues"]:
                    print(f"  WARNING: {issue}")

            print()

        # Print summary
        total = len(nodes)
        print(f"Summary: {healthy_count}/{total} nodes healthy, {unhealthy_count} with issues")

    output.set_summary(f"nodes={len(nodes)}, healthy={healthy_count}, unhealthy={unhealthy_count}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
