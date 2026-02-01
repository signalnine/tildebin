#!/usr/bin/env python3
# boxctl:
#   category: k8s/nodes
#   tags: [health, kubernetes, nodes, pressure, capacity]
#   requires: [kubectl]
#   brief: Monitor Kubernetes node pressure conditions

"""
Monitor Kubernetes node pressure conditions for proactive capacity management.

Analyzes node-level pressure signals across a Kubernetes cluster:
- Memory pressure (MemoryPressure condition)
- Disk pressure (DiskPressure condition)
- PID pressure (PIDPressure condition)
- Network unavailable status
- Allocatable vs capacity analysis

Critical for large-scale baremetal Kubernetes deployments where node pressure
can trigger pod evictions and cascading failures.

Exit codes:
    0 - No pressure conditions detected
    1 - Pressure conditions or warnings found
    2 - Usage error or kubectl not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_resource_quantity(quantity: str | None) -> int:
    """Parse Kubernetes resource quantity string to bytes/millicores."""
    if quantity is None:
        return 0

    quantity = str(quantity)

    # Memory units
    if quantity.endswith("Ki"):
        return int(quantity[:-2]) * 1024
    elif quantity.endswith("Mi"):
        return int(quantity[:-2]) * 1024 * 1024
    elif quantity.endswith("Gi"):
        return int(quantity[:-2]) * 1024 * 1024 * 1024
    elif quantity.endswith("Ti"):
        return int(quantity[:-2]) * 1024 * 1024 * 1024 * 1024
    elif quantity.endswith("K"):
        return int(quantity[:-1]) * 1000
    elif quantity.endswith("M"):
        return int(quantity[:-1]) * 1000 * 1000
    elif quantity.endswith("G"):
        return int(quantity[:-1]) * 1000 * 1000 * 1000
    elif quantity.endswith("T"):
        return int(quantity[:-1]) * 1000 * 1000 * 1000 * 1000
    # CPU units (millicores)
    elif quantity.endswith("m"):
        return int(quantity[:-1])
    elif quantity.endswith("n"):
        return int(int(quantity[:-1]) / 1000000)
    else:
        # Plain number - could be cores or bytes
        try:
            return int(quantity)
        except ValueError:
            return int(float(quantity))


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human readable string."""
    for unit in ["B", "Ki", "Mi", "Gi", "Ti"]:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}Pi"


def format_cpu(millicores: int) -> str:
    """Format millicores to human readable string."""
    if millicores >= 1000:
        return f"{millicores/1000:.1f} cores"
    return f"{millicores}m"


def analyze_node_conditions(node: dict) -> tuple[list, list, dict]:
    """Analyze node conditions for pressure signals."""
    issues = []
    warnings = []
    conditions = {}

    status = node.get("status", {})
    node_conditions = status.get("conditions", [])

    # Map condition types to their status
    for condition in node_conditions:
        cond_type = condition.get("type", "")
        cond_status = condition.get("status", "Unknown")
        reason = condition.get("reason", "")
        message = condition.get("message", "")
        conditions[cond_type] = {
            "status": cond_status,
            "reason": reason,
            "message": message,
        }

    # Check pressure conditions (True = bad)
    pressure_conditions = ["MemoryPressure", "DiskPressure", "PIDPressure"]
    for cond in pressure_conditions:
        if cond in conditions:
            if conditions[cond]["status"] == "True":
                issues.append(
                    {
                        "type": "pressure",
                        "condition": cond,
                        "reason": conditions[cond]["reason"],
                        "message": conditions[cond]["message"],
                    }
                )

    # Check Ready condition (False = bad)
    if "Ready" in conditions:
        if conditions["Ready"]["status"] != "True":
            issues.append(
                {
                    "type": "not_ready",
                    "condition": "Ready",
                    "reason": conditions["Ready"]["reason"],
                    "message": conditions["Ready"]["message"],
                }
            )

    # Check NetworkUnavailable (True = bad)
    if "NetworkUnavailable" in conditions:
        if conditions["NetworkUnavailable"]["status"] == "True":
            issues.append(
                {
                    "type": "network",
                    "condition": "NetworkUnavailable",
                    "reason": conditions["NetworkUnavailable"]["reason"],
                    "message": conditions["NetworkUnavailable"]["message"],
                }
            )

    return issues, warnings, conditions


def analyze_node_resources(node: dict, reserved_warn: float) -> tuple[dict, list]:
    """Analyze node capacity vs allocatable resources."""
    status = node.get("status", {})
    capacity = status.get("capacity", {})
    allocatable = status.get("allocatable", {})

    resource_info = {}
    warnings = []

    # Analyze memory
    cap_memory = parse_resource_quantity(capacity.get("memory", "0"))
    alloc_memory = parse_resource_quantity(allocatable.get("memory", "0"))
    if cap_memory > 0:
        memory_reserved_pct = ((cap_memory - alloc_memory) / cap_memory) * 100
        resource_info["memory"] = {
            "capacity": cap_memory,
            "allocatable": alloc_memory,
            "reserved_pct": memory_reserved_pct,
            "capacity_str": format_bytes(cap_memory),
            "allocatable_str": format_bytes(alloc_memory),
        }
        if memory_reserved_pct > reserved_warn:
            warnings.append(
                {
                    "type": "high_reservation",
                    "resource": "memory",
                    "reserved_pct": memory_reserved_pct,
                }
            )

    # Analyze CPU
    cap_cpu = parse_resource_quantity(capacity.get("cpu", "0"))
    alloc_cpu = parse_resource_quantity(allocatable.get("cpu", "0"))
    # Convert cores to millicores if needed
    if cap_cpu > 0 and cap_cpu < 1000:
        cap_cpu = cap_cpu * 1000
    if alloc_cpu > 0 and alloc_cpu < 1000:
        alloc_cpu = alloc_cpu * 1000
    if cap_cpu > 0:
        cpu_reserved_pct = ((cap_cpu - alloc_cpu) / cap_cpu) * 100
        resource_info["cpu"] = {
            "capacity": cap_cpu,
            "allocatable": alloc_cpu,
            "reserved_pct": cpu_reserved_pct,
            "capacity_str": format_cpu(cap_cpu),
            "allocatable_str": format_cpu(alloc_cpu),
        }

    # Analyze ephemeral storage
    cap_storage = parse_resource_quantity(capacity.get("ephemeral-storage", "0"))
    alloc_storage = parse_resource_quantity(allocatable.get("ephemeral-storage", "0"))
    if cap_storage > 0:
        storage_reserved_pct = ((cap_storage - alloc_storage) / cap_storage) * 100
        resource_info["ephemeral-storage"] = {
            "capacity": cap_storage,
            "allocatable": alloc_storage,
            "reserved_pct": storage_reserved_pct,
            "capacity_str": format_bytes(cap_storage),
            "allocatable_str": format_bytes(alloc_storage),
        }
        if storage_reserved_pct > reserved_warn:
            warnings.append(
                {
                    "type": "high_reservation",
                    "resource": "ephemeral-storage",
                    "reserved_pct": storage_reserved_pct,
                }
            )

    # Analyze pods
    cap_pods = int(capacity.get("pods", "0"))
    alloc_pods = int(allocatable.get("pods", "0"))
    if cap_pods > 0:
        resource_info["pods"] = {
            "capacity": cap_pods,
            "allocatable": alloc_pods,
            "reserved_pct": ((cap_pods - alloc_pods) / cap_pods) * 100,
        }

    return resource_info, warnings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no pressure, 1 = pressure/warnings, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes node pressure conditions"
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
        help="Only show nodes with pressure conditions or warnings",
    )
    parser.add_argument(
        "--reserved-warn",
        type=float,
        default=30.0,
        metavar="PCT",
        help="Warn if system-reserved resources exceed this percentage (default: 30)",
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
    results = []

    for node in nodes:
        node_name = node["metadata"]["name"]
        labels = node["metadata"].get("labels", {})

        # Get node role
        roles = []
        for label in labels:
            if label.startswith("node-role.kubernetes.io/"):
                role = label.split("/")[-1]
                if role:
                    roles.append(role)
        if not roles:
            roles = ["worker"]

        # Analyze conditions
        issues, _, conditions = analyze_node_conditions(node)

        # Analyze resources
        resources, resource_warnings = analyze_node_resources(node, opts.reserved_warn)

        # Combine warnings
        warnings = resource_warnings

        # Skip nodes without issues if warn_only
        if opts.warn_only and not issues and not warnings:
            continue

        node_info = {
            "name": node_name,
            "roles": roles,
            "conditions": conditions,
            "resources": resources,
            "issues": issues,
            "warnings": warnings,
            "ready": conditions.get("Ready", {}).get("status") == "True",
        }

        results.append(node_info)

    # Count issues
    nodes_with_issues = sum(1 for r in results if r["issues"])
    nodes_with_warnings = sum(1 for r in results if r["warnings"] and not r["issues"])

    # Output
    if opts.format == "json":
        output_data = {
            "nodes": results,
            "summary": {
                "total_nodes": len(nodes),
                "nodes_with_pressure": nodes_with_issues,
                "nodes_with_warnings": nodes_with_warnings,
                "healthy_nodes": len(nodes) - nodes_with_issues - nodes_with_warnings,
            },
        }
        print(json.dumps(output_data, indent=2, default=str))
    else:
        for node_info in results:
            name = node_info["name"]
            roles = ",".join(node_info["roles"])
            ready = "Ready" if node_info["ready"] else "NotReady"
            issues = node_info["issues"]
            warnings = node_info["warnings"]

            # Status indicator
            if issues:
                marker = "[PRESSURE]"
            elif warnings:
                marker = "[WARNING]"
            else:
                marker = "[OK]"

            print(f"{marker} Node: {name} ({roles}) - {ready}")

            # Print issues
            if issues:
                print("  Pressure Conditions:")
                for issue in issues:
                    if issue["type"] == "pressure":
                        print(f"    - {issue['condition']}: {issue['reason']}")
                    elif issue["type"] == "not_ready":
                        print(f"    - NotReady: {issue['reason']}")
                    elif issue["type"] == "network":
                        print(f"    - NetworkUnavailable: {issue['reason']}")

            # Print warnings
            if warnings:
                print("  Warnings:")
                for warning in warnings:
                    if warning["type"] == "high_reservation":
                        print(
                            f"    - High {warning['resource']} reservation: "
                            f"{warning['reserved_pct']:.1f}%"
                        )

            # Print resource summary
            resources = node_info["resources"]
            if resources:
                print("  Resources (allocatable/capacity):")
                if "memory" in resources:
                    mem = resources["memory"]
                    print(
                        f"    Memory: {mem['allocatable_str']} / {mem['capacity_str']} "
                        f"({100-mem['reserved_pct']:.1f}% allocatable)"
                    )
                if "cpu" in resources:
                    cpu = resources["cpu"]
                    print(
                        f"    CPU: {cpu['allocatable_str']} / {cpu['capacity_str']} "
                        f"({100-cpu['reserved_pct']:.1f}% allocatable)"
                    )

            print()

        # Summary
        print(f"Summary: {len(nodes)} nodes analyzed")
        if nodes_with_issues:
            print(f"  - {nodes_with_issues} node(s) with active pressure conditions")
        if nodes_with_warnings:
            print(f"  - {nodes_with_warnings} node(s) with warnings")
        if not nodes_with_issues and not nodes_with_warnings:
            print("  - All nodes healthy, no pressure detected")

    output.set_summary(
        f"nodes={len(nodes)}, pressure={nodes_with_issues}, warnings={nodes_with_warnings}"
    )

    # Determine exit code
    has_pressure = any(r["issues"] for r in results)
    has_warnings = any(r["warnings"] for r in results)

    return 1 if has_pressure or has_warnings else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
