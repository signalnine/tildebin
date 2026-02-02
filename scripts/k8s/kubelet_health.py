#!/usr/bin/env python3
# boxctl:
#   category: k8s/nodes
#   tags: [kubelet, health, kubernetes, nodes, monitoring]
#   requires: [kubectl]
#   brief: Monitor kubelet health across cluster nodes
#   privilege: user
#   related: [node_health, node_pressure, restart_monitor]

"""
Kubernetes kubelet health monitor.

Monitors the health status of kubelet on Kubernetes nodes by checking
node conditions, heartbeat freshness, and restart frequency. Essential
for proactive detection of node agent issues in large-scale clusters.

Features:
- Check kubelet health via node conditions (Ready, MemoryPressure, DiskPressure, PIDPressure)
- Monitor kubelet heartbeat staleness
- Check kubelet version consistency across the cluster
- Identify nodes with kubelet connectivity issues
- Support for filtering by node labels or names

Exit codes:
    0 - All kubelets healthy
    1 - One or more kubelets unhealthy or warnings detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_kubelet_conditions(node: dict) -> tuple[dict, list]:
    """Extract kubelet-related conditions from node status."""
    conditions = node.get("status", {}).get("conditions", [])
    kubelet_conditions = {}
    issues = []

    # Conditions managed by kubelet
    kubelet_condition_types = [
        "Ready",  # Overall node readiness
        "MemoryPressure",  # Memory pressure detection
        "DiskPressure",  # Disk pressure detection
        "PIDPressure",  # PID exhaustion detection
        "NetworkUnavailable",  # Network status (some CNIs)
    ]

    for condition in conditions:
        cond_type = condition.get("type")
        if cond_type in kubelet_condition_types:
            status = condition.get("status")
            reason = condition.get("reason", "")
            message = condition.get("message", "")
            last_transition = condition.get("lastTransitionTime", "")
            last_heartbeat = condition.get("lastHeartbeatTime", "")

            kubelet_conditions[cond_type] = {
                "status": status,
                "reason": reason,
                "message": message,
                "lastTransition": last_transition,
                "lastHeartbeat": last_heartbeat,
            }

            # Check for problematic conditions
            if cond_type == "Ready" and status != "True":
                issues.append(f"Node not ready: {reason} - {message}")
            elif cond_type in ["MemoryPressure", "DiskPressure", "PIDPressure"] and status == "True":
                issues.append(f"{cond_type}: {reason}")
            elif cond_type == "NetworkUnavailable" and status == "True":
                issues.append(f"Network unavailable: {reason}")

    return kubelet_conditions, issues


def check_kubelet_version(node: dict) -> dict:
    """Extract kubelet version information."""
    node_info = node.get("status", {}).get("nodeInfo", {})
    return {
        "kubeletVersion": node_info.get("kubeletVersion", "unknown"),
        "containerRuntimeVersion": node_info.get("containerRuntimeVersion", "unknown"),
        "osImage": node_info.get("osImage", "unknown"),
        "kernelVersion": node_info.get("kernelVersion", "unknown"),
    }


def check_heartbeat_staleness(node: dict, stale_threshold_seconds: int = 60) -> tuple[bool | None, float | None]:
    """Check if kubelet heartbeat is stale."""
    conditions = node.get("status", {}).get("conditions", [])

    for condition in conditions:
        if condition.get("type") == "Ready":
            last_heartbeat = condition.get("lastHeartbeatTime")
            if last_heartbeat:
                try:
                    # Parse ISO format timestamp
                    heartbeat_time = datetime.fromisoformat(last_heartbeat.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    age_seconds = (now - heartbeat_time).total_seconds()

                    if age_seconds > stale_threshold_seconds:
                        return True, age_seconds
                    return False, age_seconds
                except (ValueError, TypeError):
                    pass

    return None, None  # Unable to determine


def analyze_kubelet_health(node: dict) -> dict:
    """Perform comprehensive kubelet health analysis for a node."""
    node_name = node["metadata"]["name"]

    # Get kubelet conditions
    conditions, issues = check_kubelet_conditions(node)

    # Get version info
    version_info = check_kubelet_version(node)

    # Check heartbeat staleness
    is_stale, heartbeat_age = check_heartbeat_staleness(node)
    if is_stale:
        issues.append(f"Stale heartbeat: {heartbeat_age:.0f}s old")

    # Get node labels and taints
    taints = node.get("spec", {}).get("taints", [])

    unschedulable = node.get("spec", {}).get("unschedulable", False)
    if unschedulable:
        issues.append("Node is cordoned (unschedulable)")

    return {
        "name": node_name,
        "healthy": len(issues) == 0,
        "conditions": conditions,
        "issues": issues,
        "version": version_info,
        "heartbeatAge": heartbeat_age,
        "cordoned": unschedulable,
        "taintCount": len(taints),
    }


def check_version_consistency(results: list) -> tuple[bool, dict]:
    """Check if all kubelets are running the same version."""
    versions = defaultdict(list)

    for result in results:
        version = result["version"]["kubeletVersion"]
        versions[version].append(result["name"])

    if len(versions) > 1:
        return False, dict(versions)
    return True, dict(versions)


def format_plain_output(results: list, version_info: tuple, warn_only: bool = False) -> str:
    """Format results as plain text."""
    output = []

    healthy_count = sum(1 for r in results if r["healthy"])
    total_count = len(results)

    output.append(f"Kubelet Health Summary: {healthy_count}/{total_count} healthy")
    output.append("")

    # Version consistency check
    consistent, versions = version_info
    if not consistent:
        output.append("WARNING: Inconsistent kubelet versions detected:")
        for version, nodes in versions.items():
            output.append(f"  {version}: {len(nodes)} node(s)")
        output.append("")

    for result in results:
        if warn_only and result["healthy"]:
            continue

        status = "HEALTHY" if result["healthy"] else "UNHEALTHY"
        output.append(f"Node: {result['name']} [{status}]")
        output.append(f"  Kubelet: {result['version']['kubeletVersion']}")
        output.append(f"  Runtime: {result['version']['containerRuntimeVersion']}")

        if result["heartbeatAge"] is not None:
            output.append(f"  Heartbeat age: {result['heartbeatAge']:.0f}s")

        if result["cordoned"]:
            output.append("  Status: CORDONED")

        if result["issues"]:
            output.append("  Issues:")
            for issue in result["issues"]:
                output.append(f"    - {issue}")

        output.append("")

    return "\n".join(output)


def format_table_output(results: list, version_info: tuple, warn_only: bool = False) -> str:
    """Format results as table."""
    output = []

    healthy_count = sum(1 for r in results if r["healthy"])
    total_count = len(results)

    output.append(f"\nKubelet Health: {healthy_count}/{total_count} healthy")

    # Version consistency
    consistent, versions = version_info
    if not consistent:
        output.append("WARNING: Mixed kubelet versions in cluster")
    output.append("")

    # Table header
    output.append(f"{'NODE':<35} {'STATUS':<10} {'VERSION':<15} {'HEARTBEAT':<12} {'ISSUES'}")
    output.append("-" * 100)

    for result in results:
        if warn_only and result["healthy"]:
            continue

        status = "OK" if result["healthy"] else "UNHEALTHY"
        version = result["version"]["kubeletVersion"][:14]

        if result["heartbeatAge"] is not None:
            heartbeat = f"{result['heartbeatAge']:.0f}s"
        else:
            heartbeat = "N/A"

        issues = ", ".join(result["issues"][:2]) if result["issues"] else "None"
        if len(issues) > 35:
            issues = issues[:32] + "..."

        output.append(f"{result['name']:<35} {status:<10} {version:<15} {heartbeat:<12} {issues}")

    return "\n".join(output)


def format_json_output(results: list, version_info: tuple, warn_only: bool = False) -> str:
    """Format results as JSON."""
    consistent, versions = version_info

    filtered_results = results if not warn_only else [r for r in results if not r["healthy"]]

    output = {
        "summary": {
            "total": len(results),
            "healthy": sum(1 for r in results if r["healthy"]),
            "unhealthy": sum(1 for r in results if not r["healthy"]),
            "versionConsistent": consistent,
            "versions": versions,
        },
        "nodes": filtered_results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return json.dumps(output, indent=2, default=str)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all OK, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor kubelet health across Kubernetes cluster nodes"
    )

    parser.add_argument(
        "--node",
        "-n",
        help="Check specific node by name",
    )

    parser.add_argument(
        "--label",
        "-l",
        help="Filter nodes by label selector (e.g., node-role.kubernetes.io/worker=)",
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

    # Build kubectl command
    cmd = ["kubectl", "get", "nodes", "-o", "json"]
    if opts.label:
        cmd.extend(["-l", opts.label])
    if opts.node:
        cmd.append(opts.node)

    # Get nodes
    try:
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        nodes_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get nodes: {e}")
        return 2

    # Handle both single node and list responses
    if nodes_data.get("kind") == "Node":
        nodes = [nodes_data]
    else:
        nodes = nodes_data.get("items", [])

    if not nodes:
        if opts.node:
            output.error(f"Node '{opts.node}' not found")
        else:
            output.error("No nodes found in cluster")
        return 1

    # Analyze each node
    results = []
    for node in nodes:
        result = analyze_kubelet_health(node)
        results.append(result)

    # Check version consistency
    version_info = check_version_consistency(results)

    # Output results
    if opts.format == "json":
        print(format_json_output(results, version_info, opts.warn_only))
    elif opts.format == "table":
        print(format_table_output(results, version_info, opts.warn_only))
    else:
        print(format_plain_output(results, version_info, opts.warn_only))

    # Determine exit code
    has_issues = any(not r["healthy"] for r in results)
    has_version_mismatch = not version_info[0] and len(version_info[1]) > 1

    healthy_count = sum(1 for r in results if r["healthy"])
    unhealthy_count = len(results) - healthy_count
    output.set_summary(f"nodes={len(results)}, healthy={healthy_count}, unhealthy={unhealthy_count}")

    return 1 if (has_issues or has_version_mismatch) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
