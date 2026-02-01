#!/usr/bin/env python3
# boxctl:
#   category: k8s/nodes
#   tags: [taints, kubernetes, nodes, scheduling, tolerations]
#   requires: [kubectl]
#   brief: Analyze node taints and their impact on pod scheduling

"""
Analyze Kubernetes node taints and their impact on pod scheduling.

Examines node taints across a Kubernetes cluster and identifies:
- Nodes with taints that prevent scheduling (NoSchedule, NoExecute)
- Nodes with PreferNoSchedule taints (soft constraints)
- Pods that tolerate specific taints
- Workload distribution on tainted vs untainted nodes
- Orphaned taints (taints with no matching tolerations)

Useful for managing large-scale baremetal clusters where nodes are frequently
tainted for maintenance, hardware issues, or specialized workloads (GPU, high-memory, etc.).

Exit codes:
    0 - No taint-related issues detected
    1 - Issues found (nodes with blocking taints, imbalanced scheduling)
    2 - Usage error or kubectl not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_taints(node: dict) -> list:
    """Extract taints from a node."""
    spec = node.get("spec", {})
    return spec.get("taints", [])


def parse_tolerations(pod: dict) -> list:
    """Extract tolerations from a pod."""
    spec = pod.get("spec", {})
    return spec.get("tolerations", [])


def taint_blocks_scheduling(taint: dict) -> bool:
    """Check if a taint blocks pod scheduling."""
    effect = taint.get("effect", "")
    return effect in ["NoSchedule", "NoExecute"]


def taint_prefers_no_schedule(taint: dict) -> bool:
    """Check if a taint is a soft constraint."""
    return taint.get("effect", "") == "PreferNoSchedule"


def toleration_matches_taint(toleration: dict, taint: dict) -> bool:
    """Check if a toleration matches a taint."""
    # Match on key
    tol_key = toleration.get("key")
    taint_key = taint.get("key", "")

    if tol_key != taint_key:
        # Check for empty key (matches all)
        if tol_key not in [None, ""]:
            return False

    # Match on effect
    tol_effect = toleration.get("effect", "")
    taint_effect = taint.get("effect", "")
    if tol_effect and taint_effect and tol_effect != taint_effect:
        return False

    # Match on operator
    operator = toleration.get("operator", "Equal")
    if operator == "Exists":
        return True
    elif operator == "Equal":
        return toleration.get("value") == taint.get("value")

    return False


def pod_tolerates_taint(pod: dict, taint: dict) -> bool:
    """Check if a pod tolerates a specific taint."""
    tolerations = parse_tolerations(pod)
    for toleration in tolerations:
        if toleration_matches_taint(toleration, taint):
            return True
    return False


def analyze_taints(nodes: list, pods: list, warn_only: bool = False) -> dict:
    """Analyze node taints and their impact."""
    results = {
        "tainted_nodes": [],
        "untainted_nodes": [],
        "blocking_taints": [],
        "soft_taints": [],
        "pod_distribution": {"tainted": 0, "untainted": 0},
        "orphaned_taints": [],
        "issues_found": False,
    }

    # Collect all taints across cluster
    all_taints = {}

    # Analyze nodes
    for node in nodes:
        node_name = node["metadata"]["name"]
        taints = parse_taints(node)

        if not taints:
            results["untainted_nodes"].append(node_name)
        else:
            node_info = {
                "name": node_name,
                "taints": taints,
                "blocking_count": 0,
                "soft_count": 0,
            }

            for taint in taints:
                taint_key = f"{taint.get('key', '')}={taint.get('value', '')}"
                if taint_key not in all_taints:
                    all_taints[taint_key] = {
                        "taint": taint,
                        "nodes": [],
                        "tolerating_pods": 0,
                    }
                all_taints[taint_key]["nodes"].append(node_name)

                if taint_blocks_scheduling(taint):
                    node_info["blocking_count"] += 1
                    results["blocking_taints"].append(
                        {
                            "node": node_name,
                            "key": taint.get("key", ""),
                            "value": taint.get("value", ""),
                            "effect": taint.get("effect", ""),
                        }
                    )
                elif taint_prefers_no_schedule(taint):
                    node_info["soft_count"] += 1
                    results["soft_taints"].append(
                        {
                            "node": node_name,
                            "key": taint.get("key", ""),
                            "value": taint.get("value", ""),
                            "effect": taint.get("effect", ""),
                        }
                    )

            results["tainted_nodes"].append(node_info)

    # Analyze pod distribution and tolerations
    for pod in pods:
        node_name = pod.get("spec", {}).get("nodeName", "")

        if not node_name:
            continue

        # Check if pod is on tainted node
        is_on_tainted_node = any(
            tainted["name"] == node_name for tainted in results["tainted_nodes"]
        )

        if is_on_tainted_node:
            results["pod_distribution"]["tainted"] += 1

            # Count which taints this pod tolerates
            for taint_key, taint_info in all_taints.items():
                if node_name in taint_info["nodes"]:
                    if pod_tolerates_taint(pod, taint_info["taint"]):
                        taint_info["tolerating_pods"] += 1
        else:
            results["pod_distribution"]["untainted"] += 1

    # Identify orphaned taints (no pods tolerate them)
    for taint_key, taint_info in all_taints.items():
        if taint_info["tolerating_pods"] == 0 and taint_blocks_scheduling(
            taint_info["taint"]
        ):
            results["orphaned_taints"].append(
                {
                    "key": taint_info["taint"].get("key", ""),
                    "value": taint_info["taint"].get("value", ""),
                    "effect": taint_info["taint"].get("effect", ""),
                    "nodes": taint_info["nodes"],
                }
            )

    # Determine if issues found
    if warn_only:
        results["issues_found"] = (
            len(results["blocking_taints"]) > 0 or len(results["orphaned_taints"]) > 0
        )
    else:
        results["issues_found"] = (
            len(results["tainted_nodes"]) > 0
            or len(results["blocking_taints"]) > 0
            or len(results["orphaned_taints"]) > 0
        )

    return results


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes node taints and scheduling impact"
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
        help="Show detailed information about all taints",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show nodes with blocking taints or orphaned taints",
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

    # Analyze taints
    results = analyze_taints(nodes, pods, opts.warn_only)

    # Output results
    if opts.format == "json":
        print(json.dumps(results, indent=2))
    elif opts.format == "table":
        _output_table(results, opts.warn_only)
    else:
        _output_plain(results, opts.verbose, opts.warn_only)

    output.set_summary(
        f"tainted={len(results['tainted_nodes'])}, "
        f"blocking={len(results['blocking_taints'])}, "
        f"orphaned={len(results['orphaned_taints'])}"
    )

    # Exit with appropriate code
    return 1 if results["issues_found"] else 0


def _output_plain(results: dict, verbose: bool, warn_only: bool) -> None:
    """Output results in plain text format."""
    print("Node Taint Analysis")
    print("=" * 60)
    print()

    # Summary
    total_nodes = len(results["tainted_nodes"]) + len(results["untainted_nodes"])
    tainted_count = len(results["tainted_nodes"])
    print(f"Total Nodes: {total_nodes}")
    print(f"Tainted Nodes: {tainted_count}")
    print(f"Untainted Nodes: {len(results['untainted_nodes'])}")
    print()

    # Pod distribution
    total_pods = (
        results["pod_distribution"]["tainted"] + results["pod_distribution"]["untainted"]
    )
    print("Pod Distribution:")
    print(f"  Pods on tainted nodes: {results['pod_distribution']['tainted']}")
    print(f"  Pods on untainted nodes: {results['pod_distribution']['untainted']}")
    print(f"  Total pods: {total_pods}")
    print()

    # Blocking taints
    if results["blocking_taints"] or not warn_only:
        print(
            f"Blocking Taints (NoSchedule/NoExecute): {len(results['blocking_taints'])}"
        )
        if verbose and results["blocking_taints"]:
            for taint in results["blocking_taints"]:
                print(
                    f"  - {taint['node']}: {taint['key']}={taint['value']} "
                    f"({taint['effect']})"
                )
        print()

    # Soft taints
    if results["soft_taints"] and verbose:
        print(f"Soft Taints (PreferNoSchedule): {len(results['soft_taints'])}")
        for taint in results["soft_taints"]:
            print(
                f"  - {taint['node']}: {taint['key']}={taint['value']} "
                f"({taint['effect']})"
            )
        print()

    # Orphaned taints
    if results["orphaned_taints"]:
        print(
            f"WARNING: Orphaned Taints (no tolerating pods): "
            f"{len(results['orphaned_taints'])}"
        )
        for taint in results["orphaned_taints"]:
            print(
                f"  - {taint['key']}={taint['value']} ({taint['effect']}) "
                f"on nodes: {', '.join(taint['nodes'])}"
            )
        print()

    # Status
    if results["issues_found"]:
        print("Status: ISSUES DETECTED")
    else:
        print("Status: OK")


def _output_table(results: dict, warn_only: bool) -> None:
    """Output results in table format."""
    print(f"{'Node':<30} {'Blocking':<10} {'Soft':<10} {'Total Taints':<15}")
    print("-" * 65)

    if not warn_only:
        for node_info in results["tainted_nodes"]:
            print(
                f"{node_info['name']:<30} {node_info['blocking_count']:<10} "
                f"{node_info['soft_count']:<10} {len(node_info['taints']):<15}"
            )

    if results["blocking_taints"] and warn_only:
        print("\nBlocking Taints:")
        print(f"{'Node':<30} {'Key':<25} {'Effect':<15}")
        print("-" * 70)
        for taint in results["blocking_taints"]:
            key_val = f"{taint['key']}={taint['value']}"
            print(f"{taint['node']:<30} {key_val:<25} {taint['effect']:<15}")

    if results["orphaned_taints"]:
        print("\nOrphaned Taints (no tolerating pods):")
        print(f"{'Key':<25} {'Effect':<15} {'Node Count':<15}")
        print("-" * 55)
        for taint in results["orphaned_taints"]:
            key_val = f"{taint['key']}={taint['value']}"
            print(f"{key_val:<25} {taint['effect']:<15} {len(taint['nodes']):<15}")


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
