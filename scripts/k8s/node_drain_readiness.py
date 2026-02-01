#!/usr/bin/env python3
# boxctl:
#   category: k8s/nodes
#   tags: [drain, kubernetes, nodes, maintenance, eviction]
#   requires: [kubectl]
#   brief: Check node drain readiness and analyze pod eviction constraints

"""
Kubernetes node drain readiness checker.

Analyzes node drainability and identifies pods that may block draining:
- Check if a node is safe to drain (pod constraints analysis)
- Identify pods that cannot be evicted (local storage, critical pods, PDB conflicts)
- Detect stateful workloads requiring manual intervention
- Respect PodDisruptionBudgets (PDBs) for high-availability workloads

Exit codes:
    0 - Node is safe to drain / readiness check passed
    1 - Node has issues preventing safe drain / pod evictions pending
    2 - Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_node_pods(context: Context, node_name: str) -> list:
    """Get all pods running on a specific node."""
    try:
        result = context.run(
            [
                "kubectl",
                "get",
                "pods",
                "-A",
                "-o",
                "json",
                "--field-selector",
                f"spec.nodeName={node_name}",
            ]
        )
        if result.returncode == 0:
            return json.loads(result.stdout).get("items", [])
    except Exception:
        pass
    return []


def get_all_nodes(context: Context) -> list:
    """Get all nodes in the cluster."""
    try:
        result = context.run(["kubectl", "get", "nodes", "-o", "json"])
        if result.returncode == 0:
            return json.loads(result.stdout).get("items", [])
    except Exception:
        pass
    return []


def get_pod_disruption_budgets(context: Context) -> list:
    """Get all PodDisruptionBudgets in cluster."""
    try:
        result = context.run(["kubectl", "get", "pdb", "-A", "-o", "json"])
        if result.returncode == 0:
            return json.loads(result.stdout).get("items", [])
    except Exception:
        pass
    return []


def check_pod_evictable(pod: dict, pdbs: list) -> list:
    """Check if a pod can be safely evicted."""
    issues = []
    pod_name = pod["metadata"]["name"]
    namespace = pod["metadata"]["namespace"]

    # Check for local storage
    volumes = pod["spec"].get("volumes", [])
    for vol in volumes:
        if vol.get("emptyDir"):
            issues.append("has emptyDir storage")
        if vol.get("hostPath"):
            issues.append("has hostPath storage")

    # Check for system critical pod annotations
    annotations = pod["metadata"].get("annotations", {})
    if annotations.get("scheduler.alpha.kubernetes.io/critical-pod") == "true":
        issues.append("marked as critical pod")

    # Check pod phase
    pod_phase = pod.get("status", {}).get("phase", "Unknown")
    if pod_phase in ["Failed", "Unknown"]:
        issues.append(f"pod phase is {pod_phase}")

    # Check for PDB conflicts
    for pdb in pdbs:
        pdb_ns = pdb["metadata"]["namespace"]
        pdb_selector = pdb["spec"].get("selector", {}).get("matchLabels", {})

        if pdb_ns == namespace:
            pod_labels = pod["metadata"].get("labels", {})
            if pdb_selector and all(
                pod_labels.get(k) == v for k, v in pdb_selector.items()
            ):
                min_available = pdb["spec"].get("minAvailable")
                max_unavailable = pdb["spec"].get("maxUnavailable")

                if min_available or max_unavailable:
                    issues.append(f"PDB constraint ({pdb['metadata']['name']})")

    # Check for stateful workload patterns
    owner_refs = pod["metadata"].get("ownerReferences", [])
    for owner in owner_refs:
        kind = owner.get("kind", "")
        if kind == "StatefulSet":
            issues.append("managed by StatefulSet")
        elif kind == "DaemonSet":
            issues.append("managed by DaemonSet")

    return issues


def analyze_node_drainability(
    context: Context, node_name: str, warn_only: bool = False
) -> tuple[dict, bool]:
    """Analyze if a node can be safely drained."""
    pods = get_node_pods(context, node_name)
    pdbs = get_pod_disruption_budgets(context)

    issues_found = False
    results = {
        "node": node_name,
        "pod_count": len(pods),
        "pods": [],
        "eviction_warnings": 0,
        "critical_pods": 0,
        "timestamp": datetime.now().isoformat(),
    }

    for pod in pods:
        pod_name = pod["metadata"]["name"]
        namespace = pod["metadata"]["namespace"]
        issues = check_pod_evictable(pod, pdbs)

        pod_info = {
            "name": pod_name,
            "namespace": namespace,
            "evictable": len(issues) == 0,
            "issues": issues if issues else [],
        }

        if issues:
            issues_found = True
            results["eviction_warnings"] += 1
            if any("critical" in issue for issue in issues):
                results["critical_pods"] += 1

        if not warn_only or issues:
            results["pods"].append(pod_info)

    return results, issues_found


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = safe to drain, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Check Kubernetes node drain readiness and pod eviction constraints"
    )
    parser.add_argument("node", nargs="?", help="Node name to check")
    parser.add_argument(
        "--action",
        choices=["check", "check-all"],
        default="check",
        help="Action to perform (default: check)",
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
        help="Only show pods with eviction issues",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Validate arguments
    if opts.action != "check-all" and not opts.node:
        output.error("node argument required for check action")
        return 2

    if opts.action == "check-all":
        # Check all nodes
        nodes = get_all_nodes(context)
        if not nodes:
            output.error("Failed to get nodes")
            return 2

        all_results = []
        exit_code = 0

        for node in nodes:
            node_name = node["metadata"]["name"]
            results, issues = analyze_node_drainability(
                context, node_name, warn_only=opts.warn_only
            )
            all_results.append((results, issues))
            if issues:
                exit_code = 1

        if opts.format == "json":
            print(json.dumps([r[0] for r in all_results], indent=2))
        else:
            for results, _ in all_results:
                _print_output(results, opts.format)
                print()

        output.set_summary(
            f"nodes={len(nodes)}, issues={sum(1 for r in all_results if r[1])}"
        )
        return exit_code

    # Single node check
    results, issues_found = analyze_node_drainability(
        context, opts.node, warn_only=opts.warn_only
    )

    if opts.format == "json":
        print(json.dumps(results, indent=2))
    else:
        _print_output(results, opts.format)

    output.set_summary(
        f"node={opts.node}, pods={results['pod_count']}, warnings={results['eviction_warnings']}"
    )

    return 1 if issues_found else 0


def _print_output(results: dict, format_type: str) -> None:
    """Print results in the specified format."""
    if format_type == "plain":
        print(f"Node: {results['node']}")
        print(f"Total pods: {results['pod_count']}")
        print(f"Eviction warnings: {results['eviction_warnings']}")
        print(f"Critical pods: {results['critical_pods']}")
        print()

        if results["pods"]:
            print("Pod Details:")
            for pod in results["pods"]:
                status = "EVICTABLE" if pod["evictable"] else "NOT EVICTABLE"
                print(f"  {pod['namespace']}/{pod['name']} [{status}]")
                if pod["issues"]:
                    for issue in pod["issues"]:
                        print(f"    - {issue}")
    else:  # table
        print(f"\n{'Node':<30} {results['node']}")
        print(f"{'Total Pods':<30} {results['pod_count']}")
        print(f"{'Eviction Warnings':<30} {results['eviction_warnings']}")
        print(f"{'Critical Pods':<30} {results['critical_pods']}\n")

        if results["pods"]:
            print(f"{'NAMESPACE/NAME':<50} {'EVICTABLE':<12} {'ISSUES'}")
            print("-" * 100)
            for pod in results["pods"]:
                status = "Yes" if pod["evictable"] else "No"
                issues_str = ", ".join(pod["issues"][:2]) if pod["issues"] else "None"
                name = f"{pod['namespace']}/{pod['name']}"
                print(f"{name:<50} {status:<12} {issues_str}")


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
