#!/usr/bin/env python3
# boxctl:
#   category: k8s/scheduling
#   tags: [topology, kubernetes, pods, affinity, availability]
#   requires: [kubectl]
#   brief: Analyze pod topology spread constraints and affinity rules
#   privilege: user
#   related: [node_taint_analyzer, pod_eviction_risk_analyzer]

"""
Kubernetes pod topology analyzer - Identify high-availability risks in pod distribution.

Analyzes:
- TopologySpreadConstraints configuration
- Pod affinity and anti-affinity rules
- Pod distribution across nodes and zones
- Deployments/StatefulSets missing topology constraints

Useful for:
- High availability validation
- Identifying single points of failure
- Cluster topology planning
- Pre-deployment validation

Exit codes:
    0 - No topology issues detected
    1 - Topology issues or risks found
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def analyze_topology_spread_constraints(pod_spec: dict) -> dict:
    """Analyze topology spread constraints in a pod spec."""
    constraints = pod_spec.get("topologySpreadConstraints", [])

    if not constraints:
        return {"has_constraints": False, "constraints": [], "topology_keys": []}

    analyzed = []
    topology_keys = set()

    for constraint in constraints:
        topology_key = constraint.get("topologyKey", "")
        max_skew = constraint.get("maxSkew", 1)
        when_unsatisfiable = constraint.get("whenUnsatisfiable", "DoNotSchedule")
        label_selector = constraint.get("labelSelector", {})

        topology_keys.add(topology_key)

        analyzed.append(
            {
                "topology_key": topology_key,
                "max_skew": max_skew,
                "when_unsatisfiable": when_unsatisfiable,
                "has_label_selector": bool(label_selector),
            }
        )

    return {
        "has_constraints": True,
        "constraints": analyzed,
        "topology_keys": list(topology_keys),
    }


def analyze_affinity(pod_spec: dict) -> dict:
    """Analyze pod affinity and anti-affinity rules."""
    affinity = pod_spec.get("affinity", {})

    result = {
        "has_pod_affinity": False,
        "has_pod_anti_affinity": False,
        "has_node_affinity": False,
        "pod_affinity_rules": [],
        "pod_anti_affinity_rules": [],
        "node_affinity_rules": [],
    }

    # Pod affinity
    pod_affinity = affinity.get("podAffinity", {})
    if pod_affinity:
        result["has_pod_affinity"] = True
        required = pod_affinity.get("requiredDuringSchedulingIgnoredDuringExecution", [])
        preferred = pod_affinity.get(
            "preferredDuringSchedulingIgnoredDuringExecution", []
        )

        for rule in required:
            result["pod_affinity_rules"].append(
                {"type": "required", "topology_key": rule.get("topologyKey", "")}
            )

        for rule in preferred:
            pod_affinity_term = rule.get("podAffinityTerm", {})
            result["pod_affinity_rules"].append(
                {
                    "type": "preferred",
                    "weight": rule.get("weight", 1),
                    "topology_key": pod_affinity_term.get("topologyKey", ""),
                }
            )

    # Pod anti-affinity
    pod_anti_affinity = affinity.get("podAntiAffinity", {})
    if pod_anti_affinity:
        result["has_pod_anti_affinity"] = True
        required = pod_anti_affinity.get(
            "requiredDuringSchedulingIgnoredDuringExecution", []
        )
        preferred = pod_anti_affinity.get(
            "preferredDuringSchedulingIgnoredDuringExecution", []
        )

        for rule in required:
            result["pod_anti_affinity_rules"].append(
                {"type": "required", "topology_key": rule.get("topologyKey", "")}
            )

        for rule in preferred:
            pod_affinity_term = rule.get("podAffinityTerm", {})
            result["pod_anti_affinity_rules"].append(
                {
                    "type": "preferred",
                    "weight": rule.get("weight", 1),
                    "topology_key": pod_affinity_term.get("topologyKey", ""),
                }
            )

    # Node affinity
    node_affinity = affinity.get("nodeAffinity", {})
    if node_affinity:
        result["has_node_affinity"] = True
        required = node_affinity.get("requiredDuringSchedulingIgnoredDuringExecution", {})
        preferred = node_affinity.get(
            "preferredDuringSchedulingIgnoredDuringExecution", []
        )

        if required:
            result["node_affinity_rules"].append({"type": "required"})
        for _ in preferred:
            result["node_affinity_rules"].append({"type": "preferred"})

    return result


def analyze_pod_distribution(pods: list, nodes: dict) -> list:
    """Analyze how pods are distributed across nodes and zones."""
    owner_pods = defaultdict(list)

    for pod in pods:
        metadata = pod.get("metadata", {})
        namespace = metadata.get("namespace", "default")
        pod_name = metadata.get("name", "unknown")
        node_name = pod.get("spec", {}).get("nodeName")

        owner_refs = metadata.get("ownerReferences", [])
        owner_key = f"{namespace}/standalone"
        for ref in owner_refs:
            if ref.get("kind") in ["ReplicaSet", "StatefulSet", "DaemonSet", "Job"]:
                owner_key = f"{namespace}/{ref.get('kind')}/{ref.get('name')}"
                break

        if node_name:
            node_info = nodes.get(node_name, {})
            owner_pods[owner_key].append(
                {
                    "name": pod_name,
                    "node": node_name,
                    "zone": node_info.get("zone", "unknown"),
                }
            )

    distribution_issues = []

    for owner_key, pods_list in owner_pods.items():
        if len(pods_list) < 2:
            continue

        namespace, *rest = owner_key.split("/")
        owner_name = "/".join(rest)

        node_counts = defaultdict(int)
        zone_counts = defaultdict(int)

        for p in pods_list:
            node_counts[p["node"]] += 1
            zone_counts[p["zone"]] += 1

        total_pods = len(pods_list)
        max_on_single_node = max(node_counts.values())
        unique_nodes = len(node_counts)
        unique_zones = len(zone_counts)

        issues = []

        if unique_nodes == 1 and total_pods > 1:
            issues.append(
                f"All {total_pods} pods on single node: {list(node_counts.keys())[0]}"
            )

        if (
            unique_zones == 1
            and total_pods > 1
            and list(zone_counts.keys())[0] != "unknown"
        ):
            issues.append(
                f"All {total_pods} pods in single zone: {list(zone_counts.keys())[0]}"
            )

        if total_pods > 2 and max_on_single_node > total_pods / 2:
            concentrated_node = max(node_counts, key=node_counts.get)
            issues.append(
                f"{max_on_single_node}/{total_pods} pods concentrated on node: "
                f"{concentrated_node}"
            )

        if issues:
            distribution_issues.append(
                {
                    "namespace": namespace,
                    "owner": owner_name,
                    "total_pods": total_pods,
                    "unique_nodes": unique_nodes,
                    "unique_zones": unique_zones,
                    "issues": issues,
                    "node_distribution": dict(node_counts),
                    "zone_distribution": dict(zone_counts),
                }
            )

    return distribution_issues


def analyze_workload(workload: dict, kind: str) -> dict:
    """Analyze a deployment or statefulset for topology configuration."""
    metadata = workload.get("metadata", {})
    namespace = metadata.get("namespace", "default")
    name = metadata.get("name", "unknown")
    replicas = workload.get("spec", {}).get("replicas", 1)

    pod_spec = workload.get("spec", {}).get("template", {}).get("spec", {})

    topology = analyze_topology_spread_constraints(pod_spec)
    affinity = analyze_affinity(pod_spec)

    issues = []
    severity = "OK"

    if replicas > 1 and not topology["has_constraints"]:
        if not affinity["has_pod_anti_affinity"]:
            issues.append("No topology spread constraints or pod anti-affinity defined")
            severity = "WARNING"

    if replicas > 1 and topology["has_constraints"]:
        has_zone_spread = any(
            "zone" in c["topology_key"].lower() for c in topology["constraints"]
        )
        if not has_zone_spread:
            issues.append("No zone-level topology spread constraint")

    if replicas > 1 and affinity["has_pod_anti_affinity"]:
        required_anti_affinity = any(
            r["type"] == "required" for r in affinity["pod_anti_affinity_rules"]
        )
        if not required_anti_affinity:
            issues.append("Pod anti-affinity is preferred, not required")

    return {
        "namespace": namespace,
        "name": name,
        "kind": kind,
        "replicas": replicas,
        "has_topology_constraints": topology["has_constraints"],
        "topology_keys": topology["topology_keys"],
        "has_pod_affinity": affinity["has_pod_affinity"],
        "has_pod_anti_affinity": affinity["has_pod_anti_affinity"],
        "has_node_affinity": affinity["has_node_affinity"],
        "issues": issues,
        "severity": severity if not issues else ("CRITICAL" if replicas > 2 else "WARNING"),
    }


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
        description="Analyze Kubernetes pod topology spread constraints and affinity rules"
    )
    parser.add_argument(
        "-n", "--namespace", help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show workloads with topology issues",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed topology information"
    )
    opts = parser.parse_args(args)

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

    nodes = {}
    for node in nodes_data.get("items", []):
        node_name = node.get("metadata", {}).get("name", "unknown")
        labels = node.get("metadata", {}).get("labels", {})
        nodes[node_name] = {
            "labels": labels,
            "zone": labels.get(
                "topology.kubernetes.io/zone",
                labels.get("failure-domain.beta.kubernetes.io/zone", "unknown"),
            ),
            "region": labels.get(
                "topology.kubernetes.io/region",
                labels.get("failure-domain.beta.kubernetes.io/region", "unknown"),
            ),
            "hostname": labels.get("kubernetes.io/hostname", node_name),
        }

    # Get pods
    try:
        cmd = ["kubectl", "get", "pods", "-o", "json"]
        if opts.namespace:
            cmd.extend(["-n", opts.namespace])
        else:
            cmd.append("--all-namespaces")
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    # Get deployments
    try:
        cmd = ["kubectl", "get", "deployments", "-o", "json"]
        if opts.namespace:
            cmd.extend(["-n", opts.namespace])
        else:
            cmd.append("--all-namespaces")
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        deployments_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get deployments: {e}")
        return 2

    # Get statefulsets
    try:
        cmd = ["kubectl", "get", "statefulsets", "-o", "json"]
        if opts.namespace:
            cmd.extend(["-n", opts.namespace])
        else:
            cmd.append("--all-namespaces")
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        statefulsets_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get statefulsets: {e}")
        return 2

    # Analyze workloads
    workloads = []

    for deployment in deployments_data.get("items", []):
        analysis = analyze_workload(deployment, "Deployment")
        if not opts.warn_only or analysis["issues"]:
            workloads.append(analysis)

    for statefulset in statefulsets_data.get("items", []):
        analysis = analyze_workload(statefulset, "StatefulSet")
        if not opts.warn_only or analysis["issues"]:
            workloads.append(analysis)

    # Analyze pod distribution
    distribution_issues = analyze_pod_distribution(pods_data.get("items", []), nodes)

    # Prepare results
    results = {
        "summary": {
            "total_workloads": len(workloads),
            "workloads_with_issues": len([w for w in workloads if w["issues"]]),
            "distribution_issues": len(distribution_issues),
            "total_nodes": len(nodes),
            "unique_zones": len(
                set(n["zone"] for n in nodes.values() if n["zone"] != "unknown")
            ),
        },
        "workloads": workloads,
        "distribution_issues": distribution_issues,
    }

    # Output
    if opts.format == "json":
        print(json.dumps(results, indent=2))
    elif opts.format == "table":
        if workloads:
            print("WORKLOAD TOPOLOGY ANALYSIS")
            print(
                f"{'NAMESPACE':<20} {'WORKLOAD':<35} {'REPLICAS':<10} "
                f"{'TOPOLOGY':<10} {'SEVERITY':<10} {'ISSUES':<40}"
            )
            print("-" * 125)

            for w in workloads:
                workload_name = f"{w['kind']}/{w['name']}"[:35]
                topology = "Yes" if w["has_topology_constraints"] else "No"
                issues_str = "; ".join(w["issues"])[:40] if w["issues"] else "None"
                print(
                    f"{w['namespace']:<20} {workload_name:<35} {w['replicas']:<10} "
                    f"{topology:<10} {w['severity']:<10} {issues_str:<40}"
                )

            print()

        if distribution_issues:
            print("POD DISTRIBUTION ISSUES")
            print(
                f"{'NAMESPACE':<20} {'OWNER':<35} {'PODS':<8} {'NODES':<8} "
                f"{'ZONES':<8} {'ISSUES':<50}"
            )
            print("-" * 130)

            for d in distribution_issues:
                issues_str = "; ".join(d["issues"])[:50]
                print(
                    f"{d['namespace']:<20} {d['owner']:<35} {d['total_pods']:<8} "
                    f"{d['unique_nodes']:<8} {d['unique_zones']:<8} {issues_str:<50}"
                )
    else:  # plain
        for w in workloads:
            if w["issues"]:
                issues_str = "; ".join(w["issues"])[:60]
                print(
                    f"{w['namespace']} {w['kind']}/{w['name']} replicas={w['replicas']} "
                    f"{w['severity']} {issues_str}"
                )

        for d in distribution_issues:
            issues_str = "; ".join(d["issues"])[:60]
            print(
                f"{d['namespace']} {d['owner']} pods={d['total_pods']} "
                f"nodes={d['unique_nodes']} zones={d['unique_zones']} {issues_str}"
            )

    has_issues = bool(
        results["summary"]["workloads_with_issues"]
        or results["summary"]["distribution_issues"]
    )
    output.set_summary(
        f"workloads={results['summary']['total_workloads']}, "
        f"issues={results['summary']['workloads_with_issues']}, "
        f"distribution_issues={results['summary']['distribution_issues']}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
