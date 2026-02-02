#!/usr/bin/env python3
# boxctl:
#   category: k8s/resources
#   tags: [qos, kubernetes, pods, eviction, resources]
#   requires: [kubectl]
#   brief: Audit pod QoS classes and identify eviction risks
#   privilege: user
#   related: [pod_eviction_risk_analyzer, resource_rightsizer, pod_resource_audit]

"""
Kubernetes QoS class auditor - Analyze pod quality of service assignments.

Analyzes:
- Pods with BestEffort QoS (first to be evicted under memory pressure)
- Pods with Burstable QoS that could be Guaranteed
- Critical workloads without Guaranteed QoS
- Namespace-level QoS distribution

QoS Classes:
    Guaranteed - CPU/memory requests equal limits for all containers
    Burstable  - At least one container has CPU or memory request
    BestEffort - No CPU or memory requests/limits set

Exit codes:
    0 - No issues detected
    1 - Issues found (BestEffort pods or misconfigured workloads)
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def determine_qos_class(pod: dict) -> tuple:
    """
    Determine the QoS class for a pod based on container resource specs.

    Returns tuple of (qos_class, reason, can_upgrade, upgrade_suggestion)
    """
    containers = pod.get("spec", {}).get("containers", [])
    init_containers = pod.get("spec", {}).get("initContainers", [])
    all_containers = containers + init_containers

    if not all_containers:
        return "BestEffort", "no containers", False, None

    all_have_requests_and_limits = True
    all_requests_equal_limits = True
    has_any_request_or_limit = False
    missing_specs = []

    for container in all_containers:
        resources = container.get("resources", {})
        requests = resources.get("requests", {})
        limits = resources.get("limits", {})
        name = container.get("name", "unknown")

        cpu_req = requests.get("cpu")
        cpu_lim = limits.get("cpu")
        mem_req = requests.get("memory")
        mem_lim = limits.get("memory")

        if cpu_req or cpu_lim or mem_req or mem_lim:
            has_any_request_or_limit = True

        if not (cpu_req and cpu_lim and mem_req and mem_lim):
            all_have_requests_and_limits = False
            missing = []
            if not cpu_req:
                missing.append("cpu request")
            if not cpu_lim:
                missing.append("cpu limit")
            if not mem_req:
                missing.append("memory request")
            if not mem_lim:
                missing.append("memory limit")
            if missing:
                missing_specs.append(f"{name}: {', '.join(missing)}")

        if cpu_req != cpu_lim or mem_req != mem_lim:
            all_requests_equal_limits = False

    if not has_any_request_or_limit:
        return "BestEffort", "no resource specs", True, "Add CPU/memory requests and limits"

    if all_have_requests_and_limits and all_requests_equal_limits:
        return "Guaranteed", "all requests equal limits", False, None

    if all_have_requests_and_limits:
        reason = "requests != limits"
        suggestion = "Set requests equal to limits for Guaranteed QoS"
    else:
        reason = f"missing: {'; '.join(missing_specs[:2])}"
        if len(missing_specs) > 2:
            reason += f" (+{len(missing_specs) - 2} more)"
        suggestion = "Add missing resource specs for all containers"

    return "Burstable", reason, True, suggestion


def analyze_pod(pod: dict) -> dict:
    """Analyze a single pod's QoS configuration."""
    metadata = pod.get("metadata", {})
    spec = pod.get("spec", {})
    status = pod.get("status", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")
    phase = status.get("phase", "Unknown")

    owner_refs = metadata.get("ownerReferences", [])
    owner_kind = owner_refs[0].get("kind", "None") if owner_refs else "None"
    owner_name = owner_refs[0].get("name", "None") if owner_refs else "None"

    qos_class = status.get("qosClass", None)
    calculated_qos, reason, can_upgrade, suggestion = determine_qos_class(pod)

    if not qos_class:
        qos_class = calculated_qos

    labels = metadata.get("labels", {})
    annotations = metadata.get("annotations", {})

    is_critical = (
        labels.get("app.kubernetes.io/component") in ["controller", "scheduler", "etcd"]
        or "critical" in labels.get("tier", "").lower()
        or "critical" in labels.get("priority", "").lower()
        or namespace.startswith("kube-")
        or annotations.get("scheduler.alpha.kubernetes.io/critical-pod") == "true"
    )

    container_count = len(spec.get("containers", []))
    init_container_count = len(spec.get("initContainers", []))

    return {
        "name": name,
        "namespace": namespace,
        "phase": phase,
        "qos_class": qos_class,
        "calculated_qos": calculated_qos,
        "reason": reason,
        "can_upgrade": can_upgrade,
        "upgrade_suggestion": suggestion,
        "owner_kind": owner_kind,
        "owner_name": owner_name,
        "is_critical": is_critical,
        "container_count": container_count,
        "init_container_count": init_container_count,
    }


def categorize_findings(analyses: list, critical_only: bool = False) -> tuple:
    """Categorize pods by QoS class and identify issues."""
    categories = {"Guaranteed": [], "Burstable": [], "BestEffort": []}

    issues = {
        "critical_not_guaranteed": [],
        "best_effort": [],
        "upgradeable": [],
    }

    namespace_stats = defaultdict(
        lambda: {"Guaranteed": 0, "Burstable": 0, "BestEffort": 0}
    )

    for analysis in analyses:
        qos = analysis["qos_class"]
        categories[qos].append(analysis)
        namespace_stats[analysis["namespace"]][qos] += 1

        if qos == "BestEffort":
            issues["best_effort"].append(analysis)

        if analysis["is_critical"] and qos != "Guaranteed":
            issues["critical_not_guaranteed"].append(analysis)

        if qos == "Burstable" and analysis["can_upgrade"]:
            if not critical_only or analysis["is_critical"]:
                issues["upgradeable"].append(analysis)

    return categories, issues, dict(namespace_stats)


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
        description="Audit Kubernetes pod QoS classes and identify eviction risks"
    )
    parser.add_argument(
        "-n", "--namespace", help="Kubernetes namespace to audit (default: all namespaces)"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "table", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show pods with QoS issues"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed recommendations and upgradeable pods",
    )
    parser.add_argument(
        "--critical-only",
        action="store_true",
        help="Only analyze pods marked as critical",
    )
    parser.add_argument(
        "--exclude-namespace",
        action="append",
        default=[],
        help="Namespaces to exclude (can be specified multiple times)",
    )
    opts = parser.parse_args(args)

    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

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
        pods = json.loads(result.stdout).get("items", [])
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    if not pods:
        if opts.format == "json":
            print(json.dumps({"summary": {"total": 0}, "categories": {}}))
        else:
            print("No pods found")
        return 0

    # Analyze each pod
    analyses = []
    for pod in pods:
        ns = pod.get("metadata", {}).get("namespace", "")
        if ns in opts.exclude_namespace:
            continue

        analysis = analyze_pod(pod)

        if analysis["phase"] not in ["Running", "Pending"]:
            continue

        if opts.critical_only and not analysis["is_critical"]:
            continue

        analyses.append(analysis)

    if not analyses:
        if opts.format == "json":
            print(json.dumps({"summary": {"total": 0}, "categories": {}}))
        else:
            print("No matching pods found")
        return 0

    # Categorize findings
    categories, issues, namespace_stats = categorize_findings(
        analyses, critical_only=opts.critical_only
    )

    has_issues = bool(issues["critical_not_guaranteed"] or issues["best_effort"])

    # Output results
    if opts.format == "json":
        result_data = {
            "summary": {
                "total": sum(len(pods) for pods in categories.values()),
                "guaranteed": len(categories["Guaranteed"]),
                "burstable": len(categories["Burstable"]),
                "best_effort": len(categories["BestEffort"]),
            },
            "issues": {
                "critical_not_guaranteed": issues["critical_not_guaranteed"],
                "best_effort": issues["best_effort"],
                "upgradeable_count": len(issues["upgradeable"]),
            },
            "namespace_distribution": namespace_stats,
            "categories": {
                "guaranteed": categories["Guaranteed"],
                "burstable": categories["Burstable"],
                "best_effort": categories["BestEffort"],
            },
        }
        print(json.dumps(result_data, indent=2, default=str))
    elif opts.format == "table":
        all_pods = []
        for qos, pods_list in categories.items():
            all_pods.extend(pods_list)

        if opts.warn_only:
            all_pods = [
                p
                for p in all_pods
                if p["qos_class"] == "BestEffort"
                or (p["is_critical"] and p["qos_class"] != "Guaranteed")
            ]

        qos_order = {"BestEffort": 0, "Burstable": 1, "Guaranteed": 2}
        all_pods.sort(
            key=lambda x: (qos_order.get(x["qos_class"], 3), x["namespace"], x["name"])
        )

        print(
            f"{'NAMESPACE':<20} {'POD':<35} {'QOS':<12} {'OWNER':<20} {'CRITICAL':<8}"
        )
        print("-" * 100)

        for pod in all_pods:
            ns = pod["namespace"][:18] + ".." if len(pod["namespace"]) > 20 else pod["namespace"]
            name = pod["name"][:33] + ".." if len(pod["name"]) > 35 else pod["name"]
            owner = f"{pod['owner_kind'][:8]}/{pod['owner_name'][:9]}"
            critical = "YES" if pod["is_critical"] else ""

            print(f"{ns:<20} {name:<35} {pod['qos_class']:<12} {owner:<20} {critical:<8}")

        print()
        print(
            f"Total: {len(all_pods)} | "
            f"Guaranteed: {len(categories['Guaranteed'])} | "
            f"Burstable: {len(categories['Burstable'])} | "
            f"BestEffort: {len(categories['BestEffort'])}"
        )
    else:  # plain
        total = sum(len(pods_list) for pods_list in categories.values())

        if not opts.warn_only:
            print("Kubernetes QoS Class Audit")
            print("=" * 80)
            print(f"Total pods analyzed: {total}")
            print(
                f"  Guaranteed:  {len(categories['Guaranteed']):4d} (protected from eviction)"
            )
            print(
                f"  Burstable:   {len(categories['Burstable']):4d} (may be evicted under pressure)"
            )
            print(
                f"  BestEffort:  {len(categories['BestEffort']):4d} (first to be evicted)"
            )
            print()

        if issues["critical_not_guaranteed"]:
            print(
                f"Critical Pods Without Guaranteed QoS "
                f"({len(issues['critical_not_guaranteed'])}):"
            )
            print("-" * 80)
            for pod in issues["critical_not_guaranteed"]:
                print(f"  {pod['namespace']}/{pod['name']}")
                print(f"    QoS: {pod['qos_class']} - {pod['reason']}")
                print(f"    Owner: {pod['owner_kind']}/{pod['owner_name']}")
                if pod["upgrade_suggestion"]:
                    print(f"    Fix: {pod['upgrade_suggestion']}")
                print()

        if issues["best_effort"]:
            print(
                f"BestEffort Pods - High Eviction Risk ({len(issues['best_effort'])}):"
            )
            print("-" * 80)
            for pod in sorted(
                issues["best_effort"], key=lambda x: (x["namespace"], x["name"])
            ):
                print(f"  {pod['namespace']}/{pod['name']}")
                print(f"    Owner: {pod['owner_kind']}/{pod['owner_name']}")
                print(f"    Fix: {pod['upgrade_suggestion']}")
                if opts.verbose:
                    print(f"    Containers: {pod['container_count']}")
                print()

        if issues["upgradeable"] and opts.verbose:
            print(
                f"Burstable Pods Upgradeable to Guaranteed "
                f"({len(issues['upgradeable'])}):"
            )
            print("-" * 80)
            for pod in sorted(
                issues["upgradeable"], key=lambda x: (x["namespace"], x["name"])
            )[:20]:
                print(f"  {pod['namespace']}/{pod['name']}")
                print(f"    Reason: {pod['reason']}")
                print(f"    Fix: {pod['upgrade_suggestion']}")
                print()
            if len(issues["upgradeable"]) > 20:
                print(f"  ... and {len(issues['upgradeable']) - 20} more")
                print()

        if not opts.warn_only and namespace_stats:
            print("QoS Distribution by Namespace:")
            print("-" * 80)
            print(
                f"{'NAMESPACE':<30} {'GUARANTEED':>12} {'BURSTABLE':>12} {'BESTEFFORT':>12}"
            )
            print("-" * 80)
            for ns in sorted(namespace_stats.keys()):
                stats = namespace_stats[ns]
                print(
                    f"{ns:<30} {stats['Guaranteed']:>12} "
                    f"{stats['Burstable']:>12} {stats['BestEffort']:>12}"
                )
            print()

        if has_issues:
            print("Recommendations:")
            print("-" * 80)
            if issues["critical_not_guaranteed"]:
                print(
                    f"  - {len(issues['critical_not_guaranteed'])} critical pods "
                    "need Guaranteed QoS"
                )
            if issues["best_effort"]:
                print(
                    f"  - {len(issues['best_effort'])} pods have BestEffort QoS "
                    "(high eviction risk)"
                )
            if issues["upgradeable"]:
                print(
                    f"  - {len(issues['upgradeable'])} Burstable pods could be "
                    "upgraded to Guaranteed"
                )
        elif opts.warn_only:
            print("No QoS issues detected")

    output.set_summary(
        f"total={total}, guaranteed={len(categories['Guaranteed'])}, "
        f"best_effort={len(categories['BestEffort'])}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
