#!/usr/bin/env python3
# boxctl:
#   category: k8s/security
#   tags: [runtime, kubernetes, security, isolation, containers]
#   requires: [kubectl]
#   brief: Analyze RuntimeClass usage across workloads
#   privilege: user
#   related: [pod_resource_audit, probe_audit]

"""
Kubernetes RuntimeClass analyzer - Audit container runtime configurations.

RuntimeClasses define different container runtimes (runc, kata, gVisor, etc.)
that can provide varying levels of isolation.

Analyzes:
- All defined RuntimeClasses with their handlers
- Which pods/namespaces use which runtimes
- Workloads running with the default runtime (no explicit RuntimeClass)
- References to non-existent RuntimeClasses
- Isolation level summary across the cluster

Useful for:
- Security audits requiring workload isolation verification
- Migration planning when introducing new runtimes
- Compliance reporting on isolation boundaries
- Capacity planning for runtime-specific node pools

Exit codes:
    0 - Analysis complete, no issues detected
    1 - Issues detected (missing RuntimeClasses, warnings)
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_owner_kind(owner_refs: list) -> str:
    """Get the kind of the controller owning this pod."""
    if not owner_refs:
        return "None"
    return owner_refs[0].get("kind", "Unknown")


def analyze_runtime_usage(pods: list, runtimeclasses: dict) -> dict:
    """Analyze runtime class usage patterns across pods."""
    analysis = {
        "total_pods": len(pods),
        "pods_with_runtime": 0,
        "pods_without_runtime": 0,
        "by_runtime": defaultdict(list),
        "by_namespace": defaultdict(lambda: defaultdict(int)),
        "missing_runtimeclasses": [],
        "issues": [],
    }

    seen_missing = set()

    for pod in pods:
        runtime = pod["runtime_class"]
        ns = pod["namespace"]

        if runtime:
            analysis["pods_with_runtime"] += 1
            analysis["by_runtime"][runtime].append(pod)
            analysis["by_namespace"][ns][runtime] += 1

            if runtime not in runtimeclasses and runtime not in seen_missing:
                seen_missing.add(runtime)
                analysis["missing_runtimeclasses"].append(runtime)
                analysis["issues"].append(
                    {
                        "severity": "WARNING",
                        "message": f"RuntimeClass '{runtime}' referenced but not defined",
                        "affected_pods": [
                            p["namespace"] + "/" + p["name"]
                            for p in pods
                            if p["runtime_class"] == runtime
                        ][:5],
                    }
                )
        else:
            analysis["pods_without_runtime"] += 1
            analysis["by_runtime"]["<default>"].append(pod)
            analysis["by_namespace"][ns]["<default>"] += 1

    for ns, runtimes in analysis["by_namespace"].items():
        if len(runtimes) > 1 and "<default>" in runtimes:
            isolation_runtimes = [r for r in runtimes if r != "<default>"]
            if isolation_runtimes:
                analysis["issues"].append(
                    {
                        "severity": "INFO",
                        "message": f"Namespace '{ns}' has mixed runtime isolation",
                        "detail": f"Some pods use {isolation_runtimes}, others use default runtime",
                    }
                )

    return analysis


def get_isolation_level(runtime: str, runtimeclasses: dict) -> str:
    """Determine isolation level based on runtime handler."""
    if runtime == "<default>" or runtime is None:
        return "standard"

    if runtime not in runtimeclasses:
        return "unknown"

    handler = runtimeclasses[runtime]["handler"].lower()

    if any(x in handler for x in ["kata", "firecracker", "qemu"]):
        return "vm-isolated"
    elif any(x in handler for x in ["gvisor", "runsc"]):
        return "sandboxed"
    elif any(x in handler for x in ["youki", "crun", "runc"]):
        return "standard"
    else:
        return "custom"


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
        description="Analyze Kubernetes RuntimeClass usage across workloads"
    )
    parser.add_argument(
        "-n", "--namespace", help="Namespace to analyze (default: all namespaces)"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "table", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed breakdown including per-namespace usage",
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show warnings and issues"
    )
    opts = parser.parse_args(args)

    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get RuntimeClasses
    runtimeclasses = {}
    try:
        result = context.run(["kubectl", "get", "runtimeclasses", "-o", "json"])
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for rc in data.get("items", []):
                name = rc.get("metadata", {}).get("name", "unknown")
                handler = rc.get("handler", name)
                scheduling = rc.get("scheduling", {})
                overhead = rc.get("overhead", {})

                runtimeclasses[name] = {
                    "handler": handler,
                    "node_selector": scheduling.get("nodeSelector", {}),
                    "tolerations": scheduling.get("tolerations", []),
                    "pod_overhead_cpu": overhead.get("podFixed", {}).get("cpu"),
                    "pod_overhead_memory": overhead.get("podFixed", {}).get("memory"),
                }
    except Exception:
        pass

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

        data = json.loads(result.stdout)
        pods = []
        for pod in data.get("items", []):
            metadata = pod.get("metadata", {})
            spec = pod.get("spec", {})

            pods.append(
                {
                    "name": metadata.get("name", "unknown"),
                    "namespace": metadata.get("namespace", "default"),
                    "runtime_class": spec.get("runtimeClassName"),
                    "node": spec.get("nodeName"),
                    "phase": pod.get("status", {}).get("phase", "Unknown"),
                    "owner_kind": get_owner_kind(metadata.get("ownerReferences", [])),
                }
            )
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    if not pods:
        if opts.namespace:
            print(f"No pods found in namespace '{opts.namespace}'")
        else:
            print("No pods found in cluster")
        return 0

    # Analyze
    analysis = analyze_runtime_usage(pods, runtimeclasses)

    has_warnings = any(i["severity"] == "WARNING" for i in analysis["issues"])

    # Output
    if opts.format == "json":
        output_data = {
            "summary": {
                "total_pods": analysis["total_pods"],
                "pods_with_runtime": analysis["pods_with_runtime"],
                "pods_without_runtime": analysis["pods_without_runtime"],
                "defined_runtimeclasses": len(runtimeclasses),
                "issue_count": len(analysis["issues"]),
            },
            "runtimeclasses": {
                name: {
                    **rc,
                    "pod_count": len(analysis["by_runtime"].get(name, [])),
                    "isolation_level": get_isolation_level(name, runtimeclasses),
                }
                for name, rc in runtimeclasses.items()
            },
            "usage_by_runtime": {
                runtime: {
                    "count": len(pod_list),
                    "isolation_level": get_isolation_level(runtime, runtimeclasses),
                    "namespaces": list(set(p["namespace"] for p in pod_list)),
                }
                for runtime, pod_list in analysis["by_runtime"].items()
            },
            "issues": analysis["issues"],
        }
        print(json.dumps(output_data, indent=2))
    elif opts.format == "table":
        if not opts.warn_only:
            print("=" * 70)
            print(f"{'KUBERNETES RUNTIMECLASS ANALYSIS':^70}")
            print("=" * 70)
            print()

            print(f"{'Metric':<35} {'Value':<35}")
            print("-" * 70)
            print(f"{'Total Pods':<35} {analysis['total_pods']:<35}")
            print(f"{'With Explicit RuntimeClass':<35} {analysis['pods_with_runtime']:<35}")
            print(f"{'Using Default Runtime':<35} {analysis['pods_without_runtime']:<35}")
            print(f"{'Defined RuntimeClasses':<35} {len(runtimeclasses):<35}")
            print()

            if runtimeclasses:
                print("-" * 70)
                print(
                    f"{'RuntimeClass':<20} {'Handler':<20} {'Isolation':<15} {'Pods':<10}"
                )
                print("-" * 70)
                for name, rc in sorted(runtimeclasses.items()):
                    isolation = get_isolation_level(name, runtimeclasses)
                    pod_count = len(analysis["by_runtime"].get(name, []))
                    print(f"{name:<20} {rc['handler']:<20} {isolation:<15} {pod_count:<10}")

                default_count = len(analysis["by_runtime"].get("<default>", []))
                print(f"{'<default>':<20} {'runc':<20} {'standard':<15} {default_count:<10}")
                print()

        if analysis["issues"]:
            if not opts.warn_only:
                print("-" * 70)
                print("ISSUES")
                print("-" * 70)

            print(f"{'Severity':<10} {'Message':<60}")
            print("-" * 70)
            for issue in analysis["issues"]:
                msg = (
                    issue["message"][:58] + ".."
                    if len(issue["message"]) > 58
                    else issue["message"]
                )
                print(f"{issue['severity']:<10} {msg:<60}")
            print()

        if not analysis["issues"] and not opts.warn_only:
            print("-" * 70)
            print(f"{'NO ISSUES DETECTED':^70}")
            print("-" * 70)
    else:  # plain
        if not opts.warn_only:
            print("RuntimeClass Analysis")
            print("=" * 60)
            print(f"Total pods: {analysis['total_pods']}")
            print(f"Pods with explicit RuntimeClass: {analysis['pods_with_runtime']}")
            print(f"Pods using default runtime: {analysis['pods_without_runtime']}")
            print()

            if runtimeclasses:
                print("Defined RuntimeClasses:")
                print("-" * 60)
                for name, rc in sorted(runtimeclasses.items()):
                    isolation = get_isolation_level(name, runtimeclasses)
                    print(f"  {name}")
                    print(f"    Handler: {rc['handler']}")
                    print(f"    Isolation: {isolation}")
                    if rc["pod_overhead_memory"]:
                        print(
                            f"    Overhead: {rc['pod_overhead_memory']} memory, "
                            f"{rc['pod_overhead_cpu'] or 'none'} CPU"
                        )
                    if rc["node_selector"]:
                        print(f"    Node selector: {rc['node_selector']}")
                print()

            print("Usage by RuntimeClass:")
            print("-" * 60)
            for runtime, pod_list in sorted(
                analysis["by_runtime"].items(), key=lambda x: -len(x[1])
            ):
                isolation = get_isolation_level(runtime, runtimeclasses)
                print(f"  {runtime}: {len(pod_list)} pods [{isolation}]")
                if opts.verbose:
                    ns_counts = defaultdict(int)
                    for pod in pod_list:
                        ns_counts[pod["namespace"]] += 1
                    for ns, count in sorted(ns_counts.items(), key=lambda x: -x[1])[:5]:
                        print(f"    {ns}: {count}")
                    if len(ns_counts) > 5:
                        print(f"    ... and {len(ns_counts) - 5} more namespaces")
            print()

        if analysis["issues"]:
            if not opts.warn_only:
                print("Issues Detected:")
                print("-" * 60)

            for issue in analysis["issues"]:
                print(f"[{issue['severity']}] {issue['message']}")
                if opts.verbose:
                    if "affected_pods" in issue:
                        for pod in issue["affected_pods"][:3]:
                            print(f"  - {pod}")
                        if len(issue["affected_pods"]) > 3:
                            print(f"  ... and {len(issue['affected_pods']) - 3} more")
                    if "detail" in issue:
                        print(f"  {issue['detail']}")
            print()

        if not analysis["issues"] and not opts.warn_only:
            print("No issues detected.")

    output.set_summary(
        f"pods={analysis['total_pods']}, "
        f"runtimes={len(runtimeclasses)}, "
        f"issues={len(analysis['issues'])}"
    )

    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
