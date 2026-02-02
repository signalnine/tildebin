#!/usr/bin/env python3
# boxctl:
#   category: k8s/scheduling
#   tags: [priority, kubernetes, scheduling, preemption]
#   requires: [kubectl]
#   brief: Analyze PriorityClass configuration and usage
#   privilege: user
#   related: [pod_eviction_risk_analyzer, qos_audit]

"""
Kubernetes PriorityClass analyzer - Audit priority configurations and usage.

Analyzes:
- All PriorityClasses with their priority values
- Pods using each PriorityClass
- Pods without explicit PriorityClass assignment
- Global default conflicts
- Preemption policy settings

Useful for:
- Preventing unexpected pod preemption
- Ensuring critical workloads are protected
- Identifying misconfigured priority assignments
- Capacity planning

Exit codes:
    0 - No issues detected
    1 - Warnings or issues found
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def analyze_priority_classes(priority_classes: list, pods: list) -> dict:
    """Analyze PriorityClass configuration and usage."""
    pc_map = {}
    global_defaults = []

    for pc in priority_classes:
        name = pc["metadata"]["name"]
        value = pc.get("value", 0)
        global_default = pc.get("globalDefault", False)
        preemption_policy = pc.get("preemptionPolicy", "PreemptLowerPriority")
        description = pc.get("description", "")

        pc_map[name] = {
            "name": name,
            "value": value,
            "global_default": global_default,
            "preemption_policy": preemption_policy,
            "description": description,
            "pod_count": 0,
            "namespaces": set(),
        }

        if global_default:
            global_defaults.append(name)

    pods_without_priority = []
    pods_by_priority = defaultdict(list)

    for pod in pods:
        metadata = pod.get("metadata", {})
        spec = pod.get("spec", {})
        pod_name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")

        priority_class_name = spec.get("priorityClassName")
        priority = spec.get("priority")

        if priority_class_name:
            pods_by_priority[priority_class_name].append(
                {
                    "name": pod_name,
                    "namespace": namespace,
                    "priority": priority,
                }
            )
            if priority_class_name in pc_map:
                pc_map[priority_class_name]["pod_count"] += 1
                pc_map[priority_class_name]["namespaces"].add(namespace)
        else:
            pods_without_priority.append(
                {
                    "name": pod_name,
                    "namespace": namespace,
                    "priority": priority,
                }
            )

    for pc in pc_map.values():
        pc["namespaces"] = sorted(pc["namespaces"])

    sorted_pcs = sorted(pc_map.values(), key=lambda x: x["value"], reverse=True)

    return {
        "priority_classes": sorted_pcs,
        "pods_by_priority": dict(pods_by_priority),
        "pods_without_priority": pods_without_priority,
        "global_defaults": global_defaults,
        "total_pods": len(pods),
        "pods_with_priority": len(pods) - len(pods_without_priority),
    }


def check_issues(analysis: dict) -> list:
    """Check for issues and return list of warnings."""
    issues = []

    if len(analysis["global_defaults"]) > 1:
        issues.append(
            {
                "severity": "WARNING",
                "type": "multiple_global_defaults",
                "classes": analysis["global_defaults"],
                "message": f"Multiple PriorityClasses marked as globalDefault: "
                f"{', '.join(analysis['global_defaults'])}",
            }
        )

    pods_without = analysis["pods_without_priority"]
    if pods_without:
        ns_counts = defaultdict(int)
        for pod in pods_without:
            ns_counts[pod["namespace"]] += 1

        issues.append(
            {
                "severity": "INFO",
                "type": "pods_without_priority",
                "count": len(pods_without),
                "namespaces": dict(ns_counts),
                "message": f"{len(pods_without)} pods have no explicit PriorityClass assignment",
            }
        )

    for pc in analysis["priority_classes"]:
        if pc["pod_count"] == 0 and not pc["name"].startswith("system-"):
            issues.append(
                {
                    "severity": "INFO",
                    "type": "unused_priority_class",
                    "class": pc["name"],
                    "message": f"PriorityClass '{pc['name']}' is defined but not used by any pods",
                }
            )

    for pc in analysis["priority_classes"]:
        if pc["value"] >= 1000000000 and not pc["name"].startswith("system-"):
            issues.append(
                {
                    "severity": "WARNING",
                    "type": "very_high_priority",
                    "class": pc["name"],
                    "value": pc["value"],
                    "message": f"PriorityClass '{pc['name']}' has very high priority "
                    f"({pc['value']}), usually reserved for system components",
                }
            )

    for pc in analysis["priority_classes"]:
        if pc["value"] > 0 and pc["preemption_policy"] == "Never":
            issues.append(
                {
                    "severity": "INFO",
                    "type": "preempt_never_high_priority",
                    "class": pc["name"],
                    "message": f"PriorityClass '{pc['name']}' has preemptionPolicy=Never "
                    "despite positive priority",
                }
            )

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = warnings found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes PriorityClass configuration and usage"
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
        help="Show detailed information including pods without priority",
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only output if issues are detected"
    )
    opts = parser.parse_args(args)

    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get PriorityClasses
    try:
        result = context.run(["kubectl", "get", "priorityclasses", "-o", "json"])
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        priority_classes = json.loads(result.stdout).get("items", [])
    except Exception as e:
        output.error(f"Failed to get priorityclasses: {e}")
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

    # Analyze
    analysis = analyze_priority_classes(priority_classes, pods)
    issues = check_issues(analysis)

    data = {
        "analysis": analysis,
        "issues": issues,
        "namespace_filter": opts.namespace,
    }

    # Handle warn-only mode
    if opts.warn_only and not issues:
        return 0

    # Output results
    if opts.format == "json":
        print(json.dumps(data, indent=2, default=str))
    elif opts.format == "table":
        print("=" * 90)
        print(f"{'PriorityClass Analysis':^90}")
        print("=" * 90)
        print(
            f"Total Classes: {len(analysis['priority_classes'])}  |  "
            f"Total Pods: {analysis['total_pods']}  |  "
            f"With Priority: {analysis['pods_with_priority']}  |  "
            f"Without: {len(analysis['pods_without_priority'])}"
        )
        print("=" * 90)
        print()
        print(
            f"{'PriorityClass Name':<35} {'Value':>12} {'Pods':>8} "
            f"{'Preemption Policy':<22} {'Def'}"
        )
        print("-" * 90)

        for pc in analysis["priority_classes"]:
            default_marker = "Yes" if pc["global_default"] else ""
            print(
                f"{pc['name']:<35} {pc['value']:>12} {pc['pod_count']:>8} "
                f"{pc['preemption_policy']:<22} {default_marker}"
            )

        if issues:
            print()
            print("=" * 90)
            print("Issues Detected:")
            print("-" * 90)
            for issue in issues:
                print(f"[{issue['severity']}] {issue['message']}")

        print()
    else:  # plain
        print("PriorityClass Analysis")
        print("======================")
        print(f"Total PriorityClasses: {len(analysis['priority_classes'])}")
        print(f"Total Pods: {analysis['total_pods']}")
        print(f"Pods with explicit priority: {analysis['pods_with_priority']}")
        print(f"Pods without explicit priority: {len(analysis['pods_without_priority'])}")
        print()

        print("PriorityClasses (sorted by priority value):")
        print("-" * 80)
        print(
            f"{'Name':<35} {'Value':<12} {'Pods':<8} {'Preemption':<20} {'Default'}"
        )
        print("-" * 80)

        for pc in analysis["priority_classes"]:
            default_marker = "*" if pc["global_default"] else ""
            print(
                f"{pc['name']:<35} {pc['value']:<12} {pc['pod_count']:<8} "
                f"{pc['preemption_policy']:<20} {default_marker}"
            )

        if opts.verbose and analysis["pods_without_priority"]:
            print()
            print(
                f"Pods without explicit PriorityClass "
                f"({len(analysis['pods_without_priority'])}):"
            )
            print("-" * 60)
            for pod in analysis["pods_without_priority"][:20]:
                print(f"  {pod['namespace']}/{pod['name']}")
            if len(analysis["pods_without_priority"]) > 20:
                print(f"  ... and {len(analysis['pods_without_priority']) - 20} more")

        if issues:
            print()
            print("Issues:")
            print("-" * 60)
            for issue in issues:
                print(f"[{issue['severity']}] {issue['message']}")

    has_warnings = any(i["severity"] == "WARNING" for i in issues)
    output.set_summary(
        f"classes={len(analysis['priority_classes'])}, "
        f"warnings={sum(1 for i in issues if i['severity'] == 'WARNING')}"
    )

    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
