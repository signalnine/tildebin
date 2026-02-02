#!/usr/bin/env python3
# boxctl:
#   category: k8s/workloads
#   tags: [revision, kubernetes, deployments, replicasets, cleanup]
#   requires: [kubectl]
#   brief: Analyze deployment revision history for cleanup opportunities
#   privilege: user
#   related: [replicaset_health, deployment_status]

"""
Kubernetes revision history analyzer - Identify excessive ReplicaSet revisions.

Deployments accumulate old ReplicaSets over time which can cause:
- etcd storage bloat (each revision stores full pod spec)
- Slower API server responses (more objects to list/watch)
- Larger cluster backups
- Slower kubectl commands

Identifies:
- Deployments with excessive revision history
- Total ReplicaSets that could be cleaned up
- Estimated etcd storage impact
- Per-namespace revision statistics

Exit codes:
    0 - No issues detected, revision counts within thresholds
    1 - Issues found (excessive revisions detected)
    2 - Usage error or kubectl not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def estimate_etcd_impact(cleanable_count: int) -> str:
    """Estimate etcd storage impact of cleanable ReplicaSets."""
    avg_rs_size_kb = 3
    total_kb = cleanable_count * avg_rs_size_kb
    if total_kb > 1024:
        return f"{total_kb / 1024:.1f} MB"
    return f"{total_kb} KB"


def analyze_deployment_revisions(
    namespace: str, deployments: list, replicasets: list, threshold: int
) -> tuple:
    """Analyze revision history for deployments in a namespace."""
    issues = []
    stats = {
        "total_deployments": len(deployments),
        "total_replicasets": len(replicasets),
        "excessive_revisions": 0,
        "cleanable_replicasets": 0,
        "deployments": [],
    }

    # Build mapping of deployment -> replicasets
    deployment_rs_map = {}
    for rs in replicasets:
        owner_refs = rs.get("metadata", {}).get("ownerReferences", [])
        for owner in owner_refs:
            if owner.get("kind") == "Deployment":
                deploy_name = owner.get("name")
                if deploy_name not in deployment_rs_map:
                    deployment_rs_map[deploy_name] = []
                deployment_rs_map[deploy_name].append(rs)

    for deploy in deployments:
        deploy_name = deploy["metadata"]["name"]
        revision_limit = deploy.get("spec", {}).get("revisionHistoryLimit", 10)
        associated_rs = deployment_rs_map.get(deploy_name, [])
        rs_count = len(associated_rs)

        old_rs_count = sum(
            1
            for rs in associated_rs
            if rs.get("spec", {}).get("replicas", 0) == 0
        )

        deploy_info = {
            "name": deploy_name,
            "replicaset_count": rs_count,
            "old_replicasets": old_rs_count,
            "revision_history_limit": revision_limit,
            "has_issue": rs_count > threshold,
        }

        if rs_count > threshold:
            stats["excessive_revisions"] += 1
            cleanable = rs_count - min(revision_limit, threshold)
            if cleanable > 0:
                stats["cleanable_replicasets"] += cleanable
                deploy_info["cleanable"] = cleanable

            issues.append(
                {
                    "deployment": deploy_name,
                    "replicaset_count": rs_count,
                    "old_replicasets": old_rs_count,
                    "threshold": threshold,
                    "revision_history_limit": revision_limit,
                    "severity": "warning" if rs_count > threshold * 2 else "info",
                }
            )

        stats["deployments"].append(deploy_info)

    return stats, issues


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
        description="Analyze Kubernetes Deployment revision history for cleanup opportunities"
    )
    parser.add_argument(
        "-n", "--namespace", help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "table", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show namespaces with issues"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed per-deployment information",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="ReplicaSet count threshold to flag as excessive (default: 10)",
    )
    opts = parser.parse_args(args)

    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get namespaces
    if opts.namespace:
        namespaces = [opts.namespace]
    else:
        try:
            result = context.run(["kubectl", "get", "namespaces", "-o", "json"])
            if result.returncode != 0:
                output.error(f"kubectl failed: {result.stderr}")
                return 2
            ns_data = json.loads(result.stdout)
            namespaces = [ns["metadata"]["name"] for ns in ns_data.get("items", [])]
        except Exception as e:
            output.error(f"Failed to get namespaces: {e}")
            return 2

    if not namespaces:
        output.error("No namespaces found or kubectl failed")
        return 2

    results = []
    for ns in namespaces:
        # Skip system namespaces unless explicitly requested
        if not opts.namespace and ns in ["kube-system", "kube-public", "kube-node-lease"]:
            continue

        try:
            # Get deployments
            result = context.run(
                ["kubectl", "get", "deployments", "-n", ns, "-o", "json"]
            )
            if result.returncode != 0:
                continue
            deployments = json.loads(result.stdout).get("items", [])

            # Get replicasets
            result = context.run(
                ["kubectl", "get", "replicasets", "-n", ns, "-o", "json"]
            )
            if result.returncode != 0:
                continue
            replicasets = json.loads(result.stdout).get("items", [])

            stats, issues = analyze_deployment_revisions(
                ns, deployments, replicasets, opts.threshold
            )

            results.append({"namespace": ns, "stats": stats, "issues": issues})
        except Exception:
            continue

    # Output results
    if opts.format == "json":
        summary = {
            "total_deployments": sum(r["stats"]["total_deployments"] for r in results),
            "total_replicasets": sum(r["stats"]["total_replicasets"] for r in results),
            "excessive_revision_count": sum(
                r["stats"]["excessive_revisions"] for r in results
            ),
            "cleanable_replicasets": sum(
                r["stats"]["cleanable_replicasets"] for r in results
            ),
        }
        summary["estimated_etcd_savings"] = estimate_etcd_impact(
            summary["cleanable_replicasets"]
        )

        output_data = {"summary": summary, "namespaces": results}
        print(json.dumps(output_data, indent=2))
    elif opts.format == "table":
        print(
            f"{'Namespace':<25} {'Deploys':<8} {'RS Total':<10} "
            f"{'Excessive':<10} {'Cleanable':<10}"
        )
        print("-" * 75)

        for ns_result in results:
            ns = ns_result["namespace"]
            stats = ns_result["stats"]
            issues = ns_result["issues"]

            if opts.warn_only and not issues:
                continue

            print(
                f"{ns:<25} {stats['total_deployments']:<8} "
                f"{stats['total_replicasets']:<10} "
                f"{stats['excessive_revisions']:<10} "
                f"{stats['cleanable_replicasets']:<10}"
            )
    else:  # plain
        print("Kubernetes Revision History Analysis")
        print("=" * 70)

        total_deployments = 0
        total_replicasets = 0
        total_issues = 0
        total_cleanable = 0

        for ns_result in results:
            ns = ns_result["namespace"]
            stats = ns_result["stats"]
            issues = ns_result["issues"]

            total_deployments += stats["total_deployments"]
            total_replicasets += stats["total_replicasets"]
            total_issues += len(issues)
            total_cleanable += stats["cleanable_replicasets"]

            if opts.warn_only and not issues:
                continue

            print(f"\nNamespace: {ns}")
            print(f"  Deployments: {stats['total_deployments']}")
            print(f"  ReplicaSets: {stats['total_replicasets']}")

            if issues:
                print(f"  Excessive Revisions: {stats['excessive_revisions']}")
                print(f"  Cleanable ReplicaSets: {stats['cleanable_replicasets']}")
                print("  Issues:")
                for issue in issues:
                    severity = "!" if issue["severity"] == "warning" else "-"
                    print(
                        f"    [{severity}] {issue['deployment']}: "
                        f"{issue['replicaset_count']} ReplicaSets "
                        f"(limit: {issue['revision_history_limit']}, "
                        f"threshold: {issue['threshold']})"
                    )

            if opts.verbose and stats["deployments"]:
                print("  Deployment Details:")
                for dep in sorted(
                    stats["deployments"],
                    key=lambda x: x["replicaset_count"],
                    reverse=True,
                ):
                    marker = "*" if dep["has_issue"] else " "
                    print(
                        f"    {marker} {dep['name']}: "
                        f"{dep['replicaset_count']} RS "
                        f"({dep['old_replicasets']} old)"
                    )

        print("\n" + "=" * 70)
        print("Summary:")
        print(f"  Total Deployments: {total_deployments}")
        print(f"  Total ReplicaSets: {total_replicasets}")
        print(f"  Deployments with excessive history: {total_issues}")
        print(f"  Cleanable ReplicaSets: {total_cleanable}")
        if total_cleanable > 0:
            print(f"  Estimated etcd savings: ~{estimate_etcd_impact(total_cleanable)}")
            print("\nRecommendation: Consider reducing revisionHistoryLimit in deployments")
            print("or running: kubectl rollout history deployment/<name> -n <namespace>")

    has_issues = any(r["issues"] for r in results)
    output.set_summary(
        f"namespaces={len(results)}, "
        f"issues={sum(len(r['issues']) for r in results)}, "
        f"cleanable={sum(r['stats']['cleanable_replicasets'] for r in results)}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
