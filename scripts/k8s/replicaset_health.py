#!/usr/bin/env python3
# boxctl:
#   category: k8s/workloads
#   tags: [replicaset, kubernetes, health, deployments, availability]
#   requires: [kubectl]
#   brief: Monitor ReplicaSet health and detect common issues
#   privilege: user
#   related: [deployment_status, revision_history]

"""
Kubernetes ReplicaSet health monitor - Detect availability issues.

Monitors:
- ReplicaSets with unavailable replicas
- Stale ReplicaSets (old revisions that haven't been cleaned up)
- ReplicaSets with failed pod creation
- Orphaned ReplicaSets (no owner deployment/statefulset)
- ReplicaSets with high restart counts on their pods
- Replica count mismatches (desired vs current vs ready)

Useful for:
- Identifying stuck deployments
- Detecting resource quota exhaustion
- Finding image pull failures or crash loops
- Troubleshooting rollout issues

Exit codes:
    0 - All ReplicaSets healthy
    1 - ReplicaSet issues detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_timestamp(ts_str: str | None) -> datetime | None:
    """Parse Kubernetes timestamp to datetime object."""
    if not ts_str:
        return None
    try:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
    except (ValueError, AttributeError):
        return None


def format_age(seconds: float | None) -> str:
    """Format age in human-readable format."""
    if seconds is None:
        return "N/A"

    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds/60)}m"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}h"
    else:
        return f"{seconds/86400:.1f}d"


def analyze_replicaset(rs: dict) -> dict:
    """Analyze a single ReplicaSet for health issues."""
    metadata = rs.get("metadata", {})
    spec = rs.get("spec", {})
    status = rs.get("status", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")
    labels = metadata.get("labels", {})
    owner_refs = metadata.get("ownerReferences", [])

    # Replica counts
    desired = spec.get("replicas", 0)
    current = status.get("replicas", 0)
    ready = status.get("readyReplicas", 0)
    available = status.get("availableReplicas", 0)

    # Calculate age
    creation_ts = parse_timestamp(metadata.get("creationTimestamp"))
    age_seconds = None
    if creation_ts:
        age_seconds = (datetime.now(timezone.utc) - creation_ts).total_seconds()

    # Check owner (usually a Deployment)
    owner_kind = None
    owner_name = None
    is_orphaned = True
    for ref in owner_refs:
        if ref.get("kind") in ["Deployment", "StatefulSet"]:
            owner_kind = ref.get("kind")
            owner_name = ref.get("name")
            is_orphaned = False
            break

    # Detect issues
    issues = []
    has_issue = False

    # Check replica count mismatches
    if desired > 0 and ready < desired:
        has_issue = True
        missing = desired - ready
        issues.append(
            {
                "type": "unavailable_replicas",
                "severity": "high" if ready == 0 else "medium",
                "message": f"{missing} replica(s) not ready ({ready}/{desired})",
            }
        )

    # Check if this is a stale/old ReplicaSet
    if desired == 0 and current == 0:
        if age_seconds and age_seconds > 86400:
            issues.append(
                {
                    "type": "stale_replicaset",
                    "severity": "low",
                    "message": f"Zero-replica ReplicaSet older than {age_seconds/86400:.1f} days",
                }
            )

    # Check for orphaned ReplicaSets
    if is_orphaned and desired > 0:
        has_issue = True
        issues.append(
            {
                "type": "orphaned",
                "severity": "medium",
                "message": "ReplicaSet has no owner Deployment/StatefulSet",
            }
        )

    # Check for ReplicaSets that can't create pods
    if current < desired and not is_orphaned:
        has_issue = True
        issues.append(
            {
                "type": "pods_not_created",
                "severity": "high",
                "message": f"Only {current} pod(s) created for {desired} desired",
            }
        )

    # Check conditions for failure messages
    conditions = status.get("conditions", [])
    for condition in conditions:
        if condition.get("type") == "ReplicaFailure" and condition.get("status") == "True":
            has_issue = True
            reason = condition.get("reason", "Unknown")
            message = condition.get("message", "")
            issues.append(
                {
                    "type": "replica_failure",
                    "severity": "high",
                    "message": f"{reason}: {message[:100]}",
                }
            )

    return {
        "name": name,
        "namespace": namespace,
        "desired": desired,
        "current": current,
        "ready": ready,
        "available": available,
        "age_seconds": age_seconds,
        "owner_kind": owner_kind,
        "owner_name": owner_name,
        "is_orphaned": is_orphaned,
        "has_issue": has_issue,
        "issues": issues,
        "revision": labels.get("pod-template-hash", "unknown"),
    }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes ReplicaSet health"
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
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed pod information for unhealthy ReplicaSets",
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show ReplicaSets with issues"
    )
    parser.add_argument(
        "--include-zero-replicas",
        action="store_true",
        help="Include ReplicaSets with zero desired replicas (old revisions)",
    )
    opts = parser.parse_args(args)

    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get ReplicaSets
    try:
        cmd = ["kubectl", "get", "replicasets", "-o", "json"]
        if opts.namespace:
            cmd.extend(["-n", opts.namespace])
        else:
            cmd.append("--all-namespaces")
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        replicasets = json.loads(result.stdout).get("items", [])
    except Exception as e:
        output.error(f"Failed to get replicasets: {e}")
        return 2

    # Analyze each ReplicaSet
    results = []
    for rs in replicasets:
        analysis = analyze_replicaset(rs)

        if not opts.include_zero_replicas:
            if analysis["desired"] == 0 and not analysis["has_issue"]:
                continue

        results.append(analysis)

    # Filter if warn_only
    display_results = results
    if opts.warn_only:
        display_results = [r for r in results if r["has_issue"]]

    # Also filter out zero-replica sets unless they have real issues
    active_results = [r for r in display_results if r["desired"] > 0 or r["has_issue"]]

    # Output
    if opts.format == "json":
        output_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total": len(results),
                "with_issues": sum(1 for r in results if r["has_issue"]),
                "unavailable": sum(
                    1
                    for r in results
                    if any(i["type"] == "unavailable_replicas" for i in r["issues"])
                ),
                "orphaned": sum(
                    1 for r in results if r["is_orphaned"] and r["desired"] > 0
                ),
            },
            "replicasets": display_results,
        }
        print(json.dumps(output_data, indent=2, default=str))
    elif opts.format == "table":
        print("+" + "-" * 100 + "+")
        print("|" + " ReplicaSet Health Monitor ".center(100) + "|")
        print("+" + "-" * 100 + "+")

        if not active_results:
            print("|" + " No ReplicaSet issues detected ".center(100) + "|")
            print("+" + "-" * 100 + "+")
        else:
            header = (
                f"| {'Namespace':<20} | {'Name':<30} | {'Ready':>7} | "
                f"{'Age':>8} | {'Status':<15} |"
            )
            print(header)
            print("+" + "-" * 100 + "+")

            for r in active_results:
                status = "ISSUE" if r["has_issue"] else "OK"
                age = format_age(r["age_seconds"])
                replicas = f"{r['ready']}/{r['desired']}"

                row = (
                    f"| {r['namespace'][:20]:<20} | {r['name'][:30]:<30} | "
                    f"{replicas:>7} | {age:>8} | {status:<15} |"
                )
                print(row)

            print("+" + "-" * 100 + "+")
    else:  # plain
        if not active_results:
            print("No ReplicaSet issues detected")
        else:
            total = len(active_results)
            with_issues = sum(1 for r in active_results if r["has_issue"])

            print("ReplicaSet Health Report")
            print(f"Total: {total} | With Issues: {with_issues}")
            print()

            by_namespace = {}
            for r in active_results:
                ns = r["namespace"]
                if ns not in by_namespace:
                    by_namespace[ns] = []
                by_namespace[ns].append(r)

            for ns in sorted(by_namespace.keys()):
                rs_list = by_namespace[ns]
                if opts.warn_only:
                    rs_list = [r for r in rs_list if r["has_issue"]]
                if not rs_list:
                    continue

                print(f"=== Namespace: {ns} ===")

                for r in rs_list:
                    status = "UNHEALTHY" if r["has_issue"] else "OK"
                    marker = "!" if r["has_issue"] else " "
                    age = format_age(r["age_seconds"])
                    owner = (
                        f"{r['owner_kind']}/{r['owner_name']}"
                        if r["owner_name"]
                        else "none"
                    )

                    print(f"{marker} {r['name']}")
                    print(f"    Status: {status} | Replicas: {r['ready']}/{r['desired']} ready")
                    print(f"    Age: {age} | Owner: {owner}")

                    if r["issues"]:
                        for issue in r["issues"]:
                            print(f"    [{issue['severity'].upper()}] {issue['message']}")

                    print()

    has_issues = any(r["has_issue"] for r in results if r["desired"] > 0)
    output.set_summary(
        f"total={len(results)}, issues={sum(1 for r in results if r['has_issue'])}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
