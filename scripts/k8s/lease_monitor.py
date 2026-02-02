#!/usr/bin/env python3
# boxctl:
#   category: k8s/cluster
#   tags: [lease, leader-election, kubernetes, health, monitoring]
#   requires: [kubectl]
#   brief: Monitor Kubernetes lease objects for leader election health
#   privilege: user
#   related: [operator_health, kubelet_health]

"""
Monitor Kubernetes Lease objects for leader election health.

Leases are the modern mechanism for leader election in Kubernetes. This script
monitors all leases across the cluster to detect:
- Stale leases (not renewed recently)
- Orphaned leases (holder no longer exists)
- Leader election contention or instability
- Missing expected leases for critical components

Useful for large-scale clusters where controller availability is
critical and HA issues can cause cascading failures.

Exit codes:
    0 - All leases healthy
    1 - Stale or problematic leases detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime, timezone
from typing import Any

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


def categorize_lease(name: str, namespace: str) -> str:
    """Categorize lease by its purpose."""
    name_lower = name.lower()

    # Control plane components
    if name in ("kube-controller-manager", "kube-scheduler"):
        return "control-plane"
    if "controller" in name_lower:
        return "controller"

    # Node heartbeat leases
    if namespace == "kube-node-lease":
        return "node-heartbeat"

    # Operator leases
    if "operator" in name_lower:
        return "operator"

    # Ingress controllers
    if "ingress" in name_lower or "nginx" in name_lower or "traefik" in name_lower:
        return "ingress"

    # Storage controllers
    if "csi" in name_lower or "storage" in name_lower:
        return "storage"

    # Service mesh
    if any(x in name_lower for x in ["istio", "linkerd", "consul", "envoy"]):
        return "service-mesh"

    # Monitoring
    if any(x in name_lower for x in ["prometheus", "grafana", "metrics"]):
        return "monitoring"

    return "other"


def format_duration(seconds: int | None) -> str:
    """Format seconds into human-readable duration."""
    if seconds is None:
        return "N/A"

    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m{seconds % 60}s"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h{minutes}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d{hours}h"


def analyze_lease(lease: dict[str, Any], stale_threshold: int) -> dict[str, Any]:
    """Analyze a single lease for issues."""
    metadata = lease.get("metadata", {})
    spec = lease.get("spec", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    # Lease spec fields
    holder_identity = spec.get("holderIdentity", "")
    lease_duration = spec.get("leaseDurationSeconds", 15)
    acquire_time = parse_timestamp(spec.get("acquireTime"))
    renew_time = parse_timestamp(spec.get("renewTime"))
    lease_transitions = spec.get("leaseTransitions", 0)

    # Calculate staleness
    now = datetime.now(timezone.utc)
    seconds_since_renew = None
    if renew_time:
        seconds_since_renew = (now - renew_time).total_seconds()

    seconds_since_acquire = None
    if acquire_time:
        seconds_since_acquire = (now - acquire_time).total_seconds()

    # Determine issues
    issues = []
    has_issue = False

    # Check if lease is stale (not renewed within threshold)
    if seconds_since_renew is not None:
        if seconds_since_renew > stale_threshold:
            issues.append(f"Stale: not renewed for {int(seconds_since_renew)}s")
            has_issue = True
        elif seconds_since_renew > lease_duration * 3:
            # Warning: more than 3x lease duration without renewal
            issues.append(f"Warning: {int(seconds_since_renew)}s since last renewal")
            has_issue = True

    # Check for missing holder
    if not holder_identity:
        issues.append("No holder identity set")
        has_issue = True

    # Check for high transition count (leadership instability)
    if lease_transitions > 10:
        issues.append(f"High leadership transitions: {lease_transitions}")
        has_issue = True

    # Categorize lease type
    lease_type = categorize_lease(name, namespace)

    return {
        "name": name,
        "namespace": namespace,
        "holder_identity": holder_identity,
        "lease_duration_seconds": lease_duration,
        "lease_transitions": lease_transitions,
        "acquire_time": acquire_time.isoformat() if acquire_time else None,
        "renew_time": renew_time.isoformat() if renew_time else None,
        "seconds_since_renew": int(seconds_since_renew) if seconds_since_renew else None,
        "seconds_since_acquire": int(seconds_since_acquire) if seconds_since_acquire else None,
        "lease_type": lease_type,
        "has_issue": has_issue,
        "issues": issues,
    }


def output_plain(leases_data: list[dict], warn_only: bool, verbose: bool) -> str:
    """Plain text output."""
    lines = []

    # Group by type
    by_type: dict[str, list[dict]] = {}
    for lease in leases_data:
        if warn_only and not lease["has_issue"]:
            continue
        lease_type = lease["lease_type"]
        if lease_type not in by_type:
            by_type[lease_type] = []
        by_type[lease_type].append(lease)

    if not by_type:
        lines.append("All leases healthy." if not warn_only else "No lease issues detected.")
        return "\n".join(lines)

    type_order = [
        "control-plane",
        "node-heartbeat",
        "controller",
        "operator",
        "ingress",
        "storage",
        "service-mesh",
        "monitoring",
        "other",
    ]

    for lease_type in type_order:
        if lease_type not in by_type:
            continue

        leases = by_type[lease_type]
        lines.append(f"\n=== {lease_type.replace('-', ' ').title()} Leases ===")

        for lease in leases:
            status = "[ISSUE]" if lease["has_issue"] else "[OK]"
            lines.append(f"\n{status} {lease['namespace']}/{lease['name']}")
            lines.append(f"  Holder: {lease['holder_identity'] or '(none)'}")
            lines.append(f"  Last renewed: {format_duration(lease['seconds_since_renew'])} ago")
            lines.append(f"  Transitions: {lease['lease_transitions']}")

            if verbose:
                lines.append(f"  Lease duration: {lease['lease_duration_seconds']}s")
                if lease["acquire_time"]:
                    lines.append(f"  Acquired: {format_duration(lease['seconds_since_acquire'])} ago")

            if lease["issues"]:
                for issue in lease["issues"]:
                    lines.append(f"  * {issue}")

    return "\n".join(lines)


def output_json(leases_data: list[dict], warn_only: bool) -> str:
    """JSON output."""
    if warn_only:
        leases_data = [lease for lease in leases_data if lease["has_issue"]]

    # Summary statistics
    total = len(leases_data)
    with_issues = sum(1 for lease in leases_data if lease["has_issue"])

    by_type: dict[str, int] = {}
    for lease in leases_data:
        lease_type = lease["lease_type"]
        by_type[lease_type] = by_type.get(lease_type, 0) + 1

    output = {
        "leases": leases_data,
        "summary": {
            "total_leases": total,
            "leases_with_issues": with_issues,
            "by_type": by_type,
        },
    }
    return json.dumps(output, indent=2)


def output_table(leases_data: list[dict], warn_only: bool) -> str:
    """Tabular output."""
    lines = []

    if warn_only:
        leases_data = [lease for lease in leases_data if lease["has_issue"]]

    lines.append(
        f"{'NAMESPACE':<20} {'NAME':<35} {'TYPE':<15} {'HOLDER':<25} "
        f"{'RENEWED':<10} {'TRANS':<6} {'STATUS'}"
    )
    lines.append("-" * 130)

    for lease in sorted(leases_data, key=lambda x: (x["namespace"], x["name"])):
        ns = lease["namespace"][:19]
        name = lease["name"][:34]
        lease_type = lease["lease_type"][:14]
        holder = (lease["holder_identity"] or "(none)")[:24]
        renewed = format_duration(lease["seconds_since_renew"])
        trans = str(lease["lease_transitions"])
        status = "ISSUE" if lease["has_issue"] else "OK"

        lines.append(
            f"{ns:<20} {name:<35} {lease_type:<15} {holder:<25} "
            f"{renewed:<10} {trans:<6} {status}"
        )

    # Summary
    total = len(leases_data)
    with_issues = sum(1 for lease in leases_data if lease["has_issue"])
    lines.append(f"\nTotal: {total} leases, {with_issues} with issues")

    return "\n".join(lines)


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
        description="Monitor Kubernetes Lease objects for leader election health"
    )

    parser.add_argument(
        "-n",
        "--namespace",
        help="Namespace to check (default: all namespaces)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show leases with issues",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed lease information",
    )

    parser.add_argument(
        "--stale-threshold",
        type=int,
        default=60,
        help="Seconds without renewal before lease is considered stale (default: 60)",
    )

    parser.add_argument(
        "--skip-node-leases",
        action="store_true",
        help="Skip node heartbeat leases in kube-node-lease namespace",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Build command to get leases
    cmd = ["kubectl", "get", "leases", "-o", "json"]
    if opts.namespace:
        cmd.extend(["-n", opts.namespace])
    else:
        cmd.append("--all-namespaces")

    # Get leases
    try:
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        data = json.loads(result.stdout)
        leases = data.get("items", [])
    except Exception as e:
        output.error(f"Failed to get leases: {e}")
        return 2

    if not leases:
        print("No leases found.")
        output.set_summary("leases=0")
        return 0

    # Optionally skip node leases
    if opts.skip_node_leases:
        leases = [
            lease
            for lease in leases
            if lease.get("metadata", {}).get("namespace") != "kube-node-lease"
        ]

    # Analyze leases
    leases_data = [analyze_lease(lease, opts.stale_threshold) for lease in leases]

    # Output results
    if opts.format == "json":
        print(output_json(leases_data, opts.warn_only))
    elif opts.format == "table":
        print(output_table(leases_data, opts.warn_only))
    else:
        print(output_plain(leases_data, opts.warn_only, opts.verbose))

    # Determine exit code
    has_issues = any(lease["has_issue"] for lease in leases_data)
    issues_count = sum(1 for lease in leases_data if lease["has_issue"])
    output.set_summary(f"leases={len(leases_data)}, issues={issues_count}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
