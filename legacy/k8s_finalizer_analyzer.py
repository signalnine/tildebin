#!/usr/bin/env python3
"""
Kubernetes finalizer analyzer - Find resources stuck due to finalizers.

Identifies resources in Terminating state that cannot be deleted because
finalizers are blocking deletion. Common in large-scale environments where
namespace deletions hang, or custom controllers fail to clean up properly.

Exit codes:
    0 - No stuck resources found
    1 - Stuck resources detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def run_kubectl(args, timeout=30):
    """Run kubectl command and return JSON output, or None on failure."""
    try:
        result = subprocess.run(
            ["kubectl"] + args + ["-o", "json"],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return None
        return None
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/",
              file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print("Error: kubectl command timed out", file=sys.stderr)
        return None


def get_terminating_namespaces():
    """Get namespaces stuck in Terminating state."""
    result = run_kubectl(["get", "namespaces"])
    if result is None:
        return []

    terminating = []
    for ns in result.get("items", []):
        metadata = ns.get("metadata", {})
        status = ns.get("status", {})
        phase = status.get("phase", "")

        if phase == "Terminating":
            deletion_timestamp = metadata.get("deletionTimestamp")
            finalizers = metadata.get("finalizers", [])

            terminating.append({
                "name": metadata.get("name"),
                "finalizers": finalizers,
                "deletion_timestamp": deletion_timestamp,
                "conditions": status.get("conditions", [])
            })

    return terminating


def get_resources_with_finalizers(namespace=None, resource_type="all"):
    """Get resources with finalizers that are in Terminating state."""
    # Resource types to check
    if resource_type == "all":
        resource_types = [
            "pods", "services", "deployments", "statefulsets", "daemonsets",
            "replicasets", "jobs", "cronjobs", "configmaps", "secrets",
            "persistentvolumeclaims", "serviceaccounts", "roles", "rolebindings",
            "networkpolicies", "ingresses", "customresourcedefinitions"
        ]
    else:
        resource_types = [resource_type]

    stuck_resources = []

    for res_type in resource_types:
        cmd = ["get", res_type]
        if namespace:
            cmd.extend(["-n", namespace])
        else:
            cmd.append("--all-namespaces")

        result = run_kubectl(cmd)
        if result is None:
            continue

        for item in result.get("items", []):
            metadata = item.get("metadata", {})
            deletion_timestamp = metadata.get("deletionTimestamp")
            finalizers = metadata.get("finalizers", [])

            # Resource is terminating if it has a deletionTimestamp
            if deletion_timestamp and finalizers:
                stuck_resources.append({
                    "kind": item.get("kind", res_type),
                    "name": metadata.get("name"),
                    "namespace": metadata.get("namespace", ""),
                    "finalizers": finalizers,
                    "deletion_timestamp": deletion_timestamp,
                    "age_since_deletion": calculate_age(deletion_timestamp)
                })

    return stuck_resources


def get_terminating_pvs():
    """Get PersistentVolumes stuck in Terminating state."""
    result = run_kubectl(["get", "pv"])
    if result is None:
        return []

    stuck = []
    for pv in result.get("items", []):
        metadata = pv.get("metadata", {})
        deletion_timestamp = metadata.get("deletionTimestamp")
        finalizers = metadata.get("finalizers", [])

        if deletion_timestamp and finalizers:
            stuck.append({
                "kind": "PersistentVolume",
                "name": metadata.get("name"),
                "namespace": "",
                "finalizers": finalizers,
                "deletion_timestamp": deletion_timestamp,
                "age_since_deletion": calculate_age(deletion_timestamp),
                "status": pv.get("status", {}).get("phase", "Unknown")
            })

    return stuck


def calculate_age(timestamp_str):
    """Calculate age from ISO timestamp string."""
    if not timestamp_str:
        return "Unknown"

    try:
        # Parse ISO format timestamp
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        deletion_time = datetime.fromisoformat(timestamp_str)
        now = datetime.now(timezone.utc)
        delta = now - deletion_time

        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)

        if days > 0:
            return f"{days}d{hours}h"
        elif hours > 0:
            return f"{hours}h{minutes}m"
        else:
            return f"{minutes}m"
    except (ValueError, TypeError):
        return "Unknown"


def output_plain(namespaces, resources, pvs, verbose=False):
    """Output results in plain text format."""
    lines = []
    has_issues = False

    if namespaces:
        has_issues = True
        lines.append("=== Terminating Namespaces ===")
        for ns in namespaces:
            lines.append(f"\nNamespace: {ns['name']}")
            lines.append(f"  Deletion requested: {ns['deletion_timestamp']}")
            lines.append(f"  Finalizers blocking deletion:")
            for f in ns['finalizers']:
                lines.append(f"    - {f}")

            if verbose and ns['conditions']:
                lines.append("  Conditions:")
                for cond in ns['conditions']:
                    lines.append(f"    - {cond.get('type')}: {cond.get('message', 'N/A')}")
        lines.append("")

    if resources:
        has_issues = True
        lines.append("=== Resources Stuck in Terminating State ===")

        # Group by namespace
        by_namespace = {}
        for res in resources:
            ns = res['namespace'] or "(cluster-scoped)"
            if ns not in by_namespace:
                by_namespace[ns] = []
            by_namespace[ns].append(res)

        for ns, items in sorted(by_namespace.items()):
            lines.append(f"\nNamespace: {ns}")
            for item in items:
                lines.append(f"  {item['kind']}/{item['name']} (stuck for {item['age_since_deletion']})")
                lines.append(f"    Finalizers:")
                for f in item['finalizers']:
                    lines.append(f"      - {f}")
        lines.append("")

    if pvs:
        has_issues = True
        lines.append("=== PersistentVolumes Stuck in Terminating State ===")
        for pv in pvs:
            lines.append(f"\n  {pv['name']} (stuck for {pv['age_since_deletion']})")
            lines.append(f"    Status: {pv.get('status', 'Unknown')}")
            lines.append(f"    Finalizers:")
            for f in pv['finalizers']:
                lines.append(f"      - {f}")
        lines.append("")

    if not has_issues:
        lines.append("No resources stuck due to finalizers.")

    return '\n'.join(lines)


def output_json(namespaces, resources, pvs):
    """Output results in JSON format."""
    result = {
        "terminating_namespaces": namespaces,
        "stuck_resources": resources,
        "stuck_persistent_volumes": pvs,
        "summary": {
            "total_terminating_namespaces": len(namespaces),
            "total_stuck_resources": len(resources),
            "total_stuck_pvs": len(pvs)
        }
    }
    return json.dumps(result, indent=2)


def output_table(namespaces, resources, pvs):
    """Output results in table format."""
    lines = []

    if namespaces or resources or pvs:
        lines.append(f"{'TYPE':<25} {'NAMESPACE':<20} {'NAME':<40} {'AGE':<10} {'FINALIZERS':<30}")
        lines.append("-" * 125)

        for ns in namespaces:
            finalizers_str = ', '.join(ns['finalizers'][:2])
            if len(ns['finalizers']) > 2:
                finalizers_str += f" (+{len(ns['finalizers'])-2} more)"
            age = calculate_age(ns['deletion_timestamp'])
            lines.append(f"{'Namespace':<25} {'-':<20} {ns['name']:<40} {age:<10} {finalizers_str:<30}")

        for res in resources:
            finalizers_str = ', '.join(res['finalizers'][:2])
            if len(res['finalizers']) > 2:
                finalizers_str += f" (+{len(res['finalizers'])-2} more)"
            ns = res['namespace'] or "-"
            lines.append(f"{res['kind']:<25} {ns:<20} {res['name']:<40} {res['age_since_deletion']:<10} {finalizers_str:<30}")

        for pv in pvs:
            finalizers_str = ', '.join(pv['finalizers'][:2])
            if len(pv['finalizers']) > 2:
                finalizers_str += f" (+{len(pv['finalizers'])-2} more)"
            lines.append(f"{'PersistentVolume':<25} {'-':<20} {pv['name']:<40} {pv['age_since_deletion']:<10} {finalizers_str:<30}")
    else:
        lines.append("No resources stuck due to finalizers.")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Find Kubernetes resources stuck due to finalizers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all namespaces for stuck resources
  %(prog)s

  # Check specific namespace
  %(prog)s -n my-namespace

  # Output as JSON for automation
  %(prog)s --format json

  # Show only terminating namespaces
  %(prog)s --namespaces-only

  # Check specific resource type
  %(prog)s --resource-type pods

  # Verbose output with conditions
  %(prog)s --verbose

Common finalizers and their causes:
  - kubernetes.io/pv-protection: PVC still bound to PV
  - kubernetes.io/pvc-protection: Pod still using PVC
  - foregroundDeletion: Waiting for dependents to delete
  - orphan: Controller waiting for orphan finalization
  - external-dns: external-dns controller not running
  - custom finalizers: Custom controllers not cleaning up

To force-remove a stuck namespace (use with caution):
  kubectl get namespace <ns> -o json | \\
    jq '.spec.finalizers = []' | \\
    kubectl replace --raw "/api/v1/namespaces/<ns>/finalize" -f -

Exit codes:
  0 - No stuck resources found
  1 - Stuck resources detected
  2 - Usage error or kubectl not available
        """
    )

    parser.add_argument(
        "-n", "--namespace",
        help="Check specific namespace only"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)"
    )
    parser.add_argument(
        "--namespaces-only",
        action="store_true",
        help="Only check for terminating namespaces"
    )
    parser.add_argument(
        "--resource-type",
        default="all",
        help="Specific resource type to check (default: all)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including conditions"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show resources stuck for more than 5 minutes"
    )

    args = parser.parse_args()

    # Gather data
    terminating_namespaces = []
    stuck_resources = []
    stuck_pvs = []

    # Always check namespaces unless checking specific namespace
    if not args.namespace:
        terminating_namespaces = get_terminating_namespaces()

    # Check resources unless namespaces-only
    if not args.namespaces_only:
        stuck_resources = get_resources_with_finalizers(
            namespace=args.namespace,
            resource_type=args.resource_type
        )

        # Check cluster-scoped PVs
        if not args.namespace:
            stuck_pvs = get_terminating_pvs()

    # Filter if warn-only (stuck for > 5 minutes)
    if args.warn_only:
        # Filter resources stuck for significant time
        def is_stuck_long(item):
            age = item.get('age_since_deletion', '')
            if 'd' in age or 'h' in age:
                return True
            if 'm' in age:
                try:
                    minutes = int(age.replace('m', ''))
                    return minutes >= 5
                except ValueError:
                    return True
            return True

        stuck_resources = [r for r in stuck_resources if is_stuck_long(r)]
        stuck_pvs = [p for p in stuck_pvs if is_stuck_long(p)]

    # Output results
    if args.format == "json":
        output = output_json(terminating_namespaces, stuck_resources, stuck_pvs)
    elif args.format == "table":
        output = output_table(terminating_namespaces, stuck_resources, stuck_pvs)
    else:
        output = output_plain(terminating_namespaces, stuck_resources, stuck_pvs,
                             verbose=args.verbose)

    print(output)

    # Exit code based on findings
    has_issues = terminating_namespaces or stuck_resources or stuck_pvs
    return 1 if has_issues else 0


if __name__ == "__main__":
    sys.exit(main())
