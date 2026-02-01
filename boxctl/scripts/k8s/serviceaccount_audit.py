#!/usr/bin/env python3
# boxctl:
#   category: k8s/security
#   tags: [security, serviceaccount, rbac, audit]
#   requires: [kubectl]
#   privilege: none
#   related: [network_policy_audit]
#   brief: Audit Kubernetes ServiceAccounts for security issues

"""
Audit Kubernetes ServiceAccounts for security misconfigurations.

Checks:
- automountServiceAccountToken enabled (should be explicitly disabled when not needed)
- Default ServiceAccount usage by pods (security anti-pattern)
- ServiceAccounts with no associated pods (potentially stale)
- ServiceAccounts bound to high-privilege roles (cluster-admin, admin)

Returns exit code 1 if security issues found.
"""

import argparse
import json
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_serviceaccounts(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all ServiceAccounts."""
    cmd = ["kubectl", "get", "serviceaccounts", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def get_pods(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all Pods."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def get_cluster_role_bindings(context: Context) -> list[dict]:
    """Get all ClusterRoleBindings."""
    result = context.run(
        ["kubectl", "get", "clusterrolebindings", "-o", "json"],
        check=False
    )
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def get_role_bindings(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all RoleBindings."""
    cmd = ["kubectl", "get", "rolebindings", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd, check=False)
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def build_sa_role_map(
    cluster_bindings: list[dict],
    role_bindings: list[dict]
) -> dict[str, list[dict]]:
    """Build a map of ServiceAccount -> roles they're bound to."""
    sa_roles: dict[str, list[dict]] = defaultdict(list)

    for binding in cluster_bindings:
        role_name = binding.get("roleRef", {}).get("name", "unknown")
        subjects = binding.get("subjects", [])

        for subject in subjects:
            if subject.get("kind") == "ServiceAccount":
                sa_namespace = subject.get("namespace", "default")
                sa_name = subject.get("name", "unknown")
                sa_key = f"{sa_namespace}/{sa_name}"
                sa_roles[sa_key].append({
                    "role": role_name,
                    "binding_type": "ClusterRoleBinding",
                    "binding_name": binding["metadata"]["name"]
                })

    for binding in role_bindings:
        role_name = binding.get("roleRef", {}).get("name", "unknown")
        binding_namespace = binding["metadata"].get("namespace", "default")
        subjects = binding.get("subjects", [])

        for subject in subjects:
            if subject.get("kind") == "ServiceAccount":
                sa_namespace = subject.get("namespace", binding_namespace)
                sa_name = subject.get("name", "unknown")
                sa_key = f"{sa_namespace}/{sa_name}"
                sa_roles[sa_key].append({
                    "role": role_name,
                    "binding_type": "RoleBinding",
                    "binding_name": binding["metadata"]["name"]
                })

    return sa_roles


def build_sa_usage_map(pods: list[dict]) -> dict[str, list[dict]]:
    """Build a map of ServiceAccount -> pods using it."""
    sa_pods: dict[str, list[dict]] = defaultdict(list)

    for pod in pods:
        namespace = pod["metadata"].get("namespace", "default")
        pod_name = pod["metadata"].get("name", "unknown")
        sa_name = pod["spec"].get("serviceAccountName", "default")
        sa_key = f"{namespace}/{sa_name}"

        sa_pods[sa_key].append({
            "pod": pod_name,
            "namespace": namespace,
            "automount": pod["spec"].get("automountServiceAccountToken")
        })

    return sa_pods


def check_issues(
    serviceaccounts: list[dict],
    sa_roles: dict[str, list[dict]],
    sa_usage: dict[str, list[dict]],
    skip_unused: bool = False
) -> list[dict]:
    """Check for security issues across all ServiceAccounts."""
    all_issues = []

    for sa in serviceaccounts:
        sa_name = sa["metadata"]["name"]
        sa_namespace = sa["metadata"].get("namespace", "default")
        sa_key = f"{sa_namespace}/{sa_name}"
        pods_using_sa = sa_usage.get(sa_key, [])

        # Check automount issues
        sa_automount = sa.get("automountServiceAccountToken", True)
        if sa_automount is True or sa_automount is None:
            pods_with_automount = [
                p for p in pods_using_sa
                if p.get("automount") is not False
            ]
            if pods_with_automount:
                all_issues.append({
                    "severity": "MEDIUM",
                    "type": "automount_enabled",
                    "serviceaccount": sa_name,
                    "namespace": sa_namespace,
                    "detail": (
                        f"automountServiceAccountToken enabled, "
                        f"{len(pods_with_automount)} pod(s) may have unnecessary token access"
                    )
                })

        # Check default SA usage
        if sa_name == "default" and pods_using_sa:
            non_system_pods = [
                p for p in pods_using_sa
                if not p["pod"].startswith("kube-")
            ]
            if non_system_pods:
                all_issues.append({
                    "severity": "LOW",
                    "type": "default_sa_usage",
                    "serviceaccount": sa_name,
                    "namespace": sa_namespace,
                    "detail": (
                        f"{len(non_system_pods)} non-system pod(s) using "
                        f"default ServiceAccount"
                    )
                })

        # Check privileged bindings
        roles = sa_roles.get(sa_key, [])
        for role_info in roles:
            role_name = role_info["role"].lower()
            if role_name == "cluster-admin":
                all_issues.append({
                    "severity": "HIGH",
                    "type": "cluster_admin_binding",
                    "serviceaccount": sa_name,
                    "namespace": sa_namespace,
                    "detail": (
                        f"Bound to cluster-admin via {role_info['binding_type']}: "
                        f"{role_info['binding_name']}"
                    )
                })
            elif "admin" in role_name:
                all_issues.append({
                    "severity": "MEDIUM",
                    "type": "admin_role_binding",
                    "serviceaccount": sa_name,
                    "namespace": sa_namespace,
                    "detail": (
                        f"Bound to admin role '{role_info['role']}' via "
                        f"{role_info['binding_type']}"
                    )
                })

        # Check unused serviceaccounts
        if not skip_unused:
            if sa_name not in ("default", "builder", "deployer"):
                if sa_namespace != "kube-system":
                    if not pods_using_sa:
                        all_issues.append({
                            "severity": "LOW",
                            "type": "unused_serviceaccount",
                            "serviceaccount": sa_name,
                            "namespace": sa_namespace,
                            "detail": "ServiceAccount has no pods using it (may be stale)"
                        })

    return all_issues


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
        description="Audit Kubernetes ServiceAccounts for security issues"
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to audit (default: all namespaces)"
    )
    parser.add_argument(
        "--skip-unused",
        action="store_true",
        help="Skip checking for unused ServiceAccounts"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl and configure cluster access.")
        return 2

    # Gather data
    serviceaccounts = get_serviceaccounts(context, opts.namespace)
    pods = get_pods(context, opts.namespace)
    cluster_bindings = get_cluster_role_bindings(context)
    role_bindings = get_role_bindings(context, opts.namespace)

    # Build lookup maps
    sa_roles = build_sa_role_map(cluster_bindings, role_bindings)
    sa_usage = build_sa_usage_map(pods)

    # Run checks
    all_issues = check_issues(serviceaccounts, sa_roles, sa_usage, opts.skip_unused)

    # Group issues by severity
    high_issues = [i for i in all_issues if i["severity"] == "HIGH"]
    medium_issues = [i for i in all_issues if i["severity"] == "MEDIUM"]
    low_issues = [i for i in all_issues if i["severity"] == "LOW"]

    result_data: dict[str, Any] = {
        "summary": {
            "total_issues": len(all_issues),
            "high_severity": len(high_issues),
            "medium_severity": len(medium_issues),
            "low_severity": len(low_issues),
            "serviceaccounts_checked": len(serviceaccounts)
        },
        "issues": all_issues
    }

    output.emit(result_data)

    # Record issues
    for issue in all_issues:
        if issue["severity"] == "HIGH":
            output.error(f"[{issue['severity']}] {issue['namespace']}/{issue['serviceaccount']}: {issue['detail']}")
        else:
            output.warning(f"[{issue['severity']}] {issue['namespace']}/{issue['serviceaccount']}: {issue['detail']}")

    if all_issues:
        output.set_summary(
            f"ServiceAccount issues: {len(high_issues)} high, "
            f"{len(medium_issues)} medium, {len(low_issues)} low"
        )
    else:
        output.set_summary(
            f"ServiceAccounts OK: {len(serviceaccounts)} checked, no issues"
        )

    return 1 if all_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
