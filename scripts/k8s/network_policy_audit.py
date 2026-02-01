#!/usr/bin/env python3
# boxctl:
#   category: k8s/security
#   tags: [security, network, policy, audit]
#   requires: [kubectl]
#   privilege: none
#   related: [serviceaccount_audit, service_health]
#   brief: Audit Kubernetes Network Policies for security issues

"""
Audit Kubernetes Network Policies to identify security issues.

Checks:
- Namespaces without network policies (default allow-all behavior)
- Pods not covered by any network policy
- Overly permissive policies (allowing all ingress/egress)
- Empty policies with no selectors
- Isolated pods with deny-all policies

Returns exit code 1 if security issues detected.
"""

import argparse
import json
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_namespaces(context: Context, exclude_system: bool = True) -> list[str]:
    """Get all namespaces in the cluster."""
    result = context.run(
        ["kubectl", "get", "namespaces", "-o", "json"],
        check=False
    )
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        namespaces = [ns["metadata"]["name"] for ns in data.get("items", [])]
        if exclude_system:
            system_ns = ["kube-system", "kube-public", "kube-node-lease"]
            namespaces = [ns for ns in namespaces if ns not in system_ns]
        return namespaces
    except (json.JSONDecodeError, KeyError):
        return []


def get_network_policies(context: Context, namespace: str | None = None) -> list[dict]:
    """Get network policies, optionally filtered by namespace."""
    cmd = ["kubectl", "get", "networkpolicies", "-o", "json"]
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
    """Get all pods, optionally filtered by namespace."""
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


def pod_matches_selector(pod_labels: dict, selector: dict) -> bool:
    """Check if pod labels match a network policy selector."""
    if not selector:
        return True

    match_labels = selector.get("matchLabels", {})
    match_expressions = selector.get("matchExpressions", [])

    for key, value in match_labels.items():
        if pod_labels.get(key) != value:
            return False

    for expr in match_expressions:
        key = expr.get("key")
        operator = expr.get("operator")
        values = expr.get("values", [])
        pod_value = pod_labels.get(key)

        if operator == "In":
            if pod_value not in values:
                return False
        elif operator == "NotIn":
            if pod_value in values:
                return False
        elif operator == "Exists":
            if key not in pod_labels:
                return False
        elif operator == "DoesNotExist":
            if key in pod_labels:
                return False

    return True


def analyze_network_policies(
    context: Context,
    namespace: str | None = None
) -> dict[str, Any]:
    """Analyze network policies and return findings."""
    findings: dict[str, Any] = {
        "namespaces_without_policies": [],
        "unprotected_pods": [],
        "overly_permissive_policies": [],
        "deny_all_policies": [],
        "policy_count": 0,
        "namespace_count": 0,
    }

    if namespace:
        namespaces = [namespace]
    else:
        namespaces = get_namespaces(context, exclude_system=True)

    findings["namespace_count"] = len(namespaces)

    all_policies = get_network_policies(context, namespace)
    findings["policy_count"] = len(all_policies)

    policies_by_ns: dict[str, list] = defaultdict(list)
    for policy in all_policies:
        ns = policy["metadata"]["namespace"]
        policies_by_ns[ns].append(policy)

    all_pods = get_pods(context, namespace)
    pods_by_ns: dict[str, list] = defaultdict(list)
    for pod in all_pods:
        ns = pod["metadata"].get("namespace", "default")
        pods_by_ns[ns].append(pod)

    for ns in namespaces:
        ns_policies = policies_by_ns.get(ns, [])

        if not ns_policies:
            findings["namespaces_without_policies"].append({
                "namespace": ns,
                "reason": "No network policies defined (default allow-all)"
            })
            continue

        ns_pods = pods_by_ns.get(ns, [])
        covered_pods: set[str] = set()

        for policy in ns_policies:
            policy_name = policy["metadata"]["name"]
            spec = policy.get("spec", {})
            pod_selector = spec.get("podSelector", {})
            policy_types = spec.get("policyTypes", [])
            ingress_rules = spec.get("ingress", [])
            egress_rules = spec.get("egress", [])

            selector_empty = (
                not pod_selector or
                (not pod_selector.get("matchLabels") and
                 not pod_selector.get("matchExpressions"))
            )

            if selector_empty:
                if not ingress_rules and not egress_rules:
                    findings["deny_all_policies"].append({
                        "namespace": ns,
                        "policy": policy_name,
                        "types": policy_types,
                        "reason": "Deny-all policy (no ingress/egress rules)"
                    })
                else:
                    is_permissive = False
                    for rule in ingress_rules:
                        if not rule or not rule.get("from"):
                            is_permissive = True
                            break
                    for rule in egress_rules:
                        if not rule or not rule.get("to"):
                            is_permissive = True
                            break

                    if is_permissive:
                        findings["overly_permissive_policies"].append({
                            "namespace": ns,
                            "policy": policy_name,
                            "reason": "Allow-all ingress or egress rule"
                        })

                for pod in ns_pods:
                    covered_pods.add(pod["metadata"]["name"])
            else:
                for pod in ns_pods:
                    pod_name = pod["metadata"]["name"]
                    pod_labels = pod["metadata"].get("labels", {})
                    if pod_matches_selector(pod_labels, pod_selector):
                        covered_pods.add(pod_name)

        for pod in ns_pods:
            pod_name = pod["metadata"]["name"]
            if pod_name not in covered_pods:
                findings["unprotected_pods"].append({
                    "namespace": ns,
                    "pod": pod_name,
                    "labels": pod["metadata"].get("labels", {}),
                    "reason": "Pod not matched by any network policy"
                })

    return findings


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
    parser = argparse.ArgumentParser(description="Audit Kubernetes Network Policies")
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to audit (default: all non-system namespaces)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl and configure cluster access.")
        return 2

    findings = analyze_network_policies(context, opts.namespace)

    output.emit(findings)

    has_issues = (
        len(findings["namespaces_without_policies"]) > 0 or
        len(findings["unprotected_pods"]) > 0 or
        len(findings["overly_permissive_policies"]) > 0
    )

    for ns_info in findings["namespaces_without_policies"]:
        output.warning(f"Namespace {ns_info['namespace']}: {ns_info['reason']}")

    for pod_info in findings["unprotected_pods"]:
        output.warning(f"Pod {pod_info['namespace']}/{pod_info['pod']}: {pod_info['reason']}")

    for policy_info in findings["overly_permissive_policies"]:
        output.warning(
            f"Policy {policy_info['namespace']}/{policy_info['policy']}: {policy_info['reason']}"
        )

    issues_count = (
        len(findings["namespaces_without_policies"]) +
        len(findings["unprotected_pods"]) +
        len(findings["overly_permissive_policies"])
    )

    if has_issues:
        output.set_summary(f"Network policy issues: {issues_count} finding(s)")
    else:
        output.set_summary(
            f"Network policies OK: {findings['policy_count']} policies in "
            f"{findings['namespace_count']} namespaces"
        )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
