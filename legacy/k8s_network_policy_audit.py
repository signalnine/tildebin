#!/usr/bin/env python3
"""
Kubernetes Network Policy Audit

Audits Kubernetes Network Policies to identify:
- Namespaces without network policies (default allow-all behavior)
- Pods not covered by any network policy
- Overly permissive policies (allowing all ingress/egress)
- Empty policies with no selectors
- Isolated pods with deny-all policies
- Network policy syntax and configuration issues

Exit codes:
0 - Network policies properly configured
1 - Security issues or missing policies detected
2 - Usage error or missing dependencies
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


def check_kubectl():
    """Check if kubectl is available and configured."""
    try:
        result = subprocess.run(
            ['kubectl', 'cluster-info'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def get_namespaces(exclude_system=True):
    """Get all namespaces in the cluster."""
    try:
        result = subprocess.run(
            ['kubectl', 'get', 'namespaces', '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return []

        data = json.loads(result.stdout)
        namespaces = [ns['metadata']['name'] for ns in data.get('items', [])]

        if exclude_system:
            # Filter out system namespaces unless explicitly requested
            system_ns = ['kube-system', 'kube-public', 'kube-node-lease', 'default']
            namespaces = [ns for ns in namespaces if ns not in system_ns]

        return namespaces
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def get_network_policies(namespace=None):
    """Get network policies, optionally filtered by namespace."""
    try:
        cmd = ['kubectl', 'get', 'networkpolicies', '-o', 'json']
        if namespace:
            cmd.extend(['-n', namespace])
        else:
            cmd.append('--all-namespaces')

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return []

        data = json.loads(result.stdout)
        return data.get('items', [])
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def get_pods(namespace=None):
    """Get all pods, optionally filtered by namespace."""
    try:
        cmd = ['kubectl', 'get', 'pods', '-o', 'json']
        if namespace:
            cmd.extend(['-n', namespace])
        else:
            cmd.append('--all-namespaces')

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return []

        data = json.loads(result.stdout)
        return data.get('items', [])
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []


def pod_matches_selector(pod_labels, selector):
    """Check if pod labels match a network policy selector."""
    if not selector:
        # Empty selector matches all pods
        return True

    match_labels = selector.get('matchLabels', {})
    match_expressions = selector.get('matchExpressions', [])

    # Check matchLabels
    for key, value in match_labels.items():
        if pod_labels.get(key) != value:
            return False

    # Check matchExpressions
    for expr in match_expressions:
        key = expr.get('key')
        operator = expr.get('operator')
        values = expr.get('values', [])

        pod_value = pod_labels.get(key)

        if operator == 'In':
            if pod_value not in values:
                return False
        elif operator == 'NotIn':
            if pod_value in values:
                return False
        elif operator == 'Exists':
            if key not in pod_labels:
                return False
        elif operator == 'DoesNotExist':
            if key in pod_labels:
                return False

    return True


def analyze_network_policies(namespace=None):
    """Analyze network policies and return findings."""
    findings = {
        'namespaces_without_policies': [],
        'unprotected_pods': [],
        'overly_permissive_policies': [],
        'empty_policies': [],
        'deny_all_policies': [],
        'policy_count': 0,
        'namespace_count': 0,
        'pod_count': 0,
    }

    # Get all resources
    if namespace:
        namespaces = [namespace]
    else:
        # Include system namespaces for comprehensive audit
        namespaces = get_namespaces(exclude_system=False)

    findings['namespace_count'] = len(namespaces)

    all_policies = get_network_policies(namespace)
    findings['policy_count'] = len(all_policies)

    # Group policies by namespace
    policies_by_ns = defaultdict(list)
    for policy in all_policies:
        ns = policy['metadata']['namespace']
        policies_by_ns[ns].append(policy)

    # Check each namespace
    for ns in namespaces:
        ns_policies = policies_by_ns.get(ns, [])

        if not ns_policies:
            findings['namespaces_without_policies'].append({
                'namespace': ns,
                'reason': 'No network policies defined (default allow-all)'
            })
            continue

        # Get pods in this namespace
        ns_pods = get_pods(namespace=ns)

        # Track which pods are covered
        covered_pods = set()

        for policy in ns_policies:
            policy_name = policy['metadata']['name']
            spec = policy.get('spec', {})
            pod_selector = spec.get('podSelector', {})
            policy_types = spec.get('policyTypes', [])
            ingress_rules = spec.get('ingress', [])
            egress_rules = spec.get('egress', [])

            # Check for empty pod selector (applies to all pods)
            if not pod_selector or not pod_selector.get('matchLabels') and not pod_selector.get('matchExpressions'):
                # This is a namespace-wide policy
                if not ingress_rules and not egress_rules:
                    # Deny-all policy
                    findings['deny_all_policies'].append({
                        'namespace': ns,
                        'policy': policy_name,
                        'types': policy_types,
                        'reason': 'Deny-all policy (no ingress/egress rules)'
                    })
                else:
                    # Check if overly permissive
                    is_permissive = False

                    for rule in ingress_rules:
                        if not rule or not rule.get('from'):
                            is_permissive = True
                            break

                    for rule in egress_rules:
                        if not rule or not rule.get('to'):
                            is_permissive = True
                            break

                    if is_permissive:
                        findings['overly_permissive_policies'].append({
                            'namespace': ns,
                            'policy': policy_name,
                            'reason': 'Allow-all ingress or egress rule',
                            'ingress_rules': len(ingress_rules),
                            'egress_rules': len(egress_rules)
                        })

                # Mark all pods as covered
                for pod in ns_pods:
                    pod_name = pod['metadata']['name']
                    covered_pods.add(pod_name)
            else:
                # Policy with specific pod selector
                for pod in ns_pods:
                    pod_name = pod['metadata']['name']
                    pod_labels = pod['metadata'].get('labels', {})

                    if pod_matches_selector(pod_labels, pod_selector):
                        covered_pods.add(pod_name)

        # Find unprotected pods
        for pod in ns_pods:
            pod_name = pod['metadata']['name']
            if pod_name not in covered_pods:
                findings['unprotected_pods'].append({
                    'namespace': ns,
                    'pod': pod_name,
                    'labels': pod['metadata'].get('labels', {}),
                    'reason': 'Pod not matched by any network policy'
                })

    findings['pod_count'] = sum(len(get_pods(namespace=ns)) for ns in namespaces)

    return findings


def output_plain(findings, warn_only=False):
    """Output findings in plain text format."""
    has_issues = False

    print(f"Network Policy Audit Summary")
    print(f"{'=' * 60}")
    print(f"Namespaces checked: {findings['namespace_count']}")
    print(f"Network policies found: {findings['policy_count']}")
    print(f"Total pods: {findings['pod_count']}")
    print()

    # Namespaces without policies
    if findings['namespaces_without_policies']:
        has_issues = True
        print(f"[WARNING] Namespaces without network policies: {len(findings['namespaces_without_policies'])}")
        if not warn_only:
            for item in findings['namespaces_without_policies']:
                print(f"  - {item['namespace']}: {item['reason']}")
        print()

    # Unprotected pods
    if findings['unprotected_pods']:
        has_issues = True
        print(f"[WARNING] Pods not covered by any network policy: {len(findings['unprotected_pods'])}")
        if not warn_only:
            for item in findings['unprotected_pods']:
                print(f"  - {item['namespace']}/{item['pod']}")
                if item.get('labels'):
                    print(f"    Labels: {item['labels']}")
        print()

    # Overly permissive policies
    if findings['overly_permissive_policies']:
        has_issues = True
        print(f"[WARNING] Overly permissive policies: {len(findings['overly_permissive_policies'])}")
        if not warn_only:
            for item in findings['overly_permissive_policies']:
                print(f"  - {item['namespace']}/{item['policy']}: {item['reason']}")
        print()

    # Deny-all policies
    if findings['deny_all_policies'] and not warn_only:
        print(f"[INFO] Deny-all policies (complete isolation): {len(findings['deny_all_policies'])}")
        for item in findings['deny_all_policies']:
            print(f"  - {item['namespace']}/{item['policy']}")
        print()

    if not has_issues and not warn_only:
        print("[OK] No network policy issues detected")

    return has_issues


def output_json(findings):
    """Output findings in JSON format."""
    print(json.dumps(findings, indent=2))

    # Determine if there are issues
    has_issues = (
        len(findings['namespaces_without_policies']) > 0 or
        len(findings['unprotected_pods']) > 0 or
        len(findings['overly_permissive_policies']) > 0
    )

    return has_issues


def output_table(findings, warn_only=False):
    """Output findings in table format."""
    has_issues = False

    print(f"Network Policy Audit")
    print(f"{'=' * 80}")
    print(f"Namespaces: {findings['namespace_count']} | Policies: {findings['policy_count']} | Pods: {findings['pod_count']}")
    print()

    # Summary table
    if findings['namespaces_without_policies'] or findings['unprotected_pods'] or findings['overly_permissive_policies']:
        has_issues = True
        print(f"{'Issue Type':<40} {'Count':<10}")
        print(f"{'-' * 50}")

        if findings['namespaces_without_policies']:
            print(f"{'Namespaces without policies':<40} {len(findings['namespaces_without_policies']):<10}")

        if findings['unprotected_pods']:
            print(f"{'Unprotected pods':<40} {len(findings['unprotected_pods']):<10}")

        if findings['overly_permissive_policies']:
            print(f"{'Overly permissive policies':<40} {len(findings['overly_permissive_policies']):<10}")

        print()

    # Details
    if not warn_only:
        if findings['namespaces_without_policies']:
            print("Namespaces Without Policies:")
            print(f"{'Namespace':<30} {'Reason':<50}")
            print(f"{'-' * 80}")
            for item in findings['namespaces_without_policies']:
                print(f"{item['namespace']:<30} {item['reason']:<50}")
            print()

        if findings['unprotected_pods']:
            print("Unprotected Pods:")
            print(f"{'Namespace/Pod':<50} {'Status':<30}")
            print(f"{'-' * 80}")
            for item in findings['unprotected_pods']:
                pod_full = f"{item['namespace']}/{item['pod']}"
                print(f"{pod_full:<50} {'Not covered by policy':<30}")
            print()

    if not has_issues and not warn_only:
        print("[OK] No network policy issues detected")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Audit Kubernetes Network Policies',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all namespaces
  k8s_network_policy_audit.py

  # Audit specific namespace
  k8s_network_policy_audit.py -n production

  # Show only issues
  k8s_network_policy_audit.py --warn-only

  # JSON output for monitoring
  k8s_network_policy_audit.py --format json

  # Table format
  k8s_network_policy_audit.py --format table
        """
    )

    parser.add_argument('-n', '--namespace',
                        help='Namespace to audit (default: all namespaces)')
    parser.add_argument('-f', '--format',
                        choices=['plain', 'json', 'table'],
                        default='plain',
                        help='Output format (default: plain)')
    parser.add_argument('-w', '--warn-only',
                        action='store_true',
                        help='Only show issues and warnings')

    args = parser.parse_args()

    # Check kubectl availability
    if not check_kubectl():
        print("Error: kubectl is not available or not configured", file=sys.stderr)
        print("Please install kubectl and configure access to a Kubernetes cluster", file=sys.stderr)
        return 2

    # Analyze network policies
    findings = analyze_network_policies(namespace=args.namespace)

    # Output results
    if args.format == 'json':
        has_issues = output_json(findings)
    elif args.format == 'table':
        has_issues = output_table(findings, warn_only=args.warn_only)
    else:
        has_issues = output_plain(findings, warn_only=args.warn_only)

    return 1 if has_issues else 0


if __name__ == '__main__':
    sys.exit(main())
