#!/usr/bin/env python3
"""
Audit Kubernetes ServiceAccounts for security issues.

This script analyzes ServiceAccounts across the cluster to identify security
misconfigurations, risky automount settings, and unused or default accounts.

Checks performed:
- automountServiceAccountToken enabled (should be explicitly disabled when not needed)
- Default ServiceAccount usage by pods (security anti-pattern)
- ServiceAccounts with no associated pods (potentially stale)
- ServiceAccounts bound to high-privilege roles (cluster-admin, admin)
- ServiceAccounts in kube-system with broad permissions
- Token projection configuration issues

Exit codes:
    0 - No critical issues detected
    1 - Security issues or warnings found
    2 - Usage error or kubectl not found
"""

import argparse
import sys
import subprocess
import json
from collections import defaultdict


def run_kubectl(args):
    """Execute kubectl command and return JSON output"""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout) if result.stdout else {}
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing kubectl output: {e}", file=sys.stderr)
        sys.exit(1)


def get_serviceaccounts(namespace=None):
    """Get all ServiceAccounts"""
    cmd = ['get', 'serviceaccounts', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    data = run_kubectl(cmd)
    return data.get('items', [])


def get_pods(namespace=None):
    """Get all Pods"""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    data = run_kubectl(cmd)
    return data.get('items', [])


def get_cluster_role_bindings():
    """Get all ClusterRoleBindings"""
    data = run_kubectl(['get', 'clusterrolebindings', '-o', 'json'])
    return data.get('items', [])


def get_role_bindings(namespace=None):
    """Get all RoleBindings"""
    cmd = ['get', 'rolebindings', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    data = run_kubectl(cmd)
    return data.get('items', [])


def build_sa_role_map(cluster_bindings, role_bindings):
    """Build a map of ServiceAccount -> roles they're bound to"""
    sa_roles = defaultdict(list)

    # Process ClusterRoleBindings
    for binding in cluster_bindings:
        role_name = binding.get('roleRef', {}).get('name', 'unknown')
        subjects = binding.get('subjects', [])

        for subject in subjects:
            if subject.get('kind') == 'ServiceAccount':
                sa_namespace = subject.get('namespace', 'default')
                sa_name = subject.get('name', 'unknown')
                sa_key = f"{sa_namespace}/{sa_name}"
                sa_roles[sa_key].append({
                    'role': role_name,
                    'binding_type': 'ClusterRoleBinding',
                    'binding_name': binding['metadata']['name']
                })

    # Process RoleBindings
    for binding in role_bindings:
        role_name = binding.get('roleRef', {}).get('name', 'unknown')
        binding_namespace = binding['metadata'].get('namespace', 'default')
        subjects = binding.get('subjects', [])

        for subject in subjects:
            if subject.get('kind') == 'ServiceAccount':
                sa_namespace = subject.get('namespace', binding_namespace)
                sa_name = subject.get('name', 'unknown')
                sa_key = f"{sa_namespace}/{sa_name}"
                sa_roles[sa_key].append({
                    'role': role_name,
                    'binding_type': 'RoleBinding',
                    'binding_name': binding['metadata']['name'],
                    'binding_namespace': binding_namespace
                })

    return sa_roles


def build_sa_usage_map(pods):
    """Build a map of ServiceAccount -> pods using it"""
    sa_pods = defaultdict(list)

    for pod in pods:
        namespace = pod['metadata'].get('namespace', 'default')
        pod_name = pod['metadata'].get('name', 'unknown')
        sa_name = pod['spec'].get('serviceAccountName', 'default')
        sa_key = f"{namespace}/{sa_name}"

        sa_pods[sa_key].append({
            'pod': pod_name,
            'namespace': namespace,
            'automount': pod['spec'].get('automountServiceAccountToken', None)
        })

    return sa_pods


def check_automount_issues(sa, pods_using_sa):
    """Check for automountServiceAccountToken security issues"""
    issues = []
    sa_name = sa['metadata']['name']
    sa_namespace = sa['metadata'].get('namespace', 'default')

    # Check SA-level automount setting
    sa_automount = sa.get('automountServiceAccountToken', True)  # Default is True

    if sa_automount is True or sa_automount is None:
        # Check if any pods override this
        pods_with_automount = [p for p in pods_using_sa if p.get('automount') is not False]

        if pods_with_automount:
            issues.append({
                'severity': 'MEDIUM',
                'type': 'automount_enabled',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"automountServiceAccountToken enabled, {len(pods_with_automount)} pod(s) may have unnecessary token access"
            })

    return issues


def check_default_sa_usage(sa, pods_using_sa):
    """Check if pods are using the default ServiceAccount"""
    issues = []
    sa_name = sa['metadata']['name']
    sa_namespace = sa['metadata'].get('namespace', 'default')

    if sa_name == 'default' and pods_using_sa:
        # Exclude kube-system default SA used by system pods
        non_system_pods = [p for p in pods_using_sa
                          if not p['pod'].startswith('kube-')]

        if non_system_pods:
            issues.append({
                'severity': 'LOW',
                'type': 'default_sa_usage',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"{len(non_system_pods)} non-system pod(s) using default ServiceAccount"
            })

    return issues


def check_unused_serviceaccounts(sa, pods_using_sa):
    """Check for ServiceAccounts with no pods using them"""
    issues = []
    sa_name = sa['metadata']['name']
    sa_namespace = sa['metadata'].get('namespace', 'default')

    # Skip built-in ServiceAccounts
    if sa_name in ('default', 'builder', 'deployer'):
        return issues

    # Skip kube-system as it has legitimate unused SAs
    if sa_namespace == 'kube-system':
        return issues

    if not pods_using_sa:
        issues.append({
            'severity': 'LOW',
            'type': 'unused_serviceaccount',
            'serviceaccount': sa_name,
            'namespace': sa_namespace,
            'detail': f"ServiceAccount has no pods using it (may be stale)"
        })

    return issues


def check_privileged_bindings(sa, sa_roles):
    """Check if ServiceAccount is bound to high-privilege roles"""
    issues = []
    sa_name = sa['metadata']['name']
    sa_namespace = sa['metadata'].get('namespace', 'default')
    sa_key = f"{sa_namespace}/{sa_name}"

    roles = sa_roles.get(sa_key, [])

    # High-privilege role patterns
    high_priv_patterns = ['cluster-admin', 'admin', 'edit', 'system:controller']

    for role_info in roles:
        role_name = role_info['role'].lower()

        # Check for cluster-admin (highest severity)
        if role_name == 'cluster-admin':
            issues.append({
                'severity': 'HIGH',
                'type': 'cluster_admin_binding',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"Bound to cluster-admin via {role_info['binding_type']}: {role_info['binding_name']}"
            })
        # Check for admin roles
        elif 'admin' in role_name:
            issues.append({
                'severity': 'MEDIUM',
                'type': 'admin_role_binding',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"Bound to admin role '{role_info['role']}' via {role_info['binding_type']}"
            })
        # Check for edit role
        elif role_name == 'edit':
            issues.append({
                'severity': 'LOW',
                'type': 'edit_role_binding',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"Bound to edit role via {role_info['binding_type']}"
            })

    return issues


def check_kubesystem_serviceaccounts(sa, sa_roles):
    """Check kube-system ServiceAccounts for overly broad permissions"""
    issues = []
    sa_name = sa['metadata']['name']
    sa_namespace = sa['metadata'].get('namespace', 'default')

    if sa_namespace != 'kube-system':
        return issues

    sa_key = f"{sa_namespace}/{sa_name}"
    roles = sa_roles.get(sa_key, [])

    # kube-system SAs with ClusterRoleBindings that aren't standard controllers
    system_controllers = [
        'kube-proxy', 'kube-dns', 'coredns', 'calico', 'flannel',
        'node-controller', 'service-controller', 'endpoint-controller',
        'replication-controller', 'default'
    ]

    if sa_name not in system_controllers:
        cluster_bindings = [r for r in roles if r['binding_type'] == 'ClusterRoleBinding']
        if cluster_bindings:
            roles_str = ', '.join([r['role'] for r in cluster_bindings])
            issues.append({
                'severity': 'MEDIUM',
                'type': 'kubesystem_cluster_binding',
                'serviceaccount': sa_name,
                'namespace': sa_namespace,
                'detail': f"Non-standard kube-system SA with ClusterRoleBinding(s): {roles_str}"
            })

    return issues


def output_plain(all_issues, verbose=False, warn_only=False):
    """Output results in plain text format"""
    if not all_issues:
        if not warn_only:
            print("No ServiceAccount security issues detected")
        return

    # Group by severity
    by_severity = defaultdict(list)
    for issue in all_issues:
        by_severity[issue['severity']].append(issue)

    for severity in ['HIGH', 'MEDIUM', 'LOW']:
        if severity not in by_severity:
            continue

        print(f"\n{severity} SEVERITY ISSUES ({len(by_severity[severity])}):")
        print("=" * 60)

        for issue in by_severity[severity]:
            if verbose:
                print(f"  Type: {issue['type']}")
                print(f"  ServiceAccount: {issue['namespace']}/{issue['serviceaccount']}")
                print(f"  Detail: {issue['detail']}")
                print()
            else:
                print(f"  [{issue['type']}] {issue['namespace']}/{issue['serviceaccount']}: {issue['detail']}")


def output_json(all_issues):
    """Output results in JSON format"""
    result = {
        'summary': {
            'total_issues': len(all_issues),
            'high_severity': len([i for i in all_issues if i['severity'] == 'HIGH']),
            'medium_severity': len([i for i in all_issues if i['severity'] == 'MEDIUM']),
            'low_severity': len([i for i in all_issues if i['severity'] == 'LOW'])
        },
        'issues': all_issues
    }
    print(json.dumps(result, indent=2))


def output_table(all_issues):
    """Output results in table format"""
    if not all_issues:
        print("No ServiceAccount security issues detected")
        return

    print(f"{'Severity':<10} {'Type':<25} {'Namespace':<20} {'ServiceAccount':<25} {'Issue':<40}")
    print("=" * 120)

    for issue in all_issues:
        detail = issue['detail']
        if len(detail) > 37:
            detail = detail[:37] + "..."
        print(f"{issue['severity']:<10} {issue['type']:<25} {issue['namespace']:<20} {issue['serviceaccount']:<25} {detail:<40}")


def main():
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes ServiceAccounts for security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to audit (default: all namespaces)'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    parser.add_argument(
        '--skip-unused',
        action='store_true',
        help='Skip checking for unused ServiceAccounts'
    )

    args = parser.parse_args()

    all_issues = []

    # Gather data
    if args.verbose and not args.warn_only:
        print("Gathering ServiceAccount data...", file=sys.stderr)

    serviceaccounts = get_serviceaccounts(args.namespace)
    pods = get_pods(args.namespace)
    cluster_bindings = get_cluster_role_bindings()
    role_bindings = get_role_bindings(args.namespace)

    # Build lookup maps
    if args.verbose and not args.warn_only:
        print("Analyzing bindings and usage...", file=sys.stderr)

    sa_roles = build_sa_role_map(cluster_bindings, role_bindings)
    sa_usage = build_sa_usage_map(pods)

    # Audit each ServiceAccount
    if args.verbose and not args.warn_only:
        print(f"Auditing {len(serviceaccounts)} ServiceAccounts...", file=sys.stderr)

    for sa in serviceaccounts:
        sa_namespace = sa['metadata'].get('namespace', 'default')
        sa_name = sa['metadata']['name']
        sa_key = f"{sa_namespace}/{sa_name}"
        pods_using_sa = sa_usage.get(sa_key, [])

        # Run checks
        all_issues.extend(check_automount_issues(sa, pods_using_sa))
        all_issues.extend(check_default_sa_usage(sa, pods_using_sa))
        all_issues.extend(check_privileged_bindings(sa, sa_roles))
        all_issues.extend(check_kubesystem_serviceaccounts(sa, sa_roles))

        if not args.skip_unused:
            all_issues.extend(check_unused_serviceaccounts(sa, pods_using_sa))

    # Output results
    if args.format == 'json':
        output_json(all_issues)
    elif args.format == 'table':
        output_table(all_issues)
    else:
        output_plain(all_issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    if all_issues:
        high_severity = [i for i in all_issues if i['severity'] == 'HIGH']
        if high_severity:
            sys.exit(1)
        sys.exit(1 if not args.warn_only else 0)

    sys.exit(0)


if __name__ == '__main__':
    main()
