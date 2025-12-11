#!/usr/bin/env python3
"""
Audit Kubernetes RBAC roles and bindings for security issues.

This script analyzes ClusterRoles, Roles, ClusterRoleBindings, and RoleBindings
to identify potentially dangerous permissions, overly permissive access, and
security policy violations.

Checks performed:
- Cluster-admin access detection
- Wildcard permissions (*, get/list/watch on all resources)
- Dangerous verbs (create, delete, deletecollection, exec, proxy)
- Service account bindings to high-privilege roles
- Anonymous user access
- Namespace-level admin access
- Secrets and ConfigMaps access patterns

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


def get_cluster_roles():
    """Get all ClusterRoles"""
    data = run_kubectl(['get', 'clusterroles', '-o', 'json'])
    return data.get('items', [])


def get_roles(namespace=None):
    """Get all Roles"""
    cmd = ['get', 'roles', '-o', 'json']
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


def check_dangerous_permissions(role):
    """Check if a role has dangerous permissions"""
    issues = []
    role_name = role['metadata']['name']
    rules = role.get('rules', [])

    for rule in rules:
        verbs = rule.get('verbs', [])
        resources = rule.get('resources', [])
        api_groups = rule.get('apiGroups', [])

        # Check for wildcard permissions
        if '*' in verbs or '*' in resources or '*' in api_groups:
            issues.append({
                'severity': 'HIGH',
                'type': 'wildcard_permissions',
                'role': role_name,
                'detail': f"Wildcard permissions: verbs={verbs}, resources={resources}, apiGroups={api_groups}"
            })

        # Check for dangerous verbs
        dangerous_verbs = {'create', 'delete', 'deletecollection', 'exec', 'proxy', 'impersonate', 'bind', 'escalate'}
        found_dangerous = dangerous_verbs.intersection(set(verbs))
        if found_dangerous and ('*' in resources or 'pods' in resources or 'pods/exec' in resources):
            issues.append({
                'severity': 'MEDIUM',
                'type': 'dangerous_verbs',
                'role': role_name,
                'detail': f"Dangerous verbs: {list(found_dangerous)} on resources: {resources}"
            })

        # Check for secrets/configmaps access
        sensitive_resources = {'secrets', 'configmaps'}
        found_sensitive = sensitive_resources.intersection(set(resources))
        if found_sensitive and ('get' in verbs or 'list' in verbs or '*' in verbs):
            issues.append({
                'severity': 'MEDIUM',
                'type': 'sensitive_resource_access',
                'role': role_name,
                'detail': f"Access to sensitive resources: {list(found_sensitive)} with verbs: {verbs}"
            })

    return issues


def check_bindings(bindings, binding_type):
    """Check RoleBindings or ClusterRoleBindings for security issues"""
    issues = []

    for binding in bindings:
        binding_name = binding['metadata']['name']
        namespace = binding['metadata'].get('namespace', 'cluster-wide')
        role_ref = binding.get('roleRef', {})
        role_name = role_ref.get('name', 'unknown')
        subjects = binding.get('subjects', [])

        # Check for cluster-admin bindings
        if role_name == 'cluster-admin':
            for subject in subjects:
                issues.append({
                    'severity': 'HIGH',
                    'type': 'cluster_admin_binding',
                    'binding': binding_name,
                    'namespace': namespace,
                    'detail': f"cluster-admin bound to {subject.get('kind', 'unknown')}: {subject.get('name', 'unknown')}"
                })

        # Check for anonymous user access
        for subject in subjects:
            if subject.get('name') == 'system:anonymous' or subject.get('name') == 'system:unauthenticated':
                issues.append({
                    'severity': 'HIGH',
                    'type': 'anonymous_access',
                    'binding': binding_name,
                    'namespace': namespace,
                    'detail': f"Anonymous/unauthenticated user bound to role: {role_name}"
                })

            # Check for service account bindings to admin roles
            if subject.get('kind') == 'ServiceAccount' and 'admin' in role_name.lower():
                issues.append({
                    'severity': 'MEDIUM',
                    'type': 'serviceaccount_admin',
                    'binding': binding_name,
                    'namespace': namespace,
                    'detail': f"ServiceAccount {subject.get('name')} bound to admin role: {role_name}"
                })

    return issues


def output_plain(all_issues, verbose=False, warn_only=False):
    """Output results in plain text format"""
    if not all_issues:
        if not warn_only:
            print("No RBAC security issues detected")
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
                print(f"  Role/Binding: {issue.get('role', issue.get('binding', 'N/A'))}")
                if 'namespace' in issue:
                    print(f"  Namespace: {issue['namespace']}")
                print(f"  Detail: {issue['detail']}")
                print()
            else:
                entity = issue.get('role', issue.get('binding', 'N/A'))
                print(f"  [{issue['type']}] {entity}: {issue['detail']}")


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
        print("No RBAC security issues detected")
        return

    print(f"{'Severity':<10} {'Type':<30} {'Entity':<30} {'Issue':<50}")
    print("=" * 120)

    for issue in all_issues:
        entity = issue.get('role', issue.get('binding', 'N/A'))
        detail = issue['detail']
        if len(detail) > 47:
            detail = detail[:47] + "..."
        print(f"{issue['severity']:<10} {issue['type']:<30} {entity:<30} {detail:<50}")


def main():
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes RBAC roles and bindings for security issues",
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

    args = parser.parse_args()

    all_issues = []

    # Audit ClusterRoles
    if args.verbose and not args.warn_only:
        print("Auditing ClusterRoles...", file=sys.stderr)
    cluster_roles = get_cluster_roles()
    for role in cluster_roles:
        all_issues.extend(check_dangerous_permissions(role))

    # Audit Roles (namespace-specific or all)
    if args.verbose and not args.warn_only:
        print("Auditing Roles...", file=sys.stderr)
    roles = get_roles(args.namespace)
    for role in roles:
        all_issues.extend(check_dangerous_permissions(role))

    # Audit ClusterRoleBindings
    if args.verbose and not args.warn_only:
        print("Auditing ClusterRoleBindings...", file=sys.stderr)
    cluster_role_bindings = get_cluster_role_bindings()
    all_issues.extend(check_bindings(cluster_role_bindings, 'ClusterRoleBinding'))

    # Audit RoleBindings
    if args.verbose and not args.warn_only:
        print("Auditing RoleBindings...", file=sys.stderr)
    role_bindings = get_role_bindings(args.namespace)
    all_issues.extend(check_bindings(role_bindings, 'RoleBinding'))

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
