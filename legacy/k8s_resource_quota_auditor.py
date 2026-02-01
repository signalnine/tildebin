#!/usr/bin/env python3
"""
Audit Kubernetes ResourceQuota and LimitRange policies across namespaces.

This script identifies potential resource management issues:
- Namespaces without ResourceQuota (unlimited resource risk)
- Namespaces without LimitRange (pods without default limits)
- Quota utilization approaching limits
- Overly permissive or missing resource constraints

Useful for:
- Multi-tenant cluster resource governance
- Preventing resource exhaustion
- Ensuring fair resource distribution
- Capacity planning and compliance

Exit codes:
    0 - No issues detected, all namespaces have proper quotas
    1 - Issues found (missing quotas, high utilization, etc.)
    2 - Usage error or kubectl not available
"""

import argparse
import sys
import subprocess
import json


def run_kubectl(args):
    """Execute kubectl command and return output"""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_namespaces(namespace=None):
    """Get list of namespaces to check"""
    if namespace:
        return [namespace]

    output = run_kubectl(['get', 'namespaces', '-o', 'json'])
    data = json.loads(output)
    return [ns['metadata']['name'] for ns in data.get('items', [])]


def get_resource_quotas(namespace):
    """Get ResourceQuotas for a namespace"""
    output = run_kubectl(['get', 'resourcequota', '-n', namespace, '-o', 'json'])
    data = json.loads(output)
    return data.get('items', [])


def get_limit_ranges(namespace):
    """Get LimitRanges for a namespace"""
    output = run_kubectl(['get', 'limitrange', '-n', namespace, '-o', 'json'])
    data = json.loads(output)
    return data.get('items', [])


def parse_quantity(quantity_str):
    """Parse Kubernetes quantity string to numeric value"""
    if not quantity_str:
        return 0

    # Handle memory units (Ki, Mi, Gi, Ti)
    if quantity_str.endswith('Ki'):
        return float(quantity_str[:-2]) * 1024
    elif quantity_str.endswith('Mi'):
        return float(quantity_str[:-2]) * 1024 * 1024
    elif quantity_str.endswith('Gi'):
        return float(quantity_str[:-2]) * 1024 * 1024 * 1024
    elif quantity_str.endswith('Ti'):
        return float(quantity_str[:-2]) * 1024 * 1024 * 1024 * 1024

    # Handle CPU millicores
    if quantity_str.endswith('m'):
        return float(quantity_str[:-1]) / 1000

    # Plain number
    try:
        return float(quantity_str)
    except ValueError:
        return 0


def calculate_utilization(used, hard):
    """Calculate quota utilization percentage"""
    if not hard or hard == 0:
        return 0
    return (used / hard) * 100


def audit_namespace(namespace, warn_threshold):
    """Audit a single namespace for resource quota issues"""
    issues = []
    quota_info = {}

    # Check for ResourceQuota
    quotas = get_resource_quotas(namespace)
    if not quotas:
        issues.append({
            'severity': 'warning',
            'type': 'missing_quota',
            'message': 'No ResourceQuota defined (unlimited resources)'
        })
    else:
        # Analyze quota utilization
        for quota in quotas:
            quota_name = quota['metadata']['name']
            status = quota.get('status', {})
            hard = status.get('hard', {})
            used = status.get('used', {})

            for resource, hard_value in hard.items():
                used_value = used.get(resource, '0')
                hard_num = parse_quantity(hard_value)
                used_num = parse_quantity(used_value)

                utilization = calculate_utilization(used_num, hard_num)

                quota_info[f"{quota_name}/{resource}"] = {
                    'used': used_value,
                    'hard': hard_value,
                    'utilization': round(utilization, 2)
                }

                if utilization >= warn_threshold:
                    issues.append({
                        'severity': 'warning',
                        'type': 'high_utilization',
                        'message': f'Quota "{quota_name}" resource "{resource}" at {utilization:.1f}% ({used_value}/{hard_value})'
                    })

    # Check for LimitRange
    limit_ranges = get_limit_ranges(namespace)
    if not limit_ranges:
        issues.append({
            'severity': 'warning',
            'type': 'missing_limitrange',
            'message': 'No LimitRange defined (pods may lack default resource limits)'
        })
    else:
        # Check if LimitRange has meaningful defaults
        has_defaults = False
        for lr in limit_ranges:
            limits = lr.get('spec', {}).get('limits', [])
            for limit in limits:
                if 'default' in limit or 'defaultRequest' in limit:
                    has_defaults = True
                    break

        if not has_defaults:
            issues.append({
                'severity': 'info',
                'type': 'no_defaults',
                'message': 'LimitRange exists but has no default resource limits'
            })

    return {
        'namespace': namespace,
        'has_quota': len(quotas) > 0,
        'has_limitrange': len(limit_ranges) > 0,
        'quota_count': len(quotas),
        'limitrange_count': len(limit_ranges),
        'quota_info': quota_info,
        'issues': issues
    }


def output_plain(results, warn_only, verbose):
    """Output results in plain text format"""
    print("Kubernetes Resource Quota Audit Report")
    print("=" * 60)

    total_ns = len(results)
    issues_count = sum(1 for r in results if r['issues'])

    for result in results:
        if warn_only and not result['issues']:
            continue

        ns = result['namespace']
        has_issues = len(result['issues']) > 0
        status = "⚠ ISSUES" if has_issues else "✓ OK"

        print(f"\nNamespace: {ns} [{status}]")
        print(f"  ResourceQuota: {'Yes' if result['has_quota'] else 'No'} ({result['quota_count']})")
        print(f"  LimitRange: {'Yes' if result['has_limitrange'] else 'No'} ({result['limitrange_count']})")

        if verbose and result['quota_info']:
            print("  Quota Utilization:")
            for quota_key, info in result['quota_info'].items():
                print(f"    {quota_key}: {info['utilization']}% ({info['used']}/{info['hard']})")

        if result['issues']:
            print("  Issues:")
            for issue in result['issues']:
                severity_mark = "⚠" if issue['severity'] == 'warning' else "ℹ"
                print(f"    {severity_mark} [{issue['type']}] {issue['message']}")

    print("\n" + "=" * 60)
    print(f"Summary: {issues_count}/{total_ns} namespaces have issues")


def output_json(results):
    """Output results in JSON format"""
    print(json.dumps(results, indent=2))


def output_table(results, warn_only):
    """Output results in table format"""
    print(f"{'Namespace':<30} {'Quota':<8} {'LimitRange':<11} {'Issues':<8}")
    print("-" * 70)

    for result in results:
        if warn_only and not result['issues']:
            continue

        ns = result['namespace']
        quota = "Yes" if result['has_quota'] else "No"
        limitrange = "Yes" if result['has_limitrange'] else "No"
        issue_count = len(result['issues'])

        print(f"{ns:<30} {quota:<8} {limitrange:<11} {issue_count:<8}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes ResourceQuota and LimitRange policies",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to audit (default: all namespaces)"
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show namespaces with issues"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed quota utilization information"
    )

    parser.add_argument(
        "--warn-threshold",
        type=float,
        default=80.0,
        help="Quota utilization warning threshold in percent (default: %(default)s)"
    )

    args = parser.parse_args()

    try:
        # Get namespaces to audit
        namespaces = get_namespaces(args.namespace)

        # Audit each namespace
        results = []
        for ns in namespaces:
            # Skip system namespaces unless explicitly requested
            if not args.namespace and ns in ['kube-system', 'kube-public', 'kube-node-lease']:
                continue

            result = audit_namespace(ns, args.warn_threshold)
            results.append(result)

        # Output results
        if args.format == "json":
            output_json(results)
        elif args.format == "table":
            output_table(results, args.warn_only)
        else:  # plain
            output_plain(results, args.warn_only, args.verbose)

        # Exit code based on findings
        has_issues = any(r['issues'] for r in results)
        sys.exit(1 if has_issues else 0)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
