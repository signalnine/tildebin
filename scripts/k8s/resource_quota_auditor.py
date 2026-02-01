#!/usr/bin/env python3
# boxctl:
#   category: k8s/resources
#   tags: [quota, governance, capacity, limits]
#   requires: [kubectl]
#   privilege: user
#   related: [limitrange_auditor, namespace_resource_analyzer]
#   brief: Audit ResourceQuota and LimitRange policies across namespaces

"""
Audit Kubernetes ResourceQuota and LimitRange policies across namespaces.

Identifies potential resource management issues:
- Namespaces without ResourceQuota (unlimited resource risk)
- Namespaces without LimitRange (pods without default limits)
- Quota utilization approaching limits
- Overly permissive or missing resource constraints

Exit codes:
    0 - No issues detected, all namespaces have proper quotas
    1 - Issues found (missing quotas, high utilization, etc.)
    2 - Usage error or kubectl not available
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


SYSTEM_NAMESPACES = {'kube-system', 'kube-public', 'kube-node-lease'}


def parse_resource_value(value: str) -> float:
    """Parse Kubernetes resource values to a numeric value."""
    if not value:
        return 0.0

    value = str(value).strip()

    # Memory units
    memory_units = {
        'Ki': 1024,
        'Mi': 1024 ** 2,
        'Gi': 1024 ** 3,
        'Ti': 1024 ** 4,
    }

    for suffix, multiplier in memory_units.items():
        if value.endswith(suffix):
            try:
                return float(value[:-len(suffix)]) * multiplier
            except ValueError:
                return 0.0

    # CPU millicores
    if value.endswith('m'):
        try:
            return float(value[:-1]) / 1000.0
        except ValueError:
            return 0.0

    try:
        return float(value)
    except ValueError:
        return 0.0


def get_namespaces(context: Context, namespace: str | None = None) -> list[str]:
    """Get list of namespaces."""
    if namespace:
        return [namespace]

    result = context.run(['kubectl', 'get', 'namespaces', '-o', 'json'])
    data = json.loads(result.stdout)
    return [ns['metadata']['name'] for ns in data.get('items', [])]


def get_resource_quotas(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all ResourceQuotas."""
    args = ['kubectl', 'get', 'resourcequota', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    result = context.run(args)
    data = json.loads(result.stdout)
    return data.get('items', [])


def get_limit_ranges(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all LimitRanges."""
    args = ['kubectl', 'get', 'limitrange', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    result = context.run(args)
    data = json.loads(result.stdout)
    return data.get('items', [])


def analyze_quota(quota: dict, warn_threshold: float) -> dict[str, Any]:
    """Analyze a single ResourceQuota for issues."""
    metadata = quota.get('metadata', {})
    status = quota.get('status', {})

    namespace = metadata.get('namespace', 'default')
    name = metadata.get('name', 'unknown')

    hard = status.get('hard', {})
    used = status.get('used', {})

    resources = []
    issues = []

    for resource_name, hard_value in hard.items():
        used_value = used.get(resource_name, '0')

        hard_num = parse_resource_value(hard_value)
        used_num = parse_resource_value(used_value)

        if hard_num > 0:
            utilization = (used_num / hard_num) * 100
        else:
            utilization = 0

        resource_info = {
            'resource': resource_name,
            'hard': hard_value,
            'used': used_value,
            'utilization_pct': round(utilization, 1),
        }
        resources.append(resource_info)

        if utilization >= warn_threshold:
            issues.append({
                'type': 'high_utilization',
                'resource': resource_name,
                'utilization_pct': round(utilization, 1),
                'message': f'{resource_name} at {utilization:.0f}% ({used_value}/{hard_value})'
            })

    return {
        'namespace': namespace,
        'name': name,
        'resources': resources,
        'issues': issues,
    }


def audit_namespace(
    namespace: str,
    quotas: list[dict],
    limit_ranges: list[dict],
    warn_threshold: float
) -> dict[str, Any]:
    """Audit a single namespace for quota/limitrange issues."""
    ns_quotas = [q for q in quotas if q.get('metadata', {}).get('namespace') == namespace]
    ns_limitranges = [lr for lr in limit_ranges if lr.get('metadata', {}).get('namespace') == namespace]

    issues = []
    quota_analyses = []

    # Check for missing quota
    if not ns_quotas:
        issues.append({
            'type': 'missing_quota',
            'message': 'No ResourceQuota defined'
        })
    else:
        for quota in ns_quotas:
            analysis = analyze_quota(quota, warn_threshold)
            quota_analyses.append(analysis)
            issues.extend(analysis['issues'])

    # Check for missing LimitRange
    if not ns_limitranges:
        issues.append({
            'type': 'missing_limitrange',
            'message': 'No LimitRange defined'
        })
    else:
        # Check if LimitRange has defaults
        has_defaults = False
        for lr in ns_limitranges:
            limits = lr.get('spec', {}).get('limits', [])
            for limit in limits:
                if 'default' in limit or 'defaultRequest' in limit:
                    has_defaults = True
                    break
        if not has_defaults:
            issues.append({
                'type': 'no_defaults',
                'message': 'LimitRange has no default resource limits'
            })

    return {
        'namespace': namespace,
        'has_quota': len(ns_quotas) > 0,
        'has_limitrange': len(ns_limitranges) > 0,
        'quota_count': len(ns_quotas),
        'limitrange_count': len(ns_limitranges),
        'quotas': quota_analyses,
        'issues': issues,
    }


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
        description='Audit Kubernetes ResourceQuota and LimitRange policies'
    )
    parser.add_argument('-n', '--namespace', help='Namespace to audit')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed quota info')
    parser.add_argument('-w', '--warn-only', action='store_true', help='Only show namespaces with issues')
    parser.add_argument('--warn-threshold', type=float, default=80.0, help='Utilization warning threshold (default: 80%%)')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    if not context.check_tool('kubectl'):
        output.error('kubectl not found in PATH')
        return 2

    try:
        namespaces = get_namespaces(context, opts.namespace)
        quotas = get_resource_quotas(context, opts.namespace)
        limit_ranges = get_limit_ranges(context, opts.namespace)
    except Exception as e:
        output.error(f'Failed to get cluster data: {e}')
        return 2

    results = []
    for namespace in namespaces:
        # Skip system namespaces unless explicitly requested
        if not opts.namespace and namespace in SYSTEM_NAMESPACES:
            continue

        result = audit_namespace(namespace, quotas, limit_ranges, opts.warn_threshold)

        if opts.warn_only and not result['issues']:
            continue

        results.append(result)

    # Calculate summary
    total_namespaces = len(results)
    namespaces_with_issues = sum(1 for r in results if r['issues'])
    namespaces_without_quota = sum(1 for r in results if not r['has_quota'])
    namespaces_without_limitrange = sum(1 for r in results if not r['has_limitrange'])

    result_data = {
        'namespaces': results,
        'summary': {
            'total_namespaces': total_namespaces,
            'namespaces_with_issues': namespaces_with_issues,
            'namespaces_without_quota': namespaces_without_quota,
            'namespaces_without_limitrange': namespaces_without_limitrange,
        }
    }

    output.emit(result_data)
    output.set_summary(f"{total_namespaces} namespaces, {namespaces_with_issues} with issues")

    has_issues = any(r['issues'] for r in results)
    return 1 if has_issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
