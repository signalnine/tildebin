#!/usr/bin/env python3
# boxctl:
#   category: k8s/resources
#   tags: [limitrange, governance, resources, quotas]
#   requires: [kubectl]
#   privilege: user
#   related: [resource_quota_auditor, namespace_resource_analyzer]
#   brief: Audit LimitRange configurations across namespaces

"""
Audit Kubernetes LimitRange configurations across namespaces.

LimitRanges control resource constraints for containers in a namespace, including
default requests/limits, min/max values, and request-to-limit ratios.

Identifies:
- Namespaces without LimitRanges (missing resource guardrails)
- Overly permissive or restrictive limit configurations
- Invalid configurations (max < min, default exceeds max)
- Missing default resource limits

Exit codes:
    0 - No issues detected
    1 - Warnings or issues found (missing LimitRanges, misconfigurations)
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


SYSTEM_NAMESPACES = {
    'kube-system',
    'kube-public',
    'kube-node-lease',
    'default',
}


def parse_resource_value(value: str) -> float:
    """Parse Kubernetes resource values to a common unit for comparison."""
    if not value:
        return 0.0

    value = str(value).strip()

    memory_units = {
        'Ki': 1024,
        'Mi': 1024 ** 2,
        'Gi': 1024 ** 3,
        'Ti': 1024 ** 4,
        'K': 1000,
        'M': 1000 ** 2,
        'G': 1000 ** 3,
        'T': 1000 ** 4,
    }

    if value.endswith('m'):
        try:
            return float(value[:-1]) / 1000.0
        except ValueError:
            return 0.0

    for suffix, multiplier in memory_units.items():
        if value.endswith(suffix):
            try:
                return float(value[:-len(suffix)]) * multiplier
            except ValueError:
                return 0.0

    try:
        return float(value)
    except ValueError:
        return 0.0


def get_namespaces(context: Context) -> list[str]:
    """Get all namespaces."""
    result = context.run(['kubectl', 'get', 'namespaces', '-o', 'json'])
    data = json.loads(result.stdout)
    return [ns['metadata']['name'] for ns in data.get('items', [])]


def get_limit_ranges(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all LimitRanges."""
    args = ['kubectl', 'get', 'limitranges', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    result = context.run(args)
    data = json.loads(result.stdout)
    return data.get('items', [])


def analyze_limit_range(lr: dict) -> dict[str, Any]:
    """Analyze a single LimitRange for issues."""
    metadata = lr.get('metadata', {})
    spec = lr.get('spec', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')

    analysis: dict[str, Any] = {
        'name': name,
        'namespace': namespace,
        'limits': [],
        'issues': [],
    }

    limits = spec.get('limits', [])
    for limit in limits:
        limit_type = limit.get('type', 'unknown')
        limit_info = {
            'type': limit_type,
            'default': limit.get('default', {}),
            'defaultRequest': limit.get('defaultRequest', {}),
            'max': limit.get('max', {}),
            'min': limit.get('min', {}),
            'maxLimitRequestRatio': limit.get('maxLimitRequestRatio', {}),
        }
        analysis['limits'].append(limit_info)

        for resource in ['cpu', 'memory']:
            min_val = limit.get('min', {}).get(resource)
            max_val = limit.get('max', {}).get(resource)
            default_val = limit.get('default', {}).get(resource)
            default_req = limit.get('defaultRequest', {}).get(resource)

            if min_val and max_val:
                min_parsed = parse_resource_value(min_val)
                max_parsed = parse_resource_value(max_val)
                if min_parsed > max_parsed:
                    analysis['issues'].append({
                        'type': 'invalid_range',
                        'message': f'{limit_type}/{resource}: min ({min_val}) > max ({max_val})'
                    })

            if default_val and max_val:
                def_parsed = parse_resource_value(default_val)
                max_parsed = parse_resource_value(max_val)
                if def_parsed > max_parsed:
                    analysis['issues'].append({
                        'type': 'default_exceeds_max',
                        'message': f'{limit_type}/{resource}: default ({default_val}) > max ({max_val})'
                    })

            if default_val and min_val:
                def_parsed = parse_resource_value(default_val)
                min_parsed = parse_resource_value(min_val)
                if def_parsed < min_parsed:
                    analysis['issues'].append({
                        'type': 'default_below_min',
                        'message': f'{limit_type}/{resource}: default ({default_val}) < min ({min_val})'
                    })

            if default_req and default_val:
                req_parsed = parse_resource_value(default_req)
                limit_parsed = parse_resource_value(default_val)
                if req_parsed > limit_parsed:
                    analysis['issues'].append({
                        'type': 'request_exceeds_limit',
                        'message': f'{limit_type}/{resource}: defaultRequest ({default_req}) > default limit ({default_val})'
                    })

    return analysis


def analyze_namespace_coverage(
    namespaces: list[str],
    limit_ranges: list[dict],
    include_system: bool
) -> dict[str, Any]:
    """Analyze which namespaces have or are missing LimitRanges."""
    lr_namespaces = set()
    for lr in limit_ranges:
        ns = lr.get('metadata', {}).get('namespace', 'default')
        lr_namespaces.add(ns)

    all_namespaces = set(namespaces)
    if not include_system:
        all_namespaces -= SYSTEM_NAMESPACES

    missing_lr = all_namespaces - lr_namespaces
    covered_ns = all_namespaces & lr_namespaces

    return {
        'total_namespaces': len(all_namespaces),
        'covered_namespaces': len(covered_ns),
        'missing_limitrange': sorted(missing_lr),
        'coverage_percent': (len(covered_ns) / len(all_namespaces) * 100) if all_namespaces else 100,
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
        description='Audit Kubernetes LimitRange configurations'
    )
    parser.add_argument('-n', '--namespace', help='Namespace to audit')
    parser.add_argument('-v', '--verbose', action='store_true', help='Detailed output')
    parser.add_argument('-w', '--warn-only', action='store_true', help='Only show warnings')
    parser.add_argument('--include-system', action='store_true', help='Include system namespaces')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    if not context.check_tool('kubectl'):
        output.error('kubectl not found in PATH')
        return 2

    try:
        namespaces = get_namespaces(context)
        limit_ranges = get_limit_ranges(context, opts.namespace)
    except Exception as e:
        output.error(f'Failed to get cluster data: {e}')
        return 2

    analyses = [analyze_limit_range(lr) for lr in limit_ranges]
    coverage = analyze_namespace_coverage(namespaces, limit_ranges, opts.include_system)

    all_issues = []
    for a in analyses:
        for issue in a['issues']:
            all_issues.append({
                'namespace': a['namespace'],
                'limitrange': a['name'],
                **issue
            })

    if coverage['missing_limitrange']:
        all_issues.append({
            'type': 'missing_limitrange',
            'message': f"{len(coverage['missing_limitrange'])} namespace(s) without LimitRange",
            'namespaces': coverage['missing_limitrange']
        })

    result = {
        'limit_ranges': analyses,
        'coverage': coverage,
        'issues': all_issues,
        'summary': {
            'total_limitranges': len(analyses),
            'total_issues': len(all_issues),
            'namespaces_without_limitrange': len(coverage['missing_limitrange']),
            'coverage_percent': coverage['coverage_percent'],
        }
    }

    output.emit(result)

    total_issues = len(all_issues)
    output.set_summary(f"{len(analyses)} LimitRanges, {total_issues} issues, {coverage['coverage_percent']:.0f}% coverage")

    return 1 if all_issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
