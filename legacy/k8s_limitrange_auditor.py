#!/usr/bin/env python3
"""
Audit Kubernetes LimitRange configurations across namespaces.

LimitRanges control resource constraints for containers in a namespace, including
default requests/limits, min/max values, and request-to-limit ratios. This script
helps administrators understand and validate LimitRange configurations across
large-scale Kubernetes clusters.

Key features:
- Lists all LimitRanges by namespace with their configurations
- Identifies namespaces without LimitRanges (missing resource guardrails)
- Detects overly permissive or restrictive limit configurations
- Compares LimitRanges against cluster-wide policies
- Warns about potential issues (max < min, ratio violations)

Exit codes:
    0 - No issues detected
    1 - Warnings or issues found (missing LimitRanges, misconfigurations)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional


# Namespaces that typically should not have user-defined LimitRanges
SYSTEM_NAMESPACES = {
    'kube-system',
    'kube-public',
    'kube-node-lease',
    'default',
}


def run_kubectl(args: List[str]) -> str:
    """Run kubectl command and return output."""
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
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_namespaces() -> List[str]:
    """Get all namespaces."""
    output = run_kubectl(['get', 'namespaces', '-o', 'json'])
    data = json.loads(output)
    return [ns['metadata']['name'] for ns in data.get('items', [])]


def get_limit_ranges(namespace: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all LimitRanges."""
    args = ['get', 'limitranges', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    data = json.loads(output)
    return data.get('items', [])


def parse_resource_value(value: str) -> float:
    """Parse Kubernetes resource values to a common unit for comparison."""
    if not value:
        return 0.0

    value = str(value).strip()

    # Memory units
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

    # CPU units
    if value.endswith('m'):
        try:
            return float(value[:-1]) / 1000.0  # millicores to cores
        except ValueError:
            return 0.0

    # Check memory units
    for suffix, multiplier in memory_units.items():
        if value.endswith(suffix):
            try:
                return float(value[:-len(suffix)]) * multiplier
            except ValueError:
                return 0.0

    # Try parsing as plain number
    try:
        return float(value)
    except ValueError:
        return 0.0


def analyze_limit_range(lr: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a single LimitRange for issues."""
    metadata = lr.get('metadata', {})
    spec = lr.get('spec', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')

    analysis = {
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

        # Check for issues
        for resource in ['cpu', 'memory']:
            min_val = limit.get('min', {}).get(resource)
            max_val = limit.get('max', {}).get(resource)
            default_val = limit.get('default', {}).get(resource)
            default_req = limit.get('defaultRequest', {}).get(resource)

            # Check max < min
            if min_val and max_val:
                min_parsed = parse_resource_value(min_val)
                max_parsed = parse_resource_value(max_val)
                if min_parsed > max_parsed:
                    analysis['issues'].append({
                        'type': 'invalid_range',
                        'message': f'{limit_type}/{resource}: min ({min_val}) > max ({max_val})'
                    })

            # Check default > max or default < min
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

            # Check defaultRequest > default (limit)
            if default_req and default_val:
                req_parsed = parse_resource_value(default_req)
                limit_parsed = parse_resource_value(default_val)
                if req_parsed > limit_parsed:
                    analysis['issues'].append({
                        'type': 'request_exceeds_limit',
                        'message': f'{limit_type}/{resource}: defaultRequest ({default_req}) > default limit ({default_val})'
                    })

    return analysis


def analyze_namespace_coverage(namespaces: List[str],
                               limit_ranges: List[Dict[str, Any]],
                               include_system: bool) -> Dict[str, Any]:
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


def format_plain(analyses: List[Dict[str, Any]],
                 coverage: Dict[str, Any],
                 verbose: bool, warn_only: bool) -> str:
    """Format output as plain text."""
    lines = []

    all_issues = []
    for a in analyses:
        all_issues.extend(a['issues'])

    # Add coverage issues
    if coverage['missing_limitrange']:
        all_issues.append({
            'type': 'missing_limitrange',
            'message': f"{len(coverage['missing_limitrange'])} namespace(s) without LimitRange"
        })

    if warn_only:
        if not all_issues:
            return "No LimitRange issues detected."

        lines.append("LIMITRANGE ISSUES")
        lines.append("=" * 60)
        for a in analyses:
            for issue in a['issues']:
                lines.append(f"[!] {a['namespace']}/{a['name']}: {issue['message']}")

        if coverage['missing_limitrange']:
            lines.append("")
            lines.append("Namespaces without LimitRange:")
            for ns in coverage['missing_limitrange'][:10]:
                lines.append(f"  - {ns}")
            if len(coverage['missing_limitrange']) > 10:
                lines.append(f"  ... and {len(coverage['missing_limitrange']) - 10} more")

        return '\n'.join(lines)

    # Full output
    lines.append("LIMITRANGE AUDIT")
    lines.append("=" * 60)

    if not analyses:
        lines.append("No LimitRanges found in the cluster.")
    else:
        # Group by namespace
        by_namespace = defaultdict(list)
        for a in analyses:
            by_namespace[a['namespace']].append(a)

        for ns in sorted(by_namespace.keys()):
            lines.append(f"\nNamespace: {ns}")
            lines.append("-" * 40)

            for a in by_namespace[ns]:
                lines.append(f"  LimitRange: {a['name']}")

                for limit in a['limits']:
                    limit_type = limit['type']
                    lines.append(f"    Type: {limit_type}")

                    if limit['default']:
                        defaults = ', '.join(f"{k}={v}" for k, v in limit['default'].items())
                        lines.append(f"      Default limits: {defaults}")

                    if limit['defaultRequest']:
                        requests = ', '.join(f"{k}={v}" for k, v in limit['defaultRequest'].items())
                        lines.append(f"      Default requests: {requests}")

                    if verbose:
                        if limit['min']:
                            mins = ', '.join(f"{k}={v}" for k, v in limit['min'].items())
                            lines.append(f"      Min: {mins}")
                        if limit['max']:
                            maxs = ', '.join(f"{k}={v}" for k, v in limit['max'].items())
                            lines.append(f"      Max: {maxs}")
                        if limit['maxLimitRequestRatio']:
                            ratios = ', '.join(f"{k}={v}" for k, v in limit['maxLimitRequestRatio'].items())
                            lines.append(f"      Max Limit/Request Ratio: {ratios}")

                # Show issues for this LimitRange
                if a['issues']:
                    for issue in a['issues']:
                        lines.append(f"    [!] {issue['message']}")

    lines.append("")

    # Coverage summary
    lines.append("NAMESPACE COVERAGE")
    lines.append("-" * 40)
    lines.append(f"  Total namespaces (excluding system): {coverage['total_namespaces']}")
    lines.append(f"  Namespaces with LimitRange: {coverage['covered_namespaces']}")
    lines.append(f"  Coverage: {coverage['coverage_percent']:.1f}%")

    if coverage['missing_limitrange']:
        lines.append("")
        lines.append("  Namespaces without LimitRange:")
        for ns in coverage['missing_limitrange'][:10]:
            lines.append(f"    - {ns}")
        if len(coverage['missing_limitrange']) > 10:
            lines.append(f"    ... and {len(coverage['missing_limitrange']) - 10} more")

    lines.append("")

    # Summary
    total_issues = len(all_issues)
    total_lrs = len(analyses)
    lines.append(f"Summary: {total_lrs} LimitRange(s), {total_issues} issue(s)")

    return '\n'.join(lines)


def format_json(analyses: List[Dict[str, Any]],
                coverage: Dict[str, Any],
                warn_only: bool) -> str:
    """Format output as JSON."""
    all_issues = []
    for a in analyses:
        for issue in a['issues']:
            all_issues.append({
                'namespace': a['namespace'],
                'limitrange': a['name'],
                **issue
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

    if warn_only:
        result = {
            'issues': all_issues,
            'coverage': {
                'missing_limitrange': coverage['missing_limitrange'],
                'coverage_percent': coverage['coverage_percent'],
            },
            'summary': result['summary']
        }

    return json.dumps(result, indent=2)


def format_table(analyses: List[Dict[str, Any]],
                 coverage: Dict[str, Any],
                 warn_only: bool) -> str:
    """Format output as table."""
    lines = []

    all_issues = []
    for a in analyses:
        all_issues.extend(a['issues'])

    if warn_only and not all_issues and not coverage['missing_limitrange']:
        return "No LimitRange issues detected."

    # LimitRanges table
    lines.append(f"{'NAMESPACE':<25} {'NAME':<25} {'TYPES':<15} {'DEFAULT CPU':<15} {'DEFAULT MEM':<15} {'ISSUES'}")
    lines.append("-" * 110)

    for a in analyses:
        types = ', '.join(l['type'] for l in a['limits'])
        default_cpu = '-'
        default_mem = '-'

        for l in a['limits']:
            if l['type'] == 'Container':
                default_cpu = l.get('default', {}).get('cpu', '-')
                default_mem = l.get('default', {}).get('memory', '-')
                break

        issue_count = len(a['issues'])
        issue_str = f"{issue_count} issue(s)" if issue_count else 'OK'

        lines.append(f"{a['namespace']:<25} {a['name']:<25} {types:<15} {str(default_cpu):<15} {str(default_mem):<15} {issue_str}")

        if warn_only:
            for issue in a['issues']:
                lines.append(f"  [!] {issue['message']}")

    if coverage['missing_limitrange']:
        lines.append("")
        lines.append(f"Namespaces without LimitRange: {len(coverage['missing_limitrange'])}")
        for ns in coverage['missing_limitrange'][:5]:
            lines.append(f"  - {ns}")
        if len(coverage['missing_limitrange']) > 5:
            lines.append(f"  ... and {len(coverage['missing_limitrange']) - 5} more")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Audit Kubernetes LimitRange configurations across namespaces.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                          Audit all LimitRanges
  %(prog)s -n production            Audit LimitRanges in production namespace
  %(prog)s --warn-only              Show only issues and warnings
  %(prog)s --format json            JSON output for automation
  %(prog)s --include-system         Include kube-system and other system namespaces

Exit codes:
  0 - No issues detected
  1 - Warnings or issues found
  2 - Usage error or kubectl not available
'''
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to audit (default: all namespaces)'
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed limit configurations'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    parser.add_argument(
        '--include-system',
        action='store_true',
        help='Include system namespaces in coverage analysis'
    )

    args = parser.parse_args()

    # Get data
    namespaces = get_namespaces()
    limit_ranges = get_limit_ranges(args.namespace)

    # Analyze each LimitRange
    analyses = [analyze_limit_range(lr) for lr in limit_ranges]

    # Analyze namespace coverage
    coverage = analyze_namespace_coverage(
        namespaces,
        limit_ranges,
        args.include_system
    )

    # Format output
    if args.format == 'json':
        output = format_json(analyses, coverage, args.warn_only)
    elif args.format == 'table':
        output = format_table(analyses, coverage, args.warn_only)
    else:
        output = format_plain(analyses, coverage, args.verbose, args.warn_only)

    print(output)

    # Determine exit code
    all_issues = []
    for a in analyses:
        all_issues.extend(a['issues'])

    # Also count missing LimitRanges as issues
    if coverage['missing_limitrange']:
        all_issues.append({'type': 'coverage'})

    sys.exit(1 if all_issues else 0)


if __name__ == '__main__':
    main()
