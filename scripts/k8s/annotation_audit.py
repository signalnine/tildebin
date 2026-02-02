#!/usr/bin/env python3
# boxctl:
#   category: k8s/compliance
#   tags: [annotations, compliance, audit, governance, kubernetes]
#   requires: [kubectl]
#   brief: Audit pod annotations for compliance and consistency
#   privilege: user
#   related: [security_audit, image_registry]

"""
Audit Kubernetes pod annotations for compliance and consistency.

This script checks pods across a cluster for required annotations and
identifies potential issues:
- Pods missing required annotations (logging, monitoring, owner, etc.)
- Pods with deprecated or invalid annotation values
- Inconsistent annotation patterns across deployments
- Annotation value validation against regex patterns

Useful for:
- Ensuring compliance with organizational standards
- Validating monitoring/logging configuration
- Tracking ownership and cost allocation
- Enforcing security policies via annotations

Exit codes:
    0 - All pods have required annotations
    1 - Some pods are missing required annotations or have invalid values
    2 - Usage error or kubectl not available
"""

import argparse
import json
import re
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


# System namespaces often excluded from audits
SYSTEM_NAMESPACES = {'kube-system', 'kube-public', 'kube-node-lease'}


def parse_required_annotations(annotations_str: str | None) -> dict:
    """Parse comma-separated list of required annotations.

    Format: key1,key2=regex,key3
    If =regex is provided, the annotation value must match the regex.
    """
    required = {}
    if not annotations_str:
        return required

    for item in annotations_str.split(','):
        item = item.strip()
        if '=' in item:
            key, pattern = item.split('=', 1)
            required[key.strip()] = pattern.strip()
        else:
            required[item] = None  # No validation pattern

    return required


def check_pod_annotations(pod: dict, required_annotations: dict, forbidden_annotations: list | None = None) -> dict:
    """Check if a pod has required annotations and valid values.

    Returns a dict with:
    - missing: list of missing annotation keys
    - invalid: list of annotations with invalid values
    - forbidden: list of forbidden annotations present
    """
    metadata = pod.get('metadata', {})
    annotations = metadata.get('annotations', {}) or {}

    issues = {
        'missing': [],
        'invalid': [],
        'forbidden': []
    }

    # Check required annotations
    for key, pattern in required_annotations.items():
        if key not in annotations:
            issues['missing'].append(key)
        elif pattern:
            # Validate value against regex pattern
            value = annotations[key]
            try:
                if not re.match(pattern, value):
                    issues['invalid'].append({
                        'key': key,
                        'value': value,
                        'expected_pattern': pattern
                    })
            except re.error:
                pass  # Invalid regex, skip validation

    # Check forbidden annotations
    if forbidden_annotations:
        for key in forbidden_annotations:
            if key in annotations:
                issues['forbidden'].append(key)

    return issues


def analyze_pods(pods_data: dict, required_annotations: dict,
                 forbidden_annotations: list | None = None,
                 skip_system_namespaces: bool = True) -> dict:
    """Analyze all pods for annotation compliance."""
    pods = pods_data.get('items', [])

    results = {
        'total_pods': 0,
        'compliant_pods': 0,
        'non_compliant_pods': 0,
        'issues_by_namespace': defaultdict(list),
        'annotation_stats': defaultdict(lambda: {'present': 0, 'missing': 0}),
        'issues': []
    }

    for pod in pods:
        metadata = pod.get('metadata', {})
        namespace = metadata.get('namespace', 'default')
        pod_name = metadata.get('name', 'unknown')

        # Skip system namespaces if requested
        if skip_system_namespaces and namespace in SYSTEM_NAMESPACES:
            continue

        results['total_pods'] += 1

        # Check annotations
        issues = check_pod_annotations(pod, required_annotations, forbidden_annotations)

        # Update stats
        annotations = metadata.get('annotations', {}) or {}
        for key in required_annotations:
            if key in annotations:
                results['annotation_stats'][key]['present'] += 1
            else:
                results['annotation_stats'][key]['missing'] += 1

        # Record issues
        has_issues = issues['missing'] or issues['invalid'] or issues['forbidden']

        if has_issues:
            results['non_compliant_pods'] += 1
            issue_record = {
                'namespace': namespace,
                'pod': pod_name,
                'missing': issues['missing'],
                'invalid': issues['invalid'],
                'forbidden': issues['forbidden']
            }
            results['issues'].append(issue_record)
            results['issues_by_namespace'][namespace].append(issue_record)
        else:
            results['compliant_pods'] += 1

    return results


def output_plain(results: dict, required_annotations: dict, verbose: bool = False, warn_only: bool = False) -> None:
    """Output results in plain text format."""
    print("Kubernetes Pod Annotation Audit")
    print("=" * 60)
    print()

    # Summary
    total = results['total_pods']
    compliant = results['compliant_pods']
    non_compliant = results['non_compliant_pods']

    print(f"Total Pods Audited: {total}")
    print(f"Compliant Pods: {compliant} ({compliant/total*100:.1f}%)" if total > 0 else "Compliant Pods: 0")
    print(f"Non-Compliant Pods: {non_compliant} ({non_compliant/total*100:.1f}%)" if total > 0 else "Non-Compliant Pods: 0")
    print()

    # Required annotations and coverage
    if required_annotations:
        print("Required Annotations Coverage:")
        for key in required_annotations:
            stats = results['annotation_stats'].get(key, {'present': 0, 'missing': 0})
            total_for_key = stats['present'] + stats['missing']
            if total_for_key > 0:
                coverage = stats['present'] / total_for_key * 100
                print(f"  {key}: {stats['present']}/{total_for_key} ({coverage:.1f}%)")
            else:
                print(f"  {key}: 0/0 (N/A)")
        print()

    # Issues by namespace
    if results['issues'] and (not warn_only or non_compliant > 0):
        print("Non-Compliant Pods by Namespace:")
        print("-" * 60)

        for namespace, issues in sorted(results['issues_by_namespace'].items()):
            print(f"\n[{namespace}] ({len(issues)} pod(s))")

            for issue in issues:
                print(f"  Pod: {issue['pod']}")
                if issue['missing']:
                    print(f"    Missing: {', '.join(issue['missing'])}")
                if issue['invalid']:
                    for inv in issue['invalid']:
                        print(f"    Invalid: {inv['key']}=\"{inv['value']}\" (expected pattern: {inv['expected_pattern']})")
                if issue['forbidden']:
                    print(f"    Forbidden: {', '.join(issue['forbidden'])}")

    # Status
    print()
    if non_compliant > 0:
        print(f"Status: ISSUES FOUND ({non_compliant} non-compliant pods)")
    else:
        print("Status: OK (all pods compliant)")


def output_json(results: dict) -> None:
    """Output results in JSON format."""
    # Convert defaultdict to regular dict for JSON serialization
    output = {
        'total_pods': results['total_pods'],
        'compliant_pods': results['compliant_pods'],
        'non_compliant_pods': results['non_compliant_pods'],
        'annotation_stats': dict(results['annotation_stats']),
        'issues': results['issues']
    }
    print(json.dumps(output, indent=2))


def output_table(results: dict, warn_only: bool = False) -> None:
    """Output results in table format."""
    if not results['issues']:
        if not warn_only:
            print(f"{'Namespace':<25} {'Pod':<35} {'Issues':<10}")
            print("-" * 70)
            print("(All pods are compliant)")
        return

    print(f"{'Namespace':<25} {'Pod':<35} {'Missing':<8} {'Invalid':<8}")
    print("-" * 76)

    for issue in sorted(results['issues'], key=lambda x: (x['namespace'], x['pod'])):
        print(f"{issue['namespace']:<25} {issue['pod'][:34]:<35} "
              f"{len(issue['missing']):<8} {len(issue['invalid']):<8}")


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all compliant, 1 = non-compliant pods found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes pod annotations for compliance"
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to audit (default: all non-system namespaces)"
    )
    parser.add_argument(
        "--required",
        help='Comma-separated list of required annotations. '
             'Use key=regex to validate values (e.g., "owner=team-.*")'
    )
    parser.add_argument(
        "--forbidden",
        help="Comma-separated list of forbidden annotations"
    )
    parser.add_argument(
        "--include-system",
        action="store_true",
        help="Include system namespaces (kube-system, etc.) in audit"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if there are non-compliant pods"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Parse required annotations
    required_annotations = parse_required_annotations(opts.required)

    if not required_annotations:
        output.error("At least one required annotation must be specified with --required")
        return 2

    # Parse forbidden annotations
    forbidden_annotations = None
    if opts.forbidden:
        forbidden_annotations = [a.strip() for a in opts.forbidden.split(',')]

    # Build namespace args
    ns_args = ["-n", opts.namespace] if opts.namespace else ["--all-namespaces"]

    # Get pods
    try:
        result = context.run(["kubectl", "get", "pods", "-o", "json"] + ns_args)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    # Analyze pods
    results = analyze_pods(
        pods_data,
        required_annotations,
        forbidden_annotations,
        skip_system_namespaces=not opts.include_system
    )

    # Output results
    if opts.format == 'json':
        output_json(results)
    elif opts.format == 'table':
        output_table(results, opts.warn_only)
    else:
        output_plain(results, required_annotations, opts.verbose, opts.warn_only)

    # Summary
    output.set_summary(
        f"total={results['total_pods']}, compliant={results['compliant_pods']}, "
        f"non_compliant={results['non_compliant_pods']}"
    )

    # Exit with appropriate code
    return 1 if results['non_compliant_pods'] > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
