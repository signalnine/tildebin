#!/usr/bin/env python3
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
import subprocess
import sys
from collections import defaultdict


def run_kubectl(args):
    """Execute kubectl command and return output."""
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


def get_pods(namespace=None):
    """Get pods in JSON format."""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output)


def parse_required_annotations(annotations_str):
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


def check_pod_annotations(pod, required_annotations, forbidden_annotations=None):
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


def analyze_pods(pods_data, required_annotations, forbidden_annotations=None,
                 skip_system_namespaces=True):
    """Analyze all pods for annotation compliance."""
    pods = pods_data.get('items', [])

    system_namespaces = {'kube-system', 'kube-public', 'kube-node-lease'}

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
        if skip_system_namespaces and namespace in system_namespaces:
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


def output_plain(results, required_annotations, verbose=False, warn_only=False):
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


def output_json(results):
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


def output_table(results, warn_only=False):
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


# Common annotation keys used in Kubernetes environments
COMMON_ANNOTATIONS = {
    'owner': 'app.kubernetes.io/owner',
    'team': 'app.kubernetes.io/team',
    'cost-center': 'app.kubernetes.io/cost-center',
    'description': 'kubernetes.io/description',
    'prometheus-scrape': 'prometheus.io/scrape',
    'prometheus-port': 'prometheus.io/port',
    'prometheus-path': 'prometheus.io/path',
    'log-format': 'logging.kubernetes.io/format',
    'sidecar-inject': 'sidecar.istio.io/inject',
}


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes pod annotations for compliance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check for owner annotation on all pods
  %(prog)s --required app.kubernetes.io/owner

  # Check multiple required annotations
  %(prog)s --required "app.kubernetes.io/owner,prometheus.io/scrape"

  # Validate annotation values with regex patterns
  %(prog)s --required "app.kubernetes.io/owner=team-.*,prometheus.io/scrape=(true|false)"

  # Check specific namespace
  %(prog)s -n production --required "app.kubernetes.io/owner"

  # Include system namespaces in audit
  %(prog)s --include-system --required "app.kubernetes.io/owner"

  # Check for forbidden annotations
  %(prog)s --forbidden "deprecated.example.com/old-config"

  # JSON output for automation
  %(prog)s --format json --required "app.kubernetes.io/owner"

Common annotation keys:
  - app.kubernetes.io/owner       Owner team/individual
  - app.kubernetes.io/team        Team responsible
  - app.kubernetes.io/cost-center Cost allocation
  - prometheus.io/scrape          Enable Prometheus scraping
  - prometheus.io/port            Prometheus metrics port
  - sidecar.istio.io/inject       Istio sidecar injection

Exit codes:
  0 - All pods have required annotations
  1 - Some pods are missing required annotations
  2 - Usage error or kubectl not available
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to audit (default: all non-system namespaces)'
    )

    parser.add_argument(
        '--required',
        help='Comma-separated list of required annotations. '
             'Use key=regex to validate values (e.g., "owner=team-.*")'
    )

    parser.add_argument(
        '--forbidden',
        help='Comma-separated list of forbidden annotations'
    )

    parser.add_argument(
        '--include-system',
        action='store_true',
        help='Include system namespaces (kube-system, etc.) in audit'
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
        help='Only output if there are non-compliant pods'
    )

    args = parser.parse_args()

    # Parse required annotations
    required_annotations = parse_required_annotations(args.required)

    if not required_annotations:
        print("Error: At least one required annotation must be specified with --required",
              file=sys.stderr)
        print("Example: --required app.kubernetes.io/owner", file=sys.stderr)
        sys.exit(2)

    # Parse forbidden annotations
    forbidden_annotations = None
    if args.forbidden:
        forbidden_annotations = [a.strip() for a in args.forbidden.split(',')]

    # Get pods
    pods_data = get_pods(args.namespace)

    # Analyze pods
    results = analyze_pods(
        pods_data,
        required_annotations,
        forbidden_annotations,
        skip_system_namespaces=not args.include_system
    )

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, required_annotations, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if results['non_compliant_pods'] > 0 else 0)


if __name__ == '__main__':
    main()
