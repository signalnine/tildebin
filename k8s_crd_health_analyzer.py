#!/usr/bin/env python3
"""
Analyze Kubernetes Custom Resource Definition (CRD) health and usage.

This script monitors CRDs and their associated custom resources, detecting:
- CRDs with no associated custom resources (potentially unused)
- CRDs missing conversion webhooks when multiple versions exist
- CRDs with deprecated API versions (v1beta1)
- Custom resources counts and distribution across namespaces
- CRDs without established/served status

Useful for managing clusters with many operators (Prometheus, Cert-Manager, etc.)
and ensuring CRD hygiene in large-scale Kubernetes deployments.

Exit codes:
    0 - All CRDs healthy, no issues detected
    1 - One or more CRDs have warnings or issues
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys


def run_kubectl(args):
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


def get_crds():
    """Get all CRDs in JSON format."""
    output = run_kubectl(['get', 'crds', '-o', 'json'])
    return json.loads(output)


def get_custom_resources(crd_name, plural, group):
    """Get count of custom resources for a CRD."""
    try:
        # Use the full resource name (plural.group)
        resource = f"{plural}.{group}"
        result = subprocess.run(
            ['kubectl', 'get', resource, '--all-namespaces', '-o', 'json'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return len(data.get('items', []))
        return 0
    except Exception:
        return 0


def analyze_crd(crd, check_resources=False):
    """Analyze a single CRD and return health info."""
    metadata = crd.get('metadata', {})
    spec = crd.get('spec', {})
    status = crd.get('status', {})

    name = metadata.get('name', 'unknown')
    group = spec.get('group', '')
    scope = spec.get('scope', 'Namespaced')
    names = spec.get('names', {})
    plural = names.get('plural', '')
    kind = names.get('kind', '')

    # Get versions info
    versions = spec.get('versions', [])
    version_names = [v.get('name', '') for v in versions]
    served_versions = [v.get('name', '') for v in versions if v.get('served', False)]
    storage_version = next((v.get('name', '') for v in versions if v.get('storage', False)), '')

    # Check conditions
    conditions = status.get('conditions', [])
    established = False
    names_accepted = False

    for condition in conditions:
        cond_type = condition.get('type', '')
        cond_status = condition.get('status', '')
        if cond_type == 'Established' and cond_status == 'True':
            established = True
        if cond_type == 'NamesAccepted' and cond_status == 'True':
            names_accepted = True

    # Detect issues
    issues = []
    is_healthy = True

    # Check if CRD is established
    if not established:
        issues.append("CRD not established")
        is_healthy = False

    # Check for names conflicts
    if not names_accepted:
        issues.append("CRD names not accepted (possible conflict)")
        is_healthy = False

    # Check for multiple versions without conversion webhook
    conversion = spec.get('conversion', {})
    conversion_strategy = conversion.get('strategy', 'None')

    if len(served_versions) > 1 and conversion_strategy == 'None':
        issues.append(f"Multiple served versions ({', '.join(served_versions)}) without conversion webhook")

    # Check for deprecated v1beta1 versions
    if any('v1beta1' in v for v in version_names):
        issues.append("Contains deprecated v1beta1 version")

    # Check for no storage version
    if not storage_version:
        issues.append("No storage version defined")
        is_healthy = False

    # Get resource count if requested
    resource_count = 0
    if check_resources:
        resource_count = get_custom_resources(name, plural, group)
        if resource_count == 0:
            issues.append("No custom resources exist (potentially unused CRD)")

    return {
        'name': name,
        'group': group,
        'kind': kind,
        'scope': scope,
        'versions': version_names,
        'served_versions': served_versions,
        'storage_version': storage_version,
        'conversion_strategy': conversion_strategy,
        'established': established,
        'names_accepted': names_accepted,
        'resource_count': resource_count,
        'issues': issues,
        'healthy': is_healthy and len(issues) == 0
    }


def print_results(results, output_format, warn_only, verbose):
    """Print analysis results."""
    has_issues = False

    if output_format == 'json':
        output = []
        for result in results:
            if not warn_only or result['issues']:
                output.append(result)
                if result['issues']:
                    has_issues = True
        print(json.dumps(output, indent=2))

    else:  # plain format
        healthy_count = 0
        issue_count = 0

        for result in results:
            if result['healthy'] and not result['issues']:
                healthy_count += 1
            else:
                issue_count += 1
                has_issues = True

            # Skip healthy if warn_only
            if warn_only and not result['issues']:
                continue

            status_marker = "OK" if result['healthy'] and not result['issues'] else "WARN"
            print(f"[{status_marker}] {result['name']}")

            if verbose or result['issues']:
                print(f"  Group: {result['group']}")
                print(f"  Kind: {result['kind']}")
                print(f"  Scope: {result['scope']}")
                print(f"  Versions: {', '.join(result['versions'])}")
                print(f"  Storage Version: {result['storage_version']}")
                print(f"  Conversion: {result['conversion_strategy']}")

                if result['resource_count'] > 0 or verbose:
                    print(f"  Resources: {result['resource_count']}")

                if result['issues']:
                    for issue in result['issues']:
                        print(f"  WARNING: {issue}")

                print()

        # Print summary
        total = healthy_count + issue_count
        print(f"Summary: {healthy_count}/{total} CRDs healthy, {issue_count} with warnings")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes Custom Resource Definition (CRD) health',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all CRDs
  %(prog)s --warn-only              # Show only CRDs with issues
  %(prog)s --check-resources        # Also check for unused CRDs
  %(prog)s --format json            # JSON output
  %(prog)s -v                       # Verbose output with all details

Exit codes:
  0 - All CRDs healthy
  1 - One or more CRDs have warnings
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show CRDs with issues'
    )

    parser.add_argument(
        '--check-resources', '-c',
        action='store_true',
        help='Check for unused CRDs (slower, queries each resource type)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed information for all CRDs'
    )

    parser.add_argument(
        '--group', '-g',
        help='Filter CRDs by API group (e.g., cert-manager.io)'
    )

    args = parser.parse_args()

    # Get all CRDs
    crds = get_crds()

    # Analyze each CRD
    results = []
    for crd in crds.get('items', []):
        # Filter by group if specified
        if args.group:
            crd_group = crd.get('spec', {}).get('group', '')
            if args.group not in crd_group:
                continue

        result = analyze_crd(crd, check_resources=args.check_resources)
        results.append(result)

    # Sort results: issues first, then by name
    results.sort(key=lambda x: (x['healthy'] and not x['issues'], x['name']))

    # Print results
    has_issues = print_results(results, args.format, args.warn_only, args.verbose)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
