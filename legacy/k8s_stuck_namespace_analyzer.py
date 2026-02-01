#!/usr/bin/env python3
"""
Analyze Kubernetes namespaces stuck in Terminating state.

Namespaces can become stuck in "Terminating" status due to:
- Finalizers that never complete
- Resources with dangling finalizers
- API resources that can't be deleted
- Webhooks blocking deletion
- Custom resources without proper cleanup

This script identifies stuck namespaces and diagnoses the root cause,
helping operators resolve deletion issues without manual investigation.

Useful for:
- Cluster cleanup and maintenance
- Debugging namespace deletion failures
- Identifying orphaned resources
- Pre-migration cluster hygiene checks

Exit codes:
    0 - No stuck namespaces found
    1 - Stuck namespaces detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from typing import Any, Dict, List, Optional


def run_kubectl(args: List[str], timeout: int = 30) -> Optional[str]:
    """Execute kubectl command and return output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/",
              file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print("Error: kubectl command timed out", file=sys.stderr)
        return None


def get_namespaces() -> List[Dict[str, Any]]:
    """Get all namespaces in JSON format."""
    output = run_kubectl(['get', 'namespaces', '-o', 'json'])
    if output is None:
        return []

    try:
        data = json.loads(output)
        return data.get('items', [])
    except json.JSONDecodeError:
        return []


def get_namespace_details(namespace: str) -> Optional[Dict[str, Any]]:
    """Get detailed namespace information."""
    output = run_kubectl(['get', 'namespace', namespace, '-o', 'json'])
    if output is None:
        return None

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def get_api_resources() -> List[str]:
    """Get list of namespaced API resources."""
    output = run_kubectl(['api-resources', '--namespaced=true', '-o', 'name'])
    if output is None:
        return []

    return [r.strip() for r in output.strip().split('\n') if r.strip()]


def get_resources_in_namespace(namespace: str, resource_type: str) -> List[Dict[str, Any]]:
    """Get all resources of a type in a namespace."""
    output = run_kubectl([
        'get', resource_type,
        '-n', namespace,
        '-o', 'json',
        '--ignore-not-found'
    ], timeout=10)

    if output is None or not output.strip():
        return []

    try:
        data = json.loads(output)
        return data.get('items', [])
    except json.JSONDecodeError:
        return []


def analyze_stuck_namespace(namespace: str, verbose: bool = False) -> Dict[str, Any]:
    """Analyze why a namespace is stuck in Terminating state."""
    ns_data = get_namespace_details(namespace)
    if ns_data is None:
        return {
            'namespace': namespace,
            'error': 'Could not fetch namespace details',
            'issues': [],
            'blocking_resources': [],
            'finalizers': []
        }

    metadata = ns_data.get('metadata', {})
    status = ns_data.get('status', {})
    spec = ns_data.get('spec', {})

    # Get namespace-level finalizers
    ns_finalizers = metadata.get('finalizers', [])
    spec_finalizers = spec.get('finalizers', [])
    all_finalizers = list(set(ns_finalizers + spec_finalizers))

    issues = []
    blocking_resources = []

    # Check for namespace-level finalizers
    if all_finalizers:
        issues.append({
            'type': 'namespace_finalizers',
            'description': f"Namespace has {len(all_finalizers)} finalizer(s)",
            'details': all_finalizers
        })

    # Check deletion timestamp
    deletion_timestamp = metadata.get('deletionTimestamp')
    if deletion_timestamp:
        issues.append({
            'type': 'deletion_pending',
            'description': f"Deletion initiated at {deletion_timestamp}",
            'details': deletion_timestamp
        })

    # Check conditions
    conditions = status.get('conditions', [])
    for condition in conditions:
        if condition.get('type') == 'NamespaceDeletionContentFailure':
            if condition.get('status') == 'True':
                issues.append({
                    'type': 'deletion_content_failure',
                    'description': condition.get('message', 'Content deletion failed'),
                    'details': condition.get('reason', 'Unknown')
                })
        elif condition.get('type') == 'NamespaceDeletionDiscoveryFailure':
            if condition.get('status') == 'True':
                issues.append({
                    'type': 'discovery_failure',
                    'description': condition.get('message', 'Discovery failed'),
                    'details': condition.get('reason', 'Unknown')
                })
        elif condition.get('type') == 'NamespaceFinalizersRemaining':
            if condition.get('status') == 'True':
                issues.append({
                    'type': 'finalizers_remaining',
                    'description': condition.get('message', 'Finalizers remaining'),
                    'details': condition.get('reason', 'Unknown')
                })
        elif condition.get('type') == 'NamespaceContentRemaining':
            if condition.get('status') == 'True':
                issues.append({
                    'type': 'content_remaining',
                    'description': condition.get('message', 'Content remaining'),
                    'details': condition.get('reason', 'Unknown')
                })

    # Find resources with finalizers in the namespace
    if verbose:
        common_resources = [
            'pods', 'services', 'deployments', 'replicasets',
            'statefulsets', 'daemonsets', 'jobs', 'cronjobs',
            'configmaps', 'secrets', 'persistentvolumeclaims',
            'serviceaccounts', 'roles', 'rolebindings',
            'networkpolicies', 'ingresses'
        ]

        for resource_type in common_resources:
            resources = get_resources_in_namespace(namespace, resource_type)
            for resource in resources:
                res_metadata = resource.get('metadata', {})
                res_finalizers = res_metadata.get('finalizers', [])
                res_name = res_metadata.get('name', 'unknown')

                if res_finalizers:
                    blocking_resources.append({
                        'kind': resource.get('kind', resource_type),
                        'name': res_name,
                        'finalizers': res_finalizers,
                        'deletion_timestamp': res_metadata.get('deletionTimestamp')
                    })

    return {
        'namespace': namespace,
        'phase': status.get('phase', 'Unknown'),
        'deletion_timestamp': deletion_timestamp,
        'finalizers': all_finalizers,
        'issues': issues,
        'blocking_resources': blocking_resources,
        'conditions': conditions
    }


def find_stuck_namespaces(namespaces: List[Dict[str, Any]]) -> List[str]:
    """Find namespaces that are stuck in Terminating state."""
    stuck = []
    for ns in namespaces:
        status = ns.get('status', {})
        metadata = ns.get('metadata', {})

        phase = status.get('phase', '')
        deletion_timestamp = metadata.get('deletionTimestamp')

        if phase == 'Terminating' or deletion_timestamp:
            stuck.append(metadata.get('name', 'unknown'))

    return stuck


def output_plain(results: List[Dict], verbose: bool):
    """Plain text output."""
    if not results:
        print("No stuck namespaces found.")
        return

    print(f"Found {len(results)} stuck namespace(s):\n")

    for result in results:
        print(f"=== {result['namespace']} ===")
        print(f"  Phase: {result.get('phase', 'Unknown')}")

        if result.get('deletion_timestamp'):
            print(f"  Deletion initiated: {result['deletion_timestamp']}")

        if result.get('finalizers'):
            print(f"  Namespace finalizers:")
            for f in result['finalizers']:
                print(f"    - {f}")

        if result.get('issues'):
            print("  Issues detected:")
            for issue in result['issues']:
                print(f"    [{issue['type']}] {issue['description']}")

        if result.get('blocking_resources'):
            print("  Resources with finalizers:")
            for res in result['blocking_resources']:
                finalizers_str = ', '.join(res['finalizers'])
                print(f"    - {res['kind']}/{res['name']}: {finalizers_str}")

        # Suggest remediation
        print("  Suggested remediation:")
        if result.get('finalizers'):
            print(f"    kubectl patch namespace {result['namespace']} -p "
                  "'{\"metadata\":{\"finalizers\":null}}' --type=merge")
        if result.get('blocking_resources'):
            print(f"    # Remove finalizers from blocking resources first")
            for res in result['blocking_resources'][:3]:
                print(f"    kubectl patch {res['kind'].lower()} {res['name']} "
                      f"-n {result['namespace']} -p "
                      "'{\"metadata\":{\"finalizers\":null}}' --type=merge")

        print()


def output_json(results: List[Dict]):
    """JSON output."""
    summary = {
        'total_stuck': len(results),
        'namespaces_with_finalizers': sum(1 for r in results if r.get('finalizers')),
        'namespaces_with_blocking_resources': sum(1 for r in results if r.get('blocking_resources'))
    }

    output = {
        'summary': summary,
        'stuck_namespaces': results
    }
    print(json.dumps(output, indent=2))


def output_table(results: List[Dict]):
    """Tabular output."""
    print(f"{'NAMESPACE':<30} {'PHASE':<15} {'FINALIZERS':<12} {'ISSUES':<8} {'BLOCKING'}")
    print("-" * 85)

    for result in results:
        ns = result['namespace'][:29]
        phase = result.get('phase', 'Unknown')[:14]
        finalizers = len(result.get('finalizers', []))
        issues = len(result.get('issues', []))
        blocking = len(result.get('blocking_resources', []))

        print(f"{ns:<30} {phase:<15} {finalizers:<12} {issues:<8} {blocking}")

    print(f"\nTotal: {len(results)} stuck namespace(s)")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes namespaces stuck in Terminating state",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Find all stuck namespaces
  %(prog)s

  # Detailed analysis with blocking resources
  %(prog)s --verbose

  # Analyze specific namespace
  %(prog)s --namespace my-stuck-namespace

  # Output as JSON for automation
  %(prog)s --format json

Common causes of stuck namespaces:
  - Finalizers on namespace or resources
  - Webhooks blocking deletion
  - CRD resources without proper cleanup
  - API server unable to reach resource controllers

Remediation (use with caution):
  # Remove namespace finalizers
  kubectl patch namespace <name> -p '{"metadata":{"finalizers":null}}' --type=merge

  # Force delete (after removing finalizers)
  kubectl delete namespace <name> --grace-period=0 --force

Exit codes:
  0 - No stuck namespaces found
  1 - Stuck namespaces detected
  2 - Usage error or kubectl not available
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Analyze specific namespace (default: check all)'
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
        help='Show detailed analysis including blocking resources'
    )

    args = parser.parse_args()

    # Get namespaces
    if args.namespace:
        # Check specific namespace
        ns_data = get_namespace_details(args.namespace)
        if ns_data is None:
            print(f"Error: Namespace '{args.namespace}' not found", file=sys.stderr)
            sys.exit(2)

        metadata = ns_data.get('metadata', {})
        status = ns_data.get('status', {})

        if status.get('phase') != 'Terminating' and not metadata.get('deletionTimestamp'):
            print(f"Namespace '{args.namespace}' is not stuck (phase: {status.get('phase', 'Active')})")
            sys.exit(0)

        stuck_namespaces = [args.namespace]
    else:
        # Check all namespaces
        namespaces = get_namespaces()
        if not namespaces:
            print("No namespaces found or unable to list namespaces.")
            sys.exit(0)

        stuck_namespaces = find_stuck_namespaces(namespaces)

    if not stuck_namespaces:
        print("No stuck namespaces found.")
        sys.exit(0)

    # Analyze each stuck namespace
    results = []
    for ns in stuck_namespaces:
        analysis = analyze_stuck_namespace(ns, args.verbose)
        results.append(analysis)

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results)
    else:
        output_plain(results, args.verbose)

    sys.exit(1 if results else 0)


if __name__ == '__main__':
    main()
