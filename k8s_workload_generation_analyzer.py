#!/usr/bin/env python3
"""
Analyze Kubernetes workload ownership and generation chains.

This script traces the ownership chain of pods and workloads to identify
what controller, operator, or user created them. Useful for:
- Understanding what's generating unexpected pods
- Compliance auditing (tracking workload origins)
- Troubleshooting operator-managed workloads
- Identifying orphaned resources without proper ownership

The script follows ownerReferences chains to build a complete picture
of workload provenance, from Pod -> ReplicaSet -> Deployment -> Operator.

Exit codes:
    0 - Success, no issues found
    1 - Issues found (orphaned workloads, unknown generators)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime


def run_kubectl(args):
    """Execute kubectl command and return JSON output"""
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
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/",
              file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_pods(namespace=None):
    """Get all pods with their metadata"""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output).get('items', [])


def get_resource(kind, name, namespace):
    """Get a specific resource by kind, name, and namespace"""
    cmd = ['get', kind.lower(), name, '-n', namespace, '-o', 'json']
    try:
        output = run_kubectl(cmd)
        return json.loads(output)
    except SystemExit:
        return None


def get_owner_chain(resource, namespace, visited=None):
    """
    Recursively trace the ownership chain of a resource.
    Returns a list of owners from immediate parent to root.
    """
    if visited is None:
        visited = set()

    chain = []
    owner_refs = resource.get('metadata', {}).get('ownerReferences', [])

    if not owner_refs:
        return chain

    for owner_ref in owner_refs:
        owner_key = f"{owner_ref['kind']}/{owner_ref['name']}"

        # Prevent infinite loops
        if owner_key in visited:
            continue
        visited.add(owner_key)

        owner_info = {
            'kind': owner_ref['kind'],
            'name': owner_ref['name'],
            'uid': owner_ref.get('uid', ''),
            'controller': owner_ref.get('controller', False),
        }

        # Try to get the owner resource for more details
        owner_resource = get_resource(owner_ref['kind'], owner_ref['name'], namespace)
        if owner_resource:
            owner_info['labels'] = owner_resource.get('metadata', {}).get('labels', {})
            owner_info['annotations'] = owner_resource.get('metadata', {}).get('annotations', {})

            # Recursively get parent owners
            parent_chain = get_owner_chain(owner_resource, namespace, visited)
            chain.append(owner_info)
            chain.extend(parent_chain)
        else:
            owner_info['status'] = 'not_found'
            chain.append(owner_info)

    return chain


def identify_generator(chain, pod):
    """
    Identify the ultimate generator/creator of a workload.
    Returns a dict with generator info.
    """
    if not chain:
        # No owner chain - could be standalone pod or orphaned
        created_by = pod.get('metadata', {}).get('annotations', {}).get(
            'kubernetes.io/created-by', '')

        if created_by:
            return {
                'type': 'annotation',
                'generator': 'unknown (from annotation)',
                'details': created_by[:100]
            }

        return {
            'type': 'standalone',
            'generator': 'direct_creation',
            'details': 'Pod created directly without controller'
        }

    # Get the root of the ownership chain
    root = chain[-1]
    root_kind = root['kind']

    # Known operator patterns
    operator_labels = root.get('labels', {})
    operator_annotations = root.get('annotations', {})

    # Check for common operator indicators
    generator_info = {
        'type': 'controller',
        'generator': root_kind,
        'name': root['name'],
        'details': ''
    }

    # Detect specific operators
    if 'app.kubernetes.io/managed-by' in operator_labels:
        generator_info['managed_by'] = operator_labels['app.kubernetes.io/managed-by']

    if 'helm.sh/chart' in operator_labels:
        generator_info['helm_chart'] = operator_labels['helm.sh/chart']
        generator_info['type'] = 'helm'

    if 'argocd.argoproj.io/instance' in operator_labels:
        generator_info['argocd_app'] = operator_labels['argocd.argoproj.io/instance']
        generator_info['type'] = 'argocd'

    if 'fluxcd.io/sync-checksum' in operator_annotations:
        generator_info['type'] = 'flux'

    # Check for operator-specific patterns
    for label_key in operator_labels:
        if 'operator' in label_key.lower():
            generator_info['operator_label'] = f"{label_key}={operator_labels[label_key]}"
            generator_info['type'] = 'operator'
            break

    return generator_info


def analyze_workloads(namespace=None, show_chain=False):
    """Analyze all workloads and their generation chains"""
    pods = get_pods(namespace)

    results = {
        'timestamp': datetime.now().isoformat(),
        'namespace_filter': namespace or 'all',
        'total_pods': len(pods),
        'workloads': [],
        'summary': {
            'by_generator_type': defaultdict(int),
            'by_root_kind': defaultdict(int),
            'orphaned': 0,
            'standalone': 0,
        }
    }

    for pod in pods:
        pod_name = pod['metadata']['name']
        pod_namespace = pod['metadata'].get('namespace', 'default')

        # Get ownership chain
        chain = get_owner_chain(pod, pod_namespace)

        # Identify generator
        generator = identify_generator(chain, pod)

        workload_info = {
            'pod_name': pod_name,
            'namespace': pod_namespace,
            'generator': generator,
            'chain_length': len(chain),
        }

        if show_chain:
            workload_info['ownership_chain'] = [
                {'kind': o['kind'], 'name': o['name']} for o in chain
            ]

        # Check for issues
        issues = []
        if generator['type'] == 'standalone':
            issues.append('no_controller')
            results['summary']['standalone'] += 1

        if any(o.get('status') == 'not_found' for o in chain):
            issues.append('orphaned_owner')
            results['summary']['orphaned'] += 1

        if issues:
            workload_info['issues'] = issues

        results['workloads'].append(workload_info)

        # Update summary
        results['summary']['by_generator_type'][generator['type']] += 1
        if chain:
            results['summary']['by_root_kind'][chain[-1]['kind']] += 1
        else:
            results['summary']['by_root_kind']['Pod (direct)'] += 1

    # Convert defaultdicts to regular dicts for JSON serialization
    results['summary']['by_generator_type'] = dict(results['summary']['by_generator_type'])
    results['summary']['by_root_kind'] = dict(results['summary']['by_root_kind'])

    return results


def output_plain(data, warn_only=False, verbose=False):
    """Output results in plain text format"""
    if not warn_only:
        print(f"Workload Generation Analysis")
        print(f"Namespace: {data['namespace_filter']}")
        print(f"Total Pods: {data['total_pods']}")
        print("=" * 60)
        print()

    # Summary
    if not warn_only:
        print("Generator Summary:")
        print("-" * 40)
        for gen_type, count in sorted(data['summary']['by_generator_type'].items()):
            print(f"  {gen_type}: {count}")
        print()

        print("Root Controller Types:")
        print("-" * 40)
        for kind, count in sorted(data['summary']['by_root_kind'].items()):
            print(f"  {kind}: {count}")
        print()

    # Issues
    issues_found = []
    for workload in data['workloads']:
        if 'issues' in workload:
            issues_found.append(workload)

    if issues_found:
        print("Issues Found:")
        print("-" * 60)
        for w in issues_found:
            print(f"  {w['namespace']}/{w['pod_name']}")
            print(f"    Issues: {', '.join(w['issues'])}")
            print(f"    Generator: {w['generator']['type']} - {w['generator'].get('name', 'N/A')}")
        print()
    elif not warn_only:
        print("No issues found - all workloads have proper ownership")

    # Verbose: show all workloads
    if verbose and not warn_only:
        print()
        print("All Workloads:")
        print("-" * 60)
        for w in data['workloads']:
            gen = w['generator']
            print(f"  {w['namespace']}/{w['pod_name']}")
            print(f"    Type: {gen['type']}, Generator: {gen.get('generator', 'N/A')}")
            if 'ownership_chain' in w:
                chain_str = ' -> '.join(
                    f"{o['kind']}/{o['name']}" for o in w['ownership_chain']
                )
                print(f"    Chain: Pod -> {chain_str}")
            print()


def output_json(data):
    """Output results in JSON format"""
    print(json.dumps(data, indent=2, default=str))


def output_table(data, warn_only=False):
    """Output results in table format"""
    print(f"{'Namespace':<20} {'Pod':<35} {'Generator':<15} {'Root Kind':<15} {'Issues':<15}")
    print("=" * 100)

    for w in data['workloads']:
        if warn_only and 'issues' not in w:
            continue

        ns = w['namespace'][:19]
        pod = w['pod_name'][:34]
        gen_type = w['generator']['type'][:14]

        # Get root kind from chain
        if 'ownership_chain' in w and w['ownership_chain']:
            root_kind = w['ownership_chain'][-1]['kind'][:14]
        elif w['chain_length'] > 0:
            root_kind = w['generator'].get('generator', 'Unknown')[:14]
        else:
            root_kind = 'Pod (direct)'[:14]

        issues = ', '.join(w.get('issues', []))[:14] or '-'

        print(f"{ns:<20} {pod:<35} {gen_type:<15} {root_kind:<15} {issues:<15}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes workload ownership and generation chains',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Analyze all namespaces
  %(prog)s -n kube-system               # Analyze specific namespace
  %(prog)s --format json                # JSON output for automation
  %(prog)s -w                           # Only show workloads with issues
  %(prog)s -v --show-chain              # Verbose with full ownership chains

Exit codes:
  0 - Success, no issues found
  1 - Issues found (orphaned workloads, standalone pods)
  2 - kubectl not available or error
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to analyze (default: all namespaces)'
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
        help='Show detailed information for all workloads'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show workloads with issues'
    )

    parser.add_argument(
        '--show-chain',
        action='store_true',
        help='Include full ownership chain in output'
    )

    args = parser.parse_args()

    # Analyze workloads
    data = analyze_workloads(
        namespace=args.namespace,
        show_chain=args.show_chain or args.verbose
    )

    # Output results
    if args.format == 'json':
        output_json(data)
    elif args.format == 'table':
        output_table(data, warn_only=args.warn_only)
    else:
        output_plain(data, warn_only=args.warn_only, verbose=args.verbose)

    # Determine exit code
    has_issues = (data['summary']['orphaned'] > 0 or
                  data['summary']['standalone'] > 0)

    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
