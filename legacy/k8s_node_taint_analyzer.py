#!/usr/bin/env python3
"""
Analyze Kubernetes node taints and their impact on pod scheduling.

This script examines node taints across a Kubernetes cluster and identifies:
- Nodes with taints that prevent scheduling (NoSchedule, NoExecute)
- Nodes with PreferNoSchedule taints (soft constraints)
- Pods that tolerate specific taints
- Workload distribution on tainted vs untainted nodes
- Orphaned taints (taints with no matching tolerations)

Useful for managing large-scale baremetal clusters where nodes are frequently
tainted for maintenance, hardware issues, or specialized workloads (GPU, high-memory, etc.).

Exit codes:
    0 - No taint-related issues detected
    1 - Issues found (nodes with blocking taints, imbalanced scheduling)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


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


def get_nodes():
    """Get all nodes in JSON format."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    return json.loads(output)


def get_all_pods():
    """Get all pods in JSON format."""
    output = run_kubectl(['get', 'pods', '--all-namespaces', '-o', 'json'])
    return json.loads(output)


def parse_taints(node):
    """Extract taints from a node."""
    spec = node.get('spec', {})
    return spec.get('taints', [])


def parse_tolerations(pod):
    """Extract tolerations from a pod."""
    spec = pod.get('spec', {})
    tolerations = []
    for container_tolerations in spec.get('tolerations', []):
        tolerations.append(container_tolerations)
    return tolerations


def taint_blocks_scheduling(taint):
    """Check if a taint blocks pod scheduling."""
    effect = taint.get('effect', '')
    return effect in ['NoSchedule', 'NoExecute']


def taint_prefers_no_schedule(taint):
    """Check if a taint is a soft constraint."""
    return taint.get('effect', '') == 'PreferNoSchedule'


def toleration_matches_taint(toleration, taint):
    """Check if a toleration matches a taint."""
    # Match on key
    if toleration.get('key') != taint.get('key'):
        # Check for empty key (matches all)
        if toleration.get('key') not in [None, '']:
            return False

    # Match on effect
    tol_effect = toleration.get('effect', '')
    taint_effect = taint.get('effect', '')
    if tol_effect and taint_effect and tol_effect != taint_effect:
        return False

    # Match on operator
    operator = toleration.get('operator', 'Equal')
    if operator == 'Exists':
        return True
    elif operator == 'Equal':
        return toleration.get('value') == taint.get('value')

    return False


def pod_tolerates_taint(pod, taint):
    """Check if a pod tolerates a specific taint."""
    tolerations = parse_tolerations(pod)
    for toleration in tolerations:
        if toleration_matches_taint(toleration, taint):
            return True
    return False


def analyze_taints(nodes_data, pods_data, warn_only=False):
    """Analyze node taints and their impact."""
    nodes = nodes_data.get('items', [])
    pods = pods_data.get('items', [])

    results = {
        'tainted_nodes': [],
        'untainted_nodes': [],
        'blocking_taints': [],
        'soft_taints': [],
        'pod_distribution': {
            'tainted': 0,
            'untainted': 0
        },
        'orphaned_taints': [],
        'issues_found': False
    }

    # Collect all taints across cluster
    all_taints = {}

    # Analyze nodes
    for node in nodes:
        node_name = node['metadata']['name']
        taints = parse_taints(node)

        if not taints:
            results['untainted_nodes'].append(node_name)
        else:
            node_info = {
                'name': node_name,
                'taints': taints,
                'blocking_count': 0,
                'soft_count': 0
            }

            for taint in taints:
                taint_key = f"{taint.get('key', '')}={taint.get('value', '')}"
                if taint_key not in all_taints:
                    all_taints[taint_key] = {
                        'taint': taint,
                        'nodes': [],
                        'tolerating_pods': 0
                    }
                all_taints[taint_key]['nodes'].append(node_name)

                if taint_blocks_scheduling(taint):
                    node_info['blocking_count'] += 1
                    results['blocking_taints'].append({
                        'node': node_name,
                        'key': taint.get('key', ''),
                        'value': taint.get('value', ''),
                        'effect': taint.get('effect', '')
                    })
                elif taint_prefers_no_schedule(taint):
                    node_info['soft_count'] += 1
                    results['soft_taints'].append({
                        'node': node_name,
                        'key': taint.get('key', ''),
                        'value': taint.get('value', ''),
                        'effect': taint.get('effect', '')
                    })

            results['tainted_nodes'].append(node_info)

    # Analyze pod distribution and tolerations
    for pod in pods:
        pod_name = pod['metadata'].get('name', 'unknown')
        namespace = pod['metadata'].get('namespace', 'default')
        node_name = pod['spec'].get('nodeName', '')

        if not node_name:
            continue

        # Check if pod is on tainted node
        is_on_tainted_node = any(
            tainted['name'] == node_name
            for tainted in results['tainted_nodes']
        )

        if is_on_tainted_node:
            results['pod_distribution']['tainted'] += 1

            # Count which taints this pod tolerates
            for taint_key, taint_info in all_taints.items():
                if node_name in taint_info['nodes']:
                    if pod_tolerates_taint(pod, taint_info['taint']):
                        taint_info['tolerating_pods'] += 1
        else:
            results['pod_distribution']['untainted'] += 1

    # Identify orphaned taints (no pods tolerate them)
    for taint_key, taint_info in all_taints.items():
        if taint_info['tolerating_pods'] == 0 and taint_blocks_scheduling(taint_info['taint']):
            results['orphaned_taints'].append({
                'key': taint_info['taint'].get('key', ''),
                'value': taint_info['taint'].get('value', ''),
                'effect': taint_info['taint'].get('effect', ''),
                'nodes': taint_info['nodes']
            })

    # Determine if issues found
    if warn_only:
        results['issues_found'] = (
            len(results['blocking_taints']) > 0 or
            len(results['orphaned_taints']) > 0
        )
    else:
        results['issues_found'] = (
            len(results['tainted_nodes']) > 0 or
            len(results['blocking_taints']) > 0 or
            len(results['orphaned_taints']) > 0
        )

    return results


def output_plain(results, verbose=False, warn_only=False):
    """Output results in plain text format."""
    print(f"Node Taint Analysis")
    print(f"=" * 60)
    print()

    # Summary
    total_nodes = len(results['tainted_nodes']) + len(results['untainted_nodes'])
    tainted_count = len(results['tainted_nodes'])
    print(f"Total Nodes: {total_nodes}")
    print(f"Tainted Nodes: {tainted_count}")
    print(f"Untainted Nodes: {len(results['untainted_nodes'])}")
    print()

    # Pod distribution
    total_pods = results['pod_distribution']['tainted'] + results['pod_distribution']['untainted']
    print(f"Pod Distribution:")
    print(f"  Pods on tainted nodes: {results['pod_distribution']['tainted']}")
    print(f"  Pods on untainted nodes: {results['pod_distribution']['untainted']}")
    print(f"  Total pods: {total_pods}")
    print()

    # Blocking taints
    if results['blocking_taints'] or not warn_only:
        print(f"Blocking Taints (NoSchedule/NoExecute): {len(results['blocking_taints'])}")
        if verbose and results['blocking_taints']:
            for taint in results['blocking_taints']:
                print(f"  - {taint['node']}: {taint['key']}={taint['value']} ({taint['effect']})")
        print()

    # Soft taints
    if results['soft_taints'] and verbose:
        print(f"Soft Taints (PreferNoSchedule): {len(results['soft_taints'])}")
        for taint in results['soft_taints']:
            print(f"  - {taint['node']}: {taint['key']}={taint['value']} ({taint['effect']})")
        print()

    # Orphaned taints
    if results['orphaned_taints']:
        print(f"WARNING: Orphaned Taints (no tolerating pods): {len(results['orphaned_taints'])}")
        for taint in results['orphaned_taints']:
            print(f"  - {taint['key']}={taint['value']} ({taint['effect']}) on nodes: {', '.join(taint['nodes'])}")
        print()

    # Tainted nodes details
    if verbose and results['tainted_nodes'] and not warn_only:
        print(f"Tainted Nodes Details:")
        for node_info in results['tainted_nodes']:
            print(f"  {node_info['name']}:")
            print(f"    Blocking taints: {node_info['blocking_count']}")
            print(f"    Soft taints: {node_info['soft_count']}")
            print(f"    Total taints: {len(node_info['taints'])}")
        print()

    # Status
    if results['issues_found']:
        print("Status: ISSUES DETECTED")
    else:
        print("Status: OK")


def output_json(results):
    """Output results in JSON format."""
    print(json.dumps(results, indent=2))


def output_table(results, warn_only=False):
    """Output results in table format."""
    print(f"{'Node':<30} {'Blocking':<10} {'Soft':<10} {'Total Taints':<15}")
    print("-" * 65)

    if not warn_only:
        for node_info in results['tainted_nodes']:
            print(f"{node_info['name']:<30} {node_info['blocking_count']:<10} "
                  f"{node_info['soft_count']:<10} {len(node_info['taints']):<15}")

    if results['blocking_taints'] and warn_only:
        print("\nBlocking Taints:")
        print(f"{'Node':<30} {'Key':<25} {'Effect':<15}")
        print("-" * 70)
        for taint in results['blocking_taints']:
            key_val = f"{taint['key']}={taint['value']}"
            print(f"{taint['node']:<30} {key_val:<25} {taint['effect']:<15}")

    if results['orphaned_taints']:
        print("\nOrphaned Taints (no tolerating pods):")
        print(f"{'Key':<25} {'Effect':<15} {'Node Count':<15}")
        print("-" * 55)
        for taint in results['orphaned_taints']:
            key_val = f"{taint['key']}={taint['value']}"
            print(f"{key_val:<25} {taint['effect']:<15} {len(taint['nodes']):<15}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes node taints and scheduling impact",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show all tainted nodes
  %(prog)s

  # Show only nodes with blocking taints
  %(prog)s --warn-only

  # Show detailed information
  %(prog)s --verbose

  # Output in JSON format
  %(prog)s --format json

  # Table format with warnings only
  %(prog)s --format table --warn-only
"""
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
        help='Show detailed information about all taints'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show nodes with blocking taints or orphaned taints'
    )

    args = parser.parse_args()

    # Get cluster data
    nodes_data = get_nodes()
    pods_data = get_all_pods()

    # Analyze taints
    results = analyze_taints(nodes_data, pods_data, args.warn_only)

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if results['issues_found'] else 0)


if __name__ == '__main__':
    main()
