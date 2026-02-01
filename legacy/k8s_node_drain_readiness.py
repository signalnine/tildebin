#!/usr/bin/env python3
"""
Kubernetes node drain readiness checker and orchestrator.

This script analyzes node drainability and manages the graceful evacuation of pods
when preparing a node for maintenance, upgrades, or decommissioning.

Features:
- Check if a node is safe to drain (pod constraints analysis)
- Identify pods that cannot be evicted (local storage, critical pods, PDB conflicts)
- Gracefully cordon and drain nodes with timeout handling
- Respect PodDisruptionBudgets (PDBs) for high-availability workloads
- Detect stateful workloads requiring manual intervention
- Provide dry-run mode for validation before actual draining
- Support for cluster-wide node readiness assessment

Exit codes:
    0 - Node is safe to drain / drain succeeded / readiness check passed
    1 - Node has issues preventing safe drain / drain failed / pod evictions pending
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime


def run_kubectl(args, namespace=None):
    """Run kubectl command and return output."""
    try:
        cmd = ['kubectl'] + args
        if namespace and '-n' not in args and '--namespace' not in args:
            cmd.extend(['-n', namespace])

        result = subprocess.run(
            cmd,
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
        return None


def run_kubectl_check(args):
    """Run kubectl and return returncode, stdout, stderr."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        sys.exit(2)


def get_node_pods(node_name):
    """Get all pods running on a specific node."""
    try:
        output = run_kubectl(['get', 'pods', '-A', '-o', 'json',
                             '--field-selector', f'spec.nodeName={node_name}'])
        if output:
            return json.loads(output).get('items', [])
    except (json.JSONDecodeError, subprocess.CalledProcessError):
        pass
    return []


def get_all_nodes():
    """Get all nodes in the cluster."""
    try:
        output = run_kubectl(['get', 'nodes', '-o', 'json'])
        if output:
            return json.loads(output).get('items', [])
    except (json.JSONDecodeError, subprocess.CalledProcessError):
        pass
    return []


def get_pod_disruption_budgets():
    """Get all PodDisruptionBudgets in cluster."""
    try:
        output = run_kubectl(['get', 'pdb', '-A', '-o', 'json'])
        if output:
            return json.loads(output).get('items', [])
    except (json.JSONDecodeError, subprocess.CalledProcessError):
        pass
    return []


def check_pod_evictable(pod, pdbs):
    """Check if a pod can be safely evicted."""
    issues = []
    pod_name = pod['metadata']['name']
    namespace = pod['metadata']['namespace']

    # Check for local storage
    volumes = pod['spec'].get('volumes', [])
    for vol in volumes:
        if vol.get('emptyDir'):
            issues.append("has emptyDir storage")
        if vol.get('hostPath'):
            issues.append("has hostPath storage")

    # Check for system critical pod annotations
    annotations = pod['metadata'].get('annotations', {})
    if annotations.get('scheduler.alpha.kubernetes.io/critical-pod') == 'true':
        issues.append("marked as critical pod")
    if 'critical' in annotations.get('kubectl.kubernetes.io/description', '').lower():
        issues.append("marked as critical via annotation")

    # Check pod phase and conditions
    pod_phase = pod['status'].get('phase', 'Unknown')
    if pod_phase in ['Failed', 'Unknown']:
        issues.append(f"pod phase is {pod_phase}")

    # Check for PDB conflicts
    for pdb in pdbs:
        pdb_ns = pdb['metadata']['namespace']
        pdb_selector = pdb['spec'].get('selector', {}).get('matchLabels', {})

        if pdb_ns == namespace:
            pod_labels = pod['metadata'].get('labels', {})
            if all(pod_labels.get(k) == v for k, v in pdb_selector.items()):
                min_available = pdb['spec'].get('minAvailable')
                max_unavailable = pdb['spec'].get('maxUnavailable')

                if min_available or max_unavailable:
                    issues.append(f"PDB constraint ({pdb['metadata']['name']})")

    # Check for stateful workload patterns
    owner_refs = pod['metadata'].get('ownerReferences', [])
    for owner in owner_refs:
        kind = owner.get('kind', '')
        if kind in ['StatefulSet', 'DaemonSet']:
            issues.append(f"managed by {kind}")

    return issues


def analyze_node_drainability(node_name, warn_only=False):
    """Analyze if a node can be safely drained."""
    pods = get_node_pods(node_name)
    pdbs = get_pod_disruption_budgets()

    issues_found = False
    results = {
        'node': node_name,
        'pod_count': len(pods),
        'pods': [],
        'eviction_warnings': 0,
        'critical_pods': 0,
        'timestamp': datetime.now().isoformat()
    }

    for pod in pods:
        pod_name = pod['metadata']['name']
        namespace = pod['metadata']['namespace']
        issues = check_pod_evictable(pod, pdbs)

        pod_info = {
            'name': pod_name,
            'namespace': namespace,
            'evictable': len(issues) == 0,
            'issues': issues if issues else []
        }

        if issues:
            issues_found = True
            results['eviction_warnings'] += 1
            if any('critical' in issue for issue in issues):
                results['critical_pods'] += 1

        if not warn_only or issues:
            results['pods'].append(pod_info)

    return results, issues_found


def cordon_node(node_name, dry_run=False):
    """Cordon a node to prevent new pod scheduling."""
    if dry_run:
        print(f"[DRY-RUN] Would cordon node: {node_name}")
        return True

    try:
        run_kubectl(['cordon', node_name])
        print(f"Cordoned node: {node_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error cordoning node {node_name}: {e}", file=sys.stderr)
        return False


def drain_node(node_name, grace_period=30, dry_run=False, force=False):
    """Drain a node by evicting all pods."""
    if dry_run:
        print(f"[DRY-RUN] Would drain node: {node_name}")
        print(f"[DRY-RUN] Grace period: {grace_period}s")
        return True

    cmd = ['drain', node_name,
           f'--grace-period={grace_period}',
           '--ignore-daemonsets',
           '--ignore-daemonsets']

    if force:
        cmd.extend(['--delete-emptydir-data', '--force'])

    try:
        run_kubectl(cmd)
        print(f"Drained node: {node_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error draining node {node_name}: {e}", file=sys.stderr)
        return False


def uncordon_node(node_name, dry_run=False):
    """Uncordon a node to allow new pod scheduling."""
    if dry_run:
        print(f"[DRY-RUN] Would uncordon node: {node_name}")
        return True

    try:
        run_kubectl(['uncordon', node_name])
        print(f"Uncordoned node: {node_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error uncordoning node {node_name}: {e}", file=sys.stderr)
        return False


def get_node_status(node_name):
    """Get current node status and cordoning state."""
    nodes = get_all_nodes()
    for node in nodes:
        if node['metadata']['name'] == node_name:
            spec = node['spec']
            status = node['status']

            return {
                'name': node_name,
                'cordoned': spec.get('unschedulable', False),
                'ready': any(c['type'] == 'Ready' and c['status'] == 'True'
                           for c in status.get('conditions', [])),
                'status': next((c['type'] for c in status.get('conditions', [])
                              if c['status'] != 'True'), 'Unknown'),
                'allocatable': status.get('allocatable', {}),
                'capacity': status.get('capacity', {})
            }
    return None


def format_plain_output(results):
    """Format results as plain text."""
    output = []
    output.append(f"Node: {results['node']}")
    output.append(f"Total pods: {results['pod_count']}")
    output.append(f"Eviction warnings: {results['eviction_warnings']}")
    output.append(f"Critical pods: {results['critical_pods']}")
    output.append("")

    if results['pods']:
        output.append("Pod Details:")
        for pod in results['pods']:
            status = "EVICTABLE" if pod['evictable'] else "NOT EVICTABLE"
            output.append(f"  {pod['namespace']}/{pod['name']} [{status}]")
            if pod['issues']:
                for issue in pod['issues']:
                    output.append(f"    - {issue}")

    return "\n".join(output)


def format_table_output(results):
    """Format results as table."""
    output = []
    output.append(f"\n{'Node':<30} {results['node']}")
    output.append(f"{'Total Pods':<30} {results['pod_count']}")
    output.append(f"{'Eviction Warnings':<30} {results['eviction_warnings']}")
    output.append(f"{'Critical Pods':<30} {results['critical_pods']}\n")

    if results['pods']:
        output.append(f"{'NAMESPACE/NAME':<50} {'EVICTABLE':<12} {'ISSUES'}")
        output.append("-" * 100)
        for pod in results['pods']:
            status = "✓" if pod['evictable'] else "✗"
            issues_str = ", ".join(pod['issues'][:1]) if pod['issues'] else "None"
            name = f"{pod['namespace']}/{pod['name']}"
            output.append(f"{name:<50} {status:<12} {issues_str}")

    return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check if a node is safe to drain
  k8s_node_drain_readiness.py node-1 --action check

  # Simulate draining without actually draining
  k8s_node_drain_readiness.py node-1 --action drain --dry-run

  # Cordon, drain, and show only problematic pods
  k8s_node_drain_readiness.py node-1 --action drain --warn-only

  # Drain with force flag for stateful workloads
  k8s_node_drain_readiness.py node-1 --action drain --force

  # Uncordon a node after maintenance
  k8s_node_drain_readiness.py node-1 --action uncordon

  # Check all nodes for drainability
  k8s_node_drain_readiness.py --action check-all --format json
        """
    )

    parser.add_argument('node', nargs='?', help='Node name to check/drain')
    parser.add_argument('--action', choices=['check', 'drain', 'uncordon', 'check-all'],
                       default='check',
                       help='Action to perform (default: check)')
    parser.add_argument('--format', '-f', choices=['plain', 'table', 'json'],
                       default='table',
                       help='Output format (default: table)')
    parser.add_argument('--warn-only', '-w', action='store_true',
                       help='Only show pods with eviction issues')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without making changes')
    parser.add_argument('--force', action='store_true',
                       help='Force drain including pods with emptyDir data')
    parser.add_argument('--grace-period', type=int, default=30,
                       help='Grace period for pod termination in seconds (default: 30)')

    args = parser.parse_args()

    # Validate required arguments
    if args.action != 'check-all' and not args.node:
        parser.error("node argument required for this action")

    if args.action == 'check-all':
        # Check all nodes
        nodes = get_all_nodes()
        all_results = []
        exit_code = 0

        for node in nodes:
            node_name = node['metadata']['name']
            results, issues = analyze_node_drainability(node_name, warn_only=args.warn_only)
            all_results.append((results, issues))
            if issues:
                exit_code = 1

        if args.format == 'json':
            print(json.dumps([r[0] for r in all_results], indent=2))
        else:
            for results, _ in all_results:
                if args.format == 'plain':
                    print(format_plain_output(results))
                else:
                    print(format_table_output(results))
                print()

        sys.exit(exit_code)

    # Single node operations
    if args.action == 'check':
        results, issues_found = analyze_node_drainability(args.node, warn_only=args.warn_only)

        if args.format == 'json':
            print(json.dumps(results, indent=2))
        elif args.format == 'plain':
            print(format_plain_output(results))
        else:
            print(format_table_output(results))

        sys.exit(1 if issues_found else 0)

    elif args.action == 'drain':
        # Cordon first
        if not cordon_node(args.node, dry_run=args.dry_run):
            sys.exit(1)

        # Then drain
        if not drain_node(args.node, grace_period=args.grace_period,
                         dry_run=args.dry_run, force=args.force):
            sys.exit(1)

        sys.exit(0)

    elif args.action == 'uncordon':
        if not uncordon_node(args.node, dry_run=args.dry_run):
            sys.exit(1)
        sys.exit(0)


if __name__ == '__main__':
    main()
