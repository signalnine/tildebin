#!/usr/bin/env python3
"""
Analyze Pod Disruption Budget (PDB) coverage across Kubernetes workloads.

This script identifies Deployments, StatefulSets, and ReplicaSets that lack
PDB protection, making them vulnerable to unexpected disruptions during
node maintenance, upgrades, or voluntary evictions.

Features:
- Identifies workloads without PDB coverage
- Detects PDBs that are too restrictive (minAvailable=100% or maxUnavailable=0)
- Highlights critical namespaces (kube-system, monitoring, etc.)
- Suggests appropriate PDB configurations based on replica counts
- Supports namespace filtering and multiple output formats

Use cases:
- Pre-maintenance validation
- Cluster hardening audits
- SLA compliance verification
- Identifying single points of failure

Exit codes:
    0 - All workloads have adequate PDB coverage
    1 - One or more workloads lack PDB coverage or have issues
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime


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
        if 'the server doesn\'t have a resource type' in e.stderr:
            return None
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_deployments(namespace=None):
    """Get all Deployments in the cluster."""
    args = ['get', 'deployments', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    if output:
        return json.loads(output).get('items', [])
    return []


def get_statefulsets(namespace=None):
    """Get all StatefulSets in the cluster."""
    args = ['get', 'statefulsets', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    if output:
        return json.loads(output).get('items', [])
    return []


def get_replicasets(namespace=None):
    """Get all standalone ReplicaSets (not owned by Deployments)."""
    args = ['get', 'replicasets', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    if not output:
        return []

    replicasets = json.loads(output).get('items', [])
    # Filter to only standalone ReplicaSets (not owned by Deployments)
    standalone = []
    for rs in replicasets:
        owner_refs = rs.get('metadata', {}).get('ownerReferences', [])
        has_deployment_owner = any(
            ref.get('kind') == 'Deployment' for ref in owner_refs
        )
        if not has_deployment_owner:
            standalone.append(rs)
    return standalone


def get_pdbs(namespace=None):
    """Get all PodDisruptionBudgets in the cluster."""
    args = ['get', 'pdb', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    if output:
        return json.loads(output).get('items', [])
    return []


def labels_match(selector_labels, pod_labels):
    """Check if selector labels match pod labels."""
    if not selector_labels:
        return False
    return all(
        pod_labels.get(k) == v for k, v in selector_labels.items()
    )


def find_matching_pdb(workload, pdbs):
    """Find PDB that matches a workload's selector."""
    namespace = workload.get('metadata', {}).get('namespace', 'default')
    workload_selector = workload.get('spec', {}).get('selector', {})
    match_labels = workload_selector.get('matchLabels', {})

    matching_pdbs = []
    for pdb in pdbs:
        pdb_namespace = pdb.get('metadata', {}).get('namespace', 'default')
        if pdb_namespace != namespace:
            continue

        pdb_selector = pdb.get('spec', {}).get('selector', {})
        pdb_match_labels = pdb_selector.get('matchLabels', {})

        if labels_match(pdb_match_labels, match_labels):
            matching_pdbs.append(pdb)

    return matching_pdbs


def analyze_pdb_policy(pdb, replicas):
    """Analyze if a PDB policy is too restrictive."""
    issues = []
    spec = pdb.get('spec', {})

    min_available = spec.get('minAvailable')
    max_unavailable = spec.get('maxUnavailable')

    if min_available is not None:
        if isinstance(min_available, str) and min_available.endswith('%'):
            pct = int(min_available.rstrip('%'))
            if pct == 100:
                issues.append("minAvailable=100% blocks all evictions")
            elif pct > 80 and replicas <= 2:
                issues.append(f"minAvailable={pct}% may block maintenance with {replicas} replicas")
        elif isinstance(min_available, int):
            if min_available >= replicas:
                issues.append(f"minAvailable={min_available} equals replicas={replicas}, blocks all evictions")
            elif min_available == replicas - 1 and replicas <= 2:
                issues.append(f"minAvailable={min_available} with {replicas} replicas is tight")

    if max_unavailable is not None:
        if isinstance(max_unavailable, str) and max_unavailable.endswith('%'):
            pct = int(max_unavailable.rstrip('%'))
            if pct == 0:
                issues.append("maxUnavailable=0% blocks all evictions")
        elif isinstance(max_unavailable, int):
            if max_unavailable == 0:
                issues.append("maxUnavailable=0 blocks all evictions")

    return issues


def suggest_pdb(workload_name, replicas, kind):
    """Suggest appropriate PDB configuration based on workload."""
    if replicas <= 1:
        return "Consider scaling to 2+ replicas before adding PDB"

    if replicas == 2:
        return "Suggest: maxUnavailable=1 or minAvailable=1"
    elif replicas <= 5:
        return "Suggest: maxUnavailable=1 or minAvailable=50%"
    else:
        return "Suggest: maxUnavailable=25% or minAvailable=75%"


def is_critical_namespace(namespace):
    """Check if namespace contains critical system workloads."""
    critical_namespaces = {
        'kube-system',
        'kube-public',
        'monitoring',
        'prometheus',
        'logging',
        'ingress',
        'ingress-nginx',
        'cert-manager',
        'istio-system',
        'linkerd',
        'vault',
        'consul',
    }
    return namespace in critical_namespaces


def analyze_workload(workload, kind, pdbs, include_suggestions=True):
    """Analyze a single workload for PDB coverage."""
    metadata = workload.get('metadata', {})
    spec = workload.get('spec', {})
    status = workload.get('status', {})

    namespace = metadata.get('namespace', 'default')
    name = metadata.get('name', 'unknown')

    # Get replica count
    replicas = spec.get('replicas', 1)
    ready_replicas = status.get('readyReplicas', 0)

    result = {
        'namespace': namespace,
        'name': name,
        'kind': kind,
        'replicas': replicas,
        'ready_replicas': ready_replicas,
        'has_pdb': False,
        'pdb_names': [],
        'issues': [],
        'severity': 'OK',
        'suggestion': None,
        'is_critical': is_critical_namespace(namespace),
    }

    # Find matching PDBs
    matching_pdbs = find_matching_pdb(workload, pdbs)

    if matching_pdbs:
        result['has_pdb'] = True
        result['pdb_names'] = [
            pdb.get('metadata', {}).get('name', 'unknown')
            for pdb in matching_pdbs
        ]

        # Check if PDB policies are too restrictive
        for pdb in matching_pdbs:
            pdb_issues = analyze_pdb_policy(pdb, replicas)
            if pdb_issues:
                result['issues'].extend(pdb_issues)

        if result['issues']:
            result['severity'] = 'WARNING'
    else:
        # No PDB coverage
        result['issues'].append("No PDB coverage")

        if replicas <= 1:
            result['severity'] = 'LOW'
            result['issues'].append("Single replica - PDB would not help")
        elif is_critical_namespace(namespace):
            result['severity'] = 'CRITICAL'
        else:
            result['severity'] = 'HIGH'

        if include_suggestions:
            result['suggestion'] = suggest_pdb(name, replicas, kind)

    return result


def format_plain_output(results, warn_only=False):
    """Format results as plain text."""
    lines = []
    for r in results:
        if warn_only and r['severity'] == 'OK':
            continue

        pdb_str = ','.join(r['pdb_names']) if r['pdb_names'] else 'NONE'
        issues_str = '; '.join(r['issues']) if r['issues'] else ''

        lines.append(
            f"{r['namespace']} {r['name']} {r['kind']} "
            f"replicas={r['replicas']} pdb={pdb_str} "
            f"severity={r['severity']} {issues_str}"
        )

    return '\n'.join(lines)


def format_table_output(results, warn_only=False):
    """Format results as ASCII table."""
    lines = []
    lines.append(
        f"{'NAMESPACE':<20} {'WORKLOAD':<35} {'KIND':<12} "
        f"{'REPL':<5} {'PDB':<15} {'SEVERITY':<10} {'ISSUES'}"
    )
    lines.append("-" * 140)

    for r in results:
        if warn_only and r['severity'] == 'OK':
            continue

        pdb_str = ','.join(r['pdb_names'])[:14] if r['pdb_names'] else 'NONE'
        issues_str = '; '.join(r['issues'])[:45] if r['issues'] else ''

        critical_marker = '*' if r['is_critical'] else ' '
        lines.append(
            f"{r['namespace']:<20} {r['name']:<35} {r['kind']:<12} "
            f"{r['replicas']:<5} {pdb_str:<15} {r['severity']:<10} {critical_marker}{issues_str}"
        )

    return '\n'.join(lines)


def format_json_output(results, warn_only=False):
    """Format results as JSON."""
    filtered = results if not warn_only else [
        r for r in results if r['severity'] != 'OK'
    ]

    summary = {
        'timestamp': datetime.now().isoformat(),
        'total_workloads': len(results),
        'workloads_without_pdb': sum(1 for r in results if not r['has_pdb']),
        'critical_issues': sum(1 for r in results if r['severity'] == 'CRITICAL'),
        'high_issues': sum(1 for r in results if r['severity'] == 'HIGH'),
        'warning_issues': sum(1 for r in results if r['severity'] == 'WARNING'),
    }

    return json.dumps({
        'summary': summary,
        'workloads': filtered
    }, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Pod Disruption Budget coverage for Kubernetes workloads",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all workloads for PDB coverage
  k8s_pdb_coverage_analyzer.py

  # Check only production namespace
  k8s_pdb_coverage_analyzer.py -n production

  # Show only workloads missing PDB coverage
  k8s_pdb_coverage_analyzer.py --warn-only

  # Get JSON output for CI/CD integration
  k8s_pdb_coverage_analyzer.py --format json

  # Include suggestions for PDB configurations
  k8s_pdb_coverage_analyzer.py --suggest

Severity levels:
  CRITICAL - Critical namespace workload without PDB (kube-system, monitoring, etc.)
  HIGH     - Multi-replica workload without PDB coverage
  WARNING  - Has PDB but policy may be too restrictive
  LOW      - Single replica workload (PDB would not help)
  OK       - Adequate PDB coverage
        """
    )

    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show workloads with issues (exclude OK severity)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including suggestions"
    )
    parser.add_argument(
        "--suggest",
        action="store_true",
        help="Include PDB configuration suggestions"
    )
    parser.add_argument(
        "--kind",
        choices=["all", "deployment", "statefulset", "replicaset"],
        default="all",
        help="Workload kind to analyze (default: all)"
    )

    args = parser.parse_args()

    # Fetch cluster resources
    pdbs = get_pdbs(args.namespace)

    workloads = []

    if args.kind in ['all', 'deployment']:
        deployments = get_deployments(args.namespace)
        for d in deployments:
            workloads.append(('Deployment', d))

    if args.kind in ['all', 'statefulset']:
        statefulsets = get_statefulsets(args.namespace)
        for s in statefulsets:
            workloads.append(('StatefulSet', s))

    if args.kind in ['all', 'replicaset']:
        replicasets = get_replicasets(args.namespace)
        for r in replicasets:
            workloads.append(('ReplicaSet', r))

    if not workloads:
        print("No workloads found", file=sys.stderr)
        sys.exit(0)

    # Analyze each workload
    results = []
    for kind, workload in workloads:
        result = analyze_workload(
            workload, kind, pdbs,
            include_suggestions=args.suggest or args.verbose
        )
        results.append(result)

    # Sort by severity (CRITICAL first, then HIGH, WARNING, LOW, OK)
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'WARNING': 2, 'LOW': 3, 'OK': 4}
    results.sort(key=lambda r: (severity_order.get(r['severity'], 5), r['namespace'], r['name']))

    # Output
    if args.format == 'plain':
        output = format_plain_output(results, args.warn_only)
    elif args.format == 'table':
        output = format_table_output(results, args.warn_only)
    else:
        output = format_json_output(results, args.warn_only)

    if output:
        print(output)

    # Determine exit code
    has_critical = any(r['severity'] == 'CRITICAL' for r in results)
    has_high = any(r['severity'] == 'HIGH' for r in results)
    has_warning = any(r['severity'] == 'WARNING' for r in results)

    if has_critical or has_high:
        sys.exit(1)
    elif has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
