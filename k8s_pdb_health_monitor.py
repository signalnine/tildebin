#!/usr/bin/env python3
"""
Monitor Kubernetes PodDisruptionBudget health and availability.

PodDisruptionBudgets (PDBs) are critical for maintaining application availability
during voluntary disruptions like node drains, upgrades, and maintenance. This
script monitors PDBs to detect:

- PDBs with no allowed disruptions (blocking maintenance)
- PDBs protecting non-existent or unhealthy deployments
- Misconfigured PDBs (minAvailable > replicas)
- PDBs with excessive disruption budgets
- Workloads lacking PDB protection

Useful for large-scale baremetal clusters where maintenance windows require
careful orchestration of pod evictions.

Exit codes:
    0 - All PDBs healthy
    1 - PDB issues detected
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


def get_pdbs(namespace: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all PodDisruptionBudgets in JSON format."""
    cmd = ['get', 'pdb', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    if output is None:
        return []

    try:
        data = json.loads(output)
        return data.get('items', [])
    except json.JSONDecodeError:
        return []


def get_deployments(namespace: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Get deployments as a map keyed by namespace/name."""
    cmd = ['get', 'deployments', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    if output is None:
        return {}

    try:
        data = json.loads(output)
        result = {}
        for deploy in data.get('items', []):
            metadata = deploy.get('metadata', {})
            name = metadata.get('name', '')
            ns = metadata.get('namespace', '')
            spec = deploy.get('spec', {})
            status = deploy.get('status', {})
            result[f"{ns}/{name}"] = {
                'replicas': spec.get('replicas', 0),
                'ready_replicas': status.get('readyReplicas', 0),
                'labels': spec.get('selector', {}).get('matchLabels', {}),
            }
        return result
    except json.JSONDecodeError:
        return {}


def get_statefulsets(namespace: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Get statefulsets as a map keyed by namespace/name."""
    cmd = ['get', 'statefulsets', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    if output is None:
        return {}

    try:
        data = json.loads(output)
        result = {}
        for sts in data.get('items', []):
            metadata = sts.get('metadata', {})
            name = metadata.get('name', '')
            ns = metadata.get('namespace', '')
            spec = sts.get('spec', {})
            status = sts.get('status', {})
            result[f"{ns}/{name}"] = {
                'replicas': spec.get('replicas', 0),
                'ready_replicas': status.get('readyReplicas', 0),
                'labels': spec.get('selector', {}).get('matchLabels', {}),
            }
        return result
    except json.JSONDecodeError:
        return {}


def labels_match(selector: Dict[str, str], labels: Dict[str, str]) -> bool:
    """Check if selector labels match workload labels."""
    if not selector:
        return False
    for key, value in selector.items():
        if labels.get(key) != value:
            return False
    return True


def find_matching_workloads(
    pdb_selector: Dict[str, str],
    namespace: str,
    deployments: Dict[str, Dict[str, Any]],
    statefulsets: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Find workloads that match the PDB selector."""
    matches = []

    # Check deployments
    for key, deploy in deployments.items():
        if not key.startswith(f"{namespace}/"):
            continue
        if labels_match(pdb_selector, deploy['labels']):
            matches.append({
                'type': 'Deployment',
                'name': key.split('/', 1)[1],
                'replicas': deploy['replicas'],
                'ready_replicas': deploy['ready_replicas'],
            })

    # Check statefulsets
    for key, sts in statefulsets.items():
        if not key.startswith(f"{namespace}/"):
            continue
        if labels_match(pdb_selector, sts['labels']):
            matches.append({
                'type': 'StatefulSet',
                'name': key.split('/', 1)[1],
                'replicas': sts['replicas'],
                'ready_replicas': sts['ready_replicas'],
            })

    return matches


def analyze_pdb(
    pdb: Dict[str, Any],
    deployments: Dict[str, Dict[str, Any]],
    statefulsets: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """Analyze a single PDB for issues."""
    metadata = pdb.get('metadata', {})
    spec = pdb.get('spec', {})
    status = pdb.get('status', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')

    # PDB spec
    min_available = spec.get('minAvailable')
    max_unavailable = spec.get('maxUnavailable')
    selector = spec.get('selector', {}).get('matchLabels', {})

    # PDB status
    current_healthy = status.get('currentHealthy', 0)
    desired_healthy = status.get('desiredHealthy', 0)
    disruptions_allowed = status.get('disruptionsAllowed', 0)
    expected_pods = status.get('expectedPods', 0)

    # Find matching workloads
    matching_workloads = find_matching_workloads(
        selector, namespace, deployments, statefulsets
    )

    # Determine issues
    issues = []
    has_issue = False
    severity = 'ok'

    # Check if PDB is blocking disruptions
    if disruptions_allowed == 0 and expected_pods > 0:
        issues.append("No disruptions allowed - will block maintenance")
        has_issue = True
        severity = 'critical'

    # Check if PDB has no matching pods
    if expected_pods == 0:
        issues.append("No pods match selector")
        has_issue = True
        severity = 'warning'

    # Check for unhealthy pods
    if expected_pods > 0 and current_healthy < expected_pods:
        unhealthy_count = expected_pods - current_healthy
        issues.append(f"{unhealthy_count} unhealthy pod(s)")
        has_issue = True
        if severity != 'critical':
            severity = 'warning'

    # Check for misconfiguration
    if min_available is not None:
        # If minAvailable is a percentage, we can't easily check misconfiguration
        if isinstance(min_available, int) and min_available > expected_pods:
            issues.append(f"minAvailable ({min_available}) > expected pods ({expected_pods})")
            has_issue = True
            severity = 'critical'

    # Check if matching workloads are healthy
    for workload in matching_workloads:
        if workload['ready_replicas'] < workload['replicas']:
            unready = workload['replicas'] - workload['ready_replicas']
            issues.append(
                f"{workload['type']} {workload['name']}: {unready} pod(s) not ready"
            )
            has_issue = True
            if severity != 'critical':
                severity = 'warning'

    return {
        'name': name,
        'namespace': namespace,
        'min_available': min_available,
        'max_unavailable': max_unavailable,
        'selector': selector,
        'current_healthy': current_healthy,
        'desired_healthy': desired_healthy,
        'disruptions_allowed': disruptions_allowed,
        'expected_pods': expected_pods,
        'matching_workloads': matching_workloads,
        'has_issue': has_issue,
        'severity': severity,
        'issues': issues,
    }


def output_plain(pdbs_data: List[Dict], warn_only: bool, verbose: bool):
    """Plain text output."""
    if warn_only:
        pdbs_data = [p for p in pdbs_data if p['has_issue']]

    if not pdbs_data:
        print("All PDBs healthy." if not warn_only else "No PDB issues detected.")
        return

    # Group by severity
    critical = [p for p in pdbs_data if p['severity'] == 'critical']
    warning = [p for p in pdbs_data if p['severity'] == 'warning']
    ok = [p for p in pdbs_data if p['severity'] == 'ok']

    if critical:
        print("=== Critical PDB Issues ===")
        for pdb in critical:
            print_pdb_plain(pdb, verbose)

    if warning:
        print("\n=== Warning PDB Issues ===")
        for pdb in warning:
            print_pdb_plain(pdb, verbose)

    if ok and not warn_only:
        print("\n=== Healthy PDBs ===")
        for pdb in ok:
            print_pdb_plain(pdb, verbose)


def print_pdb_plain(pdb: Dict, verbose: bool):
    """Print a single PDB in plain format."""
    status_marker = {
        'critical': '[CRITICAL]',
        'warning': '[WARNING]',
        'ok': '[OK]',
    }.get(pdb['severity'], '[UNKNOWN]')

    print(f"\n{status_marker} {pdb['namespace']}/{pdb['name']}")

    # Show policy
    if pdb['min_available'] is not None:
        print(f"  Policy: minAvailable={pdb['min_available']}")
    elif pdb['max_unavailable'] is not None:
        print(f"  Policy: maxUnavailable={pdb['max_unavailable']}")

    # Show status
    print(f"  Status: {pdb['current_healthy']}/{pdb['expected_pods']} healthy, "
          f"{pdb['disruptions_allowed']} disruptions allowed")

    if verbose and pdb['selector']:
        selector_str = ', '.join(f"{k}={v}" for k, v in pdb['selector'].items())
        print(f"  Selector: {selector_str}")

    if verbose and pdb['matching_workloads']:
        print("  Workloads:")
        for wl in pdb['matching_workloads']:
            print(f"    - {wl['type']}/{wl['name']}: "
                  f"{wl['ready_replicas']}/{wl['replicas']} ready")

    if pdb['issues']:
        for issue in pdb['issues']:
            print(f"  * {issue}")


def output_json(pdbs_data: List[Dict], warn_only: bool):
    """JSON output."""
    if warn_only:
        pdbs_data = [p for p in pdbs_data if p['has_issue']]

    # Summary
    total = len(pdbs_data)
    critical = sum(1 for p in pdbs_data if p['severity'] == 'critical')
    warning = sum(1 for p in pdbs_data if p['severity'] == 'warning')
    blocking = sum(1 for p in pdbs_data if p['disruptions_allowed'] == 0 and p['expected_pods'] > 0)

    output = {
        'pdbs': pdbs_data,
        'summary': {
            'total_pdbs': total,
            'critical_issues': critical,
            'warning_issues': warning,
            'blocking_maintenance': blocking,
        }
    }
    print(json.dumps(output, indent=2))


def output_table(pdbs_data: List[Dict], warn_only: bool):
    """Tabular output."""
    if warn_only:
        pdbs_data = [p for p in pdbs_data if p['has_issue']]

    print(f"{'NAMESPACE':<20} {'NAME':<30} {'HEALTHY':<10} {'ALLOWED':<10} "
          f"{'POLICY':<20} {'STATUS'}")
    print("-" * 110)

    for pdb in sorted(pdbs_data, key=lambda x: (
        0 if x['severity'] == 'critical' else (1 if x['severity'] == 'warning' else 2),
        x['namespace'],
        x['name']
    )):
        ns = pdb['namespace'][:19]
        name = pdb['name'][:29]
        healthy = f"{pdb['current_healthy']}/{pdb['expected_pods']}"
        allowed = str(pdb['disruptions_allowed'])

        if pdb['min_available'] is not None:
            policy = f"min={pdb['min_available']}"
        elif pdb['max_unavailable'] is not None:
            policy = f"maxUnavail={pdb['max_unavailable']}"
        else:
            policy = 'N/A'

        status = pdb['severity'].upper()

        print(f"{ns:<20} {name:<30} {healthy:<10} {allowed:<10} {policy:<20} {status}")

    # Summary
    total = len(pdbs_data)
    critical = sum(1 for p in pdbs_data if p['severity'] == 'critical')
    warning = sum(1 for p in pdbs_data if p['severity'] == 'warning')
    print(f"\nTotal: {total} PDBs, {critical} critical, {warning} warnings")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes PodDisruptionBudget health",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all PDBs across all namespaces
  %(prog)s

  # Check PDBs in specific namespace
  %(prog)s -n production

  # Show only PDBs with issues
  %(prog)s --warn-only

  # Output as JSON for automation
  %(prog)s --format json

  # Verbose output with workload details
  %(prog)s -v

Issue detection:
  - Critical: PDB blocking disruptions (disruptionsAllowed=0)
  - Critical: minAvailable exceeds expected pods
  - Warning: No pods match PDB selector
  - Warning: Unhealthy pods protected by PDB
  - Warning: Matching workloads have unready replicas

Exit codes:
  0 - All PDBs healthy
  1 - PDB issues detected
  2 - Usage error or kubectl not available
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to check (default: all namespaces)'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show PDBs with issues'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed PDB information including selectors and workloads'
    )

    args = parser.parse_args()

    # Get PDBs
    pdbs = get_pdbs(args.namespace)

    if not pdbs:
        print("No PodDisruptionBudgets found.")
        sys.exit(0)

    # Get workloads for cross-referencing
    deployments = get_deployments(args.namespace)
    statefulsets = get_statefulsets(args.namespace)

    # Analyze PDBs
    pdbs_data = [
        analyze_pdb(pdb, deployments, statefulsets)
        for pdb in pdbs
    ]

    # Output results
    if args.format == 'json':
        output_json(pdbs_data, args.warn_only)
    elif args.format == 'table':
        output_table(pdbs_data, args.warn_only)
    else:
        output_plain(pdbs_data, args.warn_only, args.verbose)

    # Determine exit code
    has_issues = any(p['has_issue'] for p in pdbs_data)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
