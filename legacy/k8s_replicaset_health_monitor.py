#!/usr/bin/env python3
"""
Monitor Kubernetes ReplicaSet health and detect common issues.

ReplicaSets are the foundation of Kubernetes workload management. Problems
at the ReplicaSet level often indicate deployment issues, resource constraints,
or configuration problems that affect application availability.

This script monitors:
- ReplicaSets with unavailable replicas (not meeting desired count)
- Stale ReplicaSets (old revisions that haven't been cleaned up)
- ReplicaSets with failed pod creation
- Orphaned ReplicaSets (no owner deployment/statefulset)
- ReplicaSets with high restart counts on their pods
- Replica count mismatches (desired vs current vs ready)

Useful for identifying:
- Stuck deployments that can't scale up
- Resource quota exhaustion preventing pod scheduling
- Image pull failures or crash loops
- Deployment rollout issues

Exit codes:
    0 - All ReplicaSets healthy
    1 - ReplicaSet issues detected
    2 - Usage error or kubectl not available
"""

import argparse
import sys
import subprocess
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional


def run_kubectl(args: List[str]) -> str:
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
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/",
              file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_replicasets(namespace: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all ReplicaSets in JSON format."""
    cmd = ['get', 'replicasets', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    data = json.loads(output)
    return data.get('items', [])


def get_pods_for_replicaset(namespace: str, rs_name: str) -> List[Dict[str, Any]]:
    """Get pods owned by a specific ReplicaSet."""
    cmd = ['get', 'pods', '-n', namespace, '-o', 'json',
           '-l', f'pod-template-hash']  # ReplicaSets add this label

    try:
        output = run_kubectl(cmd)
        data = json.loads(output)
        pods = []

        for pod in data.get('items', []):
            # Check owner references
            owner_refs = pod.get('metadata', {}).get('ownerReferences', [])
            for ref in owner_refs:
                if ref.get('kind') == 'ReplicaSet' and ref.get('name') == rs_name:
                    pods.append(pod)
                    break

        return pods
    except Exception:
        return []


def parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse Kubernetes timestamp to datetime object."""
    if not ts_str:
        return None
    try:
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        return datetime.fromisoformat(ts_str)
    except (ValueError, AttributeError):
        return None


def analyze_replicaset(rs: Dict[str, Any], include_pods: bool = False) -> Dict[str, Any]:
    """Analyze a single ReplicaSet for health issues."""
    metadata = rs.get('metadata', {})
    spec = rs.get('spec', {})
    status = rs.get('status', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    labels = metadata.get('labels', {})
    owner_refs = metadata.get('ownerReferences', [])

    # Replica counts
    desired = spec.get('replicas', 0)
    current = status.get('replicas', 0)
    ready = status.get('readyReplicas', 0)
    available = status.get('availableReplicas', 0)
    fully_labeled = status.get('fullyLabeledReplicas', 0)

    # Calculate age
    creation_ts = parse_timestamp(metadata.get('creationTimestamp'))
    age_seconds = None
    if creation_ts:
        age_seconds = (datetime.now(timezone.utc) - creation_ts).total_seconds()

    # Check owner (usually a Deployment)
    owner_kind = None
    owner_name = None
    is_orphaned = True
    for ref in owner_refs:
        if ref.get('kind') in ['Deployment', 'StatefulSet']:
            owner_kind = ref.get('kind')
            owner_name = ref.get('name')
            is_orphaned = False
            break

    # Detect issues
    issues = []
    has_issue = False

    # Check replica count mismatches
    if desired > 0 and ready < desired:
        has_issue = True
        missing = desired - ready
        issues.append({
            'type': 'unavailable_replicas',
            'severity': 'high' if ready == 0 else 'medium',
            'message': f'{missing} replica(s) not ready ({ready}/{desired})',
        })

    # Check if this is a stale/old ReplicaSet (zero replicas but still exists)
    if desired == 0 and current == 0:
        # Old revision - check age
        if age_seconds and age_seconds > 86400:  # Older than 24 hours
            issues.append({
                'type': 'stale_replicaset',
                'severity': 'low',
                'message': f'Zero-replica ReplicaSet older than {age_seconds/86400:.1f} days',
            })

    # Check for orphaned ReplicaSets
    if is_orphaned and desired > 0:
        has_issue = True
        issues.append({
            'type': 'orphaned',
            'severity': 'medium',
            'message': 'ReplicaSet has no owner Deployment/StatefulSet',
        })

    # Check for ReplicaSets that can't create pods (replica mismatch without owner cleanup)
    if current < desired and not is_orphaned:
        # This might indicate scheduling issues or resource problems
        has_issue = True
        issues.append({
            'type': 'pods_not_created',
            'severity': 'high',
            'message': f'Only {current} pod(s) created for {desired} desired',
        })

    # Check conditions for failure messages
    conditions = status.get('conditions', [])
    for condition in conditions:
        if condition.get('type') == 'ReplicaFailure' and condition.get('status') == 'True':
            has_issue = True
            reason = condition.get('reason', 'Unknown')
            message = condition.get('message', '')
            issues.append({
                'type': 'replica_failure',
                'severity': 'high',
                'message': f'{reason}: {message[:100]}',
            })

    result = {
        'name': name,
        'namespace': namespace,
        'desired': desired,
        'current': current,
        'ready': ready,
        'available': available,
        'age_seconds': age_seconds,
        'owner_kind': owner_kind,
        'owner_name': owner_name,
        'is_orphaned': is_orphaned,
        'has_issue': has_issue,
        'issues': issues,
        'revision': labels.get('pod-template-hash', 'unknown'),
    }

    # Get pod details if requested
    if include_pods and has_issue:
        pods = get_pods_for_replicaset(namespace, name)
        pod_summary = []
        total_restarts = 0

        for pod in pods:
            pod_meta = pod.get('metadata', {})
            pod_status = pod.get('status', {})
            pod_name = pod_meta.get('name', 'unknown')
            phase = pod_status.get('phase', 'Unknown')

            # Count container restarts
            restarts = 0
            container_statuses = pod_status.get('containerStatuses', [])
            for cs in container_statuses:
                restarts += cs.get('restartCount', 0)
            total_restarts += restarts

            # Check for waiting containers
            waiting_reason = None
            for cs in container_statuses:
                waiting = cs.get('state', {}).get('waiting', {})
                if waiting:
                    waiting_reason = waiting.get('reason', 'Waiting')
                    break

            pod_summary.append({
                'name': pod_name,
                'phase': phase,
                'restarts': restarts,
                'waiting_reason': waiting_reason,
            })

        result['pods'] = pod_summary
        result['total_restarts'] = total_restarts

        # Add high restart count as an issue
        if total_restarts > 10:
            issues.append({
                'type': 'high_restarts',
                'severity': 'medium',
                'message': f'Pods have {total_restarts} total restarts',
            })

    return result


def format_age(seconds: Optional[float]) -> str:
    """Format age in human-readable format."""
    if seconds is None:
        return 'N/A'

    if seconds < 60:
        return f'{int(seconds)}s'
    elif seconds < 3600:
        return f'{int(seconds/60)}m'
    elif seconds < 86400:
        return f'{seconds/3600:.1f}h'
    else:
        return f'{seconds/86400:.1f}d'


def output_plain(results: List[Dict], warn_only: bool, verbose: bool):
    """Plain text output."""
    # Filter if warn_only
    if warn_only:
        results = [r for r in results if r['has_issue']]

    # Also filter out zero-replica sets unless they have real issues
    active_results = [r for r in results if r['desired'] > 0 or r['has_issue']]

    if not active_results:
        print("No ReplicaSet issues detected")
        return

    # Summary
    total = len(active_results)
    with_issues = sum(1 for r in active_results if r['has_issue'])

    print(f"ReplicaSet Health Report")
    print(f"Total: {total} | With Issues: {with_issues}")
    print()

    # Group by namespace
    by_namespace = {}
    for r in active_results:
        ns = r['namespace']
        if ns not in by_namespace:
            by_namespace[ns] = []
        by_namespace[ns].append(r)

    for ns in sorted(by_namespace.keys()):
        rs_list = by_namespace[ns]
        if warn_only:
            rs_list = [r for r in rs_list if r['has_issue']]
        if not rs_list:
            continue

        print(f"=== Namespace: {ns} ===")

        for r in rs_list:
            status = "UNHEALTHY" if r['has_issue'] else "OK"
            marker = "!" if r['has_issue'] else " "
            age = format_age(r['age_seconds'])
            owner = f"{r['owner_kind']}/{r['owner_name']}" if r['owner_name'] else "none"

            print(f"{marker} {r['name']}")
            print(f"    Status: {status} | Replicas: {r['ready']}/{r['desired']} ready")
            print(f"    Age: {age} | Owner: {owner}")

            if r['issues']:
                for issue in r['issues']:
                    print(f"    [{issue['severity'].upper()}] {issue['message']}")

            if verbose and 'pods' in r:
                print("    Pods:")
                for pod in r['pods']:
                    status_str = pod['phase']
                    if pod['waiting_reason']:
                        status_str = pod['waiting_reason']
                    print(f"      - {pod['name']}: {status_str} (restarts: {pod['restarts']})")

            print()


def output_json(results: List[Dict], warn_only: bool):
    """JSON output."""
    if warn_only:
        results = [r for r in results if r['has_issue']]

    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'summary': {
            'total': len(results),
            'with_issues': sum(1 for r in results if r['has_issue']),
            'unavailable': sum(1 for r in results
                              if any(i['type'] == 'unavailable_replicas' for i in r['issues'])),
            'orphaned': sum(1 for r in results if r['is_orphaned'] and r['desired'] > 0),
        },
        'replicasets': results
    }

    print(json.dumps(output, indent=2, default=str))


def output_table(results: List[Dict], warn_only: bool):
    """Tabular output."""
    if warn_only:
        results = [r for r in results if r['has_issue']]

    # Filter zero-replica unless has issues
    results = [r for r in results if r['desired'] > 0 or r['has_issue']]

    print("+" + "-" * 100 + "+")
    print("|" + " ReplicaSet Health Monitor ".center(100) + "|")
    print("+" + "-" * 100 + "+")

    if not results:
        print("|" + " No ReplicaSet issues detected ".center(100) + "|")
        print("+" + "-" * 100 + "+")
        return

    # Header
    header = f"| {'Namespace':<20} | {'Name':<30} | {'Ready':>7} | {'Age':>8} | {'Status':<15} |"
    print(header)
    print("+" + "-" * 100 + "+")

    for r in results:
        status = "ISSUE" if r['has_issue'] else "OK"
        age = format_age(r['age_seconds'])
        replicas = f"{r['ready']}/{r['desired']}"

        row = f"| {r['namespace'][:20]:<20} | {r['name'][:30]:<30} | " \
              f"{replicas:>7} | {age:>8} | {status:<15} |"
        print(row)

    print("+" + "-" * 100 + "+")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes ReplicaSet health",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all ReplicaSets across all namespaces
  %(prog)s

  # Check ReplicaSets in specific namespace
  %(prog)s -n production

  # Show only unhealthy ReplicaSets
  %(prog)s --warn-only

  # Verbose output with pod details
  %(prog)s --verbose

  # JSON output for monitoring integration
  %(prog)s --format json

Exit codes:
  0 - All ReplicaSets healthy
  1 - ReplicaSet issues detected
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
        '-v', '--verbose',
        action='store_true',
        help='Show detailed pod information for unhealthy ReplicaSets'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show ReplicaSets with issues'
    )

    parser.add_argument(
        '--include-zero-replicas',
        action='store_true',
        help='Include ReplicaSets with zero desired replicas (old revisions)'
    )

    args = parser.parse_args()

    # Get ReplicaSets
    replicasets = get_replicasets(args.namespace)

    # Analyze each ReplicaSet
    results = []
    for rs in replicasets:
        analysis = analyze_replicaset(rs, include_pods=args.verbose)

        # Skip zero-replica sets unless requested or they have issues
        if not args.include_zero_replicas:
            if analysis['desired'] == 0 and not analysis['has_issue']:
                continue

        results.append(analysis)

    # Output
    if args.format == 'json':
        output_json(results, args.warn_only)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.warn_only, args.verbose)

    # Exit code
    has_issues = any(r['has_issue'] for r in results if r['desired'] > 0)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
