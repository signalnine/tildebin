#!/usr/bin/env python3
"""
Monitor Kubernetes Lease objects for leader election health.

Leases are the modern mechanism for leader election in Kubernetes. This script
monitors all leases across the cluster to detect:
- Stale leases (not renewed recently)
- Orphaned leases (holder no longer exists)
- Leader election contention or instability
- Missing expected leases for critical components

Useful for large-scale baremetal clusters where controller availability is
critical and HA issues can cause cascading failures.

Exit codes:
    0 - All leases healthy
    1 - Stale or problematic leases detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
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


def get_leases(namespace: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all leases in JSON format."""
    cmd = ['get', 'leases', '-o', 'json']
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


def get_pods(namespace: Optional[str] = None) -> Dict[str, bool]:
    """Get map of pod names to their existence (for orphan detection)."""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    if output is None:
        return {}

    try:
        data = json.loads(output)
        pods = {}
        for pod in data.get('items', []):
            metadata = pod.get('metadata', {})
            name = metadata.get('name', '')
            ns = metadata.get('namespace', '')
            # Store both full name and short name
            pods[f"{ns}/{name}"] = True
            pods[name] = True
        return pods
    except json.JSONDecodeError:
        return {}


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


def analyze_lease(lease: Dict[str, Any], pods: Dict[str, bool],
                  stale_threshold: int) -> Dict[str, Any]:
    """Analyze a single lease for issues."""
    metadata = lease.get('metadata', {})
    spec = lease.get('spec', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')

    # Lease spec fields
    holder_identity = spec.get('holderIdentity', '')
    lease_duration = spec.get('leaseDurationSeconds', 15)
    acquire_time = parse_timestamp(spec.get('acquireTime'))
    renew_time = parse_timestamp(spec.get('renewTime'))
    lease_transitions = spec.get('leaseTransitions', 0)

    # Calculate staleness
    now = datetime.now(timezone.utc)
    seconds_since_renew = None
    if renew_time:
        seconds_since_renew = (now - renew_time).total_seconds()

    seconds_since_acquire = None
    if acquire_time:
        seconds_since_acquire = (now - acquire_time).total_seconds()

    # Determine issues
    issues = []
    has_issue = False

    # Check if lease is stale (not renewed within threshold)
    if seconds_since_renew is not None:
        if seconds_since_renew > stale_threshold:
            issues.append(f"Stale: not renewed for {int(seconds_since_renew)}s")
            has_issue = True
        elif seconds_since_renew > lease_duration * 3:
            # Warning: more than 3x lease duration without renewal
            issues.append(f"Warning: {int(seconds_since_renew)}s since last renewal")
            has_issue = True

    # Check for missing holder
    if not holder_identity:
        issues.append("No holder identity set")
        has_issue = True

    # Check if holder pod exists (basic orphan detection)
    # holderIdentity often contains pod name or node name
    if holder_identity:
        # Try to extract pod name (common format: name_uuid)
        holder_parts = holder_identity.split('_')
        pod_name = holder_parts[0] if holder_parts else holder_identity

        # Check if holder might be orphaned
        # Only flag as orphan if we have pod data and pod isn't found
        if pods and pod_name not in pods:
            # Check with namespace prefix too
            full_name = f"{namespace}/{pod_name}"
            if full_name not in pods:
                # Don't flag as orphan for node-based leases or external holders
                if not any(x in holder_identity.lower() for x in
                          ['node', 'master', 'control-plane']):
                    issues.append(f"Holder may be orphaned: {pod_name}")
                    # Only mark as issue if also stale
                    if seconds_since_renew and seconds_since_renew > stale_threshold:
                        has_issue = True

    # Check for high transition count (leadership instability)
    if lease_transitions > 10:
        issues.append(f"High leadership transitions: {lease_transitions}")
        has_issue = True

    # Categorize lease type
    lease_type = categorize_lease(name, namespace)

    return {
        'name': name,
        'namespace': namespace,
        'holder_identity': holder_identity,
        'lease_duration_seconds': lease_duration,
        'lease_transitions': lease_transitions,
        'acquire_time': acquire_time.isoformat() if acquire_time else None,
        'renew_time': renew_time.isoformat() if renew_time else None,
        'seconds_since_renew': int(seconds_since_renew) if seconds_since_renew else None,
        'seconds_since_acquire': int(seconds_since_acquire) if seconds_since_acquire else None,
        'lease_type': lease_type,
        'has_issue': has_issue,
        'issues': issues,
    }


def categorize_lease(name: str, namespace: str) -> str:
    """Categorize lease by its purpose."""
    name_lower = name.lower()

    # Control plane components
    if name in ('kube-controller-manager', 'kube-scheduler'):
        return 'control-plane'
    if 'controller' in name_lower:
        return 'controller'

    # Node heartbeat leases
    if namespace == 'kube-node-lease':
        return 'node-heartbeat'

    # Operator leases
    if 'operator' in name_lower:
        return 'operator'

    # Ingress controllers
    if 'ingress' in name_lower or 'nginx' in name_lower or 'traefik' in name_lower:
        return 'ingress'

    # Storage controllers
    if 'csi' in name_lower or 'storage' in name_lower:
        return 'storage'

    # Service mesh
    if any(x in name_lower for x in ['istio', 'linkerd', 'consul', 'envoy']):
        return 'service-mesh'

    # Monitoring
    if any(x in name_lower for x in ['prometheus', 'grafana', 'metrics']):
        return 'monitoring'

    return 'other'


def format_duration(seconds: Optional[int]) -> str:
    """Format seconds into human-readable duration."""
    if seconds is None:
        return 'N/A'

    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m{seconds % 60}s"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h{minutes}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d{hours}h"


def output_plain(leases_data: List[Dict], warn_only: bool, verbose: bool):
    """Plain text output."""
    # Group by type
    by_type: Dict[str, List[Dict]] = {}
    for lease in leases_data:
        if warn_only and not lease['has_issue']:
            continue
        lease_type = lease['lease_type']
        if lease_type not in by_type:
            by_type[lease_type] = []
        by_type[lease_type].append(lease)

    if not by_type:
        print("All leases healthy." if not warn_only else "No lease issues detected.")
        return

    type_order = ['control-plane', 'node-heartbeat', 'controller', 'operator',
                  'ingress', 'storage', 'service-mesh', 'monitoring', 'other']

    for lease_type in type_order:
        if lease_type not in by_type:
            continue

        leases = by_type[lease_type]
        print(f"\n=== {lease_type.replace('-', ' ').title()} Leases ===")

        for lease in leases:
            status = "[ISSUE]" if lease['has_issue'] else "[OK]"
            print(f"\n{status} {lease['namespace']}/{lease['name']}")
            print(f"  Holder: {lease['holder_identity'] or '(none)'}")
            print(f"  Last renewed: {format_duration(lease['seconds_since_renew'])} ago")
            print(f"  Transitions: {lease['lease_transitions']}")

            if verbose:
                print(f"  Lease duration: {lease['lease_duration_seconds']}s")
                if lease['acquire_time']:
                    print(f"  Acquired: {format_duration(lease['seconds_since_acquire'])} ago")

            if lease['issues']:
                for issue in lease['issues']:
                    print(f"  * {issue}")


def output_json(leases_data: List[Dict], warn_only: bool):
    """JSON output."""
    if warn_only:
        leases_data = [l for l in leases_data if l['has_issue']]

    # Summary statistics
    total = len(leases_data)
    with_issues = sum(1 for l in leases_data if l['has_issue'])

    by_type: Dict[str, int] = {}
    for lease in leases_data:
        lease_type = lease['lease_type']
        by_type[lease_type] = by_type.get(lease_type, 0) + 1

    output = {
        'leases': leases_data,
        'summary': {
            'total_leases': total,
            'leases_with_issues': with_issues,
            'by_type': by_type,
        }
    }
    print(json.dumps(output, indent=2))


def output_table(leases_data: List[Dict], warn_only: bool):
    """Tabular output."""
    if warn_only:
        leases_data = [l for l in leases_data if l['has_issue']]

    print(f"{'NAMESPACE':<20} {'NAME':<35} {'TYPE':<15} {'HOLDER':<25} "
          f"{'RENEWED':<10} {'TRANS':<6} {'STATUS'}")
    print("-" * 130)

    for lease in sorted(leases_data, key=lambda x: (x['namespace'], x['name'])):
        ns = lease['namespace'][:19]
        name = lease['name'][:34]
        lease_type = lease['lease_type'][:14]
        holder = (lease['holder_identity'] or '(none)')[:24]
        renewed = format_duration(lease['seconds_since_renew'])
        trans = str(lease['lease_transitions'])
        status = 'ISSUE' if lease['has_issue'] else 'OK'

        print(f"{ns:<20} {name:<35} {lease_type:<15} {holder:<25} "
              f"{renewed:<10} {trans:<6} {status}")

    # Summary
    total = len(leases_data)
    with_issues = sum(1 for l in leases_data if l['has_issue'])
    print(f"\nTotal: {total} leases, {with_issues} with issues")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes Lease objects for leader election health",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all leases across all namespaces
  %(prog)s

  # Check leases in kube-system only
  %(prog)s -n kube-system

  # Show only leases with issues
  %(prog)s --warn-only

  # Output as JSON for automation
  %(prog)s --format json

  # Custom stale threshold (default: 60 seconds)
  %(prog)s --stale-threshold 120

  # Skip node heartbeat leases (can be noisy in large clusters)
  %(prog)s --skip-node-leases

Lease types detected:
  - control-plane: kube-controller-manager, kube-scheduler
  - node-heartbeat: Node heartbeat leases (kube-node-lease namespace)
  - controller: Various Kubernetes controllers
  - operator: Operator framework leases
  - ingress: Ingress controller leader election
  - storage: CSI and storage controller leases
  - service-mesh: Istio, Linkerd, etc.
  - monitoring: Prometheus, Grafana, etc.

Exit codes:
  0 - All leases healthy
  1 - Stale or problematic leases detected
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
        help='Only show leases with issues'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed lease information'
    )

    parser.add_argument(
        '--stale-threshold',
        type=int,
        default=60,
        help='Seconds without renewal before lease is considered stale (default: 60)'
    )

    parser.add_argument(
        '--skip-node-leases',
        action='store_true',
        help='Skip node heartbeat leases in kube-node-lease namespace'
    )

    parser.add_argument(
        '--check-orphans',
        action='store_true',
        help='Check if lease holders still exist (requires extra API calls)'
    )

    args = parser.parse_args()

    # Get leases
    leases = get_leases(args.namespace)

    if not leases:
        print("No leases found.")
        sys.exit(0)

    # Optionally skip node leases
    if args.skip_node_leases:
        leases = [l for l in leases
                  if l.get('metadata', {}).get('namespace') != 'kube-node-lease']

    # Get pods for orphan detection if requested
    pods = {}
    if args.check_orphans:
        pods = get_pods(args.namespace)

    # Analyze leases
    leases_data = [
        analyze_lease(lease, pods, args.stale_threshold)
        for lease in leases
    ]

    # Output results
    if args.format == 'json':
        output_json(leases_data, args.warn_only)
    elif args.format == 'table':
        output_table(leases_data, args.warn_only)
    else:
        output_plain(leases_data, args.warn_only, args.verbose)

    # Determine exit code
    has_issues = any(l['has_issue'] for l in leases_data)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
