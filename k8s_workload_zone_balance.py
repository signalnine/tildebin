#!/usr/bin/env python3
"""
Analyze Kubernetes workload distribution across topology zones.

This script checks whether pods are properly distributed across failure domains
(availability zones, regions, or custom topology keys) to ensure high availability.
It identifies workloads with poor zone distribution that could be affected by
zone-level failures.

The script analyzes:
- Pod distribution across zones for each workload (Deployment, StatefulSet, DaemonSet)
- Zone imbalance ratios and single-zone vulnerabilities
- Topology spread constraints compliance
- Workloads lacking zone redundancy

Useful for:
- Pre-maintenance checks to ensure zone failover readiness
- Capacity planning across availability zones
- Compliance auditing for HA requirements
- Identifying workloads needing topology spread constraints

Exit codes:
    0 - All workloads have acceptable zone distribution
    1 - One or more workloads have poor zone distribution
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
    """Get all nodes with their zone labels."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    nodes_data = json.loads(output)

    nodes = {}
    for node in nodes_data.get('items', []):
        node_name = node.get('metadata', {}).get('name', 'unknown')
        labels = node.get('metadata', {}).get('labels', {})

        # Common topology keys
        zone = (
            labels.get('topology.kubernetes.io/zone') or
            labels.get('failure-domain.beta.kubernetes.io/zone') or
            labels.get('zone') or
            'unknown'
        )
        region = (
            labels.get('topology.kubernetes.io/region') or
            labels.get('failure-domain.beta.kubernetes.io/region') or
            labels.get('region') or
            'unknown'
        )

        nodes[node_name] = {
            'zone': zone,
            'region': region,
            'labels': labels
        }

    return nodes


def get_pods(namespace=None):
    """Get all pods with their node assignments."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_workload_owner(pod):
    """Get the workload (Deployment, StatefulSet, etc.) owning a pod."""
    owner_refs = pod.get('metadata', {}).get('ownerReferences', [])

    for owner in owner_refs:
        kind = owner.get('kind', '')
        name = owner.get('name', '')

        if kind == 'ReplicaSet':
            # Get the Deployment from ReplicaSet name (format: deployment-name-hash)
            parts = name.rsplit('-', 1)
            if len(parts) > 1:
                return 'Deployment', parts[0]
            return 'ReplicaSet', name
        elif kind in ['StatefulSet', 'DaemonSet', 'Job']:
            return kind, name

    return 'Standalone', pod.get('metadata', {}).get('name', 'unknown')


def analyze_zone_distribution(pods_data, nodes, min_zones=2):
    """
    Analyze zone distribution for each workload.

    Returns a list of workload analyses with zone distribution metrics.
    """
    # Group pods by workload
    workloads = defaultdict(lambda: {
        'pods': [],
        'zones': defaultdict(int),
        'nodes': set()
    })

    for pod in pods_data.get('items', []):
        namespace = pod.get('metadata', {}).get('namespace', 'default')
        pod_name = pod.get('metadata', {}).get('name', 'unknown')
        node_name = pod.get('spec', {}).get('nodeName')
        phase = pod.get('status', {}).get('phase', 'Unknown')

        # Skip non-running pods
        if phase not in ['Running', 'Pending']:
            continue

        kind, workload_name = get_workload_owner(pod)
        key = (namespace, kind, workload_name)

        if node_name and node_name in nodes:
            zone = nodes[node_name]['zone']
        else:
            zone = 'unscheduled' if not node_name else 'unknown'

        workloads[key]['pods'].append({
            'name': pod_name,
            'node': node_name,
            'zone': zone,
            'phase': phase
        })
        workloads[key]['zones'][zone] += 1
        if node_name:
            workloads[key]['nodes'].add(node_name)

    # Analyze each workload
    results = []
    for (namespace, kind, name), data in workloads.items():
        pod_count = len(data['pods'])
        zone_count = len([z for z in data['zones'] if z not in ('unknown', 'unscheduled')])
        zones = dict(data['zones'])

        # Calculate zone balance metrics
        if zone_count > 0:
            zone_values = [v for k, v in zones.items() if k not in ('unknown', 'unscheduled')]
            max_in_zone = max(zone_values) if zone_values else 0
            min_in_zone = min(zone_values) if zone_values else 0
            imbalance_ratio = (max_in_zone / min_in_zone) if min_in_zone > 0 else float('inf')
        else:
            max_in_zone = 0
            min_in_zone = 0
            imbalance_ratio = 0

        # Determine risk level
        issues = []
        risk_level = 'OK'

        if pod_count >= min_zones and zone_count == 1:
            # Single zone is the worst case - no zone redundancy
            issues.append("All pods in single zone - no zone redundancy")
            risk_level = 'CRITICAL'
        elif pod_count >= min_zones and zone_count < min_zones:
            issues.append(f"Only {zone_count} zone(s) but has {pod_count} pods")
            risk_level = 'HIGH'
        elif imbalance_ratio > 2.0 and zone_count >= min_zones:
            issues.append(f"Zone imbalance ratio: {imbalance_ratio:.1f}x")
            risk_level = 'MEDIUM'

        # Check for unscheduled pods
        unscheduled = zones.get('unscheduled', 0)
        if unscheduled > 0:
            issues.append(f"{unscheduled} pod(s) unscheduled")
            if risk_level == 'OK':
                risk_level = 'MEDIUM'

        # Skip standalone pods with only 1 replica (expected behavior)
        if kind == 'Standalone' and pod_count == 1:
            continue

        # Skip DaemonSets (they run on all nodes by design)
        if kind == 'DaemonSet':
            continue

        results.append({
            'namespace': namespace,
            'kind': kind,
            'name': name,
            'pod_count': pod_count,
            'zone_count': zone_count,
            'zones': zones,
            'node_count': len(data['nodes']),
            'imbalance_ratio': imbalance_ratio if imbalance_ratio != float('inf') else 999.9,
            'risk_level': risk_level,
            'issues': issues
        })

    # Sort by risk level (CRITICAL > HIGH > MEDIUM > OK)
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'OK': 3}
    results.sort(key=lambda x: (risk_order.get(x['risk_level'], 4), -x['pod_count']))

    return results


def get_zone_summary(nodes):
    """Get summary of nodes per zone."""
    zone_counts = defaultdict(int)
    for node_name, node_info in nodes.items():
        zone_counts[node_info['zone']] += 1
    return dict(zone_counts)


def format_plain(results, zone_summary, warn_only):
    """Format output as plain text."""
    lines = []

    # Zone summary
    lines.append("Cluster Zones:")
    for zone, count in sorted(zone_summary.items()):
        lines.append(f"  {zone}: {count} nodes")
    lines.append("")

    # Workload analysis
    for r in results:
        if warn_only and r['risk_level'] == 'OK':
            continue

        zones_str = ", ".join(f"{z}:{c}" for z, c in sorted(r['zones'].items()))
        lines.append(
            f"{r['namespace']} {r['kind']}/{r['name']} "
            f"pods={r['pod_count']} zones={r['zone_count']} "
            f"[{r['risk_level']}] ({zones_str})"
        )
        for issue in r['issues']:
            lines.append(f"  - {issue}")

    return "\n".join(lines)


def format_table(results, zone_summary, warn_only):
    """Format output as ASCII table."""
    lines = []

    # Zone summary header
    lines.append("CLUSTER ZONE SUMMARY")
    lines.append("-" * 40)
    for zone, count in sorted(zone_summary.items()):
        lines.append(f"  {zone:<25} {count} nodes")
    lines.append("")

    # Workload table
    lines.append(f"{'NAMESPACE':<20} {'WORKLOAD':<35} {'PODS':<6} {'ZONES':<6} {'RISK':<10} {'DISTRIBUTION'}")
    lines.append("-" * 120)

    for r in results:
        if warn_only and r['risk_level'] == 'OK':
            continue

        workload = f"{r['kind'][:3]}/{r['name']}"[:35]
        zones_str = ", ".join(f"{z}:{c}" for z, c in sorted(r['zones'].items()))[:40]

        lines.append(
            f"{r['namespace']:<20} {workload:<35} {r['pod_count']:<6} "
            f"{r['zone_count']:<6} {r['risk_level']:<10} {zones_str}"
        )

    return "\n".join(lines)


def format_json(results, zone_summary, warn_only):
    """Format output as JSON."""
    output = {
        'cluster_zones': zone_summary,
        'total_workloads': len(results),
        'workloads_at_risk': len([r for r in results if r['risk_level'] != 'OK']),
        'workloads': [r for r in results if not warn_only or r['risk_level'] != 'OK']
    }
    return json.dumps(output, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes workload distribution across topology zones",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check zone distribution for all workloads
  k8s_workload_zone_balance.py

  # Check specific namespace
  k8s_workload_zone_balance.py -n production

  # Show only workloads with zone issues
  k8s_workload_zone_balance.py --warn-only

  # Require at least 3 zones for HA
  k8s_workload_zone_balance.py --min-zones 3

  # JSON output for monitoring integration
  k8s_workload_zone_balance.py --format json
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
        help="Only show workloads with zone distribution issues"
    )
    parser.add_argument(
        "--min-zones",
        type=int,
        default=2,
        help="Minimum zones required for HA (default: 2)"
    )

    args = parser.parse_args()

    # Get cluster data
    nodes = get_nodes()
    if not nodes:
        print("Error: No nodes found in cluster", file=sys.stderr)
        sys.exit(1)

    zone_summary = get_zone_summary(nodes)
    pods_data = get_pods(args.namespace)
    results = analyze_zone_distribution(pods_data, nodes, args.min_zones)

    if not results:
        if args.namespace:
            print(f"No workloads found in namespace {args.namespace}", file=sys.stderr)
        else:
            print("No workloads found in cluster", file=sys.stderr)
        sys.exit(0)

    # Format output
    if args.format == "plain":
        print(format_plain(results, zone_summary, args.warn_only))
    elif args.format == "table":
        print(format_table(results, zone_summary, args.warn_only))
    elif args.format == "json":
        print(format_json(results, zone_summary, args.warn_only))

    # Exit code based on findings
    has_issues = any(r['risk_level'] != 'OK' for r in results)
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
