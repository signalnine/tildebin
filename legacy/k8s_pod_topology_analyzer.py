#!/usr/bin/env python3
"""
Analyze Kubernetes pod topology spread constraints and affinity rules.

This script identifies pods that may be vulnerable to node/zone failures due to
missing or misconfigured topology spread constraints. It helps ensure high
availability by detecting single points of failure in pod distribution.

The script analyzes:
- TopologySpreadConstraints configuration
- Pod affinity and anti-affinity rules
- Pod distribution across nodes and zones
- Deployments/StatefulSets missing topology constraints

Useful for:
- High availability validation
- Identifying single points of failure
- Cluster topology planning
- Pre-deployment validation
- Baremetal cluster operations where node failures are costly

Exit codes:
    0 - No topology issues detected
    1 - Topology issues or risks found
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
    """Get all nodes with their labels."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    nodes_data = json.loads(output)

    nodes = {}
    for node in nodes_data.get('items', []):
        node_name = node.get('metadata', {}).get('name', 'unknown')
        labels = node.get('metadata', {}).get('labels', {})

        nodes[node_name] = {
            'labels': labels,
            'zone': labels.get('topology.kubernetes.io/zone', labels.get('failure-domain.beta.kubernetes.io/zone', 'unknown')),
            'region': labels.get('topology.kubernetes.io/region', labels.get('failure-domain.beta.kubernetes.io/region', 'unknown')),
            'hostname': labels.get('kubernetes.io/hostname', node_name)
        }

    return nodes


def get_pods(namespace=None):
    """Get all pods with their topology configuration."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_deployments(namespace=None):
    """Get all deployments."""
    args = ['get', 'deployments', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_statefulsets(namespace=None):
    """Get all statefulsets."""
    args = ['get', 'statefulsets', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def analyze_topology_spread_constraints(pod_spec):
    """Analyze topology spread constraints in a pod spec."""
    constraints = pod_spec.get('topologySpreadConstraints', [])

    if not constraints:
        return {
            'has_constraints': False,
            'constraints': [],
            'topology_keys': []
        }

    analyzed = []
    topology_keys = set()

    for constraint in constraints:
        topology_key = constraint.get('topologyKey', '')
        max_skew = constraint.get('maxSkew', 1)
        when_unsatisfiable = constraint.get('whenUnsatisfiable', 'DoNotSchedule')
        label_selector = constraint.get('labelSelector', {})

        topology_keys.add(topology_key)

        analyzed.append({
            'topology_key': topology_key,
            'max_skew': max_skew,
            'when_unsatisfiable': when_unsatisfiable,
            'has_label_selector': bool(label_selector)
        })

    return {
        'has_constraints': True,
        'constraints': analyzed,
        'topology_keys': list(topology_keys)
    }


def analyze_affinity(pod_spec):
    """Analyze pod affinity and anti-affinity rules."""
    affinity = pod_spec.get('affinity', {})

    result = {
        'has_pod_affinity': False,
        'has_pod_anti_affinity': False,
        'has_node_affinity': False,
        'pod_affinity_rules': [],
        'pod_anti_affinity_rules': [],
        'node_affinity_rules': []
    }

    # Pod affinity
    pod_affinity = affinity.get('podAffinity', {})
    if pod_affinity:
        result['has_pod_affinity'] = True
        required = pod_affinity.get('requiredDuringSchedulingIgnoredDuringExecution', [])
        preferred = pod_affinity.get('preferredDuringSchedulingIgnoredDuringExecution', [])

        for rule in required:
            result['pod_affinity_rules'].append({
                'type': 'required',
                'topology_key': rule.get('topologyKey', '')
            })

        for rule in preferred:
            pod_affinity_term = rule.get('podAffinityTerm', {})
            result['pod_affinity_rules'].append({
                'type': 'preferred',
                'weight': rule.get('weight', 1),
                'topology_key': pod_affinity_term.get('topologyKey', '')
            })

    # Pod anti-affinity
    pod_anti_affinity = affinity.get('podAntiAffinity', {})
    if pod_anti_affinity:
        result['has_pod_anti_affinity'] = True
        required = pod_anti_affinity.get('requiredDuringSchedulingIgnoredDuringExecution', [])
        preferred = pod_anti_affinity.get('preferredDuringSchedulingIgnoredDuringExecution', [])

        for rule in required:
            result['pod_anti_affinity_rules'].append({
                'type': 'required',
                'topology_key': rule.get('topologyKey', '')
            })

        for rule in preferred:
            pod_affinity_term = rule.get('podAffinityTerm', {})
            result['pod_anti_affinity_rules'].append({
                'type': 'preferred',
                'weight': rule.get('weight', 1),
                'topology_key': pod_affinity_term.get('topologyKey', '')
            })

    # Node affinity
    node_affinity = affinity.get('nodeAffinity', {})
    if node_affinity:
        result['has_node_affinity'] = True
        required = node_affinity.get('requiredDuringSchedulingIgnoredDuringExecution', {})
        preferred = node_affinity.get('preferredDuringSchedulingIgnoredDuringExecution', [])

        if required:
            result['node_affinity_rules'].append({'type': 'required'})
        for _ in preferred:
            result['node_affinity_rules'].append({'type': 'preferred'})

    return result


def analyze_pod_distribution(pods, nodes):
    """Analyze how pods are distributed across nodes and zones."""
    # Group pods by owner (deployment, statefulset, etc.)
    owner_pods = defaultdict(list)

    for pod in pods.get('items', []):
        metadata = pod.get('metadata', {})
        namespace = metadata.get('namespace', 'default')
        pod_name = metadata.get('name', 'unknown')
        node_name = pod.get('spec', {}).get('nodeName')

        # Get owner reference
        owner_refs = metadata.get('ownerReferences', [])
        owner_key = f"{namespace}/standalone"
        for ref in owner_refs:
            if ref.get('kind') in ['ReplicaSet', 'StatefulSet', 'DaemonSet', 'Job']:
                owner_key = f"{namespace}/{ref.get('kind')}/{ref.get('name')}"
                break

        if node_name:
            node_info = nodes.get(node_name, {})
            owner_pods[owner_key].append({
                'name': pod_name,
                'node': node_name,
                'zone': node_info.get('zone', 'unknown')
            })

    # Analyze distribution for each owner
    distribution_issues = []

    for owner_key, pods_list in owner_pods.items():
        if len(pods_list) < 2:
            continue  # Single pod, no distribution to analyze

        namespace, *rest = owner_key.split('/')
        owner_name = '/'.join(rest)

        # Count pods per node
        node_counts = defaultdict(int)
        zone_counts = defaultdict(int)

        for p in pods_list:
            node_counts[p['node']] += 1
            zone_counts[p['zone']] += 1

        # Check for concentration issues
        total_pods = len(pods_list)
        max_on_single_node = max(node_counts.values())
        max_on_single_zone = max(zone_counts.values())
        unique_nodes = len(node_counts)
        unique_zones = len(zone_counts)

        issues = []

        # All pods on single node
        if unique_nodes == 1 and total_pods > 1:
            issues.append(f"All {total_pods} pods on single node: {list(node_counts.keys())[0]}")

        # All pods in single zone
        if unique_zones == 1 and total_pods > 1 and list(zone_counts.keys())[0] != 'unknown':
            issues.append(f"All {total_pods} pods in single zone: {list(zone_counts.keys())[0]}")

        # High concentration on one node (>50% of pods when more than 2 pods)
        if total_pods > 2 and max_on_single_node > total_pods / 2:
            concentrated_node = max(node_counts, key=node_counts.get)
            issues.append(f"{max_on_single_node}/{total_pods} pods concentrated on node: {concentrated_node}")

        if issues:
            distribution_issues.append({
                'namespace': namespace,
                'owner': owner_name,
                'total_pods': total_pods,
                'unique_nodes': unique_nodes,
                'unique_zones': unique_zones,
                'issues': issues,
                'node_distribution': dict(node_counts),
                'zone_distribution': dict(zone_counts)
            })

    return distribution_issues


def analyze_workload(workload, kind):
    """Analyze a deployment or statefulset for topology configuration."""
    metadata = workload.get('metadata', {})
    namespace = metadata.get('namespace', 'default')
    name = metadata.get('name', 'unknown')
    replicas = workload.get('spec', {}).get('replicas', 1)

    pod_spec = workload.get('spec', {}).get('template', {}).get('spec', {})

    topology = analyze_topology_spread_constraints(pod_spec)
    affinity = analyze_affinity(pod_spec)

    issues = []
    severity = 'OK'

    # Check for missing topology spread constraints
    if replicas > 1 and not topology['has_constraints']:
        if not affinity['has_pod_anti_affinity']:
            issues.append("No topology spread constraints or pod anti-affinity defined")
            severity = 'WARNING'

    # Check for zone spread
    if replicas > 1 and topology['has_constraints']:
        has_zone_spread = any(
            'zone' in c['topology_key'].lower()
            for c in topology['constraints']
        )
        if not has_zone_spread:
            issues.append("No zone-level topology spread constraint")

    # Check anti-affinity for HA
    if replicas > 1 and affinity['has_pod_anti_affinity']:
        required_anti_affinity = any(
            r['type'] == 'required'
            for r in affinity['pod_anti_affinity_rules']
        )
        if not required_anti_affinity:
            issues.append("Pod anti-affinity is preferred, not required")

    return {
        'namespace': namespace,
        'name': name,
        'kind': kind,
        'replicas': replicas,
        'has_topology_constraints': topology['has_constraints'],
        'topology_keys': topology['topology_keys'],
        'has_pod_affinity': affinity['has_pod_affinity'],
        'has_pod_anti_affinity': affinity['has_pod_anti_affinity'],
        'has_node_affinity': affinity['has_node_affinity'],
        'issues': issues,
        'severity': severity if not issues else ('CRITICAL' if replicas > 2 else 'WARNING')
    }


def format_output_plain(results):
    """Format output as plain text."""
    workloads = results.get('workloads', [])
    distribution = results.get('distribution_issues', [])

    for w in workloads:
        if w['issues']:
            issues_str = "; ".join(w['issues'])[:60]
            print(f"{w['namespace']} {w['kind']}/{w['name']} replicas={w['replicas']} {w['severity']} {issues_str}")

    for d in distribution:
        issues_str = "; ".join(d['issues'])[:60]
        print(f"{d['namespace']} {d['owner']} pods={d['total_pods']} nodes={d['unique_nodes']} zones={d['unique_zones']} {issues_str}")


def format_output_table(results):
    """Format output as ASCII table."""
    workloads = results.get('workloads', [])
    distribution = results.get('distribution_issues', [])

    if workloads:
        print("WORKLOAD TOPOLOGY ANALYSIS")
        print(f"{'NAMESPACE':<20} {'WORKLOAD':<35} {'REPLICAS':<10} {'TOPOLOGY':<10} {'SEVERITY':<10} {'ISSUES':<40}")
        print("-" * 125)

        for w in workloads:
            workload_name = f"{w['kind']}/{w['name']}"[:35]
            topology = "Yes" if w['has_topology_constraints'] else "No"
            issues_str = "; ".join(w['issues'])[:40] if w['issues'] else "None"
            print(f"{w['namespace']:<20} {workload_name:<35} {w['replicas']:<10} {topology:<10} {w['severity']:<10} {issues_str:<40}")

        print()

    if distribution:
        print("POD DISTRIBUTION ISSUES")
        print(f"{'NAMESPACE':<20} {'OWNER':<35} {'PODS':<8} {'NODES':<8} {'ZONES':<8} {'ISSUES':<50}")
        print("-" * 130)

        for d in distribution:
            issues_str = "; ".join(d['issues'])[:50]
            print(f"{d['namespace']:<20} {d['owner']:<35} {d['total_pods']:<8} {d['unique_nodes']:<8} {d['unique_zones']:<8} {issues_str:<50}")


def format_output_json(results):
    """Format output as JSON."""
    print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes pod topology spread constraints and affinity rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all workloads for topology issues
  k8s_pod_topology_analyzer.py

  # Check specific namespace
  k8s_pod_topology_analyzer.py -n production

  # Show only workloads with issues
  k8s_pod_topology_analyzer.py --warn-only

  # Get JSON output for monitoring integration
  k8s_pod_topology_analyzer.py --format json
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
        help="Only show workloads with topology issues"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed topology information"
    )

    args = parser.parse_args()

    # Gather data
    nodes = get_nodes()
    pods = get_pods(args.namespace)
    deployments = get_deployments(args.namespace)
    statefulsets = get_statefulsets(args.namespace)

    # Analyze workloads
    workloads = []

    for deployment in deployments.get('items', []):
        analysis = analyze_workload(deployment, 'Deployment')
        if not args.warn_only or analysis['issues']:
            workloads.append(analysis)

    for statefulset in statefulsets.get('items', []):
        analysis = analyze_workload(statefulset, 'StatefulSet')
        if not args.warn_only or analysis['issues']:
            workloads.append(analysis)

    # Analyze pod distribution
    distribution_issues = analyze_pod_distribution(pods, nodes)

    # Prepare results
    results = {
        'summary': {
            'total_workloads': len(workloads),
            'workloads_with_issues': len([w for w in workloads if w['issues']]),
            'distribution_issues': len(distribution_issues),
            'total_nodes': len(nodes),
            'unique_zones': len(set(n['zone'] for n in nodes.values() if n['zone'] != 'unknown'))
        },
        'workloads': workloads,
        'distribution_issues': distribution_issues
    }

    # Format and output
    if args.format == "plain":
        format_output_plain(results)
    elif args.format == "table":
        format_output_table(results)
    elif args.format == "json":
        format_output_json(results)

    # Determine exit code
    has_issues = bool(results['summary']['workloads_with_issues'] or results['summary']['distribution_issues'])
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
