#!/usr/bin/env python3
"""
Audit Kubernetes pod QoS (Quality of Service) classes across a cluster.

This script analyzes pod QoS class assignments and identifies potential issues:
- Pods with BestEffort QoS (first to be evicted under memory pressure)
- Pods with Burstable QoS that could be Guaranteed
- Critical workloads without Guaranteed QoS
- Namespace-level QoS distribution analysis
- Eviction risk assessment based on QoS classes

QoS Classes:
    Guaranteed - CPU/memory requests equal limits for all containers
    Burstable  - At least one container has CPU or memory request
    BestEffort - No CPU or memory requests/limits set

Use cases:
    - Audit cluster for eviction-prone workloads
    - Identify pods that need resource configuration
    - Plan capacity based on QoS distribution
    - Ensure critical workloads have appropriate QoS

Exit codes:
    0 - No issues detected (all pods have appropriate QoS)
    1 - Issues found (BestEffort pods or misconfigured workloads)
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
        return None


def get_pods(namespace=None):
    """Get all pods in JSON format."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    if not output:
        return []
    return json.loads(output).get('items', [])


def determine_qos_class(pod):
    """
    Determine the QoS class for a pod based on container resource specs.

    Returns tuple of (qos_class, reason, can_upgrade, upgrade_suggestion)
    """
    containers = pod.get('spec', {}).get('containers', [])
    init_containers = pod.get('spec', {}).get('initContainers', [])
    all_containers = containers + init_containers

    if not all_containers:
        return 'BestEffort', 'no containers', False, None

    all_have_requests_and_limits = True
    all_requests_equal_limits = True
    has_any_request_or_limit = False
    missing_specs = []

    for container in all_containers:
        resources = container.get('resources', {})
        requests = resources.get('requests', {})
        limits = resources.get('limits', {})
        name = container.get('name', 'unknown')

        cpu_req = requests.get('cpu')
        cpu_lim = limits.get('cpu')
        mem_req = requests.get('memory')
        mem_lim = limits.get('memory')

        # Track what's missing
        if cpu_req or cpu_lim or mem_req or mem_lim:
            has_any_request_or_limit = True

        # Check for Guaranteed requirements
        if not (cpu_req and cpu_lim and mem_req and mem_lim):
            all_have_requests_and_limits = False
            missing = []
            if not cpu_req:
                missing.append('cpu request')
            if not cpu_lim:
                missing.append('cpu limit')
            if not mem_req:
                missing.append('memory request')
            if not mem_lim:
                missing.append('memory limit')
            if missing:
                missing_specs.append(f"{name}: {', '.join(missing)}")

        # Check if requests equal limits
        if cpu_req != cpu_lim or mem_req != mem_lim:
            all_requests_equal_limits = False

    # Determine QoS class
    if not has_any_request_or_limit:
        return 'BestEffort', 'no resource specs', True, 'Add CPU/memory requests and limits'

    if all_have_requests_and_limits and all_requests_equal_limits:
        return 'Guaranteed', 'all requests equal limits', False, None

    # Burstable
    if all_have_requests_and_limits:
        reason = 'requests != limits'
        suggestion = 'Set requests equal to limits for Guaranteed QoS'
    else:
        reason = f"missing: {'; '.join(missing_specs[:2])}"
        if len(missing_specs) > 2:
            reason += f" (+{len(missing_specs) - 2} more)"
        suggestion = 'Add missing resource specs for all containers'

    return 'Burstable', reason, True, suggestion


def analyze_pod(pod):
    """Analyze a single pod's QoS configuration."""
    metadata = pod.get('metadata', {})
    spec = pod.get('spec', {})
    status = pod.get('status', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    phase = status.get('phase', 'Unknown')

    # Get owner reference
    owner_refs = metadata.get('ownerReferences', [])
    owner_kind = owner_refs[0].get('kind', 'None') if owner_refs else 'None'
    owner_name = owner_refs[0].get('name', 'None') if owner_refs else 'None'

    # Get QoS class from status (if available) or calculate it
    qos_class = status.get('qosClass', None)
    calculated_qos, reason, can_upgrade, suggestion = determine_qos_class(pod)

    # Use calculated if status doesn't have it
    if not qos_class:
        qos_class = calculated_qos

    # Check for critical labels/annotations
    labels = metadata.get('labels', {})
    annotations = metadata.get('annotations', {})

    is_critical = (
        labels.get('app.kubernetes.io/component') in ['controller', 'scheduler', 'etcd'] or
        'critical' in labels.get('tier', '').lower() or
        'critical' in labels.get('priority', '').lower() or
        namespace.startswith('kube-') or
        annotations.get('scheduler.alpha.kubernetes.io/critical-pod') == 'true'
    )

    # Count containers
    container_count = len(spec.get('containers', []))
    init_container_count = len(spec.get('initContainers', []))

    return {
        'name': name,
        'namespace': namespace,
        'phase': phase,
        'qos_class': qos_class,
        'calculated_qos': calculated_qos,
        'reason': reason,
        'can_upgrade': can_upgrade,
        'upgrade_suggestion': suggestion,
        'owner_kind': owner_kind,
        'owner_name': owner_name,
        'is_critical': is_critical,
        'container_count': container_count,
        'init_container_count': init_container_count
    }


def categorize_findings(analyses, critical_only=False):
    """Categorize pods by QoS class and identify issues."""
    categories = {
        'Guaranteed': [],
        'Burstable': [],
        'BestEffort': []
    }

    issues = {
        'critical_not_guaranteed': [],  # Critical pods without Guaranteed QoS
        'best_effort': [],              # Any BestEffort pods (eviction risk)
        'upgradeable': []               # Burstable that could be Guaranteed
    }

    namespace_stats = defaultdict(lambda: {'Guaranteed': 0, 'Burstable': 0, 'BestEffort': 0})

    for analysis in analyses:
        qos = analysis['qos_class']
        categories[qos].append(analysis)
        namespace_stats[analysis['namespace']][qos] += 1

        # Track issues
        if qos == 'BestEffort':
            issues['best_effort'].append(analysis)

        if analysis['is_critical'] and qos != 'Guaranteed':
            issues['critical_not_guaranteed'].append(analysis)

        if qos == 'Burstable' and analysis['can_upgrade']:
            if not critical_only or analysis['is_critical']:
                issues['upgradeable'].append(analysis)

    return categories, issues, dict(namespace_stats)


def output_plain(categories, issues, namespace_stats, verbose=False, warn_only=False):
    """Output results in plain text format."""
    total = sum(len(pods) for pods in categories.values())

    if not warn_only:
        print("Kubernetes QoS Class Audit")
        print("=" * 80)
        print(f"Total pods analyzed: {total}")
        print(f"  Guaranteed:  {len(categories['Guaranteed']):4d} (protected from eviction)")
        print(f"  Burstable:   {len(categories['Burstable']):4d} (may be evicted under pressure)")
        print(f"  BestEffort:  {len(categories['BestEffort']):4d} (first to be evicted)")
        print()

    # Critical pods not Guaranteed
    if issues['critical_not_guaranteed']:
        print(f"Critical Pods Without Guaranteed QoS ({len(issues['critical_not_guaranteed'])}):")
        print("-" * 80)
        for pod in issues['critical_not_guaranteed']:
            print(f"  {pod['namespace']}/{pod['name']}")
            print(f"    QoS: {pod['qos_class']} - {pod['reason']}")
            print(f"    Owner: {pod['owner_kind']}/{pod['owner_name']}")
            if pod['upgrade_suggestion']:
                print(f"    Fix: {pod['upgrade_suggestion']}")
            print()

    # BestEffort pods
    if issues['best_effort']:
        print(f"BestEffort Pods - High Eviction Risk ({len(issues['best_effort'])}):")
        print("-" * 80)
        for pod in sorted(issues['best_effort'], key=lambda x: (x['namespace'], x['name'])):
            print(f"  {pod['namespace']}/{pod['name']}")
            print(f"    Owner: {pod['owner_kind']}/{pod['owner_name']}")
            print(f"    Fix: {pod['upgrade_suggestion']}")
            if verbose:
                print(f"    Containers: {pod['container_count']}")
            print()

    # Upgradeable Burstable pods
    if issues['upgradeable'] and verbose:
        print(f"Burstable Pods Upgradeable to Guaranteed ({len(issues['upgradeable'])}):")
        print("-" * 80)
        for pod in sorted(issues['upgradeable'], key=lambda x: (x['namespace'], x['name']))[:20]:
            print(f"  {pod['namespace']}/{pod['name']}")
            print(f"    Reason: {pod['reason']}")
            print(f"    Fix: {pod['upgrade_suggestion']}")
            print()
        if len(issues['upgradeable']) > 20:
            print(f"  ... and {len(issues['upgradeable']) - 20} more")
            print()

    # Namespace summary
    if not warn_only and namespace_stats:
        print("QoS Distribution by Namespace:")
        print("-" * 80)
        print(f"{'NAMESPACE':<30} {'GUARANTEED':>12} {'BURSTABLE':>12} {'BESTEFFORT':>12}")
        print("-" * 80)
        for ns in sorted(namespace_stats.keys()):
            stats = namespace_stats[ns]
            print(f"{ns:<30} {stats['Guaranteed']:>12} {stats['Burstable']:>12} {stats['BestEffort']:>12}")
        print()

    # Summary
    has_issues = bool(issues['critical_not_guaranteed'] or issues['best_effort'])
    if has_issues:
        print("Recommendations:")
        print("-" * 80)
        if issues['critical_not_guaranteed']:
            print(f"  - {len(issues['critical_not_guaranteed'])} critical pods need Guaranteed QoS")
        if issues['best_effort']:
            print(f"  - {len(issues['best_effort'])} pods have BestEffort QoS (high eviction risk)")
        if issues['upgradeable']:
            print(f"  - {len(issues['upgradeable'])} Burstable pods could be upgraded to Guaranteed")
    elif warn_only:
        print("No QoS issues detected")

    return has_issues


def output_json(categories, issues, namespace_stats):
    """Output results in JSON format."""
    result = {
        'summary': {
            'total': sum(len(pods) for pods in categories.values()),
            'guaranteed': len(categories['Guaranteed']),
            'burstable': len(categories['Burstable']),
            'best_effort': len(categories['BestEffort'])
        },
        'issues': {
            'critical_not_guaranteed': issues['critical_not_guaranteed'],
            'best_effort': issues['best_effort'],
            'upgradeable_count': len(issues['upgradeable'])
        },
        'namespace_distribution': namespace_stats,
        'categories': {
            'guaranteed': categories['Guaranteed'],
            'burstable': categories['Burstable'],
            'best_effort': categories['BestEffort']
        }
    }
    print(json.dumps(result, indent=2, default=str))

    has_issues = bool(issues['critical_not_guaranteed'] or issues['best_effort'])
    return has_issues


def output_table(categories, issues, namespace_stats, warn_only=False):
    """Output results in table format."""
    all_pods = []
    for qos, pods in categories.items():
        all_pods.extend(pods)

    if warn_only:
        all_pods = [p for p in all_pods if p['qos_class'] == 'BestEffort' or
                    (p['is_critical'] and p['qos_class'] != 'Guaranteed')]

    # Sort by QoS class (BestEffort first), then namespace, then name
    qos_order = {'BestEffort': 0, 'Burstable': 1, 'Guaranteed': 2}
    all_pods.sort(key=lambda x: (qos_order.get(x['qos_class'], 3), x['namespace'], x['name']))

    print(f"{'NAMESPACE':<20} {'POD':<35} {'QOS':<12} {'OWNER':<20} {'CRITICAL':<8}")
    print("-" * 100)

    for pod in all_pods:
        ns = pod['namespace'][:18] + '..' if len(pod['namespace']) > 20 else pod['namespace']
        name = pod['name'][:33] + '..' if len(pod['name']) > 35 else pod['name']
        owner = f"{pod['owner_kind'][:8]}/{pod['owner_name'][:9]}"
        critical = "YES" if pod['is_critical'] else ""

        print(f"{ns:<20} {name:<35} {pod['qos_class']:<12} {owner:<20} {critical:<8}")

    print()
    print(f"Total: {len(all_pods)} | "
          f"Guaranteed: {len(categories['Guaranteed'])} | "
          f"Burstable: {len(categories['Burstable'])} | "
          f"BestEffort: {len(categories['BestEffort'])}")

    has_issues = bool(issues['critical_not_guaranteed'] or issues['best_effort'])
    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Audit Kubernetes pod QoS classes and identify eviction risks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Audit all pods
  %(prog)s -n production                # Audit specific namespace
  %(prog)s --warn-only                  # Only show issues
  %(prog)s --format json                # JSON output for automation
  %(prog)s -v                           # Show upgrade recommendations
  %(prog)s --critical-only              # Focus on critical workloads

QoS Classes:
  Guaranteed  - All containers have CPU/memory requests equal to limits
  Burstable   - At least one container has a CPU or memory request
  BestEffort  - No resource requests or limits (first to be evicted)

Exit codes:
  0 - No issues detected
  1 - Issues found (BestEffort or critical pods without Guaranteed QoS)
  2 - kubectl unavailable
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Kubernetes namespace to audit (default: all namespaces)'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show pods with QoS issues'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed recommendations and upgradeable pods'
    )
    parser.add_argument(
        '--critical-only',
        action='store_true',
        help='Only analyze pods marked as critical'
    )
    parser.add_argument(
        '--exclude-namespace',
        action='append',
        default=[],
        help='Namespaces to exclude (can be specified multiple times)'
    )

    args = parser.parse_args()

    # Get pods
    pods = get_pods(args.namespace)
    if not pods:
        if args.format == 'json':
            print(json.dumps({'summary': {'total': 0}, 'categories': {}}))
        else:
            print("No pods found")
        sys.exit(0)

    # Analyze each pod
    analyses = []
    for pod in pods:
        ns = pod.get('metadata', {}).get('namespace', '')
        if ns in args.exclude_namespace:
            continue

        analysis = analyze_pod(pod)

        # Filter by phase - only analyze running/pending pods
        if analysis['phase'] not in ['Running', 'Pending']:
            continue

        # Filter by critical if requested
        if args.critical_only and not analysis['is_critical']:
            continue

        analyses.append(analysis)

    if not analyses:
        if args.format == 'json':
            print(json.dumps({'summary': {'total': 0}, 'categories': {}}))
        else:
            print("No matching pods found")
        sys.exit(0)

    # Categorize findings
    categories, issues, namespace_stats = categorize_findings(
        analyses,
        critical_only=args.critical_only
    )

    # Output results
    if args.format == 'json':
        has_issues = output_json(categories, issues, namespace_stats)
    elif args.format == 'table':
        has_issues = output_table(categories, issues, namespace_stats, args.warn_only)
    else:
        has_issues = output_plain(categories, issues, namespace_stats, args.verbose, args.warn_only)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
