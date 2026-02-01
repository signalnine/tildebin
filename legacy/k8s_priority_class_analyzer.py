#!/usr/bin/env python3
"""
Analyze Kubernetes PriorityClass configuration and usage.

This script audits PriorityClasses in a Kubernetes cluster to help understand
and manage pod scheduling priorities. Critical for large-scale clusters where
proper priority configuration prevents:
- Unexpected pod preemption
- Critical workloads being evicted
- Resource starvation for low-priority pods
- Misconfigured or missing PriorityClass assignments

Key features:
- List all PriorityClasses with their priority values
- Identify pods using each PriorityClass
- Detect pods without explicit PriorityClass assignment
- Warn about global default conflicts
- Analyze preemption policy settings

Exit codes:
    0 - No issues detected
    1 - Warnings or issues found (pods without priority, conflicts)
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


def get_priority_classes():
    """Get all PriorityClasses in the cluster."""
    output = run_kubectl(['get', 'priorityclasses', '-o', 'json'])
    data = json.loads(output)
    return data.get('items', [])


def get_pods(namespace=None):
    """Get all pods, optionally filtered by namespace."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    data = json.loads(output)
    return data.get('items', [])


def analyze_priority_classes(priority_classes, pods):
    """
    Analyze PriorityClass configuration and usage.

    Returns:
        dict with analysis results
    """
    # Map priority class names to their configs
    pc_map = {}
    global_defaults = []

    for pc in priority_classes:
        name = pc['metadata']['name']
        value = pc.get('value', 0)
        global_default = pc.get('globalDefault', False)
        preemption_policy = pc.get('preemptionPolicy', 'PreemptLowerPriority')
        description = pc.get('description', '')

        pc_map[name] = {
            'name': name,
            'value': value,
            'global_default': global_default,
            'preemption_policy': preemption_policy,
            'description': description,
            'pod_count': 0,
            'namespaces': set(),
        }

        if global_default:
            global_defaults.append(name)

    # Count pods using each priority class
    pods_without_priority = []
    pods_by_priority = defaultdict(list)

    for pod in pods:
        metadata = pod.get('metadata', {})
        spec = pod.get('spec', {})
        pod_name = metadata.get('name', 'unknown')
        namespace = metadata.get('namespace', 'default')

        priority_class_name = spec.get('priorityClassName')
        priority = spec.get('priority')

        if priority_class_name:
            pods_by_priority[priority_class_name].append({
                'name': pod_name,
                'namespace': namespace,
                'priority': priority,
            })
            if priority_class_name in pc_map:
                pc_map[priority_class_name]['pod_count'] += 1
                pc_map[priority_class_name]['namespaces'].add(namespace)
        else:
            # Pod has no explicit PriorityClass
            pods_without_priority.append({
                'name': pod_name,
                'namespace': namespace,
                'priority': priority,
            })

    # Convert sets to lists for JSON serialization
    for pc in pc_map.values():
        pc['namespaces'] = sorted(pc['namespaces'])

    # Sort priority classes by value (descending)
    sorted_pcs = sorted(pc_map.values(), key=lambda x: x['value'], reverse=True)

    return {
        'priority_classes': sorted_pcs,
        'pods_by_priority': dict(pods_by_priority),
        'pods_without_priority': pods_without_priority,
        'global_defaults': global_defaults,
        'total_pods': len(pods),
        'pods_with_priority': len(pods) - len(pods_without_priority),
    }


def check_issues(analysis):
    """Check for issues and return list of warnings."""
    issues = []

    # Check for multiple global defaults (configuration error)
    if len(analysis['global_defaults']) > 1:
        issues.append({
            'severity': 'WARNING',
            'type': 'multiple_global_defaults',
            'classes': analysis['global_defaults'],
            'message': f"Multiple PriorityClasses marked as globalDefault: {', '.join(analysis['global_defaults'])}"
        })

    # Check for pods without explicit priority class
    pods_without = analysis['pods_without_priority']
    if pods_without:
        # Group by namespace
        ns_counts = defaultdict(int)
        for pod in pods_without:
            ns_counts[pod['namespace']] += 1

        issues.append({
            'severity': 'INFO',
            'type': 'pods_without_priority',
            'count': len(pods_without),
            'namespaces': dict(ns_counts),
            'message': f"{len(pods_without)} pods have no explicit PriorityClass assignment"
        })

    # Check for unused PriorityClasses (excluding system ones)
    for pc in analysis['priority_classes']:
        if pc['pod_count'] == 0 and not pc['name'].startswith('system-'):
            issues.append({
                'severity': 'INFO',
                'type': 'unused_priority_class',
                'class': pc['name'],
                'message': f"PriorityClass '{pc['name']}' is defined but not used by any pods"
            })

    # Check for very high priority non-system classes (potential misconfiguration)
    for pc in analysis['priority_classes']:
        if pc['value'] >= 1000000000 and not pc['name'].startswith('system-'):
            issues.append({
                'severity': 'WARNING',
                'type': 'very_high_priority',
                'class': pc['name'],
                'value': pc['value'],
                'message': f"PriorityClass '{pc['name']}' has very high priority ({pc['value']}), usually reserved for system components"
            })

    # Check for PreemptNever on high-priority classes (might be intentional but worth noting)
    for pc in analysis['priority_classes']:
        if pc['value'] > 0 and pc['preemption_policy'] == 'Never':
            issues.append({
                'severity': 'INFO',
                'type': 'preempt_never_high_priority',
                'class': pc['name'],
                'message': f"PriorityClass '{pc['name']}' has preemptionPolicy=Never despite positive priority"
            })

    return issues


def output_plain(data, verbose=False, warn_only=False):
    """Output results in plain text format."""
    if warn_only and not data['issues']:
        return

    analysis = data['analysis']

    print(f"PriorityClass Analysis")
    print(f"======================")
    print(f"Total PriorityClasses: {len(analysis['priority_classes'])}")
    print(f"Total Pods: {analysis['total_pods']}")
    print(f"Pods with explicit priority: {analysis['pods_with_priority']}")
    print(f"Pods without explicit priority: {len(analysis['pods_without_priority'])}")
    print()

    print("PriorityClasses (sorted by priority value):")
    print("-" * 80)
    print(f"{'Name':<35} {'Value':<12} {'Pods':<8} {'Preemption':<20} {'Default'}")
    print("-" * 80)

    for pc in analysis['priority_classes']:
        default_marker = '*' if pc['global_default'] else ''
        print(f"{pc['name']:<35} {pc['value']:<12} {pc['pod_count']:<8} {pc['preemption_policy']:<20} {default_marker}")

    if verbose and analysis['pods_without_priority']:
        print()
        print(f"Pods without explicit PriorityClass ({len(analysis['pods_without_priority'])}):")
        print("-" * 60)
        for pod in analysis['pods_without_priority'][:20]:  # Limit output
            print(f"  {pod['namespace']}/{pod['name']}")
        if len(analysis['pods_without_priority']) > 20:
            print(f"  ... and {len(analysis['pods_without_priority']) - 20} more")

    if data['issues']:
        print()
        print("Issues:")
        print("-" * 60)
        for issue in data['issues']:
            print(f"[{issue['severity']}] {issue['message']}")


def output_json(data):
    """Output results in JSON format."""
    print(json.dumps(data, indent=2, default=str))


def output_table(data, verbose=False, warn_only=False):
    """Output results in table format."""
    if warn_only and not data['issues']:
        return

    analysis = data['analysis']

    print("=" * 90)
    print(f"{'PriorityClass Analysis':^90}")
    print("=" * 90)
    print(f"Total Classes: {len(analysis['priority_classes'])}  |  "
          f"Total Pods: {analysis['total_pods']}  |  "
          f"With Priority: {analysis['pods_with_priority']}  |  "
          f"Without: {len(analysis['pods_without_priority'])}")
    print("=" * 90)

    print()
    print(f"{'PriorityClass Name':<35} {'Value':>12} {'Pods':>8} {'Preemption Policy':<22} {'Def'}")
    print("-" * 90)

    for pc in analysis['priority_classes']:
        default_marker = 'Yes' if pc['global_default'] else ''
        print(f"{pc['name']:<35} {pc['value']:>12} {pc['pod_count']:>8} {pc['preemption_policy']:<22} {default_marker}")

    if data['issues']:
        print()
        print("=" * 90)
        print("Issues Detected:")
        print("-" * 90)
        for issue in data['issues']:
            print(f"[{issue['severity']}] {issue['message']}")

    print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes PriorityClass configuration and usage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis of all PriorityClasses
  k8s_priority_class_analyzer.py

  # JSON output for monitoring integration
  k8s_priority_class_analyzer.py --format json

  # Check specific namespace pods
  k8s_priority_class_analyzer.py -n production

  # Show detailed info including pods without priority
  k8s_priority_class_analyzer.py -v

  # Only show output if issues detected
  k8s_priority_class_analyzer.py --warn-only

PriorityClass basics:
  - Higher value = higher scheduling priority
  - system-cluster-critical and system-node-critical are reserved for system pods
  - globalDefault=true applies to pods without explicit priorityClassName
  - PreemptLowerPriority allows evicting lower-priority pods
        """
    )

    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to analyze (default: all namespaces)"
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including pods without priority"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if issues are detected"
    )

    args = parser.parse_args()

    # Get data from cluster
    priority_classes = get_priority_classes()
    pods = get_pods(args.namespace)

    # Analyze
    analysis = analyze_priority_classes(priority_classes, pods)
    issues = check_issues(analysis)

    # Prepare output data
    data = {
        'analysis': analysis,
        'issues': issues,
        'namespace_filter': args.namespace,
    }

    # Handle warn-only mode
    if args.warn_only and not issues:
        sys.exit(0)

    # Output results
    if args.format == "json":
        output_json(data)
    elif args.format == "table":
        output_table(data, args.verbose, args.warn_only)
    else:  # plain
        output_plain(data, args.verbose, args.warn_only)

    # Exit based on findings
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)
    sys.exit(1 if has_warnings else 0)


if __name__ == "__main__":
    main()
