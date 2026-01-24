#!/usr/bin/env python3
"""
Analyze Kubernetes pods stuck in Pending state and diagnose scheduling failures.

This script helps operators quickly identify why pods cannot be scheduled:
- Insufficient CPU/memory resources
- Node selector mismatches
- Taint/toleration issues
- Affinity/anti-affinity conflicts
- PersistentVolumeClaim binding failures
- Unschedulable nodes

Useful for troubleshooting scheduling bottlenecks in large-scale Kubernetes deployments.

Exit codes:
    0 - No pending pods found
    1 - Pending pods found (with analysis)
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


def get_pending_pods(namespace=None):
    """Get all pods in Pending state."""
    args = ['get', 'pods', '-o', 'json', '--field-selector=status.phase=Pending']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_nodes():
    """Get all nodes with their status and resources."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    return json.loads(output)


def get_events_for_pod(namespace, pod_name):
    """Get recent events for a specific pod."""
    try:
        output = run_kubectl([
            'get', 'events', '-n', namespace,
            '--field-selector', f'involvedObject.name={pod_name}',
            '-o', 'json'
        ])
        events = json.loads(output)
        return events.get('items', [])
    except subprocess.CalledProcessError:
        return []


def analyze_scheduling_failure(pod, events):
    """Analyze why a pod is stuck in Pending state."""
    reasons = []

    # Check pod conditions
    conditions = pod.get('status', {}).get('conditions', [])
    for condition in conditions:
        if condition.get('type') == 'PodScheduled' and condition.get('status') == 'False':
            reason = condition.get('reason', '')
            message = condition.get('message', '')
            if reason:
                reasons.append({
                    'type': 'scheduling',
                    'reason': reason,
                    'message': message
                })

    # Analyze events for more details
    for event in events:
        if event.get('type') == 'Warning':
            event_reason = event.get('reason', '')
            event_message = event.get('message', '')

            # Categorize common scheduling failures
            if 'Insufficient' in event_message:
                reasons.append({
                    'type': 'resources',
                    'reason': event_reason,
                    'message': event_message
                })
            elif 'node(s) had taint' in event_message or 'toleration' in event_message.lower():
                reasons.append({
                    'type': 'taints',
                    'reason': event_reason,
                    'message': event_message
                })
            elif 'node(s) didn\'t match' in event_message:
                reasons.append({
                    'type': 'affinity',
                    'reason': event_reason,
                    'message': event_message
                })
            elif 'persistentvolumeclaim' in event_message.lower() or 'pvc' in event_message.lower():
                reasons.append({
                    'type': 'storage',
                    'reason': event_reason,
                    'message': event_message
                })
            elif event_reason in ['FailedScheduling', 'Unschedulable']:
                reasons.append({
                    'type': 'scheduling',
                    'reason': event_reason,
                    'message': event_message
                })

    # Check for node selector that might not match any nodes
    spec = pod.get('spec', {})
    if spec.get('nodeSelector'):
        reasons.append({
            'type': 'nodeSelector',
            'reason': 'NodeSelectorPresent',
            'message': f"Pod requires nodeSelector: {spec['nodeSelector']}"
        })

    # Check for node affinity
    affinity = spec.get('affinity', {})
    if affinity.get('nodeAffinity', {}).get('requiredDuringSchedulingIgnoredDuringExecution'):
        reasons.append({
            'type': 'affinity',
            'reason': 'RequiredNodeAffinity',
            'message': 'Pod has required node affinity rules'
        })

    # Check for pod anti-affinity
    if affinity.get('podAntiAffinity', {}).get('requiredDuringSchedulingIgnoredDuringExecution'):
        reasons.append({
            'type': 'antiAffinity',
            'reason': 'RequiredPodAntiAffinity',
            'message': 'Pod has required pod anti-affinity rules'
        })

    # Check for PVC references
    volumes = spec.get('volumes', [])
    for volume in volumes:
        if volume.get('persistentVolumeClaim'):
            pvc_name = volume['persistentVolumeClaim'].get('claimName', '')
            reasons.append({
                'type': 'storage',
                'reason': 'PVCRequired',
                'message': f"Pod references PVC: {pvc_name}"
            })

    # Deduplicate reasons by message
    seen = set()
    unique_reasons = []
    for r in reasons:
        key = (r['type'], r['message'])
        if key not in seen:
            seen.add(key)
            unique_reasons.append(r)

    return unique_reasons


def get_pending_duration(pod):
    """Calculate how long a pod has been pending."""
    import datetime

    creation_time = pod.get('metadata', {}).get('creationTimestamp', '')
    if not creation_time:
        return None

    try:
        # Parse ISO format timestamp
        created = datetime.datetime.fromisoformat(creation_time.replace('Z', '+00:00'))
        now = datetime.datetime.now(datetime.timezone.utc)
        delta = now - created

        # Format duration
        total_seconds = int(delta.total_seconds())
        if total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            return f"{total_seconds // 60}m"
        elif total_seconds < 86400:
            return f"{total_seconds // 3600}h"
        else:
            return f"{total_seconds // 86400}d"
    except (ValueError, TypeError):
        return None


def analyze_pods(pods_data, verbose=False):
    """Analyze all pending pods and return analysis results."""
    pods = pods_data.get('items', [])
    results = []

    for pod in pods:
        pod_name = pod['metadata']['name']
        namespace = pod['metadata'].get('namespace', 'default')

        # Get events for this pod
        events = get_events_for_pod(namespace, pod_name) if verbose else []

        # Analyze scheduling failure
        reasons = analyze_scheduling_failure(pod, events)

        # Get pending duration
        duration = get_pending_duration(pod)

        # Extract resource requests
        containers = pod.get('spec', {}).get('containers', [])
        total_cpu_request = 0
        total_memory_request = 0

        for container in containers:
            resources = container.get('resources', {}).get('requests', {})
            cpu = resources.get('cpu', '0')
            memory = resources.get('memory', '0')

            # Parse CPU (convert to millicores)
            if isinstance(cpu, str):
                if cpu.endswith('m'):
                    total_cpu_request += int(cpu[:-1])
                else:
                    try:
                        total_cpu_request += int(float(cpu) * 1000)
                    except ValueError:
                        pass

            # Parse memory (keep as string for display)
            if memory != '0':
                total_memory_request = memory  # Just show last one for simplicity

        results.append({
            'namespace': namespace,
            'name': pod_name,
            'duration': duration,
            'cpu_request': f"{total_cpu_request}m" if total_cpu_request else 'none',
            'memory_request': total_memory_request if total_memory_request else 'none',
            'reasons': reasons,
            'reason_summary': categorize_failure(reasons)
        })

    return results


def categorize_failure(reasons):
    """Categorize the primary failure reason."""
    if not reasons:
        return 'unknown'

    # Priority order for categorization
    type_priority = ['resources', 'storage', 'taints', 'affinity', 'antiAffinity', 'nodeSelector', 'scheduling']

    for priority_type in type_priority:
        for reason in reasons:
            if reason['type'] == priority_type:
                return priority_type

    return reasons[0]['type'] if reasons else 'unknown'


def print_plain(results, verbose=False):
    """Print results in plain text format."""
    if not results:
        print("No pending pods found")
        return

    # Group by failure reason
    by_reason = defaultdict(list)
    for pod in results:
        by_reason[pod['reason_summary']].append(pod)

    print(f"Found {len(results)} pending pod(s)\n")

    # Summary by reason
    print("Summary by failure type:")
    for reason_type, pods in sorted(by_reason.items(), key=lambda x: -len(x[1])):
        print(f"  {reason_type}: {len(pods)} pod(s)")
    print()

    # Details
    print("Pending pods:")
    print("-" * 80)

    for pod in results:
        duration_str = f" ({pod['duration']})" if pod['duration'] else ""
        print(f"{pod['namespace']}/{pod['name']}{duration_str}")
        print(f"  Resources: CPU={pod['cpu_request']}, Memory={pod['memory_request']}")
        print(f"  Failure type: {pod['reason_summary']}")

        if verbose and pod['reasons']:
            print("  Details:")
            for reason in pod['reasons'][:3]:  # Limit to 3 reasons
                msg = reason['message']
                if len(msg) > 100:
                    msg = msg[:100] + "..."
                print(f"    - [{reason['type']}] {msg}")
        print()


def print_json(results):
    """Print results in JSON format."""
    print(json.dumps(results, indent=2))


def print_table(results):
    """Print results in table format."""
    if not results:
        print("No pending pods found")
        return

    # Header
    print(f"{'Namespace':<20} {'Pod':<35} {'Duration':<10} {'Failure Type':<15}")
    print("-" * 85)

    for pod in results:
        namespace = pod['namespace'][:19]
        name = pod['name'][:34]
        duration = pod['duration'] or 'N/A'
        reason = pod['reason_summary'][:14]
        print(f"{namespace:<20} {name:<35} {duration:<10} {reason:<15}")

    print()
    print(f"Total: {len(results)} pending pod(s)")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes pods stuck in Pending state',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Analyze pending pods across all namespaces
  %(prog)s -n production            # Analyze pending pods in production namespace
  %(prog)s -v                       # Verbose output with detailed failure reasons
  %(prog)s --format json            # JSON output for scripting
  %(prog)s --format table           # Compact table view

Common failure types:
  resources    - Insufficient CPU/memory on nodes
  storage      - PVC binding or provisioning issues
  taints       - Node taints without matching tolerations
  affinity     - Node/pod affinity rules cannot be satisfied
  antiAffinity - Pod anti-affinity conflicts
  nodeSelector - No nodes match the selector
  scheduling   - Other scheduling failures

Exit codes:
  0 - No pending pods found
  1 - Pending pods found
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to analyze (default: all namespaces)'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed failure reasons from events'
    )

    args = parser.parse_args()

    # Get pending pods
    pods_data = get_pending_pods(args.namespace)

    # Check if there are any pending pods
    if not pods_data.get('items'):
        if args.format == 'json':
            print('[]')
        else:
            print("No pending pods found")
        sys.exit(0)

    # Analyze pods
    results = analyze_pods(pods_data, args.verbose)

    # Output results
    if args.format == 'json':
        print_json(results)
    elif args.format == 'table':
        print_table(results)
    else:
        print_plain(results, args.verbose)

    # Exit with code 1 if there are pending pods
    sys.exit(1 if results else 0)


if __name__ == '__main__':
    main()
