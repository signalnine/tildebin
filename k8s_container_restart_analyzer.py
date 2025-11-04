#!/usr/bin/env python3
"""
Analyze Kubernetes container restart patterns and identify root causes.

This script helps identify chronic restart issues by analyzing restart patterns,
categorizing causes (OOMKills, CrashLoopBackOff, probe failures), and providing
actionable remediation suggestions for large-scale Kubernetes environments.

Exit codes:
  0 - No restarts or only informational findings
  1 - Restarts detected with warnings
  2 - Usage error
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta


def run_command(cmd):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {cmd}", file=sys.stderr)
        print(f"Error: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_pods_with_restarts(namespace=None, timeframe_minutes=None):
    """Get all pods with restart information."""
    cmd = "kubectl get pods --all-namespaces -o json"
    if namespace:
        cmd = f"kubectl get pods -n {namespace} -o json"

    output = run_command(cmd)
    pods_data = json.loads(output)

    pods_with_restarts = []

    for pod in pods_data.get('items', []):
        pod_name = pod['metadata']['name']
        pod_namespace = pod['metadata']['namespace']
        pod_created = pod['metadata'].get('creationTimestamp', '')

        # Get container statuses
        container_statuses = pod.get('status', {}).get('containerStatuses', [])

        for container in container_statuses:
            restart_count = container.get('restartCount', 0)

            if restart_count > 0:
                # Try to determine restart reason
                last_state = container.get('lastState', {})
                current_state = container.get('state', {})

                reason = "Unknown"
                exit_code = None
                last_restart_time = None

                # Check terminated state
                if 'terminated' in last_state:
                    terminated = last_state['terminated']
                    reason = terminated.get('reason', 'Unknown')
                    exit_code = terminated.get('exitCode')
                    last_restart_time = terminated.get('finishedAt', '')

                # Check if currently waiting (CrashLoopBackOff, etc.)
                waiting_reason = None
                if 'waiting' in current_state:
                    waiting_reason = current_state['waiting'].get('reason')

                pods_with_restarts.append({
                    'namespace': pod_namespace,
                    'pod_name': pod_name,
                    'container_name': container['name'],
                    'restart_count': restart_count,
                    'reason': reason,
                    'exit_code': exit_code,
                    'waiting_reason': waiting_reason,
                    'last_restart_time': last_restart_time,
                    'pod_created': pod_created,
                    'ready': container.get('ready', False)
                })

    # Filter by timeframe if specified
    if timeframe_minutes:
        cutoff_time = datetime.utcnow() - timedelta(minutes=timeframe_minutes)
        filtered_pods = []

        for pod in pods_with_restarts:
            if pod['last_restart_time']:
                try:
                    # Parse ISO 8601 timestamp
                    restart_time = datetime.fromisoformat(pod['last_restart_time'].replace('Z', '+00:00'))
                    if restart_time.replace(tzinfo=None) >= cutoff_time:
                        filtered_pods.append(pod)
                except (ValueError, AttributeError):
                    # If we can't parse the time, include it to be safe
                    filtered_pods.append(pod)
            else:
                # No timestamp available, include it
                filtered_pods.append(pod)

        return filtered_pods

    return pods_with_restarts


def get_pod_events(namespace, pod_name):
    """Get events related to a specific pod."""
    cmd = f"kubectl get events -n {namespace} --field-selector involvedObject.name={pod_name} -o json"
    try:
        output = run_command(cmd)
        events_data = json.loads(output)
        return events_data.get('items', [])
    except:
        return []


def categorize_restart_reason(reason, exit_code, waiting_reason):
    """Categorize the restart reason into high-level categories."""
    reason_lower = str(reason).lower()
    waiting_lower = str(waiting_reason).lower() if waiting_reason else ""

    # OOMKilled
    if 'oomkilled' in reason_lower or exit_code == 137:
        return 'OOMKilled'

    # CrashLoopBackOff
    if 'crashloop' in waiting_lower:
        return 'CrashLoopBackOff'

    # Application error
    if exit_code and exit_code != 0 and exit_code != 137:
        return 'ApplicationError'

    # Probe failures
    if 'liveness' in reason_lower or 'readiness' in reason_lower:
        return 'ProbeFailure'

    # Eviction
    if 'evicted' in reason_lower:
        return 'Evicted'

    # SIGTERM/SIGKILL
    if exit_code == 143:
        return 'SIGTERM'
    elif exit_code == 137 and 'oom' not in reason_lower:
        return 'SIGKILL'

    return 'Unknown'


def identify_flapping_containers(pods_with_restarts, threshold=5):
    """Identify containers with high restart counts (flapping)."""
    flapping = []
    for pod in pods_with_restarts:
        if pod['restart_count'] >= threshold:
            flapping.append(pod)
    return flapping


def get_resource_limits(namespace, pod_name, container_name):
    """Check if container has resource limits set."""
    cmd = f"kubectl get pod {pod_name} -n {namespace} -o json"
    try:
        output = run_command(cmd)
        pod_data = json.loads(output)

        containers = pod_data.get('spec', {}).get('containers', [])
        for container in containers:
            if container['name'] == container_name:
                resources = container.get('resources', {})
                limits = resources.get('limits', {})
                requests = resources.get('requests', {})
                return {
                    'has_memory_limit': 'memory' in limits,
                    'has_cpu_limit': 'cpu' in limits,
                    'memory_limit': limits.get('memory'),
                    'memory_request': requests.get('memory'),
                    'cpu_limit': limits.get('cpu'),
                    'cpu_request': requests.get('cpu')
                }
        return None
    except:
        return None


def suggest_remediation(category, pod_info, resources_info):
    """Suggest remediation based on restart category."""
    suggestions = []

    if category == 'OOMKilled':
        suggestions.append("Container is being killed due to memory limits")
        if resources_info and not resources_info.get('has_memory_limit'):
            suggestions.append("⚠ No memory limit set - consider setting limits")
        else:
            suggestions.append("Consider increasing memory limits")
        suggestions.append(f"Check logs: kubectl logs {pod_info['pod_name']} -n {pod_info['namespace']} -c {pod_info['container_name']} --previous")

    elif category == 'CrashLoopBackOff':
        suggestions.append("Container is repeatedly crashing")
        suggestions.append(f"Check logs: kubectl logs {pod_info['pod_name']} -n {pod_info['namespace']} -c {pod_info['container_name']} --previous")
        suggestions.append("Verify image exists and is accessible")
        suggestions.append("Check for missing dependencies or configuration")

    elif category == 'ApplicationError':
        suggestions.append(f"Application exited with code {pod_info['exit_code']}")
        suggestions.append(f"Check logs: kubectl logs {pod_info['pod_name']} -n {pod_info['namespace']} -c {pod_info['container_name']} --previous")
        suggestions.append("Review application startup logic and dependencies")

    elif category == 'ProbeFailure':
        suggestions.append("Liveness or readiness probe is failing")
        suggestions.append("Verify probe configuration (path, port, timeout)")
        suggestions.append("Check if application needs more time to start (initialDelaySeconds)")
        suggestions.append(f"Describe pod: kubectl describe pod {pod_info['pod_name']} -n {pod_info['namespace']}")

    elif category == 'Evicted':
        suggestions.append("Pod was evicted due to resource pressure")
        suggestions.append("Check node conditions for disk or memory pressure")
        suggestions.append("Consider setting resource requests/limits")

    elif category == 'SIGTERM':
        suggestions.append("Container received SIGTERM (graceful shutdown)")
        suggestions.append("May be intentional (rolling update, pod deletion)")
        suggestions.append("If unexpected, check for OOM at node level")

    elif category == 'SIGKILL':
        suggestions.append("Container received SIGKILL (forced termination)")
        suggestions.append("May indicate node issues or forced pod deletion")
        suggestions.append("Check node events and system logs")

    else:
        suggestions.append("Unable to determine specific cause")
        suggestions.append(f"Check logs: kubectl logs {pod_info['pod_name']} -n {pod_info['namespace']} -c {pod_info['container_name']} --previous")
        suggestions.append(f"Describe pod: kubectl describe pod {pod_info['pod_name']} -n {pod_info['namespace']}")

    return suggestions


def analyze_restarts(pods_with_restarts, verbose=False):
    """Analyze restart patterns and categorize issues."""
    analysis = {
        'total_pods': len(pods_with_restarts),
        'total_restarts': sum(p['restart_count'] for p in pods_with_restarts),
        'by_category': defaultdict(list),
        'by_namespace': defaultdict(int),
        'flapping_containers': [],
        'missing_limits': []
    }

    for pod in pods_with_restarts:
        # Categorize
        category = categorize_restart_reason(
            pod['reason'],
            pod['exit_code'],
            pod['waiting_reason']
        )

        analysis['by_category'][category].append(pod)
        analysis['by_namespace'][pod['namespace']] += pod['restart_count']

        # Check for flapping (5+ restarts)
        if pod['restart_count'] >= 5:
            analysis['flapping_containers'].append(pod)

        # Check resource limits
        if verbose:
            resources = get_resource_limits(
                pod['namespace'],
                pod['pod_name'],
                pod['container_name']
            )
            pod['resources'] = resources

            if resources and not resources.get('has_memory_limit'):
                analysis['missing_limits'].append(pod)

    return analysis


def format_output_plain(analysis, verbose=False, warn_only=False):
    """Format output in plain text."""
    output = []

    if not warn_only:
        output.append(f"Container Restart Analysis")
        output.append(f"=" * 80)
        output.append(f"Total containers with restarts: {analysis['total_pods']}")
        output.append(f"Total restart count: {analysis['total_restarts']}")
        output.append("")

    # Restarts by category
    if analysis['by_category']:
        output.append("Restarts by Category:")
        output.append("-" * 80)
        for category, pods in sorted(analysis['by_category'].items(),
                                     key=lambda x: len(x[1]),
                                     reverse=True):
            restart_sum = sum(p['restart_count'] for p in pods)
            output.append(f"  {category}: {len(pods)} containers, {restart_sum} total restarts")
        output.append("")

    # Restarts by namespace
    if not warn_only and analysis['by_namespace']:
        output.append("Restarts by Namespace:")
        output.append("-" * 80)
        for namespace, count in sorted(analysis['by_namespace'].items(),
                                       key=lambda x: x[1],
                                       reverse=True)[:10]:
            output.append(f"  {namespace}: {count} restarts")
        output.append("")

    # Flapping containers (high priority)
    if analysis['flapping_containers']:
        output.append("⚠ Flapping Containers (5+ restarts):")
        output.append("-" * 80)
        for pod in sorted(analysis['flapping_containers'],
                         key=lambda x: x['restart_count'],
                         reverse=True):
            category = categorize_restart_reason(
                pod['reason'],
                pod['exit_code'],
                pod['waiting_reason']
            )
            output.append(f"  {pod['namespace']}/{pod['pod_name']}/{pod['container_name']}")
            output.append(f"    Restarts: {pod['restart_count']}, Category: {category}")
            output.append(f"    Ready: {pod['ready']}, Last Reason: {pod['reason']}")

            if verbose:
                resources = pod.get('resources')
                if resources:
                    output.append(f"    Memory Limit: {resources.get('memory_limit', 'None')}")
                    output.append(f"    CPU Limit: {resources.get('cpu_limit', 'None')}")

                suggestions = suggest_remediation(category, pod, resources)
                if suggestions:
                    output.append("    Remediation:")
                    for suggestion in suggestions:
                        output.append(f"      - {suggestion}")
            output.append("")

    # Detailed breakdown by category (verbose mode)
    if verbose and not warn_only:
        output.append("Detailed Analysis by Category:")
        output.append("-" * 80)
        for category, pods in sorted(analysis['by_category'].items()):
            output.append(f"\n{category} ({len(pods)} containers):")
            for pod in sorted(pods, key=lambda x: x['restart_count'], reverse=True)[:5]:
                output.append(f"  {pod['namespace']}/{pod['pod_name']}/{pod['container_name']}")
                output.append(f"    Restarts: {pod['restart_count']}, Exit Code: {pod['exit_code']}")

                resources = pod.get('resources')
                suggestions = suggest_remediation(category, pod, resources)
                if suggestions:
                    output.append("    Remediation:")
                    for suggestion in suggestions[:3]:  # Top 3 suggestions
                        output.append(f"      - {suggestion}")
            if len(pods) > 5:
                output.append(f"  ... and {len(pods) - 5} more")
            output.append("")

    # Missing resource limits
    if verbose and analysis['missing_limits']:
        output.append("⚠ Containers Without Memory Limits:")
        output.append("-" * 80)
        for pod in analysis['missing_limits'][:10]:
            output.append(f"  {pod['namespace']}/{pod['pod_name']}/{pod['container_name']}")
        if len(analysis['missing_limits']) > 10:
            output.append(f"  ... and {len(analysis['missing_limits']) - 10} more")
        output.append("")

    return "\n".join(output)


def format_output_json(analysis):
    """Format output as JSON."""
    # Convert defaultdicts to regular dicts for JSON serialization
    output = {
        'total_pods': analysis['total_pods'],
        'total_restarts': analysis['total_restarts'],
        'by_category': {k: v for k, v in analysis['by_category'].items()},
        'by_namespace': dict(analysis['by_namespace']),
        'flapping_containers': analysis['flapping_containers'],
        'missing_limits': analysis['missing_limits']
    }
    return json.dumps(output, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all container restarts
  %(prog)s

  # Analyze restarts in specific namespace
  %(prog)s -n kube-system

  # Show verbose output with remediation suggestions
  %(prog)s --verbose

  # Only show flapping containers (5+ restarts)
  %(prog)s --warn-only

  # Analyze restarts in last 24 hours
  %(prog)s --timeframe 1440

  # Output as JSON for monitoring integration
  %(prog)s --output json

  # Combine filters
  %(prog)s -n production --verbose --warn-only

Exit codes:
  0 - No restarts or only informational findings
  1 - Restarts detected with warnings
  2 - Usage error
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Analyze restarts in specific namespace (default: all namespaces)'
    )
    parser.add_argument(
        '--timeframe',
        type=int,
        metavar='MINUTES',
        help='Only analyze restarts within last N minutes'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed analysis with remediation suggestions'
    )
    parser.add_argument(
        '--warn-only',
        action='store_true',
        help='Only show warnings (flapping containers)'
    )
    parser.add_argument(
        '--output',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: plain)'
    )

    args = parser.parse_args()

    # Get pods with restarts
    pods_with_restarts = get_pods_with_restarts(
        namespace=args.namespace,
        timeframe_minutes=args.timeframe
    )

    if not pods_with_restarts:
        print("No container restarts detected.")
        sys.exit(0)

    # Analyze restarts
    analysis = analyze_restarts(pods_with_restarts, verbose=args.verbose)

    # Format and print output
    if args.output == 'json':
        print(format_output_json(analysis))
    else:
        print(format_output_plain(analysis, verbose=args.verbose, warn_only=args.warn_only))

    # Exit with appropriate code
    if analysis['flapping_containers'] or analysis['total_restarts'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
