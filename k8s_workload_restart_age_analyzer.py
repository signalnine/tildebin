#!/usr/bin/env python3
"""
Analyze workload restart age across Kubernetes clusters.

Identifies pods based on how long they've been running without restart, helping
detect both stability issues (frequent restarts) and stale deployments (pods
running for extended periods without updates).

Use cases:
- Identify stale workloads that haven't been updated/redeployed
- Detect stability patterns across namespaces
- Find pods that survived multiple deployments (stuck/orphaned)
- Audit deployment freshness for security compliance
- Capacity planning based on workload age distribution

Exit codes:
    0 - All workloads within acceptable age bounds
    1 - Workloads found outside age thresholds (too old or too young)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


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


def parse_k8s_timestamp(timestamp_str):
    """Parse Kubernetes timestamp to datetime object."""
    if not timestamp_str:
        return None
    try:
        # Handle both formats: with and without microseconds
        if '.' in timestamp_str:
            return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def format_duration(seconds):
    """Format seconds into human-readable duration."""
    if seconds < 0:
        return "unknown"

    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)

    if days > 0:
        return f"{days}d{hours}h"
    elif hours > 0:
        return f"{hours}h{minutes}m"
    else:
        return f"{minutes}m"


def get_pods(namespace=None):
    """Get all pods with their status information."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def analyze_pod_age(pod, now):
    """
    Analyze a pod's age and restart patterns.

    Returns dict with:
    - name: pod name
    - namespace: pod namespace
    - age_seconds: time since pod creation
    - last_restart_seconds: time since last container restart (if any)
    - restart_count: total restart count across containers
    - owner_kind: deployment, statefulset, daemonset, etc.
    - status: Running, Pending, etc.
    """
    metadata = pod.get('metadata', {})
    spec = pod.get('spec', {})
    status = pod.get('status', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')

    # Get creation timestamp
    creation_time = parse_k8s_timestamp(metadata.get('creationTimestamp'))
    age_seconds = (now - creation_time).total_seconds() if creation_time else -1

    # Analyze container statuses for restart info
    container_statuses = status.get('containerStatuses', [])
    total_restarts = 0
    last_restart_time = None

    for cs in container_statuses:
        total_restarts += cs.get('restartCount', 0)

        # Check last state for restart timing
        last_state = cs.get('lastState', {})
        if 'terminated' in last_state:
            finished = parse_k8s_timestamp(last_state['terminated'].get('finishedAt'))
            if finished and (not last_restart_time or finished > last_restart_time):
                last_restart_time = finished

    last_restart_seconds = -1
    if last_restart_time:
        last_restart_seconds = (now - last_restart_time).total_seconds()

    # Get owner reference
    owner_refs = metadata.get('ownerReferences', [])
    owner_kind = owner_refs[0].get('kind', 'None') if owner_refs else 'None'

    # Pod phase
    phase = status.get('phase', 'Unknown')

    return {
        'name': name,
        'namespace': namespace,
        'age_seconds': age_seconds,
        'age_human': format_duration(age_seconds),
        'last_restart_seconds': last_restart_seconds,
        'last_restart_human': format_duration(last_restart_seconds) if last_restart_seconds >= 0 else 'never',
        'restart_count': total_restarts,
        'owner_kind': owner_kind,
        'phase': phase,
        'creation_time': metadata.get('creationTimestamp', 'unknown')
    }


def categorize_by_age(pods_analysis, stale_days=30, fresh_hours=1):
    """
    Categorize pods by age.

    Returns dict with:
    - stale: pods older than stale_days
    - normal: pods in healthy age range
    - fresh: pods younger than fresh_hours (recently deployed/restarted)
    """
    stale_seconds = stale_days * 86400
    fresh_seconds = fresh_hours * 3600

    categories = {
        'stale': [],
        'normal': [],
        'fresh': []
    }

    for pod in pods_analysis:
        age = pod['age_seconds']
        if age < 0:
            continue

        if age > stale_seconds:
            categories['stale'].append(pod)
        elif age < fresh_seconds:
            categories['fresh'].append(pod)
        else:
            categories['normal'].append(pod)

    return categories


def output_plain(categories, pods_analysis, verbose=False, warn_only=False):
    """Output results in plain text format."""
    total = len(pods_analysis)
    stale_count = len(categories['stale'])
    fresh_count = len(categories['fresh'])
    normal_count = len(categories['normal'])

    if not warn_only:
        print(f"Workload Restart Age Analysis")
        print(f"Total pods analyzed: {total}")
        print(f"  Stale (old): {stale_count}")
        print(f"  Normal: {normal_count}")
        print(f"  Fresh (recent): {fresh_count}")
        print()

    # Show stale pods
    if categories['stale']:
        print(f"Stale Workloads ({stale_count}):")
        print("-" * 80)
        for pod in sorted(categories['stale'], key=lambda x: -x['age_seconds']):
            restarts = f"restarts={pod['restart_count']}" if pod['restart_count'] > 0 else "no restarts"
            print(f"  {pod['namespace']}/{pod['name']}")
            print(f"    Age: {pod['age_human']}, Owner: {pod['owner_kind']}, {restarts}")
        print()

    # Show fresh pods (might indicate instability or recent deployment)
    if categories['fresh'] and verbose:
        print(f"Fresh Workloads ({fresh_count}):")
        print("-" * 80)
        for pod in sorted(categories['fresh'], key=lambda x: x['age_seconds']):
            restarts = f"restarts={pod['restart_count']}" if pod['restart_count'] > 0 else "no restarts"
            print(f"  {pod['namespace']}/{pod['name']}")
            print(f"    Age: {pod['age_human']}, Owner: {pod['owner_kind']}, {restarts}")
        print()

    # Verbose: show all pods
    if verbose and not warn_only:
        print(f"All Workloads by Age:")
        print("-" * 80)
        for pod in sorted(pods_analysis, key=lambda x: -x['age_seconds']):
            status_marker = ""
            if pod in categories['stale']:
                status_marker = "[STALE] "
            elif pod in categories['fresh']:
                status_marker = "[FRESH] "
            print(f"  {status_marker}{pod['namespace']}/{pod['name']}: {pod['age_human']}")

    if not categories['stale'] and warn_only:
        print("All workloads within acceptable age bounds")


def output_json(categories, pods_analysis):
    """Output results in JSON format."""
    result = {
        'summary': {
            'total': len(pods_analysis),
            'stale': len(categories['stale']),
            'normal': len(categories['normal']),
            'fresh': len(categories['fresh'])
        },
        'categories': {
            'stale': categories['stale'],
            'normal': categories['normal'],
            'fresh': categories['fresh']
        },
        'all_pods': pods_analysis
    }
    print(json.dumps(result, indent=2, default=str))


def output_table(categories, pods_analysis, warn_only=False):
    """Output results in table format."""
    if warn_only:
        pods_to_show = categories['stale']
    else:
        pods_to_show = sorted(pods_analysis, key=lambda x: -x['age_seconds'])

    print(f"{'NAMESPACE':<20} {'POD':<40} {'AGE':<10} {'RESTARTS':<10} {'OWNER':<15} {'STATUS':<10}")
    print("-" * 115)

    for pod in pods_to_show:
        status = "STALE" if pod in categories['stale'] else ("FRESH" if pod in categories['fresh'] else "OK")
        name = pod['name'][:38] + '..' if len(pod['name']) > 40 else pod['name']
        ns = pod['namespace'][:18] + '..' if len(pod['namespace']) > 20 else pod['namespace']
        print(f"{ns:<20} {name:<40} {pod['age_human']:<10} {pod['restart_count']:<10} {pod['owner_kind']:<15} {status:<10}")

    print()
    print(f"Total: {len(pods_analysis)} | Stale: {len(categories['stale'])} | Fresh: {len(categories['fresh'])}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze workload restart age in Kubernetes clusters',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Analyze all pods
  %(prog)s -n production                # Analyze specific namespace
  %(prog)s --stale-days 14              # Flag pods older than 14 days as stale
  %(prog)s --format json                # JSON output for automation
  %(prog)s --warn-only                  # Only show stale workloads
  %(prog)s -v                           # Verbose output with all pods

Use cases:
  - Identify pods that haven't been redeployed in a long time
  - Audit deployment freshness for security/compliance
  - Find orphaned or stuck workloads
  - Track deployment cadence across namespaces

Exit codes:
  0 - All workloads within acceptable age bounds
  1 - Stale workloads found (older than threshold)
  2 - kubectl not available or usage error
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Kubernetes namespace to analyze (default: all namespaces)'
    )
    parser.add_argument(
        '--stale-days',
        type=int,
        default=30,
        help='Days after which a workload is considered stale (default: 30)'
    )
    parser.add_argument(
        '--fresh-hours',
        type=int,
        default=1,
        help='Hours within which a workload is considered fresh (default: 1)'
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
        help='Only show stale workloads'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information for all workloads'
    )
    parser.add_argument(
        '--exclude-namespace',
        action='append',
        default=[],
        help='Namespaces to exclude (can be specified multiple times)'
    )

    args = parser.parse_args()

    # Get current time
    now = datetime.now(timezone.utc)

    # Get pods
    pods_data = get_pods(args.namespace)
    pods = pods_data.get('items', [])

    if not pods:
        if args.format == 'json':
            print(json.dumps({'summary': {'total': 0}, 'categories': {}, 'all_pods': []}))
        else:
            print("No pods found")
        sys.exit(0)

    # Analyze each pod
    pods_analysis = []
    for pod in pods:
        analysis = analyze_pod_age(pod, now)

        # Skip excluded namespaces
        if analysis['namespace'] in args.exclude_namespace:
            continue

        # Skip non-running pods for age analysis
        if analysis['phase'] not in ['Running', 'Succeeded']:
            continue

        pods_analysis.append(analysis)

    if not pods_analysis:
        if args.format == 'json':
            print(json.dumps({'summary': {'total': 0}, 'categories': {}, 'all_pods': []}))
        else:
            print("No running pods found")
        sys.exit(0)

    # Categorize by age
    categories = categorize_by_age(
        pods_analysis,
        stale_days=args.stale_days,
        fresh_hours=args.fresh_hours
    )

    # Output results
    if args.format == 'json':
        output_json(categories, pods_analysis)
    elif args.format == 'table':
        output_table(categories, pods_analysis, args.warn_only)
    else:
        output_plain(categories, pods_analysis, args.verbose, args.warn_only)

    # Exit code based on findings
    has_stale = len(categories['stale']) > 0
    sys.exit(1 if has_stale else 0)


if __name__ == '__main__':
    main()
