#!/usr/bin/env python3
"""
Analyze Kubernetes pod startup latency to identify slow-starting pods.

This script measures the time from pod creation to ready state, breaking down
the latency into phases: scheduling, image pull, init containers, and container
startup. Useful for identifying performance bottlenecks in large baremetal
Kubernetes clusters.

Key metrics analyzed:
- Total startup time (creation to ready)
- Scheduling latency (creation to scheduled)
- Image pull time (from container start events)
- Init container duration
- Container startup time

Exit codes:
    0 - Analysis complete, no slow pods detected (below threshold)
    1 - Slow pods detected (above threshold)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


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


def get_pods(namespace: Optional[str] = None,
             include_completed: bool = False) -> List[Dict[str, Any]]:
    """Get pods with their status details."""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    if output is None:
        return []

    try:
        data = json.loads(output)
        pods = data.get('items', [])

        # Filter out completed pods unless requested
        if not include_completed:
            pods = [p for p in pods if p.get('status', {}).get('phase')
                    not in ('Succeeded', 'Failed')]

        return pods
    except json.JSONDecodeError:
        return []


def get_pod_events(namespace: str, pod_name: str) -> List[Dict[str, Any]]:
    """Get events for a specific pod."""
    cmd = ['get', 'events', '-n', namespace, '-o', 'json',
           '--field-selector', f'involvedObject.name={pod_name}']

    output = run_kubectl(cmd)
    if output is None:
        return []

    try:
        data = json.loads(output)
        return data.get('items', [])
    except json.JSONDecodeError:
        return []


def analyze_pod_startup(pod: Dict[str, Any],
                        fetch_events: bool = False) -> Dict[str, Any]:
    """Analyze startup latency for a single pod."""
    metadata = pod.get('metadata', {})
    status = pod.get('status', {})
    spec = pod.get('spec', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')

    # Parse creation time
    creation_time = parse_timestamp(metadata.get('creationTimestamp'))

    # Get container statuses
    container_statuses = status.get('containerStatuses', [])
    init_container_statuses = status.get('initContainerStatuses', [])

    # Get conditions for timing info
    conditions = {c['type']: c for c in status.get('conditions', [])}

    # Calculate phase timings
    scheduled_time = None
    ready_time = None
    initialized_time = None

    if 'PodScheduled' in conditions:
        scheduled_time = parse_timestamp(
            conditions['PodScheduled'].get('lastTransitionTime'))

    if 'Ready' in conditions:
        ready_cond = conditions['Ready']
        if ready_cond.get('status') == 'True':
            ready_time = parse_timestamp(ready_cond.get('lastTransitionTime'))

    if 'Initialized' in conditions:
        initialized_time = parse_timestamp(
            conditions['Initialized'].get('lastTransitionTime'))

    # Calculate latencies
    scheduling_latency = None
    init_latency = None
    startup_latency = None
    total_latency = None

    if creation_time and scheduled_time:
        scheduling_latency = (scheduled_time - creation_time).total_seconds()

    if scheduled_time and initialized_time:
        init_latency = (initialized_time - scheduled_time).total_seconds()

    if initialized_time and ready_time:
        startup_latency = (ready_time - initialized_time).total_seconds()

    if creation_time and ready_time:
        total_latency = (ready_time - creation_time).total_seconds()

    # Analyze container restart counts and states
    total_restarts = sum(cs.get('restartCount', 0)
                         for cs in container_statuses)

    # Check for image pull issues (waiting state with ImagePullBackOff)
    image_issues = []
    for cs in container_statuses:
        waiting = cs.get('state', {}).get('waiting', {})
        reason = waiting.get('reason', '')
        if reason in ('ImagePullBackOff', 'ErrImagePull', 'ErrImageNeverPull'):
            image_issues.append({
                'container': cs.get('name'),
                'reason': reason,
                'message': waiting.get('message', '')
            })

    # Analyze init containers
    init_container_info = []
    for ics in init_container_statuses:
        terminated = ics.get('state', {}).get('terminated', {})
        started = parse_timestamp(terminated.get('startedAt'))
        finished = parse_timestamp(terminated.get('finishedAt'))

        duration = None
        if started and finished:
            duration = (finished - started).total_seconds()

        init_container_info.append({
            'name': ics.get('name'),
            'ready': ics.get('ready', False),
            'duration_seconds': duration,
            'exit_code': terminated.get('exitCode'),
            'restarts': ics.get('restartCount', 0)
        })

    # Determine if pod is ready
    is_ready = (conditions.get('Ready', {}).get('status') == 'True')

    # Determine if pod is slow (will be set by caller based on threshold)
    phase = status.get('phase', 'Unknown')

    # Get node name for locality analysis
    node_name = spec.get('nodeName', '')

    # Get image names for analysis
    containers = spec.get('containers', [])
    images = [c.get('image', '') for c in containers]

    result = {
        'name': name,
        'namespace': namespace,
        'node': node_name,
        'phase': phase,
        'is_ready': is_ready,
        'images': images,
        'creation_time': creation_time.isoformat() if creation_time else None,
        'ready_time': ready_time.isoformat() if ready_time else None,
        'scheduling_latency_seconds': scheduling_latency,
        'init_latency_seconds': init_latency,
        'startup_latency_seconds': startup_latency,
        'total_latency_seconds': total_latency,
        'total_restarts': total_restarts,
        'init_containers': init_container_info,
        'image_issues': image_issues,
        'is_slow': False,  # Set by caller
        'issues': []  # Populated below
    }

    # Identify issues
    issues = []

    if image_issues:
        issues.append(f"Image pull issues: {len(image_issues)} container(s)")

    if total_restarts > 0:
        issues.append(f"Container restarts: {total_restarts}")

    # Check for slow init containers (> 30s each)
    slow_init = [ic for ic in init_container_info
                 if ic['duration_seconds'] and ic['duration_seconds'] > 30]
    if slow_init:
        issues.append(f"Slow init containers: {len(slow_init)}")

    # Not ready but should be
    if phase == 'Running' and not is_ready:
        issues.append("Running but not ready")

    # Pending for too long
    if phase == 'Pending' and creation_time:
        pending_duration = (datetime.now(timezone.utc) -
                            creation_time).total_seconds()
        if pending_duration > 60:
            issues.append(f"Pending for {int(pending_duration)}s")

    result['issues'] = issues

    return result


def format_duration(seconds: Optional[float]) -> str:
    """Format seconds into human-readable duration."""
    if seconds is None:
        return 'N/A'

    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m{seconds % 60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h{minutes}m"


def output_plain(pods_data: List[Dict], warn_only: bool, verbose: bool):
    """Plain text output."""
    # Filter if warn-only
    if warn_only:
        pods_data = [p for p in pods_data if p['is_slow'] or p['issues']]

    if not pods_data:
        print("No slow pods detected." if warn_only else "No pods found.")
        return

    # Group by namespace
    by_namespace: Dict[str, List[Dict]] = {}
    for pod in pods_data:
        ns = pod['namespace']
        if ns not in by_namespace:
            by_namespace[ns] = []
        by_namespace[ns].append(pod)

    for namespace in sorted(by_namespace.keys()):
        pods = by_namespace[namespace]
        print(f"\n=== Namespace: {namespace} ===")

        # Sort by total latency (slowest first), with None values last
        pods.sort(key=lambda p: (p['total_latency_seconds'] is None,
                                  -(p['total_latency_seconds'] or 0)))

        for pod in pods:
            status = "[SLOW]" if pod['is_slow'] else "[OK]"
            if pod['issues']:
                status = "[ISSUE]"

            ready_status = "Ready" if pod['is_ready'] else pod['phase']
            print(f"\n{status} {pod['name']} ({ready_status})")

            if pod['total_latency_seconds'] is not None:
                print(f"  Total startup: {format_duration(pod['total_latency_seconds'])}")

                if verbose:
                    if pod['scheduling_latency_seconds'] is not None:
                        print(f"    Scheduling: {format_duration(pod['scheduling_latency_seconds'])}")
                    if pod['init_latency_seconds'] is not None:
                        print(f"    Init containers: {format_duration(pod['init_latency_seconds'])}")
                    if pod['startup_latency_seconds'] is not None:
                        print(f"    Container startup: {format_duration(pod['startup_latency_seconds'])}")
            elif pod['phase'] == 'Pending':
                print(f"  Status: Still pending")
            else:
                print(f"  Status: Not yet ready")

            if verbose:
                print(f"  Node: {pod['node'] or '(not scheduled)'}")
                if pod['images']:
                    print(f"  Images: {', '.join(pod['images'][:2])}")
                    if len(pod['images']) > 2:
                        print(f"          (+{len(pod['images']) - 2} more)")

            if pod['init_containers'] and verbose:
                for ic in pod['init_containers']:
                    dur = format_duration(ic['duration_seconds'])
                    status_ic = "done" if ic['ready'] else "pending"
                    print(f"    Init: {ic['name']} ({dur}, {status_ic})")

            if pod['issues']:
                for issue in pod['issues']:
                    print(f"  * {issue}")

            if pod['image_issues']:
                for img_issue in pod['image_issues']:
                    print(f"  * {img_issue['container']}: {img_issue['reason']}")


def output_json(pods_data: List[Dict], warn_only: bool):
    """JSON output."""
    if warn_only:
        pods_data = [p for p in pods_data if p['is_slow'] or p['issues']]

    # Calculate summary statistics
    latencies = [p['total_latency_seconds'] for p in pods_data
                 if p['total_latency_seconds'] is not None]

    summary = {
        'total_pods': len(pods_data),
        'slow_pods': sum(1 for p in pods_data if p['is_slow']),
        'pods_with_issues': sum(1 for p in pods_data if p['issues']),
        'ready_pods': sum(1 for p in pods_data if p['is_ready']),
        'pending_pods': sum(1 for p in pods_data if p['phase'] == 'Pending'),
    }

    if latencies:
        summary['latency_stats'] = {
            'min_seconds': min(latencies),
            'max_seconds': max(latencies),
            'avg_seconds': sum(latencies) / len(latencies),
            'p50_seconds': sorted(latencies)[len(latencies) // 2],
            'p90_seconds': sorted(latencies)[int(len(latencies) * 0.9)]
                          if len(latencies) >= 10 else None,
        }

    output = {
        'pods': pods_data,
        'summary': summary
    }

    print(json.dumps(output, indent=2))


def output_table(pods_data: List[Dict], warn_only: bool):
    """Tabular output."""
    if warn_only:
        pods_data = [p for p in pods_data if p['is_slow'] or p['issues']]

    print(f"{'NAMESPACE':<20} {'POD':<40} {'STATUS':<10} "
          f"{'TOTAL':<10} {'SCHED':<8} {'INIT':<8} {'START':<8} {'ISSUES'}")
    print("-" * 130)

    # Sort by total latency descending
    pods_data.sort(key=lambda p: (p['total_latency_seconds'] is None,
                                   -(p['total_latency_seconds'] or 0)))

    for pod in pods_data:
        ns = pod['namespace'][:19]
        name = pod['name'][:39]

        if pod['is_slow']:
            status = 'SLOW'
        elif pod['issues']:
            status = 'ISSUE'
        elif pod['is_ready']:
            status = 'Ready'
        else:
            status = pod['phase'][:9]

        total = format_duration(pod['total_latency_seconds'])
        sched = format_duration(pod['scheduling_latency_seconds'])
        init = format_duration(pod['init_latency_seconds'])
        start = format_duration(pod['startup_latency_seconds'])

        issues_str = '; '.join(pod['issues'][:2]) if pod['issues'] else ''
        if len(pod['issues']) > 2:
            issues_str += f" (+{len(pod['issues']) - 2})"

        print(f"{ns:<20} {name:<40} {status:<10} "
              f"{total:<10} {sched:<8} {init:<8} {start:<8} {issues_str}")

    # Summary
    slow_count = sum(1 for p in pods_data if p['is_slow'])
    issue_count = sum(1 for p in pods_data if p['issues'])
    print(f"\nTotal: {len(pods_data)} pods, {slow_count} slow, "
          f"{issue_count} with issues")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes pod startup latency",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all pods across all namespaces
  %(prog)s

  # Check pods in a specific namespace
  %(prog)s -n kube-system

  # Show only slow pods (above threshold)
  %(prog)s --warn-only

  # Custom slow threshold (default: 60 seconds)
  %(prog)s --slow-threshold 120

  # Output as JSON for automation
  %(prog)s --format json

  # Verbose output with timing breakdown
  %(prog)s -v

Startup phases analyzed:
  - Scheduling: Time from creation to pod scheduled on a node
  - Init: Time for init containers to complete
  - Startup: Time for main containers to become ready

Exit codes:
  0 - Analysis complete, no slow pods detected
  1 - Slow pods detected (above threshold)
  2 - Usage error or kubectl not available
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to analyze (default: all namespaces)'
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
        help='Only show slow pods or pods with issues'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed timing breakdown'
    )

    parser.add_argument(
        '--slow-threshold',
        type=int,
        default=60,
        help='Seconds above which a pod is considered slow (default: 60)'
    )

    parser.add_argument(
        '--include-completed',
        action='store_true',
        help='Include completed (Succeeded/Failed) pods in analysis'
    )

    args = parser.parse_args()

    # Get pods
    pods = get_pods(args.namespace, args.include_completed)

    if not pods:
        print("No pods found.")
        sys.exit(0)

    # Analyze each pod
    pods_data = []
    for pod in pods:
        analysis = analyze_pod_startup(pod)

        # Mark as slow if above threshold
        if (analysis['total_latency_seconds'] is not None and
                analysis['total_latency_seconds'] > args.slow_threshold):
            analysis['is_slow'] = True

        pods_data.append(analysis)

    # Output results
    if args.format == 'json':
        output_json(pods_data, args.warn_only)
    elif args.format == 'table':
        output_table(pods_data, args.warn_only)
    else:
        output_plain(pods_data, args.warn_only, args.verbose)

    # Determine exit code
    has_slow_pods = any(p['is_slow'] for p in pods_data)
    sys.exit(1 if has_slow_pods else 0)


if __name__ == '__main__':
    main()
