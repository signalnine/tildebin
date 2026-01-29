#!/usr/bin/env python3
"""
Kubernetes Pod Lifecycle Hook Analyzer

Analyzes pod lifecycle hook configurations to identify issues affecting
graceful shutdown and startup behavior:
- Missing preStop hooks on stateful workloads
- preStop hook timeout vs terminationGracePeriodSeconds mismatches
- postStart hook failures blocking pod startup
- Lifecycle hook configuration issues

For large-scale Kubernetes environments, proper lifecycle hook configuration
is critical for graceful node drains, rolling updates, and data integrity.

Exit codes:
    0 - All pods have properly configured lifecycle hooks
    1 - Lifecycle hook issues detected
    2 - Usage error or kubectl not found
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


# Default thresholds
DEFAULT_THRESHOLDS = {
    'min_grace_period': 30,        # Minimum terminationGracePeriodSeconds
    'prestop_buffer': 5,           # Seconds buffer between preStop and grace period
    'prestop_exec_timeout': 10,    # Warn if exec preStop likely takes longer
}

# System namespaces often excluded from audits
SYSTEM_NAMESPACES = {'kube-system', 'kube-public', 'kube-node-lease'}

# Workload types that typically need preStop hooks
STATEFUL_ANNOTATIONS = [
    'statefulset.kubernetes.io/pod-name',
]

STATEFUL_LABELS = [
    'app.kubernetes.io/component',
    'statefulset.kubernetes.io/pod-name',
]


def run_kubectl(args):
    """Execute kubectl command and return JSON output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout) if result.stdout else {}
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/",
              file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing kubectl output: {e}", file=sys.stderr)
        sys.exit(1)


def get_pods(namespace=None):
    """Get all pods, optionally filtered by namespace."""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    data = run_kubectl(cmd)
    return data.get('items', [])


def get_pod_events(namespace, pod_name):
    """Get events for a specific pod to detect lifecycle hook issues."""
    cmd = ['get', 'events', '-n', namespace, '-o', 'json',
           '--field-selector', f'involvedObject.name={pod_name}']

    try:
        result = subprocess.run(
            ['kubectl'] + cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data.get('items', [])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return []


def is_stateful_workload(pod):
    """Determine if a pod is likely a stateful workload needing preStop hooks."""
    metadata = pod.get('metadata', {})
    labels = metadata.get('labels', {})
    annotations = metadata.get('annotations', {})
    owner_refs = metadata.get('ownerReferences', [])

    # Check if owned by StatefulSet
    for ref in owner_refs:
        if ref.get('kind') == 'StatefulSet':
            return True

    # Check for stateful-related labels/annotations
    for label in STATEFUL_LABELS:
        if label in labels:
            return True

    for annotation in STATEFUL_ANNOTATIONS:
        if annotation in annotations:
            return True

    # Check for PVC mounts (indicates stateful workload)
    spec = pod.get('spec', {})
    volumes = spec.get('volumes', [])
    for vol in volumes:
        if vol.get('persistentVolumeClaim'):
            return True

    return False


def analyze_lifecycle_hook(hook, hook_type, container_name):
    """Analyze a single lifecycle hook configuration."""
    issues = []

    if not hook:
        return issues

    # Check exec hooks
    exec_hook = hook.get('exec')
    if exec_hook:
        command = exec_hook.get('command', [])
        if not command:
            issues.append({
                'severity': 'HIGH',
                'type': f'{hook_type}_empty_exec',
                'detail': f'{hook_type} exec hook has empty command',
                'recommendation': 'Specify a command for the exec hook'
            })
        elif 'sleep' in ' '.join(command).lower():
            # sleep in preStop is a common pattern, but check duration
            sleep_match = None
            for i, arg in enumerate(command):
                if arg == 'sleep' and i + 1 < len(command):
                    try:
                        sleep_match = int(command[i + 1])
                    except (ValueError, IndexError):
                        pass
                elif arg.startswith('sleep'):
                    try:
                        sleep_match = int(arg.replace('sleep', '').strip())
                    except ValueError:
                        pass

            if sleep_match and sleep_match > 60:
                issues.append({
                    'severity': 'MEDIUM',
                    'type': f'{hook_type}_long_sleep',
                    'detail': f'{hook_type} has long sleep ({sleep_match}s)',
                    'recommendation': 'Ensure sleep duration is within '
                                    'terminationGracePeriodSeconds'
                })

    # Check httpGet hooks
    http_hook = hook.get('httpGet')
    if http_hook:
        if not http_hook.get('path'):
            issues.append({
                'severity': 'MEDIUM',
                'type': f'{hook_type}_no_path',
                'detail': f'{hook_type} HTTP hook has no path specified',
                'recommendation': 'Specify a path for the HTTP hook'
            })
        if not http_hook.get('port'):
            issues.append({
                'severity': 'HIGH',
                'type': f'{hook_type}_no_port',
                'detail': f'{hook_type} HTTP hook has no port specified',
                'recommendation': 'Specify a port for the HTTP hook'
            })

    # Check tcpSocket hooks
    tcp_hook = hook.get('tcpSocket')
    if tcp_hook:
        if not tcp_hook.get('port'):
            issues.append({
                'severity': 'HIGH',
                'type': f'{hook_type}_no_port',
                'detail': f'{hook_type} TCP hook has no port specified',
                'recommendation': 'Specify a port for the TCP hook'
            })

    return issues


def analyze_container_lifecycle(container, pod_name, namespace, grace_period,
                                 is_stateful, check_events=False):
    """Analyze lifecycle hooks for a single container."""
    issues = []
    container_name = container.get('name', 'unknown')
    lifecycle = container.get('lifecycle', {})

    pre_stop = lifecycle.get('preStop')
    post_start = lifecycle.get('postStart')

    # Check for missing preStop on stateful workloads
    if is_stateful and not pre_stop:
        issues.append({
            'severity': 'HIGH',
            'type': 'missing_prestop_stateful',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'Stateful workload missing preStop hook',
            'recommendation': 'Add preStop hook for graceful shutdown and data sync'
        })

    # Check for missing preStop with PVC mounts
    volume_mounts = container.get('volumeMounts', [])
    has_pvc_mount = any(vm.get('name', '').startswith('pvc-') or
                        'data' in vm.get('name', '').lower()
                        for vm in volume_mounts)

    if has_pvc_mount and not pre_stop:
        issues.append({
            'severity': 'MEDIUM',
            'type': 'missing_prestop_pvc',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'Container with data volume missing preStop hook',
            'recommendation': 'Add preStop hook to flush data before termination'
        })

    # Analyze preStop hook configuration
    if pre_stop:
        hook_issues = analyze_lifecycle_hook(pre_stop, 'preStop', container_name)
        for issue in hook_issues:
            issue['namespace'] = namespace
            issue['pod'] = pod_name
            issue['container'] = container_name
            issues.append(issue)

        # Check preStop vs grace period timing
        exec_hook = pre_stop.get('exec')
        if exec_hook:
            command = exec_hook.get('command', [])
            cmd_str = ' '.join(str(c) for c in command)

            # Detect potential timeout issues
            if 'sleep' in cmd_str:
                # Try to extract sleep duration
                for i, arg in enumerate(command):
                    if arg == 'sleep' and i + 1 < len(command):
                        try:
                            sleep_duration = int(command[i + 1])
                            if sleep_duration >= grace_period:
                                issues.append({
                                    'severity': 'HIGH',
                                    'type': 'prestop_exceeds_grace',
                                    'namespace': namespace,
                                    'pod': pod_name,
                                    'container': container_name,
                                    'detail': f'preStop sleep ({sleep_duration}s) >= '
                                             f'grace period ({grace_period}s)',
                                    'recommendation': 'Increase terminationGracePeriodSeconds '
                                                    'or reduce preStop duration'
                                })
                            elif sleep_duration > grace_period - DEFAULT_THRESHOLDS['prestop_buffer']:
                                issues.append({
                                    'severity': 'MEDIUM',
                                    'type': 'prestop_near_grace',
                                    'namespace': namespace,
                                    'pod': pod_name,
                                    'container': container_name,
                                    'detail': f'preStop sleep ({sleep_duration}s) close to '
                                             f'grace period ({grace_period}s)',
                                    'recommendation': 'Add buffer between preStop duration '
                                                    'and terminationGracePeriodSeconds'
                                })
                        except (ValueError, IndexError):
                            pass

    # Analyze postStart hook configuration
    if post_start:
        hook_issues = analyze_lifecycle_hook(post_start, 'postStart', container_name)
        for issue in hook_issues:
            issue['namespace'] = namespace
            issue['pod'] = pod_name
            issue['container'] = container_name
            issues.append(issue)

    # Check for low terminationGracePeriodSeconds
    if grace_period < DEFAULT_THRESHOLDS['min_grace_period']:
        if is_stateful or has_pvc_mount:
            issues.append({
                'severity': 'MEDIUM',
                'type': 'low_grace_period',
                'namespace': namespace,
                'pod': pod_name,
                'container': container_name,
                'detail': f'Low terminationGracePeriodSeconds ({grace_period}s) '
                         'for stateful workload',
                'recommendation': 'Increase terminationGracePeriodSeconds for '
                                'proper graceful shutdown'
            })

    return issues


def analyze_pod_lifecycle(pod, exclude_system=True, check_events=False):
    """Analyze lifecycle hook configurations for a pod."""
    issues = []
    metadata = pod.get('metadata', {})
    pod_name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    spec = pod.get('spec', {})
    status = pod.get('status', {})

    # Skip system namespaces if requested
    if exclude_system and namespace in SYSTEM_NAMESPACES:
        return issues

    # Skip completed pods
    phase = status.get('phase', '')
    if phase in ('Succeeded', 'Failed'):
        return issues

    # Get termination grace period
    grace_period = spec.get('terminationGracePeriodSeconds', 30)

    # Determine if stateful
    is_stateful = is_stateful_workload(pod)

    # Analyze each container
    containers = spec.get('containers', [])
    for container in containers:
        issues.extend(analyze_container_lifecycle(
            container, pod_name, namespace, grace_period,
            is_stateful, check_events
        ))

    # Check for lifecycle hook failures in events
    if check_events:
        events = get_pod_events(namespace, pod_name)
        for event in events:
            reason = event.get('reason', '')
            message = event.get('message', '')

            if 'FailedPostStartHook' in reason:
                issues.append({
                    'severity': 'HIGH',
                    'type': 'poststart_failed',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': '*',
                    'detail': f'postStart hook failed: {message[:100]}',
                    'recommendation': 'Fix postStart hook or container may not start properly'
                })

            if 'FailedPreStopHook' in reason:
                issues.append({
                    'severity': 'HIGH',
                    'type': 'prestop_failed',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': '*',
                    'detail': f'preStop hook failed: {message[:100]}',
                    'recommendation': 'Fix preStop hook for graceful termination'
                })

    return issues


def output_plain(all_issues, verbose=False, warn_only=False):
    """Output results in plain text format."""
    if not all_issues:
        print("All pods have properly configured lifecycle hooks")
        return

    # Group by severity
    by_severity = defaultdict(list)
    for issue in all_issues:
        by_severity[issue['severity']].append(issue)

    # Summary
    if not warn_only:
        print("Kubernetes Pod Lifecycle Hook Analysis")
        print("=" * 70)
        print(f"Total issues: {len(all_issues)}")
        print(f"  HIGH: {len(by_severity['HIGH'])}")
        print(f"  MEDIUM: {len(by_severity['MEDIUM'])}")
        print(f"  LOW: {len(by_severity['LOW'])}")
        print()

    # Output by severity
    for severity in ['HIGH', 'MEDIUM', 'LOW']:
        if severity not in by_severity:
            continue

        if warn_only and severity == 'LOW':
            continue

        issues = by_severity[severity]
        print(f"{severity} SEVERITY ({len(issues)} issues):")
        print("-" * 70)

        for issue in issues:
            print(f"  [{issue['type']}] {issue['namespace']}/{issue['pod']}")
            if issue.get('container') and issue['container'] != '*':
                print(f"    Container: {issue['container']}")
            print(f"    {issue['detail']}")
            if verbose and issue.get('recommendation'):
                print(f"    Recommendation: {issue['recommendation']}")
        print()


def output_json(all_issues):
    """Output results in JSON format."""
    result = {
        'summary': {
            'total_issues': len(all_issues),
            'high': len([i for i in all_issues if i['severity'] == 'HIGH']),
            'medium': len([i for i in all_issues if i['severity'] == 'MEDIUM']),
            'low': len([i for i in all_issues if i['severity'] == 'LOW'])
        },
        'issues': all_issues
    }
    print(json.dumps(result, indent=2))


def output_table(all_issues, warn_only=False):
    """Output results in table format."""
    if not all_issues:
        print("All pods have properly configured lifecycle hooks")
        return

    # Filter if warn_only
    if warn_only:
        all_issues = [i for i in all_issues if i['severity'] != 'LOW']

    if not all_issues:
        print("No high or medium severity issues found")
        return

    print(f"{'Severity':<8} {'Type':<28} {'Namespace/Pod':<35} {'Container':<15}")
    print("=" * 90)

    for issue in sorted(all_issues,
                       key=lambda x: ['HIGH', 'MEDIUM', 'LOW'].index(x['severity'])):
        pod_full = f"{issue['namespace']}/{issue['pod']}"
        if len(pod_full) > 32:
            pod_full = pod_full[:32] + "..."

        container = issue.get('container', '*')
        if len(container) > 12:
            container = container[:12] + "..."

        issue_type = issue['type']
        if len(issue_type) > 25:
            issue_type = issue_type[:25] + "..."

        print(f"{issue['severity']:<8} {issue_type:<28} {pod_full:<35} {container:<15}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes pod lifecycle hook configurations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all pods in all namespaces
  %(prog)s

  # Analyze specific namespace
  %(prog)s -n production

  # Include system namespaces (kube-system, etc.)
  %(prog)s --include-system

  # Show only high/medium severity issues
  %(prog)s --warn-only

  # Check events for lifecycle hook failures
  %(prog)s --check-events

  # JSON output for monitoring/alerting
  %(prog)s --format json

  # Verbose output with recommendations
  %(prog)s -v

Checks performed:
  - Missing preStop hooks on stateful workloads (HIGH)
  - preStop timeout exceeds terminationGracePeriodSeconds (HIGH)
  - postStart/preStop hook failures from events (HIGH)
  - Missing preStop on containers with PVC mounts (MEDIUM)
  - preStop duration close to grace period (MEDIUM)
  - Low terminationGracePeriodSeconds for stateful workloads (MEDIUM)
  - HTTP/TCP hooks without required fields (HIGH/MEDIUM)
  - Exec hooks with empty commands (HIGH)

Why lifecycle hooks matter:
  - preStop hooks enable graceful shutdown during node drains
  - Missing hooks cause connection drops during rolling updates
  - Timeout mismatches lead to SIGKILL instead of graceful shutdown
  - postStart failures block container startup

Exit codes:
  0 - All pods have proper lifecycle hook configuration
  1 - Issues detected
  2 - Usage error or kubectl not found
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to analyze (default: all namespaces)'
    )

    parser.add_argument(
        '--include-system',
        action='store_true',
        help='Include system namespaces (kube-system, kube-public, etc.)'
    )

    parser.add_argument(
        '--check-events',
        action='store_true',
        help='Check pod events for lifecycle hook failures (slower)'
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
        help='Show detailed information with recommendations'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings (exclude LOW severity)'
    )

    args = parser.parse_args()

    # Get and analyze pods
    pods = get_pods(args.namespace)

    all_issues = []
    for pod in pods:
        issues = analyze_pod_lifecycle(
            pod,
            exclude_system=not args.include_system,
            check_events=args.check_events
        )
        all_issues.extend(issues)

    # Output results
    if args.format == 'json':
        output_json(all_issues)
    elif args.format == 'table':
        output_table(all_issues, args.warn_only)
    else:
        output_plain(all_issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    if all_issues:
        high_medium = [i for i in all_issues if i['severity'] in ('HIGH', 'MEDIUM')]
        sys.exit(1 if high_medium else 0)

    sys.exit(0)


if __name__ == '__main__':
    main()
