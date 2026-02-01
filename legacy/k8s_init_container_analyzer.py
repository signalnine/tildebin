#!/usr/bin/env python3
"""
Analyze Kubernetes init container failures and startup issues.

Init containers run before main application containers and must complete
successfully for the pod to start. This script identifies pods stuck waiting
for init containers, analyzes common failure patterns, and provides actionable
remediation suggestions.

Common init container issues detected:
- Init containers stuck in waiting/running state
- Init container failures blocking pod startup
- Image pull errors for init containers
- Slow init containers causing pod startup delays
- Resource exhaustion in init containers
- Configuration issues (missing secrets, configmaps)

Exit codes:
    0 - No init container issues detected
    1 - Init container issues found
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime


def run_kubectl(args):
    """Execute kubectl command and return output."""
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
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/",
              file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_pods_with_init_containers(namespace=None):
    """Get all pods that have init containers defined."""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    pods_data = json.loads(output)

    pods_with_init = []

    for pod in pods_data.get('items', []):
        spec = pod.get('spec', {})
        init_containers = spec.get('initContainers', [])

        if not init_containers:
            continue

        metadata = pod['metadata']
        status = pod.get('status', {})

        pod_info = {
            'name': metadata['name'],
            'namespace': metadata.get('namespace', 'default'),
            'phase': status.get('phase', 'Unknown'),
            'created': metadata.get('creationTimestamp', ''),
            'init_containers': [],
            'init_container_statuses': status.get('initContainerStatuses', []),
            'conditions': status.get('conditions', []),
            'issues': []
        }

        # Parse init container specs
        for init_spec in init_containers:
            init_info = {
                'name': init_spec.get('name'),
                'image': init_spec.get('image'),
                'command': init_spec.get('command'),
                'resources': init_spec.get('resources', {})
            }
            pod_info['init_containers'].append(init_info)

        pods_with_init.append(pod_info)

    return pods_with_init


def analyze_init_container_status(pod_info):
    """Analyze init container status and identify issues."""
    issues = []
    init_statuses = pod_info.get('init_container_statuses', [])
    init_specs = pod_info.get('init_containers', [])

    # Build a map of init container specs by name
    spec_map = {ic['name']: ic for ic in init_specs}

    completed_count = 0
    running_count = 0
    waiting_count = 0
    failed_count = 0

    for status in init_statuses:
        name = status.get('name', 'unknown')
        state = status.get('state', {})
        last_state = status.get('lastState', {})
        ready = status.get('ready', False)
        restart_count = status.get('restartCount', 0)

        init_spec = spec_map.get(name, {})

        # Check current state
        if 'terminated' in state:
            term = state['terminated']
            exit_code = term.get('exitCode', 0)
            reason = term.get('reason', 'Unknown')

            if exit_code == 0:
                completed_count += 1
            else:
                failed_count += 1
                issues.append({
                    'type': 'init_container_failed',
                    'severity': 'CRITICAL',
                    'container': name,
                    'exit_code': exit_code,
                    'reason': reason,
                    'message': f"Init container '{name}' failed with exit code {exit_code}: {reason}",
                    'image': init_spec.get('image', 'unknown')
                })

        elif 'running' in state:
            running_count += 1
            running = state['running']
            started_at = running.get('startedAt', '')

            # Check if running for too long (potential stuck init container)
            if started_at:
                try:
                    start_time = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
                    duration = datetime.now(start_time.tzinfo) - start_time
                    duration_minutes = duration.total_seconds() / 60

                    if duration_minutes > 10:
                        issues.append({
                            'type': 'init_container_slow',
                            'severity': 'WARNING',
                            'container': name,
                            'duration_minutes': round(duration_minutes, 1),
                            'message': f"Init container '{name}' running for {duration_minutes:.1f} minutes (may be stuck)",
                            'image': init_spec.get('image', 'unknown')
                        })
                except (ValueError, TypeError):
                    pass

        elif 'waiting' in state:
            waiting_count += 1
            waiting = state['waiting']
            reason = waiting.get('reason', 'Unknown')
            message = waiting.get('message', '')

            # Categorize waiting reason
            if reason in ['ImagePullBackOff', 'ErrImagePull', 'ImageInspectError']:
                issues.append({
                    'type': 'init_image_pull_error',
                    'severity': 'CRITICAL',
                    'container': name,
                    'reason': reason,
                    'message': f"Init container '{name}' image pull failed: {reason}",
                    'details': message,
                    'image': init_spec.get('image', 'unknown')
                })
            elif reason == 'CrashLoopBackOff':
                issues.append({
                    'type': 'init_crashloop',
                    'severity': 'CRITICAL',
                    'container': name,
                    'reason': reason,
                    'restart_count': restart_count,
                    'message': f"Init container '{name}' in CrashLoopBackOff ({restart_count} restarts)",
                    'image': init_spec.get('image', 'unknown')
                })
            elif reason == 'CreateContainerConfigError':
                issues.append({
                    'type': 'init_config_error',
                    'severity': 'CRITICAL',
                    'container': name,
                    'reason': reason,
                    'message': f"Init container '{name}' config error (missing secret/configmap?): {message}",
                    'details': message,
                    'image': init_spec.get('image', 'unknown')
                })
            elif reason == 'PodInitializing':
                # Normal state - previous init container may be running
                pass
            else:
                issues.append({
                    'type': 'init_waiting',
                    'severity': 'WARNING',
                    'container': name,
                    'reason': reason,
                    'message': f"Init container '{name}' waiting: {reason}",
                    'details': message,
                    'image': init_spec.get('image', 'unknown')
                })

        # Check restart count
        if restart_count >= 3:
            # Check if not already reported as crashloop
            existing = [i for i in issues if i['container'] == name and i['type'] == 'init_crashloop']
            if not existing:
                issues.append({
                    'type': 'init_high_restarts',
                    'severity': 'WARNING',
                    'container': name,
                    'restart_count': restart_count,
                    'message': f"Init container '{name}' has restarted {restart_count} times",
                    'image': init_spec.get('image', 'unknown')
                })

        # Check for OOMKilled in last state
        if 'terminated' in last_state:
            term = last_state['terminated']
            if term.get('reason') == 'OOMKilled' or term.get('exitCode') == 137:
                issues.append({
                    'type': 'init_oom_killed',
                    'severity': 'WARNING',
                    'container': name,
                    'message': f"Init container '{name}' was previously OOMKilled",
                    'resources': init_spec.get('resources', {}),
                    'image': init_spec.get('image', 'unknown')
                })

    pod_info['analysis'] = {
        'total_init_containers': len(init_specs),
        'completed': completed_count,
        'running': running_count,
        'waiting': waiting_count,
        'failed': failed_count,
        'all_completed': completed_count == len(init_specs) and failed_count == 0
    }

    return issues


def get_remediation_suggestions(issue):
    """Get remediation suggestions based on issue type."""
    suggestions = []
    issue_type = issue['type']

    if issue_type == 'init_container_failed':
        suggestions.append(f"Check init container logs: kubectl logs <pod> -c {issue['container']} --previous")
        suggestions.append("Review init container command and arguments")
        if issue.get('exit_code') == 1:
            suggestions.append("Exit code 1 typically indicates application error - check logic")
        elif issue.get('exit_code') == 127:
            suggestions.append("Exit code 127 indicates command not found - verify image and entrypoint")
        elif issue.get('exit_code') == 126:
            suggestions.append("Exit code 126 indicates permission denied - check file permissions")

    elif issue_type == 'init_image_pull_error':
        suggestions.append("Verify image name and tag are correct")
        suggestions.append("Check image pull secrets are configured and valid")
        suggestions.append("Ensure the image exists in the registry")
        suggestions.append("Check network connectivity to registry")

    elif issue_type == 'init_crashloop':
        suggestions.append(f"Check logs: kubectl logs <pod> -c {issue['container']} --previous")
        suggestions.append("Verify init container command completes successfully")
        suggestions.append("Check if dependencies are available (network, services)")
        suggestions.append("Consider adding retry logic to init container")

    elif issue_type == 'init_config_error':
        suggestions.append("Verify referenced secrets/configmaps exist in the namespace")
        suggestions.append("Check that volume mounts are correctly specified")
        suggestions.append("Ensure serviceAccount has permissions to access secrets")

    elif issue_type == 'init_slow':
        suggestions.append("Check what the init container is waiting for")
        suggestions.append("Verify network connectivity to dependencies")
        suggestions.append("Consider adding timeouts to init container logic")
        suggestions.append("Check if init container is doing expensive operations")

    elif issue_type == 'init_oom_killed':
        resources = issue.get('resources', {})
        limits = resources.get('limits', {})
        if 'memory' in limits:
            suggestions.append(f"Current memory limit: {limits['memory']} - consider increasing")
        else:
            suggestions.append("Set explicit memory limits for init container")
        suggestions.append("Profile init container memory usage")

    elif issue_type == 'init_high_restarts':
        suggestions.append("Check init container logs for recurring errors")
        suggestions.append("Verify external dependencies are stable")
        suggestions.append("Consider adding liveness/startup logic")

    else:
        suggestions.append(f"Check pod events: kubectl describe pod <pod>")
        suggestions.append(f"Check init container logs: kubectl logs <pod> -c {issue['container']}")

    return suggestions


def format_output_plain(pods_with_issues, summary, verbose=False, warn_only=False):
    """Format output as plain text."""
    lines = []

    if not warn_only:
        lines.append("Init Container Analysis")
        lines.append("=" * 70)
        lines.append(f"Total pods with init containers: {summary['total_pods']}")
        lines.append(f"Pods with init container issues: {summary['pods_with_issues']}")
        lines.append(f"Total issues found: {summary['total_issues']}")
        lines.append("")

    if summary['by_issue_type']:
        lines.append("Issues by Type:")
        lines.append("-" * 70)
        for issue_type, count in sorted(summary['by_issue_type'].items(),
                                        key=lambda x: x[1], reverse=True):
            lines.append(f"  {issue_type}: {count}")
        lines.append("")

    if pods_with_issues:
        if not warn_only:
            lines.append("Affected Pods:")
            lines.append("-" * 70)

        for pod_info in pods_with_issues:
            if not pod_info.get('issues'):
                continue

            lines.append(f"\n{pod_info['namespace']}/{pod_info['name']}:")
            lines.append(f"  Phase: {pod_info['phase']}")
            analysis = pod_info.get('analysis', {})
            lines.append(f"  Init containers: {analysis.get('completed', 0)}/{analysis.get('total_init_containers', 0)} completed")

            for issue in pod_info['issues']:
                severity = issue.get('severity', 'INFO')
                lines.append(f"  [{severity}] {issue['message']}")

                if verbose:
                    if issue.get('image'):
                        lines.append(f"    Image: {issue['image']}")
                    if issue.get('details'):
                        lines.append(f"    Details: {issue['details'][:100]}")

                    suggestions = get_remediation_suggestions(issue)
                    if suggestions:
                        lines.append("    Remediation:")
                        for suggestion in suggestions[:3]:
                            lines.append(f"      - {suggestion}")

    elif not warn_only:
        lines.append("No init container issues detected.")

    lines.append("")
    return '\n'.join(lines)


def format_output_json(pods_with_issues, summary):
    """Format output as JSON."""
    result = {
        'summary': summary,
        'pods': []
    }

    for pod_info in pods_with_issues:
        if pod_info.get('issues'):
            pod_output = {
                'namespace': pod_info['namespace'],
                'name': pod_info['name'],
                'phase': pod_info['phase'],
                'analysis': pod_info.get('analysis', {}),
                'issues': []
            }

            for issue in pod_info['issues']:
                issue_output = dict(issue)
                issue_output['remediation'] = get_remediation_suggestions(issue)
                pod_output['issues'].append(issue_output)

            result['pods'].append(pod_output)

    return json.dumps(result, indent=2)


def format_output_table(pods_with_issues, summary, warn_only=False):
    """Format output as table."""
    lines = []

    if not warn_only:
        lines.append(f"{'Namespace':<20} {'Pod':<30} {'Container':<20} {'Issue':<30}")
        lines.append("-" * 105)

    for pod_info in pods_with_issues:
        for issue in pod_info.get('issues', []):
            severity = issue.get('severity', 'INFO')
            issue_type = issue.get('type', 'unknown')
            container = issue.get('container', 'N/A')

            lines.append(
                f"{pod_info['namespace']:<20} "
                f"{pod_info['name'][:28]:<30} "
                f"{container:<20} "
                f"[{severity}] {issue_type}"
            )

    if not pods_with_issues and not warn_only:
        lines.append("No init container issues found.")

    lines.append("")
    lines.append(f"Summary: {summary['pods_with_issues']} pods with issues, {summary['total_issues']} total issues")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all init container issues
  %(prog)s

  # Analyze in specific namespace
  %(prog)s -n production

  # Show verbose output with remediation suggestions
  %(prog)s --verbose

  # Only show critical issues
  %(prog)s --severity critical

  # Output as JSON for monitoring
  %(prog)s --format json

Exit codes:
  0 - No init container issues detected
  1 - Init container issues found
  2 - Usage error or kubectl not available
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Check specific namespace (default: all namespaces)'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed analysis with remediation suggestions'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and critical issues'
    )

    parser.add_argument(
        '--severity',
        choices=['critical', 'warning', 'all'],
        default='all',
        help='Filter by severity level (default: all)'
    )

    args = parser.parse_args()

    # Get pods with init containers
    pods_with_init = get_pods_with_init_containers(namespace=args.namespace)

    if not pods_with_init:
        print("No pods with init containers found.")
        sys.exit(0)

    # Analyze each pod
    pods_with_issues = []
    total_issues = 0
    issues_by_type = {}

    for pod_info in pods_with_init:
        issues = analyze_init_container_status(pod_info)

        # Filter by severity if specified
        if args.severity != 'all':
            severity_filter = args.severity.upper()
            issues = [i for i in issues if i.get('severity') == severity_filter]

        pod_info['issues'] = issues

        if issues:
            pods_with_issues.append(pod_info)
            total_issues += len(issues)

            for issue in issues:
                issue_type = issue.get('type', 'unknown')
                issues_by_type[issue_type] = issues_by_type.get(issue_type, 0) + 1
        elif not args.warn_only:
            # Include pods without issues in analysis (they have completed init)
            pods_with_issues.append(pod_info)

    # Build summary
    summary = {
        'total_pods': len(pods_with_init),
        'pods_with_issues': len([p for p in pods_with_issues if p.get('issues')]),
        'total_issues': total_issues,
        'by_issue_type': issues_by_type
    }

    # Format output
    if args.format == 'json':
        output = format_output_json(pods_with_issues, summary)
    elif args.format == 'table':
        output = format_output_table(pods_with_issues, summary, args.warn_only)
    else:
        output = format_output_plain(pods_with_issues, summary, args.verbose, args.warn_only)

    print(output)

    # Exit code based on issues found
    if total_issues > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
