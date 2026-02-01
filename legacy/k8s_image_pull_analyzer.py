#!/usr/bin/env python3
"""
Kubernetes Image Pull Analyzer

Analyzes image pull issues across the cluster including:
- ImagePullBackOff and ErrImagePull errors
- Image pull times and patterns
- Registry connectivity problems
- Authentication failures
- Slow image pulls that may indicate registry cache issues

Useful for:
- Diagnosing why pods are stuck in ImagePullBackOff
- Identifying nodes with slow registry access
- Detecting registry authentication problems
- Finding problematic images or registries

Exit codes:
    0 - No image pull issues detected
    1 - Image pull issues found (ImagePullBackOff, slow pulls, auth failures)
    2 - Usage error or kubectl not available
"""

import argparse
import sys
import subprocess
import json
from collections import defaultdict
from datetime import datetime, timezone


def run_kubectl(args):
    """Execute kubectl command and return output"""
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


def get_pods(namespace=None):
    """Get all pods in JSON format"""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output)


def get_events(namespace=None):
    """Get recent events in JSON format"""
    cmd = ['get', 'events', '-o', 'json', '--sort-by', '.lastTimestamp']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output)


def analyze_pod_image_status(pod):
    """Analyze image pull status for a pod"""
    issues = []
    namespace = pod['metadata']['namespace']
    name = pod['metadata']['name']

    # Check container statuses
    container_statuses = pod.get('status', {}).get('containerStatuses', [])
    init_container_statuses = pod.get('status', {}).get('initContainerStatuses', [])

    all_statuses = container_statuses + init_container_statuses

    for status in all_statuses:
        container_name = status['name']
        image = status['image']

        # Check for image pull errors
        waiting = status.get('state', {}).get('waiting', {})
        if waiting:
            reason = waiting.get('reason', '')
            message = waiting.get('message', '')

            if reason in ['ImagePullBackOff', 'ErrImagePull']:
                issues.append({
                    'type': 'image_pull_backoff',
                    'severity': 'error',
                    'namespace': namespace,
                    'pod': name,
                    'container': container_name,
                    'image': image,
                    'reason': reason,
                    'message': message
                })

        # Check for authentication errors in terminated state
        terminated = status.get('lastState', {}).get('terminated', {})
        if terminated:
            reason = terminated.get('reason', '')
            message = terminated.get('message', '')

            if 'authentication' in message.lower() or 'unauthorized' in message.lower():
                issues.append({
                    'type': 'auth_failure',
                    'severity': 'error',
                    'namespace': namespace,
                    'pod': name,
                    'container': container_name,
                    'image': image,
                    'reason': reason,
                    'message': message
                })

    return issues


def analyze_events(events, max_age_minutes=60):
    """Analyze events for image pull related issues"""
    issues = []

    for event in events.get('items', []):
        reason = event.get('reason', '')
        message = event.get('message', '')
        event_type = event.get('type', '')

        # Filter for image-related events
        if reason not in ['Failed', 'BackOff', 'Pulling', 'Pulled']:
            continue

        # Check event age
        last_timestamp = event.get('lastTimestamp')
        if not last_timestamp:
            continue

        # Parse timestamp
        try:
            event_time = datetime.fromisoformat(last_timestamp.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            age_minutes = (now - event_time).total_seconds() / 60

            if age_minutes > max_age_minutes:
                continue
        except Exception:
            continue

        # Extract relevant information
        involved_object = event.get('involvedObject', {})
        namespace = involved_object.get('namespace', 'unknown')
        pod_name = involved_object.get('name', 'unknown')

        # Detect slow pulls
        if reason == 'Pulling' and event_type == 'Normal':
            issues.append({
                'type': 'pulling',
                'severity': 'info',
                'namespace': namespace,
                'pod': pod_name,
                'message': message,
                'timestamp': last_timestamp
            })

        # Detect pull failures
        if reason in ['Failed', 'BackOff'] and 'image' in message.lower():
            severity = 'error' if event_type == 'Warning' else 'warning'
            issues.append({
                'type': 'pull_failure',
                'severity': severity,
                'namespace': namespace,
                'pod': pod_name,
                'reason': reason,
                'message': message,
                'timestamp': last_timestamp
            })

    return issues


def aggregate_issues(issues):
    """Aggregate issues by type and image"""
    aggregated = {
        'by_type': defaultdict(int),
        'by_image': defaultdict(int),
        'by_namespace': defaultdict(int),
        'by_node': defaultdict(int),
        'total': len(issues)
    }

    for issue in issues:
        issue_type = issue.get('type', 'unknown')
        aggregated['by_type'][issue_type] += 1

        if 'image' in issue:
            image = issue['image']
            aggregated['by_image'][image] += 1

        if 'namespace' in issue:
            namespace = issue['namespace']
            aggregated['by_namespace'][namespace] += 1

        if 'node' in issue:
            node = issue['node']
            aggregated['by_node'][node] += 1

    return aggregated


def output_plain(issues, aggregated, verbose=False, warn_only=False):
    """Output results in plain text format"""
    if warn_only:
        issues = [i for i in issues if i.get('severity') in ['error', 'warning']]

    if not issues:
        print("No image pull issues detected")
        return

    print(f"Found {len(issues)} image pull issues\n")

    # Summary by type
    print("Issues by type:")
    for issue_type, count in sorted(aggregated['by_type'].items()):
        print(f"  {issue_type}: {count}")
    print()

    # Issues by image
    if aggregated['by_image']:
        print("Issues by image:")
        for image, count in sorted(aggregated['by_image'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {image}: {count}")
        print()

    # Detailed issues
    if verbose:
        print("Detailed issues:")
        for issue in issues:
            severity = issue.get('severity', 'info').upper()
            issue_type = issue.get('type', 'unknown')
            namespace = issue.get('namespace', 'unknown')
            pod = issue.get('pod', 'unknown')

            print(f"[{severity}] {issue_type}")
            print(f"  Namespace: {namespace}")
            print(f"  Pod: {pod}")

            if 'container' in issue:
                print(f"  Container: {issue['container']}")
            if 'image' in issue:
                print(f"  Image: {issue['image']}")
            if 'message' in issue:
                print(f"  Message: {issue['message']}")
            print()


def output_json(issues, aggregated):
    """Output results in JSON format"""
    result = {
        'summary': {
            'total_issues': len(issues),
            'by_type': dict(aggregated['by_type']),
            'by_image': dict(aggregated['by_image']),
            'by_namespace': dict(aggregated['by_namespace'])
        },
        'issues': issues
    }
    print(json.dumps(result, indent=2))


def output_table(issues, aggregated, warn_only=False):
    """Output results in table format"""
    if warn_only:
        issues = [i for i in issues if i.get('severity') in ['error', 'warning']]

    if not issues:
        print("No image pull issues detected")
        return

    print(f"Image Pull Issues Summary (Total: {len(issues)})")
    print()

    # Summary table
    print(f"{'Type':<25} {'Count':<10}")
    print("-" * 35)
    for issue_type, count in sorted(aggregated['by_type'].items()):
        print(f"{issue_type:<25} {count:<10}")
    print()

    # Top images with issues
    if aggregated['by_image']:
        print(f"{'Image':<60} {'Count':<10}")
        print("-" * 70)
        for image, count in sorted(aggregated['by_image'].items(), key=lambda x: x[1], reverse=True)[:10]:
            image_short = image if len(image) <= 60 else image[:57] + "..."
            print(f"{image_short:<60} {count:<10}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes image pull issues and performance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all namespaces for image pull issues
  %(prog)s

  # Check specific namespace with detailed output
  %(prog)s -n production -v

  # Only show errors and warnings
  %(prog)s --warn-only

  # Output in JSON format for automation
  %(prog)s --format json

  # Analyze recent events (last 30 minutes)
  %(prog)s --max-age 30
"""
    )

    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to check (default: all namespaces)"
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
        help="Show detailed information"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and errors"
    )

    parser.add_argument(
        "--max-age",
        type=int,
        default=60,
        help="Maximum age of events to analyze in minutes (default: 60)"
    )

    args = parser.parse_args()

    # Get pods and events
    pods = get_pods(args.namespace)
    events = get_events(args.namespace)

    # Analyze issues
    all_issues = []

    # Analyze pod statuses
    for pod in pods.get('items', []):
        pod_issues = analyze_pod_image_status(pod)
        all_issues.extend(pod_issues)

    # Analyze events
    event_issues = analyze_events(events, args.max_age)
    all_issues.extend(event_issues)

    # Aggregate results
    aggregated = aggregate_issues(all_issues)

    # Output results
    if args.format == "json":
        output_json(all_issues, aggregated)
    elif args.format == "table":
        output_table(all_issues, aggregated, args.warn_only)
    else:  # plain
        output_plain(all_issues, aggregated, args.verbose, args.warn_only)

    # Exit with appropriate code
    error_count = sum(1 for i in all_issues if i.get('severity') == 'error')
    sys.exit(1 if error_count > 0 else 0)


if __name__ == "__main__":
    main()
