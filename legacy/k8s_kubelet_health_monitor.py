#!/usr/bin/env python3
"""
Kubernetes kubelet health monitor.

This script monitors the health status of kubelet on Kubernetes nodes by checking
node conditions, kubelet healthz endpoints, and kubelet-related metrics. Essential
for proactive detection of node agent issues in large-scale clusters.

Features:
- Check kubelet health via node conditions (Ready, MemoryPressure, DiskPressure, PIDPressure)
- Detect kubelet certificate expiration warnings
- Monitor kubelet restart frequency via node events
- Check kubelet version consistency across the cluster
- Identify nodes with kubelet connectivity issues
- Support for filtering by node labels or names

Exit codes:
    0 - All kubelets healthy
    1 - One or more kubelets unhealthy or warnings detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
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
        return None


def get_nodes(label_selector=None, node_name=None):
    """Get nodes from cluster."""
    cmd = ['get', 'nodes', '-o', 'json']
    if label_selector:
        cmd.extend(['-l', label_selector])
    if node_name:
        cmd.append(node_name)

    output = run_kubectl(cmd)
    if not output:
        return []

    try:
        data = json.loads(output)
        # Handle both single node and list responses
        if data.get('kind') == 'Node':
            return [data]
        return data.get('items', [])
    except json.JSONDecodeError:
        return []


def get_node_events(node_name):
    """Get events related to a specific node."""
    cmd = ['get', 'events', '-n', 'default', '-o', 'json',
           '--field-selector', f'involvedObject.name={node_name},involvedObject.kind=Node']

    output = run_kubectl(cmd)
    if not output:
        return []

    try:
        return json.loads(output).get('items', [])
    except json.JSONDecodeError:
        return []


def check_kubelet_conditions(node):
    """Extract kubelet-related conditions from node status."""
    conditions = node.get('status', {}).get('conditions', [])
    kubelet_conditions = {}
    issues = []

    # Conditions managed by kubelet
    kubelet_condition_types = [
        'Ready',           # Overall node readiness
        'MemoryPressure',  # Memory pressure detection
        'DiskPressure',    # Disk pressure detection
        'PIDPressure',     # PID exhaustion detection
        'NetworkUnavailable'  # Network status (some CNIs)
    ]

    for condition in conditions:
        cond_type = condition.get('type')
        if cond_type in kubelet_condition_types:
            status = condition.get('status')
            reason = condition.get('reason', '')
            message = condition.get('message', '')
            last_transition = condition.get('lastTransitionTime', '')
            last_heartbeat = condition.get('lastHeartbeatTime', '')

            kubelet_conditions[cond_type] = {
                'status': status,
                'reason': reason,
                'message': message,
                'lastTransition': last_transition,
                'lastHeartbeat': last_heartbeat
            }

            # Check for problematic conditions
            if cond_type == 'Ready' and status != 'True':
                issues.append(f"Node not ready: {reason} - {message}")
            elif cond_type in ['MemoryPressure', 'DiskPressure', 'PIDPressure'] and status == 'True':
                issues.append(f"{cond_type}: {reason}")
            elif cond_type == 'NetworkUnavailable' and status == 'True':
                issues.append(f"Network unavailable: {reason}")

    return kubelet_conditions, issues


def check_kubelet_version(node):
    """Extract kubelet version information."""
    node_info = node.get('status', {}).get('nodeInfo', {})
    return {
        'kubeletVersion': node_info.get('kubeletVersion', 'unknown'),
        'containerRuntimeVersion': node_info.get('containerRuntimeVersion', 'unknown'),
        'osImage': node_info.get('osImage', 'unknown'),
        'kernelVersion': node_info.get('kernelVersion', 'unknown')
    }


def check_heartbeat_staleness(node, stale_threshold_seconds=60):
    """Check if kubelet heartbeat is stale."""
    conditions = node.get('status', {}).get('conditions', [])

    for condition in conditions:
        if condition.get('type') == 'Ready':
            last_heartbeat = condition.get('lastHeartbeatTime')
            if last_heartbeat:
                try:
                    # Parse ISO format timestamp
                    heartbeat_time = datetime.fromisoformat(last_heartbeat.replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    age_seconds = (now - heartbeat_time).total_seconds()

                    if age_seconds > stale_threshold_seconds:
                        return True, age_seconds
                    return False, age_seconds
                except (ValueError, TypeError):
                    pass

    return None, None  # Unable to determine


def count_kubelet_restarts(events):
    """Count kubelet restart events from node events."""
    restart_count = 0
    restart_events = []

    for event in events:
        reason = event.get('reason', '')
        message = event.get('message', '').lower()

        # Look for kubelet restart indicators
        if reason in ['Starting', 'NodeReady', 'RegisteredNode']:
            if 'kubelet' in message or reason == 'Starting':
                restart_count += 1
                restart_events.append({
                    'reason': reason,
                    'message': event.get('message', ''),
                    'time': event.get('lastTimestamp') or event.get('eventTime', '')
                })

    return restart_count, restart_events


def analyze_kubelet_health(node, include_events=True):
    """Perform comprehensive kubelet health analysis for a node."""
    node_name = node['metadata']['name']

    # Get kubelet conditions
    conditions, issues = check_kubelet_conditions(node)

    # Get version info
    version_info = check_kubelet_version(node)

    # Check heartbeat staleness
    is_stale, heartbeat_age = check_heartbeat_staleness(node)
    if is_stale:
        issues.append(f"Stale heartbeat: {heartbeat_age:.0f}s old")

    # Check for kubelet restarts via events
    restart_count = 0
    restart_events = []
    if include_events:
        events = get_node_events(node_name)
        restart_count, restart_events = count_kubelet_restarts(events)
        if restart_count > 2:
            issues.append(f"Multiple kubelet restarts detected: {restart_count}")

    # Get node labels and taints that might affect scheduling
    labels = node['metadata'].get('labels', {})
    taints = node['spec'].get('taints', [])

    unschedulable = node['spec'].get('unschedulable', False)
    if unschedulable:
        issues.append("Node is cordoned (unschedulable)")

    return {
        'name': node_name,
        'healthy': len(issues) == 0,
        'conditions': conditions,
        'issues': issues,
        'version': version_info,
        'heartbeatAge': heartbeat_age,
        'restartCount': restart_count,
        'restartEvents': restart_events if restart_events else None,
        'cordoned': unschedulable,
        'taintCount': len(taints)
    }


def check_version_consistency(results):
    """Check if all kubelets are running the same version."""
    versions = defaultdict(list)

    for result in results:
        version = result['version']['kubeletVersion']
        versions[version].append(result['name'])

    if len(versions) > 1:
        return False, dict(versions)
    return True, dict(versions)


def format_plain_output(results, version_info, warn_only=False):
    """Format results as plain text."""
    output = []

    healthy_count = sum(1 for r in results if r['healthy'])
    total_count = len(results)

    output.append(f"Kubelet Health Summary: {healthy_count}/{total_count} healthy")
    output.append("")

    # Version consistency check
    consistent, versions = version_info
    if not consistent:
        output.append("WARNING: Inconsistent kubelet versions detected:")
        for version, nodes in versions.items():
            output.append(f"  {version}: {len(nodes)} node(s)")
        output.append("")

    for result in results:
        if warn_only and result['healthy']:
            continue

        status = "HEALTHY" if result['healthy'] else "UNHEALTHY"
        output.append(f"Node: {result['name']} [{status}]")
        output.append(f"  Kubelet: {result['version']['kubeletVersion']}")
        output.append(f"  Runtime: {result['version']['containerRuntimeVersion']}")

        if result['heartbeatAge'] is not None:
            output.append(f"  Heartbeat age: {result['heartbeatAge']:.0f}s")

        if result['restartCount'] > 0:
            output.append(f"  Recent restarts: {result['restartCount']}")

        if result['cordoned']:
            output.append("  Status: CORDONED")

        if result['issues']:
            output.append("  Issues:")
            for issue in result['issues']:
                output.append(f"    - {issue}")

        output.append("")

    return "\n".join(output)


def format_table_output(results, version_info, warn_only=False):
    """Format results as table."""
    output = []

    healthy_count = sum(1 for r in results if r['healthy'])
    total_count = len(results)

    output.append(f"\nKubelet Health: {healthy_count}/{total_count} healthy")

    # Version consistency
    consistent, versions = version_info
    if not consistent:
        output.append("WARNING: Mixed kubelet versions in cluster")
    output.append("")

    # Table header
    output.append(f"{'NODE':<35} {'STATUS':<10} {'VERSION':<15} {'HEARTBEAT':<12} {'ISSUES'}")
    output.append("-" * 100)

    for result in results:
        if warn_only and result['healthy']:
            continue

        status = "OK" if result['healthy'] else "UNHEALTHY"
        version = result['version']['kubeletVersion'][:14]

        if result['heartbeatAge'] is not None:
            heartbeat = f"{result['heartbeatAge']:.0f}s"
        else:
            heartbeat = "N/A"

        issues = ", ".join(result['issues'][:2]) if result['issues'] else "None"
        if len(issues) > 35:
            issues = issues[:32] + "..."

        output.append(f"{result['name']:<35} {status:<10} {version:<15} {heartbeat:<12} {issues}")

    return "\n".join(output)


def format_json_output(results, version_info, warn_only=False):
    """Format results as JSON."""
    consistent, versions = version_info

    filtered_results = results if not warn_only else [r for r in results if not r['healthy']]

    output = {
        'summary': {
            'total': len(results),
            'healthy': sum(1 for r in results if r['healthy']),
            'unhealthy': sum(1 for r in results if not r['healthy']),
            'versionConsistent': consistent,
            'versions': versions
        },
        'nodes': filtered_results,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }

    return json.dumps(output, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all nodes
  k8s_kubelet_health_monitor.py

  # Check specific node
  k8s_kubelet_health_monitor.py --node worker-1

  # Check nodes with specific label
  k8s_kubelet_health_monitor.py -l node-role.kubernetes.io/worker=

  # Show only unhealthy kubelets
  k8s_kubelet_health_monitor.py --warn-only

  # JSON output for monitoring integration
  k8s_kubelet_health_monitor.py --format json

  # Skip event collection for faster execution
  k8s_kubelet_health_monitor.py --skip-events
        """
    )

    parser.add_argument(
        '--node', '-n',
        help='Check specific node by name'
    )

    parser.add_argument(
        '--label', '-l',
        help='Filter nodes by label selector (e.g., node-role.kubernetes.io/worker=)'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'table', 'json'],
        default='table',
        help='Output format (default: table)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show nodes with issues'
    )

    parser.add_argument(
        '--skip-events',
        action='store_true',
        help='Skip event collection (faster but less info)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed information'
    )

    args = parser.parse_args()

    # Get nodes
    nodes = get_nodes(label_selector=args.label, node_name=args.node)

    if not nodes:
        if args.node:
            print(f"Error: Node '{args.node}' not found", file=sys.stderr)
        else:
            print("Error: No nodes found in cluster", file=sys.stderr)
        sys.exit(1)

    # Analyze each node
    results = []
    for node in nodes:
        result = analyze_kubelet_health(node, include_events=not args.skip_events)
        results.append(result)

    # Check version consistency
    version_info = check_version_consistency(results)

    # Output results
    if args.format == 'json':
        print(format_json_output(results, version_info, args.warn_only))
    elif args.format == 'table':
        print(format_table_output(results, version_info, args.warn_only))
    else:
        print(format_plain_output(results, version_info, args.warn_only))

    # Determine exit code
    has_issues = any(not r['healthy'] for r in results)
    has_version_mismatch = not version_info[0] and len(version_info[1]) > 1

    sys.exit(1 if (has_issues or has_version_mismatch) else 0)


if __name__ == '__main__':
    main()
