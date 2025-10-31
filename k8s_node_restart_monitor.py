#!/usr/bin/env python3
"""Monitor Kubernetes node restart activity and detect problem nodes.

This script analyzes node uptime and restart patterns to identify:
- Nodes with excessive restarts (potential hardware/software issues)
- Nodes that have recently recovered from crashes
- Cluster-wide restart trends

Critical for baremetal deployments where node stability directly impacts
application availability. Helps identify hardware failures, kernel panics,
or configuration issues causing repeated restarts.

Exit codes:
  0: No restart issues detected
  1: Nodes with excessive restarts or recent crashes detected
  2: Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta

def run_kubectl(args):
    """Run kubectl and return JSON output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        print("Error: kubectl not found", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"kubectl error: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def get_nodes():
    """Get all nodes with their metadata."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    return json.loads(output)

def get_node_status(node_name):
    """Get detailed status for a specific node."""
    output = run_kubectl(['get', 'node', node_name, '-o', 'json'])
    return json.loads(output)

def calculate_uptime(status_data):
    """Extract and calculate node uptime in seconds.

    Returns tuple: (uptime_seconds, boot_time_str)
    """
    try:
        for condition in status_data.get('status', {}).get('conditions', []):
            if condition['type'] == 'Ready':
                # When a node transitions to Ready, we know it just booted
                # We'll estimate uptime from the condition timestamp
                transition_time_str = condition.get('lastTransitionTime', '')
                if transition_time_str:
                    boot_time = datetime.fromisoformat(transition_time_str.replace('Z', '+00:00'))
                    current_time = datetime.now(boot_time.tzinfo)
                    uptime = (current_time - boot_time).total_seconds()
                    return max(0, uptime), transition_time_str
    except (KeyError, ValueError):
        pass
    return None, None

def parse_container_status(container_status):
    """Parse container restart count and last state."""
    restart_count = container_status.get('restartCount', 0)
    last_state = container_status.get('lastState', {})
    reason = None

    if last_state and 'terminated' in last_state:
        reason = last_state['terminated'].get('reason', 'Unknown')

    return restart_count, reason

def get_node_pod_restarts(node_name):
    """Get restart counts for all pods on a node."""
    try:
        output = run_kubectl([
            'get', 'pods',
            '--all-namespaces',
            '--field-selector', f'spec.nodeName={node_name}',
            '-o', 'json'
        ])
        pods_data = json.loads(output)

        total_restarts = 0
        max_restarts = 0
        restart_details = []

        for pod in pods_data.get('items', []):
            pod_name = pod['metadata']['name']
            namespace = pod['metadata']['namespace']

            for container in pod.get('status', {}).get('containerStatuses', []):
                restart_count, reason = parse_container_status(container)
                total_restarts += restart_count
                max_restarts = max(max_restarts, restart_count)

                if restart_count > 0:
                    restart_details.append({
                        'pod': pod_name,
                        'namespace': namespace,
                        'container': container.get('name', 'unknown'),
                        'restarts': restart_count,
                        'reason': reason
                    })

        return total_restarts, max_restarts, restart_details
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return 0, 0, []

def assess_node_health(node_data, pod_restarts, max_pod_restarts):
    """Determine node health status based on restart patterns.

    Returns: (status, reason)
    status: "OK", "WARNING", or "CRITICAL"
    """
    # Thresholds for node restart detection
    EXCESSIVE_POD_RESTARTS = 5  # Max restarts for any single pod
    HIGH_TOTAL_POD_RESTARTS = 20  # Total restarts across all pods

    issues = []

    # Check for excessive pod restarts (indicates node issues)
    if max_pod_restarts > EXCESSIVE_POD_RESTARTS:
        issues.append(f"Container with {max_pod_restarts} restarts")

    if pod_restarts > HIGH_TOTAL_POD_RESTARTS:
        issues.append(f"Total {pod_restarts} restarts across pods")

    # Check node conditions
    for condition in node_data.get('status', {}).get('conditions', []):
        condition_type = condition.get('type')
        status = condition.get('status')
        reason = condition.get('reason', 'Unknown')

        if condition_type == 'Ready' and status == 'False':
            issues.append(f"Node not ready: {reason}")
        elif condition_type in ['MemoryPressure', 'DiskPressure', 'PIDPressure']:
            if status == 'True':
                issues.append(f"{condition_type}: {reason}")

    if issues:
        # Determine severity
        if "not ready" in str(issues).lower() or max_pod_restarts > EXCESSIVE_POD_RESTARTS * 2:
            return "CRITICAL", " | ".join(issues)
        else:
            return "WARNING", " | ".join(issues)

    return "OK", "Healthy"

def format_uptime(seconds):
    """Format uptime in human-readable format."""
    if seconds is None:
        return "Unknown"

    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)

    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"

def print_plain_output(nodes_data):
    """Print output in plain (space-separated) format."""
    for node_name, node_info in sorted(nodes_data.items()):
        status = node_info['status']
        uptime = format_uptime(node_info['uptime'])
        pod_restarts = node_info['pod_restarts']
        max_restarts = node_info['max_pod_restarts']
        reason = node_info['reason']

        print(f"{node_name} {status} {uptime} {pod_restarts} {max_restarts} {reason}")

def print_table_output(nodes_data):
    """Print output in table format."""
    print(f"{'Node':<30} {'Status':<10} {'Uptime':<15} {'Pod Restarts':<12} {'Max Restarts':<12} {'Reason'}")
    print("-" * 120)

    for node_name, node_info in sorted(nodes_data.items()):
        status = node_info['status']
        uptime = format_uptime(node_info['uptime'])
        pod_restarts = node_info['pod_restarts']
        max_restarts = node_info['max_pod_restarts']
        reason = node_info['reason'][:50]  # Truncate long reasons

        print(f"{node_name:<30} {status:<10} {uptime:<15} {pod_restarts:<12} {max_restarts:<12} {reason}")

def print_json_output(nodes_data):
    """Print output in JSON format."""
    output = {}
    for node_name, node_info in sorted(nodes_data.items()):
        output[node_name] = {
            'status': node_info['status'],
            'uptime_seconds': node_info['uptime'],
            'uptime_formatted': format_uptime(node_info['uptime']),
            'pod_restarts': node_info['pod_restarts'],
            'max_pod_restarts': node_info['max_pod_restarts'],
            'reason': node_info['reason'],
            'restart_details': node_info['restart_details']
        }
    print(json.dumps(output, indent=2))

def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes node restart activity and detect problem nodes'
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

    args = parser.parse_args()

    # Collect node data
    nodes_data = {}
    has_issues = False

    try:
        nodes = get_nodes()

        for node in nodes.get('items', []):
            node_name = node['metadata']['name']

            # Get detailed node info
            node_status = get_node_status(node_name)

            # Calculate uptime
            uptime_seconds, boot_time = calculate_uptime(node_status)

            # Get pod restart information
            pod_restarts, max_pod_restarts, restart_details = get_node_pod_restarts(node_name)

            # Assess health
            status, reason = assess_node_health(node_status, pod_restarts, max_pod_restarts)

            if status != "OK":
                has_issues = True

            nodes_data[node_name] = {
                'status': status,
                'uptime': uptime_seconds,
                'boot_time': boot_time,
                'pod_restarts': pod_restarts,
                'max_pod_restarts': max_pod_restarts,
                'reason': reason,
                'restart_details': restart_details
            }

    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as e:
        print(f"Error gathering node information: {e}", file=sys.stderr)
        sys.exit(1)

    # Filter output if warn-only
    if args.warn_only:
        nodes_data = {k: v for k, v in nodes_data.items() if v['status'] != 'OK'}

    # Format and print output
    if args.format == 'json':
        print_json_output(nodes_data)
    elif args.format == 'table':
        print_table_output(nodes_data)
    else:  # plain
        print_plain_output(nodes_data)

    # Exit with appropriate status
    sys.exit(1 if has_issues else 0)

if __name__ == "__main__":
    main()
