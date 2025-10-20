#!/usr/bin/env python3
"""
Check Kubernetes node health and resource availability.

This script provides a comprehensive health check for Kubernetes nodes in a cluster,
including node status, resource utilization, and problem detection. Useful for
monitoring large-scale baremetal Kubernetes deployments.

Exit codes:
    0 - All nodes healthy
    1 - One or more nodes unhealthy or warnings detected
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
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_nodes():
    """Get all nodes in JSON format."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    return json.loads(output)


def get_node_metrics():
    """Get node metrics if metrics-server is available."""
    try:
        output = run_kubectl(['top', 'nodes', '--no-headers'])
        metrics = {}
        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                name = parts[0]
                cpu = parts[1]  # e.g., "1234m" or "12%"
                cpu_pct = parts[2]  # e.g., "12%"
                mem = parts[3]  # e.g., "1234Mi"
                mem_pct = parts[4]  # e.g., "12%"
                metrics[name] = {
                    'cpu': cpu,
                    'cpu_percent': cpu_pct,
                    'memory': mem,
                    'memory_percent': mem_pct
                }
        return metrics
    except subprocess.CalledProcessError:
        # metrics-server not available
        return None


def parse_quantity(quantity_str):
    """Parse Kubernetes quantity string to bytes or millicores."""
    if not quantity_str:
        return 0

    # Handle millicores (e.g., "1000m" = 1 core)
    if quantity_str.endswith('m'):
        return int(quantity_str[:-1])

    # Handle memory units
    units = {
        'Ki': 1024,
        'Mi': 1024**2,
        'Gi': 1024**3,
        'Ti': 1024**4,
        'K': 1000,
        'M': 1000**2,
        'G': 1000**3,
        'T': 1000**4,
    }

    for suffix, multiplier in units.items():
        if quantity_str.endswith(suffix):
            return int(quantity_str[:-len(suffix)]) * multiplier

    # Plain number
    try:
        return int(quantity_str)
    except ValueError:
        return 0


def check_node_conditions(node):
    """Check node conditions and return status and issues."""
    conditions = node.get('status', {}).get('conditions', [])
    issues = []
    ready = False

    for condition in conditions:
        condition_type = condition.get('type')
        status = condition.get('status')
        reason = condition.get('reason', '')
        message = condition.get('message', '')

        if condition_type == 'Ready':
            if status == 'True':
                ready = True
            else:
                issues.append(f"NotReady: {reason} - {message}")
        elif status == 'True' and condition_type in ['MemoryPressure', 'DiskPressure', 'PIDPressure', 'NetworkUnavailable']:
            issues.append(f"{condition_type}: {reason}")

    return ready, issues


def get_node_allocatable(node):
    """Get allocatable resources for a node."""
    allocatable = node.get('status', {}).get('allocatable', {})
    return {
        'cpu': parse_quantity(allocatable.get('cpu', '0')),
        'memory': parse_quantity(allocatable.get('memory', '0')),
        'pods': int(allocatable.get('pods', '0'))
    }


def format_bytes(bytes_val):
    """Format bytes to human readable format."""
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}PiB"


def format_cpu(millicores):
    """Format millicores to cores."""
    cores = millicores / 1000.0
    return f"{cores:.2f}"


def print_node_status(nodes_data, metrics, output_format, warn_only):
    """Print node status in requested format."""
    nodes = nodes_data.get('items', [])

    if output_format == 'json':
        output = []
        for node in nodes:
            name = node['metadata']['name']
            ready, issues = check_node_conditions(node)
            allocatable = get_node_allocatable(node)

            node_info = {
                'name': name,
                'ready': ready,
                'issues': issues,
                'allocatable': {
                    'cpu_cores': format_cpu(allocatable['cpu']),
                    'memory': format_bytes(allocatable['memory']),
                    'pods': allocatable['pods']
                }
            }

            if metrics and name in metrics:
                node_info['usage'] = metrics[name]

            # Filter if warn_only
            if not warn_only or issues or not ready:
                output.append(node_info)

        print(json.dumps(output, indent=2))
        return any(not node['ready'] or node['issues'] for node in output)

    else:  # plain format
        has_issues = False
        healthy_count = 0
        unhealthy_count = 0

        for node in nodes:
            name = node['metadata']['name']
            ready, issues = check_node_conditions(node)
            allocatable = get_node_allocatable(node)

            # Count status
            if ready and not issues:
                healthy_count += 1
            else:
                unhealthy_count += 1
                has_issues = True

            # Skip healthy nodes if warn_only
            if warn_only and ready and not issues:
                continue

            # Print node info
            status = "READY" if ready else "NOT READY"
            print(f"Node: {name} - {status}")

            # Print allocatable resources
            print(f"  Allocatable: {format_cpu(allocatable['cpu'])} CPU cores, "
                  f"{format_bytes(allocatable['memory'])} memory, {allocatable['pods']} pods")

            # Print current usage if available
            if metrics and name in metrics:
                m = metrics[name]
                print(f"  Current Usage: {m['cpu']} ({m['cpu_percent']}) CPU, "
                      f"{m['memory']} ({m['memory_percent']}) memory")

            # Print issues
            if issues:
                for issue in issues:
                    print(f"  WARNING: {issue}")

            print()

        # Print summary
        total = len(nodes)
        print(f"Summary: {healthy_count}/{total} nodes healthy, {unhealthy_count} with issues")

        if metrics is None:
            print("\nNote: Node metrics unavailable (metrics-server may not be installed)")

        return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Check Kubernetes node health and resource availability',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Check all nodes, plain output
  %(prog)s --warn-only        # Show only nodes with issues
  %(prog)s --format json      # JSON output
  %(prog)s -f json -w         # JSON output, only problematic nodes

Exit codes:
  0 - All nodes healthy
  1 - One or more nodes unhealthy
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show nodes with warnings or issues'
    )

    args = parser.parse_args()

    # Get node data
    nodes_data = get_nodes()

    # Try to get metrics
    metrics = get_node_metrics()

    # Print status
    has_issues = print_node_status(nodes_data, metrics, args.format, args.warn_only)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
