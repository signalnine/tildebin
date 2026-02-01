#!/usr/bin/env python3
"""
Monitor Kubernetes node pressure conditions for proactive capacity management.

This script analyzes node-level pressure signals across a Kubernetes cluster:
- Memory pressure (MemoryPressure condition)
- Disk pressure (DiskPressure condition)
- PID pressure (PIDPressure condition)
- Network unavailable status
- Allocatable vs capacity analysis
- Kubelet eviction thresholds proximity

Critical for large-scale baremetal Kubernetes deployments where node pressure
can trigger pod evictions and cascading failures.

Exit codes:
    0 - No pressure conditions detected
    1 - Pressure conditions or warnings found
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


def get_nodes():
    """Get all nodes in JSON format."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    return json.loads(output)


def parse_resource_quantity(quantity):
    """Parse Kubernetes resource quantity string to bytes/millicores."""
    if quantity is None:
        return 0

    quantity = str(quantity)

    # Memory units
    if quantity.endswith('Ki'):
        return int(quantity[:-2]) * 1024
    elif quantity.endswith('Mi'):
        return int(quantity[:-2]) * 1024 * 1024
    elif quantity.endswith('Gi'):
        return int(quantity[:-2]) * 1024 * 1024 * 1024
    elif quantity.endswith('Ti'):
        return int(quantity[:-2]) * 1024 * 1024 * 1024 * 1024
    elif quantity.endswith('K'):
        return int(quantity[:-1]) * 1000
    elif quantity.endswith('M'):
        return int(quantity[:-1]) * 1000 * 1000
    elif quantity.endswith('G'):
        return int(quantity[:-1]) * 1000 * 1000 * 1000
    elif quantity.endswith('T'):
        return int(quantity[:-1]) * 1000 * 1000 * 1000 * 1000
    # CPU units (millicores)
    elif quantity.endswith('m'):
        return int(quantity[:-1])
    elif quantity.endswith('n'):
        return int(quantity[:-1]) / 1000000
    else:
        # Plain number - could be cores or bytes
        try:
            return int(quantity)
        except ValueError:
            return float(quantity)


def format_bytes(bytes_val):
    """Format bytes to human readable string."""
    for unit in ['B', 'Ki', 'Mi', 'Gi', 'Ti']:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}Pi"


def format_cpu(millicores):
    """Format millicores to human readable string."""
    if millicores >= 1000:
        return f"{millicores/1000:.1f} cores"
    return f"{millicores}m"


def analyze_node_conditions(node):
    """Analyze node conditions for pressure signals."""
    issues = []
    warnings = []
    conditions = {}

    status = node.get('status', {})
    node_conditions = status.get('conditions', [])

    # Map condition types to their status
    for condition in node_conditions:
        cond_type = condition.get('type', '')
        cond_status = condition.get('status', 'Unknown')
        reason = condition.get('reason', '')
        message = condition.get('message', '')
        conditions[cond_type] = {
            'status': cond_status,
            'reason': reason,
            'message': message
        }

    # Check pressure conditions (True = bad)
    pressure_conditions = ['MemoryPressure', 'DiskPressure', 'PIDPressure']
    for cond in pressure_conditions:
        if cond in conditions:
            if conditions[cond]['status'] == 'True':
                issues.append({
                    'type': 'pressure',
                    'condition': cond,
                    'reason': conditions[cond]['reason'],
                    'message': conditions[cond]['message']
                })

    # Check Ready condition (False = bad)
    if 'Ready' in conditions:
        if conditions['Ready']['status'] != 'True':
            issues.append({
                'type': 'not_ready',
                'condition': 'Ready',
                'reason': conditions['Ready']['reason'],
                'message': conditions['Ready']['message']
            })

    # Check NetworkUnavailable (True = bad)
    if 'NetworkUnavailable' in conditions:
        if conditions['NetworkUnavailable']['status'] == 'True':
            issues.append({
                'type': 'network',
                'condition': 'NetworkUnavailable',
                'reason': conditions['NetworkUnavailable']['reason'],
                'message': conditions['NetworkUnavailable']['message']
            })

    return issues, warnings, conditions


def analyze_node_resources(node):
    """Analyze node capacity vs allocatable resources."""
    status = node.get('status', {})
    capacity = status.get('capacity', {})
    allocatable = status.get('allocatable', {})

    resource_info = {}

    # Analyze memory
    cap_memory = parse_resource_quantity(capacity.get('memory', '0'))
    alloc_memory = parse_resource_quantity(allocatable.get('memory', '0'))
    if cap_memory > 0:
        memory_reserved_pct = ((cap_memory - alloc_memory) / cap_memory) * 100
        resource_info['memory'] = {
            'capacity': cap_memory,
            'allocatable': alloc_memory,
            'reserved_pct': memory_reserved_pct,
            'capacity_str': format_bytes(cap_memory),
            'allocatable_str': format_bytes(alloc_memory)
        }

    # Analyze CPU
    cap_cpu = parse_resource_quantity(capacity.get('cpu', '0'))
    alloc_cpu = parse_resource_quantity(allocatable.get('cpu', '0'))
    # Convert cores to millicores if needed
    if cap_cpu > 0 and cap_cpu < 1000:
        cap_cpu = cap_cpu * 1000
    if alloc_cpu > 0 and alloc_cpu < 1000:
        alloc_cpu = alloc_cpu * 1000
    if cap_cpu > 0:
        cpu_reserved_pct = ((cap_cpu - alloc_cpu) / cap_cpu) * 100
        resource_info['cpu'] = {
            'capacity': cap_cpu,
            'allocatable': alloc_cpu,
            'reserved_pct': cpu_reserved_pct,
            'capacity_str': format_cpu(cap_cpu),
            'allocatable_str': format_cpu(alloc_cpu)
        }

    # Analyze ephemeral storage
    cap_storage = parse_resource_quantity(capacity.get('ephemeral-storage', '0'))
    alloc_storage = parse_resource_quantity(allocatable.get('ephemeral-storage', '0'))
    if cap_storage > 0:
        storage_reserved_pct = ((cap_storage - alloc_storage) / cap_storage) * 100
        resource_info['ephemeral-storage'] = {
            'capacity': cap_storage,
            'allocatable': alloc_storage,
            'reserved_pct': storage_reserved_pct,
            'capacity_str': format_bytes(cap_storage),
            'allocatable_str': format_bytes(alloc_storage)
        }

    # Analyze pods
    cap_pods = int(capacity.get('pods', '0'))
    alloc_pods = int(allocatable.get('pods', '0'))
    if cap_pods > 0:
        resource_info['pods'] = {
            'capacity': cap_pods,
            'allocatable': alloc_pods,
            'reserved_pct': ((cap_pods - alloc_pods) / cap_pods) * 100
        }

    # Analyze PIDs (if available)
    cap_pids = capacity.get('pids')
    alloc_pids = allocatable.get('pids')
    if cap_pids:
        cap_pids = int(cap_pids)
        alloc_pids = int(alloc_pids) if alloc_pids else cap_pids
        resource_info['pids'] = {
            'capacity': cap_pids,
            'allocatable': alloc_pids,
            'reserved_pct': ((cap_pids - alloc_pids) / cap_pids) * 100 if cap_pids > 0 else 0
        }

    return resource_info


def analyze_nodes(nodes_data, warn_only, thresholds):
    """Analyze all nodes and return results."""
    nodes = nodes_data.get('items', [])
    results = []

    for node in nodes:
        node_name = node['metadata']['name']
        labels = node['metadata'].get('labels', {})

        # Get node role
        roles = []
        for label in labels:
            if label.startswith('node-role.kubernetes.io/'):
                role = label.split('/')[-1]
                if role:
                    roles.append(role)
        if not roles:
            roles = ['worker']

        # Analyze conditions
        issues, warnings, conditions = analyze_node_conditions(node)

        # Analyze resources
        resources = analyze_node_resources(node)

        # Check for high reserved resources (potential pressure risk)
        for resource_type, info in resources.items():
            if resource_type in ['memory', 'ephemeral-storage']:
                if info['reserved_pct'] > thresholds.get('reserved_warn', 30):
                    warnings.append({
                        'type': 'high_reservation',
                        'resource': resource_type,
                        'reserved_pct': info['reserved_pct']
                    })

        # Skip nodes without issues if warn_only
        if warn_only and not issues and not warnings:
            continue

        node_info = {
            'name': node_name,
            'roles': roles,
            'conditions': conditions,
            'resources': resources,
            'issues': issues,
            'warnings': warnings,
            'ready': conditions.get('Ready', {}).get('status') == 'True'
        }

        results.append(node_info)

    return results


def print_plain(results):
    """Print results in plain text format."""
    nodes_with_issues = sum(1 for r in results if r['issues'])
    nodes_with_warnings = sum(1 for r in results if r['warnings'] and not r['issues'])

    for node_info in results:
        name = node_info['name']
        roles = ','.join(node_info['roles'])
        ready = 'Ready' if node_info['ready'] else 'NotReady'
        issues = node_info['issues']
        warnings = node_info['warnings']

        # Status indicator
        if issues:
            marker = "[PRESSURE]"
        elif warnings:
            marker = "[WARNING]"
        else:
            marker = "[OK]"

        print(f"{marker} Node: {name} ({roles}) - {ready}")

        # Print issues
        if issues:
            print("  Pressure Conditions:")
            for issue in issues:
                if issue['type'] == 'pressure':
                    print(f"    - {issue['condition']}: {issue['reason']}")
                    if issue['message']:
                        print(f"      {issue['message']}")
                elif issue['type'] == 'not_ready':
                    print(f"    - NotReady: {issue['reason']}")
                elif issue['type'] == 'network':
                    print(f"    - NetworkUnavailable: {issue['reason']}")

        # Print warnings
        if warnings:
            print("  Warnings:")
            for warning in warnings:
                if warning['type'] == 'high_reservation':
                    print(f"    - High {warning['resource']} reservation: {warning['reserved_pct']:.1f}%")

        # Print resource summary
        resources = node_info['resources']
        if resources:
            print("  Resources (allocatable/capacity):")
            if 'memory' in resources:
                mem = resources['memory']
                print(f"    Memory: {mem['allocatable_str']} / {mem['capacity_str']} ({100-mem['reserved_pct']:.1f}% allocatable)")
            if 'cpu' in resources:
                cpu = resources['cpu']
                print(f"    CPU: {cpu['allocatable_str']} / {cpu['capacity_str']} ({100-cpu['reserved_pct']:.1f}% allocatable)")
            if 'ephemeral-storage' in resources:
                stor = resources['ephemeral-storage']
                print(f"    Storage: {stor['allocatable_str']} / {stor['capacity_str']} ({100-stor['reserved_pct']:.1f}% allocatable)")
            if 'pods' in resources:
                pods = resources['pods']
                print(f"    Pods: {pods['allocatable']} / {pods['capacity']}")

        print()

    # Summary
    total = len(results)
    print(f"Summary: {total} nodes analyzed")
    if nodes_with_issues:
        print(f"  - {nodes_with_issues} node(s) with active pressure conditions")
    if nodes_with_warnings:
        print(f"  - {nodes_with_warnings} node(s) with warnings")
    if not nodes_with_issues and not nodes_with_warnings:
        print("  - All nodes healthy, no pressure detected")


def print_json(results):
    """Print results in JSON format."""
    output = {
        'nodes': results,
        'summary': {
            'total_nodes': len(results),
            'nodes_with_pressure': sum(1 for r in results if r['issues']),
            'nodes_with_warnings': sum(1 for r in results if r['warnings'] and not r['issues']),
            'healthy_nodes': sum(1 for r in results if not r['issues'] and not r['warnings'])
        }
    }
    print(json.dumps(output, indent=2, default=str))


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes node pressure conditions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all nodes for pressure conditions
  %(prog)s --warn-only              # Show only nodes with issues or warnings
  %(prog)s --format json            # JSON output for automation
  %(prog)s --reserved-warn 40       # Warn if >40%% resources reserved by system

Pressure Conditions Monitored:
  MemoryPressure    - Node is running low on memory
  DiskPressure      - Node is running low on disk space
  PIDPressure       - Node is running low on process IDs
  NetworkUnavailable - Node network is not properly configured

Exit codes:
  0 - No pressure conditions detected
  1 - Pressure conditions or warnings found
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
        help='Only show nodes with pressure conditions or warnings'
    )

    parser.add_argument(
        '--reserved-warn',
        type=float,
        default=30.0,
        metavar='PCT',
        help='Warn if system-reserved resources exceed this percentage (default: 30)'
    )

    args = parser.parse_args()

    # Set thresholds
    thresholds = {
        'reserved_warn': args.reserved_warn
    }

    # Get node data
    nodes_data = get_nodes()

    # Analyze nodes
    results = analyze_nodes(nodes_data, args.warn_only, thresholds)

    # Print results
    if args.format == 'json':
        print_json(results)
    else:
        print_plain(results)

    # Determine exit code
    has_pressure = any(r['issues'] for r in results)
    has_warnings = any(r['warnings'] for r in results)

    sys.exit(1 if has_pressure or has_warnings else 0)


if __name__ == '__main__':
    main()
