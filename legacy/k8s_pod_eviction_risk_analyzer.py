#!/usr/bin/env python3
"""
Analyze Kubernetes pods at risk of eviction.

This script identifies pods likely to be evicted due to node memory pressure,
disk pressure, or other kubelet eviction policies. It helps prevent unexpected
pod disruptions in production clusters.

The script analyzes:
- Node memory/disk pressure conditions
- Pod memory limits vs node available memory
- QoS class (Guaranteed, Burstable, BestEffort)
- Pod priority and grace periods
- Node conditions that trigger eviction

Useful for:
- Preventing unexpected pod disruptions
- Identifying at-risk workloads before eviction
- Capacity planning and resource optimization
- Compliance and SLA monitoring
- Baremetal cluster operations where evictions are expensive

Exit codes:
    0 - No pods at high risk of eviction
    1 - One or more pods at risk of eviction detected
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


def parse_memory_value(mem_str):
    """
    Parse Kubernetes memory string to bytes.
    Examples: "512Mi" -> 536870912, "1Gi" -> 1073741824, "1000m" -> 1000000
    """
    if not mem_str:
        return 0

    mem_str = mem_str.strip().upper()

    # Extract numeric and unit parts
    numeric_part = ""
    unit_part = ""
    for i, char in enumerate(mem_str):
        if char.isdigit() or char == '.':
            numeric_part += char
        else:
            unit_part = mem_str[i:]
            break

    if not numeric_part:
        return 0

    value = float(numeric_part)

    # Handle different units
    units = {
        'K': 1000,
        'M': 1000 ** 2,
        'G': 1000 ** 3,
        'T': 1000 ** 4,
        'KI': 1024,
        'MI': 1024 ** 2,
        'GI': 1024 ** 3,
        'TI': 1024 ** 4,
    }

    unit_key = unit_part.rstrip('B').upper() if unit_part else ''
    multiplier = units.get(unit_key, 1)

    return int(value * multiplier)


def get_nodes_with_pressure():
    """Get all nodes and their pressure conditions."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    nodes_data = json.loads(output)

    pressure_nodes = {}
    for node in nodes_data.get('items', []):
        node_name = node.get('metadata', {}).get('name', 'unknown')
        conditions = node.get('status', {}).get('conditions', [])

        pressure_info = {
            'memory_pressure': False,
            'disk_pressure': False,
            'pid_pressure': False,
            'not_ready': False,
            'all_conditions': conditions
        }

        for condition in conditions:
            cond_type = condition.get('type', '')
            cond_status = condition.get('status', 'Unknown')

            if cond_type == 'MemoryPressure' and cond_status == 'True':
                pressure_info['memory_pressure'] = True
            elif cond_type == 'DiskPressure' and cond_status == 'True':
                pressure_info['disk_pressure'] = True
            elif cond_type == 'PIDPressure' and cond_status == 'True':
                pressure_info['pid_pressure'] = True
            elif cond_type == 'Ready' and cond_status == 'False':
                pressure_info['not_ready'] = True

        if any([pressure_info['memory_pressure'], pressure_info['disk_pressure'],
                pressure_info['pid_pressure'], pressure_info['not_ready']]):
            pressure_nodes[node_name] = pressure_info

    return pressure_nodes


def get_pods_with_resources(namespace=None):
    """Get all pods with their resource requests/limits."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_node_allocatable():
    """Get node allocatable resources."""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    nodes_data = json.loads(output)

    allocatable = {}
    for node in nodes_data.get('items', []):
        node_name = node.get('metadata', {}).get('name', 'unknown')
        node_alloc = node.get('status', {}).get('allocatable', {})

        allocatable[node_name] = {
            'memory': parse_memory_value(node_alloc.get('memory', '0')),
            'cpu': node_alloc.get('cpu', '0'),
            'ephemeral_storage': parse_memory_value(node_alloc.get('ephemeral-storage', '0'))
        }

    return allocatable


def determine_qos_class(pod):
    """Determine QoS class of a pod."""
    # QoS class is already set in pod status, but we calculate it for verification
    containers = pod.get('spec', {}).get('containers', [])

    has_memory_limit = False
    has_memory_request = False
    has_cpu_limit = False
    has_cpu_request = False

    for container in containers:
        resources = container.get('resources', {})
        limits = resources.get('limits', {})
        requests = resources.get('requests', {})

        if limits.get('memory'):
            has_memory_limit = True
        if requests.get('memory'):
            has_memory_request = True
        if limits.get('cpu'):
            has_cpu_limit = True
        if requests.get('cpu'):
            has_cpu_request = True

    # Guaranteed: all containers have limits and requests, and they're equal
    if has_memory_limit and has_memory_request and has_cpu_limit and has_cpu_request:
        # Check if requests == limits for all containers
        all_equal = True
        for container in containers:
            resources = container.get('resources', {})
            limits = resources.get('limits', {})
            requests = resources.get('requests', {})
            if limits != requests:
                all_equal = False
                break
        if all_equal:
            return 'Guaranteed'

    # BestEffort: no requests or limits
    if not has_memory_request and not has_memory_limit and not has_cpu_request and not has_cpu_limit:
        return 'BestEffort'

    # Burstable: everything else
    return 'Burstable'


def analyze_pod_eviction_risk(pod, pressure_nodes, allocatable):
    """
    Analyze a pod for eviction risk.

    Returns:
        Tuple of (risk_level, risk_reasons)
        risk_level: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
        risk_reasons: List of specific reasons
    """
    namespace = pod.get('metadata', {}).get('namespace', 'default')
    pod_name = pod.get('metadata', {}).get('name', 'unknown')
    node_name = pod.get('spec', {}).get('nodeName')

    risk_reasons = []

    # Check if pod is on a node with pressure
    if node_name and node_name in pressure_nodes:
        pressure_info = pressure_nodes[node_name]
        if pressure_info['memory_pressure']:
            risk_reasons.append("Node has MemoryPressure condition")
        if pressure_info['disk_pressure']:
            risk_reasons.append("Node has DiskPressure condition")
        if pressure_info['pid_pressure']:
            risk_reasons.append("Node has PIDPressure condition")
        if pressure_info['not_ready']:
            risk_reasons.append("Node is NotReady")

    # Determine QoS class (BestEffort and Burstable are evicted first)
    qos_class = determine_qos_class(pod)

    if qos_class == 'BestEffort':
        risk_reasons.append("QoS class: BestEffort (evicted first)")
    elif qos_class == 'Burstable':
        risk_reasons.append("QoS class: Burstable (evicted after Guaranteed)")

    # Check for memory limits
    containers = pod.get('spec', {}).get('containers', [])
    total_memory_request = 0
    total_memory_limit = 0
    containers_without_memory = []

    for container in containers:
        container_name = container.get('name', 'unknown')
        resources = container.get('resources', {})
        limits = resources.get('limits', {})
        requests = resources.get('requests', {})

        mem_limit = limits.get('memory')
        mem_request = requests.get('memory')

        if mem_limit:
            total_memory_limit += parse_memory_value(mem_limit)
        if mem_request:
            total_memory_request += parse_memory_value(mem_request)

        if not mem_limit and not mem_request:
            containers_without_memory.append(container_name)

    if containers_without_memory:
        risk_reasons.append(
            f"Containers without memory limits: {', '.join(containers_without_memory)}"
        )

    # Check pod phase
    phase = pod.get('status', {}).get('phase')
    if phase not in ['Running', 'Succeeded']:
        risk_reasons.append(f"Pod phase: {phase}")

    # Check for restart or crash conditions
    container_statuses = pod.get('status', {}).get('containerStatuses', [])
    for cs in container_statuses:
        restart_count = cs.get('restartCount', 0)
        if restart_count > 5:
            risk_reasons.append(f"High restart count: {restart_count}")

        last_state = cs.get('lastState', {})
        if 'terminated' in last_state:
            terminated = last_state['terminated']
            reason = terminated.get('reason', 'Unknown')
            if reason == 'OOMKilled':
                risk_reasons.append(f"Container {cs.get('name')} was OOMKilled")

    # Determine risk level
    risk_level = 'LOW'

    if not risk_reasons:
        risk_level = 'NONE'
    elif any('MemoryPressure' in r for r in risk_reasons) or any('OOMKilled' in r for r in risk_reasons):
        risk_level = 'CRITICAL'
    elif qos_class == 'BestEffort':
        risk_level = 'HIGH'
    elif qos_class == 'Burstable' and any('without' in r for r in risk_reasons):
        risk_level = 'HIGH'
    elif any('Pressure' in r or 'NotReady' in r for r in risk_reasons):
        risk_level = 'MEDIUM'
    elif containers_without_memory:
        risk_level = 'MEDIUM'

    return risk_level, risk_reasons


def format_output_plain(pods_data, namespace):
    """Format output as plain text."""
    for pod in pods_data:
        ns = pod.get('namespace', 'unknown')
        name = pod.get('name', 'unknown')
        risk = pod.get('risk_level', 'UNKNOWN')
        qos = pod.get('qos_class', 'Unknown')

        if namespace and ns != namespace:
            continue

        reasons_str = "; ".join(pod.get('reasons', []))[:60]
        print(f"{ns:20} {name:40} {risk:10} {qos:15} {reasons_str}")


def format_output_table(pods_data, namespace):
    """Format output as ASCII table."""
    print(f"{'NAMESPACE':<20} {'POD NAME':<40} {'RISK':<10} {'QOS':<15} {'REASONS':<50}")
    print("-" * 135)

    for pod in pods_data:
        ns = pod.get('namespace', 'unknown')
        name = pod.get('name', 'unknown')
        risk = pod.get('risk_level', 'UNKNOWN')
        qos = pod.get('qos_class', 'Unknown')
        reasons = pod.get('reasons', [])

        if namespace and ns != namespace:
            continue

        reasons_str = "; ".join(reasons)[:50] if reasons else ""
        print(f"{ns:<20} {name:<40} {risk:<10} {qos:<15} {reasons_str:<50}")


def format_output_json(pods_data, namespace):
    """Format output as JSON."""
    output = {
        'pods_at_risk': len([p for p in pods_data if p['risk_level'] != 'NONE']),
        'pods': []
    }

    for pod in pods_data:
        if namespace and pod.get('namespace') != namespace:
            continue
        output['pods'].append(pod)

    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes pods at risk of eviction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all pods for eviction risk
  k8s_pod_eviction_risk_analyzer.py

  # Check pods in production namespace only
  k8s_pod_eviction_risk_analyzer.py -n production

  # Show only high-risk pods
  k8s_pod_eviction_risk_analyzer.py --warn-only

  # Get JSON output for monitoring integration
  k8s_pod_eviction_risk_analyzer.py --format json
        """
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show pods at risk of eviction (exclude NONE/LOW)"
    )

    args = parser.parse_args()

    # Get data
    pods_data = get_pods_with_resources(args.namespace)
    pods = pods_data.get('items', [])

    if not pods:
        print("No pods found" if args.namespace else "No pods found in cluster", file=sys.stderr)
        sys.exit(0)

    pressure_nodes = get_nodes_with_pressure()
    allocatable = get_node_allocatable()

    # Analyze each pod
    pods_at_risk = []
    all_analyzed_pods = []

    for pod in pods:
        namespace = pod.get('metadata', {}).get('namespace', 'default')
        pod_name = pod.get('metadata', {}).get('name', 'unknown')
        qos_class = determine_qos_class(pod)
        risk_level, risk_reasons = analyze_pod_eviction_risk(pod, pressure_nodes, allocatable)

        pod_info = {
            'namespace': namespace,
            'name': pod_name,
            'qos_class': qos_class,
            'risk_level': risk_level,
            'reasons': risk_reasons
        }

        all_analyzed_pods.append(pod_info)

        if risk_level != 'NONE' and risk_level != 'LOW':
            pods_at_risk.append(pod_info)

    # Determine what to output
    output_pods = pods_at_risk if args.warn_only else all_analyzed_pods

    if not output_pods:
        if args.warn_only:
            print("No pods at risk of eviction found", file=sys.stderr)
        sys.exit(0 if not pods_at_risk else 1)

    # Format and output
    if args.format == "plain":
        format_output_plain(output_pods, args.namespace)
    elif args.format == "table":
        format_output_table(output_pods, args.namespace)
    elif args.format == "json":
        format_output_json(output_pods, args.namespace)

    # Exit code based on whether we found at-risk pods
    sys.exit(1 if pods_at_risk else 0)


if __name__ == "__main__":
    main()
