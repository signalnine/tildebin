#!/usr/bin/env python3
"""
Summarize Kubernetes resource allocation and usage by namespace.

Provides a namespace-level view of resource requests, limits, and actual usage
for capacity planning, cost attribution, and identifying over/under-provisioned
namespaces in multi-tenant clusters.

Features:
- Aggregates CPU and memory requests/limits per namespace
- Shows actual usage vs requests (if metrics-server available)
- Calculates request-to-limit ratios
- Identifies namespaces with high overprovisioning
- Supports filtering and sorting options
- Outputs in plain, JSON, or table format

Use cases:
- Cost attribution in multi-tenant clusters
- Capacity planning and resource forecasting
- Identifying wasteful resource allocations
- Namespace resource budget analysis
- Cluster-wide resource utilization overview

Exit codes:
    0 - Summary generated successfully
    1 - Issues detected (overprovisioned namespaces)
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


def parse_resource_value(value, resource_type):
    """
    Parse Kubernetes resource value to a normalized number.

    CPU: millicores (1000m = 1 core)
    Memory: bytes
    """
    if not value:
        return 0

    value = str(value).strip()

    if resource_type == 'cpu':
        # CPU in millicores
        if value.endswith('m'):
            return int(value[:-1])
        elif value.endswith('n'):
            # nanocores
            return int(value[:-1]) // 1000000
        else:
            # whole cores
            return int(float(value) * 1000)

    elif resource_type == 'memory':
        # Memory in bytes
        multipliers = {
            'Ki': 1024,
            'Mi': 1024 ** 2,
            'Gi': 1024 ** 3,
            'Ti': 1024 ** 4,
            'K': 1000,
            'M': 1000 ** 2,
            'G': 1000 ** 3,
            'T': 1000 ** 4,
        }

        for suffix, mult in multipliers.items():
            if value.endswith(suffix):
                return int(float(value[:-len(suffix)]) * mult)

        # Plain bytes
        return int(value)

    return 0


def format_cpu(millicores):
    """Format CPU millicores for display."""
    if millicores >= 1000:
        return f"{millicores / 1000:.2f}"
    else:
        return f"{millicores}m"


def format_memory(bytes_val):
    """Format memory bytes for display."""
    if bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.2f}Gi"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.2f}Mi"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.2f}Ki"
    else:
        return f"{bytes_val}B"


def get_all_pods():
    """Get all pods in JSON format."""
    output = run_kubectl(['get', 'pods', '--all-namespaces', '-o', 'json'])
    return json.loads(output)


def get_pod_metrics():
    """Get pod metrics if metrics-server is available."""
    try:
        output = run_kubectl(['top', 'pods', '--all-namespaces', '--no-headers'])
        metrics = {}

        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                namespace = parts[0]
                pod_name = parts[1]
                cpu_str = parts[2]
                memory_str = parts[3]

                key = f"{namespace}/{pod_name}"
                metrics[key] = {
                    'cpu': parse_resource_value(cpu_str, 'cpu'),
                    'memory': parse_resource_value(memory_str, 'memory'),
                }

        return metrics
    except subprocess.CalledProcessError:
        return None


def get_namespaces():
    """Get list of all namespaces."""
    output = run_kubectl(['get', 'namespaces', '-o', 'json'])
    data = json.loads(output)
    return [ns['metadata']['name'] for ns in data.get('items', [])]


def aggregate_namespace_resources(pods_data, metrics):
    """
    Aggregate resource requests, limits, and usage by namespace.

    Returns dict keyed by namespace with aggregated values.
    """
    namespaces = defaultdict(lambda: {
        'pod_count': 0,
        'container_count': 0,
        'cpu_requests': 0,
        'cpu_limits': 0,
        'memory_requests': 0,
        'memory_limits': 0,
        'cpu_usage': 0,
        'memory_usage': 0,
        'has_metrics': False,
    })

    pods = pods_data.get('items', [])

    for pod in pods:
        namespace = pod['metadata'].get('namespace', 'default')
        pod_name = pod['metadata']['name']
        phase = pod.get('status', {}).get('phase', '')

        # Skip completed/failed pods
        if phase in ['Succeeded', 'Failed']:
            continue

        namespaces[namespace]['pod_count'] += 1

        # Aggregate container resources
        containers = pod.get('spec', {}).get('containers', [])
        for container in containers:
            namespaces[namespace]['container_count'] += 1

            resources = container.get('resources', {})
            requests = resources.get('requests', {})
            limits = resources.get('limits', {})

            # CPU
            namespaces[namespace]['cpu_requests'] += parse_resource_value(
                requests.get('cpu', '0'), 'cpu'
            )
            namespaces[namespace]['cpu_limits'] += parse_resource_value(
                limits.get('cpu', '0'), 'cpu'
            )

            # Memory
            namespaces[namespace]['memory_requests'] += parse_resource_value(
                requests.get('memory', '0'), 'memory'
            )
            namespaces[namespace]['memory_limits'] += parse_resource_value(
                limits.get('memory', '0'), 'memory'
            )

        # Add actual usage if metrics available
        if metrics:
            pod_key = f"{namespace}/{pod_name}"
            if pod_key in metrics:
                namespaces[namespace]['cpu_usage'] += metrics[pod_key]['cpu']
                namespaces[namespace]['memory_usage'] += metrics[pod_key]['memory']
                namespaces[namespace]['has_metrics'] = True

    return dict(namespaces)


def calculate_efficiency(ns_data):
    """Calculate efficiency metrics for a namespace."""
    # CPU efficiency: usage / requests
    cpu_efficiency = 0.0
    if ns_data['cpu_requests'] > 0:
        cpu_efficiency = (ns_data['cpu_usage'] / ns_data['cpu_requests']) * 100

    # Memory efficiency: usage / requests
    memory_efficiency = 0.0
    if ns_data['memory_requests'] > 0:
        memory_efficiency = (ns_data['memory_usage'] / ns_data['memory_requests']) * 100

    # Request to limit ratio
    cpu_req_limit_ratio = 0.0
    if ns_data['cpu_limits'] > 0:
        cpu_req_limit_ratio = (ns_data['cpu_requests'] / ns_data['cpu_limits']) * 100

    memory_req_limit_ratio = 0.0
    if ns_data['memory_limits'] > 0:
        memory_req_limit_ratio = (ns_data['memory_requests'] / ns_data['memory_limits']) * 100

    return {
        'cpu_efficiency': round(cpu_efficiency, 1),
        'memory_efficiency': round(memory_efficiency, 1),
        'cpu_req_limit_ratio': round(cpu_req_limit_ratio, 1),
        'memory_req_limit_ratio': round(memory_req_limit_ratio, 1),
    }


def analyze_namespaces(ns_data, overprov_threshold):
    """
    Analyze namespaces and identify issues.

    Returns list of issues found.
    """
    issues = []

    for namespace, data in ns_data.items():
        if not data['has_metrics']:
            continue

        efficiency = calculate_efficiency(data)

        # Check for significant overprovisioning (requests >> usage)
        if efficiency['cpu_efficiency'] < overprov_threshold and data['cpu_requests'] > 1000:
            issues.append({
                'namespace': namespace,
                'type': 'cpu_overprovisioned',
                'message': f"CPU efficiency only {efficiency['cpu_efficiency']}% "
                           f"(using {format_cpu(data['cpu_usage'])} of "
                           f"{format_cpu(data['cpu_requests'])} requested)",
            })

        if efficiency['memory_efficiency'] < overprov_threshold and data['memory_requests'] > 100 * 1024 * 1024:
            issues.append({
                'namespace': namespace,
                'type': 'memory_overprovisioned',
                'message': f"Memory efficiency only {efficiency['memory_efficiency']}% "
                           f"(using {format_memory(data['memory_usage'])} of "
                           f"{format_memory(data['memory_requests'])} requested)",
            })

    return issues


def output_plain(ns_data, issues, show_all, sort_by, verbose):
    """Output results in plain text format."""
    lines = []

    # Calculate cluster totals
    total_cpu_req = sum(d['cpu_requests'] for d in ns_data.values())
    total_cpu_lim = sum(d['cpu_limits'] for d in ns_data.values())
    total_mem_req = sum(d['memory_requests'] for d in ns_data.values())
    total_mem_lim = sum(d['memory_limits'] for d in ns_data.values())
    total_pods = sum(d['pod_count'] for d in ns_data.values())

    lines.append("Kubernetes Namespace Resource Summary")
    lines.append("=" * 60)
    lines.append("")
    lines.append("Cluster Totals:")
    lines.append(f"  Namespaces: {len(ns_data)}")
    lines.append(f"  Total Pods: {total_pods}")
    lines.append(f"  CPU Requests: {format_cpu(total_cpu_req)}")
    lines.append(f"  CPU Limits: {format_cpu(total_cpu_lim)}")
    lines.append(f"  Memory Requests: {format_memory(total_mem_req)}")
    lines.append(f"  Memory Limits: {format_memory(total_mem_lim)}")
    lines.append("")

    # Sort namespaces
    sorted_ns = list(ns_data.items())
    if sort_by == 'cpu':
        sorted_ns.sort(key=lambda x: x[1]['cpu_requests'], reverse=True)
    elif sort_by == 'memory':
        sorted_ns.sort(key=lambda x: x[1]['memory_requests'], reverse=True)
    elif sort_by == 'pods':
        sorted_ns.sort(key=lambda x: x[1]['pod_count'], reverse=True)
    else:  # name
        sorted_ns.sort(key=lambda x: x[0])

    # Filter out system namespaces if not showing all
    if not show_all:
        system_ns = {'kube-system', 'kube-public', 'kube-node-lease'}
        sorted_ns = [(ns, data) for ns, data in sorted_ns if ns not in system_ns]

    lines.append("Per-Namespace Breakdown:")
    lines.append("-" * 60)

    for namespace, data in sorted_ns:
        if data['pod_count'] == 0:
            continue

        lines.append(f"\n{namespace}:")
        lines.append(f"  Pods: {data['pod_count']} ({data['container_count']} containers)")
        lines.append(f"  CPU:    Requests: {format_cpu(data['cpu_requests']):>10}  "
                     f"Limits: {format_cpu(data['cpu_limits']):>10}")
        lines.append(f"  Memory: Requests: {format_memory(data['memory_requests']):>10}  "
                     f"Limits: {format_memory(data['memory_limits']):>10}")

        if data['has_metrics'] and verbose:
            efficiency = calculate_efficiency(data)
            lines.append(f"  Usage:  CPU: {format_cpu(data['cpu_usage']):>10}  "
                         f"Memory: {format_memory(data['memory_usage']):>10}")
            lines.append(f"  Efficiency: CPU: {efficiency['cpu_efficiency']}%  "
                         f"Memory: {efficiency['memory_efficiency']}%")

    lines.append("")

    # Show issues
    if issues:
        lines.append("Warnings:")
        lines.append("-" * 40)
        for issue in issues:
            lines.append(f"  [{issue['namespace']}] {issue['message']}")
        lines.append("")

    return '\n'.join(lines)


def output_table(ns_data, show_all, sort_by):
    """Output results in table format."""
    lines = []

    # Header
    lines.append(f"{'Namespace':<25} {'Pods':>6} {'CPU Req':>10} {'CPU Lim':>10} "
                 f"{'Mem Req':>10} {'Mem Lim':>10}")
    lines.append("-" * 85)

    # Sort namespaces
    sorted_ns = list(ns_data.items())
    if sort_by == 'cpu':
        sorted_ns.sort(key=lambda x: x[1]['cpu_requests'], reverse=True)
    elif sort_by == 'memory':
        sorted_ns.sort(key=lambda x: x[1]['memory_requests'], reverse=True)
    elif sort_by == 'pods':
        sorted_ns.sort(key=lambda x: x[1]['pod_count'], reverse=True)
    else:
        sorted_ns.sort(key=lambda x: x[0])

    if not show_all:
        system_ns = {'kube-system', 'kube-public', 'kube-node-lease'}
        sorted_ns = [(ns, data) for ns, data in sorted_ns if ns not in system_ns]

    for namespace, data in sorted_ns:
        if data['pod_count'] == 0:
            continue

        lines.append(
            f"{namespace[:25]:<25} {data['pod_count']:>6} "
            f"{format_cpu(data['cpu_requests']):>10} {format_cpu(data['cpu_limits']):>10} "
            f"{format_memory(data['memory_requests']):>10} {format_memory(data['memory_limits']):>10}"
        )

    # Totals
    total_pods = sum(d['pod_count'] for d in ns_data.values())
    total_cpu_req = sum(d['cpu_requests'] for d in ns_data.values())
    total_cpu_lim = sum(d['cpu_limits'] for d in ns_data.values())
    total_mem_req = sum(d['memory_requests'] for d in ns_data.values())
    total_mem_lim = sum(d['memory_limits'] for d in ns_data.values())

    lines.append("-" * 85)
    lines.append(
        f"{'TOTAL':<25} {total_pods:>6} "
        f"{format_cpu(total_cpu_req):>10} {format_cpu(total_cpu_lim):>10} "
        f"{format_memory(total_mem_req):>10} {format_memory(total_mem_lim):>10}"
    )

    return '\n'.join(lines)


def output_json(ns_data, issues):
    """Output results in JSON format."""
    # Add efficiency metrics to each namespace
    for namespace, data in ns_data.items():
        if data['has_metrics']:
            data['efficiency'] = calculate_efficiency(data)

    result = {
        'namespaces': ns_data,
        'cluster_totals': {
            'namespace_count': len(ns_data),
            'pod_count': sum(d['pod_count'] for d in ns_data.values()),
            'container_count': sum(d['container_count'] for d in ns_data.values()),
            'cpu_requests': sum(d['cpu_requests'] for d in ns_data.values()),
            'cpu_limits': sum(d['cpu_limits'] for d in ns_data.values()),
            'memory_requests': sum(d['memory_requests'] for d in ns_data.values()),
            'memory_limits': sum(d['memory_limits'] for d in ns_data.values()),
        },
        'issues': issues,
    }

    return json.dumps(result, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description='Summarize Kubernetes resource allocation by namespace',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Summary of all namespaces
  %(prog)s --format table           # Compact table output
  %(prog)s --format json            # JSON output for automation
  %(prog)s --sort cpu               # Sort by CPU requests
  %(prog)s --sort memory            # Sort by memory requests
  %(prog)s --all                    # Include system namespaces
  %(prog)s -v                       # Show efficiency metrics

Use cases:
  - Cost attribution: Identify which teams/apps consume most resources
  - Capacity planning: See cluster-wide resource allocation
  - Waste detection: Find namespaces with low efficiency ratios
  - Budget analysis: Compare actual vs requested resources

Exit codes:
  0 - Summary generated successfully
  1 - Issues detected (overprovisioned namespaces)
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '--sort', '-s',
        choices=['name', 'cpu', 'memory', 'pods'],
        default='cpu',
        help='Sort order for namespaces (default: %(default)s)'
    )

    parser.add_argument(
        '--all', '-a',
        action='store_true',
        dest='show_all',
        help='Include system namespaces (kube-system, etc.)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show efficiency metrics (requires metrics-server)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only output if there are warnings'
    )

    parser.add_argument(
        '--overprov-threshold',
        type=float,
        default=25.0,
        help='Efficiency threshold for overprovisioning warnings (default: %(default)s%%)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.overprov_threshold <= 0 or args.overprov_threshold > 100:
        print("Error: --overprov-threshold must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    # Get pod data
    pods_data = get_all_pods()

    # Try to get metrics
    metrics = None
    if args.verbose or args.format == 'json':
        metrics = get_pod_metrics()
        if metrics is None and args.verbose:
            print("Note: Pod metrics unavailable (metrics-server may not be installed)",
                  file=sys.stderr)

    # Aggregate by namespace
    ns_data = aggregate_namespace_resources(pods_data, metrics)

    if not ns_data:
        print("No pods found in cluster", file=sys.stderr)
        sys.exit(0)

    # Analyze for issues
    issues = []
    if metrics:
        issues = analyze_namespaces(ns_data, args.overprov_threshold)

    # Handle warn-only mode
    if args.warn_only and not issues:
        sys.exit(0)

    # Output
    if args.format == 'json':
        output = output_json(ns_data, issues)
    elif args.format == 'table':
        output = output_table(ns_data, args.show_all, args.sort)
    else:
        output = output_plain(ns_data, issues, args.show_all, args.sort, args.verbose)

    print(output)

    # Exit with warning code if issues found
    sys.exit(1 if issues else 0)


if __name__ == '__main__':
    main()
