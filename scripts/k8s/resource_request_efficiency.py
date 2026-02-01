#!/usr/bin/env python3
# boxctl:
#   category: k8s/resources
#   tags: [efficiency, rightsizing, cost, capacity]
#   requires: [kubectl]
#   privilege: user
#   related: [namespace_resource_analyzer, pod_resource_audit]
#   brief: Analyze resource request efficiency vs actual usage

"""
Analyze Kubernetes resource request efficiency by comparing actual usage to requests.

Identifies over-provisioned and under-utilized pods by comparing their actual
CPU and memory usage (from metrics-server) against their resource requests.
Helps identify wasted cluster capacity and opportunities for rightsizing.

Key metrics:
- Efficiency ratio: actual_usage / requested_resources
- Over-provisioned: pods requesting much more than they use (<25% efficiency)
- Under-provisioned: pods using more than requested (>100% efficiency, risky)

Exit codes:
    0 - No efficiency issues detected (all pods within thresholds)
    1 - Efficiency issues found (over/under-provisioned pods detected)
    2 - Usage error, kubectl not available, or metrics-server unavailable
"""

import argparse
import json
import re
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_cpu_value(cpu_str: str | None) -> int | None:
    """Parse CPU value string to millicores."""
    if not cpu_str:
        return None
    cpu_str = str(cpu_str).strip()

    if cpu_str.endswith('m'):
        try:
            return int(cpu_str[:-1])
        except ValueError:
            return None
    elif cpu_str.endswith('n'):
        try:
            return int(cpu_str[:-1]) // 1000000
        except ValueError:
            return None
    else:
        try:
            return int(float(cpu_str) * 1000)
        except ValueError:
            return None


def parse_memory_value(mem_str: str | None) -> int | None:
    """Parse memory value string to bytes."""
    if not mem_str:
        return None
    mem_str = str(mem_str).strip()

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
        if mem_str.endswith(suffix):
            try:
                return int(float(mem_str[:-len(suffix)]) * mult)
            except ValueError:
                return None

    try:
        return int(mem_str)
    except ValueError:
        return None


def format_cpu(millicores: int | None) -> str:
    """Format millicores for display."""
    if millicores is None:
        return "N/A"
    if millicores >= 1000:
        return f"{millicores / 1000:.2f}"
    return f"{millicores}m"


def format_memory(bytes_val: int | None) -> str:
    """Format bytes for display."""
    if bytes_val is None:
        return "N/A"
    if bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.2f}Gi"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.1f}Mi"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.0f}Ki"
    return f"{bytes_val}"


def get_pod_specs(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get pod specifications including resource requests."""
    args = ['kubectl', 'get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    result = context.run(args)
    return json.loads(result.stdout)


def get_pod_metrics(context: Context, namespace: str | None = None) -> dict[str, dict] | None:
    """Get pod metrics from metrics-server."""
    args = ['kubectl', 'top', 'pods', '--no-headers', '--containers']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    result = context.run(args, check=False)
    if result.returncode != 0:
        return None

    metrics = {}
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        parts = line.split()

        if namespace:
            # Format: POD CONTAINER CPU(cores) MEMORY(bytes)
            if len(parts) >= 4:
                pod_name = parts[0]
                container = parts[1]
                cpu = parts[2]
                memory = parts[3]
                key = f"{namespace}/{pod_name}"
        else:
            # Format: NAMESPACE POD CONTAINER CPU(cores) MEMORY(bytes)
            if len(parts) >= 5:
                ns = parts[0]
                pod_name = parts[1]
                container = parts[2]
                cpu = parts[3]
                memory = parts[4]
                key = f"{ns}/{pod_name}"
            else:
                continue

        if key not in metrics:
            metrics[key] = {}
        metrics[key][container] = {
            'cpu': parse_cpu_value(cpu),
            'memory': parse_memory_value(memory)
        }

    return metrics


def analyze_efficiency(
    pods_data: dict,
    metrics: dict,
    low_threshold: float,
    high_threshold: float
) -> list[dict]:
    """Analyze resource efficiency for all pods."""
    pods = pods_data.get('items', [])
    results = []

    for pod in pods:
        pod_name = pod['metadata']['name']
        namespace = pod['metadata'].get('namespace', 'default')
        pod_key = f"{namespace}/{pod_name}"

        # Skip pods not in Running phase
        phase = pod.get('status', {}).get('phase', '')
        if phase != 'Running':
            continue

        # Get pod metrics
        pod_metrics = metrics.get(pod_key, {})
        if not pod_metrics:
            continue

        containers = pod.get('spec', {}).get('containers', [])
        container_results = []

        for container in containers:
            container_name = container.get('name', 'unknown')
            resources = container.get('resources', {})
            requests = resources.get('requests', {})

            # Get requested values
            cpu_request = parse_cpu_value(requests.get('cpu'))
            mem_request = parse_memory_value(requests.get('memory'))

            # Get actual usage
            container_metrics = pod_metrics.get(container_name, {})
            cpu_actual = container_metrics.get('cpu')
            mem_actual = container_metrics.get('memory')

            # Calculate efficiency ratios
            cpu_efficiency = None
            mem_efficiency = None

            if cpu_request and cpu_request > 0 and cpu_actual is not None:
                cpu_efficiency = (cpu_actual / cpu_request) * 100

            if mem_request and mem_request > 0 and mem_actual is not None:
                mem_efficiency = (mem_actual / mem_request) * 100

            # Determine issues
            issues = []
            if cpu_efficiency is not None:
                if cpu_efficiency < low_threshold:
                    issues.append({
                        'type': 'cpu_over_provisioned',
                        'message': f'CPU at {cpu_efficiency:.1f}% efficiency'
                    })
                elif cpu_efficiency > high_threshold:
                    issues.append({
                        'type': 'cpu_under_provisioned',
                        'message': f'CPU at {cpu_efficiency:.1f}% efficiency'
                    })

            if mem_efficiency is not None:
                if mem_efficiency < low_threshold:
                    issues.append({
                        'type': 'memory_over_provisioned',
                        'message': f'Memory at {mem_efficiency:.1f}% efficiency'
                    })
                elif mem_efficiency > high_threshold:
                    issues.append({
                        'type': 'memory_under_provisioned',
                        'message': f'Memory at {mem_efficiency:.1f}% efficiency'
                    })

            container_results.append({
                'name': container_name,
                'cpu_request': cpu_request,
                'cpu_actual': cpu_actual,
                'cpu_efficiency': round(cpu_efficiency, 1) if cpu_efficiency else None,
                'mem_request': mem_request,
                'mem_actual': mem_actual,
                'mem_efficiency': round(mem_efficiency, 1) if mem_efficiency else None,
                'issues': issues
            })

        # Only include pods with metrics
        if container_results:
            results.append({
                'namespace': namespace,
                'pod': pod_name,
                'containers': container_results
            })

    return results


def aggregate_by_workload(results: list[dict]) -> list[dict]:
    """Aggregate efficiency data by deployment/workload."""
    workload_stats: dict[str, dict] = defaultdict(lambda: {
        'cpu_efficiency_sum': 0,
        'mem_efficiency_sum': 0,
        'cpu_count': 0,
        'mem_count': 0,
        'pod_count': 0,
        'issues': 0
    })

    for pod_result in results:
        namespace = pod_result['namespace']
        pod_name = pod_result['pod']

        # Extract workload name
        workload = re.sub(r'-[a-z0-9]{5,10}-[a-z0-9]{5}$', '', pod_name)
        workload = re.sub(r'-[0-9]+$', '', workload)
        key = f"{namespace}/{workload}"

        workload_stats[key]['pod_count'] += 1

        for container in pod_result['containers']:
            if container['cpu_efficiency'] is not None:
                workload_stats[key]['cpu_efficiency_sum'] += container['cpu_efficiency']
                workload_stats[key]['cpu_count'] += 1

            if container['mem_efficiency'] is not None:
                workload_stats[key]['mem_efficiency_sum'] += container['mem_efficiency']
                workload_stats[key]['mem_count'] += 1

            if container['issues']:
                workload_stats[key]['issues'] += 1

    # Calculate averages
    aggregated = []
    for workload, stats in workload_stats.items():
        avg_cpu = stats['cpu_efficiency_sum'] / stats['cpu_count'] if stats['cpu_count'] > 0 else None
        avg_mem = stats['mem_efficiency_sum'] / stats['mem_count'] if stats['mem_count'] > 0 else None

        aggregated.append({
            'workload': workload,
            'pod_count': stats['pod_count'],
            'avg_cpu_efficiency': round(avg_cpu, 1) if avg_cpu else None,
            'avg_mem_efficiency': round(avg_mem, 1) if avg_mem else None,
            'containers_with_issues': stats['issues']
        })

    aggregated.sort(key=lambda x: (
        -x['containers_with_issues'],
        x['avg_cpu_efficiency'] or 100,
        x['avg_mem_efficiency'] or 100
    ))

    return aggregated


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes resource request efficiency vs actual usage'
    )
    parser.add_argument('-n', '--namespace', help='Namespace to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show per-pod details')
    parser.add_argument('-w', '--warn-only', action='store_true', help='Only show pods with issues')
    parser.add_argument('--low-threshold', type=float, default=25.0, help='Low efficiency threshold (default: 25%%)')
    parser.add_argument('--high-threshold', type=float, default=100.0, help='High efficiency threshold (default: 100%%)')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    if not context.check_tool('kubectl'):
        output.error('kubectl not found in PATH')
        return 2

    try:
        pods_data = get_pod_specs(context, opts.namespace)
    except Exception as e:
        output.error(f'Failed to get pod specs: {e}')
        return 2

    metrics = get_pod_metrics(context, opts.namespace)
    if metrics is None:
        output.error('Failed to get pod metrics. Is metrics-server installed?')
        return 2

    if not metrics:
        output.warning('No pod metrics available')
        output.emit({'pods': [], 'workloads': [], 'summary': {}})
        return 0

    results = analyze_efficiency(pods_data, metrics, opts.low_threshold, opts.high_threshold)

    if opts.warn_only:
        results = [p for p in results if any(c['issues'] for c in p['containers'])]

    aggregated = aggregate_by_workload(results)

    # Calculate summary
    total_pods = sum(w['pod_count'] for w in aggregated)
    workloads_with_issues = sum(1 for w in aggregated if w['containers_with_issues'] > 0)

    result_data: dict[str, Any] = {
        'workloads': aggregated,
        'summary': {
            'total_pods': total_pods,
            'total_workloads': len(aggregated),
            'workloads_with_issues': workloads_with_issues,
            'low_threshold': opts.low_threshold,
            'high_threshold': opts.high_threshold,
        }
    }

    if opts.verbose:
        result_data['pods'] = results

    output.emit(result_data)
    output.set_summary(f"{total_pods} pods, {workloads_with_issues} workloads with issues")

    has_issues = workloads_with_issues > 0
    return 1 if has_issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
