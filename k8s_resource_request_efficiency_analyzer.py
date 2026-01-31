#!/usr/bin/env python3
"""
Analyze Kubernetes resource request efficiency by comparing actual usage to requests.

This script identifies over-provisioned and under-utilized pods by comparing their
actual CPU and memory usage (from metrics-server) against their resource requests.
This helps identify wasted cluster capacity and opportunities for rightsizing.

Key metrics:
- Efficiency ratio: actual_usage / requested_resources
- Over-provisioned: pods requesting much more than they use (<25% efficiency)
- Under-provisioned: pods using more than requested (>100% efficiency, risky)

Useful for:
- Cost optimization in large-scale Kubernetes deployments
- Identifying phantom capacity (allocated but unused resources)
- Rightsizing recommendations for deployment resource requests
- Capacity planning and cluster consolidation

Exit codes:
    0 - No efficiency issues detected (all pods within thresholds)
    1 - Efficiency issues found (over/under-provisioned pods detected)
    2 - Usage error, kubectl not available, or metrics-server unavailable
"""

import argparse
import json
import re
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
        return None


def parse_cpu_value(cpu_str):
    """Parse CPU value string to millicores (integer)."""
    if not cpu_str:
        return None
    cpu_str = str(cpu_str).strip()
    if cpu_str.endswith('m'):
        return int(cpu_str[:-1])
    elif cpu_str.endswith('n'):
        return int(cpu_str[:-1]) // 1000000
    else:
        # Whole cores
        try:
            return int(float(cpu_str) * 1000)
        except ValueError:
            return None


def parse_memory_value(mem_str):
    """Parse memory value string to bytes (integer)."""
    if not mem_str:
        return None
    mem_str = str(mem_str).strip()

    # Handle kubernetes memory formats
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

    # Plain bytes
    try:
        return int(mem_str)
    except ValueError:
        return None


def format_cpu(millicores):
    """Format millicores for display."""
    if millicores is None:
        return "N/A"
    if millicores >= 1000:
        return f"{millicores / 1000:.2f}"
    return f"{millicores}m"


def format_memory(bytes_val):
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


def get_pod_specs(namespace=None):
    """Get pod specifications including resource requests."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    if not output:
        return None
    return json.loads(output)


def get_pod_metrics(namespace=None):
    """Get pod metrics from metrics-server."""
    args = ['top', 'pods', '--no-headers', '--containers']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    if not output:
        return None

    metrics = {}
    for line in output.strip().split('\n'):
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


def analyze_efficiency(pods_data, metrics, low_threshold, high_threshold):
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

            # Determine status
            issues = []
            if cpu_efficiency is not None:
                if cpu_efficiency < low_threshold:
                    issues.append(f"CPU over-provisioned ({cpu_efficiency:.1f}% used)")
                elif cpu_efficiency > high_threshold:
                    issues.append(f"CPU under-provisioned ({cpu_efficiency:.1f}% used)")

            if mem_efficiency is not None:
                if mem_efficiency < low_threshold:
                    issues.append(f"Memory over-provisioned ({mem_efficiency:.1f}% used)")
                elif mem_efficiency > high_threshold:
                    issues.append(f"Memory under-provisioned ({mem_efficiency:.1f}% used)")

            container_results.append({
                'name': container_name,
                'cpu_request': cpu_request,
                'cpu_actual': cpu_actual,
                'cpu_efficiency': cpu_efficiency,
                'mem_request': mem_request,
                'mem_actual': mem_actual,
                'mem_efficiency': mem_efficiency,
                'issues': issues
            })

        # Only include pods that have at least one container with metrics
        if container_results:
            results.append({
                'namespace': namespace,
                'pod': pod_name,
                'containers': container_results
            })

    return results


def aggregate_by_workload(results):
    """Aggregate efficiency data by deployment/workload."""
    workload_stats = defaultdict(lambda: {
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

        # Extract workload name (remove pod suffix like -abc123-xyz)
        workload = re.sub(r'-[a-z0-9]{5,10}-[a-z0-9]{5}$', '', pod_name)
        workload = re.sub(r'-[0-9]+$', '', workload)  # StatefulSet pods
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
            'avg_cpu_efficiency': avg_cpu,
            'avg_mem_efficiency': avg_mem,
            'containers_with_issues': stats['issues']
        })

    # Sort by number of issues, then by lowest efficiency
    aggregated.sort(key=lambda x: (
        -x['containers_with_issues'],
        x['avg_cpu_efficiency'] or 100,
        x['avg_mem_efficiency'] or 100
    ))

    return aggregated


def print_plain_output(results, aggregated, warn_only, verbose, low_threshold, high_threshold):
    """Print results in plain text format."""
    has_issues = False

    if verbose:
        print("=== Pod-Level Resource Efficiency ===\n")

        for pod_result in results:
            namespace = pod_result['namespace']
            pod_name = pod_result['pod']

            pod_has_issues = any(c['issues'] for c in pod_result['containers'])

            if warn_only and not pod_has_issues:
                continue

            if pod_has_issues:
                has_issues = True

            status_marker = "!" if pod_has_issues else " "
            print(f"{status_marker} {namespace}/{pod_name}")

            for container in pod_result['containers']:
                cpu_eff = f"{container['cpu_efficiency']:.1f}%" if container['cpu_efficiency'] is not None else "N/A"
                mem_eff = f"{container['mem_efficiency']:.1f}%" if container['mem_efficiency'] is not None else "N/A"

                cpu_str = f"{format_cpu(container['cpu_actual'])}/{format_cpu(container['cpu_request'])}"
                mem_str = f"{format_memory(container['mem_actual'])}/{format_memory(container['mem_request'])}"

                print(f"    {container['name']}: CPU {cpu_str} ({cpu_eff}), Mem {mem_str} ({mem_eff})")

                for issue in container['issues']:
                    print(f"      -> {issue}")

        print()

    print("=== Workload Efficiency Summary ===\n")
    print(f"{'Workload':<50} {'Pods':>5} {'CPU Eff':>10} {'Mem Eff':>10} {'Issues':>7}")
    print("-" * 85)

    for workload in aggregated:
        cpu_eff = f"{workload['avg_cpu_efficiency']:.1f}%" if workload['avg_cpu_efficiency'] is not None else "N/A"
        mem_eff = f"{workload['avg_mem_efficiency']:.1f}%" if workload['avg_mem_efficiency'] is not None else "N/A"

        workload_has_issues = workload['containers_with_issues'] > 0
        if warn_only and not workload_has_issues:
            continue

        if workload_has_issues:
            has_issues = True

        print(f"{workload['workload']:<50} {workload['pod_count']:>5} {cpu_eff:>10} {mem_eff:>10} {workload['containers_with_issues']:>7}")

    # Summary statistics
    total_pods = sum(w['pod_count'] for w in aggregated)
    workloads_with_issues = sum(1 for w in aggregated if w['containers_with_issues'] > 0)

    print()
    print(f"Total: {total_pods} pods across {len(aggregated)} workloads")
    print(f"Workloads with efficiency issues: {workloads_with_issues}")
    print(f"Thresholds: <{low_threshold}% = over-provisioned, >{high_threshold}% = under-provisioned")

    return has_issues


def print_json_output(results, aggregated, warn_only):
    """Print results in JSON format."""
    if warn_only:
        # Filter to only pods/workloads with issues
        results = [p for p in results if any(c['issues'] for c in p['containers'])]
        aggregated = [w for w in aggregated if w['containers_with_issues'] > 0]

    output = {
        'pods': results,
        'workload_summary': aggregated,
        'statistics': {
            'total_pods': sum(w['pod_count'] for w in aggregated),
            'total_workloads': len(aggregated),
            'workloads_with_issues': sum(1 for w in aggregated if w['containers_with_issues'] > 0)
        }
    }

    print(json.dumps(output, indent=2))

    return any(w['containers_with_issues'] > 0 for w in aggregated)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes resource request efficiency vs actual usage',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Analyze all pods across all namespaces
  %(prog)s -n production                # Analyze pods in production namespace only
  %(prog)s --warn-only                  # Show only workloads with efficiency issues
  %(prog)s --low-threshold 30           # Flag pods using <30%% of requested resources
  %(prog)s --verbose                    # Show per-pod details
  %(prog)s --format json                # JSON output for automation

Exit codes:
  0 - No efficiency issues detected
  1 - Efficiency issues found (over/under-provisioned pods)
  2 - Usage error, kubectl unavailable, or metrics-server unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to analyze (default: all namespaces)'
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
        help='Only show pods/workloads with efficiency issues'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed per-pod breakdown'
    )

    parser.add_argument(
        '--low-threshold',
        type=float,
        default=25.0,
        help='Efficiency threshold below which pods are considered over-provisioned (default: 25%%)'
    )

    parser.add_argument(
        '--high-threshold',
        type=float,
        default=100.0,
        help='Efficiency threshold above which pods are considered under-provisioned (default: 100%%)'
    )

    args = parser.parse_args()

    # Get pod specifications
    pods_data = get_pod_specs(args.namespace)
    if pods_data is None:
        print("Error: Failed to get pod specifications from Kubernetes", file=sys.stderr)
        sys.exit(2)

    # Get pod metrics
    metrics = get_pod_metrics(args.namespace)
    if metrics is None:
        print("Error: Failed to get pod metrics. Is metrics-server installed?", file=sys.stderr)
        print("Install metrics-server: https://github.com/kubernetes-sigs/metrics-server", file=sys.stderr)
        sys.exit(2)

    if not metrics:
        print("Error: No pod metrics available. Ensure metrics-server is running and pods have usage data.", file=sys.stderr)
        sys.exit(2)

    # Analyze efficiency
    results = analyze_efficiency(pods_data, metrics, args.low_threshold, args.high_threshold)

    if not results:
        if args.format == 'plain':
            print("No running pods with resource requests and metrics found.")
        else:
            print(json.dumps({'pods': [], 'workload_summary': [], 'statistics': {}}))
        sys.exit(0)

    # Aggregate by workload
    aggregated = aggregate_by_workload(results)

    # Output results
    if args.format == 'json':
        has_issues = print_json_output(results, aggregated, args.warn_only)
    else:
        has_issues = print_plain_output(
            results, aggregated, args.warn_only, args.verbose,
            args.low_threshold, args.high_threshold
        )

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
