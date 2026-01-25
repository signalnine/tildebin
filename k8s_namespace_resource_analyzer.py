#!/usr/bin/env python3
"""
Analyze Kubernetes namespace resource utilization for capacity planning and chargeback.

This script provides a comprehensive view of resource consumption by namespace:
- Aggregate CPU and memory requests/limits per namespace
- Pod and container counts by namespace
- Resource quota utilization percentages
- Top resource consumers identification
- Namespace without resource quotas (governance risk)

Useful for:
- Chargeback and cost allocation in multi-tenant clusters
- Capacity planning and rightsizing
- Identifying namespaces without governance controls
- Resource distribution analysis across teams

Exit codes:
    0 - Analysis completed successfully
    1 - Issues detected (namespaces without quotas, overcommitted resources)
    2 - Usage error or kubectl not available
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
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def parse_resource_value(value):
    """Parse Kubernetes resource values to base units (bytes for memory, millicores for CPU)."""
    if not value:
        return 0

    value = str(value)

    # CPU parsing (to millicores)
    if value.endswith('m'):
        return int(value[:-1])
    elif value.endswith('n'):
        return int(value[:-1]) // 1000000
    elif re.match(r'^[0-9.]+$', value):
        return int(float(value) * 1000)

    # Memory parsing (to bytes)
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

    for suffix, multiplier in multipliers.items():
        if value.endswith(suffix):
            return int(float(value[:-len(suffix)]) * multiplier)

    # Plain bytes
    if re.match(r'^[0-9]+$', value):
        return int(value)

    return 0


def format_cpu(millicores):
    """Format millicores for display."""
    if millicores >= 1000:
        return f"{millicores / 1000:.1f}"
    return f"{millicores}m"


def format_memory(bytes_val):
    """Format bytes for display."""
    if bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.1f}Gi"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.1f}Mi"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f}Ki"
    return f"{bytes_val}"


def get_all_pods():
    """Get all pods across all namespaces."""
    output = run_kubectl(['get', 'pods', '--all-namespaces', '-o', 'json'])
    return json.loads(output)


def get_resource_quotas():
    """Get all resource quotas."""
    output = run_kubectl(['get', 'resourcequota', '--all-namespaces', '-o', 'json'])
    return json.loads(output)


def get_namespaces():
    """Get all namespaces."""
    output = run_kubectl(['get', 'namespaces', '-o', 'json'])
    return json.loads(output)


def analyze_namespace_resources(pods_data, quotas_data, namespaces_data):
    """Analyze resource utilization by namespace."""
    ns_stats = defaultdict(lambda: {
        'cpu_requests': 0,
        'cpu_limits': 0,
        'memory_requests': 0,
        'memory_limits': 0,
        'pod_count': 0,
        'container_count': 0,
        'running_pods': 0,
        'has_quota': False,
        'quota_cpu_used': 0,
        'quota_cpu_hard': 0,
        'quota_memory_used': 0,
        'quota_memory_hard': 0,
        'pods_without_requests': 0,
        'pods_without_limits': 0,
    })

    # Initialize all namespaces
    for ns in namespaces_data.get('items', []):
        ns_name = ns['metadata']['name']
        ns_stats[ns_name]  # Initialize entry

    # Process pods
    for pod in pods_data.get('items', []):
        namespace = pod['metadata'].get('namespace', 'default')
        phase = pod.get('status', {}).get('phase', 'Unknown')

        ns_stats[namespace]['pod_count'] += 1
        if phase == 'Running':
            ns_stats[namespace]['running_pods'] += 1

        has_requests = False
        has_limits = False

        for container in pod.get('spec', {}).get('containers', []):
            ns_stats[namespace]['container_count'] += 1

            resources = container.get('resources', {})
            requests = resources.get('requests', {})
            limits = resources.get('limits', {})

            if requests:
                has_requests = True
                ns_stats[namespace]['cpu_requests'] += parse_resource_value(requests.get('cpu', '0'))
                ns_stats[namespace]['memory_requests'] += parse_resource_value(requests.get('memory', '0'))

            if limits:
                has_limits = True
                ns_stats[namespace]['cpu_limits'] += parse_resource_value(limits.get('cpu', '0'))
                ns_stats[namespace]['memory_limits'] += parse_resource_value(limits.get('memory', '0'))

        if not has_requests:
            ns_stats[namespace]['pods_without_requests'] += 1
        if not has_limits:
            ns_stats[namespace]['pods_without_limits'] += 1

    # Process quotas
    for quota in quotas_data.get('items', []):
        namespace = quota['metadata'].get('namespace', 'default')
        ns_stats[namespace]['has_quota'] = True

        status = quota.get('status', {})
        hard = status.get('hard', {})
        used = status.get('used', {})

        # CPU quota
        for key in ['requests.cpu', 'cpu']:
            if key in hard:
                ns_stats[namespace]['quota_cpu_hard'] = parse_resource_value(hard[key])
                ns_stats[namespace]['quota_cpu_used'] = parse_resource_value(used.get(key, '0'))
                break

        # Memory quota
        for key in ['requests.memory', 'memory']:
            if key in hard:
                ns_stats[namespace]['quota_memory_hard'] = parse_resource_value(hard[key])
                ns_stats[namespace]['quota_memory_used'] = parse_resource_value(used.get(key, '0'))
                break

    return dict(ns_stats)


def calculate_cluster_totals(ns_stats):
    """Calculate cluster-wide totals."""
    totals = {
        'cpu_requests': 0,
        'cpu_limits': 0,
        'memory_requests': 0,
        'memory_limits': 0,
        'pod_count': 0,
        'container_count': 0,
        'running_pods': 0,
        'namespaces_with_quota': 0,
        'namespaces_without_quota': 0,
    }

    for ns, stats in ns_stats.items():
        totals['cpu_requests'] += stats['cpu_requests']
        totals['cpu_limits'] += stats['cpu_limits']
        totals['memory_requests'] += stats['memory_requests']
        totals['memory_limits'] += stats['memory_limits']
        totals['pod_count'] += stats['pod_count']
        totals['container_count'] += stats['container_count']
        totals['running_pods'] += stats['running_pods']

        if stats['has_quota']:
            totals['namespaces_with_quota'] += 1
        elif stats['pod_count'] > 0:
            totals['namespaces_without_quota'] += 1

    return totals


def print_plain_output(ns_stats, totals, warn_only, top_n, verbose):
    """Print results in plain text format."""
    has_issues = False

    # Sort namespaces by CPU requests (descending)
    sorted_ns = sorted(
        ns_stats.items(),
        key=lambda x: x[1]['cpu_requests'],
        reverse=True
    )

    # Apply top-N filter if specified
    if top_n and top_n > 0:
        sorted_ns = sorted_ns[:top_n]

    print("=== Namespace Resource Utilization ===\n")

    for namespace, stats in sorted_ns:
        # Skip empty namespaces unless verbose
        if not verbose and stats['pod_count'] == 0:
            continue

        # Skip namespaces without issues if warn_only
        issues = []
        if not stats['has_quota'] and stats['pod_count'] > 0:
            issues.append("No resource quota")
            has_issues = True
        if stats['pods_without_requests'] > 0:
            issues.append(f"{stats['pods_without_requests']} pods without requests")
            has_issues = True
        if stats['pods_without_limits'] > 0:
            issues.append(f"{stats['pods_without_limits']} pods without limits")
            has_issues = True

        if warn_only and not issues:
            continue

        # Calculate percentages
        cpu_pct = 0
        memory_pct = 0
        if totals['cpu_requests'] > 0:
            cpu_pct = (stats['cpu_requests'] / totals['cpu_requests']) * 100
        if totals['memory_requests'] > 0:
            memory_pct = (stats['memory_requests'] / totals['memory_requests']) * 100

        # Print namespace info
        status_marker = "!" if issues else " "
        print(f"{status_marker} {namespace}")
        print(f"    Pods: {stats['running_pods']}/{stats['pod_count']} running, {stats['container_count']} containers")
        print(f"    CPU Requests: {format_cpu(stats['cpu_requests'])} ({cpu_pct:.1f}% of cluster)")
        print(f"    Memory Requests: {format_memory(stats['memory_requests'])} ({memory_pct:.1f}% of cluster)")

        if verbose:
            print(f"    CPU Limits: {format_cpu(stats['cpu_limits'])}")
            print(f"    Memory Limits: {format_memory(stats['memory_limits'])}")

        if stats['has_quota']:
            if stats['quota_cpu_hard'] > 0:
                cpu_quota_pct = (stats['quota_cpu_used'] / stats['quota_cpu_hard']) * 100
                print(f"    Quota CPU: {format_cpu(stats['quota_cpu_used'])}/{format_cpu(stats['quota_cpu_hard'])} ({cpu_quota_pct:.0f}%)")
            if stats['quota_memory_hard'] > 0:
                mem_quota_pct = (stats['quota_memory_used'] / stats['quota_memory_hard']) * 100
                print(f"    Quota Memory: {format_memory(stats['quota_memory_used'])}/{format_memory(stats['quota_memory_hard'])} ({mem_quota_pct:.0f}%)")

        if issues:
            print(f"    Issues: {', '.join(issues)}")

        print()

    # Print summary
    print("=== Cluster Summary ===")
    print(f"Total Namespaces: {len(ns_stats)}")
    print(f"Total Pods: {totals['running_pods']}/{totals['pod_count']} running")
    print(f"Total Containers: {totals['container_count']}")
    print(f"Total CPU Requests: {format_cpu(totals['cpu_requests'])}")
    print(f"Total Memory Requests: {format_memory(totals['memory_requests'])}")
    print(f"Namespaces with Quotas: {totals['namespaces_with_quota']}")
    print(f"Namespaces without Quotas: {totals['namespaces_without_quota']}")

    return has_issues


def print_json_output(ns_stats, totals):
    """Print results in JSON format."""
    output = {
        'namespaces': {},
        'cluster_totals': {
            'cpu_requests_millicores': totals['cpu_requests'],
            'cpu_limits_millicores': totals['cpu_limits'],
            'memory_requests_bytes': totals['memory_requests'],
            'memory_limits_bytes': totals['memory_limits'],
            'pod_count': totals['pod_count'],
            'running_pods': totals['running_pods'],
            'container_count': totals['container_count'],
            'namespaces_with_quota': totals['namespaces_with_quota'],
            'namespaces_without_quota': totals['namespaces_without_quota'],
        }
    }

    for namespace, stats in ns_stats.items():
        output['namespaces'][namespace] = {
            'cpu_requests_millicores': stats['cpu_requests'],
            'cpu_limits_millicores': stats['cpu_limits'],
            'memory_requests_bytes': stats['memory_requests'],
            'memory_limits_bytes': stats['memory_limits'],
            'pod_count': stats['pod_count'],
            'running_pods': stats['running_pods'],
            'container_count': stats['container_count'],
            'has_quota': stats['has_quota'],
            'pods_without_requests': stats['pods_without_requests'],
            'pods_without_limits': stats['pods_without_limits'],
        }

        if stats['quota_cpu_hard'] > 0:
            output['namespaces'][namespace]['quota_cpu_used_millicores'] = stats['quota_cpu_used']
            output['namespaces'][namespace]['quota_cpu_hard_millicores'] = stats['quota_cpu_hard']
        if stats['quota_memory_hard'] > 0:
            output['namespaces'][namespace]['quota_memory_used_bytes'] = stats['quota_memory_used']
            output['namespaces'][namespace]['quota_memory_hard_bytes'] = stats['quota_memory_hard']

    print(json.dumps(output, indent=2))


def print_table_output(ns_stats, totals, top_n):
    """Print results in table format."""
    # Sort namespaces by CPU requests (descending)
    sorted_ns = sorted(
        [(ns, stats) for ns, stats in ns_stats.items() if stats['pod_count'] > 0],
        key=lambda x: x[1]['cpu_requests'],
        reverse=True
    )

    if top_n and top_n > 0:
        sorted_ns = sorted_ns[:top_n]

    # Header
    print(f"{'NAMESPACE':<30} {'PODS':>8} {'CPU REQ':>10} {'CPU %':>7} {'MEM REQ':>10} {'MEM %':>7} {'QUOTA':>6}")
    print("-" * 90)

    for namespace, stats in sorted_ns:
        cpu_pct = 0
        memory_pct = 0
        if totals['cpu_requests'] > 0:
            cpu_pct = (stats['cpu_requests'] / totals['cpu_requests']) * 100
        if totals['memory_requests'] > 0:
            memory_pct = (stats['memory_requests'] / totals['memory_requests']) * 100

        quota_status = "Yes" if stats['has_quota'] else "No"

        print(f"{namespace:<30} {stats['pod_count']:>8} {format_cpu(stats['cpu_requests']):>10} {cpu_pct:>6.1f}% {format_memory(stats['memory_requests']):>10} {memory_pct:>6.1f}% {quota_status:>6}")

    print("-" * 90)
    print(f"{'TOTAL':<30} {totals['pod_count']:>8} {format_cpu(totals['cpu_requests']):>10} {'100.0%':>7} {format_memory(totals['memory_requests']):>10} {'100.0%':>7}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes namespace resource utilization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Analyze all namespaces
  %(prog)s --format table           # Tabular output
  %(prog)s --top 10                 # Show top 10 resource consumers
  %(prog)s --warn-only              # Only show namespaces with issues
  %(prog)s --format json            # JSON output for automation
  %(prog)s -v                       # Verbose output with limits

Exit codes:
  0 - Analysis completed successfully
  1 - Issues detected (missing quotas, pods without requests/limits)
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show namespaces with issues'
    )

    parser.add_argument(
        '--top', '-t',
        type=int,
        metavar='N',
        help='Show only top N namespaces by CPU requests'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show additional details (limits, etc.)'
    )

    args = parser.parse_args()

    # Gather data
    pods_data = get_all_pods()
    quotas_data = get_resource_quotas()
    namespaces_data = get_namespaces()

    # Analyze
    ns_stats = analyze_namespace_resources(pods_data, quotas_data, namespaces_data)
    totals = calculate_cluster_totals(ns_stats)

    # Output
    has_issues = False
    if args.format == 'json':
        print_json_output(ns_stats, totals)
        # Check for issues in JSON mode
        has_issues = totals['namespaces_without_quota'] > 0
    elif args.format == 'table':
        print_table_output(ns_stats, totals, args.top)
        has_issues = totals['namespaces_without_quota'] > 0
    else:
        has_issues = print_plain_output(ns_stats, totals, args.warn_only, args.top, args.verbose)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
