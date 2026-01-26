#!/usr/bin/env python3
"""
Analyze Kubernetes resource requests/limits to identify right-sizing opportunities.

This script compares configured resource requests/limits against actual usage
(via metrics-server) to identify workloads that are over-provisioned or
under-provisioned. Helps optimize cluster capacity and reduce costs.

Use cases:
- Identify pods requesting far more CPU/memory than they use
- Find pods at risk of OOM due to insufficient limits
- Generate resource optimization recommendations
- Audit namespace resource efficiency
- Support capacity planning decisions

Exit codes:
    0 - All workloads appropriately sized
    1 - Right-sizing opportunities found
    2 - Usage error or kubectl/metrics unavailable
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
        return None


def parse_cpu(cpu_str):
    """Parse CPU string to millicores (int)."""
    if not cpu_str:
        return None
    cpu_str = str(cpu_str).strip()
    if cpu_str.endswith('m'):
        return int(cpu_str[:-1])
    elif cpu_str.endswith('n'):
        return int(cpu_str[:-1]) // 1000000
    else:
        try:
            return int(float(cpu_str) * 1000)
        except ValueError:
            return None


def parse_memory(mem_str):
    """Parse memory string to bytes (int)."""
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

    for suffix, multiplier in multipliers.items():
        if mem_str.endswith(suffix):
            try:
                return int(float(mem_str[:-len(suffix)]) * multiplier)
            except ValueError:
                return None

    try:
        return int(mem_str)
    except ValueError:
        return None


def format_cpu(millicores):
    """Format millicores to human-readable string."""
    if millicores is None:
        return "N/A"
    if millicores >= 1000:
        return f"{millicores / 1000:.1f}"
    return f"{millicores}m"


def format_memory(bytes_val):
    """Format bytes to human-readable string."""
    if bytes_val is None:
        return "N/A"
    if bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.1f}Gi"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.0f}Mi"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.0f}Ki"
    return f"{bytes_val}B"


def get_pods(namespace=None):
    """Get all pods with resource specifications."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    if not output:
        return []
    return json.loads(output).get('items', [])


def get_pod_metrics(namespace=None):
    """Get pod metrics from metrics-server."""
    args = ['top', 'pods', '--no-headers']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    if not output:
        return {}

    metrics = {}
    for line in output.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3:
            if namespace:
                # Format: POD CPU MEM
                pod_name = parts[0]
                ns = namespace
                cpu = parts[1]
                mem = parts[2]
            else:
                # Format: NAMESPACE POD CPU MEM
                ns = parts[0]
                pod_name = parts[1]
                cpu = parts[2]
                mem = parts[3] if len(parts) > 3 else "0Mi"

            key = f"{ns}/{pod_name}"
            metrics[key] = {
                'cpu': parse_cpu(cpu),
                'memory': parse_memory(mem)
            }

    return metrics


def analyze_pod(pod, metrics):
    """Analyze a single pod's resource efficiency."""
    metadata = pod.get('metadata', {})
    spec = pod.get('spec', {})
    status = pod.get('status', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    key = f"{namespace}/{name}"

    # Skip non-running pods
    phase = status.get('phase', '')
    if phase != 'Running':
        return None

    # Get owner reference for grouping
    owner_refs = metadata.get('ownerReferences', [])
    owner_kind = owner_refs[0].get('kind', 'None') if owner_refs else 'None'
    owner_name = owner_refs[0].get('name', 'None') if owner_refs else 'None'

    # Aggregate resources across containers
    total_cpu_request = 0
    total_cpu_limit = 0
    total_mem_request = 0
    total_mem_limit = 0
    has_requests = False
    has_limits = False

    containers = spec.get('containers', [])
    for container in containers:
        resources = container.get('resources', {})
        requests = resources.get('requests', {})
        limits = resources.get('limits', {})

        cpu_req = parse_cpu(requests.get('cpu'))
        cpu_lim = parse_cpu(limits.get('cpu'))
        mem_req = parse_memory(requests.get('memory'))
        mem_lim = parse_memory(limits.get('memory'))

        if cpu_req:
            total_cpu_request += cpu_req
            has_requests = True
        if cpu_lim:
            total_cpu_limit += cpu_lim
            has_limits = True
        if mem_req:
            total_mem_request += mem_req
            has_requests = True
        if mem_lim:
            total_mem_limit += mem_lim
            has_limits = True

    # Get actual usage from metrics
    usage = metrics.get(key, {})
    actual_cpu = usage.get('cpu')
    actual_mem = usage.get('memory')

    # Calculate efficiency ratios
    cpu_efficiency = None
    mem_efficiency = None

    if actual_cpu is not None and total_cpu_request > 0:
        cpu_efficiency = (actual_cpu / total_cpu_request) * 100
    if actual_mem is not None and total_mem_request > 0:
        mem_efficiency = (actual_mem / total_mem_request) * 100

    return {
        'name': name,
        'namespace': namespace,
        'owner_kind': owner_kind,
        'owner_name': owner_name,
        'cpu_request': total_cpu_request if has_requests else None,
        'cpu_limit': total_cpu_limit if has_limits else None,
        'cpu_actual': actual_cpu,
        'cpu_efficiency': cpu_efficiency,
        'mem_request': total_mem_request if has_requests else None,
        'mem_limit': total_mem_limit if has_limits else None,
        'mem_actual': actual_mem,
        'mem_efficiency': mem_efficiency,
        'has_requests': has_requests,
        'has_limits': has_limits
    }


def categorize_findings(analyses, cpu_threshold=30, mem_threshold=30):
    """
    Categorize pods by their resource efficiency.

    Thresholds are percentages - pods using less than threshold% of
    their requests are considered over-provisioned.
    """
    categories = {
        'over_provisioned': [],      # Using <threshold% of requests
        'under_provisioned': [],     # Using >90% of requests/limits
        'no_requests': [],           # Missing resource requests
        'no_limits': [],             # Missing resource limits
        'efficient': [],             # Within acceptable range
        'no_metrics': []             # No usage data available
    }

    for analysis in analyses:
        if analysis is None:
            continue

        has_metrics = (analysis['cpu_actual'] is not None or
                       analysis['mem_actual'] is not None)

        if not has_metrics:
            categories['no_metrics'].append(analysis)
            continue

        if not analysis['has_requests']:
            categories['no_requests'].append(analysis)
            continue

        if not analysis['has_limits']:
            categories['no_limits'].append(analysis)

        # Check for over-provisioning
        cpu_over = (analysis['cpu_efficiency'] is not None and
                    analysis['cpu_efficiency'] < cpu_threshold)
        mem_over = (analysis['mem_efficiency'] is not None and
                    analysis['mem_efficiency'] < mem_threshold)

        if cpu_over or mem_over:
            categories['over_provisioned'].append(analysis)
            continue

        # Check for under-provisioning (>90% usage)
        cpu_under = (analysis['cpu_efficiency'] is not None and
                     analysis['cpu_efficiency'] > 90)
        mem_under = (analysis['mem_efficiency'] is not None and
                     analysis['mem_efficiency'] > 90)

        if cpu_under or mem_under:
            categories['under_provisioned'].append(analysis)
            continue

        categories['efficient'].append(analysis)

    return categories


def calculate_savings(categories):
    """Calculate potential resource savings from right-sizing."""
    total_cpu_savings = 0
    total_mem_savings = 0

    for pod in categories['over_provisioned']:
        if pod['cpu_request'] and pod['cpu_actual']:
            # Suggest setting request to 150% of actual usage
            suggested = int(pod['cpu_actual'] * 1.5)
            savings = pod['cpu_request'] - suggested
            if savings > 0:
                total_cpu_savings += savings

        if pod['mem_request'] and pod['mem_actual']:
            # Suggest setting request to 120% of actual usage
            suggested = int(pod['mem_actual'] * 1.2)
            savings = pod['mem_request'] - suggested
            if savings > 0:
                total_mem_savings += savings

    return total_cpu_savings, total_mem_savings


def output_plain(categories, analyses, verbose=False, warn_only=False):
    """Output results in plain text format."""
    total = len([a for a in analyses if a is not None])
    over_count = len(categories['over_provisioned'])
    under_count = len(categories['under_provisioned'])
    no_req_count = len(categories['no_requests'])

    if not warn_only:
        print("Resource Right-Sizing Analysis")
        print("=" * 80)
        print(f"Total running pods analyzed: {total}")
        print(f"  Over-provisioned: {over_count}")
        print(f"  Under-provisioned: {under_count}")
        print(f"  Missing requests: {no_req_count}")
        print(f"  Efficiently sized: {len(categories['efficient'])}")
        print(f"  No metrics available: {len(categories['no_metrics'])}")
        print()

    # Over-provisioned pods
    if categories['over_provisioned']:
        print(f"Over-Provisioned Workloads ({over_count}):")
        print("-" * 80)
        for pod in sorted(categories['over_provisioned'],
                          key=lambda x: (x['mem_efficiency'] or 100)):
            cpu_eff = f"{pod['cpu_efficiency']:.0f}%" if pod['cpu_efficiency'] else "N/A"
            mem_eff = f"{pod['mem_efficiency']:.0f}%" if pod['mem_efficiency'] else "N/A"

            print(f"  {pod['namespace']}/{pod['name']}")
            print(f"    Owner: {pod['owner_kind']}/{pod['owner_name']}")
            print(f"    CPU: {format_cpu(pod['cpu_actual'])} used / "
                  f"{format_cpu(pod['cpu_request'])} requested ({cpu_eff})")
            print(f"    Memory: {format_memory(pod['mem_actual'])} used / "
                  f"{format_memory(pod['mem_request'])} requested ({mem_eff})")

            if verbose:
                # Suggest new values
                if pod['cpu_actual'] and pod['cpu_request']:
                    suggested_cpu = int(pod['cpu_actual'] * 1.5)
                    print(f"    Suggested CPU request: {format_cpu(suggested_cpu)}")
                if pod['mem_actual'] and pod['mem_request']:
                    suggested_mem = int(pod['mem_actual'] * 1.2)
                    print(f"    Suggested memory request: {format_memory(suggested_mem)}")
            print()

    # Under-provisioned pods
    if categories['under_provisioned']:
        print(f"Under-Provisioned Workloads ({under_count}):")
        print("-" * 80)
        for pod in sorted(categories['under_provisioned'],
                          key=lambda x: -(x['mem_efficiency'] or 0)):
            cpu_eff = f"{pod['cpu_efficiency']:.0f}%" if pod['cpu_efficiency'] else "N/A"
            mem_eff = f"{pod['mem_efficiency']:.0f}%" if pod['mem_efficiency'] else "N/A"

            print(f"  {pod['namespace']}/{pod['name']}")
            print(f"    Owner: {pod['owner_kind']}/{pod['owner_name']}")
            print(f"    CPU: {format_cpu(pod['cpu_actual'])} used / "
                  f"{format_cpu(pod['cpu_request'])} requested ({cpu_eff})")
            print(f"    Memory: {format_memory(pod['mem_actual'])} used / "
                  f"{format_memory(pod['mem_request'])} requested ({mem_eff})")
            print()

    # Missing requests
    if categories['no_requests'] and not warn_only:
        print(f"Missing Resource Requests ({no_req_count}):")
        print("-" * 80)
        for pod in categories['no_requests'][:10]:
            print(f"  {pod['namespace']}/{pod['name']}")
        if len(categories['no_requests']) > 10:
            print(f"  ... and {len(categories['no_requests']) - 10} more")
        print()

    # Savings summary
    if categories['over_provisioned']:
        cpu_savings, mem_savings = calculate_savings(categories)
        print("Potential Savings (if right-sized):")
        print("-" * 80)
        print(f"  CPU: {format_cpu(cpu_savings)} cores could be reclaimed")
        print(f"  Memory: {format_memory(mem_savings)} could be reclaimed")
        print()

    if not categories['over_provisioned'] and warn_only:
        print("All workloads are appropriately sized")


def output_json(categories, analyses):
    """Output results in JSON format."""
    cpu_savings, mem_savings = calculate_savings(categories)

    result = {
        'summary': {
            'total': len([a for a in analyses if a is not None]),
            'over_provisioned': len(categories['over_provisioned']),
            'under_provisioned': len(categories['under_provisioned']),
            'missing_requests': len(categories['no_requests']),
            'efficient': len(categories['efficient']),
            'no_metrics': len(categories['no_metrics'])
        },
        'potential_savings': {
            'cpu_millicores': cpu_savings,
            'memory_bytes': mem_savings,
            'cpu_formatted': format_cpu(cpu_savings),
            'memory_formatted': format_memory(mem_savings)
        },
        'categories': {
            'over_provisioned': categories['over_provisioned'],
            'under_provisioned': categories['under_provisioned'],
            'missing_requests': categories['no_requests'],
            'missing_limits': categories['no_limits'],
            'efficient': categories['efficient']
        }
    }
    print(json.dumps(result, indent=2, default=str))


def output_table(categories, analyses, warn_only=False):
    """Output results in table format."""
    if warn_only:
        pods_to_show = (categories['over_provisioned'] +
                        categories['under_provisioned'])
    else:
        pods_to_show = [a for a in analyses if a is not None]

    print(f"{'NAMESPACE':<15} {'POD':<30} {'CPU%':<8} {'MEM%':<8} "
          f"{'CPU REQ':<10} {'MEM REQ':<10} {'STATUS':<15}")
    print("-" * 106)

    for pod in sorted(pods_to_show, key=lambda x: (x['mem_efficiency'] or 100)):
        ns = pod['namespace'][:13] + '..' if len(pod['namespace']) > 15 else pod['namespace']
        name = pod['name'][:28] + '..' if len(pod['name']) > 30 else pod['name']
        cpu_eff = f"{pod['cpu_efficiency']:.0f}%" if pod['cpu_efficiency'] else "N/A"
        mem_eff = f"{pod['mem_efficiency']:.0f}%" if pod['mem_efficiency'] else "N/A"

        if pod in categories['over_provisioned']:
            status = "OVER-PROV"
        elif pod in categories['under_provisioned']:
            status = "UNDER-PROV"
        elif pod in categories['no_requests']:
            status = "NO-REQ"
        else:
            status = "OK"

        print(f"{ns:<15} {name:<30} {cpu_eff:<8} {mem_eff:<8} "
              f"{format_cpu(pod['cpu_request']):<10} "
              f"{format_memory(pod['mem_request']):<10} {status:<15}")

    print()
    print(f"Total: {len(pods_to_show)} | "
          f"Over: {len(categories['over_provisioned'])} | "
          f"Under: {len(categories['under_provisioned'])}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes resource requests/limits for right-sizing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Analyze all pods
  %(prog)s -n production                # Analyze specific namespace
  %(prog)s --cpu-threshold 20           # Flag pods using <20%% CPU
  %(prog)s --format json                # JSON output for automation
  %(prog)s --warn-only                  # Only show over/under-provisioned
  %(prog)s -v                           # Show suggested new values

Use cases:
  - Identify pods wasting cluster resources
  - Find pods at risk of OOM or throttling
  - Generate right-sizing recommendations
  - Optimize cluster capacity and costs

Exit codes:
  0 - All workloads appropriately sized
  1 - Right-sizing opportunities found
  2 - kubectl or metrics-server unavailable
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Kubernetes namespace to analyze (default: all namespaces)'
    )
    parser.add_argument(
        '--cpu-threshold',
        type=int,
        default=30,
        help='CPU efficiency threshold %% below which pod is over-provisioned (default: 30)'
    )
    parser.add_argument(
        '--mem-threshold',
        type=int,
        default=30,
        help='Memory efficiency threshold %% below which pod is over-provisioned (default: 30)'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show over/under-provisioned workloads'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed recommendations'
    )
    parser.add_argument(
        '--exclude-namespace',
        action='append',
        default=[],
        help='Namespaces to exclude (can be specified multiple times)'
    )

    args = parser.parse_args()

    # Get pods
    pods = get_pods(args.namespace)
    if not pods:
        if args.format == 'json':
            print(json.dumps({'summary': {'total': 0}, 'categories': {}}))
        else:
            print("No pods found")
        sys.exit(0)

    # Get metrics
    metrics = get_pod_metrics(args.namespace)
    if not metrics:
        print("Warning: No metrics available. Is metrics-server running?",
              file=sys.stderr)
        print("Install metrics-server: "
              "https://github.com/kubernetes-sigs/metrics-server",
              file=sys.stderr)
        # Continue without metrics - will show as no_metrics category

    # Analyze each pod
    analyses = []
    for pod in pods:
        ns = pod.get('metadata', {}).get('namespace', '')
        if ns in args.exclude_namespace:
            continue
        analysis = analyze_pod(pod, metrics)
        if analysis:
            analyses.append(analysis)

    if not analyses:
        if args.format == 'json':
            print(json.dumps({'summary': {'total': 0}, 'categories': {}}))
        else:
            print("No running pods found")
        sys.exit(0)

    # Categorize findings
    categories = categorize_findings(
        analyses,
        cpu_threshold=args.cpu_threshold,
        mem_threshold=args.mem_threshold
    )

    # Output results
    if args.format == 'json':
        output_json(categories, analyses)
    elif args.format == 'table':
        output_table(categories, analyses, args.warn_only)
    else:
        output_plain(categories, analyses, args.verbose, args.warn_only)

    # Exit code based on findings
    has_issues = (len(categories['over_provisioned']) > 0 or
                  len(categories['under_provisioned']) > 0 or
                  len(categories['no_requests']) > 0)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
