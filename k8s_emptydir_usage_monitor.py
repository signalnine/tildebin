#!/usr/bin/env python3
"""
Monitor Kubernetes emptyDir volume usage and identify pods at risk.

EmptyDir volumes are ephemeral storage backed by node disk or memory.
When pods use emptyDir without size limits, they can:
- Fill up node disk space causing node failures
- Exhaust node memory (when medium=Memory)
- Cause unexpected pod evictions

This script identifies:
- Pods using emptyDir volumes without sizeLimit
- Pods with large emptyDir allocations relative to node capacity
- Memory-backed emptyDir volumes (tmpfs)
- Namespaces with high aggregate emptyDir usage

Exit codes:
    0 - No issues detected
    1 - Issues found (unbounded emptyDir, high usage)
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


def parse_size_value(value):
    """
    Parse Kubernetes size value to bytes.

    Supports: Ki, Mi, Gi, Ti, K, M, G, T suffixes and plain bytes.
    Returns bytes as integer.
    """
    if not value:
        return 0

    value = str(value).strip()

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
    try:
        return int(value)
    except ValueError:
        return 0


def format_size(bytes_val):
    """Format bytes for human-readable display."""
    if bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.2f}Gi"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.2f}Mi"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.2f}Ki"
    else:
        return f"{bytes_val}B"


def get_all_pods(namespace=None):
    """Get all pods in JSON format."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def analyze_pod_emptydirs(pod):
    """
    Analyze a pod's emptyDir volumes.

    Returns dict with volume analysis and list of issues.
    """
    metadata = pod.get('metadata', {})
    spec = pod.get('spec', {})
    status = pod.get('status', {})

    pod_name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    phase = status.get('phase', 'Unknown')

    volumes = spec.get('volumes', [])
    containers = spec.get('containers', [])

    emptydir_volumes = []
    issues = []

    # Find all emptyDir volumes
    for volume in volumes:
        if 'emptyDir' not in volume:
            continue

        vol_name = volume.get('name', 'unknown')
        emptydir_spec = volume.get('emptyDir', {})

        medium = emptydir_spec.get('medium', '')
        size_limit = emptydir_spec.get('sizeLimit')

        vol_info = {
            'name': vol_name,
            'medium': medium if medium else 'disk',
            'size_limit': size_limit,
            'size_limit_bytes': parse_size_value(size_limit) if size_limit else 0,
            'mounted_in': [],
        }

        # Check which containers mount this volume
        for container in containers:
            container_name = container.get('name', 'unknown')
            volume_mounts = container.get('volumeMounts', [])

            for mount in volume_mounts:
                if mount.get('name') == vol_name:
                    vol_info['mounted_in'].append({
                        'container': container_name,
                        'mount_path': mount.get('mountPath', ''),
                        'read_only': mount.get('readOnly', False),
                    })

        emptydir_volumes.append(vol_info)

        # Check for issues
        if not size_limit:
            severity = 'HIGH' if medium == 'Memory' else 'MEDIUM'
            medium_desc = 'memory-backed (tmpfs)' if medium == 'Memory' else 'disk-backed'
            issues.append({
                'type': 'no_size_limit',
                'severity': severity,
                'volume': vol_name,
                'message': f"emptyDir '{vol_name}' ({medium_desc}) has no sizeLimit - "
                           f"can consume unlimited {'RAM' if medium == 'Memory' else 'disk'}",
            })

        if medium == 'Memory':
            issues.append({
                'type': 'memory_backed',
                'severity': 'INFO',
                'volume': vol_name,
                'message': f"emptyDir '{vol_name}' uses Memory medium (tmpfs) - "
                           f"counts against container memory limit",
            })

    return {
        'namespace': namespace,
        'pod': pod_name,
        'phase': phase,
        'emptydir_volumes': emptydir_volumes,
        'issues': issues,
        'total_size_limit_bytes': sum(v['size_limit_bytes'] for v in emptydir_volumes),
        'unbounded_count': sum(1 for v in emptydir_volumes if not v['size_limit']),
        'memory_backed_count': sum(1 for v in emptydir_volumes if v['medium'] == 'Memory'),
    }


def analyze_cluster(pods_data, namespace_filter, include_system):
    """
    Analyze all pods and aggregate by namespace.

    Returns tuple of (pod_results, namespace_summary, cluster_summary).
    """
    pods = pods_data.get('items', [])
    pod_results = []
    namespace_stats = defaultdict(lambda: {
        'pod_count': 0,
        'emptydir_count': 0,
        'unbounded_count': 0,
        'memory_backed_count': 0,
        'total_size_limit_bytes': 0,
        'issues': [],
    })

    system_namespaces = {'kube-system', 'kube-public', 'kube-node-lease'}

    for pod in pods:
        namespace = pod.get('metadata', {}).get('namespace', 'default')
        phase = pod.get('status', {}).get('phase', '')

        # Skip completed/failed pods
        if phase in ['Succeeded', 'Failed']:
            continue

        # Skip system namespaces if not included
        if not include_system and namespace in system_namespaces:
            continue

        # Apply namespace filter
        if namespace_filter and namespace != namespace_filter:
            continue

        analysis = analyze_pod_emptydirs(pod)

        # Only include pods with emptyDir volumes
        if analysis['emptydir_volumes']:
            pod_results.append(analysis)

            # Update namespace stats
            ns = namespace_stats[namespace]
            ns['pod_count'] += 1
            ns['emptydir_count'] += len(analysis['emptydir_volumes'])
            ns['unbounded_count'] += analysis['unbounded_count']
            ns['memory_backed_count'] += analysis['memory_backed_count']
            ns['total_size_limit_bytes'] += analysis['total_size_limit_bytes']
            ns['issues'].extend(analysis['issues'])

    # Calculate cluster totals
    cluster_summary = {
        'total_pods_with_emptydir': len(pod_results),
        'total_emptydir_volumes': sum(len(p['emptydir_volumes']) for p in pod_results),
        'total_unbounded': sum(p['unbounded_count'] for p in pod_results),
        'total_memory_backed': sum(p['memory_backed_count'] for p in pod_results),
        'total_size_limit_bytes': sum(p['total_size_limit_bytes'] for p in pod_results),
        'namespaces_affected': len(namespace_stats),
    }

    return pod_results, dict(namespace_stats), cluster_summary


def output_plain(pod_results, namespace_stats, cluster_summary, warn_only, verbose):
    """Output results in plain text format."""
    lines = []

    lines.append("Kubernetes EmptyDir Volume Usage Monitor")
    lines.append("=" * 50)
    lines.append("")

    # Cluster summary
    lines.append("Cluster Summary:")
    lines.append(f"  Pods with emptyDir: {cluster_summary['total_pods_with_emptydir']}")
    lines.append(f"  Total emptyDir volumes: {cluster_summary['total_emptydir_volumes']}")
    lines.append(f"  Unbounded (no sizeLimit): {cluster_summary['total_unbounded']}")
    lines.append(f"  Memory-backed (tmpfs): {cluster_summary['total_memory_backed']}")
    if cluster_summary['total_size_limit_bytes'] > 0:
        lines.append(f"  Total allocated size: {format_size(cluster_summary['total_size_limit_bytes'])}")
    lines.append("")

    # Filter for issues if warn_only
    if warn_only:
        pod_results = [p for p in pod_results if p['issues']]

    if not pod_results:
        if warn_only:
            lines.append("No issues detected.")
        else:
            lines.append("No pods with emptyDir volumes found.")
        return '\n'.join(lines)

    # Per-namespace summary
    if namespace_stats and not warn_only:
        lines.append("By Namespace:")
        lines.append("-" * 40)

        for ns, stats in sorted(namespace_stats.items()):
            unbounded_marker = " [!]" if stats['unbounded_count'] > 0 else ""
            lines.append(f"  {ns}: {stats['emptydir_count']} volumes, "
                         f"{stats['unbounded_count']} unbounded{unbounded_marker}")
        lines.append("")

    # Per-pod details
    lines.append("Pod Details:")
    lines.append("-" * 40)

    for pod in pod_results:
        status_marker = "[!]" if pod['issues'] else "[OK]"
        lines.append(f"\n{status_marker} {pod['namespace']}/{pod['pod']} ({pod['phase']})")

        for vol in pod['emptydir_volumes']:
            limit_str = format_size(vol['size_limit_bytes']) if vol['size_limit'] else "UNBOUNDED"
            medium_str = f" ({vol['medium']})" if vol['medium'] != 'disk' else ""
            lines.append(f"    Volume: {vol['name']} - {limit_str}{medium_str}")

            if verbose:
                for mount in vol['mounted_in']:
                    ro_str = " [RO]" if mount['read_only'] else ""
                    lines.append(f"      -> {mount['container']}:{mount['mount_path']}{ro_str}")

        if pod['issues']:
            for issue in pod['issues']:
                if issue['severity'] != 'INFO' or verbose:
                    lines.append(f"    [{issue['severity']}] {issue['message']}")

    lines.append("")

    # Summary of issues
    total_issues = sum(len(p['issues']) for p in pod_results)
    high_severity = sum(1 for p in pod_results for i in p['issues'] if i['severity'] == 'HIGH')
    medium_severity = sum(1 for p in pod_results for i in p['issues'] if i['severity'] == 'MEDIUM')

    if total_issues > 0:
        lines.append("Issue Summary:")
        lines.append(f"  HIGH severity: {high_severity}")
        lines.append(f"  MEDIUM severity: {medium_severity}")
        lines.append("")
        lines.append("Recommendation: Set sizeLimit on emptyDir volumes to prevent")
        lines.append("unbounded disk/memory consumption and unexpected evictions.")

    return '\n'.join(lines)


def output_table(pod_results, namespace_stats, cluster_summary):
    """Output results in table format."""
    lines = []

    # Header
    lines.append(f"{'Namespace':<20} {'Pod':<30} {'Volume':<15} {'Medium':<8} {'Limit':<12} {'Issues':<8}")
    lines.append("-" * 95)

    for pod in pod_results:
        for i, vol in enumerate(pod['emptydir_volumes']):
            ns = pod['namespace'] if i == 0 else ""
            pod_name = pod['pod'][:30] if i == 0 else ""
            limit_str = format_size(vol['size_limit_bytes']) if vol['size_limit'] else "NONE"
            issue_marker = "YES" if any(iss['volume'] == vol['name'] for iss in pod['issues']) else ""

            lines.append(f"{ns:<20} {pod_name:<30} {vol['name']:<15} {vol['medium']:<8} "
                         f"{limit_str:<12} {issue_marker:<8}")

    # Totals
    lines.append("-" * 95)
    lines.append(f"{'TOTAL':<20} {cluster_summary['total_pods_with_emptydir']:<30} "
                 f"{cluster_summary['total_emptydir_volumes']:<15} "
                 f"{'':<8} {format_size(cluster_summary['total_size_limit_bytes']):<12} "
                 f"{cluster_summary['total_unbounded']:<8}")

    return '\n'.join(lines)


def output_json(pod_results, namespace_stats, cluster_summary):
    """Output results in JSON format."""
    result = {
        'cluster_summary': cluster_summary,
        'namespace_summary': namespace_stats,
        'pods': pod_results,
    }

    return json.dumps(result, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes emptyDir volume usage and identify risks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all namespaces
  %(prog)s -n production            # Check specific namespace
  %(prog)s --warn-only              # Only show pods with issues
  %(prog)s --format json            # JSON output for automation
  %(prog)s -v                       # Verbose output with mount details
  %(prog)s --include-system         # Include kube-system namespace

Risks addressed:
  - Unbounded emptyDir can fill node disk, causing node failure
  - Memory-backed emptyDir (tmpfs) consumes node RAM
  - No sizeLimit means pod can consume unlimited storage

Exit codes:
  0 - No issues detected
  1 - Issues found (unbounded volumes, etc.)
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to check (default: all namespaces)'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed mount information'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show pods with issues'
    )

    parser.add_argument(
        '--include-system',
        action='store_true',
        help='Include system namespaces (kube-system, etc.)'
    )

    args = parser.parse_args()

    # Get pod data
    pods_data = get_all_pods(args.namespace)

    # Analyze cluster
    pod_results, namespace_stats, cluster_summary = analyze_cluster(
        pods_data,
        args.namespace,
        args.include_system
    )

    # Check for issues
    has_issues = cluster_summary['total_unbounded'] > 0

    # Handle warn-only with no issues
    if args.warn_only and not has_issues:
        if args.format == 'json':
            print(json.dumps({'cluster_summary': cluster_summary, 'pods': [], 'issues': False}))
        sys.exit(0)

    # Output
    if args.format == 'json':
        output = output_json(pod_results, namespace_stats, cluster_summary)
    elif args.format == 'table':
        output = output_table(pod_results, namespace_stats, cluster_summary)
    else:
        output = output_plain(pod_results, namespace_stats, cluster_summary,
                              args.warn_only, args.verbose)

    print(output)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
