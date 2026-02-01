#!/usr/bin/env python3
"""
Kubernetes Revision History Analyzer - Identify excessive ReplicaSet revisions.

Deployments accumulate old ReplicaSets over time which can cause:
- etcd storage bloat (each revision stores full pod spec)
- Slower API server responses (more objects to list/watch)
- Larger cluster backups
- Slower kubectl commands

This script identifies:
- Deployments with excessive revision history
- Total ReplicaSets that could be cleaned up
- Estimated etcd storage impact
- Per-namespace revision statistics

Exit codes:
    0 - No issues detected, revision counts within thresholds
    1 - Issues found (excessive revisions detected)
    2 - Usage error or kubectl not available
"""

import argparse
import subprocess
import json
import sys


def run_kubectl(args):
    """Execute kubectl command and return JSON output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print("Error: kubectl command timed out", file=sys.stderr)
        return None


def get_namespaces(namespace=None):
    """Get list of namespaces to check."""
    if namespace:
        return [namespace]

    output = run_kubectl(['get', 'namespaces', '-o', 'json'])
    if not output:
        return []
    data = json.loads(output)
    return [ns['metadata']['name'] for ns in data.get('items', [])]


def get_deployments(namespace):
    """Get all deployments in a namespace."""
    output = run_kubectl(['get', 'deployments', '-n', namespace, '-o', 'json'])
    if not output:
        return []
    data = json.loads(output)
    return data.get('items', [])


def get_replicasets(namespace):
    """Get all ReplicaSets in a namespace."""
    output = run_kubectl(['get', 'replicasets', '-n', namespace, '-o', 'json'])
    if not output:
        return []
    data = json.loads(output)
    return data.get('items', [])


def analyze_deployment_revisions(namespace, deployments, replicasets, threshold):
    """Analyze revision history for deployments in a namespace."""
    issues = []
    stats = {
        'total_deployments': len(deployments),
        'total_replicasets': len(replicasets),
        'excessive_revisions': 0,
        'cleanable_replicasets': 0,
        'deployments': []
    }

    # Build mapping of deployment -> replicasets
    deployment_rs_map = {}
    for rs in replicasets:
        owner_refs = rs.get('metadata', {}).get('ownerReferences', [])
        for owner in owner_refs:
            if owner.get('kind') == 'Deployment':
                deploy_name = owner.get('name')
                if deploy_name not in deployment_rs_map:
                    deployment_rs_map[deploy_name] = []
                deployment_rs_map[deploy_name].append(rs)

    for deploy in deployments:
        deploy_name = deploy['metadata']['name']
        revision_limit = deploy.get('spec', {}).get('revisionHistoryLimit', 10)
        associated_rs = deployment_rs_map.get(deploy_name, [])
        rs_count = len(associated_rs)

        # Count old (scaled to 0) replicasets
        old_rs_count = sum(
            1 for rs in associated_rs
            if rs.get('spec', {}).get('replicas', 0) == 0
        )

        deploy_info = {
            'name': deploy_name,
            'replicaset_count': rs_count,
            'old_replicasets': old_rs_count,
            'revision_history_limit': revision_limit,
            'has_issue': rs_count > threshold
        }

        if rs_count > threshold:
            stats['excessive_revisions'] += 1
            cleanable = rs_count - min(revision_limit, threshold)
            if cleanable > 0:
                stats['cleanable_replicasets'] += cleanable
                deploy_info['cleanable'] = cleanable

            issues.append({
                'deployment': deploy_name,
                'replicaset_count': rs_count,
                'old_replicasets': old_rs_count,
                'threshold': threshold,
                'revision_history_limit': revision_limit,
                'severity': 'warning' if rs_count > threshold * 2 else 'info'
            })

        stats['deployments'].append(deploy_info)

    return stats, issues


def estimate_etcd_impact(cleanable_count):
    """Estimate etcd storage impact of cleanable ReplicaSets."""
    # Average ReplicaSet object is ~2-5KB in etcd
    avg_rs_size_kb = 3
    total_kb = cleanable_count * avg_rs_size_kb
    if total_kb > 1024:
        return f"{total_kb / 1024:.1f} MB"
    return f"{total_kb} KB"


def output_plain(results, warn_only, verbose):
    """Output results in plain text format."""
    print("Kubernetes Revision History Analysis")
    print("=" * 70)

    total_deployments = 0
    total_replicasets = 0
    total_issues = 0
    total_cleanable = 0

    for ns_result in results:
        ns = ns_result['namespace']
        stats = ns_result['stats']
        issues = ns_result['issues']

        total_deployments += stats['total_deployments']
        total_replicasets += stats['total_replicasets']
        total_issues += len(issues)
        total_cleanable += stats['cleanable_replicasets']

        if warn_only and not issues:
            continue

        print(f"\nNamespace: {ns}")
        print(f"  Deployments: {stats['total_deployments']}")
        print(f"  ReplicaSets: {stats['total_replicasets']}")

        if issues:
            print(f"  Excessive Revisions: {stats['excessive_revisions']}")
            print(f"  Cleanable ReplicaSets: {stats['cleanable_replicasets']}")
            print("  Issues:")
            for issue in issues:
                severity = "!" if issue['severity'] == 'warning' else "-"
                print(f"    [{severity}] {issue['deployment']}: "
                      f"{issue['replicaset_count']} ReplicaSets "
                      f"(limit: {issue['revision_history_limit']}, "
                      f"threshold: {issue['threshold']})")

        if verbose and stats['deployments']:
            print("  Deployment Details:")
            for dep in sorted(stats['deployments'],
                              key=lambda x: x['replicaset_count'],
                              reverse=True):
                marker = "*" if dep['has_issue'] else " "
                print(f"    {marker} {dep['name']}: "
                      f"{dep['replicaset_count']} RS "
                      f"({dep['old_replicasets']} old)")

    print("\n" + "=" * 70)
    print("Summary:")
    print(f"  Total Deployments: {total_deployments}")
    print(f"  Total ReplicaSets: {total_replicasets}")
    print(f"  Deployments with excessive history: {total_issues}")
    print(f"  Cleanable ReplicaSets: {total_cleanable}")
    if total_cleanable > 0:
        print(f"  Estimated etcd savings: ~{estimate_etcd_impact(total_cleanable)}")
        print("\nRecommendation: Consider reducing revisionHistoryLimit in deployments")
        print("or running: kubectl rollout history deployment/<name> -n <namespace>")


def output_json(results):
    """Output results in JSON format."""
    summary = {
        'total_deployments': sum(r['stats']['total_deployments'] for r in results),
        'total_replicasets': sum(r['stats']['total_replicasets'] for r in results),
        'excessive_revision_count': sum(r['stats']['excessive_revisions'] for r in results),
        'cleanable_replicasets': sum(r['stats']['cleanable_replicasets'] for r in results),
    }
    summary['estimated_etcd_savings'] = estimate_etcd_impact(summary['cleanable_replicasets'])

    output = {
        'summary': summary,
        'namespaces': results
    }
    print(json.dumps(output, indent=2))


def output_table(results, warn_only):
    """Output results in table format."""
    print(f"{'Namespace':<25} {'Deploys':<8} {'RS Total':<10} "
          f"{'Excessive':<10} {'Cleanable':<10}")
    print("-" * 75)

    for ns_result in results:
        ns = ns_result['namespace']
        stats = ns_result['stats']
        issues = ns_result['issues']

        if warn_only and not issues:
            continue

        print(f"{ns:<25} {stats['total_deployments']:<8} "
              f"{stats['total_replicasets']:<10} "
              f"{stats['excessive_revisions']:<10} "
              f"{stats['cleanable_replicasets']:<10}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes Deployment revision history for cleanup opportunities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all namespaces
  %(prog)s -n production            # Check specific namespace
  %(prog)s --threshold 5            # Warn if >5 ReplicaSets per deployment
  %(prog)s --format json            # JSON output for automation
  %(prog)s -w                       # Only show deployments with issues
"""
    )

    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to check (default: all namespaces)"
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show namespaces with issues"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed per-deployment information"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="ReplicaSet count threshold to flag as excessive (default: %(default)s)"
    )

    args = parser.parse_args()

    try:
        namespaces = get_namespaces(args.namespace)
        if not namespaces:
            print("Error: No namespaces found or kubectl failed", file=sys.stderr)
            sys.exit(1)

        results = []
        for ns in namespaces:
            # Skip system namespaces unless explicitly requested
            if not args.namespace and ns in ['kube-system', 'kube-public', 'kube-node-lease']:
                continue

            deployments = get_deployments(ns)
            replicasets = get_replicasets(ns)

            stats, issues = analyze_deployment_revisions(
                ns, deployments, replicasets, args.threshold
            )

            results.append({
                'namespace': ns,
                'stats': stats,
                'issues': issues
            })

        # Output results
        if args.format == "json":
            output_json(results)
        elif args.format == "table":
            output_table(results, args.warn_only)
        else:
            output_plain(results, args.warn_only, args.verbose)

        # Exit code based on findings
        has_issues = any(r['issues'] for r in results)
        sys.exit(1 if has_issues else 0)

    except json.JSONDecodeError as e:
        print(f"Error parsing kubectl output: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
