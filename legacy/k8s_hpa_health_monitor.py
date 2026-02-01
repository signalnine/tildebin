#!/usr/bin/env python3
"""
Monitor HorizontalPodAutoscaler (HPA) health and effectiveness.

This script analyzes HorizontalPodAutoscalers in a Kubernetes cluster to identify:
- HPA scaling issues (unable to compute metrics, at limits, flapping)
- Metrics server availability and health
- HPA misconfiguration (invalid targets, missing metrics)
- Scaling patterns and effectiveness
- HPAs at min/max replica limits with unmet targets

Useful for:
- Ensuring autoscaling reliability in production
- Detecting metrics server failures
- Identifying HPA configuration issues
- Preventing service degradation from scaling problems
- Capacity planning based on HPA behavior

Exit codes:
    0 - All HPAs healthy and functioning correctly
    1 - HPA issues detected (scaling problems, metrics unavailable, misconfigurations)
    2 - kubectl not found or usage error
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def run_kubectl(args):
    """Execute kubectl command and return output."""
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
        print(f"Error: kubectl command failed: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def check_metrics_server():
    """Check if metrics server is available and healthy."""
    try:
        # Check if metrics-server is deployed
        output = run_kubectl(['get', 'deployment', '-n', 'kube-system', 'metrics-server', '-o', 'json'])
        deployment = json.loads(output)

        available = deployment.get('status', {}).get('availableReplicas', 0)
        desired = deployment.get('spec', {}).get('replicas', 1)

        # Try to query metrics API
        try:
            run_kubectl(['top', 'nodes', '--no-headers'])
            metrics_api_working = True
        except:
            metrics_api_working = False

        return {
            'deployed': True,
            'available_replicas': available,
            'desired_replicas': desired,
            'healthy': available >= desired and metrics_api_working,
            'metrics_api_working': metrics_api_working
        }
    except:
        return {
            'deployed': False,
            'healthy': False,
            'metrics_api_working': False
        }


def get_hpas(namespace=None):
    """Get all HPAs in the cluster or specific namespace."""
    cmd = ['get', 'hpa', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output).get('items', [])


def get_recent_events(namespace, hpa_name, minutes=10):
    """Get recent events related to an HPA."""
    cmd = [
        'get', 'events',
        '-n', namespace,
        '--field-selector', f'involvedObject.name={hpa_name},involvedObject.kind=HorizontalPodAutoscaler',
        '-o', 'json'
    ]

    try:
        output = run_kubectl(cmd)
        events = json.loads(output).get('items', [])
        return events[-10:]  # Last 10 events
    except:
        return []


def analyze_hpa(hpa):
    """Analyze a single HPA for health and configuration issues."""
    metadata = hpa.get('metadata', {})
    spec = hpa.get('spec', {})
    status = hpa.get('status', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')

    issues = []
    warnings = []

    # Get replica information
    current_replicas = status.get('currentReplicas', 0)
    desired_replicas = status.get('desiredReplicas', 0)
    min_replicas = spec.get('minReplicas', 1)
    max_replicas = spec.get('maxReplicas', 10)

    # Check for metrics availability
    current_metrics = status.get('currentMetrics', [])
    conditions = status.get('conditions', [])

    # Analyze conditions
    for condition in conditions:
        condition_type = condition.get('type', '')
        condition_status = condition.get('status', '')
        reason = condition.get('reason', '')
        message = condition.get('message', '')

        if condition_type == 'ScalingActive' and condition_status != 'True':
            issues.append(f"Scaling inactive: {reason} - {message}")

        if condition_type == 'AbleToScale' and condition_status != 'True':
            issues.append(f"Unable to scale: {reason} - {message}")

        if condition_type == 'ScalingLimited' and condition_status == 'True':
            if 'minimum' in message.lower():
                warnings.append(f"At minimum replica limit ({min_replicas})")
            elif 'maximum' in message.lower():
                warnings.append(f"At maximum replica limit ({max_replicas})")

    # Check if metrics are available
    if not current_metrics:
        issues.append("No current metrics available")

    # Check for metric computation issues
    for metric in current_metrics:
        metric_type = metric.get('type', '')
        if metric_type == 'Resource':
            resource = metric.get('resource', {})
            current = resource.get('current', {})
            if 'averageUtilization' not in current and 'averageValue' not in current:
                issues.append(f"Resource metric '{resource.get('name')}' has no current value")
        elif metric_type == 'Pods':
            pods = metric.get('pods', {})
            current = pods.get('current', {})
            if 'averageValue' not in current:
                issues.append(f"Pods metric has no current value")
        elif metric_type == 'External':
            external = metric.get('external', {})
            current = external.get('current', {})
            if 'value' not in current and 'averageValue' not in current:
                issues.append(f"External metric has no current value")

    # Check for flapping (current != desired)
    if current_replicas != desired_replicas:
        warnings.append(f"Scaling in progress: {current_replicas} -> {desired_replicas} replicas")

    # Check if at limits with unmet targets
    if current_replicas == max_replicas:
        # Check if we should scale further but can't
        for condition in conditions:
            if condition.get('type') == 'ScalingLimited' and 'maximum' in condition.get('message', '').lower():
                issues.append(f"At max replicas ({max_replicas}) but may need more capacity")

    # Check target reference exists
    scale_target_ref = spec.get('scaleTargetRef', {})
    target_kind = scale_target_ref.get('kind', '')
    target_name = scale_target_ref.get('name', '')

    if not target_name:
        issues.append("No scale target reference configured")

    # Analyze metrics specification
    metrics_spec = spec.get('metrics', [])
    if not metrics_spec:
        issues.append("No metrics configured")

    # Check for reasonable min/max spread
    if max_replicas - min_replicas < 2:
        warnings.append(f"Small scaling range ({min_replicas}-{max_replicas})")

    return {
        'name': name,
        'namespace': namespace,
        'target': f"{target_kind}/{target_name}",
        'current_replicas': current_replicas,
        'desired_replicas': desired_replicas,
        'min_replicas': min_replicas,
        'max_replicas': max_replicas,
        'issues': issues,
        'warnings': warnings,
        'healthy': len(issues) == 0,
        'metrics_count': len(current_metrics),
        'conditions': conditions
    }


def output_plain(results, metrics_server, warn_only=False):
    """Output results in plain text format."""
    print("=== Metrics Server Status ===")
    if metrics_server['deployed']:
        status = "HEALTHY" if metrics_server['healthy'] else "UNHEALTHY"
        print(f"Status: {status}")
        print(f"Replicas: {metrics_server['available_replicas']}/{metrics_server['desired_replicas']}")
        print(f"Metrics API: {'Working' if metrics_server['metrics_api_working'] else 'FAILED'}")
    else:
        print("Status: NOT DEPLOYED")

    print("\n=== HPA Health Summary ===")

    total = len(results)
    healthy = sum(1 for r in results if r['healthy'])
    unhealthy = total - healthy

    print(f"Total HPAs: {total}")
    print(f"Healthy: {healthy}")
    print(f"Unhealthy: {unhealthy}")

    if not results:
        print("\nNo HPAs found in cluster")
        return

    print("\n=== HPA Details ===")

    for result in results:
        if warn_only and result['healthy']:
            continue

        status_icon = "✓" if result['healthy'] else "✗"
        print(f"\n{status_icon} {result['namespace']}/{result['name']}")
        print(f"  Target: {result['target']}")
        print(f"  Replicas: {result['current_replicas']} (desired: {result['desired_replicas']}, min: {result['min_replicas']}, max: {result['max_replicas']})")
        print(f"  Metrics: {result['metrics_count']} active")

        if result['issues']:
            print("  Issues:")
            for issue in result['issues']:
                print(f"    - {issue}")

        if result['warnings']:
            print("  Warnings:")
            for warning in result['warnings']:
                print(f"    - {warning}")


def output_json(results, metrics_server):
    """Output results in JSON format."""
    output = {
        'metrics_server': metrics_server,
        'summary': {
            'total_hpas': len(results),
            'healthy': sum(1 for r in results if r['healthy']),
            'unhealthy': sum(1 for r in results if not r['healthy'])
        },
        'hpas': results
    }
    print(json.dumps(output, indent=2))


def output_table(results, metrics_server, warn_only=False):
    """Output results in table format."""
    print("Metrics Server Status:")
    print(f"  {'Status:':<20} {'HEALTHY' if metrics_server.get('healthy') else 'UNHEALTHY'}")
    print(f"  {'Deployed:':<20} {'Yes' if metrics_server.get('deployed') else 'No'}")
    print(f"  {'Metrics API:':<20} {'Working' if metrics_server.get('metrics_api_working') else 'FAILED'}")
    print()

    if not results:
        print("No HPAs found in cluster")
        return

    # Filter if warn-only
    display_results = [r for r in results if not warn_only or not r['healthy']]

    if not display_results:
        print("No issues found")
        return

    # Print header
    print(f"{'NAMESPACE':<20} {'NAME':<30} {'STATUS':<10} {'REPLICAS':<12} {'ISSUES':<10}")
    print("-" * 82)

    # Print rows
    for result in display_results:
        status = "OK" if result['healthy'] else "ISSUES"
        replicas = f"{result['current_replicas']}/{result['desired_replicas']}"
        issue_count = len(result['issues']) + len(result['warnings'])

        print(f"{result['namespace']:<20} {result['name']:<30} {status:<10} {replicas:<12} {issue_count:<10}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor HorizontalPodAutoscaler health and effectiveness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all HPAs in the cluster
  %(prog)s

  # Check HPAs in specific namespace
  %(prog)s -n production

  # Show only HPAs with issues
  %(prog)s --warn-only

  # Output as JSON for monitoring tools
  %(prog)s --format json

  # Output as table
  %(prog)s --format table
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to check (default: all namespaces)'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show HPAs with issues or warnings'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including conditions'
    )

    args = parser.parse_args()

    # Check metrics server
    metrics_server = check_metrics_server()

    # Get and analyze HPAs
    hpas = get_hpas(args.namespace)

    if not hpas and args.format != 'json':
        print("No HPAs found in cluster", file=sys.stderr)

    results = []
    for hpa in hpas:
        result = analyze_hpa(hpa)
        results.append(result)

    # Output results
    if args.format == 'json':
        output_json(results, metrics_server)
    elif args.format == 'table':
        output_table(results, metrics_server, args.warn_only)
    else:  # plain
        output_plain(results, metrics_server, args.warn_only)

    # Determine exit code
    has_issues = any(not r['healthy'] for r in results)
    metrics_server_unhealthy = not metrics_server['healthy']

    if has_issues or metrics_server_unhealthy:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
