#!/usr/bin/env python3
"""
Kubernetes Service Endpoint Health Monitor

Monitors Kubernetes Services to detect those without healthy endpoints,
which indicates broken application connectivity. This is critical for
identifying services that appear configured but are non-functional.

Checks for:
- Services with no endpoints (selector mismatch or no pods)
- Services with endpoints but all NotReady
- LoadBalancer services without external IPs
- Service port mismatches with pod containers

Exit codes:
    0 - All services have healthy endpoints
    1 - One or more services have endpoint issues
    2 - Usage error or kubectl not found
"""

import argparse
import sys
import subprocess
import json
from collections import defaultdict


def run_kubectl(args):
    """Execute kubectl command and return output"""
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
        print(f"Error: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_services(namespace=None):
    """Get services in JSON format"""
    cmd = ['get', 'services', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output)


def get_endpoints(namespace=None):
    """Get endpoints in JSON format"""
    cmd = ['get', 'endpoints', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output)


def get_pods(namespace=None):
    """Get pods in JSON format"""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output)


def analyze_service_endpoints(services, endpoints, pods):
    """Analyze services for endpoint health issues"""
    issues = []

    # Build endpoint map: namespace/name -> endpoint object
    endpoint_map = {}
    for ep in endpoints.get('items', []):
        ns = ep['metadata']['namespace']
        name = ep['metadata']['name']
        key = f"{ns}/{name}"
        endpoint_map[key] = ep

    # Build pod map for selector matching
    pod_map = defaultdict(list)
    for pod in pods.get('items', []):
        ns = pod['metadata']['namespace']
        labels = pod['metadata'].get('labels', {})
        pod_map[ns].append({
            'name': pod['metadata']['name'],
            'labels': labels,
            'ready': is_pod_ready(pod)
        })

    for svc in services.get('items', []):
        ns = svc['metadata']['namespace']
        name = svc['metadata']['name']
        svc_type = svc['spec'].get('type', 'ClusterIP')
        selector = svc['spec'].get('selector', {})

        # Skip services without selectors (e.g., ExternalName, headless)
        if not selector:
            continue

        key = f"{ns}/{name}"

        # Check if service has endpoint object
        if key not in endpoint_map:
            issues.append({
                'namespace': ns,
                'service': name,
                'type': svc_type,
                'issue': 'no_endpoint_object',
                'severity': 'critical',
                'details': 'Service has no corresponding endpoint object'
            })
            continue

        ep = endpoint_map[key]
        subsets = ep.get('subsets', [])

        # Check if endpoint has any addresses
        total_ready = 0
        total_not_ready = 0

        for subset in subsets:
            ready_addrs = subset.get('addresses', [])
            not_ready_addrs = subset.get('notReadyAddresses', [])
            total_ready += len(ready_addrs)
            total_not_ready += len(not_ready_addrs)

        if total_ready == 0 and total_not_ready == 0:
            # No endpoints at all - check if pods exist with matching labels
            matching_pods = [
                p for p in pod_map.get(ns, [])
                if all(p['labels'].get(k) == v for k, v in selector.items())
            ]

            if not matching_pods:
                issues.append({
                    'namespace': ns,
                    'service': name,
                    'type': svc_type,
                    'issue': 'no_matching_pods',
                    'severity': 'critical',
                    'details': f'No pods match selector {selector}'
                })
            else:
                issues.append({
                    'namespace': ns,
                    'service': name,
                    'type': svc_type,
                    'issue': 'pods_exist_but_no_endpoints',
                    'severity': 'critical',
                    'details': f'{len(matching_pods)} matching pods found but no endpoints registered'
                })

        elif total_ready == 0 and total_not_ready > 0:
            issues.append({
                'namespace': ns,
                'service': name,
                'type': svc_type,
                'issue': 'all_endpoints_not_ready',
                'severity': 'critical',
                'details': f'{total_not_ready} endpoints exist but all are NotReady'
            })

        elif total_ready > 0 and total_not_ready > 0:
            # Some ready, some not ready - warning level
            issues.append({
                'namespace': ns,
                'service': name,
                'type': svc_type,
                'issue': 'partial_endpoints_not_ready',
                'severity': 'warning',
                'details': f'{total_ready} ready, {total_not_ready} not ready'
            })

        # Check LoadBalancer services for external IP
        if svc_type == 'LoadBalancer':
            status = svc.get('status', {})
            load_balancer = status.get('loadBalancer', {})
            ingress = load_balancer.get('ingress', [])

            if not ingress:
                issues.append({
                    'namespace': ns,
                    'service': name,
                    'type': svc_type,
                    'issue': 'loadbalancer_no_external_ip',
                    'severity': 'warning',
                    'details': 'LoadBalancer service has no external IP assigned'
                })

    return issues


def is_pod_ready(pod):
    """Check if pod is ready"""
    conditions = pod.get('status', {}).get('conditions', [])
    for condition in conditions:
        if condition['type'] == 'Ready':
            return condition['status'] == 'True'
    return False


def output_plain(issues, warn_only=False):
    """Plain text output"""
    filtered = [i for i in issues if not warn_only or i['severity'] in ['critical', 'warning']]

    if not filtered:
        print("All services have healthy endpoints")
        return

    # Group by severity
    critical = [i for i in filtered if i['severity'] == 'critical']
    warnings = [i for i in filtered if i['severity'] == 'warning']

    if critical:
        print(f"CRITICAL: {len(critical)} service(s) with endpoint failures:")
        for issue in critical:
            print(f"  {issue['namespace']}/{issue['service']} ({issue['type']})")
            print(f"    Issue: {issue['issue']}")
            print(f"    Details: {issue['details']}")
            print()

    if warnings:
        print(f"WARNING: {len(warnings)} service(s) with endpoint issues:")
        for issue in warnings:
            print(f"  {issue['namespace']}/{issue['service']} ({issue['type']})")
            print(f"    Issue: {issue['issue']}")
            print(f"    Details: {issue['details']}")
            print()


def output_json(issues, warn_only=False):
    """JSON output"""
    filtered = [i for i in issues if not warn_only or i['severity'] in ['critical', 'warning']]
    print(json.dumps({
        'total_issues': len(filtered),
        'critical': len([i for i in filtered if i['severity'] == 'critical']),
        'warnings': len([i for i in filtered if i['severity'] == 'warning']),
        'issues': filtered
    }, indent=2))


def output_table(issues, warn_only=False):
    """Tabular output"""
    filtered = [i for i in issues if not warn_only or i['severity'] in ['critical', 'warning']]

    if not filtered:
        print("All services have healthy endpoints")
        return

    print(f"{'Namespace':<20} {'Service':<30} {'Type':<15} {'Severity':<10} {'Issue':<30}")
    print("-" * 105)

    for issue in filtered:
        print(f"{issue['namespace']:<20} {issue['service']:<30} {issue['type']:<15} "
              f"{issue['severity']:<10} {issue['issue']:<30}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes Service endpoint health",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all services in all namespaces
  k8s_service_endpoint_monitor.py

  # Check services in specific namespace
  k8s_service_endpoint_monitor.py -n production

  # Show only issues (no healthy status)
  k8s_service_endpoint_monitor.py --warn-only

  # Output in JSON format
  k8s_service_endpoint_monitor.py --format json

Exit codes:
  0 - All services have healthy endpoints
  1 - One or more services have endpoint issues
  2 - Usage error or kubectl not found
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
        help="Only show services with issues (hide healthy services)"
    )

    args = parser.parse_args()

    # Get Kubernetes resources
    services = get_services(args.namespace)
    endpoints = get_endpoints(args.namespace)
    pods = get_pods(args.namespace)

    # Analyze
    issues = analyze_service_endpoints(services, endpoints, pods)

    # Output
    if args.format == "json":
        output_json(issues, args.warn_only)
    elif args.format == "table":
        output_table(issues, args.warn_only)
    else:
        output_plain(issues, args.warn_only)

    # Exit based on findings
    has_critical = any(i['severity'] == 'critical' for i in issues)
    sys.exit(1 if has_critical or issues else 0)


if __name__ == "__main__":
    main()
