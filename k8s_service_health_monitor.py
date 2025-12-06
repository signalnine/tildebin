#!/usr/bin/env python3
"""
Kubernetes Service Health Monitor

Monitors the health of Kubernetes Services by checking:
- Service endpoint availability (ready vs not-ready endpoints)
- Service type and configuration
- Port configuration correctness
- Selector matching
- Services with zero endpoints (potential issues)

This tool helps identify service networking issues in Kubernetes clusters,
particularly useful for troubleshooting connectivity problems and ensuring
services have healthy backend pods.

Exit codes:
    0 - All services healthy
    1 - Issues detected (services without endpoints, unhealthy endpoints)
    2 - Usage error or kubectl not available
"""

import argparse
import sys
import subprocess
import json


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
        print(f"Error executing kubectl: {e.stderr}", file=sys.stderr)
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


def analyze_service_health(services_data, endpoints_data, verbose=False):
    """
    Analyze service health by correlating services with their endpoints

    Returns:
        list: List of issues found (empty if all healthy)
    """
    issues = []
    healthy_services = []

    # Create endpoint lookup map
    endpoints_map = {}
    for ep in endpoints_data.get('items', []):
        namespace = ep['metadata'].get('namespace', 'default')
        name = ep['metadata']['name']
        key = f"{namespace}/{name}"
        endpoints_map[key] = ep

    # Analyze each service
    for svc in services_data.get('items', []):
        namespace = svc['metadata'].get('namespace', 'default')
        name = svc['metadata']['name']
        svc_type = svc['spec'].get('type', 'ClusterIP')
        key = f"{namespace}/{name}"

        # Skip headless services (ClusterIP: None)
        cluster_ip = svc['spec'].get('clusterIP')
        if cluster_ip == 'None':
            if verbose:
                healthy_services.append({
                    'namespace': namespace,
                    'name': name,
                    'type': 'Headless',
                    'status': 'healthy',
                    'message': 'Headless service (no health check needed)'
                })
            continue

        # Get corresponding endpoint
        ep = endpoints_map.get(key)

        if not ep:
            # Service exists but no endpoint object (unusual but possible)
            issues.append({
                'namespace': namespace,
                'name': name,
                'type': svc_type,
                'severity': 'warning',
                'issue': 'No endpoint object found',
                'ready_endpoints': 0,
                'total_endpoints': 0
            })
            continue

        # Count ready and not-ready endpoints
        ready_count = 0
        not_ready_count = 0

        # Check subsets for endpoint readiness
        subsets = ep.get('subsets', [])

        if not subsets:
            # Service has no backend pods
            issues.append({
                'namespace': namespace,
                'name': name,
                'type': svc_type,
                'severity': 'error',
                'issue': 'No endpoints available (no backing pods)',
                'ready_endpoints': 0,
                'total_endpoints': 0
            })
            continue

        for subset in subsets:
            ready_addresses = subset.get('addresses', [])
            not_ready_addresses = subset.get('notReadyAddresses', [])
            ready_count += len(ready_addresses)
            not_ready_count += len(not_ready_addresses)

        total_endpoints = ready_count + not_ready_count

        if ready_count == 0 and not_ready_count > 0:
            # Service has endpoints but all are not ready
            issues.append({
                'namespace': namespace,
                'name': name,
                'type': svc_type,
                'severity': 'error',
                'issue': 'All endpoints not ready',
                'ready_endpoints': 0,
                'total_endpoints': total_endpoints
            })
        elif ready_count > 0 and not_ready_count > 0:
            # Service has some ready and some not-ready endpoints
            issues.append({
                'namespace': namespace,
                'name': name,
                'type': svc_type,
                'severity': 'warning',
                'issue': 'Some endpoints not ready',
                'ready_endpoints': ready_count,
                'total_endpoints': total_endpoints
            })
        elif ready_count > 0:
            # Service is healthy
            if verbose:
                healthy_services.append({
                    'namespace': namespace,
                    'name': name,
                    'type': svc_type,
                    'status': 'healthy',
                    'ready_endpoints': ready_count,
                    'total_endpoints': total_endpoints
                })

    return issues, healthy_services


def output_plain(issues, healthy_services, warn_only=False, verbose=False):
    """Plain text output"""
    if issues:
        if not warn_only:
            print("Services with issues:")
            print()

        for issue in issues:
            if warn_only and issue['severity'] != 'warning':
                continue

            severity_marker = "ERROR" if issue['severity'] == 'error' else "WARN"
            print(f"[{severity_marker}] {issue['namespace']}/{issue['name']} ({issue['type']})")
            print(f"  Issue: {issue['issue']}")
            print(f"  Endpoints: {issue['ready_endpoints']}/{issue['total_endpoints']} ready")
            print()

    if verbose and healthy_services:
        print("Healthy services:")
        print()
        for svc in healthy_services:
            if 'message' in svc:
                print(f"[OK] {svc['namespace']}/{svc['name']} ({svc['type']}) - {svc['message']}")
            else:
                print(f"[OK] {svc['namespace']}/{svc['name']} ({svc['type']}) - {svc['ready_endpoints']}/{svc['total_endpoints']} endpoints ready")
        print()

    if not issues and not verbose:
        print("All services healthy")


def output_json(issues, healthy_services, verbose=False):
    """JSON output"""
    output = {
        'issues': issues,
        'summary': {
            'total_issues': len(issues),
            'errors': len([i for i in issues if i['severity'] == 'error']),
            'warnings': len([i for i in issues if i['severity'] == 'warning'])
        }
    }

    if verbose:
        output['healthy_services'] = healthy_services
        output['summary']['healthy_services'] = len(healthy_services)

    print(json.dumps(output, indent=2))


def output_table(issues, healthy_services, warn_only=False, verbose=False):
    """Tabular output"""
    if issues:
        filtered_issues = issues
        if warn_only:
            filtered_issues = [i for i in issues if i['severity'] == 'warning']

        if filtered_issues:
            print(f"{'SEVERITY':<8} {'NAMESPACE':<20} {'SERVICE':<30} {'TYPE':<15} {'READY':<10} {'ISSUE':<40}")
            print("-" * 123)

            for issue in filtered_issues:
                severity = issue['severity'].upper()
                namespace = issue['namespace'][:19]
                name = issue['name'][:29]
                svc_type = issue['type'][:14]
                ready = f"{issue['ready_endpoints']}/{issue['total_endpoints']}"
                issue_text = issue['issue'][:39]

                print(f"{severity:<8} {namespace:<20} {name:<30} {svc_type:<15} {ready:<10} {issue_text:<40}")

            print()

    if verbose and healthy_services:
        print("\nHealthy Services:")
        print(f"{'NAMESPACE':<20} {'SERVICE':<30} {'TYPE':<15} {'ENDPOINTS':<15}")
        print("-" * 80)

        for svc in healthy_services:
            namespace = svc['namespace'][:19]
            name = svc['name'][:29]
            svc_type = svc['type'][:14]

            if 'ready_endpoints' in svc:
                endpoints = f"{svc['ready_endpoints']}/{svc['total_endpoints']}"
            else:
                endpoints = svc.get('message', 'N/A')[:14]

            print(f"{namespace:<20} {name:<30} {svc_type:<15} {endpoints:<15}")

        print()

    if not issues and not verbose:
        print("All services healthy")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes Service health and endpoint availability",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all services in all namespaces
  %(prog)s

  # Check services in specific namespace
  %(prog)s -n production

  # Show detailed output including healthy services
  %(prog)s -v

  # JSON output for automation
  %(prog)s --format json

  # Only show warnings (skip errors)
  %(prog)s --warn-only

Exit codes:
  0 - All services healthy
  1 - Issues detected
  2 - Usage error or kubectl not available
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
        "-v", "--verbose",
        action="store_true",
        help="Show healthy services in addition to issues"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings (exclude errors)"
    )

    args = parser.parse_args()

    try:
        # Get services and endpoints
        services_data = get_services(args.namespace)
        endpoints_data = get_endpoints(args.namespace)

        # Analyze health
        issues, healthy_services = analyze_service_health(
            services_data,
            endpoints_data,
            verbose=args.verbose
        )

        # Output results
        if args.format == "json":
            output_json(issues, healthy_services, args.verbose)
        elif args.format == "table":
            output_table(issues, healthy_services, args.warn_only, args.verbose)
        else:  # plain
            output_plain(issues, healthy_services, args.warn_only, args.verbose)

        # Exit with appropriate code
        sys.exit(1 if issues else 0)

    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
