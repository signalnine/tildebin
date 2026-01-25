#!/usr/bin/env python3
"""
Monitor Kubernetes EndpointSlice health and detect service discovery issues.

EndpointSlices are the modern replacement for Endpoints, providing better
scalability for large clusters. This script monitors their health to catch
service discovery problems before they impact applications.

Checks performed:
- EndpointSlices with no ready endpoints (service down)
- EndpointSlices with high not-ready endpoint ratio
- Services missing EndpointSlices entirely
- Stale EndpointSlices (endpoints stuck in not-ready)
- EndpointSlice count per service (fragmentation)
- Port mismatches between service and endpoints

Useful for:
- Service mesh debugging
- Load balancer health verification
- Large-scale cluster operations
- Service discovery troubleshooting
- Pre-deployment validation

Exit codes:
    0 - All EndpointSlices healthy
    1 - Issues detected (missing endpoints, unhealthy services)
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


def get_endpointslices(namespace=None):
    """Get all EndpointSlices in JSON format."""
    args = ['get', 'endpointslices', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_services(namespace=None):
    """Get all Services in JSON format."""
    args = ['get', 'services', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def analyze_endpointslice(eps):
    """Analyze a single EndpointSlice for issues."""
    metadata = eps.get('metadata', {})
    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    labels = metadata.get('labels', {})

    # Get the service this EndpointSlice belongs to
    service_name = labels.get('kubernetes.io/service-name', 'unknown')

    endpoints = eps.get('endpoints', [])
    ports = eps.get('ports', [])

    issues = []
    is_healthy = True

    # Count endpoint conditions
    ready_count = 0
    not_ready_count = 0
    terminating_count = 0
    unknown_count = 0

    for endpoint in endpoints:
        conditions = endpoint.get('conditions', {})

        # Ready is the primary health indicator
        ready = conditions.get('ready')
        serving = conditions.get('serving')
        terminating = conditions.get('terminating')

        if terminating:
            terminating_count += 1
        elif ready:
            ready_count += 1
        elif ready is False:
            not_ready_count += 1
        else:
            # Ready is nil/unknown
            unknown_count += 1

    total_endpoints = len(endpoints)

    # Check for no endpoints at all
    if total_endpoints == 0:
        issues.append("No endpoints defined")
        is_healthy = False

    # Check for no ready endpoints
    elif ready_count == 0:
        if terminating_count == total_endpoints:
            issues.append(f"All {total_endpoints} endpoints terminating")
        elif not_ready_count > 0:
            issues.append(f"No ready endpoints ({not_ready_count} not ready)")
        else:
            issues.append("No ready endpoints")
        is_healthy = False

    # Check for high not-ready ratio (>50% not ready)
    elif not_ready_count > 0:
        not_ready_ratio = not_ready_count / total_endpoints
        if not_ready_ratio > 0.5:
            issues.append(
                f"High not-ready ratio: {not_ready_count}/{total_endpoints} "
                f"({not_ready_ratio:.0%}) not ready"
            )
            is_healthy = False
        elif not_ready_ratio > 0.2:
            issues.append(
                f"Some endpoints not ready: {not_ready_count}/{total_endpoints}"
            )

    # Check for terminating endpoints
    if terminating_count > 0 and terminating_count < total_endpoints:
        issues.append(f"{terminating_count}/{total_endpoints} endpoints terminating")

    # Check for missing port definitions
    if not ports:
        issues.append("No ports defined in EndpointSlice")

    return {
        'name': name,
        'namespace': namespace,
        'service': service_name,
        'ready': ready_count,
        'not_ready': not_ready_count,
        'terminating': terminating_count,
        'unknown': unknown_count,
        'total': total_endpoints,
        'ports': len(ports),
        'healthy': is_healthy,
        'issues': issues
    }


def check_service_coverage(services, endpointslices_by_service, exclude_headless=True):
    """Check which services are missing EndpointSlices."""
    missing_services = []

    for svc in services.get('items', []):
        metadata = svc.get('metadata', {})
        name = metadata.get('name', 'unknown')
        namespace = metadata.get('namespace', 'default')
        spec = svc.get('spec', {})

        # Skip ExternalName services (they don't have endpoints)
        if spec.get('type') == 'ExternalName':
            continue

        # Optionally skip headless services
        if exclude_headless and spec.get('clusterIP') == 'None':
            continue

        # Skip services without selectors (manually managed)
        if not spec.get('selector'):
            continue

        key = f"{namespace}/{name}"
        if key not in endpointslices_by_service:
            missing_services.append({
                'name': name,
                'namespace': namespace,
                'type': spec.get('type', 'ClusterIP'),
                'selector': spec.get('selector', {})
            })

    return missing_services


def check_endpointslice_fragmentation(endpointslices_by_service, threshold=10):
    """Check for services with too many EndpointSlice fragments."""
    fragmented = []

    for service_key, slices in endpointslices_by_service.items():
        if len(slices) > threshold:
            namespace, name = service_key.split('/', 1)
            total_endpoints = sum(s['total'] for s in slices)
            fragmented.append({
                'name': name,
                'namespace': namespace,
                'slice_count': len(slices),
                'total_endpoints': total_endpoints
            })

    return fragmented


def print_results(results, missing_services, fragmented, output_format, warn_only):
    """Print analysis results."""
    has_issues = False

    if output_format == 'json':
        output = {
            'endpointslices': [],
            'missing_services': missing_services,
            'fragmented_services': fragmented,
            'summary': {
                'total_slices': 0,
                'healthy_slices': 0,
                'unhealthy_slices': 0,
                'missing_services': len(missing_services),
                'fragmented_services': len(fragmented)
            }
        }

        for result in results:
            if warn_only and result['healthy'] and not result['issues']:
                continue

            output['endpointslices'].append(result)
            output['summary']['total_slices'] += 1

            if result['healthy']:
                output['summary']['healthy_slices'] += 1
            else:
                output['summary']['unhealthy_slices'] += 1
                has_issues = True

        if missing_services:
            has_issues = True
        if fragmented:
            has_issues = True

        print(json.dumps(output, indent=2))

    else:  # plain format
        healthy_count = 0
        unhealthy_count = 0

        print("=== EndpointSlice Health ===\n")

        for result in results:
            if warn_only and result['healthy'] and not result['issues']:
                continue

            if result['healthy']:
                healthy_count += 1
            else:
                unhealthy_count += 1
                has_issues = True

            status = "+" if result['healthy'] else "!"
            print(f"[{status}] {result['namespace']}/{result['name']}")
            print(f"    Service: {result['service']}")
            print(f"    Endpoints: {result['ready']} ready, "
                  f"{result['not_ready']} not-ready, "
                  f"{result['terminating']} terminating")

            if result['issues']:
                for issue in result['issues']:
                    print(f"    WARNING: {issue}")
            print()

        # Print missing services
        if missing_services:
            has_issues = True
            print("=== Services Missing EndpointSlices ===\n")
            for svc in missing_services:
                print(f"[!] {svc['namespace']}/{svc['name']}")
                print(f"    Type: {svc['type']}")
                print(f"    Selector: {svc['selector']}")
                print()

        # Print fragmented services
        if fragmented:
            has_issues = True
            print("=== Fragmented Services (many EndpointSlices) ===\n")
            for frag in fragmented:
                print(f"[!] {frag['namespace']}/{frag['name']}")
                print(f"    Slices: {frag['slice_count']}, "
                      f"Total endpoints: {frag['total_endpoints']}")
                print()

        # Summary
        total = healthy_count + unhealthy_count
        print(f"Summary: {healthy_count}/{total} EndpointSlices healthy")
        if missing_services:
            print(f"         {len(missing_services)} services missing EndpointSlices")
        if fragmented:
            print(f"         {len(fragmented)} services with excessive fragmentation")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes EndpointSlice health',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all EndpointSlices
  %(prog)s -n production            # Check only production namespace
  %(prog)s --warn-only              # Show only unhealthy slices
  %(prog)s --format json            # JSON output
  %(prog)s --include-headless       # Include headless service checks
  %(prog)s --frag-threshold 5       # Flag services with >5 slices

Exit codes:
  0 - All EndpointSlices healthy
  1 - Issues detected
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to check (default: all namespaces)'
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
        help='Only show EndpointSlices with issues'
    )

    parser.add_argument(
        '--include-headless',
        action='store_true',
        help='Include headless services in missing service check'
    )

    parser.add_argument(
        '--frag-threshold',
        type=int,
        default=10,
        help='EndpointSlice count threshold for fragmentation warning (default: 10)'
    )

    parser.add_argument(
        '--skip-coverage-check',
        action='store_true',
        help='Skip checking for services missing EndpointSlices'
    )

    args = parser.parse_args()

    # Get EndpointSlices
    endpointslices = get_endpointslices(args.namespace)

    # Analyze each EndpointSlice
    results = []
    endpointslices_by_service = defaultdict(list)

    for eps in endpointslices.get('items', []):
        result = analyze_endpointslice(eps)
        results.append(result)

        # Group by service for coverage check
        service_key = f"{result['namespace']}/{result['service']}"
        endpointslices_by_service[service_key].append(result)

    # Check service coverage
    missing_services = []
    if not args.skip_coverage_check:
        services = get_services(args.namespace)
        missing_services = check_service_coverage(
            services,
            endpointslices_by_service,
            exclude_headless=not args.include_headless
        )

    # Check fragmentation
    fragmented = check_endpointslice_fragmentation(
        endpointslices_by_service,
        args.frag_threshold
    )

    # Print results
    has_issues = print_results(
        results, missing_services, fragmented,
        args.format, args.warn_only
    )

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
