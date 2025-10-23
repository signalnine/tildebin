#!/usr/bin/env python3
"""
Monitor Kubernetes Deployments and StatefulSets status and replica availability.

This script provides visibility into Deployment and StatefulSet health, including:
- Replica availability (desired, ready, updated, available)
- Deployment/StatefulSet conditions (Progressing, Available)
- Image versions currently deployed
- Rollout status and progressing conditions
- Detection of stalled rollouts and pending replicas

Useful for monitoring application health in large-scale Kubernetes deployments.

Exit codes:
    0 - All deployments/statefulsets healthy and fully rolled out
    1 - One or more deployments/statefulsets not ready or unhealthy
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


def get_deployments(namespace=None):
    """Get all deployments in JSON format."""
    args = ['get', 'deployments', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_statefulsets(namespace=None):
    """Get all statefulsets in JSON format."""
    args = ['get', 'statefulsets', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def check_deployment_status(deployment):
    """Check deployment status and return health info."""
    status = deployment.get('status', {})
    spec = deployment.get('spec', {})

    desired = spec.get('replicas', 0)
    ready = status.get('readyReplicas', 0)
    updated = status.get('updatedReplicas', 0)
    available = status.get('availableReplicas', 0)
    observed_generation = status.get('observedGeneration', 0)

    metadata = deployment.get('metadata', {})
    generation = metadata.get('generation', 0)

    issues = []
    is_healthy = True

    # Check if deployment is fully rolled out
    if ready != desired or updated != desired or available != desired:
        issues.append(f"Not fully rolled out: {ready}/{desired} ready, {updated}/{desired} updated, {available}/{desired} available")
        is_healthy = False

    # Check if generation is observed
    if observed_generation < generation:
        issues.append("Rollout in progress (generation not yet observed)")
        is_healthy = False

    # Check conditions
    conditions = status.get('conditions', [])
    for condition in conditions:
        condition_type = condition.get('type', '')
        cond_status = condition.get('status', 'Unknown')
        reason = condition.get('reason', '')
        message = condition.get('message', '')

        if condition_type == 'Progressing' and cond_status != 'True':
            issues.append(f"Progressing={cond_status}: {reason} - {message}")
            is_healthy = False

        if condition_type == 'Available' and cond_status != 'True':
            issues.append(f"Available={cond_status}: {reason}")
            is_healthy = False

    return is_healthy, issues, {
        'desired': desired,
        'ready': ready,
        'updated': updated,
        'available': available
    }


def check_statefulset_status(statefulset):
    """Check statefulset status and return health info."""
    status = statefulset.get('status', {})
    spec = statefulset.get('spec', {})

    desired = spec.get('replicas', 0)
    ready = status.get('readyReplicas', 0)
    updated = status.get('updatedReplicas', 0)
    current = status.get('currentReplicas', 0)
    observed_generation = status.get('observedGeneration', 0)

    metadata = statefulset.get('metadata', {})
    generation = metadata.get('generation', 0)

    issues = []
    is_healthy = True

    # Check if statefulset is fully rolled out
    if ready != desired or updated != desired or current != desired:
        issues.append(f"Not fully rolled out: {ready}/{desired} ready, {updated}/{desired} updated, {current}/{desired} current")
        is_healthy = False

    # Check if generation is observed
    if observed_generation < generation:
        issues.append("Rollout in progress (generation not yet observed)")
        is_healthy = False

    # Check conditions
    conditions = status.get('conditions', [])
    for condition in conditions:
        condition_type = condition.get('type', '')
        cond_status = condition.get('status', 'Unknown')
        reason = condition.get('reason', '')
        message = condition.get('message', '')

        if cond_status != 'True':
            issues.append(f"{condition_type}={cond_status}: {reason} - {message}")
            is_healthy = False

    return is_healthy, issues, {
        'desired': desired,
        'ready': ready,
        'updated': updated,
        'current': current
    }


def get_images(resource):
    """Extract image versions from resource."""
    containers = resource.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
    images = []
    for container in containers:
        image = container.get('image', 'unknown')
        images.append(image)
    return images


def print_status(deployments, statefulsets, output_format, warn_only, namespace_filter=None):
    """Print deployment and statefulset status."""
    has_issues = False

    if output_format == 'json':
        output = []

        # Process deployments
        for dep in deployments.get('items', []):
            name = dep['metadata']['name']
            ns = dep['metadata'].get('namespace', 'default')

            if namespace_filter and ns != namespace_filter:
                continue

            is_healthy, issues, replicas = check_deployment_status(dep)
            images = get_images(dep)

            dep_info = {
                'type': 'Deployment',
                'namespace': ns,
                'name': name,
                'healthy': is_healthy,
                'replicas': replicas,
                'images': images,
                'issues': issues
            }

            if not warn_only or issues:
                output.append(dep_info)
                if issues:
                    has_issues = True

        # Process statefulsets
        for sts in statefulsets.get('items', []):
            name = sts['metadata']['name']
            ns = sts['metadata'].get('namespace', 'default')

            if namespace_filter and ns != namespace_filter:
                continue

            is_healthy, issues, replicas = check_statefulset_status(sts)
            images = get_images(sts)

            sts_info = {
                'type': 'StatefulSet',
                'namespace': ns,
                'name': name,
                'healthy': is_healthy,
                'replicas': replicas,
                'images': images,
                'issues': issues
            }

            if not warn_only or issues:
                output.append(sts_info)
                if issues:
                    has_issues = True

        print(json.dumps(output, indent=2))

    else:  # plain format
        healthy_count = 0
        unhealthy_count = 0

        # Process deployments
        for dep in deployments.get('items', []):
            name = dep['metadata']['name']
            ns = dep['metadata'].get('namespace', 'default')

            if namespace_filter and ns != namespace_filter:
                continue

            is_healthy, issues, replicas = check_deployment_status(dep)
            images = get_images(dep)

            if is_healthy:
                healthy_count += 1
            else:
                unhealthy_count += 1
                has_issues = True

            # Skip healthy if warn_only
            if warn_only and is_healthy:
                continue

            # Print deployment info
            status_marker = "✓" if is_healthy else "⚠"
            print(f"{status_marker} Deployment: {ns}/{name}")
            print(f"  Replicas: {replicas['ready']}/{replicas['desired']} ready, "
                  f"{replicas['updated']}/{replicas['desired']} updated, "
                  f"{replicas['available']}/{replicas['desired']} available")
            print(f"  Images: {', '.join(images)}")

            if issues:
                for issue in issues:
                    print(f"  WARNING: {issue}")

            print()

        # Process statefulsets
        for sts in statefulsets.get('items', []):
            name = sts['metadata']['name']
            ns = sts['metadata'].get('namespace', 'default')

            if namespace_filter and ns != namespace_filter:
                continue

            is_healthy, issues, replicas = check_statefulset_status(sts)
            images = get_images(sts)

            if is_healthy:
                healthy_count += 1
            else:
                unhealthy_count += 1
                has_issues = True

            # Skip healthy if warn_only
            if warn_only and is_healthy:
                continue

            # Print statefulset info
            status_marker = "✓" if is_healthy else "⚠"
            print(f"{status_marker} StatefulSet: {ns}/{name}")
            print(f"  Replicas: {replicas['ready']}/{replicas['desired']} ready, "
                  f"{replicas['updated']}/{replicas['desired']} updated, "
                  f"{replicas['current']}/{replicas['desired']} current")
            print(f"  Images: {', '.join(images)}")

            if issues:
                for issue in issues:
                    print(f"  WARNING: {issue}")

            print()

        # Print summary
        total = healthy_count + unhealthy_count
        print(f"Summary: {healthy_count}/{total} deployments/statefulsets healthy, {unhealthy_count} with issues")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes Deployments and StatefulSets status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all deployments and statefulsets
  %(prog)s -n production            # Check only in production namespace
  %(prog)s --warn-only              # Show only deployments with issues
  %(prog)s --format json            # JSON output
  %(prog)s -w -f json               # JSON output, only problematic resources

Exit codes:
  0 - All deployments/statefulsets healthy and fully rolled out
  1 - One or more deployments/statefulsets not ready
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
        help='Only show deployments/statefulsets with issues'
    )

    args = parser.parse_args()

    # Get deployments and statefulsets
    deployments = get_deployments(args.namespace)
    statefulsets = get_statefulsets(args.namespace)

    # Print status
    has_issues = print_status(deployments, statefulsets, args.format, args.warn_only, args.namespace)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
