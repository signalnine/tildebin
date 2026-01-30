#!/usr/bin/env python3
"""
Audit Kubernetes pod container image registries for compliance.

This script analyzes running pods to identify which container registries
are being used and detects potential policy violations:
- Images pulled from unapproved registries
- Images from public registries (Docker Hub) in production namespaces
- Images using implicit docker.io registry (shorthand notation)
- Registry usage statistics across the cluster

Unlike the image policy auditor which checks workload definitions, this
script examines actual running pods to see what's deployed right now,
including images from Jobs, CronJobs, and manually created pods.

Exit codes:
    0 - All images from approved registries (or no violations in warn mode)
    1 - Images from unapproved registries detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


DEFAULT_APPROVED_REGISTRIES = [
    'gcr.io',
    'us-docker.pkg.dev',
    'eu-docker.pkg.dev',
    'asia-docker.pkg.dev',
    'registry.k8s.io',
    'quay.io',
    'ghcr.io',
]

# Namespaces typically considered production
PRODUCTION_NAMESPACES = [
    'default',
    'production',
    'prod',
]


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


def get_pods(namespace=None):
    """Get all pods in JSON format."""
    args = ['get', 'pods', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def parse_registry(image):
    """
    Extract registry from container image reference.

    Returns tuple of (registry, normalized_image, is_implicit_dockerhub).
    """
    # Handle digest format
    if '@sha256:' in image:
        image = image.split('@')[0]

    # Handle tag format
    if ':' in image:
        parts = image.rsplit(':', 1)
        # Check if this is a port number (registry:port/image) or a tag
        if '/' in parts[1]:
            # This was a port in the registry, not a tag
            pass
        else:
            image = parts[0]

    parts = image.split('/')

    if len(parts) == 1:
        # Simple image name like "nginx" -> implicit docker.io/library/
        return 'docker.io', f"docker.io/library/{parts[0]}", True

    if len(parts) == 2:
        # Could be registry/image or user/image
        if '.' in parts[0] or ':' in parts[0]:
            # Contains dot or port -> it's a registry
            return parts[0], image, False
        else:
            # No dot -> docker.io user image
            return 'docker.io', f"docker.io/{image}", True

    # registry/path/to/image
    return parts[0], image, False


def audit_pods(pods, approved_registries, production_namespaces, block_public_in_prod):
    """
    Audit all pods for registry compliance.

    Returns dict with:
      - findings: list of per-image findings
      - registry_stats: count of images per registry
      - violations: list of policy violations
    """
    findings = []
    registry_stats = defaultdict(int)
    violations = []

    for pod in pods.get('items', []):
        metadata = pod.get('metadata', {})
        pod_name = metadata.get('name', 'unknown')
        namespace = metadata.get('namespace', 'default')
        status = pod.get('status', {})

        # Get container statuses (shows actual pulled images)
        container_statuses = status.get('containerStatuses', [])
        init_container_statuses = status.get('initContainerStatuses', [])

        all_statuses = [
            (cs, 'container') for cs in container_statuses
        ] + [
            (cs, 'initContainer') for cs in init_container_statuses
        ]

        for container_status, container_type in all_statuses:
            container_name = container_status.get('name', 'unknown')
            image = container_status.get('image', '')
            image_id = container_status.get('imageID', '')

            if not image:
                continue

            registry, normalized_image, is_implicit = parse_registry(image)
            registry_stats[registry] += 1

            # Check for violations
            image_violations = []

            # Check approved registries
            is_approved = any(
                registry == ar or registry.endswith('.' + ar)
                for ar in approved_registries
            )

            if approved_registries and not is_approved:
                image_violations.append(f"Unapproved registry: {registry}")

            # Check implicit docker.io usage
            if is_implicit:
                image_violations.append("Implicit docker.io registry (use explicit registry)")

            # Check public registry in production
            if block_public_in_prod:
                is_production = namespace in production_namespaces
                is_public = registry == 'docker.io'
                if is_production and is_public:
                    image_violations.append(f"Public registry in production namespace '{namespace}'")

            finding = {
                'namespace': namespace,
                'pod': pod_name,
                'container': container_name,
                'container_type': container_type,
                'image': image,
                'normalized_image': normalized_image,
                'registry': registry,
                'is_implicit_dockerhub': is_implicit,
                'image_id': image_id,
                'violations': image_violations,
                'compliant': len(image_violations) == 0
            }

            findings.append(finding)

            if image_violations:
                for v in image_violations:
                    violations.append({
                        'namespace': namespace,
                        'pod': pod_name,
                        'container': container_name,
                        'image': image,
                        'violation': v
                    })

    return {
        'findings': findings,
        'registry_stats': dict(registry_stats),
        'violations': violations
    }


def format_plain(result, warn_only=False, show_stats=True):
    """Format results as plain text."""
    output = []
    findings = result['findings']
    registry_stats = result['registry_stats']
    violations = result['violations']

    if warn_only:
        findings = [f for f in findings if not f['compliant']]

    # Registry statistics
    if show_stats and registry_stats:
        output.append("Registry Usage Statistics:")
        output.append("-" * 40)
        for registry, count in sorted(registry_stats.items(), key=lambda x: -x[1]):
            output.append(f"  {registry}: {count} images")
        output.append("")

    if not findings:
        if warn_only:
            output.append("No registry policy violations detected.")
        else:
            output.append("No running pods found.")
        return '\n'.join(output)

    # Group by namespace
    by_namespace = defaultdict(list)
    for finding in findings:
        by_namespace[finding['namespace']].append(finding)

    for namespace in sorted(by_namespace.keys()):
        ns_findings = by_namespace[namespace]

        output.append(f"Namespace: {namespace}")
        output.append("-" * 40)

        for finding in ns_findings:
            status = "+" if finding['compliant'] else "!"
            output.append(f"[{status}] Pod: {finding['pod']}")
            output.append(f"    Container: {finding['container']} ({finding['container_type']})")
            output.append(f"    Image: {finding['image']}")
            output.append(f"    Registry: {finding['registry']}")

            if finding['is_implicit_dockerhub']:
                output.append(f"    Note: Implicit docker.io (normalized: {finding['normalized_image']})")

            for violation in finding['violations']:
                output.append(f"    VIOLATION: {violation}")

            output.append("")

    # Summary
    compliant = sum(1 for f in result['findings'] if f['compliant'])
    non_compliant = sum(1 for f in result['findings'] if not f['compliant'])
    output.append(f"Summary: {compliant} compliant, {non_compliant} violations")

    return '\n'.join(output)


def format_json(result, warn_only=False):
    """Format results as JSON."""
    if warn_only:
        result = result.copy()
        result['findings'] = [f for f in result['findings'] if not f['compliant']]
    return json.dumps(result, indent=2)


def format_table(result, warn_only=False):
    """Format results as a table."""
    findings = result['findings']

    if warn_only:
        findings = [f for f in findings if not f['compliant']]

    if not findings:
        return "No registry policy violations detected." if warn_only else "No running pods found."

    header = f"{'NAMESPACE':<15} {'POD':<25} {'CONTAINER':<15} {'REGISTRY':<25} {'STATUS':<8}"
    separator = '-' * 95
    rows = [header, separator]

    for finding in findings:
        ns = finding['namespace'][:14]
        pod = finding['pod'][:24]
        container = finding['container'][:14]
        registry = finding['registry'][:24]
        status = 'OK' if finding['compliant'] else 'FAIL'

        row = f"{ns:<15} {pod:<25} {container:<15} {registry:<25} {status:<8}"
        rows.append(row)

    rows.append(separator)
    compliant = sum(1 for f in result['findings'] if f['compliant'])
    non_compliant = sum(1 for f in result['findings'] if not f['compliant'])
    rows.append(f"Total: {len(result['findings'])} images, {compliant} compliant, {non_compliant} violations")

    return '\n'.join(rows)


def main():
    parser = argparse.ArgumentParser(
        description='Audit Kubernetes pod container image registries for compliance.',
        epilog='''
Examples:
  # Audit all pods in all namespaces
  k8s_pod_image_registry_audit.py

  # Audit only specific namespace
  k8s_pod_image_registry_audit.py -n production

  # Show only violations
  k8s_pod_image_registry_audit.py --warn-only

  # Output as JSON for CI/CD pipelines
  k8s_pod_image_registry_audit.py --format json

  # Add approved registry
  k8s_pod_image_registry_audit.py --approved-registry my-registry.example.com

  # Block public Docker Hub in production namespaces
  k8s_pod_image_registry_audit.py --block-public-in-prod

  # Skip registry approval checks (just report stats)
  k8s_pod_image_registry_audit.py --skip-approval-check

Exit codes:
  0 - All images from approved registries
  1 - Unapproved registry usage detected
  2 - Usage error or kubectl unavailable
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to audit (default: all namespaces)'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show images with policy violations'
    )
    parser.add_argument(
        '--approved-registry',
        action='append',
        dest='approved_registries',
        metavar='REGISTRY',
        help='Add an approved registry (can be specified multiple times)'
    )
    parser.add_argument(
        '--skip-approval-check',
        action='store_true',
        help='Skip registry approval validation (report stats only)'
    )
    parser.add_argument(
        '--block-public-in-prod',
        action='store_true',
        help='Flag public Docker Hub usage in production namespaces as violation'
    )
    parser.add_argument(
        '--production-namespace',
        action='append',
        dest='production_namespaces',
        metavar='NAMESPACE',
        help='Add a namespace to treat as production (for --block-public-in-prod)'
    )
    parser.add_argument(
        '--no-stats',
        action='store_true',
        help='Hide registry usage statistics'
    )

    args = parser.parse_args()

    # Build approved registries list
    if args.skip_approval_check:
        approved_registries = []
    else:
        approved_registries = DEFAULT_APPROVED_REGISTRIES.copy()
        if args.approved_registries:
            approved_registries.extend(args.approved_registries)

    # Build production namespaces list
    production_namespaces = PRODUCTION_NAMESPACES.copy()
    if args.production_namespaces:
        production_namespaces.extend(args.production_namespaces)

    # Get pods
    pods = get_pods(args.namespace)

    if not pods.get('items'):
        print("No running pods found.", file=sys.stderr)
        return 0

    # Audit pods
    result = audit_pods(
        pods,
        approved_registries,
        production_namespaces,
        args.block_public_in_prod
    )

    # Format output
    if args.format == 'json':
        output = format_json(result, args.warn_only)
    elif args.format == 'table':
        output = format_table(result, args.warn_only)
    else:
        output = format_plain(result, args.warn_only, show_stats=not args.no_stats)

    print(output)

    # Determine exit code
    has_violations = len(result['violations']) > 0
    return 1 if has_violations else 0


if __name__ == '__main__':
    sys.exit(main())
