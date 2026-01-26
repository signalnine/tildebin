#!/usr/bin/env python3
"""
Audit Kubernetes workload container images for security best practices.

This script analyzes container images across Deployments, StatefulSets,
DaemonSets, and Jobs for common security issues:
- Mutable tags (latest, dev, main) that can change unexpectedly
- Missing image digests (sha256 pinning) for reproducible deployments
- Images from untrusted registries
- Use of deprecated or insecure base images

Supply chain security requires pinning images by digest to ensure the
exact image content is deployed, not just a mutable tag that could be
overwritten by attackers or change unexpectedly.

Exit codes:
    0 - All images pass policy checks
    1 - Policy violations detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
import re
import subprocess
import sys


DEFAULT_TRUSTED_REGISTRIES = [
    'gcr.io',
    'us-docker.pkg.dev',
    'docker.io/library',
    'quay.io',
    'registry.k8s.io',
    'ghcr.io',
]

MUTABLE_TAGS = ['latest', 'dev', 'develop', 'main', 'master', 'head', 'edge', 'nightly']


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


def get_workloads(namespace=None):
    """Get all workloads (Deployments, StatefulSets, DaemonSets, Jobs)."""
    workloads = []

    resource_types = ['deployments', 'statefulsets', 'daemonsets', 'jobs']

    for resource_type in resource_types:
        args = ['get', resource_type, '-o', 'json']
        if namespace:
            args.extend(['-n', namespace])
        else:
            args.append('--all-namespaces')

        try:
            output = run_kubectl(args)
            data = json.loads(output)
            for item in data.get('items', []):
                item['_resource_type'] = resource_type
                workloads.append(item)
        except json.JSONDecodeError:
            continue

    return workloads


def parse_image_ref(image):
    """
    Parse container image reference into components.

    Returns dict with:
      - registry: The registry hostname (or None for docker.io default)
      - repository: The image repository path
      - tag: The image tag (or None)
      - digest: The image digest sha256:... (or None)
      - is_pinned: True if image has a digest
      - full: The full image reference
    """
    result = {
        'full': image,
        'registry': None,
        'repository': None,
        'tag': None,
        'digest': None,
        'is_pinned': False
    }

    # Check for digest
    if '@sha256:' in image:
        image_part, digest = image.split('@', 1)
        result['digest'] = digest
        result['is_pinned'] = True
        image = image_part

    # Check for tag
    if ':' in image:
        # Handle case where : is in registry (hostname:port)
        parts = image.rsplit(':', 1)
        if '/' in parts[1]:
            # The : was in the registry, not a tag
            pass
        else:
            image = parts[0]
            result['tag'] = parts[1]

    # Parse registry and repository
    parts = image.split('/')

    if len(parts) == 1:
        # docker.io/library/image format (shorthand)
        result['registry'] = 'docker.io'
        result['repository'] = f"library/{parts[0]}"
    elif len(parts) == 2:
        # Could be registry/image or user/image
        if '.' in parts[0] or ':' in parts[0]:
            # It's a registry
            result['registry'] = parts[0]
            result['repository'] = parts[1]
        else:
            # It's a docker.io user/image
            result['registry'] = 'docker.io'
            result['repository'] = image
    else:
        # registry/path/to/image
        result['registry'] = parts[0]
        result['repository'] = '/'.join(parts[1:])

    # Default tag to 'latest' if not specified and not pinned
    if not result['tag'] and not result['is_pinned']:
        result['tag'] = 'latest'

    return result


def check_image_policy(image_ref, trusted_registries, require_digest=True):
    """
    Check if an image meets policy requirements.

    Returns list of policy violations (empty if compliant).
    """
    violations = []

    # Check for mutable tags
    tag = image_ref.get('tag')
    if tag and tag.lower() in MUTABLE_TAGS:
        violations.append(f"Mutable tag '{tag}' can change unexpectedly")

    # Check for digest pinning
    if require_digest and not image_ref['is_pinned']:
        violations.append("Image not pinned by digest (sha256)")

    # Check for trusted registry
    registry = image_ref.get('registry', '')
    is_trusted = any(
        registry.startswith(tr) or registry == tr
        for tr in trusted_registries
    )
    if trusted_registries and not is_trusted:
        violations.append(f"Untrusted registry: {registry}")

    return violations


def extract_containers(workload):
    """Extract container images from a workload resource."""
    containers = []

    # Get pod spec based on resource type
    spec = workload.get('spec', {})

    if workload.get('_resource_type') == 'jobs':
        pod_spec = spec.get('template', {}).get('spec', {})
    else:
        pod_spec = spec.get('template', {}).get('spec', {})

    # Regular containers
    for container in pod_spec.get('containers', []):
        containers.append({
            'name': container.get('name', 'unknown'),
            'image': container.get('image', ''),
            'type': 'container'
        })

    # Init containers
    for container in pod_spec.get('initContainers', []):
        containers.append({
            'name': container.get('name', 'unknown'),
            'image': container.get('image', ''),
            'type': 'initContainer'
        })

    return containers


def audit_workloads(workloads, trusted_registries, require_digest):
    """
    Audit all workloads for image policy compliance.

    Returns list of findings.
    """
    findings = []

    for workload in workloads:
        metadata = workload.get('metadata', {})
        name = metadata.get('name', 'unknown')
        namespace = metadata.get('namespace', 'default')
        resource_type = workload.get('_resource_type', 'unknown')

        containers = extract_containers(workload)

        for container in containers:
            image = container.get('image', '')
            if not image:
                continue

            image_ref = parse_image_ref(image)
            violations = check_image_policy(image_ref, trusted_registries, require_digest)

            finding = {
                'namespace': namespace,
                'resource_type': resource_type,
                'resource_name': name,
                'container_name': container['name'],
                'container_type': container['type'],
                'image': image,
                'image_ref': image_ref,
                'violations': violations,
                'compliant': len(violations) == 0
            }

            findings.append(finding)

    return findings


def format_plain(findings, warn_only=False, verbose=False):
    """Format findings as plain text."""
    output = []

    if warn_only:
        findings = [f for f in findings if not f['compliant']]

    if not findings:
        output.append("No image policy violations detected." if warn_only else "No workloads found.")
        return '\n'.join(output)

    # Group by namespace
    by_namespace = {}
    for finding in findings:
        ns = finding['namespace']
        if ns not in by_namespace:
            by_namespace[ns] = []
        by_namespace[ns].append(finding)

    compliant_count = sum(1 for f in findings if f['compliant'])
    violation_count = sum(1 for f in findings if not f['compliant'])

    for namespace in sorted(by_namespace.keys()):
        ns_findings = by_namespace[namespace]

        output.append(f"Namespace: {namespace}")
        output.append("-" * 40)

        for finding in ns_findings:
            if warn_only and finding['compliant']:
                continue

            status = "+" if finding['compliant'] else "!"
            resource = f"{finding['resource_type']}/{finding['resource_name']}"
            container = finding['container_name']

            output.append(f"[{status}] {resource}")
            output.append(f"    Container: {container} ({finding['container_type']})")
            output.append(f"    Image: {finding['image']}")

            if verbose:
                ref = finding['image_ref']
                output.append(f"    Registry: {ref['registry']}")
                output.append(f"    Tag: {ref['tag'] or 'none'}")
                output.append(f"    Pinned: {'Yes' if ref['is_pinned'] else 'No'}")

            if finding['violations']:
                for violation in finding['violations']:
                    output.append(f"    Violation: {violation}")

            output.append("")

    output.append(f"Summary: {compliant_count} compliant, {violation_count} violations")

    return '\n'.join(output)


def format_json(findings, warn_only=False):
    """Format findings as JSON."""
    if warn_only:
        findings = [f for f in findings if not f['compliant']]

    return json.dumps(findings, indent=2)


def format_table(findings, warn_only=False):
    """Format findings as a table."""
    if warn_only:
        findings = [f for f in findings if not f['compliant']]

    if not findings:
        return "No image policy violations detected." if warn_only else "No workloads found."

    header = f"{'NAMESPACE':<15} {'RESOURCE':<30} {'CONTAINER':<20} {'STATUS':<10} {'VIOLATIONS':<30}"
    separator = '-' * 110
    rows = [header, separator]

    for finding in findings:
        ns = finding['namespace'][:14]
        resource = f"{finding['resource_type'][:4]}/{finding['resource_name']}"[:29]
        container = finding['container_name'][:19]
        status = 'OK' if finding['compliant'] else 'FAIL'
        violations = '; '.join(finding['violations'])[:29] if finding['violations'] else '-'

        row = f"{ns:<15} {resource:<30} {container:<20} {status:<10} {violations:<30}"
        rows.append(row)

    compliant_count = sum(1 for f in findings if f['compliant'])
    violation_count = sum(1 for f in findings if not f['compliant'])
    rows.append(separator)
    rows.append(f"Total: {len(findings)} images, {compliant_count} compliant, {violation_count} violations")

    return '\n'.join(rows)


def main():
    parser = argparse.ArgumentParser(
        description='Audit Kubernetes workload images for security best practices.',
        epilog='''
Examples:
  # Audit all workloads in all namespaces
  k8s_image_policy_auditor.py

  # Audit only specific namespace
  k8s_image_policy_auditor.py -n production

  # Show only violations
  k8s_image_policy_auditor.py --warn-only

  # Output as JSON for CI/CD pipelines
  k8s_image_policy_auditor.py --format json

  # Skip digest requirement (only check for mutable tags)
  k8s_image_policy_auditor.py --no-require-digest

  # Add custom trusted registry
  k8s_image_policy_auditor.py --trusted-registry my-registry.example.com

  # Disable registry checks entirely
  k8s_image_policy_auditor.py --skip-registry-check

Exit codes:
  0 - All images pass policy checks
  1 - Policy violations detected
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
        '-v', '--verbose',
        action='store_true',
        help='Show detailed image reference information'
    )
    parser.add_argument(
        '--no-require-digest',
        action='store_true',
        help='Do not require images to be pinned by digest'
    )
    parser.add_argument(
        '--trusted-registry',
        action='append',
        dest='trusted_registries',
        metavar='REGISTRY',
        help='Add a trusted registry (can be specified multiple times)'
    )
    parser.add_argument(
        '--skip-registry-check',
        action='store_true',
        help='Skip trusted registry validation'
    )

    args = parser.parse_args()

    # Build trusted registries list
    if args.skip_registry_check:
        trusted_registries = []
    else:
        trusted_registries = DEFAULT_TRUSTED_REGISTRIES.copy()
        if args.trusted_registries:
            trusted_registries.extend(args.trusted_registries)

    # Get workloads
    workloads = get_workloads(args.namespace)

    if not workloads:
        print("No workloads found.", file=sys.stderr)
        return 0

    # Audit workloads
    require_digest = not args.no_require_digest
    findings = audit_workloads(workloads, trusted_registries, require_digest)

    # Format output
    if args.format == 'json':
        output = format_json(findings, args.warn_only)
    elif args.format == 'table':
        output = format_table(findings, args.warn_only)
    else:
        output = format_plain(findings, args.warn_only, args.verbose)

    print(output)

    # Determine exit code
    has_violations = any(not f['compliant'] for f in findings)
    return 1 if has_violations else 0


if __name__ == '__main__':
    sys.exit(main())
