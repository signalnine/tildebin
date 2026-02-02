#!/usr/bin/env python3
# boxctl:
#   category: k8s/compliance
#   tags: [images, registry, compliance, security, kubernetes]
#   requires: [kubectl]
#   brief: Audit pod container image registries for compliance
#   privilege: user
#   related: [security_audit, annotation_audit]

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
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


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


def parse_registry(image: str) -> tuple:
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


def audit_pods(pods: dict, approved_registries: list, production_namespaces: list, block_public_in_prod: bool) -> dict:
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


def format_plain(result: dict, warn_only: bool = False, show_stats: bool = True) -> str:
    """Format results as plain text."""
    output = []
    findings = result['findings']
    registry_stats = result['registry_stats']

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


def format_json(result: dict, warn_only: bool = False) -> str:
    """Format results as JSON."""
    if warn_only:
        result = result.copy()
        result['findings'] = [f for f in result['findings'] if not f['compliant']]
    return json.dumps(result, indent=2)


def format_table(result: dict, warn_only: bool = False) -> str:
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


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all compliant, 1 = violations found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes pod container image registries for compliance"
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to audit (default: all namespaces)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show images with policy violations"
    )
    parser.add_argument(
        "--approved-registry",
        action="append",
        dest="approved_registries",
        metavar="REGISTRY",
        help="Add an approved registry (can be specified multiple times)"
    )
    parser.add_argument(
        "--skip-approval-check",
        action="store_true",
        help="Skip registry approval validation (report stats only)"
    )
    parser.add_argument(
        "--block-public-in-prod",
        action="store_true",
        help="Flag public Docker Hub usage in production namespaces as violation"
    )
    parser.add_argument(
        "--production-namespace",
        action="append",
        dest="production_namespaces",
        metavar="NAMESPACE",
        help="Add a namespace to treat as production (for --block-public-in-prod)"
    )
    parser.add_argument(
        "--no-stats",
        action="store_true",
        help="Hide registry usage statistics"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Build approved registries list
    if opts.skip_approval_check:
        approved_registries = []
    else:
        approved_registries = DEFAULT_APPROVED_REGISTRIES.copy()
        if opts.approved_registries:
            approved_registries.extend(opts.approved_registries)

    # Build production namespaces list
    production_namespaces = PRODUCTION_NAMESPACES.copy()
    if opts.production_namespaces:
        production_namespaces.extend(opts.production_namespaces)

    # Build namespace args
    ns_args = ["-n", opts.namespace] if opts.namespace else ["--all-namespaces"]

    # Get pods
    try:
        result = context.run(["kubectl", "get", "pods", "-o", "json"] + ns_args)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    if not pods.get('items'):
        print("No running pods found.")
        output.set_summary("pods=0, violations=0")
        return 0

    # Audit pods
    audit_result = audit_pods(
        pods,
        approved_registries,
        production_namespaces,
        opts.block_public_in_prod
    )

    # Format output
    if opts.format == 'json':
        out = format_json(audit_result, opts.warn_only)
    elif opts.format == 'table':
        out = format_table(audit_result, opts.warn_only)
    else:
        out = format_plain(audit_result, opts.warn_only, show_stats=not opts.no_stats)

    print(out)

    # Summary
    compliant = sum(1 for f in audit_result['findings'] if f['compliant'])
    violations = len(audit_result['violations'])
    output.set_summary(f"images={len(audit_result['findings'])}, compliant={compliant}, violations={violations}")

    # Determine exit code
    has_violations = violations > 0
    return 1 if has_violations else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
