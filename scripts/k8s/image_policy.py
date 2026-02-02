#!/usr/bin/env python3
# boxctl:
#   category: k8s/security
#   tags: [images, security, kubernetes, policy, supply-chain]
#   requires: [kubectl]
#   privilege: user
#   brief: Audit container images for security best practices
#   related: [image_pull]

"""
Kubernetes container image policy auditor - Analyze images for security compliance.

Audits container images across Deployments, StatefulSets, DaemonSets, and Jobs for:
- Mutable tags (latest, dev, main) that can change unexpectedly
- Missing image digests (sha256 pinning) for reproducible deployments
- Images from untrusted registries
- Supply chain security issues

Exit codes:
    0 - All images pass policy checks
    1 - Policy violations detected
    2 - Usage error or kubectl not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


DEFAULT_TRUSTED_REGISTRIES = [
    "gcr.io",
    "us-docker.pkg.dev",
    "docker.io/library",
    "quay.io",
    "registry.k8s.io",
    "ghcr.io",
]

MUTABLE_TAGS = ["latest", "dev", "develop", "main", "master", "head", "edge", "nightly"]


def parse_image_ref(image: str) -> dict:
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
        "full": image,
        "registry": None,
        "repository": None,
        "tag": None,
        "digest": None,
        "is_pinned": False,
    }

    # Check for digest
    if "@sha256:" in image:
        image_part, digest = image.split("@", 1)
        result["digest"] = digest
        result["is_pinned"] = True
        image = image_part

    # Check for tag
    if ":" in image:
        # Handle case where : is in registry (hostname:port)
        parts = image.rsplit(":", 1)
        if "/" in parts[1]:
            # The : was in the registry, not a tag
            pass
        else:
            image = parts[0]
            result["tag"] = parts[1]

    # Parse registry and repository
    parts = image.split("/")

    if len(parts) == 1:
        # docker.io/library/image format (shorthand)
        result["registry"] = "docker.io"
        result["repository"] = f"library/{parts[0]}"
    elif len(parts) == 2:
        # Could be registry/image or user/image
        if "." in parts[0] or ":" in parts[0]:
            # It's a registry
            result["registry"] = parts[0]
            result["repository"] = parts[1]
        else:
            # It's a docker.io user/image
            result["registry"] = "docker.io"
            result["repository"] = image
    else:
        # registry/path/to/image
        result["registry"] = parts[0]
        result["repository"] = "/".join(parts[1:])

    # Default tag to 'latest' if not specified and not pinned
    if not result["tag"] and not result["is_pinned"]:
        result["tag"] = "latest"

    return result


def check_image_policy(
    image_ref: dict, trusted_registries: list, require_digest: bool = True
) -> list:
    """
    Check if an image meets policy requirements.

    Returns list of policy violations (empty if compliant).
    """
    violations = []

    # Check for mutable tags
    tag = image_ref.get("tag")
    if tag and tag.lower() in MUTABLE_TAGS:
        violations.append(f"Mutable tag '{tag}' can change unexpectedly")

    # Check for digest pinning
    if require_digest and not image_ref["is_pinned"]:
        violations.append("Image not pinned by digest (sha256)")

    # Check for trusted registry
    registry = image_ref.get("registry", "")
    is_trusted = any(
        registry.startswith(tr) or registry == tr for tr in trusted_registries
    )
    if trusted_registries and not is_trusted:
        violations.append(f"Untrusted registry: {registry}")

    return violations


def extract_containers(workload: dict) -> list:
    """Extract container images from a workload resource."""
    containers = []

    # Get pod spec based on resource type
    spec = workload.get("spec", {})
    pod_spec = spec.get("template", {}).get("spec", {})

    # Regular containers
    for container in pod_spec.get("containers", []):
        containers.append(
            {
                "name": container.get("name", "unknown"),
                "image": container.get("image", ""),
                "type": "container",
            }
        )

    # Init containers
    for container in pod_spec.get("initContainers", []):
        containers.append(
            {
                "name": container.get("name", "unknown"),
                "image": container.get("image", ""),
                "type": "initContainer",
            }
        )

    return containers


def audit_workloads(
    workloads: list, trusted_registries: list, require_digest: bool
) -> list:
    """Audit all workloads for image policy compliance."""
    findings = []

    for workload in workloads:
        metadata = workload.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")
        resource_type = workload.get("_resource_type", "unknown")

        containers = extract_containers(workload)

        for container in containers:
            image = container.get("image", "")
            if not image:
                continue

            image_ref = parse_image_ref(image)
            violations = check_image_policy(
                image_ref, trusted_registries, require_digest
            )

            finding = {
                "namespace": namespace,
                "resource_type": resource_type,
                "resource_name": name,
                "container_name": container["name"],
                "container_type": container["type"],
                "image": image,
                "image_ref": image_ref,
                "violations": violations,
                "compliant": len(violations) == 0,
            }

            findings.append(finding)

    return findings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all OK, 1 = violations found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes workload images for security best practices"
    )
    parser.add_argument(
        "-n", "--namespace", help="Namespace to audit (default: all namespaces)"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show images with policy violations",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed image information"
    )
    parser.add_argument(
        "--no-require-digest",
        action="store_true",
        help="Do not require images to be pinned by digest",
    )
    parser.add_argument(
        "--trusted-registry",
        action="append",
        dest="trusted_registries",
        metavar="REGISTRY",
        help="Add a trusted registry (can be specified multiple times)",
    )
    parser.add_argument(
        "--skip-registry-check",
        action="store_true",
        help="Skip trusted registry validation",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Build trusted registries list
    if opts.skip_registry_check:
        trusted_registries = []
    else:
        trusted_registries = DEFAULT_TRUSTED_REGISTRIES.copy()
        if opts.trusted_registries:
            trusted_registries.extend(opts.trusted_registries)

    # Get workloads
    workloads = []
    resource_types = ["deployments", "statefulsets", "daemonsets", "jobs"]

    for resource_type in resource_types:
        cmd = ["kubectl", "get", resource_type, "-o", "json"]
        if opts.namespace:
            cmd.extend(["-n", opts.namespace])
        else:
            cmd.append("--all-namespaces")

        try:
            result = context.run(cmd)
            if result.returncode != 0:
                continue
            data = json.loads(result.stdout)
            for item in data.get("items", []):
                item["_resource_type"] = resource_type
                workloads.append(item)
        except (json.JSONDecodeError, Exception):
            continue

    if not workloads:
        print("No workloads found.")
        output.set_summary("workloads=0, violations=0")
        return 0

    # Audit workloads
    require_digest = not opts.no_require_digest
    findings = audit_workloads(workloads, trusted_registries, require_digest)

    # Filter if requested
    if opts.warn_only:
        findings = [f for f in findings if not f["compliant"]]

    # Count results
    compliant_count = sum(1 for f in findings if f["compliant"])
    violation_count = sum(1 for f in findings if not f["compliant"])

    # Format output
    if opts.format == "json":
        print(json.dumps(findings, indent=2))
    elif opts.format == "table":
        if findings:
            header = f"{'NAMESPACE':<15} {'RESOURCE':<30} {'CONTAINER':<20} {'STATUS':<10} {'VIOLATIONS':<30}"
            separator = "-" * 110
            print(header)
            print(separator)

            for finding in findings:
                ns = finding["namespace"][:14]
                resource = f"{finding['resource_type'][:4]}/{finding['resource_name']}"[
                    :29
                ]
                container = finding["container_name"][:19]
                status = "OK" if finding["compliant"] else "FAIL"
                violations = (
                    "; ".join(finding["violations"])[:29]
                    if finding["violations"]
                    else "-"
                )
                print(
                    f"{ns:<15} {resource:<30} {container:<20} {status:<10} {violations:<30}"
                )

            print(separator)
            print(
                f"Total: {len(findings)} images, {compliant_count} compliant, {violation_count} violations"
            )
        else:
            print("No images found.")
    else:  # plain format
        # Group by namespace
        by_namespace = {}
        for finding in findings:
            ns = finding["namespace"]
            if ns not in by_namespace:
                by_namespace[ns] = []
            by_namespace[ns].append(finding)

        for namespace in sorted(by_namespace.keys()):
            ns_findings = by_namespace[namespace]
            print(f"Namespace: {namespace}")
            print("-" * 40)

            for finding in ns_findings:
                status = "+" if finding["compliant"] else "!"
                resource = f"{finding['resource_type']}/{finding['resource_name']}"
                container = finding["container_name"]

                print(f"[{status}] {resource}")
                print(f"    Container: {container} ({finding['container_type']})")
                print(f"    Image: {finding['image']}")

                if opts.verbose:
                    ref = finding["image_ref"]
                    print(f"    Registry: {ref['registry']}")
                    print(f"    Tag: {ref['tag'] or 'none'}")
                    print(f"    Pinned: {'Yes' if ref['is_pinned'] else 'No'}")

                if finding["violations"]:
                    for violation in finding["violations"]:
                        print(f"    Violation: {violation}")

                print()

        print(f"Summary: {compliant_count} compliant, {violation_count} violations")

    output.set_summary(
        f"images={len(findings)}, compliant={compliant_count}, violations={violation_count}"
    )

    # Exit code based on status
    return 1 if violation_count > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
