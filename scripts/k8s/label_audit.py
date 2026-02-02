#!/usr/bin/env python3
# boxctl:
#   category: k8s/nodes
#   tags: [labels, annotations, audit, kubernetes, nodes, scheduling]
#   requires: [kubectl]
#   brief: Audit node labels and annotations for consistency and compliance
#   privilege: user
#   related: [node_health, node_taint_analyzer]

"""
Kubernetes Node Label and Annotation Auditor.

Audits node labels and annotations for consistency and compliance:
- Identifies nodes missing required labels (topology, role, etc.)
- Detects inconsistent label values across similar nodes
- Finds deprecated or obsolete labels
- Validates label format and naming conventions
- Reports annotation issues (too large, sensitive data)

Critical for large baremetal clusters where proper node labeling
ensures correct pod scheduling and resource allocation.

Exit codes:
    0 - All nodes pass audit checks
    1 - Audit issues detected (missing labels, inconsistencies)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import re
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Standard Kubernetes labels that should typically be present
STANDARD_LABELS = {
    "kubernetes.io/hostname": "Node hostname",
    "kubernetes.io/os": "Operating system",
    "kubernetes.io/arch": "CPU architecture",
}

# Topology labels for proper scheduling
TOPOLOGY_LABELS = {
    "topology.kubernetes.io/zone": "Availability zone",
    "topology.kubernetes.io/region": "Region",
}

# Deprecated labels that should be migrated
DEPRECATED_LABELS = {
    "beta.kubernetes.io/arch": "Use kubernetes.io/arch instead",
    "beta.kubernetes.io/os": "Use kubernetes.io/os instead",
    "failure-domain.beta.kubernetes.io/zone": "Use topology.kubernetes.io/zone instead",
    "failure-domain.beta.kubernetes.io/region": "Use topology.kubernetes.io/region instead",
    "node-role.kubernetes.io/master": "Use node-role.kubernetes.io/control-plane instead",
}

# Label value pattern (RFC 1123)
LABEL_VALUE_PATTERN = re.compile(r"^([a-zA-Z0-9]([-_.a-zA-Z0-9]*[a-zA-Z0-9])?)?$")

# Maximum annotation size (256KB is Kubernetes limit, warn at 100KB)
ANNOTATION_SIZE_WARN = 100 * 1024
ANNOTATION_SIZE_MAX = 256 * 1024


def check_label_format(key: str, value: str) -> list[str]:
    """Check if label key and value follow Kubernetes naming conventions."""
    issues = []

    # Check key length
    if len(key) > 253 + 1 + 63:  # prefix/name, prefix max 253, name max 63
        issues.append(f"Label key too long: {key[:50]}...")

    # Check value format
    if len(value) > 63:
        issues.append(f"Label value too long for {key}: {value[:30]}...")

    if value and not LABEL_VALUE_PATTERN.match(value):
        issues.append(f"Invalid label value format for {key}: {value[:30]}")

    return issues


def audit_node_labels(node: dict[str, Any], required_labels: set[str]) -> dict[str, Any]:
    """Audit a single node's labels."""
    metadata = node.get("metadata", {})
    name = metadata.get("name", "unknown")
    labels = metadata.get("labels", {})
    annotations = metadata.get("annotations", {})

    issues = []
    warnings = []
    info = []

    # Check for required labels
    for label in required_labels:
        if label not in labels:
            issues.append(f"Missing required label: {label}")

    # Check for standard labels
    for label, description in STANDARD_LABELS.items():
        if label not in labels:
            warnings.append(f"Missing standard label: {label} ({description})")

    # Check for topology labels
    has_zone = "topology.kubernetes.io/zone" in labels
    has_region = "topology.kubernetes.io/region" in labels
    if not has_zone:
        warnings.append("Missing topology zone label (topology.kubernetes.io/zone)")
    if not has_region:
        warnings.append("Missing topology region label (topology.kubernetes.io/region)")

    # Check for deprecated labels
    for label, migration in DEPRECATED_LABELS.items():
        if label in labels:
            warnings.append(f"Deprecated label: {label} - {migration}")

    # Check label format
    for key, value in labels.items():
        format_issues = check_label_format(key, str(value))
        issues.extend(format_issues)

    # Detect node roles
    roles = []
    for label in labels:
        if label.startswith("node-role.kubernetes.io/"):
            role = label.split("/")[-1]
            roles.append(role)

    if not roles:
        info.append("No role labels detected")

    # Check annotations size
    total_annotation_size = 0
    for key, value in annotations.items():
        size = len(key) + len(str(value))
        total_annotation_size += size

        if size > ANNOTATION_SIZE_WARN:
            warnings.append(f"Large annotation: {key} ({size / 1024:.1f}KB)")

    if total_annotation_size > ANNOTATION_SIZE_MAX:
        issues.append(f"Total annotation size exceeds limit: {total_annotation_size / 1024:.1f}KB")
    elif total_annotation_size > ANNOTATION_SIZE_WARN:
        warnings.append(f"Total annotation size approaching limit: {total_annotation_size / 1024:.1f}KB")

    return {
        "name": name,
        "labels": labels,
        "label_count": len(labels),
        "annotation_count": len(annotations),
        "annotation_size_kb": round(total_annotation_size / 1024, 2),
        "roles": roles,
        "issues": issues,
        "warnings": warnings,
        "info": info,
        "has_issues": len(issues) > 0,
        "has_warnings": len(warnings) > 0,
    }


def check_label_consistency(node_audits: list[dict[str, Any]]) -> list[str]:
    """Check for inconsistent label values across nodes."""
    inconsistencies = []

    # Group nodes by role
    role_groups = defaultdict(list)
    for audit in node_audits:
        for role in audit["roles"]:
            role_groups[role].append(audit)

    # Check consistency within role groups
    for role, nodes in role_groups.items():
        if len(nodes) < 2:
            continue

        # Collect all labels used by nodes in this role
        label_values = defaultdict(set)
        for node in nodes:
            for key, value in node["labels"].items():
                label_values[key].add(str(value))

        # Find labels with inconsistent values (excluding expected variations)
        expected_varying = {
            "kubernetes.io/hostname",
            "node.kubernetes.io/instance-type",
        }

        for key, values in label_values.items():
            if key in expected_varying:
                continue
            if len(values) > 1 and len(values) < len(nodes):
                # Some but not all nodes have different values
                inconsistencies.append(f"Inconsistent label '{key}' across {role} nodes: {sorted(values)}")

    return inconsistencies


def format_plain(
    audits: list[dict[str, Any]], inconsistencies: list[str], warn_only: bool, verbose: bool
) -> str:
    """Format output as plain text."""
    lines = []
    lines.append("Kubernetes Node Label Audit")
    lines.append("=" * 50)
    lines.append("")

    # Summary
    total = len(audits)
    with_issues = sum(1 for a in audits if a["has_issues"])
    with_warnings = sum(1 for a in audits if a["has_warnings"])

    lines.append(f"Nodes audited: {total}")
    lines.append(f"Nodes with issues: {with_issues}")
    lines.append(f"Nodes with warnings: {with_warnings}")
    lines.append("")

    # Per-node details
    for audit in audits:
        if warn_only and not audit["has_issues"] and not audit["has_warnings"]:
            continue

        status = "FAIL" if audit["has_issues"] else ("WARN" if audit["has_warnings"] else "OK")
        lines.append(f"[{status}] {audit['name']}")
        lines.append(
            f"  Labels: {audit['label_count']} | Annotations: {audit['annotation_count']} "
            f"({audit['annotation_size_kb']}KB)"
        )

        if audit["roles"]:
            lines.append(f"  Roles: {', '.join(audit['roles'])}")

        if audit["issues"]:
            for issue in audit["issues"]:
                lines.append(f"  [!] {issue}")

        if audit["warnings"]:
            for warning in audit["warnings"]:
                lines.append(f"  [*] {warning}")

        if verbose and audit["info"]:
            for info in audit["info"]:
                lines.append(f"  [i] {info}")

        lines.append("")

    # Consistency issues
    if inconsistencies:
        lines.append("Label Consistency Issues:")
        for issue in inconsistencies:
            lines.append(f"  [!] {issue}")
        lines.append("")

    # Final status
    if with_issues == 0 and not inconsistencies:
        lines.append("[OK] All nodes pass audit checks")

    return "\n".join(lines)


def format_json(
    audits: list[dict[str, Any]], inconsistencies: list[str], warn_only: bool, verbose: bool
) -> str:
    """Format output as JSON."""
    if warn_only:
        audits = [a for a in audits if a["has_issues"] or a["has_warnings"]]

    total = len(audits)
    output = {
        "summary": {
            "total_nodes": total,
            "nodes_with_issues": sum(1 for a in audits if a["has_issues"]),
            "nodes_with_warnings": sum(1 for a in audits if a["has_warnings"]),
            "consistency_issues": len(inconsistencies),
        },
        "nodes": audits,
        "consistency_issues": inconsistencies,
        "healthy": sum(1 for a in audits if a["has_issues"]) == 0 and len(inconsistencies) == 0,
    }

    return json.dumps(output, indent=2)


def format_table(
    audits: list[dict[str, Any]], inconsistencies: list[str], warn_only: bool, verbose: bool
) -> str:
    """Format output as table."""
    lines = []

    # Header
    lines.append("+" + "-" * 90 + "+")
    lines.append("| Kubernetes Node Label Audit" + " " * 61 + "|")
    lines.append("+" + "-" * 90 + "+")
    lines.append(f"| {'Node':<30} | {'Status':<8} | {'Labels':<8} | {'Roles':<20} | {'Issues':<10} |")
    lines.append("+" + "-" * 90 + "+")

    for audit in audits:
        if warn_only and not audit["has_issues"] and not audit["has_warnings"]:
            continue

        status = "FAIL" if audit["has_issues"] else ("WARN" if audit["has_warnings"] else "OK")
        roles = ", ".join(audit["roles"])[:20] if audit["roles"] else "-"
        issue_count = len(audit["issues"]) + len(audit["warnings"])

        name = audit["name"][:30]
        lines.append(
            f"| {name:<30} | {status:<8} | {audit['label_count']:<8} | " f"{roles:<20} | {issue_count:<10} |"
        )

    lines.append("+" + "-" * 90 + "+")

    # Issues summary
    all_issues = []
    for audit in audits:
        for issue in audit["issues"]:
            all_issues.append(f"{audit['name']}: {issue}")
    all_issues.extend(inconsistencies)

    if all_issues:
        lines.append(f"| {'Issues':<88} |")
        lines.append("+" + "-" * 90 + "+")
        for issue in all_issues[:10]:  # Limit display
            issue_text = issue[:88]
            lines.append(f"| {issue_text:<88} |")
        if len(all_issues) > 10:
            lines.append(f"| {'... and ' + str(len(all_issues) - 10) + ' more issues':<88} |")
        lines.append("+" + "-" * 90 + "+")
    else:
        lines.append(f"| {'All nodes pass audit checks':<88} |")
        lines.append("+" + "-" * 90 + "+")

    return "\n".join(lines)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = pass, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(description="Audit Kubernetes node labels and annotations")

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
        help="Only show nodes with issues or warnings",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed information",
    )

    parser.add_argument(
        "--require-label",
        "-l",
        action="append",
        default=[],
        dest="required_labels",
        metavar="LABEL",
        help="Label that must be present on all nodes (can be specified multiple times)",
    )

    parser.add_argument(
        "--skip-consistency",
        action="store_true",
        help="Skip label consistency checks across similar nodes",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get nodes
    try:
        result = context.run(["kubectl", "get", "nodes", "-o", "json"])
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        data = json.loads(result.stdout)
        nodes = data.get("items", [])
    except Exception as e:
        output.error(f"Failed to get nodes: {e}")
        return 2

    if not nodes:
        output.error("No nodes found in cluster")
        return 1

    # Audit each node
    required_labels = set(opts.required_labels)
    audits = [audit_node_labels(node, required_labels) for node in nodes]

    # Check consistency
    inconsistencies = []
    if not opts.skip_consistency:
        inconsistencies = check_label_consistency(audits)

    # Format output
    if opts.format == "json":
        formatted = format_json(audits, inconsistencies, opts.warn_only, opts.verbose)
    elif opts.format == "table":
        formatted = format_table(audits, inconsistencies, opts.warn_only, opts.verbose)
    else:
        formatted = format_plain(audits, inconsistencies, opts.warn_only, opts.verbose)

    print(formatted)

    # Determine exit code
    has_issues = any(a["has_issues"] for a in audits) or len(inconsistencies) > 0
    issues_count = sum(1 for a in audits if a["has_issues"])
    output.set_summary(f"nodes={len(audits)}, issues={issues_count}, consistency_issues={len(inconsistencies)}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
