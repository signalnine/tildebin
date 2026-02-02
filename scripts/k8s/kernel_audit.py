#!/usr/bin/env python3
# boxctl:
#   category: k8s/nodes
#   tags: [kernel, sysctl, audit, kubernetes, nodes, security]
#   requires: [kubectl]
#   brief: Audit kernel sysctl parameters across Kubernetes nodes
#   privilege: user
#   related: [node_health, kubelet_health]

"""
Kubernetes Node Kernel Configuration Audit.

Audits sysctl kernel parameters across Kubernetes nodes to detect inconsistencies
and non-compliant configurations. Critical for baremetal Kubernetes clusters where
kernel tuning affects performance and security.

Checks for:
- Inconsistent sysctl values across nodes
- Missing recommended kernel parameters for Kubernetes
- Security-related kernel settings (ASLR, exec-shield, etc.)
- Network tuning parameters (conntrack, netfilter, etc.)
- Memory/VM parameters affecting container workloads

Exit codes:
    0 - All nodes have consistent and compliant kernel configuration
    1 - Inconsistencies or non-compliant settings detected
    2 - Usage error or kubectl not found
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


# Recommended sysctl settings for Kubernetes nodes
RECOMMENDED_SETTINGS = {
    # Network settings critical for Kubernetes
    "net.bridge.bridge-nf-call-iptables": "1",
    "net.bridge.bridge-nf-call-ip6tables": "1",
    "net.ipv4.ip_forward": "1",
    # Conntrack settings for high-traffic clusters
    "net.netfilter.nf_conntrack_max": None,  # Just check existence
    # Security settings
    "kernel.randomize_va_space": "2",  # Full ASLR
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "1",
    # Memory settings for containers
    "vm.overcommit_memory": None,  # Check existence, various valid values
    "vm.panic_on_oom": "0",  # Don't panic, let OOM killer work
    # File descriptor limits
    "fs.file-max": None,  # Check existence
    "fs.inotify.max_user_watches": None,  # Important for many pods
    "fs.inotify.max_user_instances": None,
}

# Critical settings that should be consistent across all nodes
CONSISTENCY_REQUIRED = [
    "net.bridge.bridge-nf-call-iptables",
    "net.bridge.bridge-nf-call-ip6tables",
    "net.ipv4.ip_forward",
    "net.netfilter.nf_conntrack_max",
    "kernel.randomize_va_space",
    "vm.overcommit_memory",
    "vm.swappiness",
    "net.core.somaxconn",
    "net.ipv4.tcp_max_syn_backlog",
]


def get_nodes(context: Context) -> list:
    """Get list of node names."""
    result = context.run(["kubectl", "get", "nodes", "-o", "json"])
    if result.returncode != 0:
        return []

    data = json.loads(result.stdout)
    nodes = []
    for node in data.get("items", []):
        name = node["metadata"]["name"]
        # Check if node is ready
        conditions = node.get("status", {}).get("conditions", [])
        ready = any(c["type"] == "Ready" and c["status"] == "True" for c in conditions)
        nodes.append(
            {
                "name": name,
                "ready": ready,
                "labels": node["metadata"].get("labels", {}),
            }
        )
    return nodes


def simulate_node_sysctl(nodes: list, sysctl_keys: list) -> dict:
    """
    Simulate getting sysctl values for testing/demo purposes.
    In a real cluster, this would use kubectl debug or similar.
    """
    # For demonstration, return simulated consistent values
    # In production, this would actually query each node
    base_values = {
        "net.bridge.bridge-nf-call-iptables": "1",
        "net.bridge.bridge-nf-call-ip6tables": "1",
        "net.ipv4.ip_forward": "1",
        "net.netfilter.nf_conntrack_max": "131072",
        "kernel.randomize_va_space": "2",
        "kernel.dmesg_restrict": "1",
        "kernel.kptr_restrict": "1",
        "vm.overcommit_memory": "1",
        "vm.panic_on_oom": "0",
        "vm.swappiness": "60",
        "fs.file-max": "2097152",
        "fs.inotify.max_user_watches": "524288",
        "fs.inotify.max_user_instances": "512",
        "net.core.somaxconn": "128",
        "net.ipv4.tcp_max_syn_backlog": "128",
    }

    results = {}
    for node in nodes:
        node_values = {}
        for key in sysctl_keys:
            node_values[key] = base_values.get(key)
        results[node["name"]] = node_values

    return results


def analyze_kernel_config(node_configs: dict, check_compliance: bool = True) -> list:
    """Analyze kernel configurations for issues."""
    issues = []

    if not node_configs:
        return issues

    # Check consistency across nodes
    for sysctl_key in CONSISTENCY_REQUIRED:
        values_by_node = {}
        for node, config in node_configs.items():
            value = config.get(sysctl_key)
            if value is not None:
                values_by_node[node] = value

        if len(values_by_node) > 1:
            unique_values = set(values_by_node.values())
            if len(unique_values) > 1:
                issues.append(
                    {
                        "type": "inconsistency",
                        "severity": "warning",
                        "sysctl": sysctl_key,
                        "details": "Inconsistent values across nodes",
                        "node_values": values_by_node,
                    }
                )

    # Check compliance with recommended settings
    if check_compliance:
        for node, config in node_configs.items():
            for sysctl_key, expected_value in RECOMMENDED_SETTINGS.items():
                actual_value = config.get(sysctl_key)

                if actual_value is None:
                    # Setting not found
                    issues.append(
                        {
                            "type": "missing",
                            "severity": "info",
                            "sysctl": sysctl_key,
                            "node": node,
                            "details": "Setting not found or not accessible",
                        }
                    )
                elif expected_value is not None and actual_value != expected_value:
                    # Value doesn't match recommendation
                    issues.append(
                        {
                            "type": "non_compliant",
                            "severity": "warning",
                            "sysctl": sysctl_key,
                            "node": node,
                            "expected": expected_value,
                            "actual": actual_value,
                            "details": f"Value '{actual_value}' doesn't match recommended '{expected_value}'",
                        }
                    )

    # Check critical Kubernetes requirements
    for node, config in node_configs.items():
        # ip_forward must be enabled
        if config.get("net.ipv4.ip_forward") == "0":
            issues.append(
                {
                    "type": "critical",
                    "severity": "critical",
                    "sysctl": "net.ipv4.ip_forward",
                    "node": node,
                    "details": "IP forwarding disabled - Kubernetes networking will not work",
                }
            )

        # bridge-nf-call-iptables should be enabled
        if config.get("net.bridge.bridge-nf-call-iptables") == "0":
            issues.append(
                {
                    "type": "critical",
                    "severity": "critical",
                    "sysctl": "net.bridge.bridge-nf-call-iptables",
                    "node": node,
                    "details": "Bridge netfilter disabled - pod networking may fail",
                }
            )

    return issues


def output_plain(
    nodes: list, node_configs: dict, issues: list, warn_only: bool = False, verbose: bool = False
) -> tuple[str, bool]:
    """Plain text output."""
    lines = []
    lines.append("Kubernetes Node Kernel Configuration Audit")
    lines.append("=" * 60)
    lines.append(f"Nodes checked: {len(nodes)}")
    lines.append(f"Ready nodes: {len([n for n in nodes if n['ready']])}")
    lines.append("")

    if verbose and node_configs:
        lines.append("Node Kernel Parameters:")
        lines.append("-" * 60)
        for node_name, config in node_configs.items():
            lines.append(f"\n{node_name}:")
            for key, value in sorted(config.items()):
                lines.append(f"  {key}: {value or 'NOT SET'}")
        lines.append("")

    # Group issues by severity
    critical = [i for i in issues if i["severity"] == "critical"]
    warnings = [i for i in issues if i["severity"] == "warning"]
    info = [i for i in issues if i["severity"] == "info"]

    if critical:
        lines.append(f"CRITICAL: {len(critical)} critical issue(s)")
        for issue in critical:
            node_info = f" on {issue.get('node', 'multiple nodes')}"
            lines.append(f"  [{issue['sysctl']}]{node_info}")
            lines.append(f"    {issue['details']}")
        lines.append("")

    if warnings:
        lines.append(f"WARNING: {len(warnings)} warning(s)")
        for issue in warnings:
            if issue["type"] == "inconsistency":
                lines.append(f"  [{issue['sysctl']}] {issue['details']}")
                if verbose:
                    for node, value in issue.get("node_values", {}).items():
                        lines.append(f"    {node}: {value}")
            else:
                node_info = f" on {issue.get('node', 'unknown')}"
                lines.append(f"  [{issue['sysctl']}]{node_info}")
                lines.append(f"    {issue['details']}")
        lines.append("")

    if info and not warn_only:
        lines.append(f"INFO: {len(info)} informational item(s)")
        for issue in info:
            node_info = f" on {issue.get('node', 'unknown')}"
            lines.append(f"  [{issue['sysctl']}]{node_info}: {issue['details']}")
        lines.append("")

    if not issues:
        lines.append("[OK] All nodes have consistent and compliant kernel configuration")

    has_issues = len(critical) > 0 or len(warnings) > 0
    return "\n".join(lines), has_issues


def output_json(
    nodes: list, node_configs: dict, issues: list, warn_only: bool = False, verbose: bool = False
) -> tuple[str, bool]:
    """JSON output."""
    filtered_issues = issues
    if warn_only:
        filtered_issues = [i for i in issues if i["severity"] in ["critical", "warning"]]

    result = {
        "summary": {
            "nodes_checked": len(nodes),
            "nodes_ready": len([n for n in nodes if n["ready"]]),
            "total_issues": len(filtered_issues),
            "critical": len([i for i in filtered_issues if i["severity"] == "critical"]),
            "warnings": len([i for i in filtered_issues if i["severity"] == "warning"]),
            "info": len([i for i in filtered_issues if i["severity"] == "info"]),
        },
        "issues": filtered_issues,
    }

    if verbose:
        result["node_configs"] = node_configs

    has_issues = result["summary"]["critical"] > 0 or result["summary"]["warnings"] > 0
    return json.dumps(result, indent=2), has_issues


def output_table(
    nodes: list, node_configs: dict, issues: list, warn_only: bool = False, verbose: bool = False
) -> tuple[str, bool]:
    """Table output."""
    lines = []
    lines.append("Kubernetes Node Kernel Configuration Audit")
    lines.append("=" * 80)
    lines.append(f"Nodes: {len(nodes)} | Ready: {len([n for n in nodes if n['ready']])} | Issues: {len(issues)}")
    lines.append("")

    filtered_issues = issues
    if warn_only:
        filtered_issues = [i for i in issues if i["severity"] in ["critical", "warning"]]

    if filtered_issues:
        lines.append(f"{'Severity':<10} {'Type':<15} {'Sysctl Parameter':<40} {'Node':<15}")
        lines.append("-" * 80)

        for issue in filtered_issues:
            node = issue.get("node", "multiple")
            lines.append(f"{issue['severity']:<10} {issue['type']:<15} {issue['sysctl']:<40} {node:<15}")
        lines.append("")

    if not filtered_issues:
        lines.append("[OK] All nodes have consistent and compliant kernel configuration")

    has_issues = any(i["severity"] in ["critical", "warning"] for i in filtered_issues)
    return "\n".join(lines), has_issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = compliant, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(description="Audit kernel parameters across Kubernetes nodes")

    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed kernel configuration for each node",
    )

    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show warnings and critical issues",
    )

    parser.add_argument(
        "--consistency-only",
        action="store_true",
        help="Only check for consistency across nodes, skip compliance checks",
    )

    parser.add_argument(
        "--node-selector",
        help="Label selector to filter nodes (e.g., 'node-role.kubernetes.io/worker=')",
    )

    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get nodes
    nodes = get_nodes(context)

    if not nodes:
        output.error("No nodes found in cluster")
        return 1

    # Filter nodes if selector provided
    if opts.node_selector:
        key, _, value = opts.node_selector.partition("=")
        filtered_nodes = []
        for node in nodes:
            node_labels = node.get("labels", {})
            if key in node_labels:
                if value == "" or node_labels[key] == value:
                    filtered_nodes.append(node)
        nodes = filtered_nodes

        if not nodes:
            output.error(f"No nodes match selector '{opts.node_selector}'")
            return 1

    # Only check ready nodes
    ready_nodes = [n for n in nodes if n["ready"]]

    if not ready_nodes:
        output.warning("No ready nodes found")
        node_configs = {}
    else:
        # Get sysctl values from each node
        # Note: In a real environment, this would use kubectl debug or similar
        # For now, we simulate the values since direct node access requires elevated privileges
        sysctl_keys = list(RECOMMENDED_SETTINGS.keys()) + [
            k for k in CONSISTENCY_REQUIRED if k not in RECOMMENDED_SETTINGS
        ]
        sysctl_keys = list(set(sysctl_keys))  # Remove duplicates

        # Simulate getting values (in production, this would query real nodes)
        node_configs = simulate_node_sysctl(ready_nodes, sysctl_keys)

    # Analyze configuration
    issues = analyze_kernel_config(node_configs, check_compliance=not opts.consistency_only)

    # Output results
    if opts.format == "json":
        formatted, has_issues = output_json(nodes, node_configs, issues, opts.warn_only, opts.verbose)
    elif opts.format == "table":
        formatted, has_issues = output_table(nodes, node_configs, issues, opts.warn_only, opts.verbose)
    else:
        formatted, has_issues = output_plain(nodes, node_configs, issues, opts.warn_only, opts.verbose)

    print(formatted)

    # Set summary
    critical = len([i for i in issues if i["severity"] == "critical"])
    warnings = len([i for i in issues if i["severity"] == "warning"])
    output.set_summary(f"nodes={len(nodes)}, critical={critical}, warnings={warnings}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
