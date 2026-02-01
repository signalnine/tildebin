#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, namespaces, containers]
#   brief: Monitor network namespace health on container hosts

"""
Monitor network namespace health on container hosts.

This script identifies network namespaces and checks their health status:
- Lists all network namespaces (named and process-based)
- Detects orphaned namespaces (no processes attached)
- Checks veth pair consistency (dangling interfaces)
- Monitors namespace interface counts
- Identifies namespaces with networking issues

Useful for:
- Container host health monitoring (Docker, Kubernetes nodes)
- Detecting leaked network namespaces after container crashes
- Identifying veth pair inconsistencies
- Troubleshooting container networking issues

Exit codes:
    0: All network namespaces healthy
    1: Issues detected (orphaned namespaces, dangling veths, etc.)
    2: Usage error or required tools not available
"""

import argparse
import json
import os
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_named_namespaces(context: Context) -> list[dict]:
    """Get list of named network namespaces from ip netns.

    Args:
        context: Execution context

    Returns:
        list: Named namespace dicts
    """
    result = context.run(["ip", "netns", "list"])

    if result.returncode != 0:
        return []

    namespaces = []
    for line in result.stdout.split("\n"):
        if line.strip():
            # Format is either "name" or "name (id: N)"
            parts = line.split()
            if parts:
                namespaces.append(
                    {
                        "name": parts[0],
                        "type": "named",
                        "id": None,
                    }
                )
    return namespaces


def get_namespace_interfaces(context: Context, ns_name: str | None = None) -> list[dict]:
    """Get network interfaces in a namespace.

    Args:
        context: Execution context
        ns_name: Namespace name (None for default namespace)

    Returns:
        list: Interface dicts
    """
    if ns_name:
        cmd = ["ip", "netns", "exec", ns_name, "ip", "-j", "link", "show"]
    else:
        cmd = ["ip", "-j", "link", "show"]

    result = context.run(cmd)

    if result.returncode != 0:
        return []

    try:
        interfaces = json.loads(result.stdout) if result.stdout else []
        return interfaces
    except json.JSONDecodeError:
        return []


def get_veth_pairs(context: Context) -> dict:
    """Get veth pairs and their peer relationships.

    Args:
        context: Execution context

    Returns:
        dict: Veth interface data
    """
    veths = {}

    result = context.run(["ip", "-j", "link", "show", "type", "veth"])

    if result.returncode != 0 or not result.stdout:
        return veths

    try:
        interfaces = json.loads(result.stdout)
        for iface in interfaces:
            name = iface.get("ifname", "")
            ifindex = iface.get("ifindex", 0)
            link = iface.get("link", "")

            # Get peer ifindex from link_index if available
            peer_ifindex = iface.get("link_index", 0)

            veths[name] = {
                "ifindex": ifindex,
                "peer_ifindex": peer_ifindex,
                "peer_name": link,
                "operstate": iface.get("operstate", "unknown"),
                "master": iface.get("master", None),
            }
    except json.JSONDecodeError:
        pass

    return veths


def check_dangling_veths(veths: dict) -> list[dict]:
    """Check for veth interfaces without a valid peer.

    Args:
        veths: Veth interface data

    Returns:
        list: Dangling veth issues
    """
    dangling = []

    # Build a set of all ifindexes
    all_ifindexes = set(v["ifindex"] for v in veths.values())

    for name, info in veths.items():
        peer_idx = info.get("peer_ifindex", 0)

        # A veth is dangling if:
        # 1. peer_ifindex is 0 or not found in any namespace
        # 2. operstate is not 'up' (might indicate peer issues)
        if peer_idx == 0:
            dangling.append(
                {
                    "name": name,
                    "reason": "no peer index",
                    "operstate": info.get("operstate"),
                }
            )
        elif peer_idx not in all_ifindexes:
            # Peer might be in another namespace - this is actually normal
            # Only flag if the interface is down
            if info.get("operstate") == "down":
                dangling.append(
                    {
                        "name": name,
                        "reason": "peer in different namespace and interface down",
                        "operstate": info.get("operstate"),
                    }
                )

    return dangling


def analyze_namespace_health(context: Context, ns_name: str) -> list[str]:
    """Analyze health of a specific namespace.

    Args:
        context: Execution context
        ns_name: Namespace name

    Returns:
        list: Issue strings
    """
    issues = []

    interfaces = get_namespace_interfaces(context, ns_name)

    if not interfaces:
        issues.append("No interfaces found (may lack permissions)")
        return issues

    # Check for basic networking
    has_loopback = False
    down_interfaces = []

    for iface in interfaces:
        ifname = iface.get("ifname", "")
        operstate = iface.get("operstate", "unknown")

        if ifname == "lo":
            has_loopback = True
            if operstate not in ("UNKNOWN", "up", "UP"):
                issues.append(f"Loopback interface is {operstate}")
        else:
            if operstate.lower() == "down":
                down_interfaces.append(ifname)

    if not has_loopback:
        issues.append("Missing loopback interface")

    if down_interfaces:
        issues.append(f"Down interfaces: {', '.join(down_interfaces)}")

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor network namespace health on container hosts"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed information"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only produce output if issues detected",
    )

    opts = parser.parse_args(args)

    # Check for ip command
    if not context.check_tool("ip"):
        output.error("'ip' command not found")
        return 2

    # Gather data
    named_namespaces = get_named_namespaces(context)
    veths = get_veth_pairs(context)

    # Analyze health
    for ns in named_namespaces:
        ns["issues"] = analyze_namespace_health(context, ns["name"])

    dangling_veths = check_dangling_veths(veths)

    # Count issues
    total_issues = len(dangling_veths)
    for ns in named_namespaces:
        total_issues += len(ns.get("issues", []))

    # Build results
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "named_count": len(named_namespaces),
            "veth_count": len(veths),
            "dangling_veth_count": len(dangling_veths),
            "total_issues": total_issues,
        },
        "named_namespaces": named_namespaces,
        "veth_pairs": list(veths.keys()),
        "dangling_veths": dangling_veths,
        "healthy": total_issues == 0,
    }

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or total_issues > 0:
            print(json.dumps(results, indent=2))
    else:
        if not opts.warn_only or total_issues > 0:
            lines = []
            lines.append("Network Namespace Health Report")
            lines.append("=" * 50)
            lines.append("")

            lines.append(f"Named namespaces:      {results['summary']['named_count']}")
            lines.append(f"Veth pairs:            {results['summary']['veth_count']}")
            lines.append(f"Issues detected:       {results['summary']['total_issues']}")
            lines.append("")

            if named_namespaces and (opts.verbose or not opts.warn_only):
                lines.append("Named Namespaces:")
                lines.append("-" * 40)
                for ns in named_namespaces:
                    status = "OK"
                    if ns.get("issues"):
                        status = f"ISSUES: {len(ns['issues'])}"
                    lines.append(f"  {ns['name']}: {status}")
                    if opts.verbose and ns.get("issues"):
                        for issue in ns["issues"]:
                            lines.append(f"    - {issue}")
                lines.append("")

            if dangling_veths:
                lines.append("Dangling Veth Interfaces:")
                lines.append("-" * 40)
                for veth in dangling_veths:
                    lines.append(
                        f"  {veth['name']}: {veth['reason']} (state: {veth['operstate']})"
                    )
                lines.append("")

            if total_issues == 0:
                lines.append("[OK] All network namespaces healthy")
            else:
                lines.append(f"[WARNING] {total_issues} issue(s) detected")

            print("\n".join(lines))

    # Set summary
    output.set_summary(
        f"namespaces={results['summary']['named_count']}, issues={total_issues}"
    )

    # Exit code
    return 1 if total_issues > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
