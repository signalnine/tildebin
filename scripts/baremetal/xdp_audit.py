#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [network, xdp, ebpf, performance, security]
#   requires: [ip]
#   privilege: root
#   related: [ebpf_audit, ethtool_audit, nic_link_speed]
#   brief: Audit XDP programs attached to network interfaces

"""
Audit XDP programs attached to network interfaces.

Inspects all network interfaces for attached XDP (eXpress Data Path) programs
and reports their operating mode. XDP enables high-performance packet processing
at the driver level, but misconfigured or generic-mode programs can silently
degrade network performance.

Checks for:
- XDP programs running in generic/SKB mode (poor performance vs native/driver mode)
- XDP programs attached to bond or bridge slave interfaces (potential conflicts)
- Inventory of all XDP-attached interfaces with program IDs and modes

XDP modes:
    1 = native (driver-level, best performance)
    2 = generic/SKB (kernel fallback, significantly slower)
    3 = offloaded (NIC hardware, best possible performance)

Exit codes:
    0 - All XDP programs healthy or no XDP programs found
    1 - XDP issues detected (generic mode, slave conflicts)
    2 - Usage error or missing dependency
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


MODE_NAMES = {
    1: "native",
    2: "generic",
    3: "offloaded",
}


def parse_interfaces(ip_json: str) -> list[dict[str, Any]]:
    """Parse ip -j link show JSON output into interface list.

    Args:
        ip_json: Raw JSON string from ip -j link show

    Returns:
        List of parsed interface dicts with relevant fields.
    """
    try:
        raw = json.loads(ip_json)
    except (json.JSONDecodeError, TypeError):
        return []

    if not isinstance(raw, list):
        return []

    interfaces = []
    for iface in raw:
        if not isinstance(iface, dict):
            continue
        interfaces.append(iface)

    return interfaces


def extract_xdp_info(iface: dict[str, Any]) -> dict[str, Any] | None:
    """Extract XDP program info from a parsed interface dict.

    Args:
        iface: Single interface dict from ip -j link show output.

    Returns:
        Dict with xdp details if an XDP program is attached, None otherwise.
    """
    xdp = iface.get("xdp")
    if not isinstance(xdp, dict):
        return None

    prog = xdp.get("prog")
    if not isinstance(prog, dict):
        return None

    mode_num = xdp.get("mode")
    mode_name = MODE_NAMES.get(mode_num, f"unknown({mode_num})")

    return {
        "interface": iface.get("ifname", "unknown"),
        "link_type": iface.get("link_type", "unknown"),
        "prog_id": prog.get("id"),
        "prog_tag": prog.get("tag"),
        "jited": bool(prog.get("jited", 0)),
        "mode": mode_num,
        "mode_name": mode_name,
    }


def check_master_field(iface: dict[str, Any]) -> str | None:
    """Check if the interface has a master (is a bond/bridge slave).

    Returns the master interface name if present, None otherwise.
    """
    master = iface.get("master")
    if isinstance(master, str) and master:
        return master
    return None


def analyze_xdp(interfaces: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze XDP attachment status across all interfaces.

    Args:
        interfaces: Parsed interface list from ip -j link show.

    Returns:
        Analysis result dict with xdp_interfaces, issues, and stats.
    """
    xdp_interfaces = []
    issues = []

    for iface in interfaces:
        xdp_info = extract_xdp_info(iface)
        if xdp_info is None:
            continue

        xdp_interfaces.append(xdp_info)

        # Check for generic/SKB mode (poor performance)
        if xdp_info["mode"] == 2:
            issues.append({
                "severity": "warning",
                "category": "generic_mode",
                "interface": xdp_info["interface"],
                "message": (
                    f"{xdp_info['interface']}: XDP running in generic/SKB mode "
                    f"(prog {xdp_info['prog_id']}) - significantly slower than "
                    f"native/driver mode"
                ),
            })

        # Check for XDP on slave interfaces (bond/bridge members)
        master = check_master_field(iface)
        if master:
            issues.append({
                "severity": "info",
                "category": "slave_xdp",
                "interface": xdp_info["interface"],
                "master": master,
                "message": (
                    f"{xdp_info['interface']}: XDP attached to slave of {master} "
                    f"- potential conflicts with bond/bridge processing"
                ),
            })

    stats = {
        "total_interfaces": len(interfaces),
        "xdp_attached": len(xdp_interfaces),
        "native": sum(1 for x in xdp_interfaces if x["mode"] == 1),
        "generic": sum(1 for x in xdp_interfaces if x["mode"] == 2),
        "offloaded": sum(1 for x in xdp_interfaces if x["mode"] == 3),
    }

    return {
        "xdp_interfaces": xdp_interfaces,
        "issues": issues,
        "stats": stats,
    }


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
        description="Audit XDP programs attached to network interfaces"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed XDP program information",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show interfaces with issues",
    )

    opts = parser.parse_args(args)

    # Check for ip tool
    if not context.check_tool("ip"):
        output.error("ip not found in PATH")
        return 2

    # Get interface data
    result = context.run(["ip", "-j", "link", "show"])
    if result.returncode != 0:
        output.error(f"ip link show failed: {result.stderr}")
        return 2

    # Parse and analyze
    interfaces = parse_interfaces(result.stdout)
    analysis = analyze_xdp(interfaces)

    xdp_interfaces = analysis["xdp_interfaces"]
    issues = analysis["issues"]
    stats = analysis["stats"]

    # Determine health status
    has_warnings = any(i["severity"] == "warning" for i in issues)

    if has_warnings:
        status = "warning"
    else:
        status = "ok"

    # Emit structured data
    output.emit({
        "status": status,
        "xdp_interfaces": xdp_interfaces,
        "issues": issues,
        "stats": stats,
        "healthy": not has_warnings,
    })

    # Set summary
    if not xdp_interfaces:
        output.set_summary("No XDP programs attached to any interface")
    else:
        warning_count = sum(1 for i in issues if i["severity"] == "warning")
        output.set_summary(
            f"xdp_attached={stats['xdp_attached']}, "
            f"native={stats['native']}, "
            f"generic={stats['generic']}, "
            f"warnings={warning_count}"
        )

    output.render(opts.format, "XDP Program Audit")

    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
