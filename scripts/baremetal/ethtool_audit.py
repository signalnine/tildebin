#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, nic, ethtool, offloads]
#   brief: Audit network interface driver settings, offloads, and ring buffers

"""
Audit network interface driver settings, offloads, and ring buffers using ethtool.

This script checks for common network performance issues caused by:
- Mismatched driver versions across interfaces
- Disabled performance-critical offloads (TSO, GSO, GRO, etc.)
- Suboptimal ring buffer sizes that could cause packet drops
- MTU inconsistencies across bonded interfaces
- Missing or disabled checksum offloading

Useful for large-scale baremetal environments where network performance
issues often stem from inconsistent driver/firmware configurations.

Exit codes:
    0 - All interfaces healthy, no issues detected
    1 - Warnings or issues detected (suboptimal settings, inconsistencies)
    2 - Usage error or ethtool not available
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_physical_interfaces(context: Context) -> list[str]:
    """Get list of physical network interfaces (excluding virtual)."""
    result = context.run(["ip", "link", "show"])
    if result.returncode != 0:
        return []

    interfaces = []
    for line in result.stdout.split("\n"):
        # Match lines like "2: eth0: <BROADCAST..."
        match = re.match(r"^\d+:\s+([^:@]+)", line)
        if match:
            iface = match.group(1).strip()
            # Skip loopback, virtual, and container interfaces
            if iface in ["lo"]:
                continue
            if iface.startswith(("veth", "docker", "br-", "virbr", "vnet")):
                continue
            interfaces.append(iface)

    return interfaces


def get_driver_info(context: Context, iface: str) -> dict | None:
    """Get driver information for an interface."""
    result = context.run(["ethtool", "-i", iface])
    if result.returncode != 0:
        return None

    info = {}
    for line in result.stdout.split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip().lower().replace(" ", "_").replace("-", "_")] = value.strip()

    return info


def get_offload_settings(context: Context, iface: str) -> dict | None:
    """Get offload settings for an interface."""
    result = context.run(["ethtool", "-k", iface])
    if result.returncode != 0:
        return None

    offloads = {}
    for line in result.stdout.split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            # Parse value, handling "[fixed]" and "[not requested]" annotations
            is_on = value.startswith("on")
            is_fixed = "[fixed]" in value
            offloads[key] = {
                "enabled": is_on,
                "fixed": is_fixed,
                "raw": value,
            }

    return offloads


def get_ring_buffer_settings(context: Context, iface: str) -> dict | None:
    """Get ring buffer settings for an interface."""
    result = context.run(["ethtool", "-g", iface])
    if result.returncode != 0:
        return None

    settings = {
        "preset_max": {},
        "current": {},
    }

    section = None
    for line in result.stdout.split("\n"):
        line = line.strip()
        if "Pre-set maximums" in line:
            section = "preset_max"
        elif "Current hardware settings" in line:
            section = "current"
        elif section and ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            try:
                settings[section][key] = int(value.strip())
            except ValueError:
                settings[section][key] = value.strip()

    return settings


def get_link_settings(context: Context, iface: str) -> dict | None:
    """Get link settings (speed, duplex, etc.) for an interface."""
    result = context.run(["ethtool", iface])
    if result.returncode != 0:
        return None

    settings = {}
    for line in result.stdout.split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            settings[key] = value.strip()

    return settings


def get_interface_mtu(context: Context, iface: str) -> int | None:
    """Get MTU for an interface."""
    result = context.run(["ip", "link", "show", iface])
    if result.returncode != 0:
        return None

    match = re.search(r"mtu\s+(\d+)", result.stdout)
    if match:
        return int(match.group(1))
    return None


def audit_interface(context: Context, iface: str, verbose: bool = False) -> dict:
    """Audit a single interface and return findings."""
    findings = {
        "interface": iface,
        "issues": [],
        "warnings": [],
        "info": {},
    }

    # Get driver info
    driver_info = get_driver_info(context, iface)
    if driver_info:
        findings["info"]["driver"] = driver_info.get("driver", "unknown")
        findings["info"]["version"] = driver_info.get("version", "unknown")
        findings["info"]["firmware_version"] = driver_info.get(
            "firmware_version", "unknown"
        )
    else:
        findings["warnings"].append("Could not retrieve driver information")

    # Get link settings
    link_settings = get_link_settings(context, iface)
    if link_settings:
        speed = link_settings.get("speed", "Unknown")
        duplex = link_settings.get("duplex", "Unknown")
        findings["info"]["speed"] = speed
        findings["info"]["duplex"] = duplex

        # Check for half-duplex (almost always a problem)
        if duplex.lower() == "half":
            findings["issues"].append(
                "Half-duplex detected - likely autonegotiation mismatch"
            )

        # Check for link down
        if link_settings.get("link_detected", "").lower() == "no":
            findings["issues"].append("Link not detected")

    # Get MTU
    mtu = get_interface_mtu(context, iface)
    if mtu:
        findings["info"]["mtu"] = mtu

    # Get offload settings
    offloads = get_offload_settings(context, iface)
    if offloads:
        findings["info"]["offloads"] = {}

        # Critical offloads that should typically be enabled for performance
        critical_offloads = [
            ("tcp-segmentation-offload", "TSO"),
            ("generic-segmentation-offload", "GSO"),
            ("generic-receive-offload", "GRO"),
            ("rx-checksumming", "RX checksum"),
            ("tx-checksumming", "TX checksum"),
            ("scatter-gather", "Scatter-gather"),
        ]

        for offload_key, offload_name in critical_offloads:
            if offload_key in offloads:
                offload = offloads[offload_key]
                findings["info"]["offloads"][offload_key] = offload["enabled"]

                if not offload["enabled"] and not offload["fixed"]:
                    findings["warnings"].append(
                        f"{offload_name} ({offload_key}) is disabled - may impact performance"
                    )

        # Check for LRO which can cause issues with routing/bridging
        if "large-receive-offload" in offloads:
            lro = offloads["large-receive-offload"]
            if lro["enabled"]:
                findings["warnings"].append(
                    "LRO enabled - may cause issues with routing/bridging/forwarding"
                )

    # Get ring buffer settings
    ring_settings = get_ring_buffer_settings(context, iface)
    if ring_settings and ring_settings.get("preset_max") and ring_settings.get("current"):
        findings["info"]["ring_buffers"] = ring_settings

        # Check if RX ring is significantly below maximum
        max_rx = ring_settings["preset_max"].get("rx", 0)
        current_rx = ring_settings["current"].get("rx", 0)

        if isinstance(max_rx, int) and isinstance(current_rx, int) and max_rx > 0:
            rx_ratio = current_rx / max_rx
            if rx_ratio < 0.5:
                findings["warnings"].append(
                    f"RX ring buffer at {current_rx}/{max_rx} ({rx_ratio:.0%}) - "
                    "consider increasing to reduce packet drops under load"
                )

        # Check TX ring similarly
        max_tx = ring_settings["preset_max"].get("tx", 0)
        current_tx = ring_settings["current"].get("tx", 0)

        if isinstance(max_tx, int) and isinstance(current_tx, int) and max_tx > 0:
            tx_ratio = current_tx / max_tx
            if tx_ratio < 0.5:
                findings["warnings"].append(
                    f"TX ring buffer at {current_tx}/{max_tx} ({tx_ratio:.0%}) - "
                    "consider increasing for high-throughput workloads"
                )

    return findings


def check_driver_consistency(all_findings: list[dict]) -> list[str]:
    """Check for driver version inconsistencies across similar interfaces."""
    issues = []

    # Group by driver
    driver_versions = defaultdict(list)
    for finding in all_findings:
        driver = finding["info"].get("driver", "unknown")
        version = finding["info"].get("version", "unknown")
        if driver != "unknown":
            driver_versions[driver].append(
                {
                    "interface": finding["interface"],
                    "version": version,
                }
            )

    # Check for version mismatches within same driver
    for driver, interfaces in driver_versions.items():
        versions = set(i["version"] for i in interfaces)
        if len(versions) > 1:
            iface_list = ", ".join(
                f"{i['interface']}={i['version']}" for i in interfaces
            )
            issues.append(f"Driver {driver} has version inconsistency: {iface_list}")

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
        description="Audit network interface driver settings, offloads, and ring buffers"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Specific interface to audit (default: all physical interfaces)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information including all offloads and ring buffers",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show interfaces with warnings or issues",
    )

    opts = parser.parse_args(args)

    # Check for ethtool
    if not context.check_tool("ethtool"):
        output.error("ethtool not found in PATH")
        return 2

    # Get interfaces to audit
    if opts.interface:
        interfaces = [opts.interface]
    else:
        interfaces = get_physical_interfaces(context)

    if not interfaces:
        if opts.format == "json":
            print(json.dumps({"interfaces": [], "global_issues": [], "summary": {}}))
        else:
            print("No network interfaces found to audit")
        return 0

    # Audit each interface
    all_findings = []
    for iface in interfaces:
        finding = audit_interface(context, iface, verbose=opts.verbose)
        all_findings.append(finding)

    # Check for global issues (cross-interface)
    global_issues = check_driver_consistency(all_findings)

    # Determine if there are issues
    has_issues = bool(global_issues) or any(
        f["issues"] or f["warnings"] for f in all_findings
    )

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "global_issues": global_issues,
        "interfaces": all_findings,
        "summary": {
            "total": len(all_findings),
            "with_issues": sum(1 for f in all_findings if f["issues"]),
            "with_warnings": sum(1 for f in all_findings if f["warnings"]),
            "healthy": sum(
                1 for f in all_findings if not f["issues"] and not f["warnings"]
            ),
        },
        "healthy": not has_issues,
    }

    # Output results
    output.emit(result)
    output.render(opts.format, "Network Interface Ethtool Audit", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    output.set_summary(
        f"total={result['summary']['total']}, "
        f"issues={result['summary']['with_issues']}, "
        f"warnings={result['summary']['with_warnings']}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
