#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, config, audit, mtu, ipv6]
#   brief: Audit network interface configuration for misconfigurations

"""
Audit network interface configuration for common misconfigurations.

Checks network interface settings that can cause performance issues or
intermittent connectivity problems, including:
- MTU mismatches across interfaces
- IPv6 configuration inconsistencies
- Promiscuous mode warnings
- Bond slave MTU mismatches

Exit codes:
    0 - No issues detected
    1 - Configuration issues or warnings found
    2 - Usage error or missing dependency
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_interface_list(context: Context) -> list[str]:
    """Get list of network interfaces from /sys/class/net."""
    interfaces = []
    try:
        entries = context.glob("*", "/sys/class/net")
        for entry in entries:
            iface = entry.split("/")[-1]
            # Skip loopback and special files (like bonding_masters)
            if iface and iface != "lo" and context.is_dir(entry):
                interfaces.append(iface)
    except Exception:
        pass
    return sorted(interfaces)


def get_interface_info(iface: str, context: Context) -> dict[str, Any]:
    """Get info for a single interface."""
    base = f"/sys/class/net/{iface}"
    info: dict[str, Any] = {
        "name": iface,
        "mtu": None,
        "operstate": "unknown",
        "is_bond": False,
        "bond_slaves": [],
        "bonding_mode": None,
        "ipv6_enabled": False,
        "promiscuous": False,
    }

    # Read MTU
    try:
        mtu_str = context.read_file(f"{base}/mtu")
        info["mtu"] = int(mtu_str.strip())
    except (FileNotFoundError, ValueError):
        pass

    # Read operstate
    try:
        info["operstate"] = context.read_file(f"{base}/operstate").strip()
    except FileNotFoundError:
        pass

    # Check if bond
    if context.file_exists(f"{base}/bonding"):
        info["is_bond"] = True
        try:
            mode_str = context.read_file(f"{base}/bonding/mode")
            info["bonding_mode"] = mode_str.strip().split()[0]
        except (FileNotFoundError, IndexError):
            pass
        try:
            slaves_str = context.read_file(f"{base}/bonding/slaves")
            info["bond_slaves"] = slaves_str.strip().split() if slaves_str.strip() else []
        except FileNotFoundError:
            pass

    # Check IPv6
    try:
        disable_ipv6 = context.read_file(f"/proc/sys/net/ipv6/conf/{iface}/disable_ipv6")
        info["ipv6_enabled"] = disable_ipv6.strip() == "0"
    except FileNotFoundError:
        pass

    # Check promiscuous mode
    try:
        flags_str = context.read_file(f"{base}/flags")
        flags = int(flags_str.strip(), 16)
        info["promiscuous"] = bool(flags & 0x100)  # IFF_PROMISC
    except (FileNotFoundError, ValueError):
        pass

    return info


def audit_interfaces(interfaces: dict[str, dict], verbose: bool) -> list[dict]:
    """Audit interfaces for configuration issues."""
    findings = []

    # Filter to active non-bond interfaces
    active = {k: v for k, v in interfaces.items()
              if v["operstate"] == "up" and not v["is_bond"]}

    # Check MTU consistency
    if active:
        mtus = {v["mtu"] for v in active.values() if v["mtu"]}
        if len(mtus) > 1:
            findings.append({
                "severity": "warning",
                "category": "mtu",
                "message": f"MTU mismatch across active interfaces: {sorted(mtus)}",
            })
            if verbose:
                for iface, info in active.items():
                    if info["mtu"]:
                        findings.append({
                            "severity": "info",
                            "category": "mtu",
                            "message": f"  {iface}: MTU {info['mtu']}",
                        })

    # Check bond slave MTU
    for iface, info in interfaces.items():
        if info["is_bond"] and info["bond_slaves"]:
            bond_mtu = info["mtu"]
            for slave in info["bond_slaves"]:
                if slave in interfaces:
                    slave_mtu = interfaces[slave]["mtu"]
                    if slave_mtu and bond_mtu and slave_mtu != bond_mtu:
                        findings.append({
                            "severity": "warning",
                            "category": "bonding",
                            "message": f"Bond {iface} MTU ({bond_mtu}) != slave {slave} MTU ({slave_mtu})",
                        })

    # Check bond slave states
    for iface, info in interfaces.items():
        if info["is_bond"] and info["bond_slaves"]:
            for slave in info["bond_slaves"]:
                if slave in interfaces and interfaces[slave]["operstate"] != "up":
                    findings.append({
                        "severity": "error",
                        "category": "bonding",
                        "message": f"Bond {iface} slave {slave} is {interfaces[slave]['operstate']}",
                    })

    # Check bonding mode consistency
    bonds = {k: v for k, v in interfaces.items() if v["is_bond"]}
    if len(bonds) > 1:
        modes = {v["bonding_mode"] for v in bonds.values() if v["bonding_mode"]}
        if len(modes) > 1:
            findings.append({
                "severity": "warning",
                "category": "bonding",
                "message": f"Inconsistent bonding modes: {sorted(modes)}",
            })

    # Check IPv6 consistency
    if len(active) > 1:
        ipv6_states = {v["ipv6_enabled"] for v in active.values()}
        if len(ipv6_states) > 1:
            findings.append({
                "severity": "warning",
                "category": "ipv6",
                "message": "IPv6 enabled on some interfaces but not others",
            })
            if verbose:
                for iface, info in active.items():
                    state = "enabled" if info["ipv6_enabled"] else "disabled"
                    findings.append({
                        "severity": "info",
                        "category": "ipv6",
                        "message": f"  {iface}: IPv6 {state}",
                    })

    # Check promiscuous mode
    promisc = [k for k, v in interfaces.items()
               if v["promiscuous"] and v["operstate"] == "up"]
    if promisc:
        findings.append({
            "severity": "warning",
            "category": "security",
            "message": f"Promiscuous mode enabled on: {', '.join(promisc)}",
        })

    return findings


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
        description="Audit network interface configuration for common issues"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show warnings and errors")
    opts = parser.parse_args(args)

    # Check sysfs access
    if not context.file_exists("/sys/class/net"):
        output.error("/sys/class/net not accessible")
        return 2

    # Get interfaces
    iface_names = get_interface_list(context)
    if not iface_names:
        output.warning("No network interfaces found")
        output.emit({"findings": []})
        return 1

    # Collect interface info
    interfaces = {}
    for name in iface_names:
        interfaces[name] = get_interface_info(name, context)

    # Audit
    findings = audit_interfaces(interfaces, opts.verbose)

    # Filter if warn-only
    if opts.warn_only:
        findings = [f for f in findings if f["severity"] in ("warning", "error")]

    # Output
    if opts.format == "json":
        print(json.dumps({"findings": findings, "interface_count": len(interfaces)}, indent=2))
    else:
        if not findings:
            print("No issues detected")
        else:
            for f in findings:
                sev = f["severity"].upper()
                cat = f["category"]
                msg = f["message"]
                print(f"[{sev}] {cat}: {msg}")

    output.emit({"findings": findings, "interface_count": len(interfaces)})

    has_errors = any(f["severity"] == "error" for f in findings)
    has_warnings = any(f["severity"] == "warning" for f in findings)

    if has_errors or has_warnings:
        output.set_summary(f"{len(findings)} issue(s) found")
        return 1

    output.set_summary("All interfaces healthy")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
