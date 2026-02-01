#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, mtu, configuration]
#   brief: Detect MTU mismatches across network interfaces

"""
Detect MTU mismatches across network interfaces.

MTU (Maximum Transmission Unit) mismatches are a common cause of network problems
in large baremetal environments. When interfaces along a network path have different
MTUs, packets may be fragmented or dropped, causing:
- Silent packet loss with jumbo frames
- Reduced throughput on high-speed links
- TCP performance degradation (PMTUD failures)
- Inconsistent behavior across hosts

This script detects:
- Interfaces with non-standard MTUs (not 1500 or 9000)
- Inconsistent MTUs within bond/team/bridge groups
- Interfaces where MTU doesn't match expected jumbo frame settings
- VLAN interfaces with MTU larger than parent interface

For jumbo frame environments (10G/25G/40G/100G networks):
- Standard jumbo MTU: 9000
- Some switches require: 9216

For standard networks:
- Ethernet default: 1500

Exit codes:
    0 - No MTU issues detected
    1 - MTU mismatches or issues found
    2 - Usage error or required tools not available
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_sysfs(context: Context, path: str) -> str | None:
    """Read a value from sysfs."""
    try:
        return context.read_file(path).strip()
    except (IOError, FileNotFoundError):
        return None


def get_interface_mtu(context: Context, iface: str) -> int | None:
    """Get MTU for an interface from sysfs."""
    mtu_str = read_sysfs(context, f"/sys/class/net/{iface}/mtu")
    if mtu_str and mtu_str.isdigit():
        return int(mtu_str)
    return None


def get_interface_operstate(context: Context, iface: str) -> str:
    """Get operational state of interface."""
    state = read_sysfs(context, f"/sys/class/net/{iface}/operstate")
    return state if state else "unknown"


def get_interface_speed(context: Context, iface: str) -> int | None:
    """Get interface speed in Mbps."""
    speed_str = read_sysfs(context, f"/sys/class/net/{iface}/speed")
    if speed_str and speed_str.lstrip("-").isdigit():
        speed = int(speed_str)
        # Speed of -1 means unknown
        return speed if speed > 0 else None
    return None


def is_bond_master(context: Context, iface: str) -> bool:
    """Check if interface is a bond master."""
    return context.file_exists(f"/sys/class/net/{iface}/bonding")


def is_bridge(context: Context, iface: str) -> bool:
    """Check if interface is a bridge."""
    return context.file_exists(f"/sys/class/net/{iface}/bridge")


def is_vlan(iface: str) -> bool:
    """Check if interface is a VLAN."""
    return "." in iface


def get_vlan_parent(iface: str) -> str | None:
    """Get parent interface for a VLAN."""
    if "." in iface:
        return iface.rsplit(".", 1)[0]
    return None


def get_bond_slaves(context: Context, iface: str) -> list[str]:
    """Get list of slave interfaces for a bond."""
    slaves_str = read_sysfs(context, f"/sys/class/net/{iface}/bonding/slaves")
    if slaves_str:
        return slaves_str.split()
    return []


def get_bridge_ports(context: Context, iface: str) -> list[str]:
    """Get list of ports for a bridge."""
    brif_path = f"/sys/class/net/{iface}/brif"
    if context.file_exists(brif_path):
        try:
            return [p.split("/")[-1] for p in context.glob("*", brif_path)]
        except OSError:
            pass
    return []


def get_all_interfaces(context: Context) -> list[str]:
    """Get list of all network interfaces."""
    net_path = "/sys/class/net"
    if not context.file_exists(net_path):
        return []
    try:
        interfaces = []
        for iface in context.glob("*", net_path):
            iface_name = iface.split("/")[-1]
            if iface_name != "lo" and not iface_name.startswith("veth"):
                interfaces.append(iface_name)
        return sorted(interfaces)
    except OSError:
        return []


def classify_mtu(mtu: int) -> str:
    """Classify MTU value."""
    if mtu == 1500:
        return "standard"
    elif mtu == 9000:
        return "jumbo"
    elif mtu == 9216:
        return "jumbo-extended"
    elif mtu < 1500:
        return "reduced"
    elif 1500 < mtu < 9000:
        return "custom"
    elif mtu > 9216:
        return "oversized"
    return "unknown"


def analyze_interfaces(
    context: Context,
    expected_mtu: int | None = None,
    jumbo_expected: bool = False,
) -> dict:
    """Analyze all interfaces for MTU issues."""
    analysis = {
        "interfaces": {},
        "issues": [],
        "warnings": [],
        "summary": {
            "total_interfaces": 0,
            "standard_mtu": 0,
            "jumbo_mtu": 0,
            "other_mtu": 0,
            "bonds": 0,
            "bridges": 0,
            "vlans": 0,
        },
    }

    interfaces = get_all_interfaces(context)
    analysis["summary"]["total_interfaces"] = len(interfaces)

    # Collect interface data
    for iface in interfaces:
        mtu = get_interface_mtu(context, iface)
        if mtu is None:
            continue

        operstate = get_interface_operstate(context, iface)
        speed = get_interface_speed(context, iface)

        info = {
            "name": iface,
            "mtu": mtu,
            "mtu_class": classify_mtu(mtu),
            "operstate": operstate,
            "speed_mbps": speed,
            "type": "physical",
        }

        # Classify interface type
        if is_bond_master(context, iface):
            info["type"] = "bond"
            info["slaves"] = get_bond_slaves(context, iface)
            analysis["summary"]["bonds"] += 1
        elif is_bridge(context, iface):
            info["type"] = "bridge"
            info["ports"] = get_bridge_ports(context, iface)
            analysis["summary"]["bridges"] += 1
        elif is_vlan(iface):
            info["type"] = "vlan"
            info["parent"] = get_vlan_parent(iface)
            analysis["summary"]["vlans"] += 1

        # Count MTU types
        if mtu == 1500:
            analysis["summary"]["standard_mtu"] += 1
        elif mtu in (9000, 9216):
            analysis["summary"]["jumbo_mtu"] += 1
        else:
            analysis["summary"]["other_mtu"] += 1

        analysis["interfaces"][iface] = info

    # Check for issues

    # 1. Check expected MTU if specified
    if expected_mtu is not None:
        for iface, info in analysis["interfaces"].items():
            if info["operstate"] == "up" and info["mtu"] != expected_mtu:
                analysis["issues"].append(
                    {
                        "type": "unexpected_mtu",
                        "severity": "error",
                        "interface": iface,
                        "expected": expected_mtu,
                        "actual": info["mtu"],
                        "message": f"{iface}: MTU {info['mtu']} does not match expected {expected_mtu}",
                    }
                )

    # 2. Check jumbo frame expectation for high-speed interfaces
    if jumbo_expected:
        for iface, info in analysis["interfaces"].items():
            if info["operstate"] == "up" and info["speed_mbps"]:
                if info["speed_mbps"] >= 10000 and info["mtu"] == 1500:
                    analysis["warnings"].append(
                        {
                            "type": "no_jumbo_on_high_speed",
                            "severity": "warning",
                            "interface": iface,
                            "speed_mbps": info["speed_mbps"],
                            "mtu": info["mtu"],
                            "message": f"{iface}: {info['speed_mbps']}Mbps link using standard MTU (1500) instead of jumbo frames",
                        }
                    )

    # 3. Check bond slave MTU consistency
    for iface, info in analysis["interfaces"].items():
        if info["type"] == "bond" and info.get("slaves"):
            master_mtu = info["mtu"]
            for slave in info["slaves"]:
                slave_info = analysis["interfaces"].get(slave)
                if slave_info and slave_info["mtu"] != master_mtu:
                    analysis["issues"].append(
                        {
                            "type": "bond_mtu_mismatch",
                            "severity": "error",
                            "interface": slave,
                            "bond": iface,
                            "bond_mtu": master_mtu,
                            "slave_mtu": slave_info["mtu"],
                            "message": f"{slave}: MTU {slave_info['mtu']} mismatches bond {iface} MTU {master_mtu}",
                        }
                    )

    # 4. Check bridge port MTU consistency
    for iface, info in analysis["interfaces"].items():
        if info["type"] == "bridge" and info.get("ports"):
            bridge_mtu = info["mtu"]
            for port in info["ports"]:
                port_info = analysis["interfaces"].get(port)
                if port_info and port_info["mtu"] != bridge_mtu:
                    analysis["warnings"].append(
                        {
                            "type": "bridge_mtu_mismatch",
                            "severity": "warning",
                            "interface": port,
                            "bridge": iface,
                            "bridge_mtu": bridge_mtu,
                            "port_mtu": port_info["mtu"],
                            "message": f"{port}: MTU {port_info['mtu']} differs from bridge {iface} MTU {bridge_mtu}",
                        }
                    )

    # 5. Check VLAN MTU not exceeding parent
    for iface, info in analysis["interfaces"].items():
        if info["type"] == "vlan" and info.get("parent"):
            parent_info = analysis["interfaces"].get(info["parent"])
            if parent_info and info["mtu"] > parent_info["mtu"]:
                analysis["issues"].append(
                    {
                        "type": "vlan_mtu_exceeds_parent",
                        "severity": "error",
                        "interface": iface,
                        "parent": info["parent"],
                        "vlan_mtu": info["mtu"],
                        "parent_mtu": parent_info["mtu"],
                        "message": f"{iface}: VLAN MTU {info['mtu']} exceeds parent {info['parent']} MTU {parent_info['mtu']}",
                    }
                )

    # 6. Detect mixed MTU environments
    active_mtus = set()
    for iface, info in analysis["interfaces"].items():
        if info["operstate"] == "up" and info["type"] == "physical":
            active_mtus.add(info["mtu"])

    if 1500 in active_mtus and any(m >= 9000 for m in active_mtus):
        analysis["warnings"].append(
            {
                "type": "mixed_mtu_environment",
                "severity": "warning",
                "mtus_found": sorted(active_mtus),
                "message": f"Mixed MTU environment detected: {sorted(active_mtus)} - verify this is intentional",
            }
        )

    # 7. Check for unusual MTU values
    for iface, info in analysis["interfaces"].items():
        mtu = info["mtu"]
        if mtu < 576:  # Below minimum IP MTU
            analysis["issues"].append(
                {
                    "type": "mtu_too_small",
                    "severity": "error",
                    "interface": iface,
                    "mtu": mtu,
                    "message": f"{iface}: MTU {mtu} is below minimum IP requirement (576)",
                }
            )
        elif mtu > 9216 and info["operstate"] == "up":
            analysis["warnings"].append(
                {
                    "type": "mtu_oversized",
                    "severity": "warning",
                    "interface": iface,
                    "mtu": mtu,
                    "message": f"{iface}: MTU {mtu} exceeds typical jumbo frame size (9216)",
                }
            )

    return analysis


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
        description="Detect MTU mismatches across network interfaces"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed interface information",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show issues and warnings",
    )
    parser.add_argument(
        "--expected",
        type=int,
        metavar="MTU",
        help="Expected MTU value for all interfaces",
    )
    parser.add_argument(
        "--jumbo-expected",
        action="store_true",
        help="Expect jumbo frames on high-speed (10G+) interfaces",
    )

    opts = parser.parse_args(args)

    # Validate expected MTU
    if opts.expected is not None:
        if opts.expected < 68 or opts.expected > 65535:
            output.error("--expected MTU must be between 68 and 65535")
            return 2

    # Check for sysfs
    if not context.file_exists("/sys/class/net"):
        output.error("/sys/class/net not available")
        return 2

    # Analyze interfaces
    analysis = analyze_interfaces(
        context,
        expected_mtu=opts.expected,
        jumbo_expected=opts.jumbo_expected,
    )

    # Determine if there are issues
    has_issues = len(analysis["issues"]) > 0 or len(analysis["warnings"]) > 0

    # Build output data
    if analysis["issues"]:
        status = "error"
    elif analysis["warnings"]:
        status = "warning"
    else:
        status = "ok"

    output_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "summary": analysis["summary"],
        "issues": analysis["issues"],
        "warnings": analysis["warnings"],
        "interfaces": analysis["interfaces"],
        "healthy": not has_issues,
    }

    # Output results
    if opts.format == "json":
        print(json.dumps(output_data, indent=2))
    elif opts.format == "table":
        if opts.warn_only and not analysis["issues"] and not analysis["warnings"]:
            print("No MTU issues detected")
        else:
            print(
                f"{'Interface':<15} {'MTU':>6} {'Class':<12} {'Type':<10} "
                f"{'State':<8} {'Status':<10}"
            )
            print("=" * 70)

            for iface, info in sorted(analysis["interfaces"].items()):
                # Determine status
                iface_status = "OK"
                for issue in analysis["issues"]:
                    if issue.get("interface") == iface:
                        iface_status = "ERROR"
                        break
                if iface_status == "OK":
                    for warning in analysis["warnings"]:
                        if warning.get("interface") == iface:
                            iface_status = "WARN"
                            break

                if opts.warn_only and iface_status == "OK":
                    continue

                print(
                    f"{iface:<15} {info['mtu']:>6} {info['mtu_class']:<12} "
                    f"{info['type']:<10} {info['operstate']:<8} {iface_status:<10}"
                )
    else:
        if opts.warn_only and not analysis["issues"] and not analysis["warnings"]:
            pass  # Silent
        else:
            lines = []
            lines.append("MTU Mismatch Detector")
            lines.append("=" * 60)
            lines.append("")

            # Show issues first
            if analysis["issues"]:
                lines.append("ISSUES:")
                for issue in analysis["issues"]:
                    lines.append(f"  [ERROR] {issue['message']}")
                lines.append("")

            if analysis["warnings"]:
                lines.append("WARNINGS:")
                for warning in analysis["warnings"]:
                    lines.append(f"  [WARN] {warning['message']}")
                lines.append("")

            if not opts.warn_only:
                # Summary
                summary = analysis["summary"]
                lines.append("Summary:")
                lines.append(f"  Total interfaces: {summary['total_interfaces']}")
                lines.append(f"  Standard MTU (1500): {summary['standard_mtu']}")
                lines.append(f"  Jumbo MTU (9000/9216): {summary['jumbo_mtu']}")
                lines.append(f"  Other MTU: {summary['other_mtu']}")
                if summary["bonds"] > 0:
                    lines.append(f"  Bond interfaces: {summary['bonds']}")
                if summary["bridges"] > 0:
                    lines.append(f"  Bridge interfaces: {summary['bridges']}")
                if summary["vlans"] > 0:
                    lines.append(f"  VLAN interfaces: {summary['vlans']}")
                lines.append("")

                if opts.verbose:
                    lines.append("Interface Details:")
                    lines.append("-" * 60)
                    lines.append(
                        f"{'Interface':<15} {'MTU':>6} {'Type':<10} "
                        f"{'State':<8} {'Speed':<10}"
                    )
                    lines.append("-" * 60)

                    for iface, info in sorted(analysis["interfaces"].items()):
                        speed = (
                            f"{info['speed_mbps']}M" if info["speed_mbps"] else "N/A"
                        )
                        lines.append(
                            f"{iface:<15} {info['mtu']:>6} {info['type']:<10} "
                            f"{info['operstate']:<8} {speed:<10}"
                        )
                    lines.append("")

            if not analysis["issues"] and not analysis["warnings"]:
                lines.append("Status: OK - No MTU mismatches detected")

            print("\n".join(lines))

    # Set summary
    output.set_summary(
        f"interfaces={analysis['summary']['total_interfaces']}, "
        f"issues={len(analysis['issues'])}, "
        f"warnings={len(analysis['warnings'])}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
