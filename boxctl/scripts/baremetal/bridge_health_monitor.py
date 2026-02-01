#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, bridge, virtualization, stp]
#   brief: Monitor Linux bridge health for virtualization environments

"""
Monitor Linux bridge health for virtualization and container environments.

Checks network bridge configuration, connected interfaces, STP status,
and forwarding state. Essential for baremetal hosts running VMs or
containers that rely on bridge networking.

Checks performed:
- Bridge existence and state (up/down)
- Connected interface status
- STP (Spanning Tree Protocol) configuration
- Port states (forwarding, blocking, disabled)
- MTU consistency across bridge ports

Exit codes:
    0 - All bridges healthy
    1 - Bridge issues or warnings detected
    2 - Usage error or missing dependencies
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Port state values from kernel
PORT_STATE_MAP = {
    "0": "disabled",
    "1": "listening",
    "2": "learning",
    "3": "forwarding",
    "4": "blocking",
}


def get_bridges(context: Context) -> list[str]:
    """Get list of bridge devices."""
    bridges = []
    try:
        entries = context.glob("*", "/sys/class/net")
        for entry in entries:
            iface = entry.split("/")[-1]
            bridge_path = f"/sys/class/net/{iface}/bridge"
            if context.file_exists(bridge_path):
                bridges.append(iface)
    except Exception:
        pass
    return sorted(bridges)


def get_bridge_ports(bridge: str, context: Context) -> list[str]:
    """Get list of interfaces attached to a bridge."""
    ports = []
    brif_path = f"/sys/class/net/{bridge}/brif"
    try:
        entries = context.glob("*", brif_path)
        for entry in entries:
            port = entry.split("/")[-1]
            if port:
                ports.append(port)
    except Exception:
        pass
    return sorted(ports)


def read_sysfs(path: str, context: Context, default: str = "") -> str:
    """Read a sysfs file safely."""
    try:
        return context.read_file(path).strip()
    except FileNotFoundError:
        return default


def get_interface_state(iface: str, context: Context) -> dict[str, Any]:
    """Get interface state information."""
    base = f"/sys/class/net/{iface}"
    state = {
        "name": iface,
        "operstate": read_sysfs(f"{base}/operstate", context, "unknown"),
        "carrier": read_sysfs(f"{base}/carrier", context) == "1",
        "mtu": 0,
        "address": read_sysfs(f"{base}/address", context, "unknown"),
    }

    mtu_str = read_sysfs(f"{base}/mtu", context)
    if mtu_str.isdigit():
        state["mtu"] = int(mtu_str)

    speed_str = read_sysfs(f"{base}/speed", context)
    if speed_str and speed_str != "-1":
        try:
            state["speed_mbps"] = int(speed_str)
        except ValueError:
            pass

    return state


def get_port_state(bridge: str, port: str, context: Context) -> dict[str, Any]:
    """Get bridge port state."""
    port_path = f"/sys/class/net/{bridge}/brif/{port}"

    state_val = read_sysfs(f"{port_path}/state", context, "0")
    state_code = int(state_val) if state_val.isdigit() else -1

    path_cost = read_sysfs(f"{port_path}/path_cost", context, "0")
    priority = read_sysfs(f"{port_path}/priority", context, "0")
    hairpin = read_sysfs(f"{port_path}/hairpin_mode", context)

    return {
        "name": port,
        "state": PORT_STATE_MAP.get(state_val, "unknown"),
        "state_code": state_code,
        "path_cost": int(path_cost) if path_cost.isdigit() else 0,
        "priority": int(priority) if priority.isdigit() else 0,
        "hairpin_mode": hairpin == "1",
    }


def get_bridge_info(bridge: str, context: Context) -> dict[str, Any]:
    """Get comprehensive bridge information."""
    base = f"/sys/class/net/{bridge}"
    br_path = f"{base}/bridge"

    # Basic interface state
    info = get_interface_state(bridge, context)
    info["type"] = "bridge"

    # Bridge-specific settings
    stp = read_sysfs(f"{br_path}/stp_state", context)
    forward_delay = read_sysfs(f"{br_path}/forward_delay", context, "0")
    ageing_time = read_sysfs(f"{br_path}/ageing_time", context, "0")
    bridge_id = read_sysfs(f"{br_path}/bridge_id", context, "unknown")
    root_id = read_sysfs(f"{br_path}/root_id", context, "unknown")
    root_port = read_sysfs(f"{br_path}/root_port", context, "0")
    root_cost = read_sysfs(f"{br_path}/root_path_cost", context, "0")
    vlan_filter = read_sysfs(f"{br_path}/vlan_filtering", context)

    info["bridge"] = {
        "bridge_id": bridge_id,
        "stp_state": stp == "1",
        "forward_delay": int(forward_delay) if forward_delay.isdigit() else 0,
        "ageing_time": int(ageing_time) if ageing_time.isdigit() else 0,
        "root_id": root_id,
        "root_port": int(root_port) if root_port.isdigit() else 0,
        "root_path_cost": int(root_cost) if root_cost.isdigit() else 0,
        "is_root": bridge_id == root_id,
        "vlan_filtering": vlan_filter == "1" if vlan_filter else None,
    }

    # Get ports
    ports = get_bridge_ports(bridge, context)
    info["ports"] = []

    for port in ports:
        port_info = get_port_state(bridge, port, context)
        port_info["interface"] = get_interface_state(port, context)
        info["ports"].append(port_info)

    return info


def analyze_bridge(bridge_info: dict) -> list[dict]:
    """Analyze bridge health and return issues."""
    issues = []
    name = bridge_info["name"]

    # Check bridge is up
    if bridge_info["operstate"] != "up":
        issues.append({
            "type": "BRIDGE_DOWN",
            "severity": "critical",
            "bridge": name,
            "message": f"Bridge {name} is {bridge_info['operstate']}",
        })

    # Check for no ports
    if not bridge_info["ports"]:
        issues.append({
            "type": "NO_PORTS",
            "severity": "warning",
            "bridge": name,
            "message": f"Bridge {name} has no connected interfaces",
        })

    # Check port states
    for port in bridge_info["ports"]:
        port_name = port["name"]
        port_state = port["state"]
        iface_state = port["interface"]["operstate"]

        if port_state == "disabled":
            issues.append({
                "type": "PORT_DISABLED",
                "severity": "warning",
                "bridge": name,
                "port": port_name,
                "message": f"Port {port_name} on {name} is disabled",
            })

        if iface_state != "up":
            issues.append({
                "type": "PORT_IFACE_DOWN",
                "severity": "warning",
                "bridge": name,
                "port": port_name,
                "message": f"Port {port_name} interface is {iface_state}",
            })

        if port_state == "blocking" and bridge_info["bridge"]["stp_state"]:
            issues.append({
                "type": "PORT_BLOCKING",
                "severity": "info",
                "bridge": name,
                "port": port_name,
                "message": f"Port {port_name} is STP blocking",
            })

    # Check MTU consistency
    if len(bridge_info["ports"]) > 1:
        mtus = {p["interface"]["mtu"] for p in bridge_info["ports"] if p["interface"]["mtu"] > 0}
        if len(mtus) > 1:
            issues.append({
                "type": "MTU_MISMATCH",
                "severity": "warning",
                "bridge": name,
                "message": f"MTU mismatch on {name} ports: {sorted(mtus)}",
            })

    # Check bridge MTU vs port MTU
    bridge_mtu = bridge_info.get("mtu", 0)
    for port in bridge_info["ports"]:
        port_mtu = port["interface"].get("mtu", 0)
        if port_mtu > 0 and bridge_mtu > 0 and port_mtu < bridge_mtu:
            issues.append({
                "type": "BRIDGE_MTU_EXCEEDS_PORT",
                "severity": "warning",
                "bridge": name,
                "port": port["name"],
                "message": f"Bridge {name} MTU ({bridge_mtu}) exceeds port {port['name']} MTU ({port_mtu})",
            })

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
        description="Monitor Linux bridge health for virtualization environments"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show if there are issues")
    parser.add_argument("-b", "--bridges", nargs="+", metavar="BRIDGE",
                        help="Check specific bridges only")
    parser.add_argument("--ignore-no-ports", action="store_true",
                        help="Do not warn about bridges with no ports")
    opts = parser.parse_args(args)

    # Check sysfs access
    if not context.file_exists("/sys/class/net"):
        output.error("/sys/class/net not available")
        return 2

    # Get bridges to check
    if opts.bridges:
        all_bridges = set(get_bridges(context))
        bridges_to_check = []
        for br in opts.bridges:
            if br in all_bridges:
                bridges_to_check.append(br)
            else:
                output.warning(f"Bridge '{br}' not found")
        if not bridges_to_check:
            output.error("None of the specified bridges exist")
            return 2
    else:
        bridges_to_check = get_bridges(context)

    if not bridges_to_check:
        if opts.format == "json":
            print(json.dumps({
                "status": "ok",
                "bridge_count": 0,
                "bridges": [],
                "issues": [],
            }, indent=2))
        else:
            print("No bridges found on this system")
        output.emit({"bridges": [], "issues": []})
        return 0

    # Gather info
    bridges = []
    all_issues = []

    for bridge_name in bridges_to_check:
        bridge_info = get_bridge_info(bridge_name, context)
        bridges.append(bridge_info)

        issues = analyze_bridge(bridge_info)
        if opts.ignore_no_ports:
            issues = [i for i in issues if i["type"] != "NO_PORTS"]
        all_issues.extend(issues)

    # Output
    if opts.format == "json":
        has_critical = any(i["severity"] == "critical" for i in all_issues)
        has_warning = any(i["severity"] == "warning" for i in all_issues)
        status = "critical" if has_critical else ("warning" if has_warning else "ok")
        print(json.dumps({
            "status": status,
            "bridge_count": len(bridges),
            "bridges": bridges,
            "issues": all_issues,
        }, indent=2))
    else:
        if all_issues:
            print("ISSUES DETECTED:")
            for issue in all_issues:
                sev = issue["severity"].upper()
                print(f"  [{sev}] {issue['message']}")
            print()

        if opts.warn_only:
            if not all_issues:
                print("OK - All bridges healthy")
        else:
            for bridge in bridges:
                print(f"Bridge: {bridge['name']}")
                print("=" * 50)
                print(f"  State: {bridge['operstate']}")
                print(f"  MTU: {bridge['mtu']}")
                br = bridge["bridge"]
                print(f"  STP: {'enabled' if br['stp_state'] else 'disabled'}")
                if br["stp_state"]:
                    print(f"  Root bridge: {'yes' if br['is_root'] else 'no'}")
                if br["vlan_filtering"] is not None:
                    print(f"  VLAN filtering: {'enabled' if br['vlan_filtering'] else 'disabled'}")

                print(f"\n  Ports ({len(bridge['ports'])}):")
                if not bridge["ports"]:
                    print("    (none)")
                else:
                    for port in bridge["ports"]:
                        iface = port["interface"]
                        status = port["state"]
                        if iface["operstate"] != "up":
                            status += f" (iface: {iface['operstate']})"
                        speed = iface.get("speed_mbps")
                        speed_str = f" {speed}Mbps" if speed else ""
                        print(f"    - {port['name']}: {status}{speed_str}")
                        if opts.verbose:
                            print(f"        MTU: {iface['mtu']}, Path cost: {port['path_cost']}")
                print()

    output.emit({"bridges": bridges, "issues": all_issues})

    has_critical = any(i["severity"] == "critical" for i in all_issues)
    has_warning = any(i["severity"] == "warning" for i in all_issues)

    if has_critical or has_warning:
        output.set_summary(f"{len(bridges)} bridges, {len(all_issues)} issues")
        return 1

    output.set_summary(f"{len(bridges)} bridges healthy")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
