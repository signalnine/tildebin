#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, vlan, config, audit]
#   brief: Audit VLAN configuration and health on baremetal systems

"""
Audit VLAN configuration and health on baremetal systems.

Detects VLAN misconfigurations that commonly cause network isolation issues:
- VLAN interfaces with parent interface down
- MTU mismatches between VLAN and parent interface
- Orphaned VLANs (parent interface no longer exists)
- VLAN ID conflicts or duplicates

Exit codes:
    0 - All VLANs healthy (or no VLANs configured)
    1 - One or more VLANs have configuration issues
    2 - Usage error or missing dependency
"""

import argparse
import json
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_vlan_interfaces(context: Context) -> list[dict]:
    """Get all VLAN interfaces and their configuration."""
    vlans = []

    # Method 1: Check /proc/net/vlan/config
    if context.file_exists("/proc/net/vlan/config"):
        try:
            content = context.read_file("/proc/net/vlan/config")
            for line in content.split("\n"):
                if "|" not in line or "Name-Type" in line:
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    try:
                        vlan_id = int(parts[1])
                        vlans.append({
                            "interface": parts[0],
                            "vlan_id": vlan_id,
                            "parent": parts[2],
                            "source": "proc_vlan_config",
                        })
                    except ValueError:
                        continue
        except FileNotFoundError:
            pass

    # Method 2: Check naming patterns in sysfs
    try:
        entries = context.glob("*", "/sys/class/net")
        for entry in entries:
            iface = entry.split("/")[-1]
            if not iface:
                continue

            # Skip if already found
            if any(v["interface"] == iface for v in vlans):
                continue

            # Pattern: parent.vlanid (e.g., eth0.100)
            match = re.match(r"^(.+)\.(\d+)$", iface)
            if match:
                parent = match.group(1)
                vlan_id = int(match.group(2))
                if context.file_exists(f"/sys/class/net/{parent}"):
                    vlans.append({
                        "interface": iface,
                        "vlan_id": vlan_id,
                        "parent": parent,
                        "source": "naming_pattern",
                    })
    except Exception:
        pass

    return vlans


def read_sysfs(path: str, context: Context, default: str = "") -> str:
    """Read a sysfs file safely."""
    try:
        return context.read_file(path).strip()
    except FileNotFoundError:
        return default


def analyze_vlan(vlan: dict, context: Context) -> tuple[str, list[str], dict]:
    """Analyze a VLAN interface for configuration issues."""
    issues = []
    status = "ok"

    iface = vlan["interface"]
    parent = vlan["parent"]

    info: dict[str, Any] = {
        "interface": iface,
        "vlan_id": vlan["vlan_id"],
        "parent": parent,
        "parent_exists": False,
        "parent_up": False,
        "vlan_up": False,
        "mtu": None,
        "parent_mtu": None,
    }

    # Check VLAN interface exists
    if not context.file_exists(f"/sys/class/net/{iface}"):
        issues.append("VLAN interface does not exist in sysfs")
        return "error", issues, info

    # Get VLAN interface state
    base = f"/sys/class/net/{iface}"
    flags_str = read_sysfs(f"{base}/flags", context, "0x0")
    try:
        flags = int(flags_str, 16)
        info["vlan_up"] = bool(flags & 0x1)  # IFF_UP
    except ValueError:
        info["vlan_up"] = False

    info["operstate"] = read_sysfs(f"{base}/operstate", context, "unknown")

    mtu_str = read_sysfs(f"{base}/mtu", context)
    if mtu_str.isdigit():
        info["mtu"] = int(mtu_str)

    # Check parent
    if parent:
        info["parent_exists"] = context.file_exists(f"/sys/class/net/{parent}")

        if not info["parent_exists"]:
            issues.append(f"Parent interface '{parent}' does not exist (orphaned VLAN)")
            status = "error"
        else:
            parent_base = f"/sys/class/net/{parent}"
            parent_flags_str = read_sysfs(f"{parent_base}/flags", context, "0x0")
            try:
                parent_flags = int(parent_flags_str, 16)
                info["parent_up"] = bool(parent_flags & 0x1)
            except ValueError:
                info["parent_up"] = False

            info["parent_operstate"] = read_sysfs(f"{parent_base}/operstate", context, "unknown")

            parent_mtu_str = read_sysfs(f"{parent_base}/mtu", context)
            if parent_mtu_str.isdigit():
                info["parent_mtu"] = int(parent_mtu_str)

            if not info["parent_up"]:
                issues.append(f"Parent interface '{parent}' is administratively DOWN")
                if status == "ok":
                    status = "warning"

            if info.get("parent_operstate") == "down":
                issues.append(f"Parent interface '{parent}' has no link")
                if status == "ok":
                    status = "warning"

            if info["mtu"] and info["parent_mtu"]:
                if info["mtu"] > info["parent_mtu"]:
                    issues.append(
                        f"VLAN MTU ({info['mtu']}) exceeds parent MTU ({info['parent_mtu']})"
                    )
                    if status == "ok":
                        status = "warning"
    else:
        issues.append("Could not determine parent interface")
        if status == "ok":
            status = "warning"

    if not info["vlan_up"]:
        issues.append("VLAN interface is administratively DOWN")
        if status == "ok":
            status = "warning"

    return status, issues, info


def check_vlan_conflicts(vlans: list[dict]) -> list[dict]:
    """Check for duplicate VLAN IDs on same parent."""
    conflicts = []

    by_parent: dict[str, list[dict]] = {}
    for vlan in vlans:
        parent = vlan.get("parent") or "unknown"
        if parent not in by_parent:
            by_parent[parent] = []
        by_parent[parent].append(vlan)

    for parent, vlan_list in by_parent.items():
        vlan_ids: dict[int, str] = {}
        for vlan in vlan_list:
            vid = vlan["vlan_id"]
            if vid in vlan_ids:
                conflicts.append({
                    "vlan_id": vid,
                    "parent": parent,
                    "interfaces": [vlan_ids[vid], vlan["interface"]],
                })
            else:
                vlan_ids[vid] = vlan["interface"]

    return conflicts


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
        description="Audit VLAN configuration and health on baremetal systems"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show VLANs with issues")
    opts = parser.parse_args(args)

    # Check sysfs access
    if not context.file_exists("/sys/class/net"):
        output.error("/sys/class/net not accessible")
        return 2

    # Get VLANs
    vlans = get_vlan_interfaces(context)

    # Analyze each VLAN
    results = []
    has_issues = False

    for vlan in vlans:
        status, issues, info = analyze_vlan(vlan, context)
        result = {
            "interface": vlan["interface"],
            "status": status,
            "issues": issues,
            "info": info,
        }
        if status in ("warning", "error"):
            has_issues = True
        results.append(result)

    # Check conflicts
    conflicts = check_vlan_conflicts(vlans)
    if conflicts:
        has_issues = True

    # Output
    if opts.format == "json":
        summary = {
            "total": len(results),
            "ok": sum(1 for r in results if r["status"] == "ok"),
            "warning": sum(1 for r in results if r["status"] == "warning"),
            "error": sum(1 for r in results if r["status"] == "error"),
            "conflicts": len(conflicts),
        }
        print(json.dumps({"vlans": results, "conflicts": conflicts, "summary": summary}, indent=2))
    else:
        print("VLAN Configuration Audit")
        print("=" * 70)
        print()

        if not results:
            print("No VLAN interfaces found.")
        else:
            for r in results:
                if opts.warn_only and r["status"] == "ok":
                    continue

                symbol = {"ok": "+", "warning": "!", "error": "X"}.get(r["status"], "?")
                info = r["info"]
                parent = info["parent"] or "unknown"
                mtu = info["mtu"] or "N/A"

                print(f"[{symbol}] {r['interface']}: VLAN {info['vlan_id']} on {parent} (MTU: {mtu})")

                for issue in r["issues"]:
                    print(f"    -> {issue}")

                if opts.verbose:
                    state = "UP" if info["vlan_up"] else "DOWN"
                    print(f"    State: {state} (operstate: {info.get('operstate', 'N/A')})")
                    if info["parent"]:
                        pstate = "UP" if info["parent_up"] else "DOWN"
                        print(f"    Parent state: {pstate}")
                print()

        if conflicts:
            print("VLAN ID Conflicts:")
            for c in conflicts:
                print(f"  [X] VLAN {c['vlan_id']} on {c['parent']}: "
                      f"configured on {', '.join(c['interfaces'])}")
            print()

        total = len(results)
        ok_count = sum(1 for r in results if r["status"] == "ok")
        issue_count = sum(1 for r in results if r["status"] != "ok") + len(conflicts)
        print(f"Summary: {total} VLANs checked, {ok_count} healthy, {issue_count} with issues")

    output.emit({"vlans": results, "conflicts": conflicts})

    if has_issues:
        output.set_summary(f"{len(results)} VLANs, issues found")
        return 1

    output.set_summary(f"{len(results)} VLANs healthy")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
