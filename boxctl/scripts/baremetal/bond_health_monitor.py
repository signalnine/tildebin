#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, bonding, lacp, failover]
#   brief: Monitor network bond health and slave status

"""
Monitor network bond health and detect configuration issues.

Provides comprehensive monitoring of network bonding interfaces,
including bond mode verification, slave health tracking, failover readiness,
and detailed diagnostics for troubleshooting bond-related issues.

Exit codes:
    0 - All bonds healthy
    1 - Bond degradation or errors detected
    2 - Missing dependencies or usage error
"""

import argparse
import json
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_bond_list(context: Context) -> list[str]:
    """Get list of all bonded interfaces."""
    bonds = []
    try:
        entries = context.glob("*", "/proc/net/bonding")
        for entry in entries:
            name = entry.split("/")[-1]
            if name and name not in (".", ".."):
                bonds.append(name)
    except Exception:
        pass
    return bonds


def parse_bond_file(bond_name: str, context: Context) -> dict[str, Any] | None:
    """Parse /proc/net/bonding/<bond> file for detailed information."""
    bond_file = f"/proc/net/bonding/{bond_name}"

    try:
        content = context.read_file(bond_file)
    except FileNotFoundError:
        return None

    bond_info: dict[str, Any] = {
        "name": bond_name,
        "mode": "unknown",
        "mii_status": "unknown",
        "mii_polling_interval": 0,
        "slaves": [],
        "primary": None,
        "active_slave": None,
        "errors": [],
        "warnings": [],
    }

    # Parse bonding mode
    mode_match = re.search(r"Bonding Mode:\s*([^\n]+)", content)
    if mode_match:
        bond_info["mode"] = mode_match.group(1).strip()

    # Parse MII status
    mii_match = re.search(r"^MII Status:\s*(\w+)", content, re.MULTILINE)
    if mii_match:
        bond_info["mii_status"] = mii_match.group(1).strip()

    # Parse MII polling interval
    interval_match = re.search(r"MII Polling Interval \(ms\):\s*(\d+)", content)
    if interval_match:
        bond_info["mii_polling_interval"] = int(interval_match.group(1))

    # Parse primary slave
    primary_match = re.search(r"Primary Slave:\s*(\S+)", content)
    if primary_match:
        primary = primary_match.group(1).strip()
        if primary != "None":
            bond_info["primary"] = primary

    # Parse currently active slave
    active_match = re.search(r"Currently Active Slave:\s*(\S+)", content)
    if active_match:
        active = active_match.group(1).strip()
        if active != "None":
            bond_info["active_slave"] = active

    # Parse slave interfaces
    slave_pattern = r"Slave Interface:\s*(\S+).*?MII Status:\s*(\w+)"
    for match in re.finditer(slave_pattern, content, re.DOTALL):
        slave_name = match.group(1).strip()
        slave_status = match.group(2).strip()

        # Get slave section
        slave_start = match.start()
        next_slave = re.search(r"Slave Interface:", content[slave_start + 1:])
        slave_end = slave_start + 1 + next_slave.start() if next_slave else len(content)
        slave_section = content[slave_start:slave_end]

        # Parse link failure count
        fail_match = re.search(r"Link Failure Count:\s*(\d+)", slave_section)
        link_failures = int(fail_match.group(1)) if fail_match else 0

        # Parse speed
        speed_match = re.search(r"Speed:\s*(\S+)", slave_section)
        speed = speed_match.group(1) if speed_match else "Unknown"

        # Parse duplex
        duplex_match = re.search(r"Duplex:\s*(\S+)", slave_section)
        duplex = duplex_match.group(1) if duplex_match else "Unknown"

        bond_info["slaves"].append({
            "name": slave_name,
            "status": slave_status,
            "link_failure_count": link_failures,
            "speed": speed,
            "duplex": duplex,
        })

    return bond_info


def analyze_bond_health(bond_info: dict) -> dict:
    """Analyze bond health and add warnings/errors."""
    if not bond_info:
        return bond_info

    # Check MII status
    if bond_info["mii_status"] != "up":
        bond_info["errors"].append(f"Bond MII status is {bond_info['mii_status']}")

    # Check for slaves
    if len(bond_info["slaves"]) == 0:
        bond_info["errors"].append("No slave interfaces configured")
        return bond_info

    # Count active/down slaves
    active_slaves = [s for s in bond_info["slaves"] if s["status"] == "up"]
    down_slaves = [s for s in bond_info["slaves"] if s["status"] != "up"]

    # Warn about down slaves
    for slave in down_slaves:
        bond_info["warnings"].append(f"Slave {slave['name']} is {slave['status']}")

    # Check link failures
    for slave in bond_info["slaves"]:
        if slave["link_failure_count"] > 0:
            bond_info["warnings"].append(
                f"Slave {slave['name']} has {slave['link_failure_count']} link failures"
            )

    # Check speed/duplex mismatches
    speeds = {s["speed"] for s in active_slaves if s["speed"] != "Unknown"}
    duplexes = {s["duplex"] for s in active_slaves if s["duplex"] != "Unknown"}

    if len(speeds) > 1:
        bond_info["warnings"].append(f"Speed mismatch: {', '.join(sorted(speeds))}")

    if len(duplexes) > 1:
        bond_info["warnings"].append(f"Duplex mismatch: {', '.join(sorted(duplexes))}")

    # Mode-specific checks
    mode = bond_info["mode"].lower()
    if "active-backup" in mode:
        if not active_slaves:
            bond_info["errors"].append("No active slaves in active-backup mode")
        elif len(active_slaves) < len(bond_info["slaves"]):
            bond_info["warnings"].append(
                f"Only {len(active_slaves)}/{len(bond_info['slaves'])} slaves active"
            )
    elif "802.3ad" in mode or "lacp" in mode:
        if len(bond_info["slaves"]) < 2:
            bond_info["warnings"].append("LACP mode should have at least 2 slaves")
        if len(active_slaves) < 2:
            bond_info["warnings"].append(f"Only {len(active_slaves)} active slaves in LACP mode")

    # Check MII polling interval
    if bond_info["mii_polling_interval"] == 0:
        bond_info["warnings"].append("MII polling disabled (interval = 0)")
    elif bond_info["mii_polling_interval"] > 1000:
        bond_info["warnings"].append(
            f"MII polling interval is high ({bond_info['mii_polling_interval']}ms)"
        )

    return bond_info


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
        description="Monitor network bond health and detect configuration issues"
    )
    parser.add_argument("-b", "--bond", help="Specific bond to check (e.g., bond0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show slave details")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show bonds with issues")
    opts = parser.parse_args(args)

    # Check if bonding available
    if not context.file_exists("/proc/net/bonding"):
        output.error("Network bonding not available")
        return 2

    # Get bonds to check
    if opts.bond:
        bonds_to_check = [opts.bond]
    else:
        bonds_to_check = get_bond_list(context)

    # Parse and analyze bonds
    results = []
    for bond_name in bonds_to_check:
        bond_info = parse_bond_file(bond_name, context)
        if bond_info:
            bond_info = analyze_bond_health(bond_info)
            results.append(bond_info)

    # Output
    if opts.format == "json":
        print(json.dumps(results, indent=2))
    else:
        if not results:
            print("No bonded interfaces found")
        else:
            for bond in results:
                if opts.warn_only and not bond["errors"] and not bond["warnings"]:
                    continue

                if bond["errors"]:
                    status = "ERROR"
                elif bond["warnings"]:
                    status = "WARNING"
                else:
                    status = "HEALTHY"

                active = len([s for s in bond["slaves"] if s["status"] == "up"])
                total = len(bond["slaves"])

                print(f"{bond['name']}: {status}")
                print(f"  Mode: {bond['mode']}")
                print(f"  MII Status: {bond['mii_status']}")
                print(f"  Slaves: {total} total, {active} active")

                if bond["active_slave"]:
                    print(f"  Active Slave: {bond['active_slave']}")

                if bond["errors"]:
                    print("  ERRORS:")
                    for err in bond["errors"]:
                        print(f"    - {err}")

                if bond["warnings"]:
                    print("  WARNINGS:")
                    for warn in bond["warnings"]:
                        print(f"    - {warn}")

                if opts.verbose:
                    print("  Slave Details:")
                    for slave in bond["slaves"]:
                        status_mark = "+" if slave["status"] == "up" else "-"
                        print(f"    {status_mark} {slave['name']}: {slave['status']} "
                              f"- {slave['speed']} {slave['duplex']} "
                              f"- {slave['link_failure_count']} failures")

                print()

    output.emit({"bonds": results})

    has_errors = any(bond["errors"] for bond in results)
    has_warnings = any(bond["warnings"] for bond in results)

    if has_errors:
        output.set_summary(f"{len(results)} bonds, errors found")
        return 1
    elif has_warnings:
        output.set_summary(f"{len(results)} bonds, warnings found")
        return 1

    output.set_summary(f"{len(results)} bonds healthy")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
