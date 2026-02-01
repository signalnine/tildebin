#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, nic, flapping, stability]
#   brief: Detect network interface link flapping

"""
Detect network interface link flapping on baremetal systems.

Link flapping occurs when a network interface repeatedly transitions between
up and down states. This can be caused by:
- Failing cables or transceivers
- Bad switch ports
- Auto-negotiation issues
- Power supply problems
- Driver bugs

This script monitors the carrier state of network interfaces and detects
flapping by checking the carrier_changes counter in sysfs.

Exit codes:
    0 - No flapping detected
    1 - Link flapping detected on one or more interfaces
    2 - Missing /sys filesystem or usage error
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_interface_list(context: Context) -> list[str] | None:
    """Get list of network interfaces from /sys/class/net."""
    net_path = "/sys/class/net"
    if not context.file_exists(net_path):
        return None

    interfaces = []
    try:
        for iface in sorted(context.glob("*", net_path)):
            iface_name = iface.split("/")[-1]

            # Skip loopback
            if iface_name == "lo":
                continue
            # Skip virtual interfaces
            if iface_name.startswith("veth") or iface_name.startswith("docker"):
                continue
            # Skip bonding_masters (not a real interface)
            if iface_name == "bonding_masters":
                continue
            # Verify it's a real interface (has carrier file)
            carrier_path = f"{net_path}/{iface_name}/carrier"
            if not context.file_exists(carrier_path):
                continue
            interfaces.append(iface_name)
    except OSError:
        return None

    return interfaces


def read_sysfs_int(context: Context, path: str) -> int | None:
    """Read an integer value from sysfs."""
    try:
        content = context.read_file(path)
        return int(content.strip())
    except (FileNotFoundError, IOError, ValueError):
        return None


def read_sysfs_str(context: Context, path: str) -> str:
    """Read a string value from sysfs."""
    try:
        return context.read_file(path).strip()
    except (FileNotFoundError, IOError):
        return "unknown"


def get_interface_info(context: Context, iface: str) -> dict:
    """Get comprehensive interface information."""
    net_path = "/sys/class/net"
    return {
        "interface": iface,
        "carrier": read_sysfs_int(context, f"{net_path}/{iface}/carrier"),
        "operstate": read_sysfs_str(context, f"{net_path}/{iface}/operstate"),
        "carrier_changes": read_sysfs_int(
            context, f"{net_path}/{iface}/carrier_changes"
        ),
        "carrier_up_count": read_sysfs_int(
            context, f"{net_path}/{iface}/carrier_up_count"
        ),
        "carrier_down_count": read_sysfs_int(
            context, f"{net_path}/{iface}/carrier_down_count"
        ),
        "speed_mbps": read_sysfs_int(context, f"{net_path}/{iface}/speed"),
    }


def analyze_flapping(
    context: Context,
    interfaces: list[str],
    flap_threshold: int,
) -> tuple[list[dict], list[dict]]:
    """Analyze interfaces for link flapping using carrier_changes counter."""
    results = []
    issues = []

    for iface in interfaces:
        info = get_interface_info(context, iface)

        result = {
            "interface": iface,
            "operstate": info["operstate"],
            "carrier": "up" if info["carrier"] == 1 else "down",
            "speed_mbps": info["speed_mbps"],
            "total_carrier_changes": info["carrier_changes"],
            "carrier_up_count": info["carrier_up_count"],
            "carrier_down_count": info["carrier_down_count"],
            "flapping": False,
        }

        # Check if carrier_changes exceeds threshold
        # Note: carrier_changes is cumulative since boot, so this is checking
        # total historical flapping. For real-time monitoring, you would
        # compare two readings over time.
        if info["carrier_changes"] is not None:
            if info["carrier_changes"] >= flap_threshold:
                result["flapping"] = True
                severity = (
                    "warning" if info["carrier_changes"] < flap_threshold * 5 else "critical"
                )
                issues.append(
                    {
                        "interface": iface,
                        "severity": severity,
                        "message": f"{iface}: {info['carrier_changes']} carrier changes since boot "
                        f"(threshold: {flap_threshold})",
                        "carrier_changes": info["carrier_changes"],
                    }
                )

        results.append(result)

    return results, issues


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
        description="Detect network interface link flapping"
    )
    parser.add_argument(
        "-I",
        "--interface",
        metavar="IFACE",
        help="Specific interface to check (default: all interfaces)",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=10,
        metavar="COUNT",
        help="Carrier changes threshold for flapping alert (default: %(default)s)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only output if flapping is detected",
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if opts.threshold < 1:
        output.error("Threshold must be at least 1")
        return 2

    # Get interface list
    if opts.interface:
        interfaces = [opts.interface]
        # Verify interface exists
        if not context.file_exists(f"/sys/class/net/{opts.interface}"):
            output.error(f"Interface '{opts.interface}' not found")
            return 2
    else:
        interfaces = get_interface_list(context)
        if interfaces is None:
            output.error("Cannot read /sys/class/net")
            return 2

        if not interfaces:
            output.error("No network interfaces found")
            return 2

    # Analyze interfaces
    results, issues = analyze_flapping(context, interfaces, opts.threshold)

    # Build output data
    output_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threshold": opts.threshold,
        "interfaces": results,
        "issues": issues,
        "summary": {
            "interfaces_checked": len(results),
            "interfaces_flapping": len([r for r in results if r["flapping"]]),
            "total_issues": len(issues),
        },
        "has_flapping": any(r["flapping"] for r in results),
        "healthy": len(issues) == 0,
    }

    # Output results
    if opts.format == "json":
        if not opts.warn_only or issues:
            print(json.dumps(output_data, indent=2))
    elif opts.format == "table":
        if not opts.warn_only or issues:
            # Header
            print(
                f"{'Interface':<15} {'State':<8} {'Status':<10} {'Speed':<12} "
                f"{'Changes':>10}"
            )
            print("-" * 65)

            for result in results:
                if opts.warn_only and not result["flapping"]:
                    continue

                status = "FLAPPING" if result["flapping"] else "STABLE"
                speed = (
                    f"{result['speed_mbps']}Mbps"
                    if result["speed_mbps"]
                    else "N/A"
                )
                total = (
                    str(result["total_carrier_changes"])
                    if result["total_carrier_changes"] is not None
                    else "N/A"
                )

                print(
                    f"{result['interface']:<15} {result['carrier'].upper():<8} "
                    f"{status:<10} {speed:<12} {total:>10}"
                )

            if issues:
                print()
                print(f"Flapping Issues ({len(issues)}):")
                for issue in issues:
                    print(f"  [{issue['severity'].upper()}] {issue['message']}")
    else:
        if not opts.warn_only or issues:
            lines = []
            lines.append("Link Flapping Detection")
            lines.append("=" * 70)
            lines.append(f"Threshold: {opts.threshold} carrier changes")
            lines.append("")

            for result in results:
                if opts.warn_only and not result["flapping"]:
                    continue

                status = "FLAPPING" if result["flapping"] else "STABLE"
                carrier = result["carrier"].upper()
                speed = (
                    f"{result['speed_mbps']}Mbps"
                    if result["speed_mbps"]
                    else "N/A"
                )

                lines.append(f"[{status}] {result['interface']} ({carrier}) - {speed}")

                total = result.get("total_carrier_changes", "N/A")
                lines.append(f"  Total carrier changes since boot: {total}")

                if result["carrier_up_count"] is not None:
                    lines.append(
                        f"  Carrier up/down count: "
                        f"{result['carrier_up_count']}/{result['carrier_down_count']}"
                    )

                lines.append("")

            # Summary
            if issues:
                lines.append(
                    f"Summary: {len(issues)} interface(s) with link flapping detected"
                )
                for issue in issues:
                    lines.append(f"  [{issue['severity'].upper()}] {issue['message']}")
            elif not opts.warn_only:
                lines.append("Summary: No link flapping detected")

            print("\n".join(lines))

    # Set summary
    output.set_summary(
        f"interfaces={output_data['summary']['interfaces_checked']}, "
        f"flapping={output_data['summary']['interfaces_flapping']}"
    )

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
