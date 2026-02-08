#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, nic, firmware, driver]
#   brief: Audit NIC driver and firmware versions for consistency

"""
Audit NIC driver and firmware versions across network interfaces.

Identifies inconsistencies in NIC firmware/driver versions that can cause
subtle packet loss, latency issues, or performance degradation in large-scale
baremetal environments.

Exit codes:
    0 - All NICs consistent (or no physical NICs found)
    1 - Inconsistencies or issues detected
    2 - Usage error or missing dependency (ethtool required)
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_physical_interfaces(context: Context) -> list[str]:
    """Get list of physical network interfaces (excluding virtual/loopback)."""
    interfaces = []
    net_path = "/sys/class/net"

    try:
        for iface in sorted(context.glob("*", net_path)):
            iface_name = iface.split("/")[-1]

            # Skip loopback
            if iface_name == "lo":
                continue

            # Check if it's a physical device (has a device symlink)
            device_path = f"{net_path}/{iface_name}/device"
            if not context.file_exists(device_path):
                continue

            # Check interface type
            type_path = f"{net_path}/{iface_name}/type"
            if context.file_exists(type_path):
                try:
                    iface_type = context.read_file(type_path).strip()
                    # Type 1 = Ethernet
                    if iface_type != "1":
                        continue
                except (IOError, OSError):
                    pass

            interfaces.append(iface_name)
    except OSError:
        pass

    return interfaces


def get_driver_info(context: Context, iface: str) -> dict:
    """Get driver information for an interface using ethtool."""
    info = {
        "driver": "unknown",
        "driver_version": "unknown",
        "firmware_version": "unknown",
        "bus_info": "unknown",
    }

    result = context.run(["ethtool", "-i", iface])
    if result.returncode != 0:
        return info

    for line in result.stdout.split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower().replace("-", "_")
            value = value.strip()

            if key == "driver":
                info["driver"] = value
            elif key == "version":
                info["driver_version"] = value
            elif key == "firmware_version":
                info["firmware_version"] = value
            elif key == "bus_info":
                info["bus_info"] = value

    return info


def get_link_info(context: Context, iface: str) -> dict:
    """Get link speed and duplex information."""
    info = {
        "speed": "unknown",
        "duplex": "unknown",
        "link_detected": False,
    }

    result = context.run(["ethtool", iface])
    if result.returncode != 0:
        return info

    for line in result.stdout.split("\n"):
        line = line.strip()
        if line.startswith("Speed:"):
            info["speed"] = line.split(":", 1)[1].strip()
        elif line.startswith("Duplex:"):
            info["duplex"] = line.split(":", 1)[1].strip()
        elif line.startswith("Link detected:"):
            info["link_detected"] = "yes" in line.lower()

    return info


def audit_interfaces(
    context: Context,
    interfaces: list[str],
    expected_versions: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    """Audit all interfaces and check for inconsistencies."""
    results = []
    driver_versions = defaultdict(list)
    firmware_versions = defaultdict(list)

    for iface in interfaces:
        driver_info = get_driver_info(context, iface)
        link_info = get_link_info(context, iface)

        result = {
            "interface": iface,
            "driver": driver_info["driver"],
            "driver_version": driver_info["driver_version"],
            "firmware_version": driver_info["firmware_version"],
            "bus_info": driver_info["bus_info"],
            "speed": link_info["speed"],
            "duplex": link_info["duplex"],
            "link_detected": link_info["link_detected"],
            "issues": [],
        }

        # Track versions by driver for consistency checking
        driver = driver_info["driver"]
        if driver != "unknown":
            driver_versions[driver].append(
                {
                    "interface": iface,
                    "version": driver_info["driver_version"],
                }
            )
            firmware_versions[driver].append(
                {
                    "interface": iface,
                    "version": driver_info["firmware_version"],
                }
            )

        # Check against expected versions if provided
        if expected_versions:
            if driver in expected_versions:
                expected = expected_versions[driver]
                if "driver_version" in expected:
                    if driver_info["driver_version"] != expected["driver_version"]:
                        result["issues"].append(
                            f"Driver version mismatch: expected {expected['driver_version']}, "
                            f"got {driver_info['driver_version']}"
                        )
                if "firmware_version" in expected:
                    if driver_info["firmware_version"] != expected["firmware_version"]:
                        result["issues"].append(
                            f"Firmware version mismatch: expected {expected['firmware_version']}, "
                            f"got {driver_info['firmware_version']}"
                        )

        results.append(result)

    # Check for inconsistencies across same-driver interfaces
    inconsistencies = []

    for driver, versions in driver_versions.items():
        unique_versions = set(v["version"] for v in versions)
        if len(unique_versions) > 1:
            inconsistencies.append(
                {
                    "type": "driver_version",
                    "driver": driver,
                    "versions": list(unique_versions),
                    "interfaces": [v["interface"] for v in versions],
                }
            )
            # Mark affected interfaces
            for result in results:
                if result["driver"] == driver:
                    result["issues"].append(
                        f"Inconsistent driver version across {driver} interfaces"
                    )

    for driver, versions in firmware_versions.items():
        unique_versions = set(
            v["version"] for v in versions if v["version"] != "unknown"
        )
        if len(unique_versions) > 1:
            inconsistencies.append(
                {
                    "type": "firmware_version",
                    "driver": driver,
                    "versions": list(unique_versions),
                    "interfaces": [v["interface"] for v in versions],
                }
            )
            # Mark affected interfaces
            for result in results:
                if result["driver"] == driver:
                    if not any("Inconsistent firmware" in i for i in result["issues"]):
                        result["issues"].append(
                            f"Inconsistent firmware version across {driver} interfaces"
                        )

    return results, inconsistencies


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
        description="Audit NIC driver and firmware versions for consistency"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Specific interface to audit (default: all physical NICs)",
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
        help="Show detailed information including PCI bus and device details",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show interfaces with issues or inconsistencies",
    )
    parser.add_argument(
        "--expected",
        metavar="FILE",
        help="JSON file with expected driver/firmware versions",
    )

    opts = parser.parse_args(args)

    # Check for ethtool
    if not context.check_tool("ethtool"):
        output.error("ethtool is required but not found")
        return 2

    # Get interfaces to audit
    if opts.interface:
        interfaces = [opts.interface]
    else:
        interfaces = get_physical_interfaces(context)

    if not interfaces:
        output.emit({
            "interfaces": [],
            "inconsistencies": [],
            "summary": {"total_interfaces": 0},
        })
        output.render(opts.format, "NIC Firmware/Driver Audit")
        return 0

    # Load expected versions if provided
    expected_versions = None
    if opts.expected:
        try:
            content = context.read_file(opts.expected)
            expected_versions = json.loads(content)
        except (IOError, json.JSONDecodeError) as e:
            output.error(f"Error loading expected versions file: {e}")
            return 2

    # Audit interfaces
    results, inconsistencies = audit_interfaces(context, interfaces, expected_versions)

    # Determine if there are issues
    has_issues = any(r["issues"] for r in results) or inconsistencies

    # Build output data
    output_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "interfaces": results,
        "inconsistencies": inconsistencies,
        "summary": {
            "total_interfaces": len(results),
            "interfaces_with_issues": sum(1 for r in results if r["issues"]),
            "inconsistency_count": len(inconsistencies),
        },
        "healthy": not has_issues,
    }

    output.emit(output_data)

    # Output results
    if opts.format == "table":
        if opts.warn_only:
            results = [r for r in results if r["issues"]]

        if not results:
            print("No interfaces to display")
        else:
            # Header
            print(
                f"{'Interface':<12} {'Driver':<12} {'Driver Ver':<15} "
                f"{'Firmware Ver':<20} {'Speed':<12} {'Status':<8}"
            )
            print("-" * 85)

            for result in results:
                status = "OK" if not result["issues"] else "ISSUE"
                print(
                    f"{result['interface']:<12} "
                    f"{result['driver']:<12} "
                    f"{result['driver_version']:<15} "
                    f"{result['firmware_version']:<20} "
                    f"{result['speed']:<12} "
                    f"{status:<8}"
                )

            if inconsistencies:
                print()
                print("Inconsistencies:")
                for inc in inconsistencies:
                    print(
                        f"  - {inc['driver']}: {inc['type'].replace('_', ' ')} varies "
                        f"({', '.join(inc['versions'])})"
                    )
    else:
        output.render(opts.format, "NIC Firmware/Driver Audit", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    output.set_summary(
        f"total={output_data['summary']['total_interfaces']}, "
        f"issues={output_data['summary']['interfaces_with_issues']}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
