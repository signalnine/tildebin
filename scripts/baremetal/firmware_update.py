#!/usr/bin/env python3
# boxctl:
#   category: baremetal/firmware
#   tags: [firmware, fwupd, security, hardware, updates]
#   requires: [fwupdmgr]
#   privilege: user
#   related: [firmware_inventory, nic_firmware]
#   brief: Monitor pending firmware updates using fwupd

"""
Monitor pending firmware updates using fwupd (firmware update daemon).

Checks for available firmware updates on baremetal systems, helping maintain
security and stability by ensuring firmware is kept up to date across the fleet.

Detects:
- Devices with available firmware updates
- Security-critical firmware updates
- Firmware update service health
- Devices with known firmware issues

Exit codes:
    0: No pending updates or all devices up to date
    1: Pending firmware updates found
    2: Error (fwupdmgr not available or system error)
"""

import argparse
import json
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_fwupd_service(context: Context) -> dict[str, Any]:
    """Check if fwupd service is running and healthy."""
    info = {
        "active": False,
        "state": "unknown",
        "substate": "unknown",
    }

    try:
        result = context.run(
            ["systemctl", "is-active", "fwupd"], check=False
        )
        info["active"] = result.returncode == 0

        result = context.run(
            ["systemctl", "show", "fwupd", "--property=ActiveState,SubState"],
            check=False,
        )
        for line in result.stdout.strip().split("\n"):
            if "=" in line:
                key, value = line.split("=", 1)
                if key == "ActiveState":
                    info["state"] = value
                elif key == "SubState":
                    info["substate"] = value
    except Exception:
        info["state"] = "error"

    return info


def get_devices(context: Context) -> list[dict[str, Any]]:
    """Get list of devices that can be updated."""
    result = context.run(["fwupdmgr", "get-devices", "--json"], check=False)

    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
        return data.get("Devices", [])
    except json.JSONDecodeError:
        return []


def get_updates(context: Context) -> list[dict[str, Any]]:
    """Get list of available updates."""
    result = context.run(["fwupdmgr", "get-updates", "--json"], check=False)

    if result.returncode != 0:
        # No updates available or error
        return []

    try:
        data = json.loads(result.stdout)
        return data.get("Devices", [])
    except json.JSONDecodeError:
        return []


def analyze_device(device: dict[str, Any]) -> dict[str, Any]:
    """Analyze a device for update status."""
    name = device.get("Name", device.get("DeviceId", "Unknown"))
    vendor = device.get("Vendor", "Unknown")
    version = device.get("Version", "Unknown")
    device_id = device.get("DeviceId", "")

    # Check for flags
    flags = device.get("Flags", [])
    can_update = "updatable" in flags or "updatable-hidden" in flags
    needs_reboot = "needs-reboot" in flags
    is_internal = "internal" in flags

    # Check for releases (available updates)
    releases = device.get("Releases", [])
    has_update = len(releases) > 0

    # Get update details if available
    update_info = None
    if releases:
        latest = releases[0]
        update_info = {
            "version": latest.get("Version", "Unknown"),
            "urgency": latest.get("Urgency", "unknown"),
            "summary": latest.get("Summary", ""),
            "is_security": latest.get("IsSecurityRisk", False),
        }

    return {
        "name": name,
        "vendor": vendor,
        "current_version": version,
        "device_id": device_id,
        "can_update": can_update,
        "needs_reboot": needs_reboot,
        "is_internal": is_internal,
        "has_update": has_update,
        "update_info": update_info,
    }


def refresh_metadata(context: Context, force: bool = False) -> bool:
    """Refresh firmware metadata from remotes."""
    args = ["fwupdmgr", "refresh"]
    if force:
        args.append("--force")

    result = context.run(args, check=False)
    return result.returncode == 0


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no pending updates, 1 = updates available, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor pending firmware updates using fwupd"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed device information"
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--refresh", action="store_true", help="Refresh firmware metadata before checking"
    )
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Force refresh even if recently updated",
    )
    parser.add_argument(
        "--security-only",
        action="store_true",
        help="Only show/count security-related updates",
    )
    opts = parser.parse_args(args)

    # Check for fwupdmgr
    if not context.check_tool("fwupdmgr"):
        output.error("fwupdmgr not found. Install fwupd package.")
        return 2

    # Check service status
    service_status = check_fwupd_service(context)

    # Optionally refresh metadata
    if opts.refresh or opts.force_refresh:
        if opts.format == "plain":
            print("Refreshing firmware metadata...")
        refresh_metadata(context, force=opts.force_refresh)

    # Get device and update information
    raw_devices = get_devices(context)
    devices = [analyze_device(d) for d in raw_devices]

    # Filter for security-only if requested
    if opts.security_only:
        devices = [
            d
            for d in devices
            if d["has_update"] and d["update_info"] and d["update_info"].get("is_security")
        ]

    # Calculate summary
    devices_with_updates = [d for d in devices if d["has_update"]]
    total_devices = len(devices)
    updatable_devices = sum(1 for d in devices if d["can_update"])
    pending_updates = len(devices_with_updates)
    security_updates = sum(
        1
        for d in devices_with_updates
        if d["update_info"] and d["update_info"].get("is_security")
    )

    # Build result
    result_data = {
        "service": service_status,
        "devices": devices,
        "summary": {
            "total_devices": total_devices,
            "updatable_devices": updatable_devices,
            "pending_updates": pending_updates,
            "security_updates": security_updates,
        },
    }

    output.emit(result_data)

    # Output
    if opts.format == "json":
        print(json.dumps(result_data, indent=2))
    else:
        # Service status
        if opts.verbose:
            print("=== fwupd Service Status ===")
            status_str = "active" if service_status["active"] else "inactive"
            print(
                f"Service: {status_str} ({service_status['state']}/{service_status['substate']})"
            )
            print()

        # Devices summary
        if opts.verbose:
            print("=== Firmware Devices ===")
            for device in devices:
                status = "can update" if device["can_update"] else "not updatable"
                print(f"  {device['name']} ({device['vendor']})")
                print(f"    Version: {device['current_version']}")
                print(f"    Status: {status}")
                if device["has_update"] and device["update_info"]:
                    info = device["update_info"]
                    print(f"    Update available: {info['version']}")
                    if info["is_security"]:
                        print("    [SECURITY UPDATE]")
                print()

        # Updates summary
        if devices_with_updates:
            print("=== Pending Firmware Updates ===")
            for device in devices_with_updates:
                info = device["update_info"]
                security_tag = " [SECURITY]" if info and info.get("is_security") else ""
                urgency = info.get("urgency", "unknown") if info else "unknown"

                print(f"  {device['name']}")
                print(f"    Current: {device['current_version']}")
                print(
                    f"    Available: {info['version'] if info else 'unknown'}{security_tag}"
                )
                print(f"    Urgency: {urgency}")
                if info and info.get("summary"):
                    print(f"    Summary: {info['summary']}")
                print()
        else:
            print("No pending firmware updates")
            print()

        # Summary
        print("=== Summary ===")
        print(f"Total devices: {total_devices}")
        print(f"Updatable devices: {updatable_devices}")
        print(f"Pending updates: {pending_updates}")
        if security_updates:
            print(f"Security updates: {security_updates}")

    output.set_summary(f"{pending_updates} pending, {security_updates} security")

    return 1 if pending_updates > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
