#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, hardware, security, usb, devices]
#   brief: Monitor USB devices for security compliance

"""
Monitor USB devices connected to baremetal servers for security compliance.

Scans USB devices attached to the system and detects potentially unauthorized
devices. Useful for data center security where USB storage devices may be
prohibited or where only specific devices are allowed.

Checks performed:
- Enumerate all connected USB devices
- Classify devices by type (storage, HID, network, etc.)
- Detect mass storage devices (potential data exfiltration)
- Compare against allowed device whitelist (optional)

Exit codes:
    0 - No issues detected (all devices allowed or no storage devices)
    1 - Unauthorized or flagged devices detected
    2 - Usage error or /sys/bus/usb not available
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


USB_SYS_PATH = "/sys/bus/usb/devices"

# USB class codes
USB_CLASSES = {
    "00": "Device",
    "01": "Audio",
    "02": "Communications",
    "03": "HID",
    "05": "Physical",
    "06": "Image",
    "07": "Printer",
    "08": "Mass Storage",
    "09": "Hub",
    "0a": "CDC-Data",
    "0b": "Smart Card",
    "0d": "Content Security",
    "0e": "Video",
    "0f": "Personal Healthcare",
    "10": "Audio/Video",
    "dc": "Diagnostic",
    "e0": "Wireless Controller",
    "ef": "Miscellaneous",
    "fe": "Application Specific",
    "ff": "Vendor Specific",
}


def read_sysfs_value(context: Context, path: str) -> str | None:
    """Read a value from sysfs, return None if not available."""
    try:
        return context.read_file(path).strip()
    except (FileNotFoundError, PermissionError, IOError):
        return None


def get_usb_devices(context: Context) -> list[dict[str, Any]] | None:
    """
    Enumerate USB devices from /sys/bus/usb/devices.

    Returns:
        list: List of USB device dictionaries, or None if USB sysfs unavailable
    """
    devices = []

    if not context.file_exists(USB_SYS_PATH):
        return None

    # Get device directories
    device_paths = context.glob("*", root=USB_SYS_PATH)

    for device_path in device_paths:
        device_name = device_path.split("/")[-1]

        # Skip interfaces (contain ':'), we want devices only
        if ":" in device_name:
            continue

        # Skip root hubs pattern like 'usb1', 'usb2'
        if device_name.startswith("usb"):
            continue

        base = f"{USB_SYS_PATH}/{device_name}"

        # Get device info
        vendor_id = read_sysfs_value(context, f"{base}/idVendor")
        product_id = read_sysfs_value(context, f"{base}/idProduct")

        # Skip if no vendor/product (not a real device)
        if not vendor_id or not product_id:
            continue

        manufacturer = read_sysfs_value(context, f"{base}/manufacturer")
        product = read_sysfs_value(context, f"{base}/product")
        serial = read_sysfs_value(context, f"{base}/serial")
        device_class = read_sysfs_value(context, f"{base}/bDeviceClass")
        bus_num = read_sysfs_value(context, f"{base}/busnum")
        dev_num = read_sysfs_value(context, f"{base}/devnum")
        speed = read_sysfs_value(context, f"{base}/speed")

        # Determine device class name
        class_name = "Unknown"
        if device_class:
            class_name = USB_CLASSES.get(device_class.lower(), f"Class {device_class}")

        # Check interfaces for actual class (device class 00 means check interfaces)
        interface_classes = []
        interface_paths = context.glob(f"{device_name}:*", root=USB_SYS_PATH)
        for iface_path in interface_paths:
            iface_class = read_sysfs_value(context, f"{iface_path}/bInterfaceClass")
            if iface_class:
                iface_class_name = USB_CLASSES.get(
                    iface_class.lower(), f"Class {iface_class}"
                )
                interface_classes.append(
                    {"class_code": iface_class.lower(), "class_name": iface_class_name}
                )

        # Determine if this is a storage device
        is_storage = (
            device_class
            and device_class.lower() == "08"
            or any(ic["class_code"] == "08" for ic in interface_classes)
        )

        device_info = {
            "bus": bus_num,
            "device": dev_num,
            "vendor_id": vendor_id,
            "product_id": product_id,
            "manufacturer": manufacturer or "Unknown",
            "product": product or "Unknown",
            "serial": serial,
            "device_class": device_class,
            "class_name": class_name,
            "interface_classes": interface_classes,
            "speed": speed,
            "is_storage": is_storage,
            "path": base,
        }

        devices.append(device_info)

    return devices


def load_whitelist(context: Context, whitelist_file: str) -> set[tuple[str, str]] | None:
    """
    Load device whitelist from file.

    Whitelist format (one per line):
        vendor_id:product_id  # Comment

    Args:
        context: Execution context
        whitelist_file: Path to whitelist file

    Returns:
        set: Set of (vendor_id, product_id) tuples, or None if load failed
    """
    whitelist = set()

    try:
        content = context.read_file(whitelist_file)
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Remove inline comments
            if "#" in line:
                line = line.split("#")[0].strip()

            # Parse vendor:product
            if ":" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    vendor = parts[0].strip().lower()
                    product = parts[1].strip().lower()
                    whitelist.add((vendor, product))
    except (FileNotFoundError, PermissionError):
        return None

    return whitelist


def analyze_devices(
    devices: list[dict[str, Any]],
    whitelist: set[tuple[str, str]] | None = None,
    flag_storage: bool = True,
) -> dict[str, Any]:
    """
    Analyze USB devices for security issues.

    Args:
        devices: List of USB device dictionaries
        whitelist: Optional set of allowed (vendor_id, product_id) tuples
        flag_storage: Flag mass storage devices as issues

    Returns:
        dict: Analysis results with issues list
    """
    results = {
        "total_devices": len(devices),
        "storage_devices": 0,
        "flagged_devices": [],
        "allowed_devices": [],
        "issues": [],
    }

    for device in devices:
        vendor_id = device["vendor_id"].lower()
        product_id = device["product_id"].lower()
        device_key = (vendor_id, product_id)

        is_flagged = False
        flag_reasons = []

        # Check whitelist
        if whitelist is not None:
            if device_key not in whitelist:
                is_flagged = True
                flag_reasons.append("Not in whitelist")

        # Check for storage devices
        if device["is_storage"]:
            results["storage_devices"] += 1
            if flag_storage:
                is_flagged = True
                flag_reasons.append("Mass storage device")

        if is_flagged:
            results["flagged_devices"].append(
                {
                    "device": device,
                    "reasons": flag_reasons,
                }
            )
            for reason in flag_reasons:
                results["issues"].append(
                    {
                        "severity": "WARNING",
                        "device": f"{device['manufacturer']} {device['product']}",
                        "vendor_product": f"{vendor_id}:{product_id}",
                        "reason": reason,
                    }
                )
        else:
            results["allowed_devices"].append(device)

    return results


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor USB devices for security compliance"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed device information"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show flagged devices"
    )
    parser.add_argument(
        "--whitelist", metavar="FILE", help="Path to device whitelist file"
    )
    parser.add_argument(
        "--no-flag-storage",
        action="store_true",
        help="Do not flag mass storage devices",
    )
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check if USB sysfs is available
    if not context.file_exists(USB_SYS_PATH):
        output.error("/sys/bus/usb/devices not found. USB sysfs may not be available.")
        return 2

    # Load whitelist if specified
    whitelist = None
    if opts.whitelist:
        whitelist = load_whitelist(context, opts.whitelist)
        if whitelist is None:
            output.error(f"Could not load whitelist from {opts.whitelist}")
            return 2

    # Get USB devices
    devices = get_usb_devices(context)
    if devices is None:
        output.error("Could not enumerate USB devices")
        return 2

    # Analyze devices
    results = analyze_devices(
        devices, whitelist=whitelist, flag_storage=not opts.no_flag_storage
    )

    # Build output data
    output_data = {
        "summary": {
            "total_devices": results["total_devices"],
            "storage_devices": results["storage_devices"],
            "flagged_count": len(results["flagged_devices"]),
        },
        "issues": results["issues"],
        "has_issues": len(results["issues"]) > 0,
    }

    if opts.verbose:
        output_data["devices"] = devices
        output_data["flagged_devices"] = results["flagged_devices"]

    # Filter for warn-only mode
    if opts.warn_only and not results["issues"]:
        # No output needed in warn-only mode if no issues
        output.emit({"summary": output_data["summary"], "issues": [], "has_issues": False})
        output.set_summary("No flagged USB devices")
        return 0

    output.emit(output_data)

    # Set summary
    if results["issues"]:
        output.set_summary(
            f"{len(results['flagged_devices'])} flagged USB device(s) detected"
        )
        return 1
    else:
        output.set_summary(
            f"{results['total_devices']} USB device(s), no issues"
        )
        return 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
