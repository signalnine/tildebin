#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, scsi, sas, storage, errors]
#   requires: []
#   privilege: root
#   related: [disk_health, fc_health, iscsi_health]
#   brief: Monitor SCSI/SAS device error counters from sysfs

"""
Monitor SCSI/SAS device error counters from sysfs.

Tracks SCSI error counters (iotmo_cnt, iodone_cnt, ioerr_cnt, iorequest_cnt)
for early detection of failing disks, SAS cables, or HBA issues.

The script reads from /sys/class/scsi_device/*/device/ which provides:
- iorequest_cnt: Total I/O requests sent
- iodone_cnt: I/O requests completed successfully
- ioerr_cnt: I/O requests that resulted in errors
- iotmo_cnt: I/O requests that timed out

Returns exit code 1 if any devices have errors or warnings.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# SCSI device type codes
SCSI_TYPES = {
    "0": "disk",
    "1": "tape",
    "2": "printer",
    "3": "processor",
    "4": "worm",
    "5": "cdrom",
    "6": "scanner",
    "7": "optical",
    "8": "changer",
    "9": "comm",
    "12": "raid",
    "13": "enclosure",
    "14": "rbc",
}


def get_scsi_devices(context: Context) -> list[dict[str, Any]]:
    """Get list of SCSI devices from /sys/class/scsi_device/."""
    devices: list[dict[str, Any]] = []
    scsi_path = "/sys/class/scsi_device"

    if not context.file_exists(scsi_path):
        return devices

    try:
        device_paths = context.glob("*", root=scsi_path)
    except Exception:
        return devices

    for device_link in sorted(device_paths):
        device_id = device_link.split("/")[-1]
        device_path = f"{device_link}/device"

        if context.file_exists(device_path):
            devices.append({
                "id": device_id,
                "path": device_path,
            })

    return devices


def get_device_info(device_path: str, context: Context) -> dict[str, str]:
    """Get SCSI device information from sysfs."""
    info: dict[str, str] = {
        "vendor": "Unknown",
        "model": "Unknown",
        "rev": "",
        "type": "Unknown",
        "state": "Unknown",
    }

    for attr in ["vendor", "model", "rev", "type", "state"]:
        attr_path = f"{device_path}/{attr}"
        if context.file_exists(attr_path):
            try:
                info[attr] = context.read_file(attr_path).strip()
            except Exception:
                pass

    # Get the block device name if this is a disk
    block_path = f"{device_path}/block"
    if context.file_exists(block_path):
        try:
            block_devices = context.glob("*", root=block_path)
            if block_devices:
                info["block_device"] = block_devices[0].split("/")[-1]
        except Exception:
            pass

    return info


def get_error_counters(device_path: str, context: Context) -> dict[str, int]:
    """Get SCSI error counters from sysfs."""
    counters: dict[str, int] = {
        "iorequest_cnt": 0,
        "iodone_cnt": 0,
        "ioerr_cnt": 0,
        "iotmo_cnt": 0,
    }

    for counter in counters:
        counter_path = f"{device_path}/{counter}"
        if context.file_exists(counter_path):
            try:
                value = context.read_file(counter_path).strip()
                counters[counter] = int(value, 0)  # base 0 handles hex
            except (ValueError, Exception):
                pass

    return counters


def get_device_type_name(type_code: str) -> str:
    """Convert SCSI device type code to name."""
    return SCSI_TYPES.get(type_code, f"type-{type_code}")


def analyze_device_health(
    counters: dict[str, int],
    info: dict[str, str],
) -> tuple[str, list[str]]:
    """
    Analyze SCSI error counters for potential issues.

    Returns (status, issues_list)
    status: 'healthy', 'warning', 'critical'
    """
    issues: list[str] = []

    # Check for I/O errors
    if counters["ioerr_cnt"] > 0:
        issues.append(f"I/O errors: {counters['ioerr_cnt']}")

    # Check for I/O timeouts (often indicates cable/path issues)
    if counters["iotmo_cnt"] > 0:
        issues.append(f"I/O timeouts: {counters['iotmo_cnt']}")

    # Check device state
    if info["state"] not in ("running", "Unknown"):
        issues.append(f"Device state: {info['state']}")

    # Calculate error rate if we have I/O requests
    if counters["iorequest_cnt"] > 0:
        error_rate = (counters["ioerr_cnt"] + counters["iotmo_cnt"]) / counters["iorequest_cnt"]
        if error_rate > 0.01:  # More than 1% error rate
            issues.append(f"High error rate: {error_rate:.2%}")

    # Determine severity
    if not issues:
        return "healthy", []
    elif counters["ioerr_cnt"] > 100 or counters["iotmo_cnt"] > 10:
        return "critical", issues
    else:
        return "warning", issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor SCSI/SAS device error counters")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show issues")
    parser.add_argument("--disks-only", action="store_true", help="Only show disk devices")
    opts = parser.parse_args(args)

    # Check if /sys/class/scsi_device exists
    if not context.file_exists("/sys/class/scsi_device"):
        output.error("SCSI subsystem not found (/sys/class/scsi_device not present)")

        output.render(opts.format, "Monitor SCSI/SAS device error counters from sysfs")
        return 2

    # Get SCSI devices
    devices = get_scsi_devices(context)

    if not devices:
        output.error("No SCSI devices found")

        output.render(opts.format, "Monitor SCSI/SAS device error counters from sysfs")
        return 2

    # Collect statistics
    results: list[dict[str, Any]] = []
    has_issues = False

    for device in devices:
        info = get_device_info(device["path"], context)

        # Filter to disks only if requested
        if opts.disks_only and info["type"] != "0":
            continue

        counters = get_error_counters(device["path"], context)
        status, issues = analyze_device_health(counters, info)

        result: dict[str, Any] = {
            "scsi_id": device["id"],
            "block_device": info.get("block_device"),
            "vendor": info["vendor"].strip(),
            "model": info["model"].strip(),
            "type": get_device_type_name(info["type"]),
            "state": info["state"],
            "status": status,
            "issues": issues,
        }

        if opts.verbose:
            result["counters"] = counters

        results.append(result)

        if status in ("warning", "critical"):
            has_issues = True

    if not results:
        if opts.disks_only:
            output.error("No SCSI disk devices found")
        else:
            output.error("No SCSI device statistics collected")

        output.render(opts.format, "Monitor SCSI/SAS device error counters from sysfs")
        return 2

    output.emit({
        "devices": results,
        "summary": {
            "total_devices": len(results),
            "healthy": sum(1 for r in results if r["status"] == "healthy"),
            "warning": sum(1 for r in results if r["status"] == "warning"),
            "critical": sum(1 for r in results if r["status"] == "critical"),
        },
    })

    # Set summary
    healthy = sum(1 for r in results if r["status"] == "healthy")
    output.set_summary(f"{healthy}/{len(results)} SCSI devices healthy")

    output.render(opts.format, "Monitor SCSI/SAS device error counters from sysfs")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
