#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, storage, ssd, trim, performance]
#   brief: Monitor TRIM/discard support status for SSDs and NVMe drives

"""
Monitor TRIM/discard support status for SSDs and NVMe drives.

TRIM (ATA) or unmap/deallocate (NVMe/SCSI) commands allow the OS to inform
SSDs which blocks are no longer in use, enabling the drive's garbage collection
to work efficiently. Without TRIM, SSD performance degrades over time.

This tool checks:
- Whether the block device supports discard operations
- Filesystem mount options (discard vs fstrim)
- Actual discard granularity and limits
- Identifies misconfigured SSDs that should have TRIM enabled

Exit codes:
    0: All SSDs have proper TRIM configuration
    1: SSDs found with TRIM misconfiguration or warnings
    2: Usage error or no SSDs found
"""

import argparse
import re

from boxctl.core.context import Context
from boxctl.core.output import Output


def format_bytes(num_bytes: int) -> str:
    """Format bytes in human-readable form."""
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}TB"


def get_block_devices(context: Context) -> list[str]:
    """Get list of block devices."""
    result = context.run(["lsblk", "-d", "-n", "-o", "NAME,TYPE"])
    devices = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "disk":
            devices.append(parts[0])
    return devices


def is_ssd(device: str, context: Context) -> bool:
    """Check if device is an SSD (rotational = 0)."""
    rotational_path = f"/sys/block/{device}/queue/rotational"
    try:
        content = context.read_file(rotational_path)
        return content.strip() == "0"
    except FileNotFoundError:
        # If we can't determine, check if it's NVMe (always SSD)
        return device.startswith("nvme")


def get_device_info(device: str, context: Context) -> tuple[str, str]:
    """Get device model and size."""
    dev_path = f"/dev/{device}"
    result = context.run(["lsblk", "-n", "-o", "SIZE,MODEL", dev_path], check=False)
    if result.returncode != 0:
        return "N/A", "N/A"

    parts = result.stdout.strip().split(None, 1)
    size = parts[0] if len(parts) > 0 else "N/A"
    model = parts[1].strip() if len(parts) > 1 else "N/A"
    return size, model


def get_discard_support(device: str, context: Context) -> dict:
    """Check if device supports discard operations."""
    queue_path = f"/sys/block/{device}/queue"

    result = {
        "supported": False,
        "discard_granularity": 0,
        "discard_max_bytes": 0,
    }

    # Check discard_granularity - if non-zero, discard is supported
    granularity_path = f"{queue_path}/discard_granularity"
    try:
        content = context.read_file(granularity_path)
        result["discard_granularity"] = int(content.strip())
        result["supported"] = result["discard_granularity"] > 0
    except (FileNotFoundError, ValueError):
        pass

    # Check discard_max_bytes
    max_bytes_path = f"{queue_path}/discard_max_bytes"
    try:
        content = context.read_file(max_bytes_path)
        result["discard_max_bytes"] = int(content.strip())
    except (FileNotFoundError, ValueError):
        pass

    return result


def get_mount_info(context: Context) -> dict:
    """Get mount information for all filesystems."""
    result = context.run(["mount"], check=False)
    if result.returncode != 0:
        return {}

    mounts = {}
    for line in result.stdout.split("\n"):
        if not line:
            continue
        # Format: /dev/sda1 on /mnt type ext4 (rw,discard)
        match = re.match(r"^(/dev/\S+) on (\S+) type (\S+) \(([^)]*)\)", line)
        if match:
            device, mountpoint, fstype, options = match.groups()
            mounts[device] = {
                "mountpoint": mountpoint,
                "fstype": fstype,
                "options": options.split(","),
                "has_discard": "discard" in options,
            }
    return mounts


def check_fstrim_timer(context: Context) -> bool:
    """Check if fstrim.timer is enabled (systemd)."""
    result = context.run(["systemctl", "is-enabled", "fstrim.timer"], check=False)
    if result.returncode == 0:
        return result.stdout.strip() == "enabled"
    return False


def get_partitions(device: str, context: Context) -> list[str]:
    """Get partitions for a device."""
    result = context.run(["lsblk", "-n", "-o", "NAME", f"/dev/{device}"], check=False)
    if result.returncode != 0:
        return []

    partitions = []
    lines = result.stdout.strip().split("\n")
    for line in lines[1:]:  # Skip the device itself
        part = line.strip().lstrip("\u251c\u2500\u2514\u2502 ")  # Remove tree characters
        if part and part != device:
            partitions.append(part)
    return partitions


def analyze_device(
    device: str,
    context: Context,
    mounts: dict,
    fstrim_enabled: bool,
) -> dict:
    """Analyze TRIM status for a single device."""
    size, model = get_device_info(device, context)
    discard_info = get_discard_support(device, context)
    is_nvme = device.startswith("nvme")

    result = {
        "device": device,
        "path": f"/dev/{device}",
        "size": size,
        "model": model,
        "type": "NVMe" if is_nvme else "SATA/SAS SSD",
        "discard_supported": discard_info["supported"],
        "discard_granularity": discard_info["discard_granularity"],
        "discard_max_bytes": discard_info["discard_max_bytes"],
        "partitions": [],
        "issues": [],
        "status": "OK",
    }

    if not discard_info["supported"]:
        result["issues"].append({
            "severity": "WARNING",
            "message": "Device does not support discard operations",
        })
        result["status"] = "WARNING"
        return result

    # Check partitions/mounts
    partitions = get_partitions(device, context)

    for part in partitions:
        part_path = f"/dev/{part}"
        part_info = {
            "partition": part,
            "mounted": False,
            "mountpoint": None,
            "has_discard_mount": False,
        }

        # Check if mounted
        if part_path in mounts:
            mount = mounts[part_path]
            part_info["mounted"] = True
            part_info["mountpoint"] = mount["mountpoint"]
            part_info["has_discard_mount"] = mount["has_discard"]
            part_info["fstype"] = mount["fstype"]

        result["partitions"].append(part_info)

        # Check for issues
        if part_info["mounted"] and not part_info["has_discard_mount"]:
            if not fstrim_enabled:
                result["issues"].append({
                    "severity": "WARNING",
                    "message": f"{part} mounted without discard option and fstrim.timer not enabled",
                })
                result["status"] = "WARNING"

    # Also check if whole disk is in mounts (e.g., /dev/nvme0n1 without partitions)
    dev_path = f"/dev/{device}"
    if dev_path in mounts and not partitions:
        mount = mounts[dev_path]
        if not mount["has_discard"] and not fstrim_enabled:
            result["issues"].append({
                "severity": "WARNING",
                "message": "Device mounted without discard and fstrim.timer not enabled",
            })
            result["status"] = "WARNING"

    return result


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all OK, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor TRIM/discard status for SSDs and NVMe drives"
    )
    parser.add_argument("-d", "--device", help="Specific device to check (e.g., nvme0n1, sda)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show devices with issues")
    opts = parser.parse_args(args)

    # Get system information
    mounts = get_mount_info(context)
    fstrim_enabled = check_fstrim_timer(context)

    # Get devices to check
    if opts.device:
        device = opts.device.replace("/dev/", "")
        if not is_ssd(device, context):
            output.warning(f"{device} does not appear to be an SSD")
        devices = [device]
    else:
        try:
            all_devices = get_block_devices(context)
            devices = [d for d in all_devices if is_ssd(d, context)]
        except Exception as e:
            output.error(f"Failed to list devices: {e}")
            return 2

    if not devices:
        output.warning("No SSDs found")
        output.emit({"devices": [], "fstrim_timer_enabled": fstrim_enabled})

        output.render(opts.format, "Monitor TRIM/discard support status for SSDs and NVMe drives")
        return 0

    # Analyze devices
    results = []
    has_issues = False

    for device in devices:
        result = analyze_device(device, context, mounts, fstrim_enabled)

        if result["status"] != "OK":
            has_issues = True

        if not opts.warn_only or result["status"] != "OK" or result["issues"]:
            results.append(result)

    output.emit({
        "devices": results,
        "fstrim_timer_enabled": fstrim_enabled,
    })

    # Set summary
    ok_count = sum(1 for r in results if r["status"] == "OK")
    warning_count = sum(1 for r in results if r["status"] == "WARNING")
    output.set_summary(f"fstrim={fstrim_enabled}, {ok_count} ok, {warning_count} warnings")


    output.render(opts.format, "Monitor TRIM/discard support status for SSDs and NVMe drives")
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
