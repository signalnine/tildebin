#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, btrfs, filesystem, storage]
#   requires: [btrfs]
#   privilege: root
#   related: [zfs_health, disk_health, inode_usage]
#   brief: Monitor BTRFS filesystem health and configuration

"""
Monitor BTRFS filesystem health and configuration.

Monitors BTRFS filesystems for health issues including:
- Device errors or missing devices
- Filesystem usage and metadata space
- Scrub status and age
- RAID degradation

Returns exit code 0 if healthy, 1 if issues found, 2 on error.
"""

import argparse
import re
from datetime import datetime
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_btrfs_filesystems(context: Context) -> list[dict[str, str]]:
    """Get list of mounted BTRFS filesystems."""
    result = context.run(
        ["findmnt", "-t", "btrfs", "-n", "-o", "TARGET,SOURCE,OPTIONS"]
    )

    filesystems = []
    seen_devices = set()

    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = line.split(None, 2)
        if len(parts) < 2:
            continue

        mount_point = parts[0]
        source = parts[1]
        options = parts[2] if len(parts) > 2 else ""

        # Extract the base device (handle subvolumes)
        base_device = source.split("[")[0]

        # Skip if we've already processed this device (subvolume mounts)
        if base_device in seen_devices:
            continue
        seen_devices.add(base_device)

        filesystems.append({
            "mount_point": mount_point,
            "device": base_device,
            "options": options,
        })

    return filesystems


def get_filesystem_usage(mount_point: str, context: Context) -> dict[str, Any]:
    """Get BTRFS filesystem usage information."""
    result = context.run(
        ["btrfs", "filesystem", "usage", "-b", mount_point], check=False
    )

    usage = {
        "total_bytes": 0,
        "used_bytes": 0,
        "free_bytes": 0,
        "free_estimated_bytes": 0,
        "data_ratio": 1.0,
        "metadata_ratio": 1.0,
        "used_percent": 0.0,
    }

    for line in result.stdout.split("\n"):
        line = line.strip()

        if line.startswith("Device size:"):
            match = re.search(r"(\d+)", line)
            if match:
                usage["total_bytes"] = int(match.group(1))

        elif line.startswith("Used:"):
            match = re.search(r"(\d+)", line)
            if match:
                usage["used_bytes"] = int(match.group(1))

        elif line.startswith("Free (estimated):"):
            match = re.search(r"(\d+)", line)
            if match:
                usage["free_estimated_bytes"] = int(match.group(1))

        elif line.startswith("Free (statfs"):
            match = re.search(r"(\d+)", line)
            if match:
                usage["free_bytes"] = int(match.group(1))

        elif line.startswith("Data ratio:"):
            match = re.search(r"([\d.]+)", line)
            if match:
                usage["data_ratio"] = float(match.group(1))

        elif line.startswith("Metadata ratio:"):
            match = re.search(r"([\d.]+)", line)
            if match:
                usage["metadata_ratio"] = float(match.group(1))

    # Calculate usage percentage
    if usage["total_bytes"] > 0:
        usage["used_percent"] = (usage["used_bytes"] / usage["total_bytes"]) * 100

    return usage


def get_device_stats(mount_point: str, context: Context) -> list[dict[str, Any]]:
    """Get BTRFS device statistics (error counts)."""
    result = context.run(["btrfs", "device", "stats", mount_point], check=False)

    devices: dict[str, dict[str, Any]] = {}

    for line in result.stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Parse device path from stat lines like:
        # [/dev/sda1].write_io_errs    0
        match = re.match(r"\[([^\]]+)\]\.(\w+)\s+(\d+)", line)
        if match:
            device = match.group(1)
            stat_name = match.group(2)
            stat_value = int(match.group(3))

            if device not in devices:
                devices[device] = {
                    "device": device,
                    "write_io_errs": 0,
                    "read_io_errs": 0,
                    "flush_io_errs": 0,
                    "corruption_errs": 0,
                    "generation_errs": 0,
                    "total_errors": 0,
                }

            devices[device][stat_name] = stat_value

    # Calculate total errors for each device
    for device in devices.values():
        device["total_errors"] = (
            device["write_io_errs"]
            + device["read_io_errs"]
            + device["flush_io_errs"]
            + device["corruption_errs"]
            + device["generation_errs"]
        )

    return list(devices.values())


def get_scrub_status(mount_point: str, context: Context) -> dict[str, Any]:
    """Get BTRFS scrub status for a filesystem."""
    result = context.run(["btrfs", "scrub", "status", mount_point], check=False)

    status = {
        "running": False,
        "last_scrub": None,
        "scrub_age_days": None,
        "errors_found": 0,
    }

    for line in result.stdout.split("\n"):
        line = line.strip()

        if "Status:" in line:
            status["running"] = "running" in line.lower()

        elif line.startswith("Scrub started:") or line.startswith("Scrub finished:"):
            match = re.search(r":\s+(.+)$", line)
            if match:
                date_str = match.group(1).strip()
                if "no stats" not in date_str.lower():
                    status["last_scrub"] = date_str
                    # Parse date
                    parsed = parse_scrub_date(date_str)
                    if parsed:
                        age = (datetime.now() - parsed).days
                        status["scrub_age_days"] = max(0, age)

        elif "Error summary:" in line:
            if "no errors found" not in line.lower():
                # Count errors
                for match in re.finditer(r"(\w+)=(\d+)", line):
                    count = int(match.group(2))
                    status["errors_found"] += count

    # Handle "no stats available" case
    if "no stats available" in result.stdout.lower():
        status["last_scrub"] = None
        status["scrub_age_days"] = None

    return status


def parse_scrub_date(date_str: str) -> datetime | None:
    """Parse a date string from BTRFS scrub output."""
    formats = [
        "%a %b %d %H:%M:%S %Y",  # Sun Jan 26 10:00:00 2025
        "%Y-%m-%d %H:%M:%S",  # 2025-01-26 10:00:00
    ]

    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    return None


def get_filesystem_info(mount_point: str, context: Context) -> dict[str, Any]:
    """Get BTRFS filesystem information (label, UUID, devices)."""
    result = context.run(["btrfs", "filesystem", "show", mount_point], check=False)

    info = {
        "label": None,
        "uuid": None,
        "total_devices": 0,
        "missing_devices": 0,
    }

    for line in result.stdout.split("\n"):
        line_stripped = line.strip()

        # Parse label and UUID from first line
        if "Label:" in line:
            label_match = re.search(r"Label:\s*'?([^']*)'?", line)
            if label_match:
                label = label_match.group(1).strip()
                if label and label != "none":
                    info["label"] = label

            uuid_match = re.search(r"uuid:\s*([0-9a-f-]+)", line, re.I)
            if uuid_match:
                info["uuid"] = uuid_match.group(1)

        # Parse total devices
        elif "Total devices" in line:
            match = re.search(r"Total devices\s+(\d+)", line)
            if match:
                info["total_devices"] = int(match.group(1))

        # Check for missing devices
        if "Some devices missing" in line or "missing" in line_stripped.lower():
            info["missing_devices"] += 1

    return info


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human readable format."""
    if bytes_val == 0:
        return "0 B"
    if bytes_val >= 1024**4:
        return f"{bytes_val / (1024**4):.1f} TiB"
    elif bytes_val >= 1024**3:
        return f"{bytes_val / (1024**3):.1f} GiB"
    elif bytes_val >= 1024**2:
        return f"{bytes_val / (1024**2):.1f} MiB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KiB"
    else:
        return f"{bytes_val} B"


def analyze_filesystems(
    filesystems_data: list[dict[str, Any]],
    capacity_warn: int,
    capacity_crit: int,
    scrub_warn_days: int,
    error_threshold: int,
) -> list[dict[str, Any]]:
    """Analyze filesystems for health issues."""
    issues = []

    for fs in filesystems_data:
        mount_point = fs["mount_point"]
        usage = fs.get("usage", {})
        scrub = fs.get("scrub", {})
        device_stats = fs.get("device_stats", [])
        info = fs.get("info", {})

        # Check capacity
        used_percent = usage.get("used_percent", 0)
        if used_percent >= capacity_crit:
            issues.append({
                "severity": "CRITICAL",
                "component": "filesystem",
                "mount_point": mount_point,
                "metric": "capacity",
                "value": used_percent,
                "threshold": capacity_crit,
                "message": f"BTRFS {mount_point} critically full: {used_percent:.1f}% used",
            })
        elif used_percent >= capacity_warn:
            issues.append({
                "severity": "WARNING",
                "component": "filesystem",
                "mount_point": mount_point,
                "metric": "capacity",
                "value": used_percent,
                "threshold": capacity_warn,
                "message": f"BTRFS {mount_point} running low: {used_percent:.1f}% used",
            })

        # Check for missing devices (RAID degradation)
        if info.get("missing_devices", 0) > 0:
            issues.append({
                "severity": "CRITICAL",
                "component": "filesystem",
                "mount_point": mount_point,
                "metric": "missing_devices",
                "value": info["missing_devices"],
                "message": f"BTRFS {mount_point} has {info['missing_devices']} missing device(s)",
            })

        # Check scrub age
        if scrub and scrub.get("scrub_age_days") is not None:
            scrub_age = scrub["scrub_age_days"]
            if scrub_age >= scrub_warn_days:
                issues.append({
                    "severity": "WARNING",
                    "component": "filesystem",
                    "mount_point": mount_point,
                    "metric": "scrub_age_days",
                    "value": scrub_age,
                    "threshold": scrub_warn_days,
                    "message": f"BTRFS {mount_point} not scrubbed for {scrub_age} days",
                })
        elif scrub and scrub.get("last_scrub") is None and not scrub.get("running", False):
            issues.append({
                "severity": "WARNING",
                "component": "filesystem",
                "mount_point": mount_point,
                "metric": "scrub_age_days",
                "value": None,
                "message": f"BTRFS {mount_point} has never been scrubbed",
            })

        # Check scrub errors
        if scrub and scrub.get("errors_found", 0) > 0:
            issues.append({
                "severity": "WARNING",
                "component": "filesystem",
                "mount_point": mount_point,
                "metric": "scrub_errors",
                "value": scrub["errors_found"],
                "message": f"BTRFS {mount_point} scrub found {scrub['errors_found']} errors",
            })

        # Check device I/O errors
        for dev in device_stats:
            if dev["total_errors"] >= error_threshold:
                severity = "CRITICAL" if dev["total_errors"] >= error_threshold * 10 else "WARNING"
                issues.append({
                    "severity": severity,
                    "component": "device",
                    "mount_point": mount_point,
                    "device": dev["device"],
                    "metric": "io_errors",
                    "value": dev["total_errors"],
                    "threshold": error_threshold,
                    "message": f"Device {dev['device']} has {dev['total_errors']} errors",
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
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor BTRFS filesystem health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument(
        "--capacity-warn", type=int, default=80,
        help="Warning threshold for capacity (default: 80%%)"
    )
    parser.add_argument(
        "--capacity-crit", type=int, default=90,
        help="Critical threshold for capacity (default: 90%%)"
    )
    parser.add_argument(
        "--scrub-warn", type=int, default=30,
        help="Warning threshold for days since last scrub (default: 30)"
    )
    parser.add_argument(
        "--error-threshold", type=int, default=1,
        help="Device error count threshold (default: 1)"
    )
    opts = parser.parse_args(args)

    # Check for btrfs tool
    if not context.check_tool("btrfs"):
        output.error("btrfs not found. Install btrfs-progs package.")

        output.render(opts.format, "Monitor BTRFS filesystem health and configuration")
        return 2

    # Get list of BTRFS filesystems
    try:
        filesystems = get_btrfs_filesystems(context)
    except Exception as e:
        output.error(f"Failed to list BTRFS filesystems: {e}")

        output.render(opts.format, "Monitor BTRFS filesystem health and configuration")
        return 2

    if not filesystems:
        output.emit({"filesystems": [], "issues": []})
        output.set_summary("No BTRFS filesystems found")

        output.render(opts.format, "Monitor BTRFS filesystem health and configuration")
        return 0

    # Gather data for each filesystem
    filesystems_data = []
    for fs in filesystems:
        mount_point = fs["mount_point"]

        fs_data = {
            "mount_point": mount_point,
            "device": fs["device"],
            "usage": get_filesystem_usage(mount_point, context),
            "scrub": get_scrub_status(mount_point, context),
            "device_stats": get_device_stats(mount_point, context),
            "info": get_filesystem_info(mount_point, context),
        }
        filesystems_data.append(fs_data)

    # Analyze for issues
    issues = analyze_filesystems(
        filesystems_data,
        opts.capacity_warn,
        opts.capacity_crit,
        opts.scrub_warn,
        opts.error_threshold,
    )

    # Emit data
    if opts.verbose:
        output.emit({"filesystems": filesystems_data, "issues": issues})
    else:
        # Simplified output
        summary = []
        for fs in filesystems_data:
            summary.append({
                "mount_point": fs["mount_point"],
                "device": fs["device"],
                "used_percent": fs["usage"].get("used_percent", 0),
            })
        output.emit({"filesystems": summary, "issues": issues})

    # Set summary
    healthy = len(filesystems_data) - len([i for i in issues if i["severity"] == "CRITICAL"])
    output.set_summary(f"{len(filesystems_data)} filesystems, {len(issues)} issues")

    # Log warnings
    for issue in issues:
        if issue["severity"] == "CRITICAL":
            output.error(issue["message"])
        else:
            output.warning(issue["message"])

    # Return exit code
    if any(i["severity"] == "CRITICAL" for i in issues):

        output.render(opts.format, "Monitor BTRFS filesystem health and configuration")
        return 1
    elif issues:

        output.render(opts.format, "Monitor BTRFS filesystem health and configuration")
        return 1
    else:

        output.render(opts.format, "Monitor BTRFS filesystem health and configuration")
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
