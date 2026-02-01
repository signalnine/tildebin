#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, block, disk, storage, io]
#   requires: []
#   privilege: root
#   related: [disk_health, disk_io_latency, inode_usage]
#   brief: Monitor block device error statistics from /sys/block

"""
Monitor block device error statistics.

Reads block device statistics from /sys/block/*/stat to detect:
- High in-flight I/O counts
- High average queue times
- Completely idle devices (potential failures)

Returns exit code 0 if healthy, 1 if issues found, 2 on error.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_block_devices(context: Context) -> list[str]:
    """Get list of block devices from /sys/block/."""
    try:
        result = context.run(
            ["ls", "-1", "/sys/block"],
            check=False
        )
        if result.returncode != 0:
            return []

        devices = []
        for device in result.stdout.strip().split("\n"):
            device = device.strip()
            if not device:
                continue
            # Skip loop devices, ram devices, and device mapper
            if device.startswith(("loop", "ram", "dm-")):
                continue
            devices.append(device)

        return sorted(devices)
    except Exception:
        return []


def read_device_stat(device: str, context: Context) -> dict[str, Any] | None:
    """
    Read /sys/block/<device>/stat file.

    Format (11 fields):
    1. read I/Os
    2. read merges
    3. read sectors
    4. read ticks
    5. write I/Os
    6. write merges
    7. write sectors
    8. write ticks
    9. in_flight
    10. io_ticks
    11. time_in_queue
    """
    stat_path = f"/sys/block/{device}/stat"

    try:
        content = context.read_file(stat_path)
        fields = content.strip().split()

        if len(fields) < 11:
            return None

        return {
            "device": device,
            "read_ios": int(fields[0]),
            "read_merges": int(fields[1]),
            "read_sectors": int(fields[2]),
            "read_ticks": int(fields[3]),
            "write_ios": int(fields[4]),
            "write_merges": int(fields[5]),
            "write_sectors": int(fields[6]),
            "write_ticks": int(fields[7]),
            "in_flight": int(fields[8]),
            "io_ticks": int(fields[9]),
            "time_in_queue": int(fields[10]),
        }
    except Exception:
        return None


def get_device_model(device: str, context: Context) -> str:
    """Get device model from sysfs."""
    model_path = f"/sys/block/{device}/device/model"
    try:
        if context.file_exists(model_path):
            return context.read_file(model_path).strip()
    except Exception:
        pass
    return "Unknown"


def get_device_size(device: str, context: Context) -> int:
    """Get device size in bytes."""
    size_path = f"/sys/block/{device}/size"
    try:
        if context.file_exists(size_path):
            content = context.read_file(size_path)
            # Size is in 512-byte sectors
            sectors = int(content.strip())
            return sectors * 512
    except Exception:
        pass
    return 0


def format_bytes(bytes_val: int) -> str:
    """Format bytes in human-readable form."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}PB"


def analyze_device_health(stats: dict[str, Any]) -> tuple[str, list[str]]:
    """
    Analyze device statistics for potential issues.

    Returns (status, issues_list)
    status: 'healthy', 'warning', 'critical'
    """
    issues = []

    # Check for high I/O queue time (potential slowness)
    if stats["in_flight"] > 10:
        issues.append(f"High in-flight I/Os: {stats['in_flight']}")

    # Calculate average queue time per I/O
    total_ios = stats["read_ios"] + stats["write_ios"]
    if total_ios > 0:
        avg_queue_time = stats["time_in_queue"] / total_ios
        if avg_queue_time > 1000:  # More than 1 second average
            issues.append(f"High avg queue time: {avg_queue_time:.1f}ms")

    # Check if device is completely idle (might be failed)
    if total_ios == 0:
        issues.append("No I/O activity (device may be unused or failed)")

    if not issues:
        return "healthy", []
    elif len(issues) >= 2 or "failed" in str(issues):
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
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor block device error statistics")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed statistics")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show devices with issues")
    parser.add_argument("devices", nargs="*", help="Specific devices to check (default: all)")
    opts = parser.parse_args(args)

    # Check if /sys/block exists
    if not context.file_exists("/sys/block"):
        output.error("/sys/block not found (not a Linux system?)")
        return 2

    # Get devices to check
    if opts.devices:
        devices = opts.devices
    else:
        devices = get_block_devices(context)

    if not devices:
        output.error("No block devices found")
        return 2

    # Collect statistics
    results = []
    has_issues = False

    for device in devices:
        stats = read_device_stat(device, context)
        if stats is None:
            output.warning(f"Could not read stats for {device}")
            continue

        model = get_device_model(device, context)
        size = get_device_size(device, context)

        status, issues = analyze_device_health(stats)

        result = {
            "device": device,
            "model": model,
            "size_bytes": size,
            "size_human": format_bytes(size),
            "status": status,
            "issues": issues,
        }

        if opts.verbose:
            result["stats"] = stats

        if not opts.warn_only or status != "healthy":
            results.append(result)

        if status in ("warning", "critical"):
            has_issues = True

    if not results and not opts.warn_only:
        output.error("No valid device statistics collected")
        return 2

    # Emit results
    output.emit({"devices": results})

    # Set summary
    healthy = sum(1 for r in results if r["status"] == "healthy")
    unhealthy = len(results) - healthy
    output.set_summary(f"{len(results)} devices, {healthy} healthy, {unhealthy} with issues")

    # Log issues
    for result in results:
        if result["status"] == "critical":
            for issue in result["issues"]:
                output.error(f"{result['device']}: {issue}")
        elif result["status"] == "warning":
            for issue in result["issues"]:
                output.warning(f"{result['device']}: {issue}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
