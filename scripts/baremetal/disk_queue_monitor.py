#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, performance, storage, io, queue]
#   brief: Monitor disk I/O queue depths to detect storage bottlenecks

"""
Monitor disk I/O queue depths to detect storage bottlenecks and saturation.

Monitors block device queue depths by reading /sys/block/*/stat to identify
storage devices under heavy load. High queue depths indicate I/O saturation
that causes latency spikes and performance degradation.

Exit codes:
    0: All devices healthy (queue depths below thresholds)
    1: Warnings detected (high queue depths or saturation)
    2: Usage error or no block devices found
"""

import argparse
import os

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_block_devices(context: Context) -> list[str]:
    """Get list of physical block devices."""
    devices = []

    try:
        block_entries = context.glob("*", "/sys/block")
    except Exception:
        return devices

    for entry in block_entries:
        device = os.path.basename(entry)

        # Skip loop devices, ram disks
        if device.startswith("loop") or device.startswith("ram"):
            continue

        # Include real devices (have device link) or virtual ones (dm, md, nvme)
        device_link = f"/sys/block/{device}/device"
        is_physical = context.file_exists(device_link)
        is_dm = device.startswith("dm-")
        is_md = device.startswith("md")
        is_nvme = device.startswith("nvme")

        if is_physical or is_dm or is_md or is_nvme:
            devices.append(device)

    return sorted(devices)


def parse_device_stat(content: str) -> dict | None:
    """
    Parse I/O statistics from /sys/block/<device>/stat content.

    Fields from Documentation/block/stat.txt:
    0: reads completed
    1: reads merged
    2: sectors read
    3: time reading (ms)
    4: writes completed
    5: writes merged
    6: sectors written
    7: time writing (ms)
    8: I/Os currently in progress (queue depth)
    9: time doing I/Os (ms)
    10: weighted time doing I/Os (ms)
    """
    try:
        fields = content.split()
        if len(fields) >= 11:
            return {
                "reads_completed": int(fields[0]),
                "reads_merged": int(fields[1]),
                "sectors_read": int(fields[2]),
                "read_time_ms": int(fields[3]),
                "writes_completed": int(fields[4]),
                "writes_merged": int(fields[5]),
                "sectors_written": int(fields[6]),
                "write_time_ms": int(fields[7]),
                "ios_in_progress": int(fields[8]),
                "io_time_ms": int(fields[9]),
                "weighted_io_time_ms": int(fields[10]),
            }
    except (ValueError, IndexError):
        pass
    return None


def get_device_type(device: str, context: Context) -> str:
    """Determine device type (nvme, ssd, hdd, dm, raid)."""
    if device.startswith("nvme"):
        return "nvme"
    if device.startswith("dm-"):
        return "dm"
    if device.startswith("md"):
        return "raid"

    # Check rotational flag
    rotational_path = f"/sys/block/{device}/queue/rotational"
    try:
        content = context.read_file(rotational_path)
        rotational = int(content.strip())
        return "hdd" if rotational == 1 else "ssd"
    except (FileNotFoundError, ValueError):
        pass

    return "unknown"


def get_queue_depth_limit(device: str, context: Context) -> int:
    """Get the maximum queue depth for a device."""
    nr_requests_path = f"/sys/block/{device}/queue/nr_requests"
    try:
        content = context.read_file(nr_requests_path)
        return int(content.strip())
    except (FileNotFoundError, ValueError):
        pass
    return 128  # Common default


def get_scheduler(device: str, context: Context) -> str:
    """Get the I/O scheduler for a device."""
    scheduler_path = f"/sys/block/{device}/queue/scheduler"
    try:
        content = context.read_file(scheduler_path)
        # Active scheduler is in brackets, e.g. "[mq-deadline] none"
        import re
        match = re.search(r"\[([^\]]+)\]", content)
        if match:
            return match.group(1)
        return content.strip()
    except FileNotFoundError:
        return "unknown"


def get_device_size_gb(device: str, context: Context) -> float:
    """Get device size in GB."""
    size_path = f"/sys/block/{device}/size"
    try:
        content = context.read_file(size_path)
        sectors = int(content.strip())
        # Sectors are 512 bytes
        return round((sectors * 512) / (1024**3), 2)
    except (FileNotFoundError, ValueError):
        return 0.0


def analyze_device(
    device: str,
    stat: dict,
    context: Context,
    warn_threshold: int,
    crit_threshold: int,
) -> dict:
    """Analyze a single device and return status."""
    device_type = get_device_type(device, context)
    max_queue = get_queue_depth_limit(device, context)
    scheduler = get_scheduler(device, context)
    size_gb = get_device_size_gb(device, context)

    queue_depth = stat["ios_in_progress"]
    total_ios = stat["reads_completed"] + stat["writes_completed"]

    # Calculate utilization percentage
    utilization_pct = round((queue_depth / max_queue) * 100, 1) if max_queue > 0 else 0

    # Determine status
    if queue_depth >= crit_threshold:
        status = "critical"
    elif queue_depth >= warn_threshold:
        status = "warning"
    else:
        status = "ok"

    return {
        "device": device,
        "device_path": f"/dev/{device}",
        "type": device_type,
        "scheduler": scheduler,
        "max_queue_depth": max_queue,
        "size_gb": size_gb,
        "queue_depth": queue_depth,
        "total_ios": total_ios,
        "utilization_pct": utilization_pct,
        "status": status,
    }


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
        description="Monitor disk I/O queue depths for storage bottleneck detection"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed device information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show devices with issues")
    parser.add_argument("--warn", type=int, default=16, metavar="N", help="Warning threshold for queue depth (default: 16)")
    parser.add_argument("--crit", type=int, default=32, metavar="N", help="Critical threshold for queue depth (default: 32)")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn >= opts.crit:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    # Get block devices
    devices = get_block_devices(context)

    if not devices:
        output.error("No block devices found")
        return 2

    # Analyze each device
    results = []
    has_issues = False

    for device in devices:
        stat_path = f"/sys/block/{device}/stat"
        try:
            content = context.read_file(stat_path)
            stat = parse_device_stat(content)
            if stat is None:
                continue

            info = analyze_device(device, stat, context, opts.warn, opts.crit)

            if info["status"] in ("critical", "warning"):
                has_issues = True

            if not opts.warn_only or info["status"] != "ok":
                results.append(info)

        except FileNotFoundError:
            continue

    if not results and not opts.warn_only:
        output.error("No device statistics available")
        return 2

    # Build output
    summary_data = {
        "total_devices": len(devices),
        "critical": sum(1 for r in results if r["status"] == "critical"),
        "warning": sum(1 for r in results if r["status"] == "warning"),
        "ok": sum(1 for r in results if r["status"] == "ok"),
    }

    output.emit({
        "devices": results,
        "summary": summary_data,
    })

    output.set_summary(
        f"{summary_data['ok']} ok, {summary_data['warning']} warning, {summary_data['critical']} critical"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
