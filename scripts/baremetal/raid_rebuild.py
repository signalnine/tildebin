#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, storage, raid, mdadm, rebuild]
#   requires: []
#   privilege: root
#   related: [disk_health]
#   brief: Monitor RAID array rebuild/resync progress with time estimation

"""
Monitor RAID array rebuild/resync progress with time estimation.

Tracks progress of RAID rebuild operations (resync, recovery, reshape, check)
and provides estimated time to completion. Supports Linux software RAID (mdadm)
via /proc/mdstat.

Returns exit code 1 if any rebuilds are in progress or arrays are degraded.
"""

import argparse
import re
from datetime import datetime, timedelta
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_mdstat(content: str) -> list[dict[str, Any]]:
    """Parse /proc/mdstat for array status and rebuild progress."""
    arrays = []
    lines = content.split("\n")
    i = 0

    while i < len(lines):
        line = lines[i]

        # Match array line: "md0 : active raid1 sda1[0] sdb1[1]"
        array_match = re.match(r"^(md\d+)\s*:\s*(\w+)\s+(\w+)\s+(.+)$", line)
        if array_match:
            array_info: dict[str, Any] = {
                "name": array_match.group(1),
                "device": f"/dev/{array_match.group(1)}",
                "state": array_match.group(2),
                "level": array_match.group(3),
                "devices": array_match.group(4).strip(),
                "rebuild_in_progress": False,
                "operation": None,
                "progress_percent": None,
                "speed": None,
                "eta_minutes": None,
                "finish_time": None,
            }

            # Check following lines for status info
            j = i + 1
            while j < len(lines) and not re.match(r"^md\d+\s*:", lines[j]) and lines[j].strip():
                status_line = lines[j]

                # Match size line: "12345678 blocks super 1.2 [2/2] [UU]"
                size_match = re.search(r"(\d+)\s+blocks", status_line)
                if size_match:
                    array_info["size_blocks"] = int(size_match.group(1))

                # Match disk status: [UU] or [U_] or [_U] or [UUUU]
                disk_status_match = re.search(r"\[([U_]+)\]", status_line)
                if disk_status_match:
                    disk_status = disk_status_match.group(1)
                    array_info["disk_status"] = disk_status
                    array_info["disks_active"] = disk_status.count("U")
                    array_info["disks_total"] = len(disk_status)
                    array_info["degraded"] = "_" in disk_status

                # Match rebuild progress line
                progress_match = re.search(
                    r"\[([=>.]+)\]\s+(\w+)\s*=\s*([\d.]+)%\s*"
                    r"\((\d+)/(\d+)\)\s*"
                    r"finish=([\d.]+)(min|sec|hour)?\s*"
                    r"speed=(\d+)([KMG]?)/sec",
                    status_line
                )
                if progress_match:
                    array_info["rebuild_in_progress"] = True
                    array_info["operation"] = progress_match.group(2)
                    array_info["progress_percent"] = float(progress_match.group(3))
                    array_info["blocks_done"] = int(progress_match.group(4))
                    array_info["blocks_total"] = int(progress_match.group(5))

                    # Parse finish time
                    finish_val = float(progress_match.group(6))
                    finish_unit = progress_match.group(7) or "min"
                    if finish_unit == "sec":
                        array_info["eta_minutes"] = finish_val / 60.0
                    elif finish_unit == "hour":
                        array_info["eta_minutes"] = finish_val * 60.0
                    else:
                        array_info["eta_minutes"] = finish_val

                    # Calculate estimated finish time
                    finish_time = datetime.now() + timedelta(minutes=array_info["eta_minutes"])
                    array_info["finish_time"] = finish_time.strftime("%Y-%m-%d %H:%M:%S")

                    # Parse speed
                    speed_val = int(progress_match.group(8))
                    speed_unit = progress_match.group(9)
                    if speed_unit == "M":
                        speed_val *= 1024
                    elif speed_unit == "G":
                        speed_val *= 1024 * 1024
                    array_info["speed"] = speed_val  # KB/sec
                    array_info["speed_human"] = format_speed(speed_val)

                j += 1

            arrays.append(array_info)

        i += 1

    return arrays


def format_speed(kb_per_sec: int) -> str:
    """Format speed in human-readable form."""
    if kb_per_sec >= 1024 * 1024:
        return f"{kb_per_sec / (1024 * 1024):.1f} GB/s"
    elif kb_per_sec >= 1024:
        return f"{kb_per_sec / 1024:.1f} MB/s"
    else:
        return f"{kb_per_sec} KB/s"


def format_time(minutes: float | None) -> str:
    """Format minutes in human-readable form."""
    if minutes is None:
        return "unknown"
    if minutes < 1:
        return f"{int(minutes * 60)} seconds"
    elif minutes < 60:
        return f"{int(minutes)} minutes"
    elif minutes < 1440:  # Less than 24 hours
        hours = int(minutes / 60)
        mins = int(minutes % 60)
        return f"{hours}h {mins}m"
    else:
        days = int(minutes / 1440)
        hours = int((minutes % 1440) / 60)
        return f"{days}d {hours}h"


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no rebuilds/degraded, 1 = rebuild or degraded, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor RAID array rebuild/resync progress"
    )
    parser.add_argument("-a", "--array", help="Monitor specific array (e.g., md0)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--rebuilding-only", action="store_true",
                        help="Only show arrays with active rebuild/resync operations")
    opts = parser.parse_args(args)

    # Check for /proc/mdstat
    if not context.file_exists("/proc/mdstat"):
        output.error("/proc/mdstat not found. Software RAID may not be configured.")

        output.render(opts.format, "Monitor RAID array rebuild/resync progress with time estimation")
        return 2

    # Parse mdstat
    try:
        content = context.read_file("/proc/mdstat")
    except (IOError, OSError) as e:
        output.error(f"Unable to read /proc/mdstat: {e}")

        output.render(opts.format, "Monitor RAID array rebuild/resync progress with time estimation")
        return 2

    arrays = parse_mdstat(content)

    # Filter by array name if specified
    if opts.array:
        array_name = opts.array
        if not array_name.startswith("md"):
            array_name = f"md{array_name}"
        arrays = [a for a in arrays if a["name"] == array_name]
        if not arrays:
            output.error(f"Array {opts.array} not found")
            return 2

    # Filter to rebuilding only if requested
    if opts.rebuilding_only:
        arrays = [a for a in arrays if a["rebuild_in_progress"]]

    # Build output
    summary = {
        "total_arrays": len(arrays),
        "rebuilding": sum(1 for a in arrays if a["rebuild_in_progress"]),
        "degraded": sum(1 for a in arrays if a.get("degraded")),
    }

    output.emit({
        "timestamp": datetime.now().isoformat(),
        "arrays": arrays,
        "summary": summary,
    })

    # Set summary message
    if summary["rebuilding"] > 0:
        output.set_summary(f"{summary['rebuilding']} array(s) rebuilding")
    elif summary["degraded"] > 0:
        output.set_summary(f"{summary['degraded']} array(s) degraded")
    else:
        output.set_summary(f"{summary['total_arrays']} arrays healthy")

    # Exit code: 1 if any rebuilds in progress or degraded
    has_rebuilds = any(a["rebuild_in_progress"] for a in arrays)
    has_degraded = any(a.get("degraded") for a in arrays)

    if has_rebuilds or has_degraded:

        output.render(opts.format, "Monitor RAID array rebuild/resync progress with time estimation")
        return 1
    else:
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
