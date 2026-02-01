#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, filesystem, tmpfs, memory, storage]
#   brief: Monitor tmpfs filesystem usage

"""
Monitor tmpfs filesystem usage on baremetal systems.

Tracks tmpfs mounts including /dev/shm, /run, /tmp for high usage
that could lead to silent OOM conditions (tmpfs exhaustion doesn't
trigger standard disk space alerts).

Exit codes:
    0: All tmpfs filesystems healthy (below thresholds)
    1: Warning or critical usage detected
    2: Usage error
"""

import argparse
import json
import os

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_mounts(content: str) -> list[dict]:
    """Parse /proc/mounts content for tmpfs mounts."""
    mounts = []
    for line in content.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]
            if fstype == "tmpfs":
                mounts.append({
                    "device": device,
                    "mountpoint": mountpoint,
                    "options": options,
                })
    return mounts


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable string."""
    for unit, divisor in [("T", 1024**4), ("G", 1024**3), ("M", 1024**2), ("K", 1024)]:
        if bytes_val >= divisor:
            return f"{bytes_val / divisor:.1f}{unit}"
    return f"{bytes_val}B"


def get_status(used_percent: float, warn_threshold: float, crit_threshold: float) -> str:
    """Determine status based on usage percentage."""
    if used_percent >= crit_threshold:
        return "CRITICAL"
    elif used_percent >= warn_threshold:
        return "WARNING"
    return "OK"


def analyze_tmpfs(mounts: list[dict], statvfs_data: dict, warn_threshold: float, crit_threshold: float) -> list[dict]:
    """Analyze all tmpfs mounts and return status information."""
    results = []

    for mount in mounts:
        mountpoint = mount["mountpoint"]

        if mountpoint not in statvfs_data:
            results.append({
                "mountpoint": mountpoint,
                "device": mount["device"],
                "accessible": False,
                "status": "UNKNOWN",
            })
            continue

        stat = statvfs_data[mountpoint]
        block_size = stat["f_frsize"]
        total_blocks = stat["f_blocks"]
        free_blocks = stat["f_bfree"]

        total_bytes = total_blocks * block_size
        free_bytes = free_blocks * block_size
        used_bytes = total_bytes - free_bytes
        used_percent = (used_bytes / total_bytes * 100) if total_bytes > 0 else 0

        # Inode stats
        total_inodes = stat["f_files"]
        free_inodes = stat["f_ffree"]
        used_inodes = total_inodes - free_inodes
        inode_percent = (used_inodes / total_inodes * 100) if total_inodes > 0 else 0

        space_status = get_status(used_percent, warn_threshold, crit_threshold)
        inode_status = get_status(inode_percent, warn_threshold, crit_threshold)

        # Overall status is worst of space or inode
        if space_status == "CRITICAL" or inode_status == "CRITICAL":
            overall_status = "CRITICAL"
        elif space_status == "WARNING" or inode_status == "WARNING":
            overall_status = "WARNING"
        else:
            overall_status = "OK"

        results.append({
            "mountpoint": mountpoint,
            "device": mount["device"],
            "options": mount["options"],
            "accessible": True,
            "size_bytes": total_bytes,
            "used_bytes": used_bytes,
            "avail_bytes": free_bytes,
            "used_percent": round(used_percent, 1),
            "total_inodes": total_inodes,
            "used_inodes": used_inodes,
            "free_inodes": free_inodes,
            "inode_percent": round(inode_percent, 1),
            "space_status": space_status,
            "inode_status": inode_status,
            "status": overall_status,
        })

    return results


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
    parser = argparse.ArgumentParser(description="Monitor tmpfs filesystem usage")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show warnings")
    parser.add_argument("--warn", type=float, default=80.0, help="Warning threshold (default: 80)")
    parser.add_argument("--critical", type=float, default=90.0, help="Critical threshold (default: 90)")
    parser.add_argument("-m", "--mountpoint", help="Monitor specific mountpoint only")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0 or opts.warn > 100:
        output.error("--warn must be between 0 and 100")
        return 2
    if opts.critical < 0 or opts.critical > 100:
        output.error("--critical must be between 0 and 100")
        return 2
    if opts.warn >= opts.critical:
        output.error("--warn must be less than --critical")
        return 2

    # Read /proc/mounts
    try:
        mounts_content = context.read_file("/proc/mounts")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/mounts: {e}")
        return 2

    mounts = parse_mounts(mounts_content)

    if not mounts:
        output.warning("No tmpfs filesystems found")
        output.emit({"tmpfs_count": 0, "issues_count": 0, "filesystems": []})
        return 0

    # Filter to specific mountpoint if requested
    if opts.mountpoint:
        mounts = [m for m in mounts if m["mountpoint"] == opts.mountpoint]
        if not mounts:
            output.error(f"Mountpoint {opts.mountpoint} not found or not tmpfs")
            return 2

    # Get statvfs data for each mount
    # In real context, we use os.statvfs. For tests, this is mocked via context.
    statvfs_data = {}
    for mount in mounts:
        try:
            # Try to read from mock statvfs file if available (for testing)
            stat = os.statvfs(mount["mountpoint"])
            statvfs_data[mount["mountpoint"]] = {
                "f_frsize": stat.f_frsize,
                "f_blocks": stat.f_blocks,
                "f_bfree": stat.f_bfree,
                "f_bavail": stat.f_bavail,
                "f_files": stat.f_files,
                "f_ffree": stat.f_ffree,
            }
        except (OSError, IOError):
            pass

    results = analyze_tmpfs(mounts, statvfs_data, opts.warn, opts.critical)

    issues_count = sum(1 for r in results if r["status"] != "OK")
    has_issues = issues_count > 0

    # Output
    if opts.format == "json":
        filtered = results if not opts.warn_only else [r for r in results if r["status"] != "OK"]
        if not opts.warn_only or has_issues:
            json_output = {
                "tmpfs_count": len(results),
                "issues_count": issues_count,
                "filesystems": filtered,
            }
            print(json.dumps(json_output, indent=2))
    else:
        filtered = results if not opts.warn_only else [r for r in results if r["status"] != "OK"]
        if not opts.warn_only or has_issues:
            lines = []
            lines.append("Tmpfs Monitor")
            lines.append("=" * 40)

            if not filtered:
                if opts.warn_only:
                    lines.append("No tmpfs issues detected.")
                else:
                    lines.append("No tmpfs filesystems found.")
            else:
                for r in filtered:
                    if not r["accessible"]:
                        lines.append(f"{r['mountpoint']} INACCESSIBLE")
                        continue

                    size_str = format_bytes(r["size_bytes"])
                    used_str = format_bytes(r["used_bytes"])
                    lines.append(f"{r['mountpoint']} {r['status']} {used_str}/{size_str} ({r['used_percent']}%)")

                    if opts.verbose:
                        lines.append(f"  Device: {r['device']}")
                        lines.append(f"  Inodes: {r['used_inodes']}/{r['total_inodes']} ({r['inode_percent']}%)")

            print("\n".join(lines))

    output.emit({
        "tmpfs_count": len(results),
        "issues_count": issues_count,
        "filesystems": results,
    })
    output.set_summary(f"{len(results)} tmpfs, {issues_count} issues")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
