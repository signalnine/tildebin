#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, filesystem, storage, capacity]
#   requires: [df]
#   brief: Monitor inode usage across filesystems

"""
Monitor inode usage across filesystems to detect exhaustion.

Filesystems can run out of inodes before running out of disk space,
especially with workloads that create many small files.

Exit codes:
    0: All filesystems have healthy inode usage
    1: Warnings or critical inode usage detected
    2: Usage error or missing dependency
"""

import argparse

from boxctl.core.context import Context
from boxctl.core.output import Output


# Filesystems to skip (pseudo/virtual)
SKIP_DEVICES = {"tmpfs", "devtmpfs", "none", "overlay"}
SKIP_MOUNTS = {"/sys", "/proc", "/dev", "/run"}


def parse_df_inodes(content: str) -> list[dict]:
    """Parse df -i output."""
    filesystems = []
    lines = content.strip().split("\n")

    if len(lines) < 2:
        return filesystems

    # Skip header
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue

        device = parts[0]
        mount_point = parts[5]

        # Skip pseudo-filesystems
        if device in SKIP_DEVICES:
            continue
        if any(mount_point.startswith(skip) for skip in SKIP_MOUNTS):
            continue
        if mount_point.startswith("/snap/"):
            continue

        try:
            inodes_total = int(parts[1]) if parts[1] != "-" else 0
            inodes_used = int(parts[2]) if parts[2] != "-" else 0
            inodes_free = int(parts[3]) if parts[3] != "-" else 0

            if inodes_total == 0:
                continue

            usage_pct = (inodes_used / inodes_total) * 100

            filesystems.append({
                "device": device,
                "mount_point": mount_point,
                "inodes_total": inodes_total,
                "inodes_used": inodes_used,
                "inodes_free": inodes_free,
                "usage_percent": round(usage_pct, 1),
            })
        except (ValueError, ZeroDivisionError):
            continue

    return filesystems


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
    parser = argparse.ArgumentParser(description="Monitor inode usage")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all filesystems")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=80.0,
        help="Warning threshold for inode usage %% (default: 80)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=95.0,
        help="Critical threshold for inode usage %% (default: 95)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues detected",
    )
    opts = parser.parse_args(args)

    # Run df -i
    try:
        result = context.run(["df", "-i", "-P"])
        df_output = result.stdout
    except Exception as e:
        output.error(f"Failed to run df -i: {e}")
        return 2

    filesystems = parse_df_inodes(df_output)

    if not filesystems:
        output.error("No filesystems found")
        return 2

    # Analyze each filesystem
    issues = []
    for fs in filesystems:
        if fs["usage_percent"] >= opts.crit:
            issues.append({
                "severity": "CRITICAL",
                "mount_point": fs["mount_point"],
                "usage_percent": fs["usage_percent"],
                "message": f"Critical inode usage on {fs['mount_point']}: {fs['usage_percent']:.1f}%",
            })
        elif fs["usage_percent"] >= opts.warn:
            issues.append({
                "severity": "WARNING",
                "mount_point": fs["mount_point"],
                "usage_percent": fs["usage_percent"],
                "message": f"High inode usage on {fs['mount_point']}: {fs['usage_percent']:.1f}%",
            })

    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warning = any(i["severity"] == "WARNING" for i in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")

    # Build result
    result_data = {
        "filesystems": filesystems,
        "issues": issues,
        "status": status,
    }

    # Output
    output.emit(result_data)
    output.render(opts.format, "Inode Usage Monitor", warn_only=getattr(opts, 'warn_only', False))

    output.set_summary(f"filesystems={len(filesystems)}, issues={len(issues)}, status={status}")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
