#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, filesystem, storage, hardware]
#   brief: Monitor filesystems for read-only status

"""
Monitor filesystems for read-only status.

Checks /proc/mounts for filesystems that have been remounted read-only,
often indicating storage errors or disk failures.

Exit codes:
    0: All filesystems are read-write (healthy)
    1: One or more filesystems are read-only
    2: Usage error or /proc filesystem unavailable
"""

import argparse

from boxctl.core.context import Context
from boxctl.core.output import Output


# Virtual/special filesystems to skip
SKIP_FSTYPES = {
    "proc", "sysfs", "devpts", "tmpfs", "devtmpfs",
    "cgroup", "cgroup2", "pstore", "bpf", "tracefs",
    "debugfs", "hugetlbfs", "mqueue", "configfs",
    "fusectl", "selinuxfs", "securityfs", "efivarfs",
    "autofs", "overlay", "squashfs",
}


def parse_mounts(content: str) -> list[dict]:
    """Parse /proc/mounts content."""
    filesystems = []
    for line in content.strip().split("\n"):
        parts = line.split()
        if len(parts) < 4:
            continue

        device = parts[0]
        mount_point = parts[1]
        fs_type = parts[2]
        options = parts[3]

        # Skip virtual filesystems
        if fs_type in SKIP_FSTYPES:
            continue

        # Parse mount options
        opts = options.split(",")
        is_readonly = "ro" in opts

        filesystems.append({
            "device": device,
            "mount_point": mount_point,
            "fs_type": fs_type,
            "readonly": is_readonly,
        })

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
    parser = argparse.ArgumentParser(description="Monitor filesystems for read-only status")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all filesystems")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues detected",
    )
    opts = parser.parse_args(args)

    # Read /proc/mounts
    try:
        mounts_content = context.read_file("/proc/mounts")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/mounts: {e}")
        return 2

    filesystems = parse_mounts(mounts_content)

    # Find read-only filesystems
    readonly_fs = [fs for fs in filesystems if fs["readonly"]]
    readonly_count = len(readonly_fs)

    status = "critical" if readonly_count > 0 else "healthy"

    # Build result
    result = {
        "filesystems": filesystems,
        "readonly_count": readonly_count,
        "total_count": len(filesystems),
        "readonly_mounts": [fs["mount_point"] for fs in readonly_fs],
        "status": status,
    }

    # Output
    output.emit(result)
    output.render(opts.format, "Filesystem Read-Only Monitor", warn_only=getattr(opts, 'warn_only', False))

    output.set_summary(f"ro={readonly_count}, total={len(filesystems)}, status={status}")

    return 1 if readonly_count > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
