#!/usr/bin/env python3
# boxctl:
#   category: baremetal/system
#   tags: [health, fd, files, resources, disk]
#   brief: Monitor open file handles across the system

"""
Monitor open file handles across the system.

Identifies processes with high FD counts, detects potential FD leaks,
and finds processes holding deleted files open (common after log rotation).
Useful for troubleshooting FD exhaustion and disk space issues.

Exit codes:
    0: No issues detected (all processes within thresholds)
    1: Warnings detected (high FD usage or deleted files held open)
    2: Usage error or missing dependency
"""

import argparse
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_limits(content: str) -> dict:
    """Parse /proc/<pid>/limits to extract Max open files."""
    limits = {"soft": 0, "hard": 0}
    for line in content.strip().split("\n"):
        if "Max open files" in line:
            parts = line.split()
            nums = [p for p in parts if p.isdigit()]
            if len(nums) >= 2:
                limits["soft"] = int(nums[0])
                limits["hard"] = int(nums[1])
            break
    return limits


def categorize_fd(target: str) -> tuple[str, bool]:
    """Categorize a file descriptor target and check if deleted.

    Returns:
        tuple: (file_type, is_deleted)
    """
    deleted = False
    file_type = "unknown"

    if " (deleted)" in target:
        deleted = True
        target = target.replace(" (deleted)", "")

    if target.startswith("/"):
        file_type = "file"
    elif target.startswith("socket:"):
        file_type = "socket"
    elif target.startswith("pipe:"):
        file_type = "pipe"
    elif target.startswith("anon_inode:"):
        file_type = "anon_inode"
        if "[" in target:
            file_type = target.split("[")[1].rstrip("]")
    elif target.startswith("/dev/"):
        file_type = "device"

    return file_type, deleted


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
        description="Monitor open file handles across the system"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information including file type breakdown",
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--min-fds",
        type=int,
        default=10,
        help="Minimum open FD count to report (default: 10)",
    )
    parser.add_argument(
        "--warn-percent",
        type=int,
        default=80,
        help="Warn when FD usage exceeds this percentage (default: 80)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Show only top N processes by FD count (default: 20, 0=all)",
    )
    parser.add_argument(
        "--name", help="Filter by process name (case-insensitive substring match)"
    )
    parser.add_argument("--user", help="Filter by username")
    parser.add_argument(
        "--deleted-only",
        action="store_true",
        help="Only show processes holding deleted files open",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show processes with warnings",
    )
    opts = parser.parse_args(args)

    # Check for /proc filesystem
    if not context.file_exists("/proc/sys/kernel/hostname"):
        output.error("/proc filesystem not available")
        return 2

    # Get hostname
    try:
        hostname = context.read_file("/proc/sys/kernel/hostname").strip()
    except (FileNotFoundError, IOError):
        hostname = "unknown"

    # Collect process data
    processes = []
    summary = {
        "total_processes_checked": 0,
        "processes_reported": 0,
        "total_open_fds": 0,
        "processes_with_warnings": 0,
        "processes_with_deleted_files": 0,
        "total_deleted_files_held": 0,
    }

    # Enumerate processes
    try:
        proc_dirs = context.glob("[0-9]*", "/proc")
    except Exception:
        proc_dirs = []

    for proc_path in proc_dirs:
        pid = proc_path.split("/")[-1]
        if not pid.isdigit():
            continue

        summary["total_processes_checked"] += 1

        # Read process name
        try:
            name = context.read_file(f"/proc/{pid}/comm").strip()
        except (FileNotFoundError, IOError):
            continue

        # Get FD limits
        try:
            limits_content = context.read_file(f"/proc/{pid}/limits")
            limits = parse_limits(limits_content)
        except (FileNotFoundError, IOError):
            limits = {"soft": 0, "hard": 0}

        # Get open files
        try:
            fd_list = context.glob("*", f"/proc/{pid}/fd")
        except Exception:
            fd_list = []

        fd_count = len(fd_list)

        # Skip if below minimum
        if fd_count < opts.min_fds:
            continue

        # Count by type and find deleted files
        type_counts = defaultdict(int)
        deleted_files = []

        for fd_path in fd_list:
            fd_num = fd_path.split("/")[-1]
            try:
                target = context.readlink(fd_path)
                if not target:
                    continue
                file_type, is_deleted = categorize_fd(target)
                type_counts[file_type] += 1
                if is_deleted:
                    deleted_files.append(target)
            except (FileNotFoundError, IOError):
                continue

        # Calculate usage percentage
        usage_percent = 0
        if limits["soft"] > 0:
            usage_percent = round((fd_count / limits["soft"]) * 100, 1)

        # Determine warnings
        warnings = []
        if usage_percent >= opts.warn_percent:
            warnings.append(f"High FD usage: {usage_percent}% of soft limit")
        if deleted_files:
            warnings.append(f"Holding {len(deleted_files)} deleted file(s) open")

        # Apply filters
        if opts.name and opts.name.lower() not in name.lower():
            continue
        if opts.deleted_only and not deleted_files:
            continue

        proc_info = {
            "pid": int(pid),
            "name": name,
            "user": "unknown",
            "cmdline": "",
            "fd_count": fd_count,
            "fd_limit_soft": limits["soft"],
            "fd_limit_hard": limits["hard"],
            "usage_percent": usage_percent,
            "type_breakdown": dict(type_counts),
            "deleted_files": deleted_files,
            "warnings": warnings,
        }

        processes.append(proc_info)
        summary["total_open_fds"] += fd_count

        if warnings:
            summary["processes_with_warnings"] += 1
        if deleted_files:
            summary["processes_with_deleted_files"] += 1
            summary["total_deleted_files_held"] += len(deleted_files)

    # Sort by FD count descending
    processes.sort(key=lambda p: p["fd_count"], reverse=True)

    # Apply top_n limit
    if opts.top > 0:
        processes = processes[: opts.top]

    # Filter to warn-only if requested
    if opts.warn_only:
        processes = [p for p in processes if p["warnings"]]

    summary["processes_reported"] = len(processes)

    # Check for issues
    has_warnings = summary["processes_with_warnings"] > 0
    has_deleted = summary["processes_with_deleted_files"] > 0

    # Build result
    result = {
        "hostname": hostname,
        "summary": summary,
        "processes": processes,
    }

    output.emit(result)

    # Output
    output.render(opts.format, "Open File Handle Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    status = "warning" if (has_warnings or has_deleted) else "healthy"
    output.set_summary(f"processes_with_issues={summary['processes_with_warnings']}, status={status}")

    return 1 if (has_warnings or has_deleted) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
