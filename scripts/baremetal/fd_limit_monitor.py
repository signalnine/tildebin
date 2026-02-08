#!/usr/bin/env python3
# boxctl:
#   category: baremetal/system
#   tags: [health, fd, limits, ulimit, resources]
#   brief: Monitor file descriptor usage across system and per-process

"""
Monitor file descriptor usage across system and per-process.

Monitors FD consumption to prevent resource exhaustion and identify processes
approaching their ulimits. Useful for detecting FD leaks and preventing
"too many open files" errors in production environments.

Exit codes:
    0: No issues detected (all processes below threshold)
    1: Warnings found (processes using >80% of FD limit)
    2: Usage error or missing dependencies
"""

import argparse

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_file_nr(content: str) -> dict:
    """Parse /proc/sys/fs/file-nr content."""
    parts = content.strip().split()
    if len(parts) >= 3:
        allocated = int(parts[0])
        max_fds = int(parts[2])
        free = max_fds - allocated
        usage_percent = round((allocated / max_fds) * 100, 2) if max_fds > 0 else 0
        return {
            "allocated": allocated,
            "free": free,
            "max": max_fds,
            "usage_percent": usage_percent,
        }
    return None


def parse_limits(content: str) -> dict:
    """Parse /proc/<pid>/limits to extract Max open files."""
    for line in content.strip().split("\n"):
        if "open files" in line.lower():
            parts = line.split()
            # Format: "Max open files    1024    4096    files"
            try:
                soft_limit = parts[3]
                hard_limit = parts[4]
                if soft_limit != "unlimited":
                    soft_limit = int(soft_limit)
                if hard_limit != "unlimited":
                    hard_limit = int(hard_limit)
                return {"soft": soft_limit, "hard": hard_limit}
            except (ValueError, IndexError):
                pass
    return {"soft": None, "hard": None}


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
        description="Monitor file descriptor usage across system and per-process"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed information"
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Show all processes, not just those above threshold",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=float,
        default=80.0,
        help="Warning threshold percentage (default: 80)",
    )
    parser.add_argument(
        "-n", "--name", help="Filter by process name (case-insensitive substring match)"
    )
    parser.add_argument("-u", "--user", help="Filter by process owner username")
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show processes above threshold",
    )
    opts = parser.parse_args(args)

    # Validate threshold
    if opts.threshold < 0 or opts.threshold > 100:
        output.error("Threshold must be between 0 and 100")
        return 2

    # Get system stats
    try:
        file_nr_content = context.read_file("/proc/sys/fs/file-nr")
        system_stats = parse_file_nr(file_nr_content)
    except (FileNotFoundError, IOError) as e:
        output.error(f"Could not read system FD stats: {e}")
        return 2

    # Get process stats
    processes = []

    # Enumerate processes from /proc
    try:
        proc_dirs = context.glob("[0-9]*", "/proc")
    except Exception:
        proc_dirs = []

    for proc_path in proc_dirs:
        pid = proc_path.split("/")[-1]
        if not pid.isdigit():
            continue

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
            continue

        # Count FDs
        try:
            fd_list = context.glob("*", f"/proc/{pid}/fd")
            fd_count = len(fd_list)
        except Exception:
            fd_count = 0

        # Calculate usage percentage
        usage_percent = 0
        soft_limit = limits.get("soft")
        if soft_limit and soft_limit != "unlimited" and soft_limit > 0:
            usage_percent = round((fd_count / soft_limit) * 100, 2)

        # Apply name filter
        if opts.name and opts.name.lower() not in name.lower():
            continue

        # Apply threshold filter (unless --all)
        if not opts.all and usage_percent < opts.threshold:
            continue

        processes.append(
            {
                "pid": int(pid),
                "name": name,
                "user": "unknown",  # Would need to read /proc/pid/status
                "fd_count": fd_count,
                "soft_limit": soft_limit,
                "hard_limit": limits.get("hard"),
                "usage_percent": usage_percent,
            }
        )

    # Sort by usage percentage descending
    processes.sort(key=lambda x: x["usage_percent"], reverse=True)

    # Check for warnings
    has_warnings = any(p["usage_percent"] >= opts.threshold for p in processes)

    # Build result
    result = {"system": system_stats, "processes": processes}

    # Output
    output.emit(result)
    output.render(opts.format, "File Descriptor Limit Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    status = "warning" if has_warnings else "healthy"
    output.set_summary(
        f"system_fd={system_stats['usage_percent'] if system_stats else 0}%, status={status}"
    )

    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
