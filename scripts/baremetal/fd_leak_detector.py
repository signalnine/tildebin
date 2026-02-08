#!/usr/bin/env python3
# boxctl:
#   category: baremetal/system
#   tags: [health, fd, leak, resources, monitoring]
#   brief: Detect file descriptor leaks in long-running processes

"""
Detect file descriptor leaks in long-running processes.

Identifies processes that may have file descriptor leaks by analyzing
current FD counts. High FD counts or processes approaching their limits
can indicate resource leaks in services.

Exit codes:
    0: No FD leak indicators detected
    1: Potential FD leaks or warnings found
    2: Usage error or missing dependencies
"""

import argparse

from boxctl.core.context import Context
from boxctl.core.output import Output


# Default thresholds
DEFAULT_FD_WARNING = 1000
DEFAULT_FD_CRITICAL = 5000


def parse_file_nr(content: str) -> dict:
    """Parse /proc/sys/fs/file-nr content."""
    parts = content.strip().split()
    if len(parts) >= 3:
        return {
            "allocated": int(parts[0]),
            "free": int(parts[1]) if len(parts) > 1 else 0,
            "max": int(parts[2]),
        }
    return {"allocated": 0, "free": 0, "max": 0}


def parse_limits(content: str) -> dict:
    """Parse /proc/<pid>/limits to extract Max open files."""
    for line in content.strip().split("\n"):
        if "Max open files" in line:
            parts = line.split()
            # Format: Max open files  <soft>  <hard>  files
            try:
                return {"soft": int(parts[3]), "hard": int(parts[4])}
            except (ValueError, IndexError):
                pass
    return {"soft": None, "hard": None}


def analyze_process(
    pid: str,
    comm: str,
    fd_count: int,
    limits: dict,
    fd_warning: int,
    fd_critical: int,
) -> dict:
    """Analyze a single process for FD leak indicators."""
    info = {
        "pid": int(pid),
        "comm": comm,
        "fd_count": fd_count,
        "fd_limit": limits.get("soft"),
        "fd_usage_pct": None,
        "issues": [],
    }

    if limits.get("soft") and limits["soft"] > 0:
        info["fd_usage_pct"] = round(fd_count * 100 / limits["soft"], 1)

    # Check for issues
    if fd_count >= fd_critical:
        info["issues"].append(
            {
                "severity": "CRITICAL",
                "type": "high_fd_count",
                "message": f"Process has {fd_count} open FDs (critical threshold: {fd_critical})",
            }
        )
    elif fd_count >= fd_warning:
        info["issues"].append(
            {
                "severity": "WARNING",
                "type": "elevated_fd_count",
                "message": f"Process has {fd_count} open FDs (warning threshold: {fd_warning})",
            }
        )

    # Check FD limit proximity
    if limits.get("soft") and fd_count > limits["soft"] * 0.8:
        pct = round(fd_count * 100 / limits["soft"], 1)
        info["issues"].append(
            {
                "severity": "WARNING",
                "type": "approaching_limit",
                "message": f"Process using {pct}% of FD limit ({fd_count}/{limits['soft']})",
            }
        )

    return info


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
        description="Detect file descriptor leaks in running processes"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed information"
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only produce output if issues are found",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Number of top processes to show (default: 20)",
    )
    parser.add_argument(
        "--min-fds",
        type=int,
        default=10,
        help="Minimum FD count to include in analysis (default: 10)",
    )
    parser.add_argument(
        "--fd-warning",
        type=int,
        default=DEFAULT_FD_WARNING,
        help=f"FD count warning threshold (default: {DEFAULT_FD_WARNING})",
    )
    parser.add_argument(
        "--fd-critical",
        type=int,
        default=DEFAULT_FD_CRITICAL,
        help=f"FD count critical threshold (default: {DEFAULT_FD_CRITICAL})",
    )
    opts = parser.parse_args(args)

    # Check if /proc is accessible
    if not context.file_exists("/proc/sys/fs/file-nr"):
        output.error("/proc filesystem not accessible")
        return 2

    # Get system FD info
    try:
        file_nr_content = context.read_file("/proc/sys/fs/file-nr")
        system_fd_info = parse_file_nr(file_nr_content)
    except (FileNotFoundError, IOError):
        system_fd_info = None

    # Get process information
    # In the boxctl context, we simulate process discovery with mock data
    processes = []

    # Try to enumerate processes from /proc
    try:
        proc_dirs = context.glob("[0-9]*", "/proc")
    except Exception:
        proc_dirs = []

    for proc_path in proc_dirs:
        pid = proc_path.split("/")[-1]
        if not pid.isdigit():
            continue

        # Read process comm
        try:
            comm = context.read_file(f"/proc/{pid}/comm").strip()
        except (FileNotFoundError, IOError):
            continue

        # Count FDs
        try:
            fd_list = context.glob("*", f"/proc/{pid}/fd")
            fd_count = len(fd_list)
        except Exception:
            fd_count = 0

        if fd_count < opts.min_fds:
            continue

        # Get limits
        try:
            limits_content = context.read_file(f"/proc/{pid}/limits")
            limits = parse_limits(limits_content)
        except (FileNotFoundError, IOError):
            limits = {"soft": None, "hard": None}

        info = analyze_process(
            pid, comm, fd_count, limits, opts.fd_warning, opts.fd_critical
        )
        processes.append(info)

    # Sort by FD count descending
    processes.sort(key=lambda p: p["fd_count"], reverse=True)
    processes = processes[: opts.top]

    # Generate summary
    summary = {
        "total_processes_analyzed": len(processes),
        "processes_with_issues": sum(1 for p in processes if p["issues"]),
        "critical_count": sum(
            1 for p in processes for i in p["issues"] if i["severity"] == "CRITICAL"
        ),
        "warning_count": sum(
            1 for p in processes for i in p["issues"] if i["severity"] == "WARNING"
        ),
        "total_fds_tracked": sum(p["fd_count"] for p in processes),
    }

    if system_fd_info:
        summary["system_fd_allocated"] = system_fd_info["allocated"]
        summary["system_fd_max"] = system_fd_info["max"]
        if system_fd_info["max"] > 0:
            summary["system_fd_usage_pct"] = round(
                system_fd_info["allocated"] * 100 / system_fd_info["max"], 1
            )

    # Check warn-only mode
    has_issues = summary["critical_count"] > 0 or summary["warning_count"] > 0

    # Build result
    result = {
        "summary": summary,
        "processes": processes,
    }

    output.emit(result)

    if opts.warn_only and not has_issues:
        return 0

    # Output
    output.render(opts.format, "File Descriptor Leak Detector", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    status = (
        "critical"
        if summary["critical_count"] > 0
        else ("warning" if summary["warning_count"] > 0 else "healthy")
    )
    output.set_summary(
        f"processes_with_issues={summary['processes_with_issues']}, status={status}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
