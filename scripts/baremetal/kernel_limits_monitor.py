#!/usr/bin/env python3
# boxctl:
#   category: baremetal/resources
#   tags: [health, limits, resources, capacity, performance]
#   related: [process_limits_monitor, memory_usage]
#   brief: Monitor kernel resource limits and their current usage

"""
Monitor kernel resource limits and their current usage.

Monitors critical kernel limits that can cause system instability when exhausted:
- PID limit (kernel.pid_max)
- Threads limit (kernel.threads-max)
- Open file limit (fs.file-max)
- Inotify watches (fs.inotify.max_user_watches)
- Message queue limits (kernel.msgmni, kernel.msgmax)
- Semaphore limits (kernel.sem)
- Shared memory limits (kernel.shmmax, kernel.shmall)

Essential for high-density baremetal environments running many containers or
services where resource exhaustion can cause cascading failures.

Exit codes:
    0 - All limits within safe thresholds
    1 - One or more limits approaching exhaustion (warnings)
    2 - Usage error or unable to read kernel parameters
"""

import argparse

from boxctl.core.context import Context
from boxctl.core.output import Output


def sysctl_to_path(param: str) -> str:
    """Convert sysctl parameter name to /proc/sys path."""
    return "/proc/sys/" + param.replace(".", "/")


def read_sysctl(context: Context, param: str) -> str | None:
    """Read a sysctl parameter value."""
    path = sysctl_to_path(param)
    try:
        return context.read_file(path).strip()
    except (FileNotFoundError, IOError, PermissionError):
        return None


def count_processes(context: Context) -> int:
    """Count current number of processes from /proc/loadavg."""
    try:
        content = context.read_file("/proc/loadavg")
        # Format: "0.00 0.01 0.05 1/123 4567"
        parts = content.split()
        if len(parts) >= 4:
            task_info = parts[3]  # e.g., "1/123"
            if "/" in task_info:
                return int(task_info.split("/")[1])
    except (FileNotFoundError, IOError, ValueError, IndexError):
        pass
    return 0


def count_open_files(context: Context) -> int:
    """Count current number of open file descriptors system-wide."""
    try:
        content = context.read_file("/proc/sys/fs/file-nr")
        # Format: "allocated  free  maximum"
        parts = content.split()
        if parts:
            return int(parts[0])
    except (FileNotFoundError, IOError, ValueError, IndexError):
        pass
    return 0


def get_aio_usage(context: Context) -> tuple[int, int]:
    """Get current AIO usage and max."""
    try:
        aio_nr = int(read_sysctl(context, "fs.aio-nr") or "0")
        aio_max = int(read_sysctl(context, "fs.aio-max-nr") or "0")
        return aio_nr, aio_max
    except ValueError:
        return 0, 0


def get_limit_info(context: Context) -> list[dict]:
    """Gather information about kernel limits and usage."""
    limits = []

    # PID limit
    pid_max = read_sysctl(context, "kernel.pid_max")
    if pid_max:
        current_pids = count_processes(context)
        try:
            limits.append(
                {
                    "name": "kernel.pid_max",
                    "description": "Maximum process ID",
                    "limit": int(pid_max),
                    "current": current_pids,
                    "unit": "processes",
                }
            )
        except ValueError:
            pass

    # Threads limit
    threads_max = read_sysctl(context, "kernel.threads-max")
    if threads_max:
        current_threads = count_processes(context)  # Approximate via loadavg
        try:
            limits.append(
                {
                    "name": "kernel.threads-max",
                    "description": "Maximum number of threads",
                    "limit": int(threads_max),
                    "current": current_threads,
                    "unit": "threads",
                }
            )
        except ValueError:
            pass

    # File descriptor limit
    file_max = read_sysctl(context, "fs.file-max")
    if file_max:
        current_files = count_open_files(context)
        try:
            limits.append(
                {
                    "name": "fs.file-max",
                    "description": "Maximum open files system-wide",
                    "limit": int(file_max),
                    "current": current_files,
                    "unit": "files",
                }
            )
        except ValueError:
            pass

    # Inotify watches limit
    inotify_max = read_sysctl(context, "fs.inotify.max_user_watches")
    if inotify_max:
        try:
            limits.append(
                {
                    "name": "fs.inotify.max_user_watches",
                    "description": "Maximum inotify watches per user",
                    "limit": int(inotify_max),
                    "current": None,  # Hard to count accurately
                    "unit": "watches",
                    "note": "Current usage not available",
                }
            )
        except ValueError:
            pass

    # Message queue limit
    msgmni = read_sysctl(context, "kernel.msgmni")
    if msgmni:
        try:
            limits.append(
                {
                    "name": "kernel.msgmni",
                    "description": "Maximum message queue identifiers",
                    "limit": int(msgmni),
                    "current": None,
                    "unit": "queues",
                }
            )
        except ValueError:
            pass

    # Max message size
    msgmax = read_sysctl(context, "kernel.msgmax")
    if msgmax:
        try:
            limits.append(
                {
                    "name": "kernel.msgmax",
                    "description": "Maximum message size (bytes)",
                    "limit": int(msgmax),
                    "current": None,
                    "unit": "bytes",
                }
            )
        except ValueError:
            pass

    # Semaphore limits
    sem = read_sysctl(context, "kernel.sem")
    if sem:
        # Format: SEMMSL SEMMNS SEMOPM SEMMNI
        parts = sem.split()
        if len(parts) >= 4:
            try:
                limits.append(
                    {
                        "name": "kernel.sem (SEMMNI)",
                        "description": "Maximum semaphore sets",
                        "limit": int(parts[3]),
                        "current": None,
                        "unit": "sets",
                    }
                )
            except ValueError:
                pass

    # Shared memory max
    shmmax = read_sysctl(context, "kernel.shmmax")
    if shmmax:
        try:
            limits.append(
                {
                    "name": "kernel.shmmax",
                    "description": "Maximum shared memory segment size",
                    "limit": int(shmmax),
                    "current": None,
                    "unit": "bytes",
                }
            )
        except ValueError:
            pass

    # Shared memory pages
    shmall = read_sysctl(context, "kernel.shmall")
    if shmall:
        try:
            limits.append(
                {
                    "name": "kernel.shmall",
                    "description": "Maximum shared memory pages",
                    "limit": int(shmall),
                    "current": None,
                    "unit": "pages",
                }
            )
        except ValueError:
            pass

    # AIO requests
    aio_nr, aio_max = get_aio_usage(context)
    if aio_max > 0:
        limits.append(
            {
                "name": "fs.aio-max-nr",
                "description": "Maximum async I/O requests",
                "limit": aio_max,
                "current": aio_nr,
                "unit": "requests",
            }
        )

    # Calculate usage percentage where possible
    for limit in limits:
        if limit["current"] is not None and limit["limit"] > 0:
            limit["usage_pct"] = round((limit["current"] / limit["limit"]) * 100, 1)
        else:
            limit["usage_pct"] = None

    return limits


def analyze_limits(
    limits: list[dict], warn_threshold: int, critical_threshold: int
) -> tuple[list[dict], list[dict]]:
    """Analyze limits and return warnings and critical issues."""
    warnings = []
    critical = []

    for limit in limits:
        if limit["usage_pct"] is not None:
            if limit["usage_pct"] >= critical_threshold:
                critical.append(limit)
            elif limit["usage_pct"] >= warn_threshold:
                warnings.append(limit)

    return warnings, critical


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point for kernel limits monitoring.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = warnings/critical, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor kernel resource limits and their current usage"
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information for all limits",
    )

    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show limits with warnings or critical status",
    )

    parser.add_argument(
        "--warn",
        type=int,
        default=80,
        metavar="PCT",
        help="Warning threshold percentage (default: 80)",
    )

    parser.add_argument(
        "--crit",
        type=int,
        default=95,
        metavar="PCT",
        help="Critical threshold percentage (default: 95)",
    )

    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0 or opts.warn > 100:
        output.error("Warning threshold must be 0-100")
        return 2
    if opts.crit < 0 or opts.crit > 100:
        output.error("Critical threshold must be 0-100")
        return 2
    if opts.warn >= opts.crit:
        output.error("Warning threshold must be less than critical")
        return 2

    # Check if we can read /proc/sys
    if not context.file_exists("/proc/sys/kernel"):
        output.error("/proc/sys not available")
        return 2

    # Gather limit information
    limits = get_limit_info(context)

    if not limits:
        output.error("Unable to read any kernel limits")
        return 2

    # Analyze for warnings and critical issues
    warnings, critical = analyze_limits(limits, opts.warn, opts.crit)

    # Output based on format
    result = {
        "status": "critical" if critical else ("warning" if warnings else "ok"),
        "critical_count": len(critical),
        "warning_count": len(warnings),
        "limits": limits,
        "critical": critical,
        "warnings": warnings,
    }
    output.emit(result)

    if opts.format == "table":
        # Filter if warn_only
        if opts.warn_only:
            display_limits = warnings + critical
        else:
            display_limits = limits

        if not display_limits:
            print("No limits to display")
        else:
            print(
                f"{'Parameter':<35} {'Current':>12} {'Limit':>12} {'Usage':>8} {'Status':<10}"
            )
            print("-" * 80)

            for limit in display_limits:
                current = (
                    str(limit["current"]) if limit["current"] is not None else "N/A"
                )
                usage = (
                    f"{limit['usage_pct']}%"
                    if limit["usage_pct"] is not None
                    else "N/A"
                )

                if limit in critical:
                    status = "CRITICAL"
                elif limit in warnings:
                    status = "WARNING"
                else:
                    status = "OK"

                print(
                    f"{limit['name']:<35} {current:>12} {limit['limit']:>12} "
                    f"{usage:>8} {status:<10}"
                )
    else:
        output.render(opts.format, "Kernel Resource Limits Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    status = "critical" if critical else ("warning" if warnings else "ok")
    output.set_summary(f"critical={len(critical)}, warning={len(warnings)}, status={status}")

    # Exit code based on findings
    return 1 if (critical or warnings) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
