#!/usr/bin/env python3
# boxctl:
#   category: baremetal/system
#   tags: [health, inotify, watches, resources, filesystem]
#   brief: Monitor inotify watch usage to detect exhaustion risk

"""
Monitor inotify watch usage to detect exhaustion risk on baremetal systems.

Inotify watches are a limited kernel resource used for file system event
monitoring. When exhausted, applications fail with "No space left on device"
or "Too many open files" errors despite having disk space and file descriptors.

Common consumers: Kubernetes kubelet, IDEs, file sync tools, build tools.

Exit codes:
    0: Inotify usage is healthy
    1: High usage or issues detected (warning or critical)
    2: Usage error or cannot read inotify information
"""

import argparse

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_inotify_limits(context: Context) -> dict:
    """Read inotify kernel limits from /proc/sys/fs/inotify."""
    limits = {
        "max_user_watches": None,
        "max_user_instances": None,
        "max_queued_events": None,
    }

    paths = {
        "max_user_watches": "/proc/sys/fs/inotify/max_user_watches",
        "max_user_instances": "/proc/sys/fs/inotify/max_user_instances",
        "max_queued_events": "/proc/sys/fs/inotify/max_queued_events",
    }

    for key, path in paths.items():
        try:
            content = context.read_file(path)
            limits[key] = int(content.strip())
        except (FileNotFoundError, PermissionError, ValueError):
            pass

    return limits


def analyze_usage(
    limits: dict,
    total_watches: int,
    total_instances: int,
    warn_threshold: float,
    crit_threshold: float,
) -> tuple[list[dict], dict]:
    """Analyze inotify usage and generate issues."""
    issues = []
    summary = {
        "total_watches": total_watches,
        "total_instances": total_instances,
        "max_user_watches": limits.get("max_user_watches"),
        "max_user_instances": limits.get("max_user_instances"),
        "usage_percent": None,
        "instance_percent": None,
    }

    # Calculate watch usage percentage
    if limits.get("max_user_watches") and limits["max_user_watches"] > 0:
        summary["usage_percent"] = round(
            (total_watches / limits["max_user_watches"]) * 100, 1
        )

        if summary["usage_percent"] >= crit_threshold:
            issues.append(
                {
                    "severity": "CRITICAL",
                    "type": "high_watch_usage",
                    "message": f"Inotify watch usage critical: {summary['usage_percent']}% "
                    f"({total_watches}/{limits['max_user_watches']})",
                }
            )
        elif summary["usage_percent"] >= warn_threshold:
            issues.append(
                {
                    "severity": "WARNING",
                    "type": "high_watch_usage",
                    "message": f"Inotify watch usage elevated: {summary['usage_percent']}% "
                    f"({total_watches}/{limits['max_user_watches']})",
                }
            )

    # Calculate instance usage
    if limits.get("max_user_instances") and limits["max_user_instances"] > 0:
        summary["instance_percent"] = round(
            (total_instances / limits["max_user_instances"]) * 100, 1
        )

        if summary["instance_percent"] >= crit_threshold:
            issues.append(
                {
                    "severity": "CRITICAL",
                    "type": "high_instance_usage",
                    "message": f"Inotify instance usage critical: {summary['instance_percent']}% "
                    f"({total_instances}/{limits['max_user_instances']})",
                }
            )
        elif summary["instance_percent"] >= warn_threshold:
            issues.append(
                {
                    "severity": "WARNING",
                    "type": "high_instance_usage",
                    "message": f"Inotify instance usage elevated: {summary['instance_percent']}% "
                    f"({total_instances}/{limits['max_user_instances']})",
                }
            )

    # Check for low limits (common misconfiguration)
    if limits.get("max_user_watches") and limits["max_user_watches"] < 65536:
        issues.append(
            {
                "severity": "WARNING",
                "type": "low_limit",
                "message": f"max_user_watches limit is low: {limits['max_user_watches']} "
                f"(recommend at least 65536 for production)",
            }
        )

    return issues, summary


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
        description="Monitor inotify watch usage to detect exhaustion risk"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all processes with inotify watches",
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only output if issues are detected",
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=75.0,
        help="Warning threshold percentage (default: 75)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=90.0,
        help="Critical threshold percentage (default: 90)",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if not (0 <= opts.warn <= 100) or not (0 <= opts.crit <= 100):
        output.error("Thresholds must be between 0 and 100")
        return 2

    if opts.warn >= opts.crit:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    # Get kernel limits
    limits = get_inotify_limits(context)

    if limits["max_user_watches"] is None:
        output.error("Cannot read inotify limits from /proc/sys/fs/inotify")
        return 2

    # Count inotify watches per process
    process_watches = {}
    total_watches = 0
    total_instances = 0

    # Enumerate processes
    try:
        proc_dirs = context.glob("[0-9]*", "/proc")
    except Exception:
        proc_dirs = []

    for proc_path in proc_dirs:
        pid = proc_path.split("/")[-1]
        if not pid.isdigit():
            continue

        # Get process name
        try:
            name = context.read_file(f"/proc/{pid}/comm").strip()
        except (FileNotFoundError, IOError):
            continue

        # Look for inotify instances in fd
        try:
            fd_list = context.glob("*", f"/proc/{pid}/fd")
        except Exception:
            fd_list = []

        proc_instances = 0
        proc_watches = 0

        for fd_path in fd_list:
            fd_num = fd_path.split("/")[-1]
            try:
                target = context.readlink(fd_path)
                if not target:
                    continue
                if "inotify" in target:
                    proc_instances += 1

                    # Try to count watches from fdinfo
                    try:
                        fdinfo = context.read_file(f"/proc/{pid}/fdinfo/{fd_num}")
                        for line in fdinfo.split("\n"):
                            if line.startswith("inotify wd:"):
                                proc_watches += 1
                    except (FileNotFoundError, IOError):
                        # Can't read fdinfo, estimate 1 watch per instance
                        proc_watches += 1
            except (FileNotFoundError, IOError):
                continue

        if proc_instances > 0 or proc_watches > 0:
            process_watches[pid] = {
                "name": name,
                "watches": proc_watches,
                "instances": proc_instances,
            }
            total_watches += proc_watches
            total_instances += proc_instances

    # Analyze usage
    issues, summary = analyze_usage(
        limits, total_watches, total_instances, opts.warn, opts.crit
    )

    # Get top consumers
    sorted_procs = sorted(
        process_watches.items(), key=lambda x: x[1]["watches"], reverse=True
    )
    summary["top_consumers"] = [
        {
            "pid": int(pid),
            "name": info["name"],
            "watches": info["watches"],
            "instances": info["instances"],
        }
        for pid, info in sorted_procs[:10]
    ]

    # Check warn-only mode
    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warnings = any(i["severity"] == "WARNING" for i in issues)

    # Build result
    result = {
        "limits": limits,
        "summary": summary,
        "issues": issues,
        "processes": [
            {
                "pid": int(pid),
                "name": info["name"],
                "watches": info["watches"],
                "instances": info["instances"],
            }
            for pid, info in sorted_procs
        ],
        "healthy": len([i for i in issues if i["severity"] == "CRITICAL"]) == 0,
    }

    output.emit(result)

    if opts.warn_only and not issues:
        return 0

    # Output
    output.render(opts.format, "Inotify Watch Exhaustion Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    status = (
        "critical"
        if has_critical
        else ("warning" if has_warnings else "healthy")
    )
    output.set_summary(
        f"watches={total_watches}, usage={summary.get('usage_percent', 0)}%, status={status}"
    )

    return 1 if (has_critical or has_warnings) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
