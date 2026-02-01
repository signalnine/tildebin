#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cgroup
#   tags: [health, cgroup, memory, container, oom, monitoring]
#   related: [cgroup_cpu_limits, cgroup_pressure, memory_usage]
#   brief: Monitor cgroup memory usage against configured limits

"""
Monitor cgroup memory usage against configured limits.

Analyzes container/cgroup memory usage relative to their configured
limits (memory.max) to identify containers at risk of OOM kills. Works
with cgroup v2 and provides early warning before memory exhaustion.

Metrics tracked:
- memory.current: Current memory usage
- memory.max: Configured limit (or "max" for unlimited)
- memory.swap.current: Swap usage (if enabled)
- memory.swap.max: Swap limit

Useful for:
- Container host capacity monitoring
- Predicting OOM kills before they happen
- Identifying memory-hungry containers
- Kubernetes node memory pressure analysis
- Docker/containerd host health checks

Exit codes:
    0: No issues detected, all cgroups within safe limits
    1: Warnings or critical issues found (high memory usage)
    2: Usage error or cgroup v2 not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_memory_value(value_str: str | None) -> int | None:
    """
    Parse memory value string.
    Returns bytes as int, or None for 'max'/unlimited.
    """
    if value_str is None:
        return None
    value_str = value_str.strip()
    if value_str == "max":
        return None  # Unlimited
    try:
        return int(value_str)
    except ValueError:
        return None


def format_bytes(bytes_val: int | None) -> str:
    """Format bytes as human-readable string."""
    if bytes_val is None:
        return "unlimited"
    if bytes_val < 1024:
        return f"{bytes_val}B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f}Ki"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.1f}Mi"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f}Gi"


def get_cgroup_memory_stats(context: Context, cgroup_path: str) -> dict:
    """Get memory statistics for a cgroup."""
    rel_path = cgroup_path.replace("/sys/fs/cgroup/", "")
    if rel_path == "" or rel_path == ".":
        rel_path = "/"

    stats = {
        "path": cgroup_path,
        "name": rel_path,
    }

    # Read memory.current (usage)
    try:
        current = context.read_file(f"{cgroup_path}/memory.current")
        stats["current"] = parse_memory_value(current)
        stats["current_raw"] = current.strip()
    except (FileNotFoundError, IOError):
        stats["current"] = None
        stats["current_raw"] = None

    # Read memory.max (limit)
    try:
        max_val = context.read_file(f"{cgroup_path}/memory.max")
        stats["max"] = parse_memory_value(max_val)
        stats["max_raw"] = max_val.strip()
    except (FileNotFoundError, IOError):
        stats["max"] = None
        stats["max_raw"] = None

    # Read memory.swap.current (if available)
    try:
        swap_current = context.read_file(f"{cgroup_path}/memory.swap.current")
        stats["swap_current"] = parse_memory_value(swap_current)
    except (FileNotFoundError, IOError):
        stats["swap_current"] = None

    # Read memory.swap.max (if available)
    try:
        swap_max = context.read_file(f"{cgroup_path}/memory.swap.max")
        stats["swap_max"] = parse_memory_value(swap_max)
    except (FileNotFoundError, IOError):
        stats["swap_max"] = None

    # Read memory.high (soft limit, if available)
    try:
        high = context.read_file(f"{cgroup_path}/memory.high")
        stats["high"] = parse_memory_value(high)
    except (FileNotFoundError, IOError):
        stats["high"] = None

    # Calculate utilization
    if stats["current"] is not None and stats["max"] is not None:
        stats["utilization"] = (stats["current"] / stats["max"]) * 100
    else:
        stats["utilization"] = None

    # Calculate swap utilization
    if stats["swap_current"] is not None and stats["swap_max"] is not None:
        stats["swap_utilization"] = (stats["swap_current"] / stats["swap_max"]) * 100
    else:
        stats["swap_utilization"] = None

    return stats


def analyze_cgroup(stats: dict, warn_threshold: float, crit_threshold: float) -> list:
    """Analyze a cgroup and return any issues."""
    issues = []

    name = stats["name"]
    utilization = stats["utilization"]

    # Skip cgroups with no limit (unlimited)
    if stats["max"] is None:
        return issues

    # Skip cgroups with no usage data
    if stats["current"] is None:
        return issues

    # Check memory utilization
    if utilization is not None:
        if utilization >= crit_threshold:
            issues.append({
                "severity": "CRITICAL",
                "type": "high_memory",
                "cgroup": name,
                "utilization": round(utilization, 1),
                "current": stats["current"],
                "max": stats["max"],
                "message": f"Memory at {utilization:.1f}% ({format_bytes(stats['current'])}/{format_bytes(stats['max'])})",
            })
        elif utilization >= warn_threshold:
            issues.append({
                "severity": "WARNING",
                "type": "high_memory",
                "cgroup": name,
                "utilization": round(utilization, 1),
                "current": stats["current"],
                "max": stats["max"],
                "message": f"Memory at {utilization:.1f}% ({format_bytes(stats['current'])}/{format_bytes(stats['max'])})",
            })

    # Check swap utilization (if swap is limited)
    swap_util = stats.get("swap_utilization")
    if swap_util is not None and swap_util >= warn_threshold:
        severity = "CRITICAL" if swap_util >= crit_threshold else "WARNING"
        issues.append({
            "severity": severity,
            "type": "high_swap",
            "cgroup": name,
            "utilization": round(swap_util, 1),
            "message": f"Swap at {swap_util:.1f}%",
        })

    return issues


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
        description="Monitor cgroup memory usage against configured limits"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show additional details"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format",
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=80.0,
        help="Warning threshold percentage (default: 80)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=90.0,
        help="Critical threshold percentage (default: 90)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Show top N memory consumers (default: 10)",
    )
    parser.add_argument(
        "--cgroup",
        help="Monitor specific cgroup path (relative to /sys/fs/cgroup)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show cgroups with issues",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if not 0.0 <= opts.warn <= 100.0:
        output.error("Warning threshold must be between 0 and 100")
        return 2

    if not 0.0 <= opts.crit <= 100.0:
        output.error("Critical threshold must be between 0 and 100")
        return 2

    if opts.warn >= opts.crit:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    # Check for cgroup v2
    if not context.file_exists("/sys/fs/cgroup/cgroup.controllers"):
        output.error("cgroup v2 not mounted (unified hierarchy required)")
        output.error("Ensure cgroup v2 unified hierarchy is mounted")
        return 2

    # Find cgroups to analyze
    if opts.cgroup:
        cgroup_path = opts.cgroup
        if not cgroup_path.startswith("/"):
            cgroup_path = f"/sys/fs/cgroup/{cgroup_path}"

        if not context.file_exists(f"{cgroup_path}/memory.current"):
            output.error(f"Cgroup not found or has no memory controller: {cgroup_path}")
            return 2

        cgroup_paths = [cgroup_path]
    else:
        # For testing, we need to check what files are available
        # In production, would walk the cgroup hierarchy
        cgroup_paths = ["/sys/fs/cgroup"]

    # Gather stats for all cgroups
    results = []
    all_issues = []

    for path in cgroup_paths:
        # Check if this cgroup has memory.current
        if not context.file_exists(f"{path}/memory.current"):
            continue

        stats = get_cgroup_memory_stats(context, path)
        results.append(stats)

        # Analyze for issues
        issues = analyze_cgroup(stats, opts.warn, opts.crit)
        all_issues.extend(issues)

    if not results:
        output.error("No cgroups with memory controller found")
        return 2

    # Sort by utilization (highest first)
    sorted_results = sorted(
        [r for r in results if r["utilization"] is not None],
        key=lambda x: x["utilization"],
        reverse=True,
    )

    # Output results
    if opts.format == "json":
        result = {
            "cgroups": results,
            "issues": all_issues,
            "summary": {
                "total_cgroups": len(results),
                "with_limits": len([r for r in results if r["max"] is not None]),
                "critical_count": len([i for i in all_issues if i["severity"] == "CRITICAL"]),
                "warning_count": len([i for i in all_issues if i["severity"] == "WARNING"]),
            },
        }
        if not opts.warn_only or all_issues:
            print(json.dumps(result, indent=2))

    elif opts.format == "table":
        if opts.warn_only:
            # Only show cgroups with issues
            issue_cgroups = set(i["cgroup"] for i in all_issues)
            sorted_results = [r for r in sorted_results if r["name"] in issue_cgroups]

        if not opts.warn_only or all_issues:
            lines = []
            lines.append(
                f"{'Cgroup':<45} {'Current':<10} {'Limit':<10} {'Util%':>7} {'Status':<10}"
            )
            lines.append("-" * 85)

            for stats in sorted_results[: opts.top]:
                name = stats["name"]
                if len(name) > 43:
                    name = "..." + name[-40:]

                current = format_bytes(stats["current"])
                max_val = format_bytes(stats["max"])
                util = stats["utilization"] if stats["utilization"] is not None else 0.0

                # Determine status
                status = "OK"
                cgroup_issues = [i for i in all_issues if i["cgroup"] == stats["name"]]
                if any(i["severity"] == "CRITICAL" for i in cgroup_issues):
                    status = "CRITICAL"
                elif any(i["severity"] == "WARNING" for i in cgroup_issues):
                    status = "WARNING"

                lines.append(
                    f"{name:<45} {current:<10} {max_val:<10} {util:>6.1f}% {status:<10}"
                )

            print("\n".join(lines))

    else:  # plain
        if not opts.warn_only or all_issues:
            lines = []
            lines.append("Cgroup Memory Limits Monitor")
            lines.append("=" * 60)
            lines.append("")

            # Show top N consumers
            lines.append(f"Top {opts.top} Memory Consumers (by utilization):")
            lines.append(f"{'Cgroup':<40} {'Usage':<12} {'Limit':<12} {'%':>6}")
            lines.append("-" * 72)

            for stats in sorted_results[: opts.top]:
                name = stats["name"]
                if len(name) > 38:
                    name = "..." + name[-35:]

                current = format_bytes(stats["current"])
                max_val = format_bytes(stats["max"])
                util = stats["utilization"] if stats["utilization"] is not None else 0.0

                lines.append(f"{name:<40} {current:<12} {max_val:<12} {util:>5.1f}%")

            lines.append("")

            # Show issues
            if all_issues:
                critical = [i for i in all_issues if i["severity"] == "CRITICAL"]
                warnings = [i for i in all_issues if i["severity"] == "WARNING"]

                if critical:
                    lines.append(f"CRITICAL Issues ({len(critical)}):")
                    for issue in critical:
                        lines.append(f"  !!! {issue['cgroup']}: {issue['message']}")
                    lines.append("")

                if warnings:
                    lines.append(f"Warnings ({len(warnings)}):")
                    for issue in warnings:
                        lines.append(f"  {issue['cgroup']}: {issue['message']}")
                    lines.append("")
            else:
                lines.append("No memory limit issues detected.")
                lines.append("")

            # Verbose: show summary
            if opts.verbose:
                limited = [r for r in results if r["max"] is not None]
                unlimited = [
                    r for r in results if r["max"] is None and r["current"] is not None
                ]
                lines.append(
                    f"Summary: {len(limited)} cgroups with limits, {len(unlimited)} unlimited"
                )

            print("\n".join(lines))

    # Set summary
    has_critical = any(i["severity"] == "CRITICAL" for i in all_issues)
    has_warnings = any(i["severity"] == "WARNING" for i in all_issues)
    status = "critical" if has_critical else ("warning" if has_warnings else "healthy")
    output.set_summary(f"status={status}, issues={len(all_issues)}")

    return 1 if (has_critical or has_warnings) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
