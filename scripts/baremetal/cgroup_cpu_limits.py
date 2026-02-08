#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cgroup
#   tags: [health, cgroup, cpu, container, throttling, monitoring]
#   related: [cgroup_memory_limits, cgroup_pressure, cpu_usage]
#   brief: Monitor cgroup CPU resource limits and utilization

"""
Monitor cgroup CPU resource limits and utilization.

Analyzes CPU resource allocation for cgroups (containers, systemd
services, etc.) to identify misconfigured or over-constrained workloads.
Works with cgroup v2 unified hierarchy.

CPU resources tracked:
- cpu.max: CPU bandwidth limit (quota/period microseconds)
- cpu.weight: Proportional CPU share (1-10000, default 100)
- cpu.stat: Actual CPU usage statistics
- cpuset.cpus: Pinned CPU cores (if cpuset controller enabled)

Useful for:
- Detecting containers with overly restrictive CPU limits
- Finding services with unfair CPU weight allocation
- Identifying CPU throttling before it impacts latency
- Kubernetes pod CPU quota auditing
- Container host capacity planning

Exit codes:
    0: No issues detected, all cgroups have reasonable limits
    1: Warnings or critical issues found (throttling, misconfig)
    2: Usage error or cgroup v2 not available
"""

import argparse

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_cpu_max(value: str | None) -> tuple[int | None, int | None]:
    """
    Parse cpu.max value.

    Format: "$MAX $PERIOD" where:
    - MAX is quota in microseconds or "max" for unlimited
    - PERIOD is the period in microseconds (default 100000)

    Returns tuple: (quota_us, period_us) or (None, period_us) if unlimited
    """
    if value is None:
        return None, None

    parts = value.strip().split()
    if len(parts) != 2:
        return None, None

    quota_str, period_str = parts

    try:
        period = int(period_str)
    except ValueError:
        period = 100000  # Default

    if quota_str == "max":
        return None, period  # Unlimited

    try:
        quota = int(quota_str)
        return quota, period
    except ValueError:
        return None, period


def parse_cpu_stat(content: str | None) -> dict:
    """
    Parse cpu.stat file content.

    Format:
    usage_usec 123456
    user_usec 100000
    system_usec 23456
    nr_periods 1000
    nr_throttled 50
    throttled_usec 5000000
    ...
    """
    stats = {}
    if content is None:
        return stats

    for line in content.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            key = parts[0]
            try:
                stats[key] = int(parts[1])
            except ValueError:
                stats[key] = parts[1]

    return stats


def format_cpu_limit(stats: dict) -> str:
    """Format CPU limit as a human-readable string."""
    if stats.get("cpu_limit_pct") is None:
        return "unlimited"

    limit = stats["cpu_limit_pct"]
    if limit >= 100:
        cores = limit / 100
        return f"{cores:.1f} cores"
    else:
        return f"{limit:.0f}%"


def get_cgroup_cpu_stats(context: Context, cgroup_path: str) -> dict:
    """Get CPU statistics for a cgroup."""
    rel_path = cgroup_path.replace("/sys/fs/cgroup/", "")
    if rel_path == "" or rel_path == ".":
        rel_path = "/"

    stats = {
        "path": cgroup_path,
        "name": rel_path,
    }

    # Read cpu.max (bandwidth limit)
    try:
        cpu_max = context.read_file(f"{cgroup_path}/cpu.max")
        quota, period = parse_cpu_max(cpu_max)
        stats["quota_us"] = quota
        stats["period_us"] = period
        stats["cpu_max_raw"] = cpu_max.strip()
    except (FileNotFoundError, IOError):
        stats["quota_us"] = None
        stats["period_us"] = None
        stats["cpu_max_raw"] = None

    # Calculate CPU limit as a percentage of one CPU
    if stats["quota_us"] is not None and stats["period_us"] is not None and stats["period_us"] > 0:
        stats["cpu_limit_pct"] = (stats["quota_us"] / stats["period_us"]) * 100
    else:
        stats["cpu_limit_pct"] = None  # Unlimited

    # Read cpu.weight (proportional share)
    try:
        weight = context.read_file(f"{cgroup_path}/cpu.weight")
        stats["weight"] = int(weight.strip())
    except (FileNotFoundError, IOError, ValueError):
        stats["weight"] = None

    # Read cpu.stat (usage and throttling)
    try:
        cpu_stat = context.read_file(f"{cgroup_path}/cpu.stat")
        stat_data = parse_cpu_stat(cpu_stat)
        stats["usage_usec"] = stat_data.get("usage_usec", 0)
        stats["nr_periods"] = stat_data.get("nr_periods", 0)
        stats["nr_throttled"] = stat_data.get("nr_throttled", 0)
        stats["throttled_usec"] = stat_data.get("throttled_usec", 0)
    except (FileNotFoundError, IOError):
        stats["usage_usec"] = 0
        stats["nr_periods"] = 0
        stats["nr_throttled"] = 0
        stats["throttled_usec"] = 0

    # Calculate throttle percentage
    if stats["nr_periods"] > 0:
        stats["throttle_pct"] = (stats["nr_throttled"] / stats["nr_periods"]) * 100
    else:
        stats["throttle_pct"] = 0.0

    # Read cpuset.cpus if available
    try:
        cpuset = context.read_file(f"{cgroup_path}/cpuset.cpus")
        stats["cpuset"] = cpuset.strip()
    except (FileNotFoundError, IOError):
        stats["cpuset"] = None

    return stats


def analyze_cgroup(
    stats: dict, throttle_warn: float, throttle_crit: float, low_weight_threshold: int
) -> list:
    """Analyze a cgroup and return any issues."""
    issues = []
    name = stats["name"]

    # Check for CPU throttling
    throttle_pct = stats.get("throttle_pct", 0)
    if throttle_pct >= throttle_crit:
        issues.append({
            "severity": "CRITICAL",
            "type": "throttling",
            "cgroup": name,
            "throttle_pct": round(throttle_pct, 1),
            "nr_throttled": stats.get("nr_throttled", 0),
            "message": f"CPU throttled {throttle_pct:.1f}% of periods ({stats.get('nr_throttled', 0)} throttled)",
        })
    elif throttle_pct >= throttle_warn:
        issues.append({
            "severity": "WARNING",
            "type": "throttling",
            "cgroup": name,
            "throttle_pct": round(throttle_pct, 1),
            "nr_throttled": stats.get("nr_throttled", 0),
            "message": f"CPU throttled {throttle_pct:.1f}% of periods ({stats.get('nr_throttled', 0)} throttled)",
        })

    # Check for very low CPU weight (unfair scheduling)
    weight = stats.get("weight")
    if weight is not None and weight < low_weight_threshold:
        issues.append({
            "severity": "WARNING",
            "type": "low_weight",
            "cgroup": name,
            "weight": weight,
            "message": f"Very low CPU weight ({weight}), may be starved for CPU",
        })

    # Check for very restrictive CPU limits (< 10% of one CPU)
    cpu_limit = stats.get("cpu_limit_pct")
    if cpu_limit is not None and cpu_limit < 10:
        issues.append({
            "severity": "WARNING",
            "type": "low_limit",
            "cgroup": name,
            "cpu_limit_pct": round(cpu_limit, 1),
            "message": f"Very restrictive CPU limit ({cpu_limit:.1f}% of one core)",
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
        description="Monitor cgroup CPU resource limits and utilization"
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
        "--throttle-warn",
        type=float,
        default=10.0,
        help="Throttle warning threshold percentage (default: 10)",
    )
    parser.add_argument(
        "--throttle-crit",
        type=float,
        default=25.0,
        help="Throttle critical threshold percentage (default: 25)",
    )
    parser.add_argument(
        "--low-weight",
        type=int,
        default=50,
        help="Warn if CPU weight below this value (default: 50)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=15,
        help="Show top N cgroups (default: 15)",
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
    if not 0.0 <= opts.throttle_warn <= 100.0:
        output.error("Throttle warning threshold must be between 0 and 100")
        return 2

    if not 0.0 <= opts.throttle_crit <= 100.0:
        output.error("Throttle critical threshold must be between 0 and 100")
        return 2

    if opts.throttle_warn >= opts.throttle_crit:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    if not 1 <= opts.low_weight <= 10000:
        output.error("Low weight threshold must be between 1 and 10000")
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

        cgroup_paths = [cgroup_path]
    else:
        # For testing, we check the root cgroup
        cgroup_paths = ["/sys/fs/cgroup"]

    # Gather stats for all cgroups
    results = []
    all_issues = []

    for path in cgroup_paths:
        # Check if this cgroup has cpu.max or cpu.weight
        has_cpu = (
            context.file_exists(f"{path}/cpu.max") or
            context.file_exists(f"{path}/cpu.weight") or
            context.file_exists(f"{path}/cpu.stat")
        )
        if not has_cpu:
            continue

        stats = get_cgroup_cpu_stats(context, path)
        results.append(stats)

        # Analyze for issues
        issues = analyze_cgroup(
            stats, opts.throttle_warn, opts.throttle_crit, opts.low_weight
        )
        all_issues.extend(issues)

    if not results:
        output.error("No cgroups with CPU controller found")
        return 2

    # Sort by throttle percentage (highest first)
    sorted_results = sorted(
        results,
        key=lambda x: (x.get("throttle_pct", 0), x.get("usage_usec", 0)),
        reverse=True,
    )

    # Build result
    result = {
        "cgroups": results,
        "issues": all_issues,
        "summary": {
            "total_cgroups": len(results),
            "with_limits": len([r for r in results if r.get("cpu_limit_pct") is not None]),
            "throttled": len([r for r in results if r.get("throttle_pct", 0) > 0]),
            "critical_count": len([i for i in all_issues if i["severity"] == "CRITICAL"]),
            "warning_count": len([i for i in all_issues if i["severity"] == "WARNING"]),
        },
    }

    output.emit(result)

    # Output results
    if opts.format == "table":
        if opts.warn_only:
            # Only show cgroups with issues
            issue_cgroups = set(i["cgroup"] for i in all_issues)
            sorted_results = [r for r in sorted_results if r["name"] in issue_cgroups]

        if not opts.warn_only or all_issues:
            lines = []
            lines.append(
                f"{'Cgroup':<40} {'Limit':<10} {'Weight':>6} {'Throttle':>9} {'Status':<10}"
            )
            lines.append("-" * 80)

            for stats in sorted_results[: opts.top]:
                name = stats["name"]
                if len(name) > 38:
                    name = "..." + name[-35:]

                limit = format_cpu_limit(stats)
                weight = stats.get("weight", "-")
                weight_str = str(weight) if weight != "-" else "-"
                throttle = stats.get("throttle_pct", 0)

                # Determine status
                status = "OK"
                cgroup_issues = [i for i in all_issues if i["cgroup"] == stats["name"]]
                if any(i["severity"] == "CRITICAL" for i in cgroup_issues):
                    status = "CRITICAL"
                elif any(i["severity"] == "WARNING" for i in cgroup_issues):
                    status = "WARNING"

                lines.append(
                    f"{name:<40} {limit:<10} {weight_str:>6} {throttle:>8.1f}% {status:<10}"
                )

            print("\n".join(lines))
    else:
        output.render(opts.format, "Cgroup CPU Limits Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    has_critical = any(i["severity"] == "CRITICAL" for i in all_issues)
    has_warnings = any(i["severity"] == "WARNING" for i in all_issues)
    status = "critical" if has_critical else ("warning" if has_warnings else "healthy")
    output.set_summary(f"status={status}, issues={len(all_issues)}")

    return 1 if (has_critical or has_warnings) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
