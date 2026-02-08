#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [health, cpu, performance, capacity]
#   related: [load_average]
#   brief: Monitor CPU usage and time distribution

"""
Monitor CPU usage and time distribution.

Analyzes /proc/stat to report CPU time breakdown including user, system,
idle, iowait, and other states. Useful for identifying CPU bottlenecks
and I/O issues.

Exit codes:
    0: CPU usage within acceptable thresholds
    1: High CPU usage or iowait detected
    2: Usage error or /proc filesystem unavailable
"""

import argparse

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_stat(content: str) -> dict:
    """
    Parse /proc/stat content.

    Returns dict with 'cpu' (aggregate) and 'cpuN' (per-CPU) stats.
    Fields: user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
    """
    cpu_stats = {}
    for line in content.strip().split("\n"):
        if line.startswith("cpu"):
            parts = line.split()
            cpu_name = parts[0]
            values = [int(x) for x in parts[1:]]

            # Pad with zeros if older kernel
            while len(values) < 10:
                values.append(0)

            cpu_stats[cpu_name] = {
                "user": values[0],
                "nice": values[1],
                "system": values[2],
                "idle": values[3],
                "iowait": values[4],
                "irq": values[5],
                "softirq": values[6],
                "steal": values[7],
                "guest": values[8],
                "guest_nice": values[9],
            }

    return cpu_stats


def calculate_percentages(stats: dict) -> dict:
    """Calculate percentage breakdown for CPU stats."""
    total = sum(stats.values())
    if total == 0:
        return {k: 0.0 for k in stats}

    return {k: round((v / total) * 100, 1) for k, v in stats.items()}


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
    parser = argparse.ArgumentParser(description="Monitor CPU usage")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show per-CPU stats")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--warn-idle",
        type=float,
        default=15.0,
        help="Warning threshold for idle %% (default: 15)",
    )
    parser.add_argument(
        "--crit-idle",
        type=float,
        default=5.0,
        help="Critical threshold for idle %% (default: 5)",
    )
    parser.add_argument(
        "--warn-iowait",
        type=float,
        default=20.0,
        help="Warning threshold for iowait %% (default: 20)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues detected",
    )
    opts = parser.parse_args(args)

    # Read /proc/stat
    try:
        stat_content = context.read_file("/proc/stat")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/stat: {e}")
        return 2

    cpu_stats = parse_stat(stat_content)

    if "cpu" not in cpu_stats:
        output.error("No CPU data found in /proc/stat")
        return 2

    # Calculate aggregate percentages
    agg = cpu_stats["cpu"]
    pct = calculate_percentages(agg)

    # Analyze
    issues = []

    # Check idle (low idle = high CPU usage)
    if pct["idle"] <= opts.crit_idle:
        issues.append({
            "severity": "CRITICAL",
            "message": f"Very high CPU usage: only {pct['idle']:.1f}% idle",
        })
    elif pct["idle"] <= opts.warn_idle:
        issues.append({
            "severity": "WARNING",
            "message": f"High CPU usage: only {pct['idle']:.1f}% idle",
        })

    # Check iowait
    if pct["iowait"] >= opts.warn_iowait:
        issues.append({
            "severity": "WARNING",
            "message": f"High I/O wait: {pct['iowait']:.1f}% - possible I/O bottleneck",
        })

    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warning = any(i["severity"] == "WARNING" for i in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")

    # Build result
    result = {
        "user": pct["user"],
        "nice": pct["nice"],
        "system": pct["system"],
        "idle": pct["idle"],
        "iowait": pct["iowait"],
        "irq": pct["irq"],
        "softirq": pct["softirq"],
        "steal": pct["steal"],
        "busy": round(100 - pct["idle"], 1),
        "status": status,
        "issues": issues,
    }

    if opts.verbose:
        # Add per-CPU data
        per_cpu = {}
        for name, stats in cpu_stats.items():
            if name != "cpu":  # Skip aggregate
                per_cpu[name] = calculate_percentages(stats)
        result["per_cpu"] = per_cpu

    # Output
    output.emit(result)
    output.render(opts.format, "CPU Usage Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    output.set_summary(f"busy={100 - pct['idle']:.1f}%, iowait={pct['iowait']:.1f}%, status={status}")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
