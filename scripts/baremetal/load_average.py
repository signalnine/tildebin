#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [health, load, performance, capacity]
#   brief: Monitor system load averages relative to CPU count

"""
Monitor system load averages relative to CPU count.

Analyzes 1, 5, and 15 minute load averages, normalizes them per CPU,
and identifies overloaded or underutilized systems.

Exit codes:
    0: Load averages within acceptable thresholds
    1: Load issues detected (overload or warnings)
    2: Usage error or unable to read system metrics
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_loadavg(content: str) -> dict:
    """
    Parse /proc/loadavg content.

    Format: "load1 load5 load15 running/total last_pid"
    Example: "0.25 0.30 0.35 1/256 12345"
    """
    parts = content.strip().split()
    if len(parts) < 4:
        raise ValueError("Invalid /proc/loadavg format")

    load1, load5, load15 = float(parts[0]), float(parts[1]), float(parts[2])

    # Parse running/total processes
    running_total = parts[3].split("/")
    running = int(running_total[0]) if len(running_total) >= 1 else 0
    total = int(running_total[1]) if len(running_total) >= 2 else 0

    return {
        "load_averages": {
            "1min": round(load1, 2),
            "5min": round(load5, 2),
            "15min": round(load15, 2),
        },
        "processes": {
            "running": running,
            "total": total,
        },
    }


def analyze_load(load_averages: dict, cpu_count: int, thresholds: dict) -> dict:
    """Analyze load averages and determine status."""
    issues = []
    warnings = []

    # Calculate normalized load (load per CPU)
    normalized = {
        "1min": round(load_averages["1min"] / cpu_count, 2),
        "5min": round(load_averages["5min"] / cpu_count, 2),
        "15min": round(load_averages["15min"] / cpu_count, 2),
    }

    # Determine trend
    if load_averages["1min"] > load_averages["15min"] * 1.5:
        trend = "increasing"
    elif load_averages["1min"] < load_averages["15min"] * 0.5:
        trend = "decreasing"
    else:
        trend = "stable"

    warning_threshold = thresholds["warning"]
    critical_threshold = thresholds["critical"]

    # Check 1-minute load
    if normalized["1min"] >= critical_threshold:
        issues.append(
            f"1-min load critical: {normalized['1min']:.2f} per CPU "
            f"(threshold: {critical_threshold})"
        )
    elif normalized["1min"] >= warning_threshold:
        warnings.append(
            f"1-min load elevated: {normalized['1min']:.2f} per CPU "
            f"(threshold: {warning_threshold})"
        )

    # Check 5-minute load
    if normalized["5min"] >= critical_threshold:
        issues.append(
            f"5-min load critical: {normalized['5min']:.2f} per CPU (sustained overload)"
        )
    elif normalized["5min"] >= warning_threshold:
        warnings.append(f"5-min load elevated: {normalized['5min']:.2f} per CPU")

    # Check 15-minute load
    if normalized["15min"] >= critical_threshold:
        issues.append(
            f"15-min load critical: {normalized['15min']:.2f} per CPU (chronic overload)"
        )

    # Check for rapidly increasing load
    if trend == "increasing" and normalized["1min"] >= warning_threshold:
        warnings.append("Load is rapidly increasing - potential runaway process")

    status = "critical" if issues else ("warning" if warnings else "healthy")

    return {
        "normalized": normalized,
        "trend": trend,
        "issues": issues,
        "warnings": warnings,
        "status": status,
    }


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
        description="Monitor system load averages relative to CPU count"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--warning",
        "-W",
        type=float,
        default=0.7,
        help="Warning threshold for normalized load per CPU (default: 0.7)",
    )
    parser.add_argument(
        "--critical",
        "-C",
        type=float,
        default=1.0,
        help="Critical threshold for normalized load per CPU (default: 1.0)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues detected",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warning >= opts.critical:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    if opts.warning < 0 or opts.critical < 0:
        output.error("Thresholds must be non-negative")
        return 2

    # Read /proc/loadavg
    try:
        loadavg_content = context.read_file("/proc/loadavg")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/loadavg: {e}")
        return 2

    # Parse metrics
    try:
        metrics = parse_loadavg(loadavg_content)
    except (ValueError, IndexError) as e:
        output.error(f"Failed to parse /proc/loadavg: {e}")
        return 2

    load_averages = metrics["load_averages"]
    processes = metrics["processes"]
    cpu_count = context.cpu_count()

    # Analyze
    thresholds = {"warning": opts.warning, "critical": opts.critical}
    analysis = analyze_load(load_averages, cpu_count, thresholds)

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu": {"online": cpu_count, "configured": cpu_count, "offline": 0},
        "load_averages": load_averages,
        "normalized_load": analysis["normalized"],
        "processes": processes,
        "trend": analysis["trend"],
        "status": analysis["status"],
        "issues": analysis["issues"],
        "warnings": analysis["warnings"],
        "healthy": len(analysis["issues"]) == 0,
    }

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            lines = []
            lines.append("System Load Average Monitor")
            lines.append("=" * 40)
            lines.append("")
            lines.append(f"CPUs: {cpu_count}")
            lines.append("")
            lines.append("Load Averages:")
            lines.append(
                f"  1-min:  {load_averages['1min']:>6.2f}  "
                f"({analysis['normalized']['1min']:.2f} per CPU)"
            )
            lines.append(
                f"  5-min:  {load_averages['5min']:>6.2f}  "
                f"({analysis['normalized']['5min']:.2f} per CPU)"
            )
            lines.append(
                f"  15-min: {load_averages['15min']:>6.2f}  "
                f"({analysis['normalized']['15min']:.2f} per CPU)"
            )
            lines.append("")
            trend_symbol = {"increasing": "^", "decreasing": "v", "stable": "-"}
            lines.append(
                f"Trend: {trend_symbol.get(analysis['trend'], '?')} {analysis['trend']}"
            )
            lines.append("")

            if opts.verbose and processes["total"] > 0:
                lines.append(
                    f"Processes: {processes['running']} running / {processes['total']} total"
                )
                lines.append("")

            if analysis["issues"]:
                lines.append("ISSUES:")
                for issue in analysis["issues"]:
                    lines.append(f"  [!] {issue}")
                lines.append("")

            if analysis["warnings"]:
                lines.append("WARNINGS:")
                for warning in analysis["warnings"]:
                    lines.append(f"  [*] {warning}")
                lines.append("")

            if not analysis["issues"] and not analysis["warnings"]:
                lines.append("[OK] Load averages within acceptable thresholds")

            print("\n".join(lines))

    # Set summary for output
    output.set_summary(f"status={analysis['status']}, trend={analysis['trend']}")

    return 1 if analysis["issues"] else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
