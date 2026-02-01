#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, softnet, backlog, drops, performance]
#   brief: Monitor Linux softnet backlog statistics for packet processing issues

"""
Monitor Linux softnet backlog statistics for network packet processing issues.

The softnet subsystem handles incoming network packets via per-CPU queues.
When these queues overflow or processing stalls, packets are dropped silently
without generating ICMP errors, making issues hard to diagnose.

This script monitors /proc/net/softnet_stat for:
- Packet processing counts per CPU
- Drops due to queue overflow (netdev_budget exhausted)
- Time squeeze events (CPU couldn't process all packets in time slice)
- CPU imbalance in packet processing

Exit codes:
    0: Softnet statistics healthy, no drops or squeezes
    1: Drops or time squeezes detected (warning or critical)
    2: Cannot read /proc/net/softnet_stat or usage error
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_softnet_stat(content: str) -> list:
    """
    Parse /proc/net/softnet_stat.

    Each line represents a CPU and contains space-separated hex values:
    Column 0: total packets processed
    Column 1: dropped packets (queue full)
    Column 2: time_squeeze (ran out of time budget)

    Returns:
        list: List of dicts with per-CPU statistics
    """
    stats = []

    for cpu_idx, line in enumerate(content.strip().split("\n")):
        line = line.strip()
        if not line:
            continue

        fields = line.split()
        if len(fields) < 3:
            continue

        try:
            cpu_stat = {
                "cpu": cpu_idx,
                "processed": int(fields[0], 16),
                "dropped": int(fields[1], 16),
                "time_squeeze": int(fields[2], 16),
            }

            # Optional fields depending on kernel version
            if len(fields) > 9:
                cpu_stat["cpu_collision"] = int(fields[9], 16)
            if len(fields) > 10:
                cpu_stat["received_rps"] = int(fields[10], 16)
            if len(fields) > 11:
                cpu_stat["flow_limit_count"] = int(fields[11], 16)

            stats.append(cpu_stat)
        except (ValueError, IndexError):
            continue

    return stats


def calculate_totals(cpu_stats: list) -> dict:
    """Calculate aggregate statistics across all CPUs."""
    totals = {
        "total_processed": 0,
        "total_dropped": 0,
        "total_time_squeeze": 0,
        "total_flow_limit": 0,
        "cpu_count": len(cpu_stats),
    }

    for stat in cpu_stats:
        totals["total_processed"] += stat.get("processed", 0)
        totals["total_dropped"] += stat.get("dropped", 0)
        totals["total_time_squeeze"] += stat.get("time_squeeze", 0)
        totals["total_flow_limit"] += stat.get("flow_limit_count", 0)

    return totals


def detect_cpu_imbalance(cpu_stats: list, threshold_ratio: int = 10) -> dict | None:
    """
    Detect significant imbalance in packet processing across CPUs.

    Args:
        cpu_stats: List of per-CPU stat dictionaries
        threshold_ratio: Max/min ratio threshold for imbalance

    Returns:
        dict or None: Imbalance info if detected, None otherwise
    """
    if len(cpu_stats) < 2:
        return None

    processed_counts = [s.get("processed", 0) for s in cpu_stats]
    if not processed_counts:
        return None

    max_processed = max(processed_counts)
    min_processed = min(processed_counts)

    # Avoid division by zero; skip if all zeros
    if min_processed == 0:
        if max_processed > 0:
            return {
                "max_cpu": processed_counts.index(max_processed),
                "max_processed": max_processed,
                "min_cpu": processed_counts.index(min_processed),
                "min_processed": min_processed,
                "ratio": float("inf"),
            }
        return None

    ratio = max_processed / min_processed

    if ratio > threshold_ratio:
        return {
            "max_cpu": processed_counts.index(max_processed),
            "max_processed": max_processed,
            "min_cpu": processed_counts.index(min_processed),
            "min_processed": min_processed,
            "ratio": ratio,
        }

    return None


def analyze_stats(
    cpu_stats: list, totals: dict, drop_warn: int, drop_crit: int, squeeze_warn: int, squeeze_crit: int
) -> dict:
    """Analyze softnet statistics and generate issues."""
    issues = []
    warnings = []

    # Check total drops
    if totals["total_dropped"] >= drop_crit:
        issues.append(
            {
                "type": "packet_drops",
                "severity": "critical",
                "value": totals["total_dropped"],
                "message": f"Critical packet drops: {totals['total_dropped']:,} packets dropped due to backlog overflow",
            }
        )
    elif totals["total_dropped"] >= drop_warn:
        warnings.append(
            {
                "type": "packet_drops",
                "severity": "warning",
                "value": totals["total_dropped"],
                "message": f"Packet drops detected: {totals['total_dropped']:,} packets dropped due to backlog overflow",
            }
        )

    # Check time squeeze events
    if totals["total_time_squeeze"] >= squeeze_crit:
        issues.append(
            {
                "type": "time_squeeze",
                "severity": "critical",
                "value": totals["total_time_squeeze"],
                "message": f"Critical time squeeze events: {totals['total_time_squeeze']:,} (CPU couldn't keep up with packet rate)",
            }
        )
    elif totals["total_time_squeeze"] >= squeeze_warn:
        warnings.append(
            {
                "type": "time_squeeze",
                "severity": "warning",
                "value": totals["total_time_squeeze"],
                "message": f"Time squeeze events: {totals['total_time_squeeze']:,} (CPU processing budget exhausted)",
            }
        )

    # Check for CPU imbalance
    imbalance = detect_cpu_imbalance(cpu_stats)
    if imbalance:
        warnings.append(
            {
                "type": "cpu_imbalance",
                "max_cpu": imbalance["max_cpu"],
                "min_cpu": imbalance["min_cpu"],
                "ratio": imbalance["ratio"],
                "message": f"CPU packet processing imbalance: CPU{imbalance['max_cpu']} processed {imbalance['ratio']:.1f}x more than CPU{imbalance['min_cpu']}",
            }
        )

    # Check flow limit drops
    if totals["total_flow_limit"] > 0:
        warnings.append(
            {
                "type": "flow_limit",
                "value": totals["total_flow_limit"],
                "message": f"Flow limit drops: {totals['total_flow_limit']:,} (per-flow rate limiting triggered)",
            }
        )

    status = "critical" if issues else ("warning" if warnings else "healthy")

    return {
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
        description="Monitor Linux softnet backlog statistics for packet processing issues"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all per-CPU statistics")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--drop-warn",
        type=int,
        default=1,
        metavar="N",
        help="Warning threshold for packet drops (default: 1)",
    )
    parser.add_argument(
        "--drop-crit",
        type=int,
        default=1000,
        metavar="N",
        help="Critical threshold for packet drops (default: 1000)",
    )
    parser.add_argument(
        "--squeeze-warn",
        type=int,
        default=1,
        metavar="N",
        help="Warning threshold for time squeezes (default: 1)",
    )
    parser.add_argument(
        "--squeeze-crit",
        type=int,
        default=1000,
        metavar="N",
        help="Critical threshold for time squeezes (default: 1000)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only output if issues are detected",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.drop_warn < 0 or opts.drop_crit < 0:
        output.error("Drop thresholds must be non-negative")
        return 2

    if opts.squeeze_warn < 0 or opts.squeeze_crit < 0:
        output.error("Squeeze thresholds must be non-negative")
        return 2

    if opts.drop_warn > opts.drop_crit:
        output.error("--drop-warn must be less than or equal to --drop-crit")
        return 2

    if opts.squeeze_warn > opts.squeeze_crit:
        output.error("--squeeze-warn must be less than or equal to --squeeze-crit")
        return 2

    # Read softnet statistics
    try:
        softnet_content = context.read_file("/proc/net/softnet_stat")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Cannot read /proc/net/softnet_stat: {e}")
        return 2

    # Parse statistics
    cpu_stats = parse_softnet_stat(softnet_content)

    if not cpu_stats:
        output.error("No softnet statistics found")
        return 2

    # Calculate totals
    totals = calculate_totals(cpu_stats)

    # Analyze statistics
    analysis = analyze_stats(
        cpu_stats,
        totals,
        opts.drop_warn,
        opts.drop_crit,
        opts.squeeze_warn,
        opts.squeeze_crit,
    )

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "totals": totals,
        "per_cpu": cpu_stats,
        "status": analysis["status"],
        "issues": analysis["issues"],
        "warnings": analysis["warnings"],
        "healthy": totals["total_dropped"] == 0 and totals["total_time_squeeze"] == 0,
    }

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            lines = []
            lines.append("Softnet Backlog Statistics")
            lines.append("=" * 60)
            lines.append("")
            lines.append("Aggregate Statistics:")
            lines.append(f"  Packets processed:  {totals['total_processed']:>15,}")
            lines.append(f"  Packets dropped:    {totals['total_dropped']:>15,}")
            lines.append(f"  Time squeezes:      {totals['total_time_squeeze']:>15,}")
            if totals["total_flow_limit"] > 0:
                lines.append(f"  Flow limit drops:   {totals['total_flow_limit']:>15,}")
            lines.append("")

            if opts.verbose:
                lines.append("Per-CPU Statistics:")
                lines.append(f"  {'CPU':<6} {'Processed':>15} {'Dropped':>12} {'Squeeze':>12}")
                lines.append("  " + "-" * 47)
                for stat in cpu_stats:
                    lines.append(
                        f"  {stat['cpu']:<6} {stat['processed']:>15,} "
                        f"{stat['dropped']:>12,} {stat['time_squeeze']:>12,}"
                    )
                lines.append("")

            if analysis["issues"]:
                lines.append("ISSUES:")
                for issue in analysis["issues"]:
                    lines.append(f"  [!] {issue['message']}")
                lines.append("")

            if analysis["warnings"]:
                lines.append("WARNINGS:")
                for warning in analysis["warnings"]:
                    lines.append(f"  [*] {warning['message']}")
                lines.append("")

            if not analysis["issues"] and not analysis["warnings"]:
                lines.append("[OK] Softnet statistics healthy")

            print("\n".join(lines))

    output.set_summary(f"status={analysis['status']}")

    return 1 if analysis["issues"] else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
