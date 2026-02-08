#!/usr/bin/env python3
# boxctl:
#   category: baremetal/logging
#   tags: [health, logging, kernel, dmesg, rate]
#   brief: Monitor kernel log message rates to detect anomalies

"""
Monitor kernel log message rates to detect anomalies.

Analyzes the rate of kernel messages (via dmesg) to detect unusual
spikes that may indicate hardware problems, driver issues, or system
instability. A sudden increase in kernel message rate often precedes
hardware failures or system issues.

Exit codes:
    0: Normal message rate, no anomalies detected
    1: Elevated message rate or anomalies detected
    2: Usage error or dmesg not available
"""

import argparse
import re
from collections import defaultdict
from datetime import datetime, timedelta

from boxctl.core.context import Context
from boxctl.core.output import Output


# Kernel log priority levels (matching syslog)
PRIORITY_LEVELS = {
    "emerg": 0,
    "alert": 1,
    "crit": 2,
    "err": 3,
    "warn": 4,
    "notice": 5,
    "info": 6,
    "debug": 7,
}

# Default thresholds (messages per minute)
DEFAULT_WARN_RATE = 50
DEFAULT_CRIT_RATE = 200
DEFAULT_BURST_THRESHOLD = 20


def parse_human_timestamp(ts_str: str) -> datetime | None:
    """Parse human-readable timestamp from dmesg -T."""
    # Format: [Mon Jan 15 10:30:45 2024]
    try:
        ts_clean = ts_str.strip("[]")
        return datetime.strptime(ts_clean, "%a %b %d %H:%M:%S %Y")
    except (ValueError, AttributeError):
        return None


def parse_dmesg_line(line: str) -> tuple[datetime | None, str, str]:
    """Parse a single dmesg line and extract timestamp and message."""
    if not line.strip():
        return None, "info", ""

    timestamp = None
    priority = "info"

    # Human format: [Mon Jan 15 10:30:45 2024] message
    match = re.match(r"^\[([^\]]+)\]\s+(.*)$", line)
    if match:
        timestamp = parse_human_timestamp(match.group(1))
        message = match.group(2)
    else:
        message = line

    # Try to extract priority from message (e.g., "<3>message")
    priority_match = re.match(r"^<(\d)>\s*(.*)$", message)
    if priority_match:
        prio_num = int(priority_match.group(1))
        for name, num in PRIORITY_LEVELS.items():
            if num == prio_num:
                priority = name
                break
        message = priority_match.group(2)

    return timestamp, priority, message


def analyze_message_rates(lines: list[str], window_minutes: int = 5) -> dict:
    """Analyze message rates from dmesg output."""
    messages = []
    priority_counts: dict[str, int] = defaultdict(int)

    for line in lines:
        timestamp, priority, message = parse_dmesg_line(line)
        if message:
            messages.append(
                {
                    "timestamp": timestamp,
                    "priority": priority,
                    "message": message,
                }
            )
            priority_counts[priority] += 1

    if not messages:
        return {
            "total_messages": 0,
            "messages_per_minute": None,
            "recent_rate": None,
            "priority_breakdown": {},
            "time_window_minutes": None,
            "bursts": [],
            "has_timestamps": False,
            "high_priority_count": 0,
        }

    # Check if we have timestamps
    timestamps = [m["timestamp"] for m in messages if m["timestamp"]]
    has_timestamps = len(timestamps) > 0

    if has_timestamps and len(timestamps) >= 2:
        # Calculate time window from actual timestamps
        min_time = min(timestamps)
        max_time = max(timestamps)
        time_span = (max_time - min_time).total_seconds()
        time_window_minutes = max(time_span / 60.0, 0.1)

        # Calculate messages per minute
        messages_per_minute = len(messages) / time_window_minutes

        # Detect bursts
        bursts = detect_bursts(timestamps)

        # Calculate rate for recent window
        recent_cutoff = max_time - timedelta(minutes=window_minutes)
        recent_messages = [
            m for m in messages if m["timestamp"] and m["timestamp"] >= recent_cutoff
        ]
        recent_rate = len(recent_messages) / window_minutes if recent_messages else 0
    else:
        time_window_minutes = None
        messages_per_minute = None
        bursts = []
        recent_rate = None

    return {
        "total_messages": len(messages),
        "messages_per_minute": messages_per_minute,
        "recent_rate": recent_rate,
        "priority_breakdown": dict(priority_counts),
        "time_window_minutes": time_window_minutes,
        "bursts": bursts,
        "has_timestamps": has_timestamps,
        "high_priority_count": sum(
            priority_counts.get(p, 0) for p in ["emerg", "alert", "crit", "err"]
        ),
    }


def detect_bursts(
    timestamps: list[datetime],
    burst_window_secs: int = 5,
    burst_threshold: int = 20,
) -> list[dict]:
    """Detect message bursts (many messages in short time window)."""
    if len(timestamps) < burst_threshold:
        return []

    bursts = []
    sorted_timestamps = sorted(timestamps)

    i = 0
    while i < len(sorted_timestamps):
        window_end = sorted_timestamps[i] + timedelta(seconds=burst_window_secs)
        count = 0
        j = i

        while j < len(sorted_timestamps) and sorted_timestamps[j] <= window_end:
            count += 1
            j += 1

        if count >= burst_threshold:
            bursts.append(
                {
                    "start": sorted_timestamps[i].isoformat(),
                    "count": count,
                    "duration_secs": burst_window_secs,
                }
            )
            i = j  # Skip past this burst
        else:
            i += 1

    return bursts


def evaluate_health(
    stats: dict,
    warn_rate: float,
    crit_rate: float,
    burst_threshold: int,
) -> tuple[str, list[dict]]:
    """Evaluate system health based on message rates."""
    issues = []
    status = "OK"

    if stats["messages_per_minute"] is not None:
        rate = stats["messages_per_minute"]
        if rate >= crit_rate:
            issues.append(
                {
                    "severity": "CRITICAL",
                    "message": f"Very high message rate: {rate:.1f} msgs/min (threshold: {crit_rate})",
                }
            )
            status = "CRITICAL"
        elif rate >= warn_rate:
            issues.append(
                {
                    "severity": "WARNING",
                    "message": f"Elevated message rate: {rate:.1f} msgs/min (threshold: {warn_rate})",
                }
            )
            if status != "CRITICAL":
                status = "WARNING"

    # Check for bursts
    for burst in stats["bursts"]:
        if burst["count"] >= burst_threshold * 2:
            issues.append(
                {
                    "severity": "CRITICAL",
                    "message": f"Severe burst detected: {burst['count']} messages in {burst['duration_secs']}s",
                }
            )
            status = "CRITICAL"
        else:
            issues.append(
                {
                    "severity": "WARNING",
                    "message": f"Burst detected: {burst['count']} messages in {burst['duration_secs']}s",
                }
            )
            if status != "CRITICAL":
                status = "WARNING"

    # Check high-priority message count
    if stats["high_priority_count"] > 10:
        issues.append(
            {
                "severity": "WARNING",
                "message": f"High number of error-level messages: {stats['high_priority_count']}",
            }
        )
        if status == "OK":
            status = "WARNING"

    return status, issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor kernel log message rates to detect anomalies"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed information"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show output if issues are detected",
    )
    parser.add_argument(
        "--warn-rate",
        type=float,
        default=DEFAULT_WARN_RATE,
        help=f"Warning threshold in messages/minute (default: {DEFAULT_WARN_RATE})",
    )
    parser.add_argument(
        "--crit-rate",
        type=float,
        default=DEFAULT_CRIT_RATE,
        help=f"Critical threshold in messages/minute (default: {DEFAULT_CRIT_RATE})",
    )
    parser.add_argument(
        "--burst-threshold",
        type=int,
        default=DEFAULT_BURST_THRESHOLD,
        help=f"Burst detection threshold (msgs in 5 sec) (default: {DEFAULT_BURST_THRESHOLD})",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn_rate >= opts.crit_rate:
        output.error("warn-rate must be less than crit-rate")
        return 2

    # Check for dmesg
    if not context.check_tool("dmesg"):
        output.error("dmesg command not found")
        return 2

    # Run dmesg with human-readable timestamps
    try:
        result = context.run(["dmesg", "-T"], timeout=10)
        if result.returncode != 0:
            output.error(f"dmesg failed: {result.stderr}")
            return 2
        dmesg_output = result.stdout
    except Exception as e:
        output.error(f"Error running dmesg: {e}")
        return 2

    # Analyze message rates
    lines = dmesg_output.strip().split("\n")
    stats = analyze_message_rates(lines)

    # Evaluate health
    status, issues = evaluate_health(
        stats, opts.warn_rate, opts.crit_rate, opts.burst_threshold
    )

    has_issues = status in ("CRITICAL", "WARNING")

    # Build result
    result_data = {
        "status": status,
        "statistics": {
            "total_messages": stats["total_messages"],
            "messages_per_minute": stats["messages_per_minute"],
            "recent_rate": stats["recent_rate"],
            "time_window_minutes": stats["time_window_minutes"],
            "has_timestamps": stats["has_timestamps"],
            "high_priority_count": stats["high_priority_count"],
            "priority_breakdown": stats["priority_breakdown"],
        },
        "bursts": stats["bursts"],
        "issues": issues,
    }

    # Output
    output.emit(result_data)
    output.render(opts.format, "Kernel Log Rate Monitor", warn_only=getattr(opts, 'warn_only', False))

    rate_str = (
        f"{stats['messages_per_minute']:.1f}/min"
        if stats["messages_per_minute"] is not None
        else "unknown"
    )
    output.set_summary(f"rate={rate_str}, status={status}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
