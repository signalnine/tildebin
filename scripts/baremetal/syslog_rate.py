#!/usr/bin/env python3
# boxctl:
#   category: baremetal/logging
#   tags: [health, logging, journal, syslog, rate]
#   brief: Monitor syslog/journald message rates for log storm detection

"""
Monitor syslog/journald message rates for baremetal systems.

Detects log storms, excessive logging from specific services, and unusual
message rate patterns that may indicate:
- Runaway services generating excessive logs
- Log storms that can fill disk space rapidly
- Security events (brute force attempts, etc.)
- Application failures causing repeated error logging

Exit codes:
    0: Message rates are within normal thresholds
    1: Message rates exceed thresholds (warnings/issues found)
    2: Usage error or journalctl not available
"""

import argparse
import json
from datetime import datetime

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_journal_messages(content: str) -> list[dict]:
    """Parse journalctl JSON output into message list."""
    messages = []
    for line in content.strip().split("\n"):
        if line:
            try:
                msg = json.loads(line)
                messages.append(msg)
            except json.JSONDecodeError:
                continue
    return messages


def analyze_messages(
    messages: list[dict],
    since_minutes: int,
    rate_threshold: int,
    top_count: int,
) -> dict:
    """Analyze message statistics."""
    total_count = len(messages)
    rate_per_minute = total_count / since_minutes if since_minutes > 0 else 0

    # Count by source (unit or identifier)
    source_counts: dict[str, int] = {}
    priority_counts = {
        "0": 0,  # emerg
        "1": 0,  # alert
        "2": 0,  # crit
        "3": 0,  # err
        "4": 0,  # warning
        "5": 0,  # notice
        "6": 0,  # info
        "7": 0,  # debug
    }

    for msg in messages:
        # Get source
        source = (
            msg.get("_SYSTEMD_UNIT")
            or msg.get("SYSLOG_IDENTIFIER")
            or "unknown"
        )
        source_counts[source] = source_counts.get(source, 0) + 1

        # Get priority
        priority = msg.get("PRIORITY", "6")
        if priority in priority_counts:
            priority_counts[priority] = priority_counts.get(priority, 0) + 1

    # Sort sources by count
    top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[
        :top_count
    ]

    # Calculate per-source rates
    top_sources_with_rates = [
        {
            "source": source,
            "count": count,
            "rate_per_minute": count / since_minutes if since_minutes > 0 else 0,
            "percentage": (count / total_count * 100) if total_count > 0 else 0,
        }
        for source, count in top_sources
    ]

    # Identify high-rate sources
    high_rate_sources = [
        s for s in top_sources_with_rates if s["rate_per_minute"] > rate_threshold
    ]

    # Priority summary
    priority_summary = {
        "emergency": priority_counts["0"],
        "alert": priority_counts["1"],
        "critical": priority_counts["2"],
        "error": priority_counts["3"],
        "warning": priority_counts["4"],
        "notice": priority_counts["5"],
        "info": priority_counts["6"],
        "debug": priority_counts["7"],
    }

    return {
        "total_count": total_count,
        "rate_per_minute": rate_per_minute,
        "top_sources": top_sources_with_rates,
        "high_rate_sources": high_rate_sources,
        "priority_summary": priority_summary,
        "unique_sources": len(source_counts),
    }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = high rate detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor syslog/journald message rates"
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
        help="Only show output if high-rate sources detected",
    )
    parser.add_argument(
        "--since",
        type=int,
        default=5,
        metavar="MINUTES",
        help="Time window to analyze in minutes (default: 5)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=100,
        metavar="RATE",
        help="Message rate threshold per source (msgs/min) to trigger warning (default: 100)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Number of top sources to display (default: 10)",
    )
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.since <= 0:
        output.error("--since must be positive")
        return 2
    if opts.threshold <= 0:
        output.error("--threshold must be positive")
        return 2
    if opts.top <= 0:
        output.error("--top must be positive")
        return 2

    # Check for journalctl
    if not context.check_tool("journalctl"):
        output.error("journalctl not found in PATH")
        return 2

    # Get journal messages
    try:
        result = context.run(
            [
                "journalctl",
                "--since",
                f"{opts.since} minutes ago",
                "--no-pager",
                "-o",
                "json",
                "--output-fields=_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,PRIORITY",
            ],
            timeout=30,
        )
        if result.returncode != 0:
            output.error(f"Failed to read journal: {result.stderr}")
            return 2
        messages = parse_journal_messages(result.stdout)
    except Exception as e:
        output.error(f"Error reading journal: {e}")
        return 2

    # Analyze messages
    analysis = analyze_messages(messages, opts.since, opts.threshold, opts.top)

    has_issues = len(analysis["high_rate_sources"]) > 0

    # Build result
    result_data = {
        "timestamp": datetime.now().isoformat(),
        "window_minutes": opts.since,
        "rate_threshold": opts.threshold,
        **analysis,
        "has_issues": has_issues,
    }

    # Output
    output.emit(result_data)
    output.render(opts.format, "Syslog Message Rate Monitor", warn_only=getattr(opts, 'warn_only', False))

    output.set_summary(
        f"rate={analysis['rate_per_minute']:.1f}/min, "
        f"high_rate_sources={len(analysis['high_rate_sources'])}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
