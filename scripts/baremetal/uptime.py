#!/usr/bin/env python3
# boxctl:
#   category: baremetal/system
#   tags: [health, uptime, availability]
#   brief: Monitor system uptime and detect recent reboots

"""
Monitor system uptime and detect recent reboots.

Reads /proc/uptime to report system uptime and optionally warn
about systems that have recently rebooted (which may indicate issues).

Exit codes:
    0: System uptime is healthy
    1: Recent reboot detected (below minimum threshold)
    2: Usage error or /proc filesystem unavailable
"""

import argparse

from boxctl.core.context import Context
from boxctl.core.output import Output


def format_uptime(seconds: float) -> str:
    """Format uptime in human-readable format."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")

    return " ".join(parts)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = recent reboot, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor system uptime")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--min-uptime",
        type=float,
        default=1.0,
        help="Minimum uptime in hours before warning (default: 1)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues detected",
    )
    opts = parser.parse_args(args)

    # Read /proc/uptime
    try:
        uptime_content = context.read_file("/proc/uptime")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/uptime: {e}")
        return 2

    try:
        parts = uptime_content.strip().split()
        uptime_seconds = float(parts[0])
        idle_seconds = float(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError) as e:
        output.error(f"Failed to parse /proc/uptime: {e}")
        return 2

    uptime_hours = uptime_seconds / 3600
    uptime_human = format_uptime(uptime_seconds)

    # Check minimum uptime
    issues = []
    if uptime_hours < opts.min_uptime:
        issues.append({
            "severity": "WARNING",
            "message": f"System recently rebooted: uptime is only {uptime_human}",
        })

    status = "warning" if issues else "healthy"

    # Build result
    result = {
        "uptime_seconds": round(uptime_seconds, 1),
        "uptime_hours": round(uptime_hours, 2),
        "uptime_human": uptime_human,
        "idle_seconds": round(idle_seconds, 1),
        "status": status,
        "issues": issues,
    }

    # Output
    output.emit(result)
    output.render(opts.format, "System Uptime Monitor", warn_only=getattr(opts, 'warn_only', False))

    output.set_summary(f"uptime={uptime_human}, status={status}")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
