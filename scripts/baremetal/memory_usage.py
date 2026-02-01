#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [health, memory, performance, capacity]
#   related: [swap_monitor]
#   brief: Monitor system memory usage and availability

"""
Monitor system memory usage and availability.

Analyzes /proc/meminfo to report memory usage, available memory,
and buffer/cache breakdown. Useful for capacity planning and
detecting memory exhaustion.

Exit codes:
    0: Memory usage within acceptable thresholds
    1: Low available memory detected
    2: Usage error or /proc filesystem unavailable
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_meminfo(content: str) -> dict:
    """Parse /proc/meminfo content into a dictionary."""
    meminfo = {}
    for line in content.strip().split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            parts = value.strip().split()
            if parts:
                meminfo[key.strip()] = int(parts[0])
    return meminfo


def format_bytes(kb: int) -> str:
    """Format KB value to human readable format."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb} KB"


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
    parser = argparse.ArgumentParser(description="Monitor system memory usage")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=15.0,
        help="Warning threshold for available memory %% (default: 15)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=5.0,
        help="Critical threshold for available memory %% (default: 5)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues detected",
    )
    opts = parser.parse_args(args)

    # Read /proc/meminfo
    try:
        meminfo_content = context.read_file("/proc/meminfo")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/meminfo: {e}")
        return 2

    meminfo = parse_meminfo(meminfo_content)

    # Extract memory metrics
    mem_total = meminfo.get("MemTotal", 0)
    mem_free = meminfo.get("MemFree", 0)
    mem_available = meminfo.get("MemAvailable", 0)
    buffers = meminfo.get("Buffers", 0)
    cached = meminfo.get("Cached", 0)

    if mem_total == 0:
        output.error("Invalid MemTotal value")
        return 2

    # Calculate derived metrics
    mem_used = mem_total - mem_available
    available_pct = (mem_available / mem_total) * 100
    used_pct = 100 - available_pct

    # Determine status
    issues = []
    if available_pct <= opts.crit:
        issues.append({
            "severity": "CRITICAL",
            "message": f"Very low available memory: {available_pct:.1f}% - OOM risk",
        })
    elif available_pct <= opts.warn:
        issues.append({
            "severity": "WARNING",
            "message": f"Low available memory: {available_pct:.1f}%",
        })

    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warning = any(i["severity"] == "WARNING" for i in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")

    # Build result
    result = {
        "total_kb": mem_total,
        "used_kb": mem_used,
        "available_kb": mem_available,
        "free_kb": mem_free,
        "buffers_kb": buffers,
        "cached_kb": cached,
        "available_percent": round(available_pct, 1),
        "used_percent": round(used_pct, 1),
        "status": status,
        "issues": issues,
    }

    # Output
    if opts.format == "json":
        if not opts.warn_only or issues:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or issues:
            lines = []
            lines.append("Memory Usage")
            lines.append("=" * 40)
            lines.append(
                f"Total:     {format_bytes(mem_total)}"
            )
            lines.append(
                f"Used:      {format_bytes(mem_used)} ({used_pct:.1f}%)"
            )
            lines.append(
                f"Available: {format_bytes(mem_available)} ({available_pct:.1f}%)"
            )

            if opts.verbose:
                lines.append("")
                lines.append("Breakdown:")
                lines.append(f"  Free:    {format_bytes(mem_free)}")
                lines.append(f"  Buffers: {format_bytes(buffers)}")
                lines.append(f"  Cached:  {format_bytes(cached)}")

            lines.append("")

            if issues:
                for issue in issues:
                    prefix = "[CRITICAL]" if issue["severity"] == "CRITICAL" else "[WARNING]"
                    lines.append(f"{prefix} {issue['message']}")
            else:
                lines.append("[OK] Memory usage within acceptable thresholds")

            print("\n".join(lines))

    # Set summary
    output.set_summary(f"available={available_pct:.1f}%, status={status}")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
