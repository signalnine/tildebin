#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [health, swap, memory, performance]
#   brief: Monitor swap usage and memory pressure indicators

"""
Monitor swap usage and memory pressure indicators.

Analyzes /proc/meminfo for swap usage and /proc/vmstat for swap I/O activity.
High swap usage or frequent swap I/O indicates memory pressure.

Exit codes:
    0: Swap usage within acceptable range
    1: High swap usage or memory pressure detected
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
            # Extract numeric value (remove 'kB' suffix)
            parts = value.strip().split()
            if parts:
                meminfo[key.strip()] = int(parts[0])
    return meminfo


def parse_vmstat(content: str) -> dict:
    """Parse /proc/vmstat content into a dictionary."""
    vmstat = {}
    for line in content.strip().split("\n"):
        parts = line.strip().split(None, 1)
        if len(parts) >= 2:
            vmstat[parts[0]] = int(parts[1])
    return vmstat


def format_bytes(kb: int) -> str:
    """Format KB value to human readable format."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb} KB"


def analyze_swap(meminfo: dict, warn_pct: float, crit_pct: float) -> list[dict]:
    """Analyze swap usage and return issues."""
    issues = []

    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)
    swap_cached = meminfo.get("SwapCached", 0)
    swap_used = swap_total - swap_free

    # Handle systems without swap
    if swap_total == 0:
        return [
            {
                "severity": "INFO",
                "metric": "swap_total",
                "value": 0,
                "message": "No swap space configured",
            }
        ]

    # Calculate usage percentage
    swap_used_pct = (swap_used / swap_total * 100) if swap_total > 0 else 0

    # Check swap usage thresholds
    if swap_used_pct >= crit_pct:
        issues.append(
            {
                "severity": "CRITICAL",
                "metric": "swap_usage",
                "value": swap_used_pct,
                "threshold": crit_pct,
                "message": f"Swap usage critical: {swap_used_pct:.1f}% "
                f"({format_bytes(swap_used)} / {format_bytes(swap_total)})",
            }
        )
    elif swap_used_pct >= warn_pct:
        issues.append(
            {
                "severity": "WARNING",
                "metric": "swap_usage",
                "value": swap_used_pct,
                "threshold": warn_pct,
                "message": f"Swap usage elevated: {swap_used_pct:.1f}% "
                f"({format_bytes(swap_used)} / {format_bytes(swap_total)})",
            }
        )

    # Check swap cache
    if swap_cached > 0:
        swap_cached_pct = (swap_cached / swap_total * 100) if swap_total > 0 else 0
        if swap_cached_pct > 5:
            issues.append(
                {
                    "severity": "INFO",
                    "metric": "swap_cached",
                    "value": swap_cached_pct,
                    "message": f"Swap cache active: {swap_cached_pct:.1f}% (recent swap I/O)",
                }
            )

    return issues


def analyze_memory_pressure(meminfo: dict) -> list[dict]:
    """Analyze memory pressure indicators."""
    issues = []

    mem_total = meminfo.get("MemTotal", 0)
    mem_available = meminfo.get("MemAvailable", 0)

    if mem_total == 0:
        return issues

    mem_available_pct = mem_available / mem_total * 100

    if mem_available_pct < 5:
        issues.append(
            {
                "severity": "CRITICAL",
                "metric": "mem_available",
                "value": mem_available_pct,
                "message": f"Very low available memory: {mem_available_pct:.1f}% - OOM risk",
            }
        )
    elif mem_available_pct < 10:
        issues.append(
            {
                "severity": "WARNING",
                "metric": "mem_available",
                "value": mem_available_pct,
                "message": f"Low available memory: {mem_available_pct:.1f}%",
            }
        )

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
        description="Monitor swap usage and memory pressure"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=50.0,
        help="Warning threshold for swap usage %% (default: 50)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=75.0,
        help="Critical threshold for swap usage %% (default: 75)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues detected",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0 or opts.warn > 100:
        output.error("--warn must be between 0 and 100")
        return 2

    if opts.crit < 0 or opts.crit > 100:
        output.error("--crit must be between 0 and 100")
        return 2

    if opts.warn >= opts.crit:
        output.error("--warn must be less than --crit")
        return 2

    # Read /proc/meminfo
    try:
        meminfo_content = context.read_file("/proc/meminfo")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/meminfo: {e}")
        return 2

    meminfo = parse_meminfo(meminfo_content)

    # Read /proc/vmstat (optional)
    vmstat = {}
    try:
        vmstat_content = context.read_file("/proc/vmstat")
        vmstat = parse_vmstat(vmstat_content)
    except (FileNotFoundError, IOError):
        pass  # vmstat is optional

    # Analyze
    issues = []
    issues.extend(analyze_swap(meminfo, opts.warn, opts.crit))
    issues.extend(analyze_memory_pressure(meminfo))

    # Determine status
    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warning = any(i["severity"] == "WARNING" for i in issues)

    # Calculate swap metrics
    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)
    swap_used = swap_total - swap_free
    swap_cached = meminfo.get("SwapCached", 0)
    swap_used_pct = (swap_used / swap_total * 100) if swap_total > 0 else 0

    mem_total = meminfo.get("MemTotal", 0)
    mem_available = meminfo.get("MemAvailable", 0)
    mem_available_pct = (mem_available / mem_total * 100) if mem_total > 0 else 0

    # Build result
    result = {
        "swap": {
            "total_kb": swap_total,
            "used_kb": swap_used,
            "free_kb": swap_free,
            "cached_kb": swap_cached,
            "usage_percent": round(swap_used_pct, 1),
        },
        "memory": {
            "total_kb": mem_total,
            "available_kb": mem_available,
            "available_percent": round(mem_available_pct, 1),
        },
        "issues": issues,
    }

    if opts.verbose and vmstat:
        result["vmstat"] = {
            "pswpin": vmstat.get("pswpin", 0),
            "pswpout": vmstat.get("pswpout", 0),
        }

    # Output
    if opts.format == "json":
        if not opts.warn_only or has_critical or has_warning:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or has_critical or has_warning:
            lines = []
            lines.append(
                f"Swap: {format_bytes(swap_used)} / {format_bytes(swap_total)} "
                f"({swap_used_pct:.1f}% used)"
            )

            if swap_cached > 0:
                lines.append(f"Swap cached: {format_bytes(swap_cached)}")

            if opts.verbose:
                lines.append(
                    f"Memory available: {format_bytes(mem_available)} / {format_bytes(mem_total)} "
                    f"({mem_available_pct:.1f}%)"
                )

                if vmstat:
                    pswpin = vmstat.get("pswpin", 0)
                    pswpout = vmstat.get("pswpout", 0)
                    if pswpin > 0 or pswpout > 0:
                        lines.append(
                            f"Swap I/O since boot: {pswpin} pages in, {pswpout} pages out"
                        )

            lines.append("")

            # Print issues
            for issue in issues:
                severity = issue["severity"]
                message = issue["message"]

                if opts.warn_only and severity == "INFO":
                    continue

                prefix = {"CRITICAL": "[CRITICAL]", "WARNING": "[WARNING]", "INFO": "[INFO]"}.get(
                    severity, "[UNKNOWN]"
                )
                lines.append(f"{prefix} {message}")

            print("\n".join(lines))

    # Set summary
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")
    output.set_summary(f"swap={swap_used_pct:.1f}%, status={status}")

    return 1 if (has_critical or has_warning) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
