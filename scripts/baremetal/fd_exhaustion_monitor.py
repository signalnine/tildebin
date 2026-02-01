#!/usr/bin/env python3
# boxctl:
#   category: baremetal/system
#   tags: [health, fd, limits, resources]
#   brief: Monitor file descriptor usage to detect exhaustion risk

"""
Monitor file descriptor usage to detect exhaustion risk.

Checks system-wide file descriptor usage against kernel limits (file-max).
High FD usage can cause "Too many open files" errors, failed network
connections, and service unavailability.

Exit codes:
    0: File descriptor usage is healthy
    1: High usage detected (warning or critical)
    2: Usage error or cannot read fd information
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_file_nr(content: str) -> dict:
    """Parse /proc/sys/fs/file-nr content.

    Format: allocated  unused(legacy)  max
    Example: 3200  0  9223372036854775807
    """
    parts = content.strip().split()
    if len(parts) < 3:
        raise ValueError(f"Unexpected format in file-nr: {content}")

    allocated = int(parts[0])
    file_max = int(parts[2])
    available = file_max - allocated
    usage_percent = (allocated / file_max * 100) if file_max > 0 else 0

    return {
        "allocated": allocated,
        "max": file_max,
        "available": available,
        "usage_percent": round(usage_percent, 2),
    }


def parse_limits(content: str) -> dict:
    """Parse /proc/<pid>/limits to extract Max open files."""
    limits = {"soft": None, "hard": None}
    for line in content.strip().split("\n"):
        if "Max open files" in line:
            parts = line.split()
            # Format: "Max open files  <soft>  <hard>  files"
            try:
                limits["soft"] = int(parts[-3])
                limits["hard"] = int(parts[-2])
            except (ValueError, IndexError):
                pass
            break
    return limits


def analyze_system_fd(
    stats: dict, warn_threshold: float, crit_threshold: float
) -> list[dict]:
    """Analyze system-wide file descriptor usage."""
    issues = []
    usage = stats["usage_percent"]

    if usage >= crit_threshold:
        issues.append(
            {
                "severity": "CRITICAL",
                "scope": "system",
                "metric": "system_fd_usage",
                "value": usage,
                "threshold": crit_threshold,
                "message": f"System file descriptor usage critical: {usage:.1f}% "
                f"({stats['allocated']}/{stats['max']}) - "
                f"new files/sockets may fail to open",
            }
        )
    elif usage >= warn_threshold:
        issues.append(
            {
                "severity": "WARNING",
                "scope": "system",
                "metric": "system_fd_usage",
                "value": usage,
                "threshold": warn_threshold,
                "message": f"System file descriptor usage high: {usage:.1f}% "
                f"({stats['allocated']}/{stats['max']}) - "
                f"consider increasing fs.file-max",
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
        description="Monitor file descriptor usage to detect exhaustion risk"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed output"
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=75.0,
        help="System warning threshold for usage %% (default: 75)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=90.0,
        help="System critical threshold for usage %% (default: 90)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show warnings/errors, suppress normal output",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0 or opts.warn > 100:
        output.error("--warn must be between 0 and 100")
        return 2

    if opts.crit < 0 or opts.crit > 100:
        output.error("--crit must be between 0 and 100")
        return 2

    if opts.crit <= opts.warn:
        output.error("--crit must be greater than --warn")
        return 2

    # Read /proc/sys/fs/file-nr
    try:
        file_nr_content = context.read_file("/proc/sys/fs/file-nr")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/sys/fs/file-nr: {e}")
        return 2

    try:
        system_stats = parse_file_nr(file_nr_content)
    except ValueError as e:
        output.error(str(e))
        return 2

    # Analyze system-wide usage
    issues = analyze_system_fd(system_stats, opts.warn, opts.crit)

    # Determine status
    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warning = any(i["severity"] == "WARNING" for i in issues)

    # Build result
    result = {
        "system": {
            "allocated": system_stats["allocated"],
            "max": system_stats["max"],
            "available": system_stats["available"],
            "usage_percent": system_stats["usage_percent"],
        },
        "issues": issues,
    }

    # Output
    if opts.format == "json":
        if not opts.warn_only or has_critical or has_warning:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or has_critical or has_warning:
            lines = []
            lines.append(
                f"System FDs: {system_stats['allocated']} / {system_stats['max']} "
                f"({system_stats['usage_percent']:.1f}% used)"
            )
            lines.append(f"Available: {system_stats['available']} file descriptors")

            if issues:
                lines.append("")
                for issue in issues:
                    severity = issue["severity"]
                    message = issue["message"]
                    prefix = {"CRITICAL": "[CRITICAL]", "WARNING": "[WARNING]"}.get(
                        severity, "[INFO]"
                    )
                    lines.append(f"{prefix} {message}")

            print("\n".join(lines))

    # Set summary
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")
    output.set_summary(f"fd_usage={system_stats['usage_percent']:.1f}%, status={status}")

    return 1 if (has_critical or has_warning) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
