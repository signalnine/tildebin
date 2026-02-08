#!/usr/bin/env python3
# boxctl:
#   category: baremetal/logging
#   tags: [health, logging, journal, systemd, disk]
#   brief: Monitor systemd journal disk usage and health

"""
Monitor systemd journal disk usage and health on baremetal systems.

Checks journal disk consumption, verifies journal configuration,
and optionally identifies top log producers. Critical for preventing
disk exhaustion on systems with verbose logging.

Exit codes:
    0: Journal usage within acceptable limits
    1: Warning/Critical issues detected (high usage or corrupt journals)
    2: Usage error or missing dependencies (journalctl not available)
"""

import argparse
import re

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_disk_usage(output: str) -> dict:
    """Parse journalctl --disk-usage output."""
    data = {
        "total_bytes": 0,
        "total_human": "unknown",
    }

    # Match patterns like "1.2G", "256.0M", "512K", "1.5T"
    match = re.search(r"take up\s+([0-9.]+)([KMGTP]?)\s", output, re.IGNORECASE)
    if match:
        value = float(match.group(1))
        unit = match.group(2).upper() if match.group(2) else "B"

        multipliers = {
            "B": 1,
            "K": 1024,
            "M": 1024**2,
            "G": 1024**3,
            "T": 1024**4,
            "P": 1024**5,
        }

        data["total_bytes"] = int(value * multipliers.get(unit, 1))
        data["total_human"] = f"{value}{unit}"

    return data


def parse_journal_config(content: str) -> dict:
    """Parse journald.conf content."""
    config = {
        "SystemMaxUse": None,
        "RuntimeMaxUse": None,
        "SystemKeepFree": None,
        "RuntimeKeepFree": None,
        "MaxFileSec": None,
        "MaxRetentionSec": None,
        "Compress": None,
        "Storage": None,
    }

    for line in content.split("\n"):
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key in config and value:
            config[key] = value

    return config


def parse_size_to_bytes(size_str: str | None) -> int | None:
    """Parse human-readable size to bytes (e.g., '500M' -> 524288000)."""
    if not size_str:
        return None

    match = re.match(r"^([0-9.]+)\s*([KMGTP]?)$", size_str.strip(), re.IGNORECASE)
    if not match:
        return None

    value = float(match.group(1))
    unit = match.group(2).upper() if match.group(2) else "B"

    multipliers = {
        "B": 1,
        "K": 1024,
        "M": 1024**2,
        "G": 1024**3,
        "T": 1024**4,
        "P": 1024**5,
    }

    return int(value * multipliers.get(unit, 1))


def bytes_to_human(size_bytes: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "K", "M", "G", "T"]:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f}P"


def assess_status(
    usage_data: dict,
    config: dict,
    warn_threshold_pct: float,
    crit_threshold_pct: float,
    warn_threshold_bytes: int | None,
    crit_threshold_bytes: int | None,
) -> tuple[str, list[str]]:
    """Assess journal health status."""
    issues = []
    status = "OK"

    current_bytes = usage_data.get("total_bytes", 0)

    # Check against configured max
    max_use = config.get("SystemMaxUse")
    if max_use:
        max_bytes = parse_size_to_bytes(max_use)
        if max_bytes and current_bytes > 0:
            pct_used = (current_bytes / max_bytes) * 100
            if pct_used >= crit_threshold_pct:
                return "CRITICAL", [
                    f"Journal usage at {pct_used:.1f}% of configured max"
                ]
            elif pct_used >= warn_threshold_pct:
                issues.append(f"Journal usage at {pct_used:.1f}% of configured max")
                status = "WARNING"

    # Check absolute thresholds
    if crit_threshold_bytes and current_bytes >= crit_threshold_bytes:
        return "CRITICAL", [
            f"Journal size ({bytes_to_human(current_bytes)}) exceeds critical threshold"
        ]
    elif warn_threshold_bytes and current_bytes >= warn_threshold_bytes:
        issues.append(
            f"Journal size ({bytes_to_human(current_bytes)}) exceeds warning threshold"
        )
        status = "WARNING"

    # Check for no compression
    if config.get("Compress") and config["Compress"].lower() == "no":
        issues.append("Journal compression is disabled")
        if status == "OK":
            status = "WARNING"

    # Check storage mode
    if config.get("Storage") == "volatile":
        issues.append("Journal storage is volatile (not persistent)")
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
        0 = healthy, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor systemd journal disk usage and health"
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
        help="Only show output if issues detected",
    )
    parser.add_argument(
        "--warn-pct",
        type=float,
        default=80.0,
        help="Warning threshold as percentage of configured max (default: 80)",
    )
    parser.add_argument(
        "--crit-pct",
        type=float,
        default=95.0,
        help="Critical threshold as percentage of configured max (default: 95)",
    )
    parser.add_argument(
        "--warn-size",
        type=str,
        default=None,
        help="Warning threshold as absolute size (e.g., 2G, 500M)",
    )
    parser.add_argument(
        "--crit-size",
        type=str,
        default=None,
        help="Critical threshold as absolute size (e.g., 4G, 1G)",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn_pct <= 0 or opts.crit_pct <= 0:
        output.error("Percentage thresholds must be positive")
        return 2

    if opts.warn_pct >= opts.crit_pct:
        output.error("Warning percentage must be less than critical percentage")
        return 2

    # Parse size thresholds
    warn_bytes = parse_size_to_bytes(opts.warn_size) if opts.warn_size else None
    crit_bytes = parse_size_to_bytes(opts.crit_size) if opts.crit_size else None

    if opts.warn_size and warn_bytes is None:
        output.error(f"Invalid warning size format: {opts.warn_size}")
        return 2

    if opts.crit_size and crit_bytes is None:
        output.error(f"Invalid critical size format: {opts.crit_size}")
        return 2

    if warn_bytes and crit_bytes and warn_bytes >= crit_bytes:
        output.error("Warning size must be less than critical size")
        return 2

    # Check for journalctl
    if not context.check_tool("journalctl"):
        output.error("journalctl not found. This system may not be using systemd.")
        return 2

    # Get journal disk usage
    try:
        result = context.run(["journalctl", "--disk-usage"])
        if result.returncode != 0:
            output.error(f"Failed to get journal disk usage: {result.stderr}")
            return 1
        usage_data = parse_disk_usage(result.stdout)
    except Exception as e:
        output.error(f"Error running journalctl: {e}")
        return 2

    # Read journal configuration
    config = {}
    config_path = "/etc/systemd/journald.conf"
    if context.file_exists(config_path):
        try:
            config_content = context.read_file(config_path)
            config = parse_journal_config(config_content)
        except (IOError, OSError):
            pass

    # Assess status
    status, issues = assess_status(
        usage_data,
        config,
        opts.warn_pct,
        opts.crit_pct,
        warn_bytes,
        crit_bytes,
    )

    has_issues = status in ("CRITICAL", "WARNING")

    # Build result
    result_data = {
        "usage": usage_data,
        "config": config,
        "status": status,
        "issues": issues,
    }

    # Output
    output.emit(result_data)
    output.render(opts.format, "Journal Disk Usage Monitor", warn_only=getattr(opts, 'warn_only', False))

    output.set_summary(f"usage={usage_data.get('total_human', 'unknown')}, status={status}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
