#!/usr/bin/env python3
# boxctl:
#   category: baremetal/logging
#   tags: [health, logging, coredump, crash, debugging]
#   brief: Monitor coredump configuration and storage for production debugging

"""
Monitor coredump configuration and storage for production debugging.

Monitors the system's coredump handling configuration and storage to ensure
crash dumps are properly captured for post-mortem debugging. Critical for
large-scale baremetal environments where:

- Production crashes need to be analyzed for root cause
- Disk space must be managed to prevent coredump storage exhaustion
- Coredump patterns must be correctly configured for collection tools
- systemd-coredump or kernel coredumps need verification

Exit codes:
    0: Coredump configuration is healthy
    1: Issues detected (misconfiguration or storage concerns)
    2: Usage error or system files not accessible
"""

import argparse
import json
import re

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_coredump_config(content: str) -> dict:
    """Parse systemd coredump.conf content."""
    config = {
        "Storage": None,
        "Compress": None,
        "ProcessSizeMax": None,
        "ExternalSizeMax": None,
        "JournalSizeMax": None,
        "MaxUse": None,
        "KeepFree": None,
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


def check_ulimit(context: Context) -> dict:
    """Check core file size limit via /proc/self/limits."""
    # Read from /proc/self/limits which shows resource limits
    try:
        content = context.read_file("/proc/self/limits")
        for line in content.split("\n"):
            if "Max core file size" in line:
                parts = line.split()
                # Format: "Max core file size      unlimited        unlimited        bytes"
                # or:     "Max core file size      0                unlimited        bytes"
                soft_str = parts[4] if len(parts) > 4 else "unknown"
                hard_str = parts[5] if len(parts) > 5 else "unknown"

                soft = "unlimited" if soft_str == "unlimited" else int(soft_str)
                hard = "unlimited" if hard_str == "unlimited" else int(hard_str)

                return {
                    "soft_limit": soft,
                    "hard_limit": hard,
                    "enabled": soft != 0,
                }
    except (FileNotFoundError, IOError, ValueError, IndexError):
        pass

    # Fallback - assume enabled if we can't determine
    return {
        "soft_limit": "unknown",
        "hard_limit": "unknown",
        "enabled": True,
    }


def analyze_configuration(
    core_pattern: str,
    systemd_config: dict,
    ulimit_info: dict,
    storage_warn_pct: int,
    storage_crit_pct: int,
) -> list[dict]:
    """Analyze coredump configuration and return issues."""
    issues = []

    # Check if coredumps are disabled
    if core_pattern == "" or core_pattern == "/dev/null":
        issues.append(
            {
                "severity": "WARNING",
                "category": "configuration",
                "message": "Core dumps disabled (core_pattern is empty or /dev/null)",
            }
        )

    # Check ulimit
    if not ulimit_info["enabled"]:
        issues.append(
            {
                "severity": "WARNING",
                "category": "ulimit",
                "message": "Core file size limit is 0 - no core dumps will be generated",
            }
        )

    # Check systemd-coredump storage setting
    is_systemd = "systemd-coredump" in core_pattern
    if is_systemd:
        if systemd_config.get("Storage") == "none":
            issues.append(
                {
                    "severity": "WARNING",
                    "category": "systemd",
                    "message": "systemd-coredump storage set to none - cores discarded",
                }
            )
        elif systemd_config.get("Storage") == "journal":
            issues.append(
                {
                    "severity": "INFO",
                    "category": "systemd",
                    "message": "Coredumps stored in journal - may be truncated for large cores",
                }
            )

    return issues


def format_bytes(size: int | str) -> str:
    """Format bytes to human readable format."""
    if isinstance(size, str):
        return size
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


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
        description="Monitor coredump configuration and storage"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show additional details"
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
        help="Only show warnings and errors",
    )
    parser.add_argument(
        "--storage-warn",
        type=int,
        default=75,
        metavar="PERCENT",
        help="Storage warning threshold (default: 75%%)",
    )
    parser.add_argument(
        "--storage-crit",
        type=int,
        default=90,
        metavar="PERCENT",
        help="Storage critical threshold (default: 90%%)",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if not (0 <= opts.storage_warn <= 100):
        output.error("--storage-warn must be between 0 and 100")
        return 2
    if not (0 <= opts.storage_crit <= 100):
        output.error("--storage-crit must be between 0 and 100")
        return 2
    if opts.storage_crit <= opts.storage_warn:
        output.error("--storage-crit must be greater than --storage-warn")
        return 2

    # Read core_pattern
    core_pattern_path = "/proc/sys/kernel/core_pattern"
    try:
        core_pattern = context.read_file(core_pattern_path).strip()
    except FileNotFoundError:
        output.error(f"{core_pattern_path} not found")
        return 2
    except Exception as e:
        output.error(f"Error reading core_pattern: {e}")
        return 2

    # Read core_uses_pid
    try:
        core_uses_pid = context.read_file("/proc/sys/kernel/core_uses_pid").strip() == "1"
    except Exception:
        core_uses_pid = False

    # Read core_pipe_limit
    try:
        core_pipe_limit = int(context.read_file("/proc/sys/kernel/core_pipe_limit").strip())
    except Exception:
        core_pipe_limit = 0

    # Read systemd coredump config
    systemd_config = {}
    coredump_conf_path = "/etc/systemd/coredump.conf"
    if context.file_exists(coredump_conf_path):
        try:
            content = context.read_file(coredump_conf_path)
            systemd_config = parse_coredump_config(content)
        except Exception:
            pass

    # Check ulimit
    ulimit_info = check_ulimit(context)

    # Analyze configuration
    issues = analyze_configuration(
        core_pattern,
        systemd_config,
        ulimit_info,
        opts.storage_warn,
        opts.storage_crit,
    )

    # Check pipe limit for piped patterns
    if core_pattern.startswith("|") and core_pipe_limit == 0:
        issues.append(
            {
                "severity": "WARNING",
                "category": "configuration",
                "message": "core_pipe_limit is 0 - concurrent crashes may lose dumps",
            }
        )

    # Determine status
    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warning = any(i["severity"] == "WARNING" for i in issues)
    has_issues = has_critical or has_warning

    status = "CRITICAL" if has_critical else ("WARNING" if has_warning else "OK")

    # Determine if systemd-coredump is in use
    is_systemd_coredump = "systemd-coredump" in core_pattern

    # Build result
    result_data = {
        "core_pattern": core_pattern,
        "core_uses_pid": core_uses_pid,
        "core_pipe_limit": core_pipe_limit,
        "ulimit": ulimit_info,
        "systemd_coredump": {
            "enabled": is_systemd_coredump,
            **systemd_config,
        },
        "issues": issues,
        "status": status,
    }

    # Output
    if opts.format == "json":
        if not opts.warn_only or has_issues:
            print(json.dumps(result_data, indent=2, default=str))
    else:
        if not opts.warn_only or has_issues:
            lines = ["Coredump Configuration", "-" * 50]
            lines.append(f"Core Pattern: {core_pattern}")

            soft = ulimit_info["soft_limit"]
            if isinstance(soft, int):
                soft = format_bytes(soft)
            lines.append(
                f"Core Size Limit: {soft} (soft), {ulimit_info['hard_limit']} (hard)"
            )
            lines.append(f"Core Uses PID: {core_uses_pid}")

            if is_systemd_coredump:
                lines.append("")
                lines.append("systemd-coredump: enabled")
                if systemd_config.get("Storage"):
                    lines.append(f"  Storage: {systemd_config['Storage']}")
                if systemd_config.get("Compress"):
                    lines.append(f"  Compress: {systemd_config['Compress']}")
                if systemd_config.get("MaxUse"):
                    lines.append(f"  Max Use: {systemd_config['MaxUse']}")

            lines.append("")

            # Print issues
            if issues:
                filtered_issues = [
                    i for i in issues if not (opts.warn_only and i["severity"] == "INFO")
                ]
                for issue in filtered_issues:
                    lines.append(f"[{issue['severity']}] {issue['message']}")
            else:
                lines.append("[OK] No coredump configuration issues detected.")

            print("\n".join(lines))

    output.set_summary(f"pattern={'systemd' if is_systemd_coredump else 'file'}, status={status}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
