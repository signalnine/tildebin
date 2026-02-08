#!/usr/bin/env python3
# boxctl:
#   category: baremetal/logging
#   tags: [health, logging, logrotate, disk]
#   brief: Monitor logrotate status and log file health

"""
Monitor logrotate status and log file health for baremetal systems.

Detects log rotation issues that can lead to disk exhaustion:
- Log files that have grown too large (failed rotation)
- Logrotate state file issues
- Stale logs that haven't rotated recently

Exit codes:
    0: Log rotation is healthy, no issues detected
    1: Warnings or issues found (large logs, stale rotation)
    2: Usage error or required files not accessible
"""

import argparse
import os
from datetime import datetime, timedelta
from pathlib import Path

from boxctl.core.context import Context
from boxctl.core.output import Output


# Default paths
DEFAULT_LOG_DIRS = ["/var/log"]
LOGROTATE_STATE_FILES = [
    "/var/lib/logrotate/status",
    "/var/lib/logrotate.status",
]

# Default thresholds
DEFAULT_MAX_LOG_SIZE_MB = 100
DEFAULT_MAX_AGE_DAYS = 7


def parse_logrotate_state(content: str) -> dict[str, datetime]:
    """Parse logrotate state file content to get last rotation times."""
    state = {}

    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("logrotate state"):
            continue

        # Format: "/var/log/file" 2024-1-15-12:0:0
        parts = line.rsplit(None, 1)
        if len(parts) == 2:
            log_path = parts[0].strip('"')
            date_str = parts[1]

            try:
                if "-" in date_str and ":" in date_str:
                    date_parts = date_str.replace(":", "-").split("-")
                    if len(date_parts) >= 6:
                        dt = datetime(
                            int(date_parts[0]),
                            int(date_parts[1]),
                            int(date_parts[2]),
                            int(date_parts[3]),
                            int(date_parts[4]),
                            int(date_parts[5]),
                        )
                        state[log_path] = dt
            except (ValueError, IndexError):
                continue

    return state


def find_stale_logs(
    logrotate_state: dict[str, datetime],
    max_age_days: int,
    context: Context,
) -> list[dict]:
    """Find logs that haven't been rotated in too long."""
    if not logrotate_state:
        return []

    stale_logs = []
    now = datetime.now()
    threshold = now - timedelta(days=max_age_days)

    for log_path, last_rotation in logrotate_state.items():
        if last_rotation < threshold:
            if context.file_exists(log_path):
                age_days = (now - last_rotation).days
                stale_logs.append(
                    {
                        "path": log_path,
                        "last_rotation": last_rotation.isoformat(),
                        "age_days": age_days,
                    }
                )

    return sorted(stale_logs, key=lambda x: x["age_days"], reverse=True)


def find_large_logs(
    log_dirs: list[str],
    max_size_mb: float,
    context: Context,
) -> list[dict]:
    """Find log files exceeding size threshold."""
    large_logs = []

    # Skip compressed file extensions
    compressed_exts = {".gz", ".bz2", ".xz", ".zst", ".lz4"}

    for log_dir in log_dirs:
        if not context.file_exists(log_dir):
            continue

        # Get all files in the log directory (non-recursive for safety)
        try:
            for pattern in ["*.log", "syslog", "messages", "kern.log", "auth.log"]:
                for filepath in context.glob(pattern, log_dir):
                    # Skip compressed files
                    if Path(filepath).suffix in compressed_exts:
                        continue

                    try:
                        content = context.read_file(filepath)
                        size_bytes = len(content.encode("utf-8"))
                        size_mb = size_bytes / (1024 * 1024)

                        if size_mb >= max_size_mb:
                            large_logs.append(
                                {
                                    "path": filepath,
                                    "size_mb": round(size_mb, 2),
                                }
                            )
                    except (IOError, OSError):
                        continue
        except (IOError, OSError):
            continue

    return sorted(large_logs, key=lambda x: x["size_mb"], reverse=True)


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
        description="Monitor logrotate status and log file health"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed output"
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
        "--log-dir",
        nargs="+",
        default=DEFAULT_LOG_DIRS,
        metavar="DIR",
        help="Log directories to check (default: /var/log)",
    )
    parser.add_argument(
        "--max-size",
        type=float,
        default=DEFAULT_MAX_LOG_SIZE_MB,
        metavar="MB",
        help=f"Maximum log file size in MB (default: {DEFAULT_MAX_LOG_SIZE_MB})",
    )
    parser.add_argument(
        "--max-age",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        metavar="DAYS",
        help=f"Maximum days since last rotation (default: {DEFAULT_MAX_AGE_DAYS})",
    )
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.max_size <= 0:
        output.error("--max-size must be positive")
        return 2
    if opts.max_age <= 0:
        output.error("--max-age must be positive")
        return 2

    # Find and read logrotate state file
    logrotate_state = {}
    state_file_found = False

    for state_path in LOGROTATE_STATE_FILES:
        if context.file_exists(state_path):
            try:
                content = context.read_file(state_path)
                logrotate_state = parse_logrotate_state(content)
                state_file_found = True
                break
            except (IOError, OSError):
                continue

    # Find issues
    large_logs = find_large_logs(opts.log_dir, opts.max_size, context)
    stale_logs = find_stale_logs(logrotate_state, opts.max_age, context)

    # Build issues list
    issues = []
    for log in large_logs:
        issues.append(
            {
                "severity": "WARNING",
                "category": "large_log",
                "message": f"Large log file: {log['path']} ({log['size_mb']} MB)",
            }
        )

    for log in stale_logs:
        issues.append(
            {
                "severity": "WARNING",
                "category": "stale_rotation",
                "message": f"Stale rotation: {log['path']} ({log['age_days']} days)",
            }
        )

    if not state_file_found:
        issues.append(
            {
                "severity": "INFO",
                "category": "state_file",
                "message": "Logrotate state file not found",
            }
        )

    has_issues = any(i["severity"] in ("WARNING", "CRITICAL") for i in issues)

    # Build result
    result = {
        "state_file_found": state_file_found,
        "tracked_logs": len(logrotate_state),
        "large_logs": large_logs,
        "stale_logs": stale_logs,
        "issues": issues,
        "status": "warning" if has_issues else "healthy",
    }

    # Output
    output.emit(result)
    output.render(opts.format, "Logrotate Status Monitor", warn_only=getattr(opts, 'warn_only', False))

    status = "warning" if has_issues else "healthy"
    output.set_summary(f"large={len(large_logs)}, stale={len(stale_logs)}, status={status}")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
