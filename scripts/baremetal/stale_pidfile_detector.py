#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [process, pidfile, daemon, service, cleanup]
#   brief: Detect stale PID files that reference non-existent processes

"""
Detect stale PID files that reference non-existent processes.

PID files are commonly used by daemons to record their process ID. When services
crash or are killed improperly, these files can become stale (referencing PIDs
that no longer exist or belong to different processes). This causes issues with
service startup and monitoring.

Common PID file locations:
  /var/run/*.pid
  /run/*.pid
  /var/lock/*.pid
  /tmp/*.pid

Exit codes:
    0: No stale PID files detected
    1: Stale PID files found
    2: Usage error or missing permissions
"""

import argparse
import os
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Default directories to search for PID files
DEFAULT_DIRECTORIES = ["/var/run", "/run", "/var/lock", "/tmp"]


def read_pidfile(content: str) -> int | None:
    """Parse PID file content. Returns PID as int or None if invalid."""
    content = content.strip()
    if not content:
        return None

    # Handle multi-line PID files (some include additional info)
    first_line = content.split("\n")[0].strip()
    try:
        pid = int(first_line)
        return pid if pid > 0 else None
    except ValueError:
        return None


def format_age(seconds: int) -> str:
    """Format seconds into human-readable age string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m"
    elif seconds < 86400:
        return f"{seconds // 3600}h"
    else:
        return f"{seconds // 86400}d"


def analyze_pidfile(
    filepath: str,
    context: Context,
    check_name: bool = False,
    processes: dict[int, str] | None = None,
) -> dict[str, Any]:
    """
    Analyze a PID file and return its status.

    Returns dict with:
        - filepath: path to the PID file
        - pid: the PID from the file (or None)
        - status: 'valid', 'stale', 'invalid', or 'mismatch'
        - process_name: name of current process (if valid)
        - expected_name: name expected based on filename
        - age_seconds: age of the PID file
        - details: human-readable status details
    """
    result = {
        "filepath": filepath,
        "pid": None,
        "status": "invalid",
        "process_name": None,
        "expected_name": None,
        "age_seconds": 0,
        "details": "",
    }

    # Try to determine expected service name from filename
    basename = os.path.basename(filepath)
    if basename.endswith(".pid"):
        result["expected_name"] = basename[:-4]
    elif basename == "pid":
        result["expected_name"] = os.path.basename(os.path.dirname(filepath))

    # Read the PID file
    try:
        content = context.read_file(filepath)
    except (FileNotFoundError, IOError):
        result["details"] = "Cannot read PID file"
        return result

    pid = read_pidfile(content)
    if pid is None:
        result["details"] = "Cannot parse PID file"
        return result

    result["pid"] = pid

    # Check if process exists
    if processes is not None:
        # Use mocked process data
        if pid not in processes:
            result["status"] = "stale"
            result["details"] = f"Process {pid} does not exist"
            return result
        process_name = processes.get(pid, "")
    else:
        # Real process check
        try:
            comm_path = f"/proc/{pid}/comm"
            process_name = context.read_file(comm_path).strip()
        except (FileNotFoundError, IOError):
            result["status"] = "stale"
            result["details"] = f"Process {pid} does not exist"
            return result

    result["process_name"] = process_name

    # Check for name mismatch if requested
    if check_name and result["expected_name"] and process_name:
        expected_lower = result["expected_name"].lower()
        actual_lower = process_name.lower()

        if expected_lower not in actual_lower and actual_lower not in expected_lower:
            result["status"] = "mismatch"
            result["details"] = f'PID {pid} belongs to "{process_name}" not "{result["expected_name"]}"'
            return result

    result["status"] = "valid"
    result["details"] = f"Process {pid} ({process_name or 'unknown'}) is running"
    return result


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no stale files, 1 = stale files found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Detect stale PID files that reference non-existent processes"
    )
    parser.add_argument(
        "-d", "--directories",
        nargs="+",
        default=DEFAULT_DIRECTORIES,
        metavar="DIR",
        help="Directories to search for PID files (default: /var/run /run /var/lock /tmp)",
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Search directories recursively",
    )
    parser.add_argument(
        "--check-name",
        action="store_true",
        help="Also report PID files where process name does not match filename",
    )
    parser.add_argument(
        "--min-age",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Only report stale files older than N seconds (default: 0)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show all PID files, not just stale ones",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings (stale or mismatched PID files)",
    )

    opts = parser.parse_args(args)

    # Find all PID files
    pidfiles = []
    for directory in opts.directories:
        if not context.file_exists(directory):
            continue

        pattern = "**/*.pid" if opts.recursive else "*.pid"
        try:
            matches = context.glob(pattern, root=directory)
            pidfiles.extend(matches)
        except (IOError, OSError):
            continue

    if not pidfiles:
        output_data = {
            "pidfiles": [],
            "summary": {
                "total": 0,
                "valid": 0,
                "stale": 0,
                "mismatch": 0,
                "invalid": 0,
            },
            "has_issues": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        output.emit(output_data)
        output.render(opts.format, "Stale PID File Detector", warn_only=getattr(opts, 'warn_only', False))
        return 0

    # Analyze each PID file
    results = []
    for pidfile in pidfiles:
        result = analyze_pidfile(pidfile, context, opts.check_name)
        results.append(result)

    # Categorize results
    stale = [r for r in results if r["status"] == "stale"]
    mismatch = [r for r in results if r["status"] == "mismatch"]
    invalid = [r for r in results if r["status"] == "invalid"]
    valid = [r for r in results if r["status"] == "valid"]

    has_issues = bool(stale or mismatch)

    # Build output data
    output_data = {
        "pidfiles": results if opts.verbose else [r for r in results if r["status"] != "valid"],
        "summary": {
            "total": len(results),
            "valid": len(valid),
            "stale": len(stale),
            "mismatch": len(mismatch),
            "invalid": len(invalid),
        },
        "has_issues": has_issues,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    output.emit(output_data)

    # Output results
    if opts.format == "table":
        print(f"{'PID FILE':<50} {'PID':<8} {'AGE':<8} {'STATUS':<20}")
        print("-" * 90)

        for r in results:
            if opts.warn_only and r["status"] == "valid":
                continue

            pid_str = str(r["pid"]) if r["pid"] else "-"
            age_str = format_age(r["age_seconds"])
            status_str = "OK" if r["status"] == "valid" else r["status"].upper()

            print(f"{r['filepath'][:50]:<50} {pid_str:<8} {age_str:<8} {status_str:<20}")

        print()
        print(f"Summary: {len(results)} total, {len(valid)} valid, {len(stale)} stale, "
              f"{len(mismatch)} mismatch, {len(invalid)} invalid")
    else:
        output.render(opts.format, "Stale PID File Detector", warn_only=getattr(opts, 'warn_only', False))

    # Set output summary
    if has_issues:
        output.set_summary(f"Found {len(stale)} stale and {len(mismatch)} mismatched PID files")
    else:
        output.set_summary(f"No stale PID files detected ({len(results)} checked)")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
