#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, storage, capacity, forecasting]
#   brief: Forecast disk space exhaustion based on usage levels

"""
Forecast disk space exhaustion based on current usage levels.

Analyzes current filesystem usage to identify filesystems approaching
critical capacity. Provides usage percentage analysis and identifies
filesystems that need attention.

Exit codes:
    0: All filesystems healthy (below warning threshold)
    1: Warnings detected (high usage or approaching capacity)
    2: Usage error or unable to read filesystem data
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable size."""
    for unit, divisor in [("TB", 1024**4), ("GB", 1024**3),
                          ("MB", 1024**2), ("KB", 1024)]:
        if bytes_val >= divisor:
            return f"{bytes_val / divisor:.1f}{unit}"
    return f"{bytes_val}B"


def parse_df_output(content: str) -> list[dict]:
    """
    Parse df output.

    Args:
        content: Output from df -B1 --output=source,target,size,used,avail,pcent

    Returns:
        List of filesystem dicts
    """
    filesystems = []
    lines = content.strip().split("\n")

    for line in lines[1:]:  # Skip header
        parts = line.split()
        if len(parts) < 6:
            continue

        source = parts[0]
        # Skip pseudo filesystems
        if source.startswith(("tmpfs", "devtmpfs", "overlay", "shm", "none")):
            continue
        if not source.startswith("/"):
            continue

        try:
            mount = parts[1]
            size_bytes = int(parts[2])
            used_bytes = int(parts[3])
            avail_bytes = int(parts[4])
            use_pct = float(parts[5].rstrip("%"))

            # Skip tiny filesystems (< 100MB)
            if size_bytes < 100 * 1024 * 1024:
                continue

            filesystems.append({
                "filesystem": source,
                "mount": mount,
                "size_bytes": size_bytes,
                "used_bytes": used_bytes,
                "avail_bytes": avail_bytes,
                "use_pct": use_pct,
            })
        except (ValueError, IndexError):
            continue

    return filesystems


def analyze_filesystems(
    filesystems: list[dict],
    warn_pct: float,
    crit_pct: float,
) -> list[dict]:
    """
    Analyze filesystems and identify those at risk.

    Args:
        filesystems: List of filesystem dicts
        warn_pct: Warning threshold percentage
        crit_pct: Critical threshold percentage

    Returns:
        List of analysis results
    """
    results = []

    for fs in filesystems:
        use_pct = fs["use_pct"]

        # Determine severity
        if use_pct >= crit_pct:
            severity = "CRITICAL"
        elif use_pct >= warn_pct:
            severity = "WARNING"
        else:
            severity = "OK"

        results.append({
            "filesystem": fs["filesystem"],
            "mount": fs["mount"],
            "size_bytes": fs["size_bytes"],
            "used_bytes": fs["used_bytes"],
            "avail_bytes": fs["avail_bytes"],
            "use_pct": use_pct,
            "severity": severity,
            "size_human": format_bytes(fs["size_bytes"]),
            "avail_human": format_bytes(fs["avail_bytes"]),
        })

    # Sort by severity (CRITICAL first) then by use_pct descending
    severity_order = {"CRITICAL": 0, "WARNING": 1, "OK": 2}
    results.sort(key=lambda x: (severity_order[x["severity"]], -x["use_pct"]))

    return results


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Forecast disk space exhaustion based on usage"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )
    parser.add_argument(
        "--warn-pct",
        type=float,
        default=80.0,
        help="Warning threshold percentage (default: 80)"
    )
    parser.add_argument(
        "--crit-pct",
        type=float,
        default=95.0,
        help="Critical threshold percentage (default: 95)"
    )
    parser.add_argument(
        "--mount",
        help="Only analyze specific mount point"
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if not 0 < opts.warn_pct < opts.crit_pct <= 100:
        output.error("Invalid thresholds: warn-pct must be < crit-pct and both in 0-100")

        output.render(opts.format, "Forecast disk space exhaustion based on usage levels")
        return 2

    # Get filesystem usage via df command
    try:
        result = context.run(
            ["df", "-B1", "--output=source,target,size,used,avail,pcent"],
            check=False
        )
        if result.returncode != 0:
            output.error(f"df command failed: {result.stderr}")
            return 2
        df_output = result.stdout
    except Exception as e:
        output.error(f"Failed to run df: {e}")

        output.render(opts.format, "Forecast disk space exhaustion based on usage levels")
        return 2

    # Parse df output
    filesystems = parse_df_output(df_output)

    if not filesystems:
        output.error("No filesystems found")

        output.render(opts.format, "Forecast disk space exhaustion based on usage levels")
        return 2

    # Filter to specific mount if requested
    if opts.mount:
        filesystems = [fs for fs in filesystems if fs["mount"] == opts.mount]
        if not filesystems:
            output.error(f"Mount point '{opts.mount}' not found")
            return 2

    # Analyze filesystems
    results = analyze_filesystems(filesystems, opts.warn_pct, opts.crit_pct)

    # Build output
    has_critical = any(r["severity"] == "CRITICAL" for r in results)
    has_warning = any(r["severity"] == "WARNING" for r in results)

    # Filter for warn-only mode
    display_results = results
    if opts.warn_only:
        display_results = [r for r in results if r["severity"] != "OK"]

    # Emit data
    output_data = {
        "filesystems": display_results if opts.verbose else [
            {
                "mount": r["mount"],
                "use_pct": r["use_pct"],
                "avail_human": r["avail_human"],
                "severity": r["severity"],
            }
            for r in display_results
        ],
        "summary": {
            "total": len(results),
            "critical": sum(1 for r in results if r["severity"] == "CRITICAL"),
            "warning": sum(1 for r in results if r["severity"] == "WARNING"),
            "ok": sum(1 for r in results if r["severity"] == "OK"),
        }
    }
    output.emit(output_data)

    # Set summary
    critical_count = output_data["summary"]["critical"]
    warning_count = output_data["summary"]["warning"]
    ok_count = output_data["summary"]["ok"]
    output.set_summary(f"{ok_count} healthy, {warning_count} warning, {critical_count} critical")

    output.render(opts.format, "Forecast disk space exhaustion based on usage levels")

    return 1 if (has_critical or has_warning) else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
