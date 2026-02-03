#!/usr/bin/env python3
# boxctl:
#   category: baremetal/systemd
#   tags: [health, systemd, journal, logs, analysis]
#   requires: [journalctl, systemctl]
#   brief: Analyze systemd journal for service failures and error patterns

"""
Analyze systemd journal for service failures, restart loops, and error patterns.

Parses systemd journal logs to detect application-level issues including:
- Service failures and crashes
- OOM kills at the service level
- Segfaults and core dumps
- Authentication failures
- Disk space issues
- Service timeouts

Returns exit code 1 if critical errors or warnings are found.
"""

import argparse
import re
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Patterns for detecting issues in journal entries
ISSUE_PATTERNS = {
    "service_failure": [
        (r"(\S+\.service): (Failed|failed) with result", "CRITICAL"),
        (r"(\S+\.service): Main process exited, code=(exited|killed|dumped)", "CRITICAL"),
        (r"Failed to start (.+)\.", "CRITICAL"),
        (r"(\S+\.service): Start request repeated too quickly", "WARNING"),
    ],
    "restart_loop": [
        (r"(\S+\.service): Scheduled restart job", "WARNING"),
        (r"(\S+\.service): Service RestartSec=.*configured", "WARNING"),
        (r"(\S+\.service): Triggering OnFailure=", "WARNING"),
    ],
    "oom_kill": [
        (r"Out of memory: Killed process \d+ \((.+)\)", "CRITICAL"),
        (r"oom-kill:.*task=(\S+)", "CRITICAL"),
        (r"Memory cgroup out of memory: Killed process", "CRITICAL"),
    ],
    "segfault": [
        (r"(\S+)\[\d+\]: segfault at", "CRITICAL"),
        (r"(\S+)\[\d+\] (trap|general protection)", "CRITICAL"),
        (r"Process \d+ \((.+)\) dumped core", "CRITICAL"),
    ],
    "auth_failure": [
        (r"pam_unix.*authentication failure", "WARNING"),
        (r"Failed password for .* from", "WARNING"),
        (r"Connection closed by .* \[preauth\]", "WARNING"),
    ],
    "disk_space": [
        (r"No space left on device", "CRITICAL"),
        (r"Disk quota exceeded", "WARNING"),
        (r"Journal file .* is truncated, ignoring", "WARNING"),
    ],
    "timeout": [
        (r"(\S+\.service): State .* timed out", "CRITICAL"),
        (r"(\S+\.service): Job .* timed out", "CRITICAL"),
        (r"A stop job is running for", "WARNING"),
    ],
    "dependency": [
        (r"Dependency failed for (.+)\.", "WARNING"),
        (r"(\S+\.service): Bound to unit .* that isn.*t active", "WARNING"),
        (r"Job .* failed with result .dependency.", "WARNING"),
    ],
}


def get_failed_units(context: Context) -> list[str]:
    """Get list of currently failed systemd units."""
    result = context.run(
        ["systemctl", "list-units", "--state=failed", "--no-legend", "--plain"],
        check=False,
    )

    units = []
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            parts = line.split()
            if parts:
                units.append(parts[0])
    return units


def get_restart_counts(since: str, context: Context) -> dict[str, int]:
    """Count service restarts in the given time period."""
    result = context.run(
        ["journalctl", "-p", "6", "--since", f"-{since}", "--no-pager", "-o", "short"],
        check=False,
    )

    restart_counts: dict[str, int] = defaultdict(int)
    for line in result.stdout.split("\n"):
        if "Started " in line or "Starting " in line:
            match = re.search(r"Started (.+)\.?$|Starting (.+)\.\.\.", line)
            if match:
                service = match.group(1) or match.group(2)
                if service:
                    restart_counts[service.strip(".")] += 1

    return dict(restart_counts)


def analyze_journal_entries(
    since: str,
    priority: str,
    unit: str | None,
    context: Context,
) -> dict[str, list[dict[str, Any]]]:
    """Analyze journal entries for issues."""
    findings: dict[str, list[dict[str, Any]]] = defaultdict(list)

    # Build journalctl command
    cmd = ["journalctl", "--no-pager", "-o", "short-iso", "--since", f"-{since}"]

    if priority:
        priority_map = {
            "emerg": 0, "alert": 1, "crit": 2, "err": 3,
            "warning": 4, "notice": 5, "info": 6, "debug": 7
        }
        priority_num = priority_map.get(priority.lower(), 4)
        cmd.extend(["-p", str(priority_num)])

    if unit:
        cmd.extend(["-u", unit])

    result = context.run(cmd, check=False)

    # Analyze each line
    for line in result.stdout.split("\n"):
        if not line.strip():
            continue

        # Check against each pattern category
        for category, patterns in ISSUE_PATTERNS.items():
            for pattern, severity in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    findings[category].append({
                        "severity": severity,
                        "message": line.strip(),
                        "match": match.group(0),
                        "captured": match.groups() if match.groups() else None,
                    })
                    break  # Only match first pattern per line per category

    return dict(findings)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze systemd journal for service failures and error patterns"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full messages")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument(
        "--since",
        default="24h",
        help="Time period to analyze (e.g., 1h, 24h, 7d) (default: 24h)",
    )
    parser.add_argument(
        "-u", "--unit",
        help="Only analyze specific systemd unit",
    )
    parser.add_argument(
        "-p", "--priority",
        choices=["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
        default="warning",
        help="Minimum priority level (default: warning)",
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show if issues found",
    )
    opts = parser.parse_args(args)

    # Check for required tools
    if not context.check_tool("journalctl"):
        output.error("journalctl not found. This system may not use systemd.")

        output.render(opts.format, "Analyze systemd journal for service failures and error patterns")
        return 2

    if not context.check_tool("systemctl"):
        output.error("systemctl not found. This system may not use systemd.")

        output.render(opts.format, "Analyze systemd journal for service failures and error patterns")
        return 2

    # Gather data
    failed_units = get_failed_units(context)
    restart_counts = get_restart_counts(opts.since, context)
    findings = analyze_journal_entries(
        since=opts.since,
        priority=opts.priority,
        unit=opts.unit,
        context=context,
    )

    # Calculate totals
    total_issues = sum(len(issues) for issues in findings.values())
    critical_count = sum(
        1 for issues in findings.values()
        for issue in issues if issue["severity"] == "CRITICAL"
    )
    warning_count = sum(
        1 for issues in findings.values()
        for issue in issues if issue["severity"] == "WARNING"
    )

    # Services with high restart counts (potential issues)
    high_restart_services = {k: v for k, v in restart_counts.items() if v >= 3}

    # Add warnings/errors
    for unit in failed_units:
        output.error(f"Failed unit: {unit}")

    for category, issues in findings.items():
        for issue in issues:
            if issue["severity"] == "CRITICAL":
                output.error(f"{category}: {issue['match']}")
            else:
                output.warning(f"{category}: {issue['match']}")

    for service, count in high_restart_services.items():
        if count >= 10:
            output.error(f"High restart count: {service} ({count} restarts)")
        else:
            output.warning(f"Multiple restarts: {service} ({count} restarts)")

    # Emit structured data
    output.emit({
        "summary": {
            "failed_units_count": len(failed_units),
            "total_categories": len(findings),
            "total_issues": total_issues,
            "critical_count": critical_count,
            "warning_count": warning_count,
        },
        "failed_units": failed_units,
        "high_restart_services": high_restart_services,
        "findings": {
            category: [
                {"severity": i["severity"], "message": i["message"]}
                for i in issues
            ]
            for category, issues in findings.items()
        },
    })

    # Set summary
    has_critical = (
        len(failed_units) > 0 or
        any(i["severity"] == "CRITICAL" for issues in findings.values() for i in issues)
    )
    has_warnings = (
        any(v >= 10 for v in restart_counts.values()) or
        any(i["severity"] == "WARNING" for issues in findings.values() for i in issues)
    )

    if has_critical:
        output.set_summary(f"{critical_count} critical issues, {warning_count} warnings")
    elif has_warnings:
        output.set_summary(f"{warning_count} warnings found")
    else:
        output.set_summary("No journal issues found")

    output.render(opts.format, "Analyze systemd journal for service failures and error patterns")

    return 1 if (has_critical or has_warnings) else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
