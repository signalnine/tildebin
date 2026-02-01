#!/usr/bin/env python3
# boxctl:
#   category: baremetal/boot
#   tags: [health, boot, journald, diagnostics]
#   requires: [journalctl]
#   privilege: optional
#   related: [grub_config_audit, efi_boot_audit, reboot_required_monitor]
#   brief: Analyze boot issues from journald logs

"""
Analyze boot issues from journald logs across recent system boots.

Examines journald logs to identify boot-related problems including:
- Kernel panics and oopses
- Emergency/rescue mode entries
- OOM kills during boot
- Failed systemd units during boot
- Hardware errors detected during boot
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Patterns for different issue types
KERNEL_PANIC_PATTERNS = [
    "kernel panic",
    "kernel bug",
    "oops:",
    "general protection fault",
    "unable to handle kernel",
    "bug: unable to handle",
    "call trace:",
    "rip:",
]

OOM_PATTERNS = [
    "out of memory:",
    "oom-kill:",
    "killed process",
    "memory cgroup out of memory",
    "invoked oom-killer",
]

EMERGENCY_PATTERNS = [
    "entering emergency mode",
    "emergency mode",
    "rescue.target",
    "emergency.target",
    "you are in emergency mode",
    "give root password for maintenance",
    "entering rescue mode",
]

FAILED_UNIT_KEYWORDS = ["failed", "start", "unit", "service", "job"]

HARDWARE_PATTERNS = [
    "hardware error",
    "machine check exception",
    "mce:",
    "acpi error",
    "acpi bios error",
    "dmar:",
    "iommu:",
    "ecc error",
    "edac",
    "pcie error",
    "aer:",
    "link down",
    "i/o error",
    "medium error",
    "ata",
    "smart error",
    "uncorrected error",
]


def get_boot_list(context: Context, num_boots: int = 5) -> list[dict[str, Any]]:
    """Get list of recent boots with their boot IDs."""
    result = context.run(
        ["journalctl", "--list-boots", "--no-pager"],
        check=False,
    )

    if result.returncode != 0:
        return []

    boots = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 4:
            try:
                offset = int(parts[0])
                boot_id = parts[1]
                timestamp_parts = parts[2:]
                timestamp_str = " ".join(timestamp_parts[:4]) if len(timestamp_parts) >= 4 else ""

                boots.append({
                    "offset": offset,
                    "boot_id": boot_id,
                    "timestamp": timestamp_str,
                })
            except (ValueError, IndexError):
                continue

    return boots[:num_boots]


def get_boot_logs(context: Context, boot_id: str, priority: str | None = None) -> list[str]:
    """Get logs for a specific boot."""
    cmd = ["journalctl", "-b", boot_id, "--no-pager", "-o", "short-iso"]

    if priority:
        cmd.extend(["-p", priority])

    result = context.run(cmd, check=False)

    if result.returncode != 0:
        return []

    return [line for line in result.stdout.strip().split("\n") if line.strip()]


def check_pattern_match(logs: list[str], patterns: list[str]) -> list[dict[str, Any]]:
    """Check logs for pattern matches."""
    issues = []
    for line in logs:
        line_lower = line.lower()
        for pattern in patterns:
            if pattern in line_lower:
                issues.append({
                    "message": line.strip()[:200],
                })
                break
    return issues


def check_failed_units(logs: list[str]) -> list[dict[str, Any]]:
    """Check for failed systemd units."""
    issues = []
    for line in logs:
        line_lower = line.lower()
        if "failed" in line_lower:
            has_unit_keyword = any(kw in line_lower for kw in ["start", "unit", "service", "job"])
            if has_unit_keyword:
                issues.append({"message": line.strip()[:200]})
    return issues


def analyze_boot(context: Context, boot_info: dict, checks: set[str]) -> dict[str, Any]:
    """Analyze a single boot for issues."""
    boot_id = boot_info["boot_id"]
    all_issues: list[dict[str, Any]] = []

    logs = get_boot_logs(context, boot_id)

    if "kernel" in checks:
        for issue in check_pattern_match(logs, KERNEL_PANIC_PATTERNS):
            issue["type"] = "kernel_error"
            issue["severity"] = "critical"
            all_issues.append(issue)

    if "oom" in checks:
        for issue in check_pattern_match(logs, OOM_PATTERNS):
            issue["type"] = "oom_kill"
            issue["severity"] = "warning"
            all_issues.append(issue)

    if "emergency" in checks:
        for issue in check_pattern_match(logs, EMERGENCY_PATTERNS):
            issue["type"] = "emergency_mode"
            issue["severity"] = "critical"
            all_issues.append(issue)

    if "units" in checks:
        for issue in check_failed_units(logs):
            issue["type"] = "failed_unit"
            issue["severity"] = "warning"
            all_issues.append(issue)

    if "hardware" in checks:
        for issue in check_pattern_match(logs, HARDWARE_PATTERNS):
            issue["type"] = "hardware_error"
            issue["severity"] = "warning"
            all_issues.append(issue)

    if "critical" in checks:
        critical_logs = get_boot_logs(context, boot_id, priority="2")
        for line in critical_logs:
            if line.strip():
                all_issues.append({
                    "type": "critical_log",
                    "severity": "critical",
                    "message": line.strip()[:200],
                })

    # Deduplicate issues based on message
    seen: set[str] = set()
    unique_issues = []
    for issue in all_issues:
        msg_key = issue["message"][:100]
        if msg_key not in seen:
            seen.add(msg_key)
            unique_issues.append(issue)

    return {
        "boot_id": boot_id,
        "offset": boot_info["offset"],
        "timestamp": boot_info["timestamp"],
        "issues": unique_issues,
        "critical_count": sum(1 for i in unique_issues if i["severity"] == "critical"),
        "warning_count": sum(1 for i in unique_issues if i["severity"] == "warning"),
    }


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
    parser = argparse.ArgumentParser(description="Analyze boot issues from journald logs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--boots", type=int, default=5, metavar="N", help="Number of boots to analyze")
    parser.add_argument("--current-only", action="store_true", help="Only analyze current boot")
    parser.add_argument(
        "--checks",
        metavar="CHECKS",
        default="kernel,oom,emergency,units,hardware",
        help="Comma-separated list of checks to run",
    )
    opts = parser.parse_args(args)

    # Check for journalctl
    if not context.check_tool("journalctl"):
        output.error("journalctl not found. This script requires systemd journald.")
        return 2

    # Parse checks
    available_checks = {"kernel", "oom", "emergency", "units", "hardware", "critical"}
    requested_checks = {c.strip() for c in opts.checks.split(",")}
    invalid_checks = requested_checks - available_checks
    if invalid_checks:
        output.error(f"Invalid checks: {', '.join(invalid_checks)}")
        return 2

    # Get boot list
    if opts.current_only:
        boots = [{"offset": 0, "boot_id": "0", "timestamp": "current"}]
    else:
        boots = get_boot_list(context, opts.boots)

    if not boots:
        output.error("No boots found in journal")
        return 2

    # Analyze each boot
    results = []
    for boot in boots:
        result = analyze_boot(context, boot, requested_checks)
        results.append(result)

    # Calculate totals
    total_issues = sum(len(r["issues"]) for r in results)
    total_critical = sum(r["critical_count"] for r in results)
    total_warnings = sum(r["warning_count"] for r in results)

    output.emit({
        "boots_analyzed": len(results),
        "total_issues": total_issues,
        "total_critical": total_critical,
        "total_warnings": total_warnings,
        "boots": results,
    })

    if total_issues > 0:
        output.set_summary(f"{total_issues} boot issues ({total_critical} critical, {total_warnings} warnings)")
    else:
        output.set_summary("No boot issues detected")

    return 1 if total_issues > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
