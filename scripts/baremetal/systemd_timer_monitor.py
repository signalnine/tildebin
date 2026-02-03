#!/usr/bin/env python3
# boxctl:
#   category: baremetal/systemd
#   tags: [health, systemd, timers, scheduled-tasks]
#   requires: [systemctl]
#   brief: Monitor systemd timer health and identify missed or failed timers

"""
Monitor systemd timer health and identify missed or failed timers.

Checks for failed or inactive timers, timers that haven't run recently,
and associated service unit failures. Useful for ensuring scheduled tasks
like backups and log rotation are running on schedule.

Returns exit code 1 if any timers have issues.
"""

import argparse
import re
from datetime import datetime, timedelta
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_time_delta(time_str: str) -> timedelta | None:
    """Parse time string like '24h', '7d', '30m' into timedelta."""
    if not time_str:
        return None

    match = re.match(r"^(\d+)([smhdw])$", time_str.lower())
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    units = {
        "s": timedelta(seconds=value),
        "m": timedelta(minutes=value),
        "h": timedelta(hours=value),
        "d": timedelta(days=value),
        "w": timedelta(weeks=value),
    }

    return units.get(unit)


def get_timers(context: Context) -> list[dict[str, str]]:
    """Get list of all systemd timers."""
    result = context.run(
        ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"],
        check=False,
    )

    timers = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        # Find the .timer unit and .service unit
        timer_unit = None
        service_unit = None
        for part in parts:
            if part.endswith(".timer"):
                timer_unit = part
            elif part.endswith(".service"):
                service_unit = part

        if not timer_unit:
            continue

        timers.append({
            "name": timer_unit,
            "activates": service_unit or timer_unit.replace(".timer", ".service"),
        })

    return timers


def get_timer_details(timer_name: str, context: Context) -> dict[str, str]:
    """Get detailed information about a timer unit."""
    result = context.run(
        ["systemctl", "show", timer_name, "--no-pager"],
        check=False,
    )

    details = {}
    for line in result.stdout.strip().split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            details[key] = value

    return details


def get_service_status(service_name: str, context: Context) -> dict[str, str]:
    """Get status of the service activated by the timer."""
    result = context.run(
        ["systemctl", "show", service_name, "--no-pager"],
        check=False,
    )

    details = {}
    for line in result.stdout.strip().split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            details[key] = value

    return details


def analyze_timer(
    timer: dict[str, str],
    context: Context,
    max_age: timedelta | None = None,
) -> dict[str, Any]:
    """Analyze a timer for health issues."""
    timer_details = get_timer_details(timer["name"], context)
    service_details = get_service_status(timer["activates"], context)

    now = datetime.now()

    # Parse timestamps from microseconds
    last_trigger = None
    last_trigger_str = timer_details.get("LastTriggerUSec", "")
    if last_trigger_str and last_trigger_str != "0":
        try:
            usec = int(last_trigger_str)
            if usec > 0:
                last_trigger = datetime.fromtimestamp(usec / 1_000_000)
        except (ValueError, OSError):
            pass

    next_elapse = None
    next_elapse_str = timer_details.get("NextElapseUSecRealtime", "")
    if next_elapse_str and next_elapse_str != "0":
        try:
            usec = int(next_elapse_str)
            if usec > 0:
                next_elapse = datetime.fromtimestamp(usec / 1_000_000)
        except (ValueError, OSError):
            pass

    # Determine issues
    issues = []
    severity = "OK"

    timer_active = timer_details.get("ActiveState", "unknown")
    timer_sub = timer_details.get("SubState", "unknown")

    if timer_active == "failed":
        issues.append("Timer unit is failed")
        severity = "CRITICAL"
    elif timer_active == "inactive":
        issues.append("Timer is inactive/disabled")
        severity = "WARNING"

    # Check if timer has no next scheduled run
    if timer_active == "active" and not next_elapse:
        issues.append("No next scheduled run")
        if severity == "OK":
            severity = "WARNING"

    # Check if timer hasn't run in max_age period
    if max_age and last_trigger:
        age = now - last_trigger
        if age > max_age:
            hours = age.total_seconds() / 3600
            issues.append(f"Last run {hours:.1f}h ago (exceeds threshold)")
            if severity == "OK":
                severity = "WARNING"

    # Check associated service status
    service_result = service_details.get("Result", "success")
    if service_result not in ("success", ""):
        issues.append(f"Service last result: {service_result}")
        if service_result == "failed":
            severity = "CRITICAL"
        elif severity == "OK":
            severity = "WARNING"

    # Calculate time metrics
    time_since_last = None
    if last_trigger:
        time_since_last = now - last_trigger

    time_until_next = None
    if next_elapse and next_elapse > now:
        time_until_next = next_elapse - now

    return {
        "name": timer["name"],
        "activates": timer["activates"],
        "active_state": timer_active,
        "sub_state": timer_sub,
        "last_trigger": last_trigger.isoformat() if last_trigger else None,
        "next_elapse": next_elapse.isoformat() if next_elapse else None,
        "time_since_last_hours": round(time_since_last.total_seconds() / 3600, 2) if time_since_last else None,
        "time_until_next_hours": round(time_until_next.total_seconds() / 3600, 2) if time_until_next else None,
        "service_result": service_result,
        "issues": issues,
        "severity": severity,
        "description": timer_details.get("Description", ""),
    }


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
        description="Monitor systemd timer health and identify missed/failed timers"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show timers with issues")
    parser.add_argument(
        "--max-age",
        metavar="DURATION",
        help="Flag timers not run within duration (e.g., 24h, 7d)",
    )
    opts = parser.parse_args(args)

    # Check for systemctl
    if not context.check_tool("systemctl"):
        output.error("systemctl not found. This system may not use systemd.")

        output.render(opts.format, "Monitor systemd timer health and identify missed or failed timers")
        return 2

    # Validate max-age if provided
    max_age = None
    if opts.max_age:
        max_age = parse_time_delta(opts.max_age)
        if max_age is None:
            output.error(f"Invalid duration format: {opts.max_age}. Use format like: 30m, 24h, 7d")
            return 2

    # Get and analyze timers
    timers = get_timers(context)

    if not timers:
        output.emit({"timers": [], "summary": {"total": 0, "healthy": 0, "with_issues": 0}})
        output.set_summary("No systemd timers found")

        output.render(opts.format, "Monitor systemd timer health and identify missed or failed timers")
        return 0

    results = [analyze_timer(t, context, max_age=max_age) for t in timers]

    # Sort by severity
    severity_order = {"CRITICAL": 0, "WARNING": 1, "OK": 2}
    results.sort(key=lambda x: (severity_order.get(x["severity"], 3), x["name"]))

    # Calculate summary
    healthy = [r for r in results if r["severity"] == "OK"]
    problematic = [r for r in results if r["severity"] != "OK"]
    critical_count = sum(1 for r in results if r["severity"] == "CRITICAL")
    warning_count = sum(1 for r in results if r["severity"] == "WARNING")

    # Add warnings/errors for problematic timers
    for timer in problematic:
        if timer["severity"] == "CRITICAL":
            output.error(f"{timer['name']}: {', '.join(timer['issues'])}")
        else:
            output.warning(f"{timer['name']}: {', '.join(timer['issues'])}")

    # Emit structured data
    output.emit({
        "timers": results if not opts.warn_only else problematic,
        "summary": {
            "total": len(results),
            "healthy": len(healthy),
            "with_issues": len(problematic),
            "critical": critical_count,
            "warning": warning_count,
        },
    })

    # Set summary
    has_issues = len(problematic) > 0
    if has_issues:
        output.set_summary(f"{len(problematic)} timer issues ({critical_count} critical, {warning_count} warning)")
    else:
        output.set_summary(f"All {len(results)} timers healthy")


    output.render(opts.format, "Monitor systemd timer health and identify missed or failed timers")
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
