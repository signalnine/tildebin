#!/usr/bin/env python3
# boxctl:
#   category: baremetal/systemd
#   tags: [health, systemd, restart-loop, stability]
#   requires: [systemctl, journalctl]
#   brief: Detect systemd services stuck in restart loops

"""
Detect systemd services stuck in restart loops.

Monitors systemd services for excessive restart activity that may indicate
a service is crashing repeatedly. This is a common issue in production
environments where a misconfigured or broken service enters a restart loop.

Returns exit code 1 if any services are detected in restart loops.
"""

import argparse
from datetime import datetime, timedelta
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_failed_services(context: Context) -> list[str]:
    """Get list of currently failed services."""
    result = context.run(
        ["systemctl", "list-units", "--state=failed", "--no-pager", "--no-legend", "--plain"],
        check=False,
    )

    failed = []
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            parts = line.split()
            if parts:
                failed.append(parts[0])
    return failed


def get_activating_services(context: Context) -> list[str]:
    """Get list of services in activating/reloading state."""
    result = context.run(
        ["systemctl", "list-units", "--type=service", "--state=activating,reloading",
         "--no-pager", "--no-legend", "--plain"],
        check=False,
    )

    services = []
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            parts = line.split()
            if parts:
                services.append(parts[0])
    return services


def get_all_services(context: Context) -> list[str]:
    """Get list of all loaded services."""
    result = context.run(
        ["systemctl", "list-units", "--type=service", "--all",
         "--no-pager", "--no-legend", "--plain"],
        check=False,
    )

    services = []
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            parts = line.split()
            if parts and parts[0].endswith(".service"):
                services.append(parts[0])
    return services


def get_service_restart_count(
    service_name: str,
    since_hours: float,
    context: Context,
) -> int:
    """Count service starts in the given time window using journalctl."""
    since_time = datetime.now() - timedelta(hours=since_hours)
    since_str = since_time.strftime("%Y-%m-%d %H:%M:%S")

    result = context.run(
        ["journalctl", "-u", service_name, "--since", since_str,
         "--no-pager", "-o", "short-unix", "--grep=Started"],
        check=False,
    )

    if result.returncode != 0:
        return 0

    # Count non-empty lines
    lines = [line for line in result.stdout.strip().split("\n") if line.strip()]
    return len(lines)


def get_service_status(service_name: str, context: Context) -> dict[str, str]:
    """Get current status of a service."""
    result = context.run(
        ["systemctl", "show", service_name,
         "--property=ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestamp,Result"],
        check=False,
    )

    status = {}
    for line in result.stdout.strip().split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            status[key] = value
    return status


def detect_restart_loops(
    hours: float,
    threshold: int,
    check_all: bool,
    context: Context,
) -> list[dict[str, Any]]:
    """Detect services that are in restart loops."""
    loops = []

    if check_all:
        services = get_all_services(context)
    else:
        # Start with failed services, they're most likely to be looping
        services = get_failed_services(context)
        # Also check activating services
        activating = get_activating_services(context)
        for svc in activating:
            if svc not in services:
                services.append(svc)

    for service in services:
        restart_count = get_service_restart_count(service, hours, context)

        if restart_count >= threshold:
            status = get_service_status(service, context)

            n_restarts = 0
            try:
                n_restarts = int(status.get("NRestarts", "0"))
            except ValueError:
                pass

            loops.append({
                "service": service,
                "restarts_in_window": restart_count,
                "total_restarts": n_restarts,
                "hours_checked": hours,
                "active_state": status.get("ActiveState", "unknown"),
                "sub_state": status.get("SubState", "unknown"),
                "result": status.get("Result", "unknown"),
                "main_pid": status.get("MainPID", "0"),
                "last_start": status.get("ExecMainStartTimestamp", "unknown"),
            })

    # Sort by restart count descending
    loops.sort(key=lambda x: x["restarts_in_window"], reverse=True)
    return loops


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no loops detected, 1 = loops found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Detect systemd services stuck in restart loops"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument(
        "-H", "--hours",
        type=float,
        default=1,
        help="Time window in hours to check (default: 1)",
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=3,
        help="Minimum restarts to consider a loop (default: 3)",
    )
    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Check all services, not just failed/activating",
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if restart loops detected",
    )
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.hours <= 0:
        output.error("Hours must be a positive number")
        return 2

    if opts.threshold <= 0:
        output.error("Threshold must be a positive number")
        return 2

    # Check for required tools
    if not context.check_tool("systemctl"):
        output.error("systemctl not found. This system may not use systemd.")
        return 2

    if not context.check_tool("journalctl"):
        output.error("journalctl not found. This system may not use systemd.")
        return 2

    # Detect restart loops
    loops = detect_restart_loops(
        hours=opts.hours,
        threshold=opts.threshold,
        check_all=opts.all,
        context=context,
    )

    # Calculate severity
    critical_count = sum(1 for loop in loops if loop["restarts_in_window"] >= opts.threshold * 2)
    warning_count = len(loops) - critical_count

    # Add warnings/errors for each loop
    for loop in loops:
        severity = "CRITICAL" if loop["restarts_in_window"] >= opts.threshold * 2 else "WARNING"
        msg = f"{loop['service']}: {loop['restarts_in_window']} restarts in {opts.hours}h"
        if severity == "CRITICAL":
            output.error(msg)
        else:
            output.warning(msg)

    # Emit structured data
    output.emit({
        "services": loops,
        "summary": {
            "time_window_hours": opts.hours,
            "restart_threshold": opts.threshold,
            "services_in_loop": len(loops),
            "critical_count": critical_count,
            "warning_count": warning_count,
        },
    })

    # Set summary
    if loops:
        output.set_summary(f"{len(loops)} services in restart loop ({critical_count} critical)")
    else:
        output.set_summary("No restart loops detected")

    return 1 if loops else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
