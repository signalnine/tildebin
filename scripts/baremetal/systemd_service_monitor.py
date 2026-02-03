#!/usr/bin/env python3
# boxctl:
#   category: baremetal/systemd
#   tags: [health, systemd, services, monitoring]
#   requires: [systemctl]
#   brief: Monitor systemd service health and detect failed or degraded services

"""
Monitor systemd service health and detect failed or degraded services.

Checks for failed systemd units, system degraded state, and services
with excessive restart counts. Useful for proactive monitoring in
production baremetal environments.

Returns exit code 1 if any services have failures or warnings.
"""

import argparse
from datetime import datetime
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_system_state(context: Context) -> str:
    """Get overall system state (running, degraded, etc.)."""
    result = context.run(["systemctl", "is-system-running"])
    return result.stdout.strip()


def get_failed_units(context: Context) -> list[dict[str, str]]:
    """Get list of failed systemd units."""
    result = context.run(
        ["systemctl", "--failed", "--no-legend", "--no-pager"],
        check=False,
    )

    failed = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            failed.append({
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": " ".join(parts[4:]) if len(parts) > 4 else "",
            })

    return failed


def get_service_status(service_name: str, context: Context) -> dict[str, str]:
    """Get detailed status of a specific service."""
    result = context.run(
        ["systemctl", "show", service_name, "--no-pager"],
        check=False,
    )

    status = {}
    for line in result.stdout.split("\n"):
        if "=" in line:
            key, _, value = line.partition("=")
            status[key] = value

    return status


def get_all_services(context: Context, state_filter: str | None = None) -> list[dict[str, str]]:
    """Get list of all services with their states."""
    cmd = ["systemctl", "list-units", "--type=service", "--no-legend", "--no-pager", "--all"]
    if state_filter:
        cmd.append(f"--state={state_filter}")

    result = context.run(cmd, check=False)

    services = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 4:
            services.append({
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": " ".join(parts[4:]) if len(parts) > 4 else "",
            })

    return services


def get_service_restart_count(service_name: str, context: Context) -> int:
    """Get restart count for a service."""
    status = get_service_status(service_name, context)
    restart_count = status.get("NRestarts", "0")
    try:
        return int(restart_count)
    except ValueError:
        return 0


def check_critical_services(critical_list: list[str], context: Context) -> list[dict[str, Any]]:
    """Check if critical services are running."""
    issues = []

    for service in critical_list:
        # Ensure service name ends with .service
        service_name = service if service.endswith(".service") else f"{service}.service"

        result = context.run(
            ["systemctl", "is-active", service_name],
            check=False,
        )
        state = result.stdout.strip()

        if state != "active":
            status = get_service_status(service_name, context)
            load_state = status.get("LoadState", "unknown")

            issues.append({
                "service": service_name,
                "state": state,
                "load_state": load_state,
                "issue": "Critical service not active",
            })

    return issues


def get_services_with_high_restarts(threshold: int, context: Context) -> list[dict[str, Any]]:
    """Find services that have restarted multiple times."""
    services = get_all_services(context)
    restarted = []

    for svc in services:
        unit = svc["unit"]
        restart_count = get_service_restart_count(unit, context)

        if restart_count >= threshold:
            restarted.append({
                "unit": unit,
                "restart_count": restart_count,
                "active": svc["active"],
                "sub": svc["sub"],
            })

    return restarted


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
        description="Monitor systemd service health and detect failures"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument(
        "--critical",
        metavar="SERVICES",
        help="Comma-separated list of critical services to check",
    )
    parser.add_argument(
        "--restart-threshold",
        type=int,
        default=3,
        metavar="N",
        help="Warn if service has restarted N+ times (default: 3)",
    )
    parser.add_argument("--show-masked", action="store_true", help="Include masked services")
    opts = parser.parse_args(args)

    # Check for systemctl
    if not context.check_tool("systemctl"):
        output.error("systemctl not found. This system may not use systemd.")

        output.render(opts.format, "Monitor systemd service health and detect failed or degraded services")
        return 2

    has_issues = False

    # Get system state
    system_state = get_system_state(context)
    if system_state not in ["running", "initializing", "starting"]:
        has_issues = True

    # Get failed units
    failed_units = get_failed_units(context)
    if failed_units:
        has_issues = True
        for unit in failed_units:
            output.warning(f"Failed: {unit['unit']} ({unit['sub']})")

    # Check critical services
    critical_issues = []
    if opts.critical:
        critical_list = [s.strip() for s in opts.critical.split(",")]
        critical_issues = check_critical_services(critical_list, context)
        if critical_issues:
            has_issues = True
            for issue in critical_issues:
                output.error(f"Critical service {issue['service']} is {issue['state']}")

    # Check for services with high restart counts
    restart_warnings = get_services_with_high_restarts(opts.restart_threshold, context)
    if restart_warnings:
        has_issues = True
        for svc in restart_warnings:
            output.warning(f"{svc['unit']} restarted {svc['restart_count']} times")

    # Get masked services if requested
    masked_services = []
    if opts.show_masked:
        all_services = get_all_services(context)
        masked_services = [s for s in all_services if s["load"] == "masked"]

    # Emit structured data
    output.emit({
        "system_state": system_state,
        "failed_units": failed_units,
        "critical_issues": critical_issues,
        "restart_warnings": restart_warnings,
        "masked_services": masked_services,
        "summary": {
            "failed_count": len(failed_units),
            "critical_issues_count": len(critical_issues),
            "restart_warnings_count": len(restart_warnings),
            "has_issues": has_issues,
        },
        "timestamp": datetime.now().isoformat(),
    })

    # Set summary
    if has_issues:
        total_issues = len(failed_units) + len(critical_issues) + len(restart_warnings)
        output.set_summary(f"{total_issues} service issues detected")
    else:
        output.set_summary("All services healthy")

    output.render(opts.format, "Monitor systemd service health and detect failed or degraded services")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
