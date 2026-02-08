#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [health, watchdog, reliability, monitoring]
#   brief: Monitor hardware and software watchdog timer status

"""
Monitor hardware and software watchdog timer status on baremetal systems.

Watchdog timers are critical for production servers - they automatically reset
a hung system if the OS stops responding. This script checks:
- Hardware watchdog device availability and configuration
- Watchdog timeout settings
- Whether watchdog is actually armed and monitoring
- Daemon status

Exit codes:
    0: Watchdog properly configured and active
    1: Watchdog not configured, inactive, or misconfigured
    2: Usage error or missing dependency
"""

import argparse
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_watchdog_info(content: str) -> dict:
    """
    Parse watchdog device information.

    Expected format (one key:value per line):
    /dev/watchdog
    timeout:60
    identity:iTCO_wdt
    state:active
    nowayout:0

    Returns:
        dict: Watchdog device information
    """
    info = {
        "devices": [],
        "has_device": False,
        "has_daemon": False,
        "daemon_name": None,
        "daemon_status": None,
    }

    if not content.strip():
        return info

    current_device = {}
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("/dev/"):
            # Start of a new device
            if current_device:
                info["devices"].append(current_device)
            current_device = {"path": line}
            info["has_device"] = True
        elif ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()

            if key == "daemon":
                info["has_daemon"] = True
                info["daemon_name"] = value
            elif key == "daemon_status":
                info["daemon_status"] = value
            elif current_device:
                # Convert numeric values
                if key in ("timeout", "pretimeout", "min_timeout", "max_timeout"):
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                elif key == "nowayout":
                    value = value == "1" or value.lower() == "true"
                current_device[key] = value

    if current_device:
        info["devices"].append(current_device)

    return info


def analyze_watchdog_health(watchdog_info: dict) -> dict:
    """
    Analyze watchdog configuration and return health status.

    Args:
        watchdog_info: Parsed watchdog information

    Returns:
        dict: Analysis results with issues and warnings
    """
    issues = []
    warnings = []

    # Check for watchdog device
    if not watchdog_info["has_device"]:
        issues.append(
            {
                "type": "no_device",
                "message": "No watchdog device found (/dev/watchdog*)",
            }
        )
    else:
        has_active = False
        for dev in watchdog_info["devices"]:
            state = dev.get("state", "")
            if state == "active":
                has_active = True

            timeout = dev.get("timeout", 0)
            if isinstance(timeout, int) and timeout > 0:
                if timeout < 10:
                    warnings.append(
                        {
                            "type": "short_timeout",
                            "value": timeout,
                            "message": f"Watchdog timeout very short ({timeout}s) - risk of false resets",
                        }
                    )
                elif timeout > 300:
                    warnings.append(
                        {
                            "type": "long_timeout",
                            "value": timeout,
                            "message": f"Watchdog timeout very long ({timeout}s) - slow recovery",
                        }
                    )

        if not has_active and watchdog_info["devices"]:
            warnings.append(
                {
                    "type": "inactive",
                    "message": "Watchdog device exists but is not active",
                }
            )

    # Check for watchdog daemon
    if not watchdog_info["has_daemon"]:
        warnings.append(
            {
                "type": "no_daemon",
                "message": "No watchdog daemon detected (watchdog or systemd-watchdog)",
            }
        )
    elif watchdog_info["daemon_status"] and watchdog_info["daemon_status"] != "active":
        warnings.append(
            {
                "type": "daemon_inactive",
                "message": f"Watchdog daemon '{watchdog_info['daemon_name']}' is not active",
            }
        )

    status = "critical" if issues else ("warning" if warnings else "healthy")

    return {
        "issues": issues,
        "warnings": warnings,
        "status": status,
    }


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
        description="Monitor hardware and software watchdog timer status"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed information including recent events")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only produce output if there are warnings or issues",
    )
    opts = parser.parse_args(args)

    # Read watchdog info from simulated file
    # In real implementation, this would scan /dev/watchdog*, /sys/class/watchdog/*, etc.
    try:
        watchdog_content = context.read_file("/proc/watchdog_info")
        watchdog_info = parse_watchdog_info(watchdog_content)
    except (FileNotFoundError, IOError):
        watchdog_info = {
            "devices": [],
            "has_device": False,
            "has_daemon": False,
            "daemon_name": None,
            "daemon_status": None,
        }

    # Analyze health
    analysis = analyze_watchdog_health(watchdog_info)

    # Get uptime for context
    uptime_str = "unknown"
    try:
        uptime_content = context.read_file("/proc/uptime")
        uptime_seconds = float(uptime_content.split()[0])
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        uptime_str = f"{days}d {hours}h {minutes}m"
    except (FileNotFoundError, IOError, ValueError, IndexError):
        pass

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime": uptime_str,
        "devices": watchdog_info["devices"],
        "has_device": watchdog_info["has_device"],
        "has_daemon": watchdog_info["has_daemon"],
        "daemon_name": watchdog_info["daemon_name"],
        "daemon_status": watchdog_info["daemon_status"],
        "status": analysis["status"],
        "issues": analysis["issues"],
        "warnings": analysis["warnings"],
        "healthy": len(analysis["issues"]) == 0,
    }

    output.emit(result)

    # Check if we should output anything
    if opts.warn_only and analysis["status"] == "healthy":
        return 0

    # Output handling
    output.render(opts.format, "Watchdog Timer Status", warn_only=getattr(opts, 'warn_only', False))

    output.set_summary(f"status={analysis['status']}")

    return 1 if analysis["issues"] else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
