#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, hardware, time, rtc, clock, drift]
#   brief: Monitor hardware clock (RTC) drift against system time

"""
Monitor hardware clock (RTC) drift against system time on baremetal systems.

Compares the hardware clock (RTC/CMOS) to system time to detect drift that
could cause time jumps on reboot. Useful for detecting failing CMOS batteries,
clock crystal degradation, or misconfigured RTC settings.

Checks performed:
- Read RTC time via hwclock command
- Compare against system time
- Read RTC sysfs info for additional details
- Evaluate drift against configurable thresholds

Exit codes:
    0 - Success (hardware clock within acceptable drift)
    1 - Warning/Critical drift detected
    2 - Usage error or missing dependencies (hwclock not found or no permissions)
"""

import argparse
import re
from datetime import datetime
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


RTC_SYS_PATH = "/sys/class/rtc/rtc0"


def parse_hwclock_output(stdout: str, stderr: str = "") -> dict[str, Any]:
    """
    Parse hwclock --show --verbose output.

    Returns dict with parsed RTC data.
    """
    data = {
        "rtc_device": None,
        "rtc_time": None,
        "rtc_epoch": None,
        "drift_seconds": None,
        "is_utc": None,
        "raw_output": stdout,
    }

    combined = stdout + stderr

    # Parse RTC device
    match = re.search(r"Trying to open: (/dev/\S+)", combined)
    if match:
        data["rtc_device"] = match.group(1)

    # Parse if clock is UTC
    if "hardware clock is on utc" in combined.lower() or "kept in utc" in combined.lower():
        data["is_utc"] = True
    elif "local time" in combined.lower():
        data["is_utc"] = False

    # Parse hardware clock time
    match = re.search(r"Time read from Hardware Clock:\s*(.+)", combined)
    if match:
        data["rtc_time"] = match.group(1).strip()

    # Parse epoch time
    match = re.search(r"=\s*(\d+)\s+seconds since 1969", combined)
    if match:
        data["rtc_epoch"] = int(match.group(1))

    # Parse calculated drift
    match = re.search(
        r"Calculated Hardware Clock drift is\s+([-+]?[\d.]+)\s+seconds", combined
    )
    if match:
        data["drift_seconds"] = float(match.group(1))

    return data


def get_rtc_info(context: Context) -> dict[str, Any]:
    """
    Get additional RTC information from /sys/class/rtc/rtc0/ if available.
    """
    info = {}

    try:
        info["rtc_name"] = context.read_file(f"{RTC_SYS_PATH}/name").strip()
    except (FileNotFoundError, PermissionError):
        pass

    try:
        info["hctosys"] = context.read_file(f"{RTC_SYS_PATH}/hctosys").strip() == "1"
    except (FileNotFoundError, PermissionError):
        pass

    try:
        info["since_epoch"] = int(context.read_file(f"{RTC_SYS_PATH}/since_epoch").strip())
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    return info


def calculate_drift(hwclock_data: dict[str, Any]) -> float | None:
    """
    Calculate the drift between hardware clock and system time.

    Returns drift in seconds (positive = RTC ahead, negative = RTC behind).
    """
    if hwclock_data.get("drift_seconds") is not None:
        return hwclock_data["drift_seconds"]

    # Calculate from epoch if available
    if hwclock_data.get("rtc_epoch"):
        rtc_epoch = hwclock_data["rtc_epoch"]
        system_epoch = datetime.now().timestamp()
        return rtc_epoch - system_epoch

    return None


def assess_status(
    drift_seconds: float | None, warn_threshold: float, crit_threshold: float
) -> str:
    """
    Assess the drift status.

    Returns: 'OK', 'WARNING', 'CRITICAL', or 'UNKNOWN'
    """
    if drift_seconds is None:
        return "UNKNOWN"

    abs_drift = abs(drift_seconds)

    if abs_drift >= crit_threshold:
        return "CRITICAL"
    elif abs_drift >= warn_threshold:
        return "WARNING"
    else:
        return "OK"


def format_drift(seconds: float | None) -> str:
    """Format drift in human-readable form."""
    if seconds is None:
        return "unknown"

    abs_seconds = abs(seconds)
    direction = "ahead" if seconds > 0 else "behind"

    if abs_seconds < 0.001:
        return f"{abs_seconds * 1000000:.1f} microseconds {direction}"
    elif abs_seconds < 1:
        return f"{abs_seconds * 1000:.1f} milliseconds {direction}"
    elif abs_seconds < 60:
        return f"{abs_seconds:.2f} seconds {direction}"
    elif abs_seconds < 3600:
        return f"{abs_seconds / 60:.1f} minutes {direction}"
    else:
        return f"{abs_seconds / 3600:.1f} hours {direction}"


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor hardware clock (RTC) drift against system time"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed RTC information"
    )
    parser.add_argument(
        "--warn-threshold",
        type=float,
        default=5.0,
        help="Warning threshold for drift in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--crit-threshold",
        type=float,
        default=60.0,
        help="Critical threshold for drift in seconds (default: 60.0)",
    )
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn_threshold <= 0 or opts.crit_threshold <= 0:
        output.error("Thresholds must be positive numbers")

        output.render(opts.format, "Monitor hardware clock (RTC) drift against system time")
        return 2

    if opts.warn_threshold >= opts.crit_threshold:
        output.error("Warning threshold must be less than critical threshold")

        output.render(opts.format, "Monitor hardware clock (RTC) drift against system time")
        return 2

    # Check if hwclock is available
    if not context.check_tool("hwclock"):
        output.error("hwclock command not found. Install util-linux package.")

        output.render(opts.format, "Monitor hardware clock (RTC) drift against system time")
        return 2

    # Run hwclock to get hardware clock time
    try:
        result = context.run(["hwclock", "--show", "--verbose"])
        if result.returncode != 0:
            stderr_lower = result.stderr.lower()
            if "permission denied" in stderr_lower or "operation not permitted" in stderr_lower:
                output.error("Permission denied reading hardware clock. Run as root.")
                return 2
            output.error(f"hwclock failed: {result.stderr}")
            return 2

        hwclock_data = parse_hwclock_output(result.stdout, result.stderr)
    except Exception as e:
        output.error(f"Failed to run hwclock: {e}")

        output.render(opts.format, "Monitor hardware clock (RTC) drift against system time")
        return 2

    # Get additional RTC info from sysfs
    rtc_info = get_rtc_info(context)

    # Calculate drift
    drift = calculate_drift(hwclock_data)

    # Assess status
    status = assess_status(drift, opts.warn_threshold, opts.crit_threshold)

    # Build output data
    output_data = {
        "status": status,
        "drift_seconds": drift,
        "drift_human": format_drift(drift),
        "rtc_device": hwclock_data.get("rtc_device"),
        "rtc_time": hwclock_data.get("rtc_time"),
        "is_utc": hwclock_data.get("is_utc"),
        "thresholds": {
            "warning": opts.warn_threshold,
            "critical": opts.crit_threshold,
        },
    }

    if rtc_info:
        output_data["rtc_info"] = rtc_info

    if opts.verbose:
        output_data["rtc_epoch"] = hwclock_data.get("rtc_epoch")

    output.emit(output_data)

    # Set summary
    if status == "CRITICAL":
        output.set_summary(f"CRITICAL: RTC drift {format_drift(drift)}")

        output.render(opts.format, "Monitor hardware clock (RTC) drift against system time")
        return 1
    elif status == "WARNING":
        output.set_summary(f"WARNING: RTC drift {format_drift(drift)}")

        output.render(opts.format, "Monitor hardware clock (RTC) drift against system time")
        return 1
    elif status == "UNKNOWN":
        output.set_summary("Could not determine RTC drift")

        output.render(opts.format, "Monitor hardware clock (RTC) drift against system time")
        return 1
    else:
        output.set_summary(f"RTC drift {format_drift(drift)} (within threshold)")

        output.render(opts.format, "Monitor hardware clock (RTC) drift against system time")
        return 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
