#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, hardware, time, ptp, precision, network]
#   brief: Monitor PTP (Precision Time Protocol) clock synchronization

"""
Monitor PTP (Precision Time Protocol) clock synchronization status.

Checks PTP hardware timestamps, clock offset, path delay, and synchronization
state for systems requiring high-precision time (HPC, trading, telecom).
Reads PTP device info from /sys/class/ptp and optionally integrates with
ptp4l/pmc commands for detailed sync status.

Exit codes:
    0 - PTP clocks synchronized and healthy
    1 - PTP synchronization issues detected (high offset, not locked)
    2 - Usage error or PTP not available
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


PTP_SYS_PATH = "/sys/class/ptp"


def get_ptp_devices(context: Context) -> list[dict[str, Any]]:
    """
    Get list of PTP hardware clock devices from sysfs.

    Returns list of dicts with device info.
    """
    devices = []

    if not context.file_exists(PTP_SYS_PATH):
        return devices

    device_paths = sorted(context.glob("ptp*", root=PTP_SYS_PATH))

    for ptp_path in device_paths:
        device_name = ptp_path.split("/")[-1]
        base = f"{PTP_SYS_PATH}/{device_name}"

        device_info = {
            "name": device_name,
            "path": f"/dev/{device_name}",
            "sysfs": base,
            "clock_name": None,
            "max_adj": None,
            "n_alarms": None,
            "n_pins": None,
            "pps": False,
        }

        # Read clock name
        try:
            device_info["clock_name"] = context.read_file(f"{base}/clock_name").strip()
        except (FileNotFoundError, PermissionError):
            pass

        # Read max adjustment
        try:
            device_info["max_adj"] = int(context.read_file(f"{base}/max_adjustment").strip())
        except (FileNotFoundError, PermissionError, ValueError):
            pass

        # Read number of alarms
        try:
            device_info["n_alarms"] = int(context.read_file(f"{base}/n_alarms").strip())
        except (FileNotFoundError, PermissionError, ValueError):
            pass

        # Read number of pins
        try:
            device_info["n_pins"] = int(context.read_file(f"{base}/n_pins").strip())
        except (FileNotFoundError, PermissionError, ValueError):
            pass

        # Check for PPS support
        try:
            device_info["pps"] = context.read_file(f"{base}/pps_available").strip() == "1"
        except (FileNotFoundError, PermissionError):
            pass

        devices.append(device_info)

    return devices


def get_ptp4l_status(context: Context) -> dict[str, Any] | None:
    """
    Get PTP synchronization status from ptp4l via pmc command.

    Returns dict with sync status or None if not available.
    """
    if not context.check_tool("pmc"):
        return None

    status = {
        "available": False,
        "state": None,
        "offset_ns": None,
        "mean_path_delay_ns": None,
        "master_id": None,
        "port_state": None,
    }

    # Try to get current data set
    try:
        result = context.run(["pmc", "-u", "-b", "0", "GET CURRENT_DATA_SET"], timeout=5)
        if result.returncode == 0 and result.stdout:
            status["available"] = True

            # Parse offset from master
            match = re.search(r"offsetFromMaster\s+(-?\d+)", result.stdout)
            if match:
                status["offset_ns"] = int(match.group(1))

            # Parse mean path delay
            match = re.search(r"meanPathDelay\s+(-?\d+)", result.stdout)
            if match:
                status["mean_path_delay_ns"] = int(match.group(1))
    except Exception:
        pass

    # Get port state
    try:
        result = context.run(["pmc", "-u", "-b", "0", "GET PORT_DATA_SET"], timeout=5)
        if result.returncode == 0 and result.stdout:
            match = re.search(r"portState\s+(\w+)", result.stdout)
            if match:
                status["port_state"] = match.group(1)
                status["available"] = True  # ptp4l is running if we got port state
    except Exception:
        pass

    # Get parent data set for master info
    try:
        result = context.run(["pmc", "-u", "-b", "0", "GET PARENT_DATA_SET"], timeout=5)
        if result.returncode == 0 and result.stdout:
            match = re.search(r"parentPortIdentity\s+([\da-f.:]+)", result.stdout, re.IGNORECASE)
            if match:
                status["master_id"] = match.group(1)
    except Exception:
        pass

    # Determine overall state
    if status["port_state"]:
        port_state_upper = status["port_state"].upper()
        if port_state_upper == "SLAVE":
            status["state"] = "synchronized"
        elif port_state_upper == "MASTER":
            status["state"] = "master"
        elif port_state_upper in ("LISTENING", "UNCALIBRATED"):
            status["state"] = "acquiring"
        else:
            status["state"] = status["port_state"].lower()

    return status


def check_ptp_health(
    devices: list[dict[str, Any]],
    ptp4l_status: dict[str, Any] | None,
    offset_threshold_ns: int,
    delay_threshold_ns: int,
) -> dict[str, Any]:
    """
    Perform comprehensive PTP health check.

    Returns dict with overall health status.
    """
    health = {
        "status": "unknown",
        "devices": devices,
        "ptp4l": ptp4l_status,
        "warnings": [],
        "issues": [],
    }

    if not devices:
        health["status"] = "no_ptp"
        health["issues"].append("No PTP hardware clock devices found")
        return health

    # Check ptp4l status
    if ptp4l_status and ptp4l_status.get("available"):
        if ptp4l_status["state"] == "synchronized":
            # Check offset
            if ptp4l_status["offset_ns"] is not None:
                offset_abs = abs(ptp4l_status["offset_ns"])
                if offset_abs > offset_threshold_ns:
                    health["issues"].append(
                        f"PTP offset {ptp4l_status['offset_ns']}ns exceeds threshold {offset_threshold_ns}ns"
                    )

            # Check path delay
            if ptp4l_status["mean_path_delay_ns"] is not None:
                if ptp4l_status["mean_path_delay_ns"] > delay_threshold_ns:
                    health["warnings"].append(
                        f"High mean path delay: {ptp4l_status['mean_path_delay_ns']}ns"
                    )

            if not health["issues"]:
                health["status"] = "synchronized"

        elif ptp4l_status["state"] == "master":
            health["status"] = "master"

        elif ptp4l_status["state"] == "acquiring":
            health["issues"].append(
                f"PTP still acquiring sync (state: {ptp4l_status['port_state']})"
            )

        elif ptp4l_status["available"]:
            health["issues"].append(
                f"PTP in unexpected state: {ptp4l_status['port_state']}"
            )

    elif devices and not ptp4l_status:
        health["warnings"].append("ptp4l not running or pmc not available")
        health["status"] = "unconfigured"

    # Set final status
    if health["issues"]:
        health["status"] = "degraded"
    elif not health["status"] or health["status"] == "unknown":
        if ptp4l_status and ptp4l_status.get("state") == "synchronized":
            health["status"] = "synchronized"
        elif ptp4l_status and ptp4l_status.get("state") == "master":
            health["status"] = "master"
        elif devices and not ptp4l_status:
            health["status"] = "unconfigured"

    return health


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
        description="Monitor PTP (Precision Time Protocol) clock synchronization"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed device information"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only report if there are issues or warnings",
    )
    parser.add_argument(
        "--offset-threshold",
        type=int,
        default=1000,
        metavar="NS",
        help="Offset threshold in nanoseconds (default: 1000)",
    )
    parser.add_argument(
        "--delay-threshold",
        type=int,
        default=10000,
        metavar="NS",
        help="Path delay threshold in nanoseconds (default: 10000)",
    )
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Get PTP devices from sysfs
    devices = get_ptp_devices(context)

    # Get ptp4l status if available
    ptp4l_status = get_ptp4l_status(context)

    # Perform health check
    health = check_ptp_health(
        devices,
        ptp4l_status,
        offset_threshold_ns=opts.offset_threshold,
        delay_threshold_ns=opts.delay_threshold,
    )

    # Apply warn-only filter
    if opts.warn_only:
        if (
            health["status"] in ("synchronized", "master")
            and not health["issues"]
            and not health["warnings"]
        ):
            output.emit(
                {"status": health["status"], "issues": [], "warnings": [], "devices": []}
            )
            output.set_summary("PTP healthy")

            output.render(opts.format, "Monitor PTP (Precision Time Protocol) clock synchronization")
            return 0

    # Build output data
    output_data = {
        "status": health["status"],
        "device_count": len(devices),
        "issues": health["issues"],
        "warnings": health["warnings"],
    }

    if opts.verbose or health["status"] not in ("synchronized", "master"):
        output_data["devices"] = devices
        if ptp4l_status:
            output_data["ptp4l"] = ptp4l_status

    output.emit(output_data)

    # Set summary based on status
    status_messages = {
        "synchronized": "PTP synchronized",
        "master": "PTP master mode",
        "degraded": f"PTP degraded: {len(health['issues'])} issue(s)",
        "acquiring": "PTP acquiring sync",
        "unconfigured": "PTP devices present but not configured",
        "no_ptp": "No PTP hardware found",
        "unknown": "PTP status unknown",
    }
    output.set_summary(status_messages.get(health["status"], health["status"]))

    # Determine exit code
    if health["status"] == "no_ptp":

        output.render(opts.format, "Monitor PTP (Precision Time Protocol) clock synchronization")
        return 2
    elif health["status"] in ("degraded", "acquiring", "unknown") or health["issues"]:

        output.render(opts.format, "Monitor PTP (Precision Time Protocol) clock synchronization")
        return 1
    else:

        output.render(opts.format, "Monitor PTP (Precision Time Protocol) clock synchronization")
        return 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
