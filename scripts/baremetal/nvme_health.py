#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, storage, nvme, ssd, smart]
#   requires: [nvme]
#   privilege: root
#   related: [disk_health, ssd_wear]
#   brief: Monitor NVMe drive health and performance metrics

"""
Monitor NVMe drive health and performance metrics.

Checks NVMe-specific health indicators including:
- Temperature and thermal throttling status
- Spare capacity and wear level
- Media and data integrity errors
- Controller health and available spare threshold
- Power-on hours and unsafe shutdowns

Returns exit code 1 if any issues are detected.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_smart_log(output: str) -> dict[str, Any]:
    """Parse nvme smart-log output into a dictionary."""
    data: dict[str, Any] = {}

    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue

        parts = line.split(":", 1)
        if len(parts) != 2:
            continue

        key = parts[0].strip().lower().replace(" ", "_").replace("-", "_")
        value_str = parts[1].strip()

        # Parse numeric values
        value_str_clean = value_str.replace(",", "").replace("%", "").strip()

        # Extract just the number if there's a unit
        match = re.match(r"^([\d.]+)", value_str_clean)
        if match:
            num_str = match.group(1)
            try:
                if "." in num_str:
                    data[key] = float(num_str)
                else:
                    data[key] = int(num_str)
            except ValueError:
                data[key] = value_str
        else:
            data[key] = value_str

        data[f"{key}_raw"] = value_str

    return data


def get_nvme_smart_log(device: str, context: Context) -> dict[str, Any] | None:
    """Get SMART log data for an NVMe device."""
    result = context.run(["nvme", "smart-log", device], check=False)
    if result.returncode != 0:
        return None
    return parse_smart_log(result.stdout)


def get_nvme_id_ctrl(device: str, context: Context) -> dict[str, str] | None:
    """Get controller identification data."""
    # Extract controller path from namespace path (nvme0n1 -> nvme0)
    ctrl_match = re.match(r"(/dev/nvme\d+)", device)
    if not ctrl_match:
        return None

    ctrl_path = ctrl_match.group(1)

    result = context.run(["nvme", "id-ctrl", ctrl_path], check=False)
    if result.returncode != 0:
        return None

    data = {}
    for line in result.stdout.strip().split("\n"):
        if ":" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip().lower()
                value = parts[1].strip()
                data[key] = value

    return data


def analyze_drive_health(
    device: str,
    smart_data: dict[str, Any],
    id_data: dict[str, str] | None,
    temp_warn: int,
    temp_crit: int,
    spare_warn: int
) -> dict[str, Any]:
    """Analyze NVMe drive health and return status."""
    result: dict[str, Any] = {
        "device": device,
        "status": "healthy",
        "issues": [],
        "warnings": [],
        "metrics": {},
    }

    # Extract model and serial if available
    if id_data:
        result["model"] = id_data.get("mn", "Unknown").strip()
        result["serial"] = id_data.get("sn", "Unknown").strip()
        result["firmware"] = id_data.get("fr", "Unknown").strip()

    # Critical warning bitmap
    critical_warning = smart_data.get("critical_warning", 0)
    if isinstance(critical_warning, int) and critical_warning > 0:
        result["status"] = "critical"
        result["issues"].append({
            "type": "critical_warning",
            "value": critical_warning,
            "message": f"Critical warning flags set: {critical_warning}"
        })

        if critical_warning & 0x01:
            result["issues"].append({
                "type": "spare_below_threshold",
                "message": "Available spare space below threshold"
            })

    # Temperature
    temperature = smart_data.get("temperature", None)
    if temperature is None:
        temperature = smart_data.get("composite_temperature", None)

    if temperature is not None:
        # Some drives report in Kelvin
        if temperature > 200:
            temperature = temperature - 273

        result["metrics"]["temperature_c"] = temperature

        if temperature >= temp_crit:
            result["status"] = "critical"
            result["issues"].append({
                "type": "temperature_critical",
                "value": temperature,
                "threshold": temp_crit,
                "message": f"Temperature {temperature}C exceeds critical threshold ({temp_crit}C)"
            })
        elif temperature >= temp_warn:
            if result["status"] == "healthy":
                result["status"] = "warning"
            result["warnings"].append({
                "type": "temperature_high",
                "value": temperature,
                "threshold": temp_warn,
                "message": f"Temperature {temperature}C exceeds warning threshold ({temp_warn}C)"
            })

    # Available spare
    available_spare = smart_data.get("available_spare", None)
    if available_spare is not None:
        result["metrics"]["available_spare_pct"] = available_spare

        if available_spare <= spare_warn:
            if result["status"] == "healthy":
                result["status"] = "warning"
            result["warnings"].append({
                "type": "spare_low",
                "value": available_spare,
                "threshold": spare_warn,
                "message": f"Available spare {available_spare}% at or below threshold ({spare_warn}%)"
            })

        if available_spare <= 10:
            result["status"] = "critical"
            result["issues"].append({
                "type": "spare_critical",
                "value": available_spare,
                "message": f"Available spare critically low at {available_spare}%"
            })

    # Percentage used (wear indicator)
    percentage_used = smart_data.get("percentage_used", None)
    if percentage_used is not None:
        result["metrics"]["percentage_used"] = percentage_used

        if percentage_used >= 100:
            result["status"] = "critical"
            result["issues"].append({
                "type": "endurance_exceeded",
                "value": percentage_used,
                "message": f"Drive endurance exceeded ({percentage_used}% of rated writes)"
            })
        elif percentage_used >= 90:
            if result["status"] == "healthy":
                result["status"] = "warning"
            result["warnings"].append({
                "type": "endurance_high",
                "value": percentage_used,
                "message": f"Drive approaching endurance limit ({percentage_used}% used)"
            })

    # Media errors
    media_errors = smart_data.get("media_errors",
                                  smart_data.get("media_and_data_integrity_errors", 0))
    if media_errors and media_errors > 0:
        result["status"] = "critical"
        result["metrics"]["media_errors"] = media_errors
        result["issues"].append({
            "type": "media_errors",
            "value": media_errors,
            "message": f"{media_errors} media/data integrity errors detected"
        })

    # Unsafe shutdowns
    unsafe_shutdowns = smart_data.get("unsafe_shutdowns", 0)
    if unsafe_shutdowns:
        result["metrics"]["unsafe_shutdowns"] = unsafe_shutdowns
        if unsafe_shutdowns > 100:
            if result["status"] == "healthy":
                result["status"] = "warning"
            result["warnings"].append({
                "type": "unsafe_shutdowns_high",
                "value": unsafe_shutdowns,
                "message": f"High number of unsafe shutdowns: {unsafe_shutdowns}"
            })

    # Power-on hours
    power_on_hours = smart_data.get("power_on_hours", None)
    if power_on_hours is not None:
        result["metrics"]["power_on_hours"] = power_on_hours
        result["metrics"]["power_on_days"] = round(power_on_hours / 24, 1)

    # Data units read/written
    data_read = smart_data.get("data_units_read", 0)
    data_written = smart_data.get("data_units_written", 0)
    if data_read:
        result["metrics"]["data_read_tb"] = round(data_read * 500 / (1024 * 1024 * 1024), 2)
    if data_written:
        result["metrics"]["data_written_tb"] = round(data_written * 500 / (1024 * 1024 * 1024), 2)

    return result


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
        description="Monitor NVMe drive health and performance metrics"
    )
    parser.add_argument("-d", "--device", metavar="PATH",
                        help="Specific NVMe device to check (e.g., /dev/nvme0n1)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed metrics")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--temp-warn", type=int, default=60, metavar="CELSIUS",
                        help="Temperature warning threshold (default: 60C)")
    parser.add_argument("--temp-crit", type=int, default=75, metavar="CELSIUS",
                        help="Temperature critical threshold (default: 75C)")
    parser.add_argument("--spare-warn", type=int, default=20, metavar="PERCENT",
                        help="Available spare warning threshold (default: 20%%)")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.temp_warn >= opts.temp_crit:
        output.error("--temp-warn must be less than --temp-crit")

        output.render(opts.format, "Monitor NVMe drive health and performance metrics")
        return 2

    # Check for nvme-cli
    if not context.check_tool("nvme"):
        output.error("nvme-cli not found. Install nvme-cli package.")

        output.render(opts.format, "Monitor NVMe drive health and performance metrics")
        return 2

    # Get devices to check
    devices: list[str] = []
    if opts.device:
        devices = [opts.device]
    else:
        # Discover NVMe devices
        nvme_files = context.glob("nvme*n*", root="/dev")
        devices = [f"/dev/{f.split('/')[-1]}" for f in nvme_files
                   if re.match(r"nvme\d+n\d+$", f.split("/")[-1])]

    if not devices:
        output.emit({
            "status": "ok",
            "message": "No NVMe devices found",
            "drives": []
        })
        output.set_summary("No NVMe devices found")

        output.render(opts.format, "Monitor NVMe drive health and performance metrics")
        return 0

    # Check each device
    results = []
    for device in devices:
        smart_data = get_nvme_smart_log(device, context)
        if smart_data is None:
            results.append({
                "device": device,
                "status": "unknown",
                "issues": [{"type": "read_error", "message": "Could not read SMART data"}],
                "warnings": [],
                "metrics": {},
            })
            continue

        id_data = get_nvme_id_ctrl(device, context)

        result = analyze_drive_health(
            device, smart_data, id_data,
            opts.temp_warn, opts.temp_crit, opts.spare_warn
        )
        results.append(result)

    # Build output
    total = len(results)
    healthy = sum(1 for r in results if r["status"] == "healthy")
    warning = sum(1 for r in results if r["status"] == "warning")
    critical = sum(1 for r in results if r["status"] == "critical")

    if critical > 0:
        overall_status = "critical"
    elif warning > 0:
        overall_status = "warning"
    else:
        overall_status = "healthy"

    output.emit({
        "status": overall_status,
        "summary": {
            "total_drives": total,
            "healthy": healthy,
            "warning": warning,
            "critical": critical,
        },
        "drives": results,
    })

    output.set_summary(f"{total} drives - {healthy} healthy, {warning} warning, {critical} critical")

    # Determine exit code
    has_critical = any(r["status"] == "critical" for r in results)
    has_warning = any(r["status"] == "warning" for r in results)

    if has_critical or has_warning:

        output.render(opts.format, "Monitor NVMe drive health and performance metrics")
        return 1

    output.render(opts.format, "Monitor NVMe drive health and performance metrics")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
