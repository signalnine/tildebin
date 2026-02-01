#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage, lifecycle, hardware]
#   requires: [smartctl]
#   privilege: root
#   related: [disk_health, disk_life_predictor]
#   brief: Monitor disk lifecycle metrics for hardware refresh planning

"""
Monitor disk lifecycle metrics for hardware refresh planning.

Tracks power-on hours, estimated age, and provides lifecycle predictions
based on SMART data. Useful for large-scale baremetal fleet management
to plan hardware refresh and avoid surprise failures.

Exit codes:
    0: All disks healthy, no lifecycle concerns
    1: Some disks approaching end-of-life or have lifecycle warnings
    2: Missing dependency (smartctl not found) or usage error
"""

import argparse
import re

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_disk_list(context: Context) -> list[str]:
    """Get list of disk devices."""
    result = context.run(["lsblk", "-d", "-n", "-o", "NAME,TYPE"])
    disks = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "disk":
            disks.append(f"/dev/{parts[0]}")
    return disks


def get_disk_info(disk: str, context: Context) -> tuple[str, str]:
    """Get basic disk information (size, model)."""
    result = context.run(["lsblk", "-n", "-o", "SIZE,MODEL", disk], check=False)
    if result.returncode != 0:
        return "N/A", "N/A"

    parts = result.stdout.strip().split(None, 1)
    size = parts[0] if len(parts) > 0 else "N/A"
    model = parts[1].strip() if len(parts) > 1 else "N/A"
    return size, model


def parse_smart_info(stdout: str) -> dict:
    """Parse SMART information from smartctl output."""
    info = {
        "power_on_hours": None,
        "power_cycle_count": None,
        "start_stop_count": None,
        "reallocated_sectors": None,
        "pending_sectors": None,
        "serial": None,
        "firmware": None,
        "rotation_rate": None,
        "form_factor": None,
        "smart_supported": True,
        "is_ssd": False,
        "wear_leveling": None,
        "media_wearout": None,
    }

    if "SMART support is: Unavailable" in stdout or "SMART support is: Disabled" in stdout:
        info["smart_supported"] = False
        return info

    # Parse serial number
    match = re.search(r"Serial Number:\s+(\S+)", stdout)
    if match:
        info["serial"] = match.group(1)

    # Parse firmware version
    match = re.search(r"Firmware Version:\s+(\S+)", stdout)
    if match:
        info["firmware"] = match.group(1)

    # Parse rotation rate (0 or Solid State = SSD)
    match = re.search(r"Rotation Rate:\s+(.+)", stdout)
    if match:
        rate = match.group(1).strip()
        info["rotation_rate"] = rate
        if "Solid State" in rate or rate == "0":
            info["is_ssd"] = True

    # Parse form factor
    match = re.search(r"Form Factor:\s+(.+)", stdout)
    if match:
        info["form_factor"] = match.group(1).strip()

    # Parse SMART attributes
    # Power-On Hours (attribute 9)
    match = re.search(
        r"^\s*9\s+Power_On_Hours\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)",
        stdout,
        re.MULTILINE
    )
    if match:
        info["power_on_hours"] = int(match.group(1))

    # Power Cycle Count (attribute 12)
    match = re.search(
        r"^\s*12\s+Power_Cycle_Count\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)",
        stdout,
        re.MULTILINE
    )
    if match:
        info["power_cycle_count"] = int(match.group(1))

    # Start/Stop Count (attribute 4)
    match = re.search(
        r"^\s*4\s+Start_Stop_Count\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)",
        stdout,
        re.MULTILINE
    )
    if match:
        info["start_stop_count"] = int(match.group(1))

    # Reallocated Sectors (attribute 5)
    match = re.search(
        r"^\s*5\s+Reallocated_Sector_Ct\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)",
        stdout,
        re.MULTILINE
    )
    if match:
        info["reallocated_sectors"] = int(match.group(1))

    # Current Pending Sectors (attribute 197)
    match = re.search(
        r"^\s*197\s+Current_Pending_Sector\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)",
        stdout,
        re.MULTILINE
    )
    if match:
        info["pending_sectors"] = int(match.group(1))

    # SSD Wear Leveling Count (attribute 177)
    match = re.search(
        r"^\s*177\s+Wear_Leveling_Count\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)",
        stdout,
        re.MULTILINE
    )
    if match:
        info["wear_leveling"] = int(match.group(1))
        info["is_ssd"] = True

    # Media Wearout Indicator (attribute 233)
    match = re.search(
        r"^\s*233\s+Media_Wearout_Indicator\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)",
        stdout,
        re.MULTILINE
    )
    if match:
        info["media_wearout"] = int(match.group(1))
        info["is_ssd"] = True

    return info


def calculate_lifecycle_status(
    smart_info: dict,
    warn_hours: int = 35000,
    critical_hours: int = 50000,
    ssd_warn_hours: int = 20000,
    ssd_critical_hours: int = 40000,
) -> dict:
    """
    Calculate lifecycle status and recommendations.

    Default thresholds:
    - HDD: 35,000 hours warning (4 years), 50,000 hours critical (~5.7 years)
    - SSD: 20,000 hours warning (~2.3 years), 40,000 hours critical (~4.6 years)
    """
    status = {
        "lifecycle_status": "unknown",
        "estimated_age_years": None,
        "hours_remaining_estimate": None,
        "recommendation": None,
        "concerns": [],
    }

    if not smart_info["smart_supported"]:
        status["lifecycle_status"] = "unknown"
        status["recommendation"] = "SMART not available - manual inspection recommended"
        return status

    poh = smart_info.get("power_on_hours")
    if poh is None:
        status["lifecycle_status"] = "unknown"
        status["recommendation"] = "Power-on hours not available"
        return status

    # Calculate age in years (assuming 24/7 operation)
    hours_per_year = 8760
    status["estimated_age_years"] = round(poh / hours_per_year, 1)

    # Determine thresholds based on disk type
    is_ssd = smart_info.get("is_ssd", False)
    if is_ssd:
        warn_threshold = ssd_warn_hours
        critical_threshold = ssd_critical_hours
    else:
        warn_threshold = warn_hours
        critical_threshold = critical_hours

    # Determine lifecycle status
    if poh >= critical_threshold:
        status["lifecycle_status"] = "critical"
        status["recommendation"] = "Schedule immediate replacement"
        status["hours_remaining_estimate"] = 0
    elif poh >= warn_threshold:
        status["lifecycle_status"] = "warning"
        status["hours_remaining_estimate"] = critical_threshold - poh
        months = round(status["hours_remaining_estimate"] / 730)
        status["recommendation"] = f"Plan replacement within {months} months"
    else:
        status["lifecycle_status"] = "healthy"
        status["hours_remaining_estimate"] = warn_threshold - poh
        status["recommendation"] = "No action needed"

    # Check for additional concerns
    reallocated = smart_info.get("reallocated_sectors")
    if reallocated is not None and reallocated > 0:
        status["concerns"].append(
            f"Reallocated sectors: {reallocated}"
        )
        if status["lifecycle_status"] == "healthy":
            status["lifecycle_status"] = "warning"
            status["recommendation"] = "Monitor closely - sector reallocation detected"

    pending = smart_info.get("pending_sectors")
    if pending is not None and pending > 0:
        status["concerns"].append(
            f"Pending sectors: {pending}"
        )
        if status["lifecycle_status"] == "healthy":
            status["lifecycle_status"] = "warning"
            status["recommendation"] = "Monitor closely - pending sector reallocation"

    # SSD-specific concerns
    if is_ssd and smart_info.get("wear_leveling") is not None:
        wear = smart_info["wear_leveling"]
        if wear < 50:
            status["concerns"].append(f"SSD wear leveling at {wear}%")
            status["lifecycle_status"] = "critical"
            status["recommendation"] = "SSD nearing end of life - replace soon"
        elif wear < 80:
            status["concerns"].append(f"SSD wear leveling at {wear}%")
            if status["lifecycle_status"] == "healthy":
                status["lifecycle_status"] = "warning"

    return status


def format_hours(hours: int | None) -> str:
    """Format hours into human-readable string."""
    if hours is None:
        return "N/A"

    years = hours // 8760
    remaining = hours % 8760
    months = remaining // 730
    days = (remaining % 730) // 24

    parts = []
    if years > 0:
        parts.append(f"{years}y")
    if months > 0:
        parts.append(f"{months}m")
    if days > 0 and years == 0:
        parts.append(f"{days}d")

    return " ".join(parts) if parts else "0d"


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
        description="Monitor disk lifecycle for hardware refresh planning"
    )
    parser.add_argument("-d", "--disk", help="Specific disk to check (e.g., /dev/sda)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed SMART information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show disks with lifecycle warnings")
    parser.add_argument("--warn-hours", type=int, default=35000, help="Hours threshold for warning (HDD, default: 35000)")
    parser.add_argument("--critical-hours", type=int, default=50000, help="Hours threshold for critical (HDD, default: 50000)")
    parser.add_argument("--ssd-warn-hours", type=int, default=20000, help="Hours threshold for warning (SSD, default: 20000)")
    parser.add_argument("--ssd-critical-hours", type=int, default=40000, help="Hours threshold for critical (SSD, default: 40000)")
    opts = parser.parse_args(args)

    # Check if smartctl is available
    if not context.check_tool("smartctl"):
        output.error("smartctl not found. Install smartmontools package.")
        return 2

    # Get disk list
    if opts.disk:
        disks = [opts.disk]
    else:
        try:
            disks = get_disk_list(context)
        except Exception as e:
            output.error(f"Failed to list disks: {e}")
            return 2

    if not disks:
        output.warning("No disks found")
        output.emit({"disks": []})
        return 1

    results = []
    has_warnings = False

    for disk in disks:
        size, model = get_disk_info(disk, context)

        # Get SMART info
        smart_result = context.run(["smartctl", "-i", "-A", disk], check=False)
        smart_info = parse_smart_info(smart_result.stdout)

        lifecycle = calculate_lifecycle_status(
            smart_info,
            warn_hours=opts.warn_hours,
            critical_hours=opts.critical_hours,
            ssd_warn_hours=opts.ssd_warn_hours,
            ssd_critical_hours=opts.ssd_critical_hours,
        )

        disk_result = {
            "disk": disk,
            "size": size,
            "model": model,
            "type": "SSD" if smart_info.get("is_ssd") else "HDD",
            "power_on_hours": smart_info.get("power_on_hours"),
            "power_on_hours_formatted": format_hours(smart_info.get("power_on_hours")),
            "power_cycle_count": smart_info.get("power_cycle_count"),
            "lifecycle_status": lifecycle["lifecycle_status"],
            "estimated_age_years": lifecycle["estimated_age_years"],
            "hours_remaining_estimate": lifecycle.get("hours_remaining_estimate"),
            "recommendation": lifecycle["recommendation"],
            "concerns": lifecycle["concerns"],
            "smart_supported": smart_info["smart_supported"],
        }

        if opts.verbose:
            disk_result["serial"] = smart_info.get("serial")
            disk_result["firmware"] = smart_info.get("firmware")
            disk_result["form_factor"] = smart_info.get("form_factor")
            disk_result["reallocated_sectors"] = smart_info.get("reallocated_sectors")
            disk_result["pending_sectors"] = smart_info.get("pending_sectors")
            if smart_info.get("is_ssd"):
                disk_result["wear_leveling"] = smart_info.get("wear_leveling")

        if lifecycle["lifecycle_status"] in ("warning", "critical"):
            has_warnings = True

        if not opts.warn_only or lifecycle["lifecycle_status"] in ("warning", "critical", "unknown"):
            results.append(disk_result)

    output.emit({"disks": results})

    # Set summary
    healthy = sum(1 for r in results if r["lifecycle_status"] == "healthy")
    warning = sum(1 for r in results if r["lifecycle_status"] == "warning")
    critical = sum(1 for r in results if r["lifecycle_status"] == "critical")
    output.set_summary(f"{healthy} healthy, {warning} warning, {critical} critical")

    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
