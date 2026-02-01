#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, storage, ssd, smart, wear]
#   requires: [smartctl]
#   privilege: root
#   related: [disk_health, nvme_health]
#   brief: Monitor SSD wear levels and endurance metrics

"""
Monitor SSD wear levels and endurance metrics using SMART attributes.

Reads SSD-specific SMART attributes to estimate remaining drive life and
identify drives approaching end of life. Key metrics monitored:
- Media Wearout Indicator (Intel)
- Wear Leveling Count (Samsung, generic)
- Percentage Used Endurance Indicator
- Total LBAs Written / Host Writes
- Available Reserved Space
- Reallocated Sector Count

Returns exit code 1 if any SSDs have warnings or errors.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_disk_list(context: Context) -> list[str]:
    """Get list of disk devices."""
    result = context.run(["lsblk", "-d", "-n", "-o", "NAME,TYPE"], check=False)
    if result.returncode != 0:
        return []

    disks = [
        f"/dev/{disk.strip().split()[0]}"
        for disk in result.stdout.strip().split("\n")
        if disk.strip() and len(disk.split()) >= 2 and disk.split()[1] == "disk"
    ]
    return disks


def is_ssd(disk: str, context: Context) -> bool:
    """Check if a disk is an SSD (not rotational)."""
    device_name = disk.replace("/dev/", "")

    # NVMe devices are always SSDs
    if device_name.startswith("nvme"):
        return True

    # Check rotational flag for SATA/SAS drives
    rotational_path = f"/sys/block/{device_name}/queue/rotational"
    try:
        content = context.read_file(rotational_path)
        return content.strip() == "0"
    except (FileNotFoundError, IOError):
        return False


def get_disk_info(disk: str, context: Context) -> tuple[str, str]:
    """Get basic disk information."""
    result = context.run(["lsblk", "-n", "-o", "SIZE,MODEL", disk], check=False)
    if result.returncode != 0:
        return "N/A", "N/A"

    parts = result.stdout.strip().split(None, 1)
    size = parts[0] if len(parts) > 0 else "N/A"
    model = parts[1].strip() if len(parts) > 1 else "N/A"

    return size, model


def get_nvme_wear_info(disk: str, context: Context) -> dict[str, Any] | None:
    """Get wear info from NVMe device using smartctl."""
    result = context.run(["smartctl", "-A", disk], check=False)
    stdout = result.stdout

    if result.returncode != 0 and "Unable to detect" not in stdout:
        return None

    wear_info: dict[str, Any] = {
        "percentage_used": None,
        "available_spare": None,
        "data_written_tb": None,
        "power_on_hours": None,
        "media_errors": None,
        "wear_level": None,
    }

    for line in stdout.split("\n"):
        line_lower = line.lower()

        # Percentage Used
        if "percentage used" in line_lower:
            match = re.search(r"(\d+)%?", line)
            if match:
                wear_info["percentage_used"] = int(match.group(1))
                wear_info["wear_level"] = 100 - int(match.group(1))

        # Available Spare
        elif "available spare:" in line_lower and "threshold" not in line_lower:
            match = re.search(r"(\d+)%?", line)
            if match:
                wear_info["available_spare"] = int(match.group(1))

        # Data Written (convert to TB)
        elif "data units written" in line_lower:
            match = re.search(r"[\d,]+", line)
            if match:
                units = int(match.group().replace(",", ""))
                # Each unit is 512KB * 1000 = 512000 bytes
                tb_written = (units * 512000) / (1024**4)
                wear_info["data_written_tb"] = round(tb_written, 2)

        # Power On Hours
        elif "power on hours" in line_lower:
            match = re.search(r"[\d,]+", line)
            if match:
                wear_info["power_on_hours"] = int(match.group().replace(",", ""))

        # Media Errors
        elif "media and data integrity errors" in line_lower:
            match = re.search(r"(\d+)", line)
            if match:
                wear_info["media_errors"] = int(match.group(1))

    return wear_info


def get_sata_ssd_wear_info(disk: str, context: Context) -> dict[str, Any] | None:
    """Get wear info from SATA SSD using SMART attributes."""
    result = context.run(["smartctl", "-A", disk], check=False)
    if result.returncode != 0:
        return None

    wear_info: dict[str, Any] = {
        "percentage_used": None,
        "available_spare": None,
        "data_written_tb": None,
        "power_on_hours": None,
        "media_errors": None,
        "wear_level": None,
    }

    reallocated_sectors = 0
    total_lbas_written = None
    power_on_hours = None

    for line in result.stdout.split("\n"):
        parts = line.split()
        if len(parts) >= 10:
            attr_id = parts[0]

            # Wear Leveling Count (177, 173) - normalized value indicates remaining life
            if attr_id in ["177", "173"]:
                try:
                    norm_int = int(parts[3])
                    wear_info["wear_level"] = norm_int
                    wear_info["percentage_used"] = 100 - norm_int if norm_int <= 100 else None
                except ValueError:
                    pass

            # SSD Life Left (231)
            elif attr_id == "231":
                try:
                    norm_int = int(parts[3])
                    wear_info["wear_level"] = norm_int
                    wear_info["percentage_used"] = 100 - norm_int if norm_int <= 100 else None
                except ValueError:
                    pass

            # Available Reserved Space (232)
            elif attr_id == "232":
                try:
                    wear_info["available_spare"] = int(parts[3])
                except ValueError:
                    pass

            # Media Wearout Indicator (233)
            elif attr_id == "233":
                try:
                    norm_int = int(parts[3])
                    wear_info["wear_level"] = norm_int
                    wear_info["percentage_used"] = 100 - norm_int if norm_int <= 100 else None
                except ValueError:
                    pass

            # Total LBAs Written (241, 246)
            elif attr_id in ["241", "246"]:
                try:
                    total_lbas_written = int(parts[9])
                except ValueError:
                    pass

            # Power On Hours (9)
            elif attr_id == "9":
                try:
                    power_on_hours = int(parts[9])
                except ValueError:
                    pass

            # Reallocated Sectors (5)
            elif attr_id == "5":
                try:
                    reallocated_sectors = int(parts[9])
                except ValueError:
                    pass

    # Convert LBAs written to TB (512 bytes per LBA)
    if total_lbas_written:
        tb_written = (total_lbas_written * 512) / (1024**4)
        wear_info["data_written_tb"] = round(tb_written, 2)

    wear_info["power_on_hours"] = power_on_hours

    # Use reallocated sectors as an error indicator
    if reallocated_sectors > 0:
        wear_info["media_errors"] = reallocated_sectors

    return wear_info


def get_ssd_wear_info(disk: str, context: Context) -> dict[str, Any] | None:
    """Get wear information for an SSD."""
    if "nvme" in disk:
        return get_nvme_wear_info(disk, context)
    else:
        return get_sata_ssd_wear_info(disk, context)


def analyze_wear(
    wear_info: dict[str, Any] | None,
    warn_threshold: int,
    critical_threshold: int
) -> tuple[str, list[str]]:
    """Analyze wear info and determine status."""
    status = "healthy"
    warnings = []

    if wear_info is None:
        return "unknown", ["Unable to read SMART data"]

    wear_level = wear_info.get("wear_level")
    percentage_used = wear_info.get("percentage_used")
    available_spare = wear_info.get("available_spare")
    media_errors = wear_info.get("media_errors")

    # Check wear level / percentage used
    if wear_level is not None:
        if wear_level <= critical_threshold:
            status = "critical"
            warnings.append(f"Wear level critical: {wear_level}% remaining")
        elif wear_level <= warn_threshold:
            status = "warning"
            warnings.append(f"Wear level low: {wear_level}% remaining")

    if percentage_used is not None and percentage_used >= (100 - critical_threshold):
        status = "critical"
        warnings.append(f"{percentage_used}% of rated endurance used")
    elif percentage_used is not None and percentage_used >= (100 - warn_threshold):
        if status != "critical":
            status = "warning"
        warnings.append(f"{percentage_used}% of rated endurance used")

    # Check available spare
    if available_spare is not None and available_spare < 10:
        status = "critical"
        warnings.append(f"Low available spare: {available_spare}%")
    elif available_spare is not None and available_spare < 20:
        if status != "critical":
            status = "warning"
        warnings.append(f"Available spare declining: {available_spare}%")

    # Check media errors
    if media_errors is not None and media_errors > 0:
        status = "critical"
        warnings.append(f"Media errors detected: {media_errors}")

    return status, warnings


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
        description="Monitor SSD wear levels and endurance metrics"
    )
    parser.add_argument("-d", "--disk",
                        help="Specific disk to check (e.g., /dev/nvme0n1, /dev/sda)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed wear metrics")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--warn", type=int, default=20, metavar="PERCENT",
                        help="Warning threshold for remaining life (default: 20%%)")
    parser.add_argument("--critical", type=int, default=10, metavar="PERCENT",
                        help="Critical threshold for remaining life (default: 10%%)")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < opts.critical:
        output.error("Warning threshold must be >= critical threshold")
        return 2

    # Check for smartctl
    if not context.check_tool("smartctl"):
        output.error("smartctl not found. Install smartmontools package.")
        return 2

    # Get disk list
    if opts.disk:
        disks = [opts.disk]
    else:
        all_disks = get_disk_list(context)
        disks = [d for d in all_disks if is_ssd(d, context)]

    if not disks:
        output.emit({"ssds": [], "message": "No SSDs found"})
        output.set_summary("No SSDs found")
        return 0

    results = []
    has_warnings = False

    for disk in disks:
        size, model = get_disk_info(disk, context)
        wear_info = get_ssd_wear_info(disk, context)
        status, warnings = analyze_wear(wear_info, opts.warn, opts.critical)

        result: dict[str, Any] = {
            "disk": disk,
            "size": size,
            "model": model,
            "status": status,
            "warnings": warnings,
            "wear_level": wear_info.get("wear_level") if wear_info else None,
            "percentage_used": wear_info.get("percentage_used") if wear_info else None,
            "available_spare": wear_info.get("available_spare") if wear_info else None,
            "data_written_tb": wear_info.get("data_written_tb") if wear_info else None,
            "power_on_hours": wear_info.get("power_on_hours") if wear_info else None,
            "media_errors": wear_info.get("media_errors") if wear_info else None,
        }

        if status in ["warning", "critical", "unknown"]:
            has_warnings = True

        results.append(result)

    # Build output
    summary = {
        "total": len(disks),
        "checked": len(results),
        "healthy": sum(1 for r in results if r["status"] == "healthy"),
        "warning": sum(1 for r in results if r["status"] == "warning"),
        "critical": sum(1 for r in results if r["status"] == "critical"),
        "unknown": sum(1 for r in results if r["status"] == "unknown"),
    }

    output.emit({"ssds": results, "summary": summary})
    output.set_summary(
        f"{summary['total']} SSDs - {summary['healthy']} healthy, "
        f"{summary['warning']} warning, {summary['critical']} critical"
    )

    # Exit code
    if has_warnings:
        return 1
    else:
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
