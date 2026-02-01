#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage, predictive, hardware]
#   requires: [smartctl]
#   privilege: root
#   related: [disk_health, disk_lifecycle_monitor]
#   brief: Predict disk failure risk using SMART attribute analysis

"""
Predict disk failure risk using SMART attribute trend analysis.

Analyzes critical SMART attributes (reallocated sectors, pending sectors,
uncorrectable errors, etc.) to estimate failure risk. Provides risk scoring
based on attribute severity.

Risk Levels:
  MINIMAL  - No concerning indicators (score < 10)
  LOW      - Minor indicators, monitor closely (score 10-29)
  MEDIUM   - Elevated risk, plan replacement (score 30-59)
  HIGH     - Imminent failure likely, replace ASAP (score >= 60)

Exit codes:
    0: All disks healthy (low risk)
    1: Warnings detected (medium/high risk disks found)
    2: Missing dependency or usage error
"""

import argparse
import re

from boxctl.core.context import Context
from boxctl.core.output import Output


# SMART attributes that indicate potential failure
# Format: attribute_id -> {name, weight, warn, critical}
CRITICAL_ATTRIBUTES = {
    "5": {"name": "Reallocated_Sector_Ct", "weight": 10, "warn": 1, "critical": 10},
    "10": {"name": "Spin_Retry_Count", "weight": 8, "warn": 1, "critical": 5},
    "196": {"name": "Reallocated_Event_Count", "weight": 9, "warn": 1, "critical": 5},
    "197": {"name": "Current_Pending_Sector", "weight": 10, "warn": 1, "critical": 5},
    "198": {"name": "Offline_Uncorrectable", "weight": 10, "warn": 1, "critical": 5},
    "199": {"name": "UDMA_CRC_Error_Count", "weight": 3, "warn": 10, "critical": 100},
    "187": {"name": "Reported_Uncorrect", "weight": 8, "warn": 1, "critical": 10},
    "188": {"name": "Command_Timeout", "weight": 5, "warn": 5, "critical": 50},
    "189": {"name": "High_Fly_Writes", "weight": 4, "warn": 1, "critical": 10},
    "191": {"name": "G-Sense_Error_Rate", "weight": 3, "warn": 10, "critical": 100},
    "192": {"name": "Power-Off_Retract_Count", "weight": 2, "warn": 100, "critical": 1000},
    "193": {"name": "Load_Cycle_Count", "weight": 2, "warn": 300000, "critical": 500000},
}

# Risk level thresholds (based on weighted score)
RISK_LOW = 10
RISK_MEDIUM = 30
RISK_HIGH = 60


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


def parse_smart_attributes(stdout: str) -> tuple[dict, str]:
    """
    Parse SMART attributes from smartctl output.

    Returns:
        (attributes dict, health status string)
    """
    attributes = {}
    health_status = "UNKNOWN"

    # Check health status
    if "SMART support is: Unavailable" in stdout or "SMART support is: Disabled" in stdout:
        return None, "UNAVAILABLE"

    if "PASSED" in stdout:
        health_status = "PASSED"
    elif "FAILED" in stdout:
        health_status = "FAILED"

    # Parse SMART attributes
    for line in stdout.split("\n"):
        parts = line.split()
        if len(parts) >= 10:
            attr_id = parts[0]
            if attr_id in CRITICAL_ATTRIBUTES:
                try:
                    # Handle "123 (N/A)" format
                    raw_value = int(parts[9].split()[0])
                    attributes[attr_id] = {
                        "name": CRITICAL_ATTRIBUTES[attr_id]["name"],
                        "raw_value": raw_value,
                    }
                except (ValueError, IndexError):
                    pass

    return attributes, health_status


def calculate_risk_score(attributes: dict | None) -> tuple[int, list[dict]]:
    """
    Calculate risk score based on SMART attributes.

    Returns:
        (total_score, list of findings)
    """
    if attributes is None:
        return 100, [{"severity": "CRITICAL", "message": "Unable to read SMART data"}]

    total_score = 0
    findings = []

    for attr_id, attr_data in attributes.items():
        config = CRITICAL_ATTRIBUTES.get(attr_id)
        if not config:
            continue

        raw_value = attr_data["raw_value"]
        weight = config["weight"]
        warn_thresh = config["warn"]
        crit_thresh = config["critical"]

        if raw_value >= crit_thresh:
            score = weight * 5
            total_score += score
            findings.append({
                "severity": "CRITICAL",
                "message": f"{attr_data['name']}: {raw_value} (critical >= {crit_thresh})",
            })
        elif raw_value >= warn_thresh:
            score = weight * 2
            total_score += score
            findings.append({
                "severity": "WARNING",
                "message": f"{attr_data['name']}: {raw_value} (warn >= {warn_thresh})",
            })

    return total_score, findings


def get_risk_level(score: int) -> str:
    """Convert numeric score to risk level."""
    if score >= RISK_HIGH:
        return "HIGH"
    elif score >= RISK_MEDIUM:
        return "MEDIUM"
    elif score >= RISK_LOW:
        return "LOW"
    return "MINIMAL"


def get_recommendation(risk_level: str) -> str:
    """Generate actionable recommendation based on risk."""
    recommendations = {
        "HIGH": "IMMEDIATE ACTION: Back up data and plan disk replacement",
        "MEDIUM": "Schedule disk replacement within 30 days; verify backups",
        "LOW": "Monitor closely; ensure backups are current",
        "MINIMAL": "No action required; continue regular monitoring",
    }
    return recommendations.get(risk_level, "Unknown risk level")


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
        description="Predict disk failure risk using SMART attribute analysis"
    )
    parser.add_argument("-d", "--disk", help="Specific disk to check (e.g., /dev/sda)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show disks with elevated risk")
    opts = parser.parse_args(args)

    # Check for smartctl
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
        output.error("No disks found")
        return 2

    # Analyze disks
    results = []
    has_warnings = False

    for disk in disks:
        size, model = get_disk_info(disk, context)

        # Get SMART data
        smart_result = context.run(["smartctl", "-H", "-A", disk], check=False)
        attributes, health_status = parse_smart_attributes(smart_result.stdout)

        # Handle SMART failed status
        if health_status == "FAILED":
            risk_score = 100
            risk_level = "HIGH"
            findings = [{"severity": "CRITICAL", "message": "SMART overall health test FAILED"}]
            recommendation = get_recommendation("HIGH")
        elif health_status == "UNAVAILABLE":
            risk_score = 0
            risk_level = "MINIMAL"
            findings = [{"severity": "INFO", "message": "SMART not available for this disk"}]
            recommendation = "Cannot assess; SMART unavailable"
        else:
            risk_score, findings = calculate_risk_score(attributes)
            risk_level = get_risk_level(risk_score)
            recommendation = get_recommendation(risk_level)

        disk_result = {
            "disk": disk,
            "size": size,
            "model": model,
            "smart_status": health_status,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": findings,
            "recommendation": recommendation,
        }

        if risk_level != "MINIMAL":
            has_warnings = True

        if not opts.warn_only or risk_level != "MINIMAL":
            results.append(disk_result)

    output.emit({"disks": results})

    # Set summary
    minimal = sum(1 for r in results if r["risk_level"] == "MINIMAL")
    low = sum(1 for r in results if r["risk_level"] == "LOW")
    medium = sum(1 for r in results if r["risk_level"] == "MEDIUM")
    high = sum(1 for r in results if r["risk_level"] == "HIGH")
    output.set_summary(f"minimal={minimal}, low={low}, medium={medium}, high={high}")

    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
