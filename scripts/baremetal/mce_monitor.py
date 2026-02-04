#!/usr/bin/env python3
# boxctl:
#   category: baremetal/hardware
#   tags: [health, hardware, cpu, memory, mce, errors]
#   brief: Monitor Machine Check Exceptions (MCE) for hardware faults

"""
Monitor Machine Check Exceptions (MCE) for hardware fault detection.

Machine Check Exceptions are hardware-level error reports from the CPU
indicating serious hardware issues such as:
- CPU cache parity/ECC errors
- Memory bus errors
- System bus errors
- Thermal events (CPU overheating)
- Internal CPU errors

Data sources:
- /sys/devices/system/machinecheck/ - sysfs MCE configuration
- /sys/kernel/ras/bad_pages - Retired memory pages
- dmesg - Kernel ring buffer MCE messages

Exit codes:
    0 - No MCE errors detected
    1 - MCE errors or warnings detected
    2 - Usage error or missing dependencies
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


MCE_SYS_PATH = "/sys/devices/system/machinecheck"
RAS_BAD_PAGES_PATH = "/sys/kernel/ras/bad_pages"


def get_cpu_mce_info(context: Context) -> list[dict[str, Any]]:
    """
    Get MCE information from sysfs for all CPUs.

    Returns list of dicts with CPU MCE configuration.
    """
    cpu_info = []

    if not context.file_exists(MCE_SYS_PATH):
        return cpu_info

    cpu_paths = context.glob("machinecheck*", root=MCE_SYS_PATH)

    for cpu_path in sorted(cpu_paths):
        cpu_name = cpu_path.split("/")[-1]
        cpu_num = cpu_name.replace("machinecheck", "")

        try:
            cpu_num_int = int(cpu_num)
        except ValueError:
            continue

        base = f"{MCE_SYS_PATH}/{cpu_name}"

        info = {
            "cpu": cpu_num_int,
            "banks": [],
            "trigger": None,
            "monarch_timeout": None,
            "tolerant": None,
            "check_interval": None,
        }

        # Read MCE config values
        try:
            info["trigger"] = context.read_file(f"{base}/trigger").strip()
        except (FileNotFoundError, PermissionError):
            pass

        try:
            info["monarch_timeout"] = context.read_file(f"{base}/monarch_timeout").strip()
        except (FileNotFoundError, PermissionError):
            pass

        try:
            info["tolerant"] = context.read_file(f"{base}/tolerant").strip()
        except (FileNotFoundError, PermissionError):
            pass

        try:
            info["check_interval"] = context.read_file(f"{base}/check_interval").strip()
        except (FileNotFoundError, PermissionError):
            pass

        # Get bank information
        bank_paths = context.glob("bank*", root=base)
        for bank_path in sorted(bank_paths):
            bank_name = bank_path.split("/")[-1]
            bank_num = bank_name.replace("bank", "")

            try:
                bank_value = context.read_file(bank_path).strip()
                info["banks"].append({
                    "bank": int(bank_num),
                    "control": bank_value,
                })
            except (FileNotFoundError, PermissionError, ValueError, OSError):
                # OSError can occur on some systems (e.g., AMD EPYC) where
                # bank files exist but cannot be read
                pass

        cpu_info.append(info)

    return cpu_info


def get_ras_bad_pages(context: Context) -> list[str]:
    """
    Get RAS bad page info (memory pages retired due to errors).

    Returns list of bad page addresses.
    """
    if not context.file_exists(RAS_BAD_PAGES_PATH):
        return []

    try:
        content = context.read_file(RAS_BAD_PAGES_PATH).strip()
        if not content:
            return []
        return [line.strip() for line in content.split("\n") if line.strip()]
    except (FileNotFoundError, PermissionError):
        return []


def parse_dmesg_mce(context: Context) -> list[dict[str, Any]]:
    """
    Parse dmesg for MCE-related messages.

    Returns list of MCE events found in kernel log.
    """
    mce_patterns = [
        (r"\[Hardware Error\].*", "hardware_error"),
        (r"mce:.*", "mce"),
        (r"MCE.*error.*", "mce_error"),
        (r"Machine check events logged", "mce_logged"),
        (r"CPU.*Machine Check Exception.*", "cpu_mce"),
        (r"Bank\s+\d+:.*", "bank_error"),
        (r"CMCI storm.*", "cmci_storm"),
        (r"Corrected error.*", "corrected_error"),
        (r"Uncorrected error.*", "uncorrected_error"),
        (r"Fatal error.*", "fatal_error"),
    ]

    mce_events = []

    if not context.check_tool("dmesg"):
        return mce_events

    try:
        result = context.run(["dmesg", "-T"], timeout=10)
        if result.returncode != 0:
            # Try without -T flag
            result = context.run(["dmesg"], timeout=10)

        if result.returncode != 0:
            return mce_events

        for line in result.stdout.split("\n"):
            for pattern, event_type in mce_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    mce_events.append({
                        "type": event_type,
                        "message": line.strip(),
                        "severity": classify_severity(event_type, line),
                    })
                    break

    except Exception:
        pass

    return mce_events


def classify_severity(event_type: str, message: str) -> str:
    """Classify the severity of an MCE event."""
    message_lower = message.lower()

    if any(term in message_lower for term in ["fatal", "uncorrected", "panic"]):
        return "CRITICAL"
    elif any(term in message_lower for term in ["corrected", "cmci"]):
        return "WARNING"
    elif event_type in ("uncorrected_error", "fatal_error"):
        return "CRITICAL"
    elif event_type in ("corrected_error", "cmci_storm"):
        return "WARNING"
    else:
        return "INFO"


def analyze_mce_data(
    cpu_info: list[dict[str, Any]],
    bad_pages: list[str],
    dmesg_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Analyze all MCE data and produce summary.

    Returns dict with analysis results and overall status.
    """
    analysis = {
        "status": "OK",
        "issues": [],
        "summary": {
            "cpus_monitored": len(cpu_info),
            "bad_pages": len(bad_pages),
            "dmesg_events": len(dmesg_events),
        },
    }

    # Check for bad pages (retired memory)
    if bad_pages:
        analysis["status"] = "WARNING"
        analysis["issues"].append({
            "type": "bad_pages",
            "severity": "WARNING",
            "message": f"{len(bad_pages)} memory page(s) retired due to errors",
        })

    # Check dmesg events
    critical_events = [e for e in dmesg_events if e["severity"] == "CRITICAL"]
    warning_events = [e for e in dmesg_events if e["severity"] == "WARNING"]

    if critical_events:
        analysis["status"] = "CRITICAL"
        analysis["issues"].append({
            "type": "dmesg_critical",
            "severity": "CRITICAL",
            "message": f"{len(critical_events)} critical MCE event(s) in dmesg",
            "events": critical_events[:5],  # First 5 events
        })

    if warning_events:
        if analysis["status"] == "OK":
            analysis["status"] = "WARNING"
        analysis["issues"].append({
            "type": "dmesg_warning",
            "severity": "WARNING",
            "message": f"{len(warning_events)} warning MCE event(s) in dmesg",
            "events": warning_events[:5],
        })

    return analysis


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
        description="Monitor Machine Check Exceptions (MCE) for hardware faults"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed MCE configuration and all events",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show issues, suppress OK status messages",
    )
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Gather MCE data from all sources
    cpu_info = get_cpu_mce_info(context)
    bad_pages = get_ras_bad_pages(context)
    dmesg_events = parse_dmesg_mce(context)

    # Analyze collected data
    analysis = analyze_mce_data(cpu_info, bad_pages, dmesg_events)

    # Apply warn-only filter
    if opts.warn_only and analysis["status"] == "OK":
        output.emit({
            "status": "OK",
            "summary": analysis["summary"],
            "issues": [],
        })
        output.set_summary("No MCE issues detected")

        output.render(opts.format, "Monitor Machine Check Exceptions (MCE) for hardware faults")
        return 0

    # Build output data
    output_data = {
        "status": analysis["status"],
        "summary": analysis["summary"],
        "issues": analysis["issues"],
    }

    if bad_pages:
        output_data["bad_pages"] = bad_pages[:10]  # Limit to first 10
        if len(bad_pages) > 10:
            output_data["bad_pages_truncated"] = True
            output_data["bad_pages_total"] = len(bad_pages)

    if opts.verbose:
        # Include CPU MCE config
        output_data["cpu_mce_config"] = [
            {
                "cpu": cpu["cpu"],
                "tolerant": cpu.get("tolerant"),
                "check_interval": cpu.get("check_interval"),
                "bank_count": len(cpu.get("banks", [])),
            }
            for cpu in cpu_info[:16]  # Limit to first 16 CPUs
        ]

        # Include all dmesg events
        if dmesg_events:
            output_data["dmesg_events"] = dmesg_events[:20]  # Limit to 20

    output.emit(output_data)

    # Set summary
    if analysis["status"] == "CRITICAL":
        output.set_summary(f"CRITICAL: {len(analysis['issues'])} MCE issue(s) detected")

        output.render(opts.format, "Monitor Machine Check Exceptions (MCE) for hardware faults")
        return 1
    elif analysis["status"] == "WARNING":
        output.set_summary(f"WARNING: {len(analysis['issues'])} MCE issue(s) detected")

        output.render(opts.format, "Monitor Machine Check Exceptions (MCE) for hardware faults")
        return 1
    else:
        output.set_summary(f"MCE monitoring OK ({analysis['summary']['cpus_monitored']} CPUs)")

        output.render(opts.format, "Monitor Machine Check Exceptions (MCE) for hardware faults")
        return 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
