#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [health, kernel, taint, compliance, security]
#   brief: Monitor kernel taint status for system health

"""
Monitor kernel taint status for baremetal systems.

Kernel taints indicate various conditions that may affect kernel stability,
supportability, or debuggability. This script monitors and reports on kernel
taint flags.

Exit codes:
    0: Kernel is untainted (clean)
    1: Kernel is tainted (warnings/issues found)
    2: Usage error or unable to read taint status
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output

# Kernel taint bit definitions (from Documentation/admin-guide/tainted-kernels.rst)
TAINT_FLAGS = {
    0: ("P", "proprietary", "Proprietary module loaded", "warning"),
    1: ("F", "forced", "Module force loaded (modprobe -f)", "warning"),
    2: ("S", "smp_unsafe", "SMP-unsafe module loaded", "critical"),
    3: ("R", "forced_unload", "Module force unloaded (rmmod -f)", "warning"),
    4: ("M", "machine_check", "Machine check exception occurred", "critical"),
    5: ("B", "bad_page", "Bad memory page reference", "critical"),
    6: ("U", "userspace", "Userspace wrote to /dev/mem", "warning"),
    7: ("D", "oops", "Kernel oops has occurred", "critical"),
    8: ("A", "acpi", "ACPI table overridden by user", "info"),
    9: ("W", "warning", "Kernel warning has occurred", "warning"),
    10: ("C", "staging", "Staging driver loaded", "info"),
    11: ("I", "firmware", "Firmware bug workaround applied", "info"),
    12: ("O", "out_of_tree", "Out-of-tree module loaded", "warning"),
    13: ("E", "unsigned", "Unsigned module loaded", "warning"),
    14: ("L", "softlockup", "Soft lockup has occurred", "critical"),
    15: ("K", "live_patch", "Kernel live patch applied", "info"),
    16: ("X", "auxiliary", "Auxiliary taint (reserved)", "info"),
    17: ("T", "randstruct", "Randstruct randomization", "info"),
    18: ("N", "test", "Test taint (for testing only)", "info"),
}

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def decode_taint_value(taint_value: int) -> list[dict]:
    """Decode the taint bitmask into individual flags."""
    taints = []

    if taint_value == 0:
        return taints

    for bit, (flag, name, description, severity) in TAINT_FLAGS.items():
        if taint_value & (1 << bit):
            taints.append(
                {
                    "bit": bit,
                    "flag": flag,
                    "name": name,
                    "description": description,
                    "severity": severity,
                }
            )

    # Sort by severity (critical first)
    taints.sort(key=lambda t: SEVERITY_ORDER.get(t["severity"], 99))
    return taints


def get_taint_string(taint_value: int) -> str:
    """Get the taint string representation (e.g., 'P--S-M-')."""
    if taint_value == 0:
        return ""

    chars = []
    for bit in range(19):
        if bit in TAINT_FLAGS:
            flag = TAINT_FLAGS[bit][0]
            if taint_value & (1 << bit):
                chars.append(flag)
            else:
                chars.append("-")
        else:
            chars.append("-")

    return "".join(chars)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = untainted, 1 = tainted, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor kernel taint status for baremetal systems"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show output if tainted"
    )
    parser.add_argument(
        "--expected",
        metavar="TAINTS",
        help="Comma-separated list of expected taint names",
    )
    parser.add_argument(
        "--critical-only",
        action="store_true",
        help="Only exit 1 for critical taints",
    )
    opts = parser.parse_args(args)

    # Read taint value
    try:
        taint_content = context.read_file("/proc/sys/kernel/tainted")
        taint_value = int(taint_content.strip())
    except FileNotFoundError:
        output.error("/proc/sys/kernel/tainted not found")
        return 2
    except (ValueError, IOError) as e:
        output.error(f"Unable to read taint status: {e}")
        return 2

    # Decode taints
    taints = decode_taint_value(taint_value)
    taint_string = get_taint_string(taint_value)

    # Parse expected taints
    expected_taints = None
    unexpected_taints = []
    if opts.expected:
        expected_taints = [t.strip().lower() for t in opts.expected.split(",")]
        current_set = set(t["name"] for t in taints)
        expected_set = set(expected_taints)
        unexpected_taints = list(current_set - expected_set)

    # Build summary counts
    summary = {
        "total": len(taints),
        "critical": sum(1 for t in taints if t["severity"] == "critical"),
        "warning": sum(1 for t in taints if t["severity"] == "warning"),
        "info": sum(1 for t in taints if t["severity"] == "info"),
    }

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "taint_value": taint_value,
        "taint_string": taint_string,
        "is_tainted": taint_value != 0,
        "taints": taints,
        "summary": summary,
        "unexpected_taints": unexpected_taints,
    }

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or result["is_tainted"]:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or result["is_tainted"]:
            if not result["is_tainted"]:
                print("Kernel taint status: CLEAN (not tainted)")
            else:
                lines = []
                lines.append("Kernel taint status: TAINTED")
                lines.append(f"Taint value: {taint_value}")
                lines.append(f"Taint string: {taint_string}")
                lines.append("")
                lines.append(f"Summary: {summary['total']} taint(s) active")
                if summary["critical"] > 0:
                    lines.append(f"  Critical: {summary['critical']}")
                if summary["warning"] > 0:
                    lines.append(f"  Warning: {summary['warning']}")
                if summary["info"] > 0:
                    lines.append(f"  Info: {summary['info']}")
                lines.append("")
                lines.append("Active taints:")
                lines.append("-" * 60)
                for taint in taints:
                    severity_marker = (
                        "!!!"
                        if taint["severity"] == "critical"
                        else " ! "
                        if taint["severity"] == "warning"
                        else "   "
                    )
                    lines.append(
                        f"{severity_marker}[{taint['flag']}] {taint['name']}: {taint['description']}"
                    )
                    if opts.verbose:
                        lines.append(f"      Bit: {taint['bit']}, Severity: {taint['severity']}")

                if unexpected_taints:
                    lines.append("")
                    lines.append("Unexpected taints (not in baseline):")
                    for name in unexpected_taints:
                        lines.append(f"  - {name}")

                print("\n".join(lines))

    # Store data for output helper
    output.emit(result)
    status = "clean" if not result["is_tainted"] else "tainted"
    output.set_summary(f"status={status}, taints={summary['total']}")

    # Determine exit code
    if not result["is_tainted"]:
        return 0

    if opts.critical_only:
        return 1 if summary["critical"] > 0 else 0
    else:
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
