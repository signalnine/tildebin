#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [storage, sas, scsi, link, health, performance]
#   requires: []
#   privilege: user
#   related: [scsi_error_monitor, disk_health, multipath_health]
#   brief: Monitor SAS/SCSI link speeds and detect link degradation

"""
Monitor SAS/SCSI link speeds and detect link degradation.

Reads PHY information from /sys/class/sas_phy/ to detect:
- Link speed downgrades (negotiated < maximum)
- Invalid dword counts
- Loss of dword sync events
- Running disparity errors
- PHY reset problems

Exit codes:
    0 - All SAS links healthy (or no SAS hardware present)
    1 - Link degradation or errors detected
    2 - Usage error
"""

import argparse
import json
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output

SAS_PHY_PATH = "/sys/class/sas_phy"

ERROR_COUNTERS = [
    "invalid_dword_count",
    "loss_of_dword_sync_count",
    "running_disparity_error_count",
    "phy_reset_problem_count",
]


def read_sysfs_str(context: Context, path: str) -> str:
    """Read a string value from sysfs."""
    try:
        return context.read_file(path).strip()
    except (FileNotFoundError, IOError):
        return "unknown"


def read_sysfs_int(context: Context, path: str) -> int | None:
    """Read an integer value from sysfs."""
    try:
        content = context.read_file(path)
        return int(content.strip())
    except (FileNotFoundError, IOError, ValueError):
        return None


def get_phy_info(context: Context, phy_name: str) -> dict[str, Any]:
    """Read all SAS PHY attributes from sysfs."""
    base = f"{SAS_PHY_PATH}/{phy_name}"
    info: dict[str, Any] = {
        "phy": phy_name,
        "negotiated_linkrate": read_sysfs_str(context, f"{base}/negotiated_linkrate"),
        "maximum_linkrate": read_sysfs_str(context, f"{base}/maximum_linkrate"),
    }
    for counter in ERROR_COUNTERS:
        info[counter] = read_sysfs_int(context, f"{base}/{counter}")
    return info


def analyze_phy(info: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    """Analyze a PHY for issues.

    Returns:
        Tuple of (status, issues) where status is "ok" or "degraded"
        and issues is a list of dicts with severity and message.
    """
    issues: list[dict[str, str]] = []

    # Check for link speed downgrade
    negotiated = info["negotiated_linkrate"]
    maximum = info["maximum_linkrate"]
    if (
        negotiated != "unknown"
        and maximum != "unknown"
        and negotiated != maximum
    ):
        issues.append({
            "severity": "warning",
            "message": (
                f"{info['phy']}: negotiated {negotiated} below maximum {maximum}"
            ),
        })

    # Check error counters
    for counter in ERROR_COUNTERS:
        value = info[counter]
        if value is not None and value > 0:
            label = counter.replace("_", " ")
            issues.append({
                "severity": "warning",
                "message": f"{info['phy']}: {label} = {value}",
            })

    status = "degraded" if issues else "ok"
    return status, issues


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
        description="Monitor SAS/SCSI link speeds and detect link degradation"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: %(default)s)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed PHY information",
    )

    opts = parser.parse_args(args)

    # Check if SAS hardware exists
    if not context.is_dir(SAS_PHY_PATH):
        output.emit({"status": "ok", "phys": [], "issues": []})
        output.set_summary("No SAS hardware detected")
        output.render(opts.format, "SAS Link Health")
        return 0

    # Discover PHYs
    phy_entries = context.glob("*", SAS_PHY_PATH)
    if not phy_entries:
        output.emit({"status": "ok", "phys": [], "issues": []})
        output.set_summary("No SAS PHYs found")
        output.render(opts.format, "SAS Link Health")
        return 0

    # Analyze each PHY
    all_phys: list[dict[str, Any]] = []
    all_issues: list[dict[str, str]] = []
    has_issues = False

    for phy_path in phy_entries:
        phy_name = phy_path.split("/")[-1]
        info = get_phy_info(context, phy_name)
        status, issues = analyze_phy(info)

        phy_result: dict[str, Any] = {
            "phy": phy_name,
            "status": status,
            "negotiated_linkrate": info["negotiated_linkrate"],
            "maximum_linkrate": info["maximum_linkrate"],
        }
        for counter in ERROR_COUNTERS:
            phy_result[counter] = info[counter]

        all_phys.append(phy_result)
        all_issues.extend(issues)
        if issues:
            has_issues = True

    # Build output
    overall_status = "degraded" if has_issues else "ok"
    output_data: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": overall_status,
        "phys": all_phys,
        "issues": all_issues,
        "summary": {
            "total_phys": len(all_phys),
            "healthy": sum(1 for p in all_phys if p["status"] == "ok"),
            "degraded": sum(1 for p in all_phys if p["status"] == "degraded"),
            "total_issues": len(all_issues),
        },
        "healthy": not has_issues,
    }

    if opts.format == "json":
        print(json.dumps(output_data, indent=2))
    else:
        lines = []
        lines.append("SAS Link Health")
        lines.append("=" * 70)
        lines.append("")

        if not all_phys:
            lines.append("No SAS PHYs found.")
        else:
            for phy in all_phys:
                status_symbol = "OK" if phy["status"] == "ok" else "WARNING"
                line = (
                    f"[{status_symbol}] {phy['phy']}: "
                    f"{phy['negotiated_linkrate']} "
                    f"(max: {phy['maximum_linkrate']})"
                )
                lines.append(line)

                # Show error counters if non-zero or verbose
                for counter in ERROR_COUNTERS:
                    value = phy[counter]
                    if value is not None and (value > 0 or opts.verbose):
                        label = counter.replace("_", " ")
                        lines.append(f"    {label}: {value}")

            lines.append("")

            if all_issues:
                lines.append(f"Issues ({len(all_issues)}):")
                for issue in all_issues:
                    lines.append(
                        f"  [{issue['severity'].upper()}] {issue['message']}"
                    )
            else:
                lines.append("No issues detected.")

            lines.append("")
            lines.append(
                f"Summary: {len(all_phys)} PHYs checked, "
                f"{output_data['summary']['degraded']} with issues"
            )

        print("\n".join(lines))

    output.set_summary(
        f"total={output_data['summary']['total_phys']}, "
        f"degraded={output_data['summary']['degraded']}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
