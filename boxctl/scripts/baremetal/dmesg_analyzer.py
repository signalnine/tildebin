#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [health, kernel, hardware, errors, dmesg]
#   requires: [dmesg]
#   brief: Analyze kernel messages for hardware errors and warnings

"""
Analyze kernel messages (dmesg) for hardware errors and warnings.

Parses kernel ring buffer messages to detect hardware issues including:
- Disk I/O errors and timeouts
- Memory/ECC errors
- PCIe errors and link issues
- CPU errors and MCE events
- Network errors
- Filesystem errors
- RAID controller issues

Exit codes:
    0: No critical errors or warnings found
    1: Errors or warnings found in kernel messages
    2: Usage error or dmesg not available
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Error patterns organized by category
ERROR_PATTERNS = {
    "disk": [
        (r"(ata\d+\.\d+|sd[a-z]+): (.*(error|failed|timeout).*)", "CRITICAL"),
        (r"(nvme\d+n\d+): (.*(error|failed|timeout).*)", "CRITICAL"),
        (r"Buffer I/O error on.*", "CRITICAL"),
        (r"lost page write due to I/O error.*", "CRITICAL"),
        (r"(sd[a-z]+|nvme\d+n\d+): rejecting I/O.*", "WARNING"),
    ],
    "memory": [
        (r"(EDAC|ECC|CE|UE):.*error.*", "CRITICAL"),
        (r"Hardware Error.*memory.*", "CRITICAL"),
        (r"memory: page allocation failure.*", "WARNING"),
        (r"Out of memory.*", "CRITICAL"),
    ],
    "pcie": [
        (r"PCIe Bus Error.*", "CRITICAL"),
        (r"AER:.*error.*", "CRITICAL"),
        (r"pciehp.*failed.*", "WARNING"),
        (r"PCIe.*link.*down.*", "WARNING"),
    ],
    "cpu": [
        (r"mce:.*machine check.*", "CRITICAL"),
        (r"MCE:.*CPU.*error.*", "CRITICAL"),
        (r"CPU\d+.*microcode.*", "WARNING"),
        (r"thermal.*critical.*", "CRITICAL"),
    ],
    "network": [
        (r"(eth\d+|ens\d+|enp\d+s\d+):.*link.*down.*", "WARNING"),
        (r"(eth\d+|ens\d+|enp\d+s\d+):.*transmit timeout.*", "WARNING"),
        (r"NETDEV WATCHDOG.*", "WARNING"),
    ],
    "filesystem": [
        (r"(ext4|xfs|btrfs)-fs.*error.*", "CRITICAL"),
        (r"(EXT4|XFS|BTRFS)-fs.*warning.*", "WARNING"),
        (r"journal commit I/O error.*", "CRITICAL"),
    ],
    "raid": [
        (r"md\d+:.*failed.*", "CRITICAL"),
        (r"md\d+:.*error.*", "CRITICAL"),
        (r"md: .*removed from array.*", "WARNING"),
    ],
    "thermal": [
        (r"temperature above threshold.*", "CRITICAL"),
        (r"CPU\d+.*thermal.*throttling.*", "WARNING"),
        (r"coretemp.*critical temperature.*", "CRITICAL"),
    ],
}


def analyze_dmesg(dmesg_output: str) -> dict[str, list[dict[str, str]]]:
    """Analyze dmesg output for errors and warnings."""
    findings: dict[str, list[dict[str, str]]] = defaultdict(list)

    for line in dmesg_output.split("\n"):
        if not line.strip():
            continue

        for category, patterns in ERROR_PATTERNS.items():
            for pattern, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings[category].append(
                        {
                            "severity": severity,
                            "message": line.strip(),
                            "pattern": pattern,
                        }
                    )
                    break  # Only match first pattern per line

    return dict(findings)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze kernel messages for hardware errors and warnings"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full messages")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show issues, suppress no-error message"
    )
    opts = parser.parse_args(args)

    # Check for dmesg
    if not context.check_tool("dmesg"):
        output.error("dmesg not found. Install util-linux package.")
        return 2

    # Run dmesg
    try:
        dmesg_result = context.run(["dmesg", "-T"], check=False)
        if dmesg_result.returncode != 0:
            # Try without -T flag for older versions
            dmesg_result = context.run(["dmesg"], check=False)
        dmesg_output = dmesg_result.stdout
    except Exception as e:
        output.error(f"Failed to run dmesg: {e}")
        return 2

    # Analyze output
    findings = analyze_dmesg(dmesg_output)

    # Count issues
    total_issues = sum(len(issues) for issues in findings.values())
    critical_count = sum(
        1 for issues in findings.values() for i in issues if i["severity"] == "CRITICAL"
    )
    warning_count = sum(
        1 for issues in findings.values() for i in issues if i["severity"] == "WARNING"
    )

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_categories": len(findings),
            "total_issues": total_issues,
            "critical_count": critical_count,
            "warning_count": warning_count,
        },
        "findings": {
            category: [
                {"severity": i["severity"], "message": i["message"]}
                for i in issues
            ]
            for category, issues in findings.items()
        },
    }

    # Output handling
    if opts.format == "json":
        print(json.dumps(result, indent=2))
    else:
        if not findings:
            if not opts.warn_only:
                print("No kernel errors or warnings detected")
        else:
            # Sort categories by severity (CRITICAL first)
            categories_sorted = sorted(
                findings.items(),
                key=lambda x: (
                    min((f["severity"] for f in x[1]), default="WARNING") != "CRITICAL",
                    x[0],
                ),
            )

            for category, issues in categories_sorted:
                if not issues:
                    continue

                critical = sum(1 for i in issues if i["severity"] == "CRITICAL")
                warning = sum(1 for i in issues if i["severity"] == "WARNING")

                print(
                    f"\n{category.upper()}: {len(issues)} issue(s) "
                    f"({critical} critical, {warning} warnings)"
                )
                print("-" * 60)

                for issue in issues:
                    severity_marker = "!!!" if issue["severity"] == "CRITICAL" else "  "
                    msg = issue["message"]
                    if not opts.verbose and len(msg) > 100:
                        msg = msg[:97] + "..."
                    print(f"{severity_marker} {msg}")

    # Store data for output helper
    output.emit(result)
    output.set_summary(f"critical={critical_count}, warnings={warning_count}")

    # Exit based on findings
    return 1 if critical_count > 0 or warning_count > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
