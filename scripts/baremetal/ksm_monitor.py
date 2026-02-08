#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [memory, ksm, deduplication, virtualization, performance]
#   requires: []
#   privilege: user
#   related: [memory_usage, hugepage_monitor, libvirt_health]
#   brief: Monitor Kernel Samepage Merging status and efficiency

"""
Monitor Kernel Samepage Merging (KSM) status and efficiency.

KSM is a memory deduplication feature that scans for identical pages across
processes and merges them into a single copy-on-write page. This is particularly
useful for virtualization workloads (KVM) where multiple VMs may share
identical memory pages.

This script monitors:
- KSM run state (stopped, running, unloading)
- Pages shared (deduplicated originals)
- Pages sharing (total savings from deduplication)
- Pages unshared (scanned but unique)
- Pages volatile (changed too fast to merge)
- Full scans completed
- Sleep interval between scans
- Sharing efficiency ratio

Exit codes:
    0: KSM healthy or stopped (informational)
    1: KSM running with low efficiency (wasting CPU)
    2: Usage error or KSM not available
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


KSM_SYSFS_BASE = "/sys/kernel/mm/ksm"

KSM_FILES = [
    "run",
    "pages_shared",
    "pages_sharing",
    "pages_unshared",
    "pages_volatile",
    "full_scans",
    "sleep_millisecs",
]

KSM_RUN_STATES = {
    0: "stopped",
    1: "running",
    2: "unloading",
}


def read_ksm_metrics(context: Context) -> dict[str, int]:
    """Read all KSM sysfs files and return metrics as integers."""
    metrics: dict[str, int] = {}
    for name in KSM_FILES:
        path = f"{KSM_SYSFS_BASE}/{name}"
        try:
            content = context.read_file(path)
            metrics[name] = int(content.strip())
        except (FileNotFoundError, ValueError):
            pass
    return metrics


def calculate_sharing_ratio(metrics: dict[str, int]) -> float | None:
    """Calculate sharing ratio: pages_sharing / (pages_sharing + pages_unshared).

    Returns None if the denominator is zero.
    """
    pages_sharing = metrics.get("pages_sharing", 0)
    pages_unshared = metrics.get("pages_unshared", 0)
    denominator = pages_sharing + pages_unshared
    if denominator <= 0:
        return None
    return pages_sharing / denominator


def analyze_ksm(metrics: dict[str, int]) -> list[dict[str, Any]]:
    """Analyze KSM metrics and return issues list."""
    issues: list[dict[str, Any]] = []

    run_state = metrics.get("run", 0)

    if run_state == 0:
        issues.append({
            "severity": "INFO",
            "type": "ksm_stopped",
            "message": "KSM is stopped (not actively merging pages)",
        })
        return issues

    if run_state == 2:
        issues.append({
            "severity": "INFO",
            "type": "ksm_unloading",
            "message": "KSM is unloading (pages being unmerged)",
        })
        return issues

    # KSM is running (run_state == 1)
    sharing_ratio = calculate_sharing_ratio(metrics)
    pages_unshared = metrics.get("pages_unshared", 0)

    if sharing_ratio is not None and sharing_ratio < 0.01 and pages_unshared > 1000:
        issues.append({
            "severity": "WARNING",
            "type": "low_efficiency",
            "sharing_ratio": sharing_ratio,
            "pages_sharing": metrics.get("pages_sharing", 0),
            "pages_unshared": pages_unshared,
            "message": (
                f"KSM sharing ratio very low: {sharing_ratio * 100:.2f}% "
                f"({metrics.get('pages_sharing', 0)} sharing vs "
                f"{pages_unshared} unshared) - wasting CPU scanning"
            ),
        })

    return issues


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
        description="Monitor Kernel Samepage Merging status and efficiency",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed KSM metrics",
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and errors",
    )
    opts = parser.parse_args(args)

    # Check KSM availability
    run_path = f"{KSM_SYSFS_BASE}/run"
    if not context.file_exists(run_path):
        output.error("KSM not available: /sys/kernel/mm/ksm/run not found")
        return 2

    # Read all KSM metrics
    metrics = read_ksm_metrics(context)

    if "run" not in metrics:
        output.error("Unable to read KSM run state")
        return 2

    # Calculate derived values
    run_state = metrics["run"]
    run_state_name = KSM_RUN_STATES.get(run_state, f"unknown({run_state})")
    sharing_ratio = calculate_sharing_ratio(metrics)

    # Analyze
    issues = analyze_ksm(metrics)

    has_warning = any(i["severity"] == "WARNING" for i in issues)
    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")

    # Build result data
    result: dict[str, Any] = {
        "run_state": run_state,
        "run_state_name": run_state_name,
        "pages_shared": metrics.get("pages_shared", 0),
        "pages_sharing": metrics.get("pages_sharing", 0),
        "pages_unshared": metrics.get("pages_unshared", 0),
        "pages_volatile": metrics.get("pages_volatile", 0),
        "full_scans": metrics.get("full_scans", 0),
        "sleep_millisecs": metrics.get("sleep_millisecs", 0),
        "sharing_ratio": round(sharing_ratio, 4) if sharing_ratio is not None else None,
        "status": status,
        "issues": issues,
    }

    # Output
    if opts.format == "json":
        if not opts.warn_only or issues:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or issues:
            lines = []
            lines.append("KSM Monitor")
            lines.append("=" * 40)
            lines.append(f"State: {run_state_name}")

            if run_state == 1:
                lines.append(f"Pages shared: {metrics.get('pages_shared', 0)}")
                lines.append(f"Pages sharing: {metrics.get('pages_sharing', 0)}")
                lines.append(f"Pages unshared: {metrics.get('pages_unshared', 0)}")
                lines.append(f"Pages volatile: {metrics.get('pages_volatile', 0)}")
                lines.append(f"Full scans: {metrics.get('full_scans', 0)}")
                lines.append(f"Sleep interval: {metrics.get('sleep_millisecs', 0)} ms")
                if sharing_ratio is not None:
                    lines.append(f"Sharing ratio: {sharing_ratio * 100:.2f}%")
                lines.append("")

            if opts.verbose and run_state == 1:
                pages_sharing = metrics.get("pages_sharing", 0)
                saved_kb = pages_sharing * 4
                if saved_kb >= 1024 * 1024:
                    saved_str = f"{saved_kb / (1024 * 1024):.1f} GB"
                elif saved_kb >= 1024:
                    saved_str = f"{saved_kb / 1024:.1f} MB"
                else:
                    saved_str = f"{saved_kb} KB"
                lines.append(f"Estimated memory saved: {saved_str}")
                lines.append("")

            if issues:
                for issue in issues:
                    if opts.warn_only and issue["severity"] == "INFO":
                        continue
                    lines.append(f"[{issue['severity']}] {issue['message']}")
            elif not opts.warn_only:
                lines.append("[OK] KSM operating efficiently")

            print("\n".join(lines))

    # Emit structured data
    output.emit(result)

    # Set summary
    if run_state == 1:
        ratio_str = f"{sharing_ratio * 100:.2f}%" if sharing_ratio is not None else "N/A"
        output.set_summary(
            f"state={run_state_name}, sharing_ratio={ratio_str}, status={status}"
        )
    else:
        output.set_summary(f"state={run_state_name}, status={status}")

    if has_critical or has_warning:
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
