#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, seccomp, sandbox, process, audit]
#   requires: []
#   privilege: root
#   related: [process_capabilities_auditor, security_modules, namespace_audit]
#   brief: Audit seccomp filter status across running processes

"""
Audit seccomp filter status across running processes.

Enumerates all running processes and checks their seccomp filtering mode
from /proc/[pid]/status. Seccomp (secure computing) restricts the system
calls a process can make, providing an important security sandbox layer.

Seccomp modes:
- 0: SECCOMP_MODE_DISABLED - no seccomp filtering
- 1: SECCOMP_MODE_STRICT  - only read/write/exit/sigreturn allowed
- 2: SECCOMP_MODE_FILTER  - BPF filter program restricts syscalls

This is an informational audit tool. It reports the seccomp status of all
processes and highlights those running without any seccomp filtering.

Exit codes:
    0: Audit completed successfully
    2: Usage error or /proc filesystem not available
"""

import argparse
import json
import re
import time
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


SECCOMP_MODES = {
    0: "disabled",
    1: "strict",
    2: "filter",
}


def parse_seccomp_field(status_content: str) -> int | None:
    """Parse the Seccomp field from /proc/[pid]/status content.

    Returns the seccomp mode (0, 1, or 2), or None if not found.
    """
    for line in status_content.split("\n"):
        if line.startswith("Seccomp:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                try:
                    return int(parts[1].strip())
                except ValueError:
                    return None
    return None


def parse_seccomp_filters(status_content: str) -> int | None:
    """Parse the Seccomp_filters field from /proc/[pid]/status content.

    Returns the number of seccomp filters, or None if not found.
    """
    for line in status_content.split("\n"):
        if line.startswith("Seccomp_filters:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                try:
                    return int(parts[1].strip())
                except ValueError:
                    return None
    return None


def parse_process_name(status_content: str) -> str | None:
    """Parse the Name field from /proc/[pid]/status content."""
    for line in status_content.split("\n"):
        if line.startswith("Name:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip()
    return None


def collect_seccomp_info(context: Context) -> list[dict]:
    """Collect seccomp status for all running processes.

    Returns a list of dicts with pid, comm, seccomp_mode, and filter_count.
    Processes that disappear during enumeration are silently skipped.
    """
    results = []

    try:
        proc_entries = context.glob("[0-9]*", root="/proc")
    except (IOError, OSError):
        return results

    for entry in proc_entries:
        try:
            pid = int(entry.split("/")[-1])
        except ValueError:
            continue

        # Read status file
        try:
            status_content = context.read_file(f"/proc/{pid}/status")
        except (FileNotFoundError, IOError):
            # Process may have exited between glob and read
            continue

        seccomp_mode = parse_seccomp_field(status_content)
        if seccomp_mode is None:
            # Kernel may not support seccomp field, skip
            continue

        filter_count = parse_seccomp_filters(status_content)

        # Get process name from comm file first, fall back to status Name field
        comm = None
        try:
            comm = context.read_file(f"/proc/{pid}/comm").strip()
        except (FileNotFoundError, IOError):
            pass

        if not comm:
            comm = parse_process_name(status_content) or "unknown"

        results.append({
            "pid": pid,
            "comm": comm,
            "seccomp_mode": seccomp_mode,
            "seccomp_mode_name": SECCOMP_MODES.get(seccomp_mode, f"unknown({seccomp_mode})"),
            "filter_count": filter_count,
        })

    # Sort by PID for consistent output
    results.sort(key=lambda x: x["pid"])
    return results


def generate_summary(processes: list[dict]) -> dict:
    """Generate summary statistics from collected seccomp data."""
    total = len(processes)
    mode_counts = {0: 0, 1: 0, 2: 0}

    for proc in processes:
        mode = proc["seccomp_mode"]
        if mode in mode_counts:
            mode_counts[mode] += 1

    filtered = mode_counts[1] + mode_counts[2]
    unfiltered = mode_counts[0]

    return {
        "total_processes": total,
        "seccomp_disabled": mode_counts[0],
        "seccomp_strict": mode_counts[1],
        "seccomp_filter": mode_counts[2],
        "filtered": filtered,
        "unfiltered": unfiltered,
    }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = audit completed, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit seccomp filter status across running processes"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show all processes, not just unfiltered ones",
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only produce output if unfiltered processes exist",
    )

    opts = parser.parse_args(args)

    # Check /proc availability
    if not context.file_exists("/proc"):
        output.error("/proc filesystem not available")
        return 2

    # Collect data
    try:
        processes = collect_seccomp_info(context)
    except Exception as e:
        output.error(f"Failed to scan processes: {e}")
        return 2

    summary = generate_summary(processes)
    unfiltered_processes = [p for p in processes if p["seccomp_mode"] == 0]

    # Handle warn-only mode
    if opts.warn_only and not unfiltered_processes:
        return 0

    # Build result data
    data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": summary,
        "unfiltered_processes": unfiltered_processes,
    }

    if opts.verbose:
        data["all_processes"] = processes

    # Output results
    if opts.format == "json":
        print(json.dumps(data, indent=2))
    elif opts.format == "table":
        _output_table(summary, unfiltered_processes, processes if opts.verbose else None)
    else:
        _output_plain(summary, unfiltered_processes, processes if opts.verbose else None)

    # Set summary
    output.set_summary(
        f"Seccomp audit: {summary['total_processes']} processes, "
        f"{summary['filtered']} filtered, {summary['unfiltered']} unfiltered"
    )

    return 0


def _output_plain(
    summary: dict, unfiltered: list[dict], all_processes: list[dict] | None
) -> None:
    """Output results in plain text format."""
    print("Seccomp Filter Audit")
    print("=" * 60)
    print(f"Total processes scanned: {summary['total_processes']}")
    print(f"Seccomp disabled (mode 0): {summary['seccomp_disabled']}")
    print(f"Seccomp strict  (mode 1): {summary['seccomp_strict']}")
    print(f"Seccomp filter  (mode 2): {summary['seccomp_filter']}")
    print(f"Filtered (mode 1+2): {summary['filtered']}")
    print(f"Unfiltered (mode 0): {summary['unfiltered']}")
    print()

    if unfiltered:
        print(f"Unfiltered Processes ({len(unfiltered)}):")
        print("-" * 60)
        print(f"{'PID':<8} {'Process':<30}")
        print("-" * 38)
        for proc in unfiltered:
            print(f"{proc['pid']:<8} {proc['comm']:<30}")
        print()

    if all_processes is not None:
        print(f"All Processes ({len(all_processes)}):")
        print("-" * 60)
        print(f"{'PID':<8} {'Process':<20} {'Mode':<10} {'Filters':<10}")
        print("-" * 48)
        for proc in all_processes:
            filters = str(proc["filter_count"]) if proc["filter_count"] is not None else "-"
            print(
                f"{proc['pid']:<8} {proc['comm']:<20} "
                f"{proc['seccomp_mode_name']:<10} {filters:<10}"
            )


def _output_table(
    summary: dict, unfiltered: list[dict], all_processes: list[dict] | None
) -> None:
    """Output results in table format."""
    print("=" * 60)
    print("SECCOMP FILTER AUDIT")
    print("=" * 60)
    print()

    print(f"{'Metric':<35} {'Value':<20}")
    print("-" * 55)
    print(f"{'Total processes':<35} {summary['total_processes']:<20}")
    print(f"{'Seccomp disabled (mode 0)':<35} {summary['seccomp_disabled']:<20}")
    print(f"{'Seccomp strict (mode 1)':<35} {summary['seccomp_strict']:<20}")
    print(f"{'Seccomp filter (mode 2)':<35} {summary['seccomp_filter']:<20}")
    print(f"{'Filtered (mode 1+2)':<35} {summary['filtered']:<20}")
    print(f"{'Unfiltered (mode 0)':<35} {summary['unfiltered']:<20}")
    print()

    if unfiltered:
        print(f"{'PID':<8} {'Process':<30} {'Mode':<15}")
        print("-" * 53)
        for proc in unfiltered:
            print(f"{proc['pid']:<8} {proc['comm']:<30} {'disabled':<15}")
        print()

    if all_processes is not None:
        print(f"{'PID':<8} {'Process':<20} {'Mode':<12} {'Filters':<10}")
        print("-" * 50)
        for proc in all_processes:
            filters = str(proc["filter_count"]) if proc["filter_count"] is not None else "-"
            print(
                f"{proc['pid']:<8} {proc['comm']:<20} "
                f"{proc['seccomp_mode_name']:<12} {filters:<10}"
            )


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
