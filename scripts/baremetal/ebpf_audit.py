#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, ebpf, bpf, kernel, audit]
#   requires: [bpftool]
#   privilege: root
#   related: [kernel_module_audit, security_modules]
#   brief: Audit loaded eBPF programs and maps for security review

"""
Audit loaded eBPF programs and maps for security review.

Uses bpftool to enumerate all loaded BPF programs and maps on the system.
This is useful for security audits to understand what BPF programs are
running, their types, and resource consumption.

Checks for:
- Excessive number of loaded BPF programs (>100, potential leak)
- Large BPF maps consuming significant memory (>1GB bytes_memlock)
- Tracing/kprobe type programs (noted for awareness)

Exit codes:
    0: No issues detected
    1: Warnings found (excessive programs, large maps)
    2: Usage error or bpftool not available
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output

# BPF program types that involve tracing/kprobes
TRACING_TYPES = {
    "kprobe",
    "tracepoint",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "perf_event",
    "tracing",
}

# Threshold for excessive program count
EXCESSIVE_PROGRAM_COUNT = 100

# Threshold for large map memory (1 GB in bytes)
LARGE_MAP_BYTES = 1_073_741_824


def parse_programs(raw: str) -> list[dict[str, Any]]:
    """Parse bpftool prog list JSON output.

    Args:
        raw: JSON string from bpftool prog list --json

    Returns:
        List of program dictionaries
    """
    data = json.loads(raw)
    if not isinstance(data, list):
        return []
    return data


def parse_maps(raw: str) -> list[dict[str, Any]]:
    """Parse bpftool map list JSON output.

    Args:
        raw: JSON string from bpftool map list --json

    Returns:
        List of map dictionaries
    """
    data = json.loads(raw)
    if not isinstance(data, list):
        return []
    return data


def count_programs_by_type(programs: list[dict[str, Any]]) -> dict[str, int]:
    """Count BPF programs grouped by type.

    Args:
        programs: List of program dicts from bpftool

    Returns:
        Dict mapping program type to count
    """
    counts: dict[str, int] = {}
    for prog in programs:
        prog_type = prog.get("type", "unknown")
        counts[prog_type] = counts.get(prog_type, 0) + 1
    return counts


def analyze_programs(programs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analyze BPF programs for issues.

    Args:
        programs: List of program dicts from bpftool

    Returns:
        List of issue dictionaries
    """
    issues = []

    # Check for excessive program count
    if len(programs) > EXCESSIVE_PROGRAM_COUNT:
        issues.append({
            "severity": "WARNING",
            "metric": "program_count",
            "value": len(programs),
            "threshold": EXCESSIVE_PROGRAM_COUNT,
            "message": f"Excessive BPF programs loaded: {len(programs)} "
                       f"(threshold: {EXCESSIVE_PROGRAM_COUNT})",
        })

    # Note tracing/kprobe programs for awareness
    tracing_programs = [
        p for p in programs if p.get("type", "") in TRACING_TYPES
    ]
    if tracing_programs:
        types_found = sorted(set(p.get("type", "") for p in tracing_programs))
        issues.append({
            "severity": "INFO",
            "metric": "tracing_programs",
            "value": len(tracing_programs),
            "message": f"{len(tracing_programs)} tracing/kprobe programs active "
                       f"(types: {', '.join(types_found)})",
        })

    return issues


def analyze_maps(maps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analyze BPF maps for issues.

    Args:
        maps: List of map dicts from bpftool

    Returns:
        List of issue dictionaries
    """
    issues = []

    for m in maps:
        bytes_memlock = m.get("bytes_memlock", 0)
        if isinstance(bytes_memlock, int) and bytes_memlock > LARGE_MAP_BYTES:
            map_name = m.get("name", "unnamed")
            map_id = m.get("id", "?")
            size_gb = bytes_memlock / (1024 ** 3)
            issues.append({
                "severity": "WARNING",
                "metric": "map_memory",
                "value": bytes_memlock,
                "threshold": LARGE_MAP_BYTES,
                "message": f"Large BPF map: id={map_id} name={map_name} "
                           f"({size_gb:.2f} GB memlock)",
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
        description="Audit loaded eBPF programs and maps for security review"
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show detailed program and map listings",
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true",
        help="Only show warnings and issues",
    )
    opts = parser.parse_args(args)

    # Check for bpftool
    if not context.check_tool("bpftool"):
        output.error("bpftool not found in PATH")
        output.render(opts.format, "eBPF Program and Map Audit")
        return 2

    # Get BPF programs
    try:
        prog_result = context.run(["bpftool", "prog", "list", "--json"])
        programs = parse_programs(prog_result.stdout)
    except (json.JSONDecodeError, KeyError) as e:
        output.error(f"Failed to parse bpftool prog output: {e}")
        output.render(opts.format, "eBPF Program and Map Audit")
        return 2
    except Exception as e:
        output.error(f"Failed to list BPF programs: {e}")
        output.render(opts.format, "eBPF Program and Map Audit")
        return 2

    # Get BPF maps
    try:
        map_result = context.run(["bpftool", "map", "list", "--json"])
        maps = parse_maps(map_result.stdout)
    except (json.JSONDecodeError, KeyError) as e:
        output.error(f"Failed to parse bpftool map output: {e}")
        output.render(opts.format, "eBPF Program and Map Audit")
        return 2
    except Exception as e:
        output.error(f"Failed to list BPF maps: {e}")
        output.render(opts.format, "eBPF Program and Map Audit")
        return 2

    # Analyze
    type_counts = count_programs_by_type(programs)
    prog_issues = analyze_programs(programs)
    map_issues = analyze_maps(maps)
    all_issues = prog_issues + map_issues

    # Separate warnings from informational
    warnings = [i for i in all_issues if i["severity"] == "WARNING"]

    # Build program summaries for output
    prog_summaries = []
    for prog in programs:
        summary: dict[str, Any] = {
            "id": prog.get("id"),
            "type": prog.get("type", "unknown"),
            "name": prog.get("name", ""),
        }
        if "tag" in prog:
            summary["tag"] = prog["tag"]
        if "loaded_at" in prog:
            summary["loaded_at"] = prog["loaded_at"]
        prog_summaries.append(summary)

    # Build map summaries for output
    map_summaries = []
    for m in maps:
        summary = {
            "id": m.get("id"),
            "type": m.get("type", "unknown"),
            "name": m.get("name", ""),
        }
        if "bytes_memlock" in m:
            summary["bytes_memlock"] = m["bytes_memlock"]
        map_summaries.append(summary)

    # Determine status
    has_warnings = len(warnings) > 0
    status = "warning" if has_warnings else "healthy"

    # Emit output data
    data: dict[str, Any] = {
        "status": status,
        "program_count": len(programs),
        "map_count": len(maps),
        "type_counts": type_counts,
        "issues": all_issues,
    }

    if opts.verbose or not opts.warn_only:
        data["programs"] = prog_summaries
        data["maps"] = map_summaries

    output.emit(data)

    # Set summary
    if has_warnings:
        warning_msgs = ", ".join(w["message"] for w in warnings[:2])
        output.set_summary(
            f"{len(programs)} programs, {len(maps)} maps, "
            f"{len(warnings)} warning(s): {warning_msgs}"
        )
    else:
        output.set_summary(
            f"{len(programs)} programs, {len(maps)} maps, no issues"
        )

    output.render(opts.format, "eBPF Program and Map Audit")

    if has_warnings:
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
