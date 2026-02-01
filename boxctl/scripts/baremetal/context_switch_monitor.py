#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [health, cpu, scheduling, performance]
#   related: [cpu_usage, load_average]
#   brief: Monitor context switch rates for CPU contention

"""
Monitor context switch rates to detect CPU contention and scheduling overhead.

Context switches occur when the CPU switches from one process/thread to another.
High context switch rates can indicate:
- CPU contention (too many runnable processes)
- Excessive thread synchronization (lock contention)
- Poor process affinity (processes bouncing between CPUs)
- Interrupt storms causing frequent preemption

This script reads from /proc/stat to measure:
- System-wide context switches
- Per-CPU context switch rate
- Interrupt rates that may drive context switches
- Process/run queue metrics

Exit codes:
    0: No issues detected (context switch rates within thresholds)
    1: Warnings or issues detected (high context switch rates)
    2: Usage error or required files not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_stat(content: str) -> dict:
    """Parse /proc/stat for context switch and related metrics."""
    stats = {}
    cpu_count = 0

    for line in content.strip().split("\n"):
        parts = line.split()
        if not parts:
            continue

        if parts[0] == "ctxt":
            stats["context_switches"] = int(parts[1])
        elif parts[0] == "intr":
            stats["interrupts"] = int(parts[1])
        elif parts[0] == "processes":
            stats["processes_created"] = int(parts[1])
        elif parts[0] == "procs_running":
            stats["procs_running"] = int(parts[1])
        elif parts[0] == "procs_blocked":
            stats["procs_blocked"] = int(parts[1])
        elif parts[0].startswith("cpu") and parts[0][3:].isdigit():
            cpu_count += 1

    stats["cpu_count"] = cpu_count if cpu_count > 0 else 1
    return stats


def parse_vmstat(content: str) -> dict:
    """Parse /proc/vmstat for additional scheduling stats."""
    stats = {}

    for line in content.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            key, value = parts[0], parts[1]
            if key in ["nr_running", "nr_iowait", "pgfault", "pgmajfault"]:
                try:
                    stats[key] = int(value)
                except ValueError:
                    pass

    return stats


def analyze_issues(stats: dict, thresholds: dict) -> list:
    """Analyze context switch metrics for potential issues."""
    issues = []
    cpu_count = stats.get("cpu_count", 1)

    # Calculate per-CPU rates
    ctxt_per_cpu = stats.get("context_switches", 0) / cpu_count
    intr_per_cpu = stats.get("interrupts", 0) / cpu_count
    run_queue_per_cpu = stats.get("procs_running", 0) / cpu_count

    # Check context switch rate per CPU
    if ctxt_per_cpu >= thresholds["ctxt_per_cpu_critical"]:
        issues.append({
            "severity": "CRITICAL",
            "category": "context_switches",
            "message": f"Very high context switches: {ctxt_per_cpu:.0f} per CPU "
                      f"(threshold: {thresholds['ctxt_per_cpu_critical']:.0f})",
            "value": ctxt_per_cpu,
        })
    elif ctxt_per_cpu >= thresholds["ctxt_per_cpu_warning"]:
        issues.append({
            "severity": "WARNING",
            "category": "context_switches",
            "message": f"Elevated context switches: {ctxt_per_cpu:.0f} per CPU "
                      f"(threshold: {thresholds['ctxt_per_cpu_warning']:.0f})",
            "value": ctxt_per_cpu,
        })

    # Check interrupt rate per CPU
    if intr_per_cpu >= thresholds["intr_per_cpu_critical"]:
        issues.append({
            "severity": "CRITICAL",
            "category": "interrupts",
            "message": f"Very high interrupt rate: {intr_per_cpu:.0f} per CPU "
                      f"(threshold: {thresholds['intr_per_cpu_critical']:.0f})",
            "value": intr_per_cpu,
        })
    elif intr_per_cpu >= thresholds["intr_per_cpu_warning"]:
        issues.append({
            "severity": "WARNING",
            "category": "interrupts",
            "message": f"Elevated interrupt rate: {intr_per_cpu:.0f} per CPU "
                      f"(threshold: {thresholds['intr_per_cpu_warning']:.0f})",
            "value": intr_per_cpu,
        })

    # Check run queue depth
    if run_queue_per_cpu >= thresholds["run_queue_critical"]:
        issues.append({
            "severity": "CRITICAL",
            "category": "run_queue",
            "message": f"High run queue depth: {run_queue_per_cpu:.1f} per CPU "
                      f"({stats.get('procs_running', 0)} total runnable, "
                      f"threshold: {thresholds['run_queue_critical']:.0f})",
            "value": run_queue_per_cpu,
        })
    elif run_queue_per_cpu >= thresholds["run_queue_warning"]:
        issues.append({
            "severity": "WARNING",
            "category": "run_queue",
            "message": f"Elevated run queue depth: {run_queue_per_cpu:.1f} per CPU "
                      f"({stats.get('procs_running', 0)} total runnable, "
                      f"threshold: {thresholds['run_queue_warning']:.0f})",
            "value": run_queue_per_cpu,
        })

    # Check blocked processes
    procs_blocked = stats.get("procs_blocked", 0)
    if procs_blocked >= thresholds["blocked_critical"]:
        issues.append({
            "severity": "CRITICAL",
            "category": "blocked_processes",
            "message": f"Many blocked processes: {procs_blocked} "
                      f"(threshold: {thresholds['blocked_critical']})",
            "value": procs_blocked,
        })
    elif procs_blocked >= thresholds["blocked_warning"]:
        issues.append({
            "severity": "WARNING",
            "category": "blocked_processes",
            "message": f"Blocked processes detected: {procs_blocked} "
                      f"(threshold: {thresholds['blocked_warning']})",
            "value": procs_blocked,
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
        description="Monitor context switch rates to detect CPU contention"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show additional metrics")
    parser.add_argument(
        "--format", choices=["plain", "json", "table"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show issues"
    )
    parser.add_argument(
        "--ctxt-warn",
        type=float,
        default=20000000.0,
        help="Context switches per CPU warning threshold (default: 20000000)",
    )
    parser.add_argument(
        "--ctxt-crit",
        type=float,
        default=50000000.0,
        help="Context switches per CPU critical threshold (default: 50000000)",
    )
    parser.add_argument(
        "--intr-warn",
        type=float,
        default=50000000.0,
        help="Interrupts per CPU warning threshold (default: 50000000)",
    )
    parser.add_argument(
        "--intr-crit",
        type=float,
        default=100000000.0,
        help="Interrupts per CPU critical threshold (default: 100000000)",
    )
    parser.add_argument(
        "--run-queue-warn",
        type=float,
        default=2.0,
        help="Run queue depth per CPU warning threshold (default: 2.0)",
    )
    parser.add_argument(
        "--run-queue-crit",
        type=float,
        default=5.0,
        help="Run queue depth per CPU critical threshold (default: 5.0)",
    )
    parser.add_argument(
        "--blocked-warn",
        type=int,
        default=5,
        help="Blocked process count warning threshold (default: 5)",
    )
    parser.add_argument(
        "--blocked-crit",
        type=int,
        default=20,
        help="Blocked process count critical threshold (default: 20)",
    )
    opts = parser.parse_args(args)

    # Read /proc/stat
    try:
        stat_content = context.read_file("/proc/stat")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/stat: {e}")
        return 2

    stats = parse_stat(stat_content)

    if "context_switches" not in stats:
        output.error("No context switch data found in /proc/stat")
        return 2

    # Read optional /proc/vmstat
    vmstat = {}
    try:
        vmstat_content = context.read_file("/proc/vmstat")
        vmstat = parse_vmstat(vmstat_content)
    except (FileNotFoundError, IOError):
        pass

    # Build thresholds
    thresholds = {
        "ctxt_per_cpu_warning": opts.ctxt_warn,
        "ctxt_per_cpu_critical": opts.ctxt_crit,
        "intr_per_cpu_warning": opts.intr_warn,
        "intr_per_cpu_critical": opts.intr_crit,
        "run_queue_warning": opts.run_queue_warn,
        "run_queue_critical": opts.run_queue_crit,
        "blocked_warning": opts.blocked_warn,
        "blocked_critical": opts.blocked_crit,
    }

    # Analyze issues
    issues = analyze_issues(stats, thresholds)

    # Calculate per-CPU values
    cpu_count = stats.get("cpu_count", 1)
    ctxt_per_cpu = stats.get("context_switches", 0) / cpu_count
    intr_per_cpu = stats.get("interrupts", 0) / cpu_count

    summary = {
        "cpu_count": cpu_count,
        "context_switches_total": stats.get("context_switches", 0),
        "context_switches_per_cpu": round(ctxt_per_cpu, 1),
        "interrupts_total": stats.get("interrupts", 0),
        "interrupts_per_cpu": round(intr_per_cpu, 1),
        "procs_running": stats.get("procs_running", 0),
        "procs_blocked": stats.get("procs_blocked", 0),
        "processes_created": stats.get("processes_created", 0),
        "issue_count": len(issues),
        "critical_count": sum(1 for i in issues if i["severity"] == "CRITICAL"),
        "warning_count": sum(1 for i in issues if i["severity"] == "WARNING"),
    }

    if vmstat:
        summary["page_faults"] = vmstat.get("pgfault", 0)
        summary["major_page_faults"] = vmstat.get("pgmajfault", 0)

    # Determine status
    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warning = any(i["severity"] == "WARNING" for i in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")

    # Build result
    result = {
        "summary": summary,
        "context_switches": {
            "total": stats.get("context_switches", 0),
            "per_cpu": ctxt_per_cpu,
        },
        "interrupts": {
            "total": stats.get("interrupts", 0),
            "per_cpu": intr_per_cpu,
        },
        "processes": {
            "running": stats.get("procs_running", 0),
            "blocked": stats.get("procs_blocked", 0),
            "created": stats.get("processes_created", 0),
        },
        "issues": issues,
        "status": status,
    }

    # Early return for warn-only
    if opts.warn_only and not issues:
        return 0

    # Output
    if opts.format == "json":
        print(json.dumps(result, indent=2))
    elif opts.format == "table":
        lines = []
        lines.append(f"{'Metric':<30} {'Value':>15} {'Per CPU':>15}")
        lines.append("=" * 60)
        lines.append(
            f"{'Context switches':<30} {stats.get('context_switches', 0):>15,} {ctxt_per_cpu:>15,.0f}"
        )
        lines.append(
            f"{'Interrupts':<30} {stats.get('interrupts', 0):>15,} {intr_per_cpu:>15,.0f}"
        )
        lines.append(
            f"{'Processes running':<30} {stats.get('procs_running', 0):>15} "
            f"{stats.get('procs_running', 0) / cpu_count:>15.1f}"
        )
        lines.append(f"{'Processes blocked':<30} {stats.get('procs_blocked', 0):>15} {'-':>15}")
        lines.append("")

        if issues:
            lines.append(f"{'Severity':<10} {'Category':<20} {'Message':<50}")
            lines.append("=" * 80)
            for issue in issues:
                lines.append(f"{issue['severity']:<10} {issue['category']:<20} {issue['message'][:50]:<50}")

        print("\n".join(lines))
    else:
        lines = []
        lines.append("Context Switch Monitor")
        lines.append("=" * 50)
        lines.append(f"  CPUs: {cpu_count}")
        lines.append("")
        lines.append("Context Switches")
        lines.append("-" * 50)
        lines.append(f"  Total: {stats.get('context_switches', 0):,}")
        lines.append(f"  Per-CPU: {ctxt_per_cpu:,.0f}")
        lines.append("")
        lines.append("Interrupts")
        lines.append("-" * 50)
        lines.append(f"  Total: {stats.get('interrupts', 0):,}")
        lines.append(f"  Per-CPU: {intr_per_cpu:,.0f}")
        lines.append("")
        lines.append("Process Activity")
        lines.append("-" * 50)
        lines.append(f"  Processes running: {stats.get('procs_running', 0)}")
        lines.append(f"  Processes blocked: {stats.get('procs_blocked', 0)}")
        lines.append(f"  Processes created: {stats.get('processes_created', 0)}")

        if opts.verbose and vmstat:
            lines.append("")
            lines.append("Memory Activity")
            lines.append("-" * 50)
            lines.append(f"  Page faults: {vmstat.get('pgfault', 0):,}")
            lines.append(f"  Major page faults: {vmstat.get('pgmajfault', 0):,}")

        lines.append("")

        if issues:
            lines.append("Issues Detected")
            lines.append("=" * 50)
            for issue in sorted(issues, key=lambda x: (x["severity"] != "CRITICAL", x["category"])):
                marker = "!!!" if issue["severity"] == "CRITICAL" else "  "
                lines.append(f"{marker} [{issue['severity']}] {issue['message']}")
        else:
            lines.append("[OK] No issues detected")

        print("\n".join(lines))

    # Set summary
    output.set_summary(f"ctxt={ctxt_per_cpu:.0f}/cpu, running={stats.get('procs_running', 0)}, status={status}")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
