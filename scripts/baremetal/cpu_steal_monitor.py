#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [health, cpu, virtualization, performance]
#   related: [cpu_usage]
#   brief: Monitor CPU steal time for virtualized environments

"""
Monitor CPU steal time for virtualized environments.

CPU steal time represents the percentage of time a virtual CPU waits for a real
CPU while the hypervisor is servicing another virtual processor. High steal time
indicates the physical host is overcommitted and your VM is not getting its fair
share of CPU resources.

This is critical for:
- Cloud instances (AWS, GCP, Azure) where noisy neighbors steal CPU
- Virtualized datacenters running on overcommitted hypervisors
- Detecting hypervisor resource contention before it impacts applications

When to worry about steal time:
- < 5%: Normal for virtualized environments
- 5-10%: Elevated, monitor closely
- 10-20%: High, consider migrating or resizing VM
- > 20%: Critical, VM is severely resource-starved

Exit codes:
    0: Steal time within acceptable limits
    1: High steal time detected (exceeds warning threshold)
    2: Usage error or /proc filesystem not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_cpu_line(line: str) -> dict | None:
    """
    Parse a CPU line from /proc/stat.

    Format: cpu[N] user nice system idle iowait irq softirq steal guest guest_nice
    All values are in jiffies (typically 1/100th of a second).
    """
    parts = line.split()
    if len(parts) < 5:
        return None

    cpu_name = parts[0]
    try:
        values = [int(x) for x in parts[1:]]
    except ValueError:
        return None

    # Ensure we have enough fields (steal is field 8, index 7)
    while len(values) < 10:
        values.append(0)

    return {
        "cpu": cpu_name,
        "user": values[0],
        "nice": values[1],
        "system": values[2],
        "idle": values[3],
        "iowait": values[4],
        "irq": values[5],
        "softirq": values[6],
        "steal": values[7],
        "guest": values[8],
        "guest_nice": values[9],
    }


def parse_stat(content: str) -> dict:
    """Parse /proc/stat content and return CPU stats."""
    stats = {}
    for line in content.strip().split("\n"):
        if line.startswith("cpu"):
            parsed = parse_cpu_line(line)
            if parsed:
                stats[parsed["cpu"]] = parsed
    return stats


def calculate_percentages(stats: dict) -> dict:
    """Calculate percentage breakdown for CPU stats."""
    total = sum(
        stats.get(k, 0)
        for k in ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice"]
    )
    if total == 0:
        return {k: 0.0 for k in stats if k != "cpu"}

    return {
        k: round((v / total) * 100, 2)
        for k, v in stats.items()
        if k != "cpu"
    }


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
        description="Monitor CPU steal time for virtualized environments"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show per-CPU breakdown")
    parser.add_argument(
        "--format", choices=["plain", "json", "table"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show output if issues detected"
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=5.0,
        help="Warning threshold percentage (default: 5.0)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=15.0,
        help="Critical threshold percentage (default: 15.0)",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0 or opts.warn > 100:
        output.error("--warn must be 0-100")
        return 2
    if opts.crit < 0 or opts.crit > 100:
        output.error("--crit must be 0-100")
        return 2
    if opts.warn >= opts.crit:
        output.error("--warn must be less than --crit")
        return 2

    # Read /proc/stat
    try:
        stat_content = context.read_file("/proc/stat")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/stat: {e}")
        return 2

    cpu_stats = parse_stat(stat_content)

    if "cpu" not in cpu_stats:
        output.error("No CPU data found in /proc/stat")
        return 2

    # Analyze steal time
    issues = []
    warnings_list = []
    cpus_data = {}

    for cpu_name in sorted(cpu_stats.keys()):
        stats = cpu_stats[cpu_name]
        percentages = calculate_percentages(stats)
        steal_pct = percentages.get("steal", 0.0)

        cpus_data[cpu_name] = {
            "user": percentages.get("user", 0.0),
            "nice": percentages.get("nice", 0.0),
            "system": percentages.get("system", 0.0),
            "idle": percentages.get("idle", 0.0),
            "iowait": percentages.get("iowait", 0.0),
            "irq": percentages.get("irq", 0.0),
            "softirq": percentages.get("softirq", 0.0),
            "steal": steal_pct,
            "guest": percentages.get("guest", 0.0),
        }

        # Check per-CPU issues (exclude aggregate)
        if cpu_name != "cpu":
            if steal_pct >= opts.crit:
                issues.append({
                    "cpu": cpu_name,
                    "severity": "critical",
                    "steal_pct": steal_pct,
                    "message": f"{cpu_name}: steal time {steal_pct:.1f}% (critical threshold: {opts.crit}%)",
                })
            elif steal_pct >= opts.warn:
                warnings_list.append({
                    "cpu": cpu_name,
                    "severity": "warning",
                    "steal_pct": steal_pct,
                    "message": f"{cpu_name}: steal time {steal_pct:.1f}% (warning threshold: {opts.warn}%)",
                })

    # Check aggregate steal
    aggregate = cpus_data.get("cpu", {})
    aggregate_steal = aggregate.get("steal", 0.0)

    if aggregate_steal >= opts.crit:
        issues.insert(0, {
            "cpu": "aggregate",
            "severity": "critical",
            "steal_pct": aggregate_steal,
            "message": f"System-wide steal time {aggregate_steal:.1f}% exceeds critical threshold ({opts.crit}%)",
        })
    elif aggregate_steal >= opts.warn:
        warnings_list.insert(0, {
            "cpu": "aggregate",
            "severity": "warning",
            "steal_pct": aggregate_steal,
            "message": f"System-wide steal time {aggregate_steal:.1f}% exceeds warning threshold ({opts.warn}%)",
        })

    # Calculate summary
    steal_values = [
        cpus_data[k]["steal"]
        for k in cpus_data
        if k != "cpu"
    ]

    summary = {
        "cpu_count": len(steal_values),
        "avg_steal_pct": round(sum(steal_values) / len(steal_values), 2) if steal_values else 0,
        "max_steal_pct": round(max(steal_values), 2) if steal_values else 0,
        "min_steal_pct": round(min(steal_values), 2) if steal_values else 0,
        "aggregate_steal_pct": aggregate_steal,
        "warn_threshold": opts.warn,
        "crit_threshold": opts.crit,
    }

    # Determine status
    has_issues = len(issues) > 0
    has_warnings = len(warnings_list) > 0
    status = "critical" if has_issues else ("warning" if has_warnings else "ok")

    # Build result
    result = {
        "status": status,
        "summary": summary,
        "issues": issues,
        "warnings": warnings_list,
        "cpus": cpus_data,
    }

    # Early return for warn-only
    if opts.warn_only and not issues and not warnings_list:
        return 0

    # Output
    if opts.format == "json":
        print(json.dumps(result, indent=2))
    elif opts.format == "table":
        lines = []
        lines.append(f"{'CPU':<8} {'User':>8} {'System':>8} {'Idle':>8} {'IOWait':>8} {'Steal':>8} {'Status':<10}")
        lines.append("=" * 70)

        for cpu_name, data in sorted(cpus_data.items()):
            cpu_status = "OK"
            for issue in issues:
                if issue["cpu"] == cpu_name or (cpu_name == "cpu" and issue["cpu"] == "aggregate"):
                    cpu_status = "CRITICAL"
                    break
            if cpu_status == "OK":
                for warning in warnings_list:
                    if warning["cpu"] == cpu_name or (cpu_name == "cpu" and warning["cpu"] == "aggregate"):
                        cpu_status = "WARNING"
                        break

            label = "TOTAL" if cpu_name == "cpu" else cpu_name
            lines.append(
                f"{label:<8} {data['user']:>7.1f}% {data['system']:>7.1f}% "
                f"{data['idle']:>7.1f}% {data['iowait']:>7.1f}% {data['steal']:>7.1f}% {cpu_status:<10}"
            )

        print("\n".join(lines))
    else:
        lines = []
        lines.append("CPU Steal Time Monitor")
        lines.append("=" * 60)
        lines.append("")

        # Show issues first
        if issues:
            lines.append("CRITICAL:")
            for issue in issues:
                lines.append(f"  [!!] {issue['message']}")
            lines.append("")

        if warnings_list:
            lines.append("WARNINGS:")
            for warning in warnings_list:
                lines.append(f"  [!] {warning['message']}")
            lines.append("")

        # System summary
        lines.append("System-wide CPU usage:")
        lines.append(f"  User:     {aggregate.get('user', 0):>6.1f}%")
        lines.append(f"  System:   {aggregate.get('system', 0):>6.1f}%")
        lines.append(f"  Idle:     {aggregate.get('idle', 0):>6.1f}%")
        lines.append(f"  I/O Wait: {aggregate.get('iowait', 0):>6.1f}%")
        lines.append(f"  Steal:    {aggregate.get('steal', 0):>6.1f}%")
        lines.append("")

        lines.append(f"Steal time statistics ({summary['cpu_count']} CPUs):")
        lines.append(f"  Average: {summary['avg_steal_pct']:.2f}%")
        lines.append(f"  Maximum: {summary['max_steal_pct']:.2f}%")
        lines.append(f"  Minimum: {summary['min_steal_pct']:.2f}%")
        lines.append("")

        if opts.verbose:
            lines.append("Per-CPU steal time:")
            lines.append("-" * 60)
            lines.append(f"{'CPU':<8} {'User':>8} {'System':>8} {'Idle':>8} {'IOWait':>8} {'Steal':>8}")
            lines.append("-" * 60)

            for cpu_name, data in sorted(cpus_data.items()):
                if cpu_name == "cpu":
                    continue
                lines.append(
                    f"{cpu_name:<8} {data['user']:>7.1f}% {data['system']:>7.1f}% "
                    f"{data['idle']:>7.1f}% {data['iowait']:>7.1f}% {data['steal']:>7.1f}%"
                )
            lines.append("")

        if not issues and not warnings_list:
            lines.append(f"[OK] Steal time {aggregate_steal:.1f}% is within acceptable limits")

        print("\n".join(lines))

    # Set summary
    output.set_summary(f"steal={aggregate_steal:.1f}%, status={status}")

    return 1 if (issues or warnings_list) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
