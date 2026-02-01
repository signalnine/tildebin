#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cgroup
#   tags: [health, cgroup, psi, pressure, container, monitoring]
#   related: [proc_pressure, cgroup_memory_limits, cgroup_cpu_limits]
#   brief: Monitor cgroup v2 PSI (Pressure Stall Information) for resource contention

"""
Monitor cgroup v2 PSI (Pressure Stall Information) for resource contention.

Analyzes Pressure Stall Information from cgroup v2 to detect resource
contention issues on container hosts. PSI provides visibility into how much
time processes are stalled waiting for CPU, memory, or I/O resources.

PSI metrics:
- some: Percentage of time at least one task is stalled
- full: Percentage of time ALL tasks are stalled (more severe)

Useful for:
- Detecting container resource contention on Kubernetes nodes
- Identifying memory pressure before OOM kills occur
- Finding I/O bottlenecks affecting container performance
- Capacity planning on shared container hosts

Requirements:
- Linux kernel 4.20+ with CONFIG_PSI=y
- cgroup v2 unified hierarchy mounted

Exit codes:
    0: No pressure issues detected
    1: Pressure warnings or critical issues found
    2: Usage error or cgroup v2/PSI not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_pressure_file(content: str) -> dict:
    """
    Parse a PSI pressure file content.

    Format example:
    some avg10=0.00 avg60=0.00 avg300=0.00 total=0
    full avg10=0.00 avg60=0.00 avg300=0.00 total=0
    """
    result = {}
    for line in content.strip().split("\n"):
        parts = line.strip().split()
        if not parts:
            continue

        level = parts[0]  # 'some' or 'full'
        metrics = {}

        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                try:
                    metrics[key] = float(value) if key != "total" else int(value)
                except ValueError:
                    metrics[key] = value

        result[level] = metrics

    return result


def analyze_pressure(pressure: dict, warn_threshold: float, crit_threshold: float) -> list:
    """
    Analyze pressure metrics and return issues.

    Args:
        pressure: Dict of resource -> {some/full -> {avg10, avg60, avg300, total}}
        warn_threshold: Percentage above which to warn
        crit_threshold: Percentage above which to mark critical

    Returns:
        List of issues with severity
    """
    issues = []

    for resource, levels in pressure.items():
        for level, metrics in levels.items():
            # Check avg10 (10-second average) for immediate pressure
            avg10 = metrics.get("avg10", 0.0)

            if avg10 >= crit_threshold:
                issues.append({
                    "severity": "CRITICAL",
                    "resource": resource,
                    "level": level,
                    "avg10": avg10,
                    "avg60": metrics.get("avg60", 0.0),
                    "message": f"{resource.upper()} pressure ({level}): {avg10:.1f}% avg10",
                })
            elif avg10 >= warn_threshold:
                issues.append({
                    "severity": "WARNING",
                    "resource": resource,
                    "level": level,
                    "avg10": avg10,
                    "avg60": metrics.get("avg60", 0.0),
                    "message": f"{resource.upper()} pressure ({level}): {avg10:.1f}% avg10",
                })

    return issues


def format_pressure_summary(pressure: dict) -> str:
    """Format pressure data as a one-line summary."""
    parts = []
    for resource in ["cpu", "memory", "io"]:
        if resource in pressure:
            some = pressure[resource].get("some", {}).get("avg10", 0.0)
            full = pressure[resource].get("full", {}).get("avg10", 0.0)
            parts.append(f"{resource}={some:.1f}/{full:.1f}")
    return " ".join(parts)


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
        description="Monitor cgroup v2 PSI for resource contention"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show per-cgroup pressure breakdown"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format",
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=10.0,
        help="Warning threshold percentage (default: 10)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=25.0,
        help="Critical threshold percentage (default: 25)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show warnings and issues",
    )
    parser.add_argument(
        "--cgroup",
        help="Monitor specific cgroup path instead of system-wide",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if not 0.0 <= opts.warn <= 100.0:
        output.error("Warning threshold must be between 0 and 100")
        return 2

    if not 0.0 <= opts.crit <= 100.0:
        output.error("Critical threshold must be between 0 and 100")
        return 2

    if opts.warn >= opts.crit:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    # Check for cgroup v2 and PSI availability
    if not context.file_exists("/sys/fs/cgroup/cgroup.controllers"):
        output.error("cgroup v2 not mounted")
        output.error("Ensure kernel has cgroup v2 unified hierarchy enabled")
        return 2

    if not context.file_exists("/proc/pressure/cpu"):
        output.error("PSI not available (kernel may need CONFIG_PSI=y)")
        return 2

    # Get system-wide pressure from /proc/pressure
    system_pressure = {}
    for resource in ["cpu", "memory", "io"]:
        path = f"/proc/pressure/{resource}"
        try:
            content = context.read_file(path)
            system_pressure[resource] = parse_pressure_file(content)
        except (FileNotFoundError, IOError):
            pass

    if not system_pressure:
        output.error("Could not read pressure metrics from /proc/pressure")
        return 2

    # Analyze system pressure
    issues = analyze_pressure(system_pressure, opts.warn, opts.crit)

    # Get per-cgroup pressure if requested
    cgroup_data = []
    if opts.verbose or opts.cgroup:
        if opts.cgroup:
            # Monitor specific cgroup
            cgroup_path = opts.cgroup
            if not cgroup_path.startswith("/"):
                cgroup_path = f"/sys/fs/cgroup/{cgroup_path}"

            cgroup_pressure = {}
            for resource in ["cpu", "memory", "io"]:
                pressure_path = f"{cgroup_path}/{resource}.pressure"
                try:
                    content = context.read_file(pressure_path)
                    cgroup_pressure[resource] = parse_pressure_file(content)
                except (FileNotFoundError, IOError):
                    pass

            if cgroup_pressure:
                cgroup_data.append({
                    "name": opts.cgroup,
                    "path": cgroup_path,
                    "pressure": cgroup_pressure,
                })
                # Also analyze cgroup-specific issues
                cgroup_issues = analyze_pressure(cgroup_pressure, opts.warn, opts.crit)
                for issue in cgroup_issues:
                    issue["cgroup"] = opts.cgroup
                issues.extend(cgroup_issues)

    # Output results
    if opts.format == "json":
        result = {
            "system_pressure": system_pressure,
            "issues": issues,
            "summary": {
                "total_issues": len(issues),
                "critical_count": len([i for i in issues if i["severity"] == "CRITICAL"]),
                "warning_count": len([i for i in issues if i["severity"] == "WARNING"]),
            },
        }
        if opts.verbose and cgroup_data:
            result["cgroups"] = [
                {"name": cg["name"], "pressure": cg["pressure"]}
                for cg in cgroup_data
                if cg["pressure"]
            ]
        if not opts.warn_only or issues:
            print(json.dumps(result, indent=2))

    elif opts.format == "table":
        if not opts.warn_only or issues:
            lines = []
            lines.append(
                f"{'Resource':<10} {'Level':<8} {'avg10':<10} {'avg60':<10} {'avg300':<10}"
            )
            lines.append("-" * 50)

            for resource in ["cpu", "memory", "io"]:
                if resource in system_pressure:
                    for level in ["some", "full"]:
                        if level in system_pressure[resource]:
                            metrics = system_pressure[resource][level]
                            lines.append(
                                f"{resource:<10} {level:<8} "
                                f"{metrics.get('avg10', 0.0):<10.2f} "
                                f"{metrics.get('avg60', 0.0):<10.2f} "
                                f"{metrics.get('avg300', 0.0):<10.2f}"
                            )
            lines.append("")

            if issues:
                lines.append(
                    f"{'Severity':<10} {'Resource':<10} {'Level':<8} {'avg10':<10} {'Message':<40}"
                )
                lines.append("-" * 80)
                for issue in issues:
                    lines.append(
                        f"{issue['severity']:<10} {issue['resource']:<10} "
                        f"{issue['level']:<8} {issue['avg10']:<10.2f} "
                        f"{issue['message']:<40}"
                    )

            print("\n".join(lines))

    else:  # plain
        if not opts.warn_only or issues:
            lines = []
            lines.append("System-wide Pressure (some/full avg10):")
            lines.append(f"  {format_pressure_summary(system_pressure)}")
            lines.append("")

            if issues:
                critical = [i for i in issues if i["severity"] == "CRITICAL"]
                warnings = [i for i in issues if i["severity"] == "WARNING"]

                if critical:
                    lines.append(f"CRITICAL Issues ({len(critical)}):")
                    for issue in critical:
                        lines.append(f"  !!! {issue['message']}")
                    lines.append("")

                if warnings:
                    lines.append(f"Warnings ({len(warnings)}):")
                    for issue in warnings:
                        lines.append(f"  {issue['message']}")
                    lines.append("")
            else:
                lines.append("No pressure issues detected.")
                lines.append("")

            if opts.verbose and cgroup_data:
                lines.append("Per-Cgroup Pressure:")
                for cg in cgroup_data:
                    if cg["pressure"]:
                        lines.append(f"  {cg['name']}:")
                        lines.append(f"    {format_pressure_summary(cg['pressure'])}")

            print("\n".join(lines))

    # Set summary
    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warnings = any(i["severity"] == "WARNING" for i in issues)
    status = "critical" if has_critical else ("warning" if has_warnings else "healthy")
    output.set_summary(f"status={status}, issues={len(issues)}")

    return 1 if (has_critical or has_warnings) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
