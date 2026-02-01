#!/usr/bin/env python3
# boxctl:
#   category: baremetal/pressure
#   tags: [health, psi, pressure, performance, monitoring]
#   related: [cgroup_pressure, cpu_usage, memory_usage]
#   brief: Monitor Linux PSI (Pressure Stall Information) metrics

"""
Monitor Linux PSI (Pressure Stall Information) metrics.

Monitors /proc/pressure/{cpu,memory,io} to detect resource contention.
PSI provides early warning of resource pressure before visible performance
degradation, making it valuable for baremetal fleet monitoring.

PSI tracks three resources:
- CPU: Tasks waiting for CPU time
- Memory: Tasks stalled on memory operations (reclaim, swap)
- I/O: Tasks waiting for I/O completion

Each resource reports:
- some: Percentage of time at least one task was stalled
- full: Percentage of time ALL tasks were stalled (not for CPU)

Requirements:
- Linux kernel 4.20+ with CONFIG_PSI=y
- /proc/pressure/{cpu,memory,io} readable

Exit codes:
    0: All pressure metrics within acceptable thresholds
    1: Pressure thresholds exceeded (resource contention detected)
    2: Usage error or PSI not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_pressure_line(line: str) -> tuple[str, dict] | None:
    """
    Parse a single PSI line into a dictionary.

    Example line: some avg10=0.00 avg60=0.00 avg300=0.00 total=0
    Returns: ('some', {'avg10': 0.0, 'avg60': 0.0, 'avg300': 0.0, 'total': 0})
    """
    parts = line.strip().split()
    if len(parts) < 2:
        return None

    metric_type = parts[0]  # 'some' or 'full'
    values = {}

    for part in parts[1:]:
        if "=" in part:
            key, val = part.split("=", 1)
            try:
                if key == "total":
                    values[key] = int(val)
                else:
                    values[key] = float(val)
            except ValueError:
                values[key] = val

    return metric_type, values


def parse_pressure_file(content: str) -> dict:
    """Parse a PSI pressure file content."""
    result = {}
    for line in content.strip().split("\n"):
        parsed = parse_pressure_line(line)
        if parsed:
            metric_type, values = parsed
            result[metric_type] = values
    return result


def analyze_pressure(
    metrics: dict, warn_some: float, crit_some: float, warn_full: float, crit_full: float
) -> dict:
    """Analyze PSI metrics against thresholds and identify issues."""
    issues = []
    warnings = []

    for resource, data in metrics.items():
        if "error" in data:
            warnings.append(f"{resource}: {data['error']}")
            continue

        # Check 'some' pressure (at least one task stalled)
        if "some" in data:
            for window in ["avg10", "avg60", "avg300"]:
                if window in data["some"]:
                    val = data["some"][window]
                    if val >= crit_some:
                        issues.append({
                            "severity": "CRITICAL",
                            "resource": resource,
                            "type": "some",
                            "window": window,
                            "value": val,
                            "threshold": crit_some,
                            "message": f"{resource} {window} some={val:.2f}% (critical >= {crit_some}%)",
                        })
                    elif val >= warn_some:
                        warnings.append({
                            "severity": "WARNING",
                            "resource": resource,
                            "type": "some",
                            "window": window,
                            "value": val,
                            "threshold": warn_some,
                            "message": f"{resource} {window} some={val:.2f}% (warning >= {warn_some}%)",
                        })

        # Check 'full' pressure (all tasks stalled) - not applicable to CPU
        if "full" in data:
            for window in ["avg10", "avg60", "avg300"]:
                if window in data["full"]:
                    val = data["full"][window]
                    if val >= crit_full:
                        issues.append({
                            "severity": "CRITICAL",
                            "resource": resource,
                            "type": "full",
                            "window": window,
                            "value": val,
                            "threshold": crit_full,
                            "message": f"{resource} {window} full={val:.2f}% (critical >= {crit_full}%)",
                        })
                    elif val >= warn_full:
                        warnings.append({
                            "severity": "WARNING",
                            "resource": resource,
                            "type": "full",
                            "window": window,
                            "value": val,
                            "threshold": warn_full,
                            "message": f"{resource} {window} full={val:.2f}% (warning >= {warn_full}%)",
                        })

    # Determine overall status
    if issues:
        status = "critical"
    elif warnings:
        status = "warning"
    else:
        status = "healthy"

    return {
        "status": status,
        "issues": issues,
        "warnings": warnings,
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
        description="Monitor Linux PSI (Pressure Stall Information) metrics"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed output"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format",
    )
    parser.add_argument(
        "--warn-some",
        type=float,
        default=10.0,
        help="Warning threshold for 'some' pressure %% (default: 10.0)",
    )
    parser.add_argument(
        "--crit-some",
        type=float,
        default=25.0,
        help="Critical threshold for 'some' pressure %% (default: 25.0)",
    )
    parser.add_argument(
        "--warn-full",
        type=float,
        default=5.0,
        help="Warning threshold for 'full' pressure %% (default: 5.0)",
    )
    parser.add_argument(
        "--crit-full",
        type=float,
        default=10.0,
        help="Critical threshold for 'full' pressure %% (default: 10.0)",
    )
    parser.add_argument(
        "--resource",
        "-r",
        choices=["cpu", "memory", "io", "all"],
        default="all",
        help="Resource to monitor (default: all)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues detected",
    )
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn_some >= opts.crit_some:
        output.error("--warn-some must be less than --crit-some")
        return 2

    if opts.warn_full >= opts.crit_full:
        output.error("--warn-full must be less than --crit-full")
        return 2

    # Check if PSI is available
    if not context.file_exists("/proc/pressure/cpu"):
        output.error("PSI not available on this system")
        output.error("Requires Linux kernel 4.20+ with CONFIG_PSI=y")
        return 2

    # Read PSI metrics
    resources = ["cpu", "memory", "io"] if opts.resource == "all" else [opts.resource]
    metrics = {}

    for resource in resources:
        path = f"/proc/pressure/{resource}"
        try:
            content = context.read_file(path)
            metrics[resource] = parse_pressure_file(content)
        except FileNotFoundError:
            metrics[resource] = {"error": "not available"}
        except IOError as e:
            metrics[resource] = {"error": str(e)}

    # Analyze
    analysis = analyze_pressure(
        metrics, opts.warn_some, opts.crit_some, opts.warn_full, opts.crit_full
    )

    # Format output
    if opts.format == "json":
        result = {
            "psi_available": True,
            "metrics": metrics,
            "status": analysis["status"],
            "issues": analysis["issues"],
            "warnings": analysis["warnings"],
        }
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            print(json.dumps(result, indent=2))
    elif opts.format == "table":
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            lines = []
            lines.append("+" + "-" * 72 + "+")
            lines.append("| Pressure Stall Information (PSI)" + " " * 39 + "|")
            lines.append("+" + "-" * 72 + "+")
            lines.append(
                f"| {'Resource':<10} | {'Type':<6} | {'10s':<8} | {'60s':<8} | "
                f"{'300s':<8} | {'Status':<10} |"
            )
            lines.append("+" + "-" * 72 + "+")

            for resource in resources:
                if resource not in metrics:
                    continue
                data = metrics[resource]
                if "error" in data:
                    lines.append(
                        f"| {resource.upper():<10} | {'ERR':<6} | {'-':<8} | {'-':<8} | "
                        f"{'-':<8} | {'ERROR':<10} |"
                    )
                    continue

                # Determine status for this resource
                resource_status = "healthy"
                for issue in analysis["issues"]:
                    if isinstance(issue, dict) and issue.get("resource") == resource:
                        resource_status = "CRITICAL"
                        break
                if resource_status != "CRITICAL":
                    for warn in analysis["warnings"]:
                        if isinstance(warn, dict) and warn.get("resource") == resource:
                            resource_status = "WARNING"
                            break

                if "some" in data:
                    some = data["some"]
                    lines.append(
                        f"| {resource.upper():<10} | {'some':<6} | "
                        f"{some.get('avg10', 0):>7.2f}% | "
                        f"{some.get('avg60', 0):>7.2f}% | "
                        f"{some.get('avg300', 0):>7.2f}% | {resource_status:<10} |"
                    )

                if "full" in data:
                    full = data["full"]
                    lines.append(
                        f"| {'':<10} | {'full':<6} | "
                        f"{full.get('avg10', 0):>7.2f}% | "
                        f"{full.get('avg60', 0):>7.2f}% | "
                        f"{full.get('avg300', 0):>7.2f}% | {'':<10} |"
                    )

            lines.append("+" + "-" * 72 + "+")
            overall = analysis["status"].upper()
            lines.append(f"| Overall Status: {overall:<54} |")
            lines.append("+" + "-" * 72 + "+")
            print("\n".join(lines))
    else:  # plain
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            lines = []
            lines.append("Pressure Stall Information (PSI) Monitor")
            lines.append("=" * 50)
            lines.append("")

            for resource in resources:
                if resource not in metrics:
                    lines.append(f"{resource.upper()}: not available")
                    continue

                data = metrics[resource]
                if "error" in data:
                    lines.append(f"{resource.upper()}: {data['error']}")
                    continue

                lines.append(f"{resource.upper()}:")

                if "some" in data:
                    some = data["some"]
                    lines.append(
                        f"  some: {some.get('avg10', 0):.2f}% (10s) "
                        f"{some.get('avg60', 0):.2f}% (60s) "
                        f"{some.get('avg300', 0):.2f}% (300s)"
                    )
                    if opts.verbose and "total" in some:
                        lines.append(f"        total: {some['total']:,} us")

                if "full" in data:
                    full = data["full"]
                    lines.append(
                        f"  full: {full.get('avg10', 0):.2f}% (10s) "
                        f"{full.get('avg60', 0):.2f}% (60s) "
                        f"{full.get('avg300', 0):.2f}% (300s)"
                    )
                    if opts.verbose and "total" in full:
                        lines.append(f"        total: {full['total']:,} us")

                lines.append("")

            # Show issues and warnings
            if analysis["issues"]:
                lines.append("ISSUES:")
                for issue in analysis["issues"]:
                    lines.append(f"  [!] {issue['message']}")
                lines.append("")

            if analysis["warnings"]:
                lines.append("WARNINGS:")
                for warning in analysis["warnings"]:
                    lines.append(f"  [*] {warning['message']}")
                lines.append("")

            # Summary
            if analysis["status"] == "healthy":
                lines.append("[OK] All pressure metrics within acceptable thresholds")
            elif analysis["status"] == "warning":
                lines.append(f"[WARN] {len(analysis['warnings'])} warning(s) detected")
            else:
                lines.append(f"[CRITICAL] {len(analysis['issues'])} issue(s) detected")

            print("\n".join(lines))

    # Set summary
    output.set_summary(f"status={analysis['status']}")

    return 1 if analysis["issues"] else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
