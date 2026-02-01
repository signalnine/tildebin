#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [health, cpu, interrupts, performance, irq]
#   related: [context_switch_monitor, cpu_usage]
#   brief: Monitor hardware interrupt distribution across CPUs

"""
Monitor hardware interrupt (IRQ) distribution across CPU cores.

Analyzes IRQ distribution to detect performance issues caused by poor interrupt
balancing. Unbalanced interrupts can cause CPU hotspots and bottleneck network/
storage performance, especially on high-speed NICs and NVMe devices.

Checks performed:
- IRQ distribution across CPU cores
- Detection of IRQs concentrated on single CPUs
- CPU0 overload detection (common issue)
- Per-device interrupt balance analysis

Exit codes:
    0: All interrupts are well-balanced
    1: Imbalanced interrupts detected
    2: Usage error or missing dependencies
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_interrupts(content: str) -> tuple[int, dict]:
    """
    Parse /proc/interrupts content.

    Returns:
        tuple of (num_cpus, irq_data dict)
    """
    lines = content.strip().split("\n")
    if not lines:
        return 0, {}

    # First line contains CPU headers
    header = lines[0].split()
    num_cpus = len([h for h in header if h.startswith("CPU")])

    irq_data = {}

    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue

        irq = parts[0].rstrip(":")

        # Parse CPU counts (next num_cpus columns)
        try:
            cpu_counts = [int(parts[i + 1]) for i in range(num_cpus)]
        except (IndexError, ValueError):
            continue

        # Device name is at the end (after IRQ type)
        device = " ".join(parts[num_cpus + 1:]) if len(parts) > num_cpus + 1 else "unknown"

        irq_data[irq] = {
            "cpu_counts": cpu_counts,
            "total": sum(cpu_counts),
            "device": device,
        }

    return num_cpus, irq_data


def analyze_balance(irq_data: dict, num_cpus: int, threshold: float = 0.8) -> tuple[list, list]:
    """
    Analyze IRQ balance across CPUs.

    Args:
        irq_data: IRQ data from parse_interrupts
        num_cpus: Number of CPUs
        threshold: If X% of interrupts go to one CPU, flag as imbalanced

    Returns:
        tuple of (issues list, cpu_totals list)
    """
    issues = []
    cpu_totals = [0] * num_cpus

    for irq, data in irq_data.items():
        total = data["total"]
        if total == 0:
            continue

        cpu_counts = data["cpu_counts"]
        max_count = max(cpu_counts)
        max_cpu = cpu_counts.index(max_count)

        # Update CPU totals
        for i, count in enumerate(cpu_counts):
            cpu_totals[i] += count

        # Check if this IRQ is heavily concentrated on one CPU
        if total > 100 and max_count / total > threshold:
            percentage = (max_count / total) * 100
            issues.append({
                "type": "irq_imbalance",
                "irq": irq,
                "device": data["device"],
                "cpu": max_cpu,
                "percentage": percentage,
                "total": total,
            })

    # Check overall CPU balance
    total_interrupts = sum(cpu_totals)
    if total_interrupts > 0:
        for cpu_id, count in enumerate(cpu_totals):
            percentage = (count / total_interrupts) * 100
            if percentage > (threshold * 100):
                issues.append({
                    "type": "cpu_overload",
                    "cpu": cpu_id,
                    "percentage": percentage,
                    "count": count,
                })

    return issues, cpu_totals


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
        description="Monitor hardware interrupt (IRQ) distribution across CPU cores"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show per-CPU distribution")
    parser.add_argument(
        "--format", choices=["plain", "json", "table"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show issues"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.8,
        help="Imbalance threshold (0.0-1.0, default: 0.8 = 80%%)",
    )
    opts = parser.parse_args(args)

    # Validate threshold
    if not 0.0 <= opts.threshold <= 1.0:
        output.error("Threshold must be between 0.0 and 1.0")
        return 2

    # Read /proc/interrupts
    try:
        interrupts_content = context.read_file("/proc/interrupts")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/interrupts: {e}")
        return 2

    num_cpus, irq_data = parse_interrupts(interrupts_content)

    if num_cpus == 0 or not irq_data:
        output.error("Could not parse /proc/interrupts")
        return 2

    # Analyze balance
    issues, cpu_totals = analyze_balance(irq_data, num_cpus, opts.threshold)

    # Calculate totals
    total_interrupts = sum(cpu_totals)

    # Build result
    result = {
        "num_cpus": num_cpus,
        "total_interrupts": total_interrupts,
        "cpu_totals": cpu_totals,
        "issues": issues,
        "threshold": opts.threshold,
        "status": "healthy" if not issues else "warning",
    }

    # Early return for warn-only
    if opts.warn_only and not issues:
        return 0

    # Output
    if opts.format == "json":
        print(json.dumps(result, indent=2))
    elif opts.format == "table":
        lines = []
        lines.append(f"{'CPU':<6} {'Interrupts':>15} {'Percentage':>12}")
        lines.append("-" * 35)
        for cpu_id, count in enumerate(cpu_totals):
            percentage = (count / total_interrupts * 100) if total_interrupts > 0 else 0
            lines.append(f"CPU{cpu_id:<3} {count:>15,} {percentage:>11.1f}%")
        lines.append("")

        if issues:
            lines.append(f"{'Type':<15} {'Details':<60}")
            lines.append("-" * 75)
            for issue in issues:
                if issue["type"] == "cpu_overload":
                    details = f"CPU{issue['cpu']}: {issue['percentage']:.1f}% of interrupts"
                elif issue["type"] == "irq_imbalance":
                    dev = issue["device"][:40] if issue["device"] else "unknown"
                    details = f"IRQ {issue['irq']} ({dev}): {issue['percentage']:.1f}% on CPU{issue['cpu']}"
                else:
                    details = str(issue)
                lines.append(f"{issue['type']:<15} {details:<60}")

        print("\n".join(lines))
    else:
        lines = []
        lines.append(f"CPU Count: {num_cpus}")
        lines.append(f"Total Interrupts: {total_interrupts:,}")
        lines.append("")

        if issues:
            lines.append(f"Found {len(issues)} interrupt balance issues:")
            lines.append("")
            for issue in issues:
                if issue["type"] == "cpu_overload":
                    lines.append(
                        f"[WARNING] CPU{issue['cpu']}: {issue['percentage']:.1f}% of all "
                        f"interrupts ({issue['count']:,} total)"
                    )
                elif issue["type"] == "irq_imbalance":
                    lines.append(
                        f"[WARNING] IRQ {issue['irq']} ({issue['device']}): "
                        f"{issue['percentage']:.1f}% on CPU{issue['cpu']} ({issue['total']:,} total)"
                    )
            lines.append("")
        else:
            lines.append("[OK] No interrupt balance issues detected")
            lines.append("")

        if opts.verbose:
            lines.append("Per-CPU Interrupt Distribution:")
            for cpu_id, count in enumerate(cpu_totals):
                percentage = (count / total_interrupts * 100) if total_interrupts > 0 else 0
                lines.append(f"  CPU{cpu_id}: {count:>12,} interrupts ({percentage:>5.1f}%)")

        print("\n".join(lines))

    # Set summary
    status = "healthy" if not issues else "warning"
    output.set_summary(f"cpus={num_cpus}, total={total_interrupts:,}, issues={len(issues)}, status={status}")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
