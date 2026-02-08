#!/usr/bin/env python3
# boxctl:
#   category: baremetal/interrupts
#   tags: [health, softirq, networking, performance, irq]
#   brief: Monitor softirq activity and detect CPU imbalance or overload

"""
Monitor softirq activity and detect CPU imbalance or overload.

Analyzes software interrupt (softirq) statistics from /proc/softirqs
to identify CPU cores that are overloaded with interrupt processing.

Useful for diagnosing:
- Network performance issues (NET_RX/NET_TX bottlenecks)
- Storage I/O latency (BLOCK softirqs)
- Timer-related jitter (TIMER, HRTIMER)
- CPU imbalance in interrupt handling
- RCU callback storms

Exit codes:
    0: Softirq distribution is balanced
    1: Imbalance or high softirq activity detected
    2: Usage error or /proc filesystem not available
"""

import argparse
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_softirqs(content: str) -> dict:
    """
    Parse /proc/softirqs content.

    Returns:
        dict: Nested dict of {softirq_type: {cpu_id: count}}
    """
    softirqs = defaultdict(dict)
    lines = content.strip().split("\n")

    if not lines:
        return dict(softirqs)

    # First line contains CPU headers
    header = lines[0].strip().split()
    cpu_count = len(header)

    # Parse each softirq type
    for line in lines[1:]:
        parts = line.strip().split()
        if len(parts) < 2:
            continue

        irq_type = parts[0].rstrip(":")
        counts = parts[1:]

        for i, count in enumerate(counts):
            if i < cpu_count:
                try:
                    softirqs[irq_type][i] = int(count)
                except ValueError:
                    softirqs[irq_type][i] = 0

    return dict(softirqs)


def analyze_softirqs(softirqs: dict, cpu_count: int, imbalance_threshold: float) -> dict:
    """
    Analyze softirq distribution for issues.

    Args:
        softirqs: Softirq counts by type and CPU
        cpu_count: Number of CPUs
        imbalance_threshold: Ratio threshold for CPU imbalance

    Returns:
        dict: Analysis results with issues and warnings
    """
    issues = []
    warnings = []

    # Key softirq types to monitor closely
    critical_types = ["NET_RX", "NET_TX", "BLOCK", "TIMER", "RCU"]

    # Calculate totals per type
    totals = {}
    for irq_type, counts in softirqs.items():
        totals[irq_type] = sum(counts.values())

    # Analyze each softirq type for imbalance
    for irq_type, counts in softirqs.items():
        if not counts:
            continue

        total = totals[irq_type]
        if total == 0:
            continue

        # Calculate per-CPU percentage
        cpu_percentages = {
            cpu: (count / total * 100) if total > 0 else 0
            for cpu, count in counts.items()
        }

        # Check for imbalance (one CPU handling much more than others)
        if cpu_count > 1 and len(counts) > 1:
            avg_percentage = 100.0 / cpu_count
            max_cpu = max(cpu_percentages.items(), key=lambda x: x[1])

            # Detect imbalance: max CPU handles significantly more than average
            if max_cpu[1] > avg_percentage * imbalance_threshold:
                msg = (
                    f"{irq_type}: CPU{max_cpu[0]} handles {max_cpu[1]:.1f}% "
                    f"(expected ~{avg_percentage:.1f}% per CPU)"
                )
                if irq_type in critical_types:
                    issues.append(
                        {
                            "type": "imbalance",
                            "irq_type": irq_type,
                            "cpu": max_cpu[0],
                            "percentage": round(max_cpu[1], 1),
                            "expected": round(avg_percentage, 1),
                            "message": msg,
                        }
                    )
                else:
                    warnings.append(
                        {
                            "type": "imbalance",
                            "irq_type": irq_type,
                            "cpu": max_cpu[0],
                            "percentage": round(max_cpu[1], 1),
                            "message": msg,
                        }
                    )

    status = "critical" if issues else ("warning" if warnings else "healthy")

    return {
        "totals": totals,
        "issues": issues,
        "warnings": warnings,
        "status": status,
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
        description="Monitor softirq activity and detect CPU imbalance"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--imbalance",
        type=float,
        default=2.5,
        metavar="RATIO",
        help="Imbalance ratio threshold (default: 2.5)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues detected",
    )
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.imbalance <= 1:
        output.error("--imbalance must be greater than 1")
        return 2

    # Read /proc/softirqs
    try:
        softirqs_content = context.read_file("/proc/softirqs")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/softirqs: {e}")
        return 2

    # Parse softirqs
    try:
        softirqs = parse_softirqs(softirqs_content)
    except (ValueError, IndexError) as e:
        output.error(f"Failed to parse /proc/softirqs: {e}")
        return 2

    if not softirqs:
        output.error("No softirq data found")
        return 2

    cpu_count = context.cpu_count()

    # Analyze
    analysis = analyze_softirqs(softirqs, cpu_count, opts.imbalance)

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_count": cpu_count,
        "softirq_types": len(softirqs),
        "totals": analysis["totals"],
        "status": analysis["status"],
        "issues": analysis["issues"],
        "warnings": analysis["warnings"],
        "healthy": len(analysis["issues"]) == 0,
    }

    output.emit(result)
    output.render(opts.format, "Softirq Monitor", warn_only=getattr(opts, 'warn_only', False))

    output.set_summary(f"status={analysis['status']}")

    return 1 if analysis["issues"] else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
