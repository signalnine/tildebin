#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, napi, polling, performance]
#   brief: Monitor Linux NAPI polling health for network performance issues

"""
Monitor Linux NAPI (New API) polling health for network performance issues.

NAPI is the Linux kernel's mechanism for efficient network packet processing.
Instead of generating an interrupt for each packet, NAPI allows the kernel to
poll network devices in batches, reducing CPU overhead at high packet rates.

This script monitors NAPI-related statistics from /proc and /sys:
- NAPI polling budget utilization (gro_normal_batch)
- Global NAPI settings (netdev_budget, dev_weight)
- Network softirq statistics
- Busy polling configuration

Exit codes:
    0: NAPI configuration healthy
    1: Potential performance issues detected
    2: Cannot read NAPI statistics or usage error
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_napi_settings(context: Context) -> dict:
    """
    Read global NAPI-related kernel settings.

    Returns:
        dict: Dictionary of NAPI settings
    """
    settings = {}

    sysctl_paths = {
        "busy_poll": "/proc/sys/net/core/busy_poll",
        "busy_read": "/proc/sys/net/core/busy_read",
        "gro_normal_batch": "/proc/sys/net/core/gro_normal_batch",
        "netdev_budget": "/proc/sys/net/core/netdev_budget",
        "netdev_budget_usecs": "/proc/sys/net/core/netdev_budget_usecs",
        "dev_weight": "/proc/sys/net/core/dev_weight",
        "dev_weight_rx_bias": "/proc/sys/net/core/dev_weight_rx_bias",
        "dev_weight_tx_bias": "/proc/sys/net/core/dev_weight_tx_bias",
    }

    for name, path in sysctl_paths.items():
        try:
            value = context.read_file(path).strip()
            try:
                settings[name] = int(value)
            except ValueError:
                settings[name] = value
        except (FileNotFoundError, PermissionError, IOError):
            pass

    return settings


def parse_softirq_net_stats(content: str) -> dict:
    """
    Parse /proc/softirqs for NET_RX and NET_TX stats.

    Returns:
        dict: Softirq statistics for networking
    """
    stats = {
        "net_rx": [],
        "net_tx": [],
        "total_net_rx": 0,
        "total_net_tx": 0,
    }

    lines = content.strip().split("\n")
    if not lines:
        return stats

    header = lines[0].split()
    num_cpus = len(header)

    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue

        irq_name = parts[0].rstrip(":")
        try:
            values = [int(v) for v in parts[1 : num_cpus + 1]]
        except (ValueError, IndexError):
            continue

        if irq_name == "NET_RX":
            stats["net_rx"] = values
            stats["total_net_rx"] = sum(values)
        elif irq_name == "NET_TX":
            stats["net_tx"] = values
            stats["total_net_tx"] = sum(values)

    return stats


def analyze_napi_health(settings: dict, softirq_stats: dict) -> dict:
    """
    Analyze NAPI configuration and generate issues.

    Args:
        settings: Global NAPI settings
        softirq_stats: Softirq statistics

    Returns:
        dict: Analysis results with issues and warnings
    """
    issues = []
    warnings = []

    # Check netdev_budget (default 300, may need tuning for high throughput)
    netdev_budget = settings.get("netdev_budget")
    if netdev_budget is not None and netdev_budget < 300:
        warnings.append(
            {
                "type": "low_netdev_budget",
                "value": netdev_budget,
                "message": f"netdev_budget is low ({netdev_budget}). Consider increasing for high packet rates: sysctl -w net.core.netdev_budget=600",
            }
        )

    # Check dev_weight (NAPI weight, default 64)
    dev_weight = settings.get("dev_weight")
    if dev_weight is not None and dev_weight < 64:
        warnings.append(
            {
                "type": "low_dev_weight",
                "value": dev_weight,
                "message": f"dev_weight is {dev_weight} (default 64). Lower values may reduce throughput but improve latency.",
            }
        )

    # Check GRO batch size
    gro_batch = settings.get("gro_normal_batch")
    if gro_batch is not None and gro_batch < 8:
        warnings.append(
            {
                "type": "low_gro_batch",
                "value": gro_batch,
                "message": f"gro_normal_batch is {gro_batch}. Consider increasing for better GRO coalescing: sysctl -w net.core.gro_normal_batch=8",
            }
        )

    # Check for NET_RX softirq imbalance across CPUs
    net_rx = softirq_stats.get("net_rx", [])
    if len(net_rx) >= 2:
        max_rx = max(net_rx)
        min_rx = min(net_rx)
        if min_rx > 0:
            ratio = max_rx / min_rx
            if ratio > 10:
                max_cpu = net_rx.index(max_rx)
                min_cpu = net_rx.index(min_rx)
                issues.append(
                    {
                        "type": "softirq_imbalance",
                        "max_cpu": max_cpu,
                        "min_cpu": min_cpu,
                        "ratio": round(ratio, 1),
                        "message": f"NET_RX softirq imbalance: CPU{max_cpu} processed {ratio:.1f}x more than CPU{min_cpu}. Consider configuring RPS.",
                    }
                )
        elif max_rx > 0:
            # All on one CPU
            max_cpu = net_rx.index(max_rx)
            issues.append(
                {
                    "type": "softirq_single_cpu",
                    "cpu": max_cpu,
                    "message": f"All NET_RX softirqs handled by CPU{max_cpu}. Consider enabling RPS for better distribution.",
                }
            )

    status = "critical" if issues else ("warning" if warnings else "healthy")

    return {
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
        description="Monitor Linux NAPI polling health for network performance"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed per-CPU statistics")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only output if issues are detected",
    )
    opts = parser.parse_args(args)

    # Verify we can read at least some settings
    try:
        # Check if /proc/sys/net is accessible
        context.read_file("/proc/sys/net/core/netdev_budget")
    except (FileNotFoundError, IOError):
        # Try fallback
        pass

    # Gather data
    settings = get_napi_settings(context)

    if not settings:
        output.error("Cannot read NAPI kernel settings")
        return 2

    # Read softirq stats
    softirq_stats = {"net_rx": [], "net_tx": [], "total_net_rx": 0, "total_net_tx": 0}
    try:
        softirqs_content = context.read_file("/proc/softirqs")
        softirq_stats = parse_softirq_net_stats(softirqs_content)
    except (FileNotFoundError, IOError):
        pass  # Optional data

    # Analyze health
    analysis = analyze_napi_health(settings, softirq_stats)

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "settings": settings,
        "softirq_stats": softirq_stats,
        "status": analysis["status"],
        "issues": analysis["issues"],
        "warnings": analysis["warnings"],
        "healthy": not any(i.get("type") in ["softirq_imbalance", "softirq_single_cpu"] for i in analysis["issues"]),
    }

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            lines = []
            lines.append("NAPI Health Monitor")
            lines.append("=" * 60)
            lines.append("")

            lines.append("Global NAPI Settings:")
            lines.append(f"  netdev_budget:      {settings.get('netdev_budget', 'N/A'):>10}")
            lines.append(f"  dev_weight:         {settings.get('dev_weight', 'N/A'):>10}")
            lines.append(f"  gro_normal_batch:   {settings.get('gro_normal_batch', 'N/A'):>10}")
            lines.append(f"  busy_poll:          {settings.get('busy_poll', 'N/A'):>10} us")
            lines.append(f"  busy_read:          {settings.get('busy_read', 'N/A'):>10} us")
            lines.append("")

            lines.append("NET Softirq Statistics:")
            lines.append(f"  Total NET_RX:       {softirq_stats.get('total_net_rx', 0):>15,}")
            lines.append(f"  Total NET_TX:       {softirq_stats.get('total_net_tx', 0):>15,}")
            lines.append("")

            if opts.verbose and softirq_stats.get("net_rx"):
                lines.append("Per-CPU NET_RX Distribution:")
                for cpu, count in enumerate(softirq_stats["net_rx"]):
                    lines.append(f"  CPU{cpu:<4} {count:>15,}")
                lines.append("")

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

            if not analysis["issues"] and not analysis["warnings"]:
                lines.append("[OK] NAPI configuration healthy")

            print("\n".join(lines))

    output.set_summary(f"status={analysis['status']}")

    return 1 if analysis["issues"] else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
