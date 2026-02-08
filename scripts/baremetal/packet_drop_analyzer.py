#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, drops, interface]
#   brief: Analyze per-interface packet drops and their causes

"""
Analyze per-interface packet drops and their causes on baremetal systems.

This script provides detailed breakdown of packet drops by interface and reason,
helping distinguish between driver bugs, misconfigurations, resource exhaustion,
and potential attacks (e.g., SYN floods).

Packet drops can occur at multiple levels:
- rx_dropped: Packets dropped before delivery to protocol stack
- rx_errors: Packets with errors (CRC, frame alignment, etc.)
- rx_missed: Packets missed due to lack of receive buffers
- rx_fifo_errors: FIFO overruns (NIC buffer exhaustion)
- tx_dropped: Packets dropped during transmission
- tx_errors: Transmission errors
- tx_carrier_errors: Loss of carrier during transmission
- tx_fifo_errors: TX FIFO underruns

Exit codes:
    0: No drops detected or all drops within thresholds
    1: Drops detected above warning threshold
    2: Missing /sys or usage error
"""

import argparse
import time as time_module
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


STAT_NAMES = [
    "rx_packets",
    "rx_bytes",
    "rx_dropped",
    "rx_errors",
    "rx_missed_errors",
    "rx_fifo_errors",
    "rx_length_errors",
    "rx_over_errors",
    "rx_crc_errors",
    "rx_frame_errors",
    "tx_packets",
    "tx_bytes",
    "tx_dropped",
    "tx_errors",
    "tx_fifo_errors",
    "tx_carrier_errors",
    "tx_aborted_errors",
    "tx_window_errors",
    "tx_heartbeat_errors",
    "collisions",
]


def get_interface_list(context: Context, include_virtual: bool = False) -> list[str]:
    """Get list of network interfaces from /sys/class/net.

    Args:
        context: Execution context
        include_virtual: Whether to include virtual interfaces

    Returns:
        list: Interface names
    """
    net_path = "/sys/class/net"
    if not context.file_exists(net_path):
        return []

    interfaces = []
    try:
        # List interfaces via glob
        paths = context.glob("*", net_path)
        for path in paths:
            iface = path.split("/")[-1]

            # Skip loopback
            if iface == "lo":
                continue

            # Skip virtual interfaces unless requested
            if not include_virtual:
                if iface.startswith("veth") or iface.startswith("docker"):
                    continue
                if iface == "bonding_masters":
                    continue

            # Verify it has statistics
            stats_path = f"{net_path}/{iface}/statistics"
            if context.file_exists(stats_path):
                interfaces.append(iface)

        return sorted(interfaces)
    except (IOError, OSError):
        return []


def read_interface_stat(context: Context, iface: str, stat_name: str) -> int:
    """Read a single statistic for an interface.

    Args:
        context: Execution context
        iface: Interface name
        stat_name: Statistic name

    Returns:
        int: Statistic value (0 if not found)
    """
    path = f"/sys/class/net/{iface}/statistics/{stat_name}"
    try:
        if context.file_exists(path):
            return int(context.read_file(path).strip())
    except (ValueError, IOError):
        pass
    return 0


def get_interface_stats(context: Context, iface: str) -> dict:
    """Get all statistics for an interface.

    Args:
        context: Execution context
        iface: Interface name

    Returns:
        dict: Statistics dict
    """
    stats = {}
    for stat_name in STAT_NAMES:
        stats[stat_name] = read_interface_stat(context, iface, stat_name)
    return stats


def get_interface_operstate(context: Context, iface: str) -> str:
    """Get operational state of interface.

    Args:
        context: Execution context
        iface: Interface name

    Returns:
        str: Operational state
    """
    path = f"/sys/class/net/{iface}/operstate"
    try:
        if context.file_exists(path):
            return context.read_file(path).strip()
    except IOError:
        pass
    return "unknown"


def calculate_rates(before: dict, after: dict, interval: float) -> dict:
    """Calculate per-second rates between two samples.

    Args:
        before: First sample
        after: Second sample
        interval: Time interval in seconds

    Returns:
        dict: Rates per second
    """
    rates = {}
    for key in before:
        diff = after[key] - before[key]
        if diff < 0:  # Counter wrap
            diff = 0
        rates[key] = diff / interval if interval > 0 else 0
    return rates


def analyze_interface(
    iface: str,
    stats: dict,
    rates: dict,
    operstate: str,
    warn_rate: float,
    crit_rate: float,
) -> tuple[dict, list]:
    """Analyze interface drops and generate issues.

    Args:
        iface: Interface name
        stats: Current statistics
        rates: Per-second rates
        operstate: Operational state
        warn_rate: Warning threshold (drops/sec)
        crit_rate: Critical threshold (drops/sec)

    Returns:
        tuple: (result dict, issues list)
    """
    issues = []

    # Calculate total drops
    total_rx_drops = (
        stats["rx_dropped"]
        + stats["rx_errors"]
        + stats["rx_missed_errors"]
        + stats["rx_fifo_errors"]
    )
    total_tx_drops = (
        stats["tx_dropped"]
        + stats["tx_errors"]
        + stats["tx_fifo_errors"]
        + stats["tx_carrier_errors"]
    )

    # Drop rates
    rx_drop_rate = (
        rates["rx_dropped"]
        + rates["rx_errors"]
        + rates["rx_missed_errors"]
        + rates["rx_fifo_errors"]
    )
    tx_drop_rate = (
        rates["tx_dropped"]
        + rates["tx_errors"]
        + rates["tx_fifo_errors"]
        + rates["tx_carrier_errors"]
    )

    # Check categories
    drop_categories = [
        (
            "rx_dropped",
            "RX dropped",
            "May indicate kernel/driver buffer exhaustion or netfilter drops",
        ),
        (
            "rx_errors",
            "RX errors",
            "May indicate cable/transceiver issues or driver bugs",
        ),
        (
            "rx_missed_errors",
            "RX missed",
            "NIC ran out of receive buffers - consider increasing ring buffer",
        ),
        (
            "rx_fifo_errors",
            "RX FIFO errors",
            "NIC hardware buffer overflow - traffic rate exceeds processing",
        ),
        (
            "rx_crc_errors",
            "RX CRC errors",
            "Physical layer issues - check cables, connectors, transceivers",
        ),
        (
            "rx_frame_errors",
            "RX frame errors",
            "Frame alignment errors - possible duplex mismatch or cable issues",
        ),
        ("tx_dropped", "TX dropped", "Queue full or policy drop"),
        ("tx_errors", "TX errors", "Transmission errors - check link status and driver"),
        (
            "tx_carrier_errors",
            "TX carrier errors",
            "Lost carrier during transmission - link instability",
        ),
        (
            "collisions",
            "Collisions",
            "Should be 0 on full-duplex links - possible duplex mismatch",
        ),
    ]

    for stat_name, description, hint in drop_categories:
        count = stats.get(stat_name, 0)
        rate = rates.get(stat_name, 0)

        if rate >= crit_rate:
            issues.append(
                {
                    "severity": "CRITICAL",
                    "interface": iface,
                    "category": stat_name,
                    "description": description,
                    "hint": hint,
                    "count": count,
                    "rate_per_sec": round(rate, 2),
                    "message": f"{iface}: {description} at {rate:.2f}/sec (total: {count:,})",
                }
            )
        elif rate >= warn_rate:
            issues.append(
                {
                    "severity": "WARNING",
                    "interface": iface,
                    "category": stat_name,
                    "description": description,
                    "hint": hint,
                    "count": count,
                    "rate_per_sec": round(rate, 2),
                    "message": f"{iface}: {description} at {rate:.2f}/sec (total: {count:,})",
                }
            )

    # Determine status
    if any(i["severity"] == "CRITICAL" for i in issues):
        status = "critical"
    elif issues:
        status = "warning"
    else:
        status = "ok"

    result = {
        "interface": iface,
        "operstate": operstate,
        "status": status,
        "totals": {
            "rx_packets": stats["rx_packets"],
            "tx_packets": stats["tx_packets"],
            "rx_bytes": stats["rx_bytes"],
            "tx_bytes": stats["tx_bytes"],
            "total_rx_drops": total_rx_drops,
            "total_tx_drops": total_tx_drops,
        },
        "rates": {
            "rx_packets_per_sec": round(rates["rx_packets"], 2),
            "tx_packets_per_sec": round(rates["tx_packets"], 2),
            "rx_drop_rate": round(rx_drop_rate, 2),
            "tx_drop_rate": round(tx_drop_rate, 2),
        },
        "issues": issues,
    }

    return result, issues


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
        description="Analyze per-interface packet drops and their causes"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed breakdown and hints"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only output if issues are detected",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="Sampling interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-I",
        "--interface",
        metavar="IFACE",
        help="Specific interface to check (default: all)",
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=1.0,
        metavar="RATE",
        help="Warning threshold (drops/sec) (default: 1.0)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=10.0,
        metavar="RATE",
        help="Critical threshold (drops/sec) (default: 10.0)",
    )
    parser.add_argument(
        "--include-virtual",
        action="store_true",
        help="Include virtual interfaces (veth, docker, etc.)",
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if opts.interval <= 0:
        output.error("Interval must be positive")
        return 2

    if opts.warn >= opts.crit:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    # Get interface list
    if opts.interface:
        interfaces = [opts.interface]
        # Verify interface exists
        if not context.file_exists(f"/sys/class/net/{opts.interface}"):
            output.error(f"Interface '{opts.interface}' not found")
            return 2
    else:
        interfaces = get_interface_list(context, opts.include_virtual)
        if not interfaces:
            output.error("No network interfaces found")
            return 2

    # Take first sample
    before_stats = {}
    for iface in interfaces:
        before_stats[iface] = get_interface_stats(context, iface)

    # Wait for sampling interval
    time_module.sleep(opts.interval)

    # Take second sample
    after_stats = {}
    for iface in interfaces:
        after_stats[iface] = get_interface_stats(context, iface)

    # Analyze each interface
    results = []
    all_issues = []

    for iface in interfaces:
        rates = calculate_rates(before_stats[iface], after_stats[iface], opts.interval)
        operstate = get_interface_operstate(context, iface)
        result, issues = analyze_interface(
            iface, after_stats[iface], rates, operstate, opts.warn, opts.crit
        )
        results.append(result)
        all_issues.extend(issues)

    # Build output
    output_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sample_interval_sec": opts.interval,
        "interfaces": results,
        "issues": all_issues,
        "summary": {
            "interfaces_checked": len(results),
            "interfaces_with_issues": len([r for r in results if r["status"] != "ok"]),
            "total_issues": len(all_issues),
            "critical_count": len([i for i in all_issues if i["severity"] == "CRITICAL"]),
            "warning_count": len([i for i in all_issues if i["severity"] == "WARNING"]),
        },
        "has_issues": len(all_issues) > 0,
    }

    output.emit(output_data)

    # Output handling
    output.render(opts.format, "Packet Drop Analysis", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    output.set_summary(
        f"interfaces={len(results)}, issues={len(all_issues)}"
    )

    # Exit with appropriate code
    return 1 if all_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
