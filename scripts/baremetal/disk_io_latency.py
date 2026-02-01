#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, performance, storage, latency]
#   brief: Monitor disk I/O latency to detect performance issues

"""
Monitor disk I/O latency to detect performance issues.

Analyzes /proc/diskstats to measure disk I/O latency and identify
devices with slow response times.

Exit codes:
    0: No latency issues detected
    1: Latency warnings or threshold exceeded
    2: Usage error or unable to read disk statistics
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_diskstats(content: str) -> list[dict]:
    """
    Parse /proc/diskstats content.

    Returns list of device stats with calculated latencies.
    """
    devices = []
    for line in content.strip().split("\n"):
        parts = line.split()
        if len(parts) < 14:
            continue

        device_name = parts[2]

        # Skip loop, ram devices
        if device_name.startswith(("loop", "ram")):
            continue

        # Skip partition devices (e.g., sda1, nvme0n1p1)
        if any(c.isdigit() for c in device_name[-1:]) and not device_name.startswith("nvme"):
            # Check if it's a partition (has number at end but isn't nvme)
            if device_name[-1].isdigit() and not device_name.endswith("n1"):
                continue

        try:
            rd_ios = int(parts[3])
            rd_ticks = int(parts[6])
            wr_ios = int(parts[7])
            wr_ticks = int(parts[10])
            in_flight = int(parts[11])
            io_ticks = int(parts[12])

            # Calculate average latencies (ms per I/O)
            read_latency = (rd_ticks / rd_ios) if rd_ios > 0 else 0
            write_latency = (wr_ticks / wr_ios) if wr_ios > 0 else 0
            avg_latency = ((rd_ticks + wr_ticks) / (rd_ios + wr_ios)) if (rd_ios + wr_ios) > 0 else 0

            devices.append({
                "device": device_name,
                "read_ios": rd_ios,
                "write_ios": wr_ios,
                "read_latency_ms": round(read_latency, 2),
                "write_latency_ms": round(write_latency, 2),
                "avg_latency_ms": round(avg_latency, 2),
                "in_flight": in_flight,
                "io_ticks": io_ticks,
            })
        except (ValueError, ZeroDivisionError):
            continue

    return devices


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
    parser = argparse.ArgumentParser(description="Monitor disk I/O latency")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all devices")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "--warn-latency",
        type=float,
        default=10.0,
        help="Warning threshold for avg latency in ms (default: 10)",
    )
    parser.add_argument(
        "--crit-latency",
        type=float,
        default=50.0,
        help="Critical threshold for avg latency in ms (default: 50)",
    )
    parser.add_argument(
        "--warn-only",
        "-w",
        action="store_true",
        help="Only show output if issues detected",
    )
    opts = parser.parse_args(args)

    # Read /proc/diskstats
    try:
        diskstats_content = context.read_file("/proc/diskstats")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/diskstats: {e}")
        return 2

    devices = parse_diskstats(diskstats_content)

    if not devices:
        output.error("No disk devices found")
        return 2

    # Analyze latencies
    issues = []
    for dev in devices:
        if dev["avg_latency_ms"] >= opts.crit_latency:
            issues.append({
                "severity": "CRITICAL",
                "device": dev["device"],
                "latency_ms": dev["avg_latency_ms"],
                "message": f"Critical latency on {dev['device']}: {dev['avg_latency_ms']:.1f}ms avg",
            })
        elif dev["avg_latency_ms"] >= opts.warn_latency:
            issues.append({
                "severity": "WARNING",
                "device": dev["device"],
                "latency_ms": dev["avg_latency_ms"],
                "message": f"High latency on {dev['device']}: {dev['avg_latency_ms']:.1f}ms avg",
            })

    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warning = any(i["severity"] == "WARNING" for i in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")

    # Build result
    result = {
        "devices": devices,
        "issues": issues,
        "status": status,
    }

    # Output
    if opts.format == "json":
        if not opts.warn_only or issues:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or issues:
            lines = []
            lines.append("Disk I/O Latency Monitor")
            lines.append("=" * 60)

            if opts.verbose:
                lines.append(f"{'Device':<12} {'Read Lat':>10} {'Write Lat':>10} {'Avg Lat':>10}")
                lines.append("-" * 60)
                for dev in devices:
                    lines.append(
                        f"{dev['device']:<12} {dev['read_latency_ms']:>9.1f}ms "
                        f"{dev['write_latency_ms']:>9.1f}ms {dev['avg_latency_ms']:>9.1f}ms"
                    )
                lines.append("")

            if issues:
                for issue in issues:
                    prefix = "[CRITICAL]" if issue["severity"] == "CRITICAL" else "[WARNING]"
                    lines.append(f"{prefix} {issue['message']}")
            else:
                lines.append(f"[OK] All {len(devices)} device(s) have healthy latency")

            print("\n".join(lines))

    output.set_summary(f"devices={len(devices)}, issues={len(issues)}, status={status}")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
