#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [health, disk, io, performance, iostat]
#   requires: [iostat]
#   privilege: user
#   related: [disk_health, disk_io_latency, disk_queue_monitor]
#   brief: Monitor disk I/O performance and identify bottlenecks

"""
Monitor disk I/O performance and identify bottlenecks.

Analyzes disk I/O statistics to detect high latency, saturated I/O queues,
and slow-performing devices that may impact application performance.

Returns exit code 1 if any disk has performance warnings.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_iostat_output(output: str) -> list[dict[str, Any]]:
    """Parse iostat output and return device statistics."""
    devices = []
    lines = output.strip().split('\n')

    # Find the second statistics block (current snapshot, not since boot)
    in_second_block = False
    header_found = False

    for line in lines:
        # Look for the Device header line
        if line.startswith('Device'):
            if header_found:
                in_second_block = True
            else:
                header_found = True
            continue

        # Skip until we're in the second block
        if not in_second_block or not line.strip():
            continue

        # Parse device statistics
        parts = line.split()
        if len(parts) >= 14:
            device = parts[0]

            # Skip loop and ram devices by default
            if device.startswith('loop') or device.startswith('ram'):
                continue

            try:
                stats = {
                    'device': device,
                    'rrqm_per_s': float(parts[1]),
                    'wrqm_per_s': float(parts[2]),
                    'r_per_s': float(parts[3]),
                    'w_per_s': float(parts[4]),
                    'rkb_per_s': float(parts[5]),
                    'wkb_per_s': float(parts[6]),
                    'avgrq_sz': float(parts[7]),
                    'avgqu_sz': float(parts[8]),
                    'await': float(parts[9]),
                    'r_await': float(parts[10]),
                    'w_await': float(parts[11]),
                    'svctm': float(parts[12]),
                    'util': float(parts[13])
                }
                devices.append(stats)
            except (ValueError, IndexError):
                continue

    return devices


def analyze_device(stats: dict[str, Any]) -> tuple[str, list[str]]:
    """Analyze device stats and identify issues."""
    issues = []
    status = 'healthy'

    util = stats['util']
    await_time = stats['await']
    avgqu_sz = stats['avgqu_sz']

    # Check utilization
    if util > 90:
        issues.append(f"Utilization at {util:.1f}% (device saturated)")
        status = 'critical'
    elif util > 75:
        issues.append(f"Utilization at {util:.1f}% (nearing saturation)")
        if status == 'healthy':
            status = 'warning'

    # Check average wait time (latency)
    if await_time > 100:
        issues.append(f"Average wait time {await_time:.1f}ms (very high latency)")
        status = 'critical'
    elif await_time > 50:
        issues.append(f"Average wait time {await_time:.1f}ms (high latency)")
        if status == 'healthy':
            status = 'warning'

    # Check queue depth
    if avgqu_sz > 10:
        issues.append(f"Average queue length {avgqu_sz:.1f} (I/O backlog)")
        if status == 'healthy':
            status = 'warning'

    # Check for read vs write imbalance
    r_await = stats['r_await']
    w_await = stats['w_await']
    if r_await > 0 and w_await > 0:
        if r_await > w_await * 5:
            issues.append(
                f"Read latency ({r_await:.1f}ms) much higher than write ({w_await:.1f}ms)"
            )
        elif w_await > r_await * 5:
            issues.append(
                f"Write latency ({w_await:.1f}ms) much higher than read ({r_await:.1f}ms)"
            )

    return status, issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor disk I/O performance and identify bottlenecks"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show devices with warnings or issues"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )

    opts = parser.parse_args(args)

    # Check for iostat
    if not context.check_tool("iostat"):
        output.error("iostat not found. Install sysstat package.")

        output.render(opts.format, "Monitor disk I/O performance and identify bottlenecks")
        return 2

    # Run iostat with extended stats (-x) for 2 iterations, 1 second apart
    try:
        result = context.run(['iostat', '-x', '-d', '1', '2'], check=True)
    except Exception as e:
        output.error(f"Failed to run iostat: {e}")

        output.render(opts.format, "Monitor disk I/O performance and identify bottlenecks")
        return 2

    # Parse device statistics
    devices = parse_iostat_output(result.stdout)

    if not devices:
        output.warning("No disk devices found")
        output.emit({"devices": []})

        output.render(opts.format, "Monitor disk I/O performance and identify bottlenecks")
        return 0

    # Analyze each device
    results = []
    has_issues = False

    for stats in devices:
        status, issues = analyze_device(stats)

        # Skip healthy devices if warn-only mode
        if opts.warn_only and status == 'healthy':
            continue

        if status != 'healthy':
            has_issues = True

        device_result = {
            'device': stats['device'],
            'status': status,
            'utilization_pct': stats['util'],
            'await_ms': stats['await'],
            'r_await_ms': stats['r_await'],
            'w_await_ms': stats['w_await'],
            'avg_queue_length': stats['avgqu_sz'],
            'reads_per_sec': stats['r_per_s'],
            'writes_per_sec': stats['w_per_s'],
            'read_kb_per_sec': stats['rkb_per_s'],
            'write_kb_per_sec': stats['wkb_per_s'],
        }

        if opts.verbose:
            device_result['issues'] = issues

        results.append(device_result)

    output.emit({"devices": results})

    # Set summary
    healthy = sum(1 for r in results if r['status'] == 'healthy')
    warning = sum(1 for r in results if r['status'] == 'warning')
    critical = sum(1 for r in results if r['status'] == 'critical')
    output.set_summary(f"{healthy} healthy, {warning} warning, {critical} critical")


    output.render(opts.format, "Monitor disk I/O performance and identify bottlenecks")
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
