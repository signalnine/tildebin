#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [swap, memory, pressure, oom, capacity]
#   requires: []
#   privilege: none
#   related: [swap_monitor, memory_usage, oom_risk_analyzer, proc_pressure]
#   brief: Analyze swap usage patterns and memory pressure

"""
Analyze swap usage patterns and memory pressure on baremetal systems.

Monitors /proc/meminfo and /proc/vmstat to detect swap pressure conditions
that indicate memory exhaustion before OOM kills occur. Tracks swap in/out
rates to identify active swapping vs stale swap usage.

Key features:
- Reports swap usage percentage and absolute values
- Calculates swap in/out rates (pages/sec)
- Detects active swapping vs stale swap
- Identifies memory pressure trends
- Warns when swap usage approaches critical levels

Use cases:
- Early detection of memory exhaustion
- Capacity planning for memory-intensive workloads
- Pre-OOM visibility into memory pressure
- Identifying processes causing swap thrashing
"""

import argparse
import time
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_meminfo(context: Context) -> dict[str, int] | None:
    """Read memory information from /proc/meminfo."""
    try:
        content = context.read_file('/proc/meminfo')
    except (FileNotFoundError, PermissionError):
        return None

    meminfo = {}
    for line in content.strip().split('\n'):
        parts = line.split(':')
        if len(parts) == 2:
            key = parts[0].strip()
            value_parts = parts[1].strip().split()
            if value_parts:
                try:
                    # Convert to bytes (values are in kB)
                    value = int(value_parts[0]) * 1024
                    meminfo[key] = value
                except ValueError:
                    continue

    return meminfo if meminfo else None


def read_vmstat(context: Context) -> dict[str, int] | None:
    """Read VM statistics from /proc/vmstat."""
    try:
        content = context.read_file('/proc/vmstat')
    except (FileNotFoundError, PermissionError):
        return None

    vmstat = {}
    for line in content.strip().split('\n'):
        parts = line.split()
        if len(parts) == 2:
            try:
                vmstat[parts[0]] = int(parts[1])
            except ValueError:
                continue

    return vmstat if vmstat else None


def format_bytes(bytes_val: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PiB"


def analyze_swap(
    meminfo: dict[str, int],
    swap_rates: dict[str, float] | None,
    warn_percent: float,
    crit_percent: float,
    swap_rate_warn: float
) -> dict[str, Any]:
    """Analyze swap usage and generate assessment."""
    swap_total = meminfo.get('SwapTotal', 0)
    swap_free = meminfo.get('SwapFree', 0)
    swap_cached = meminfo.get('SwapCached', 0)
    swap_used = swap_total - swap_free

    # Memory info for context
    mem_total = meminfo.get('MemTotal', 0)
    mem_free = meminfo.get('MemFree', 0)
    mem_available = meminfo.get('MemAvailable', mem_free)
    buffers = meminfo.get('Buffers', 0)
    cached = meminfo.get('Cached', 0)

    # Calculate percentages
    swap_percent = (swap_used / swap_total * 100) if swap_total > 0 else 0
    mem_used_percent = ((mem_total - mem_available) / mem_total * 100) if mem_total > 0 else 0

    issues = []

    # Check if swap is configured
    if swap_total == 0:
        issues.append({
            'type': 'NO_SWAP',
            'severity': 'info',
            'message': "No swap space configured - OOM kills may occur under memory pressure"
        })
    else:
        # Check swap usage percentage
        if swap_percent >= crit_percent:
            issues.append({
                'type': 'SWAP_CRITICAL',
                'severity': 'critical',
                'percent': round(swap_percent, 1),
                'threshold': crit_percent,
                'message': f"Swap usage {swap_percent:.1f}% exceeds critical threshold {crit_percent}%"
            })
        elif swap_percent >= warn_percent:
            issues.append({
                'type': 'SWAP_WARNING',
                'severity': 'warning',
                'percent': round(swap_percent, 1),
                'threshold': warn_percent,
                'message': f"Swap usage {swap_percent:.1f}% exceeds warning threshold {warn_percent}%"
            })

    # Check swap activity (active swapping indicates pressure)
    if swap_rates:
        total_rate = swap_rates['swap_in_pages_sec'] + swap_rates['swap_out_pages_sec']
        if total_rate >= swap_rate_warn:
            issues.append({
                'type': 'ACTIVE_SWAPPING',
                'severity': 'warning',
                'swap_in': round(swap_rates['swap_in_pages_sec'], 1),
                'swap_out': round(swap_rates['swap_out_pages_sec'], 1),
                'message': f"Active swapping detected: {swap_rates['swap_in_pages_sec']:.1f} pages/s in, {swap_rates['swap_out_pages_sec']:.1f} pages/s out"
            })

    # Determine if swap is stale (used but no activity)
    swap_state = 'none'
    if swap_total > 0:
        if swap_used > 0:
            if swap_rates and (swap_rates['swap_in_pages_sec'] + swap_rates['swap_out_pages_sec']) < 1:
                swap_state = 'stale'  # Swap used but no activity
            else:
                swap_state = 'active'  # Swap in use with activity
        else:
            swap_state = 'unused'

    # Memory pressure indicator
    pressure = 'none'
    if mem_used_percent > 90 or swap_percent > 50:
        pressure = 'high'
    elif mem_used_percent > 70 or swap_percent > 20:
        pressure = 'moderate'
    elif swap_percent > 5:
        pressure = 'low'

    # Determine overall status
    overall_status = 'ok'
    if any(i['severity'] == 'critical' for i in issues):
        overall_status = 'critical'
    elif any(i['severity'] == 'warning' for i in issues):
        overall_status = 'warning'

    return {
        'status': overall_status,
        'swap': {
            'total_bytes': swap_total,
            'used_bytes': swap_used,
            'free_bytes': swap_free,
            'cached_bytes': swap_cached,
            'percent_used': round(swap_percent, 1),
        },
        'memory': {
            'total_bytes': mem_total,
            'available_bytes': mem_available,
            'buffers_bytes': buffers,
            'cached_bytes': cached,
            'percent_used': round(mem_used_percent, 1),
        },
        'swap_rates': swap_rates,
        'swap_state': swap_state,
        'pressure': pressure,
        'issues': issues,
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
        description="Analyze swap usage patterns and memory pressure"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed interpretation")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--warn", type=float, default=50.0, metavar="PERCENT",
                        help="Warning threshold for swap usage (default: 50)")
    parser.add_argument("--crit", type=float, default=80.0, metavar="PERCENT",
                        help="Critical threshold for swap usage (default: 80)")
    parser.add_argument("--swap-rate-warn", type=float, default=100.0, metavar="PAGES",
                        help="Warning threshold for swap activity (pages/sec, default: 100)")
    parser.add_argument("--no-sample", action="store_true",
                        help="Skip swap rate sampling (faster but no rate info)")
    parser.add_argument("--sample-interval", type=float, default=1.0, metavar="SECONDS",
                        help="Interval for swap rate sampling (default: 1.0s)")
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.warn < 0 or opts.warn > 100:
        output.error("--warn must be between 0 and 100")

        output.render(opts.format, "Analyze swap usage patterns and memory pressure")
        return 2
    if opts.crit < 0 or opts.crit > 100:
        output.error("--crit must be between 0 and 100")

        output.render(opts.format, "Analyze swap usage patterns and memory pressure")
        return 2
    if opts.crit < opts.warn:
        output.error("--crit must be >= --warn")

        output.render(opts.format, "Analyze swap usage patterns and memory pressure")
        return 2
    if opts.swap_rate_warn < 0:
        output.error("--swap-rate-warn must be non-negative")

        output.render(opts.format, "Analyze swap usage patterns and memory pressure")
        return 2
    if opts.sample_interval <= 0:
        output.error("--sample-interval must be positive")

        output.render(opts.format, "Analyze swap usage patterns and memory pressure")
        return 2

    # Check if we can read /proc
    if not context.file_exists('/proc/meminfo'):
        output.error("/proc/meminfo not available")

        output.render(opts.format, "Analyze swap usage patterns and memory pressure")
        return 2

    # Get memory info
    meminfo = read_meminfo(context)
    if meminfo is None:
        output.error("Unable to read memory information")

        output.render(opts.format, "Analyze swap usage patterns and memory pressure")
        return 2

    # Get swap rates (optional)
    swap_rates = None
    if not opts.no_sample:
        vmstat1 = read_vmstat(context)
        if vmstat1:
            time.sleep(opts.sample_interval)
            vmstat2 = read_vmstat(context)
            if vmstat2:
                pswpin1 = vmstat1.get('pswpin', 0)
                pswpout1 = vmstat1.get('pswpout', 0)
                pswpin2 = vmstat2.get('pswpin', 0)
                pswpout2 = vmstat2.get('pswpout', 0)
                swap_rates = {
                    'swap_in_pages_sec': (pswpin2 - pswpin1) / opts.sample_interval,
                    'swap_out_pages_sec': (pswpout2 - pswpout1) / opts.sample_interval,
                }

    # Analyze
    analysis = analyze_swap(
        meminfo,
        swap_rates,
        warn_percent=opts.warn,
        crit_percent=opts.crit,
        swap_rate_warn=opts.swap_rate_warn
    )

    output.emit(analysis)

    # Set summary
    swap_pct = analysis['swap']['percent_used']
    swap_state = analysis['swap_state']
    pressure = analysis['pressure']

    if analysis['status'] == 'critical':
        output.set_summary(f"Swap at {swap_pct:.1f}% - CRITICAL")
    elif analysis['status'] == 'warning':
        output.set_summary(f"Swap at {swap_pct:.1f}% - WARNING")
    else:
        output.set_summary(f"Swap {swap_state}, pressure: {pressure}")

    # Exit code
    if analysis['status'] in ['critical', 'warning']:

        output.render(opts.format, "Analyze swap usage patterns and memory pressure")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
