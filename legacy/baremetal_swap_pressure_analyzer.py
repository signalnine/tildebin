#!/usr/bin/env python3
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

Exit codes:
    0 - Swap usage within acceptable limits
    1 - Swap usage exceeds warning/critical thresholds or active swapping detected
    2 - Usage error or unable to read memory information
"""

import argparse
import json
import os
import sys
import time
from typing import Dict, Optional, Tuple


def read_meminfo() -> Optional[Dict[str, int]]:
    """Read memory information from /proc/meminfo."""
    try:
        with open('/proc/meminfo', 'r') as f:
            content = f.read()
    except (OSError, IOError):
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


def read_vmstat() -> Optional[Dict[str, int]]:
    """Read VM statistics from /proc/vmstat."""
    try:
        with open('/proc/vmstat', 'r') as f:
            content = f.read()
    except (OSError, IOError):
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


def get_swap_rates(sample_interval: float = 1.0) -> Optional[Dict[str, float]]:
    """Calculate swap in/out rates by sampling vmstat twice."""
    vmstat1 = read_vmstat()
    if vmstat1 is None:
        return None

    time.sleep(sample_interval)

    vmstat2 = read_vmstat()
    if vmstat2 is None:
        return None

    # pswpin/pswpout are cumulative page counts
    pswpin1 = vmstat1.get('pswpin', 0)
    pswpout1 = vmstat1.get('pswpout', 0)
    pswpin2 = vmstat2.get('pswpin', 0)
    pswpout2 = vmstat2.get('pswpout', 0)

    return {
        'swap_in_pages_sec': (pswpin2 - pswpin1) / sample_interval,
        'swap_out_pages_sec': (pswpout2 - pswpout1) / sample_interval,
    }


def format_bytes(bytes_val: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PiB"


def analyze_swap(meminfo: Dict[str, int], swap_rates: Optional[Dict[str, float]],
                 warn_percent: float, crit_percent: float,
                 swap_rate_warn: float) -> Dict:
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
                'message': (f"Swap usage {swap_percent:.1f}% exceeds critical "
                           f"threshold {crit_percent}%")
            })
        elif swap_percent >= warn_percent:
            issues.append({
                'type': 'SWAP_WARNING',
                'severity': 'warning',
                'percent': round(swap_percent, 1),
                'threshold': warn_percent,
                'message': (f"Swap usage {swap_percent:.1f}% exceeds warning "
                           f"threshold {warn_percent}%")
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
                'message': (f"Active swapping detected: {swap_rates['swap_in_pages_sec']:.1f} "
                           f"pages/s in, {swap_rates['swap_out_pages_sec']:.1f} pages/s out")
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


def output_plain(analysis: Dict, warn_only: bool, verbose: bool) -> None:
    """Output in plain text format."""
    issues = analysis['issues']
    swap = analysis['swap']
    memory = analysis['memory']

    # Print issues first
    if issues:
        print("ISSUES DETECTED:")
        for issue in issues:
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")
        print()

    if warn_only and not issues:
        print("OK - Swap usage within acceptable limits")
        return

    # System info
    print("Swap Pressure Analysis")
    print("=" * 50)

    # Swap usage
    print("\nSwap Usage:")
    print(f"  Total:    {format_bytes(swap['total_bytes'])}")
    print(f"  Used:     {format_bytes(swap['used_bytes'])} ({swap['percent_used']:.1f}%)")
    print(f"  Free:     {format_bytes(swap['free_bytes'])}")
    if swap['cached_bytes'] > 0:
        print(f"  Cached:   {format_bytes(swap['cached_bytes'])}")

    # Memory context
    print("\nMemory Context:")
    print(f"  Total:     {format_bytes(memory['total_bytes'])}")
    print(f"  Available: {format_bytes(memory['available_bytes'])} ({100 - memory['percent_used']:.1f}% free)")
    print(f"  Buffers:   {format_bytes(memory['buffers_bytes'])}")
    print(f"  Cached:    {format_bytes(memory['cached_bytes'])}")

    # Swap activity
    if analysis['swap_rates']:
        print("\nSwap Activity:")
        rates = analysis['swap_rates']
        print(f"  Pages in/sec:  {rates['swap_in_pages_sec']:.1f}")
        print(f"  Pages out/sec: {rates['swap_out_pages_sec']:.1f}")

    # Status
    print(f"\nSwap State: {analysis['swap_state'].capitalize()}")
    print(f"Memory Pressure: {analysis['pressure'].capitalize()}")

    if verbose:
        print("\nInterpretation:")
        if analysis['swap_state'] == 'none':
            print("  No swap configured")
        elif analysis['swap_state'] == 'unused':
            print("  Swap available but not needed - system has adequate memory")
        elif analysis['swap_state'] == 'stale':
            print("  Swap contains old data but is not actively used")
            print("  Previous memory pressure may have pushed data to swap")
        elif analysis['swap_state'] == 'active':
            print("  System is actively swapping - may indicate memory pressure")
            print("  Consider adding memory or reducing workload")

        if analysis['pressure'] == 'high':
            print("  HIGH PRESSURE: System may be at risk of OOM conditions")
        elif analysis['pressure'] == 'moderate':
            print("  MODERATE PRESSURE: Monitor closely for worsening conditions")


def output_json(analysis: Dict) -> None:
    """Output in JSON format."""
    print(json.dumps(analysis, indent=2))


def output_table(analysis: Dict, warn_only: bool) -> None:
    """Output in table format."""
    issues = analysis['issues']

    if warn_only:
        if not issues:
            print("No swap issues detected")
            return
        print(f"{'Type':<20} {'Severity':<10} {'Details':<30}")
        print("-" * 62)
        for issue in issues:
            details = issue.get('percent', issue.get('swap_in', ''))
            if 'percent' in issue:
                details = f"{issue['percent']:.1f}%"
            elif 'swap_in' in issue:
                details = f"in:{issue['swap_in']:.1f} out:{issue['swap_out']:.1f}"
            else:
                details = '-'
            print(f"{issue['type']:<20} {issue['severity']:<10} {str(details):<30}")
        return

    swap = analysis['swap']
    memory = analysis['memory']

    print(f"{'Metric':<25} {'Value':>15} {'Percent':>10}")
    print("-" * 52)
    print(f"{'Swap Total':<25} {format_bytes(swap['total_bytes']):>15}")
    print(f"{'Swap Used':<25} {format_bytes(swap['used_bytes']):>15} {swap['percent_used']:>9.1f}%")
    print(f"{'Swap Free':<25} {format_bytes(swap['free_bytes']):>15}")
    print(f"{'Memory Total':<25} {format_bytes(memory['total_bytes']):>15}")
    print(f"{'Memory Available':<25} {format_bytes(memory['available_bytes']):>15} {100-memory['percent_used']:>9.1f}%")
    print(f"{'Swap State':<25} {analysis['swap_state']:>15}")
    print(f"{'Memory Pressure':<25} {analysis['pressure']:>15}")
    print(f"{'Status':<25} {analysis['status']:>15}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze swap usage patterns and memory pressure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         Show swap pressure analysis
  %(prog)s --warn-only             Only show if there are issues
  %(prog)s --format json           JSON output for monitoring systems
  %(prog)s --warn 50 --crit 80     Custom thresholds (percent)
  %(prog)s --no-sample             Skip swap rate sampling (faster)

Thresholds (swap usage percent):
  < 20%%  - Low usage (normal)
  20-50%% - Moderate usage (monitor)
  50-80%% - High usage (warning)
  > 80%%  - Critical usage (action needed)

Exit codes:
  0 - Swap usage within acceptable limits
  1 - Swap usage exceeds thresholds or active swapping detected
  2 - Usage error or unable to read memory information
"""
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed interpretation'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show if there are issues'
    )

    parser.add_argument(
        '--warn',
        type=float,
        default=50.0,
        metavar='PERCENT',
        help='Warning threshold for swap usage (default: %(default)s)'
    )

    parser.add_argument(
        '--crit',
        type=float,
        default=80.0,
        metavar='PERCENT',
        help='Critical threshold for swap usage (default: %(default)s)'
    )

    parser.add_argument(
        '--swap-rate-warn',
        type=float,
        default=100.0,
        metavar='PAGES',
        help='Warning threshold for swap activity (pages/sec, default: 100)'
    )

    parser.add_argument(
        '--no-sample',
        action='store_true',
        help='Skip swap rate sampling (faster but no rate info)'
    )

    parser.add_argument(
        '--sample-interval',
        type=float,
        default=1.0,
        metavar='SECONDS',
        help='Interval for swap rate sampling (default: 1.0s)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.warn < 0 or args.warn > 100:
        print("Error: --warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)
    if args.crit < 0 or args.crit > 100:
        print("Error: --crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)
    if args.crit < args.warn:
        print("Error: --crit must be >= --warn", file=sys.stderr)
        sys.exit(2)
    if args.swap_rate_warn < 0:
        print("Error: --swap-rate-warn must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.sample_interval <= 0:
        print("Error: --sample-interval must be positive", file=sys.stderr)
        sys.exit(2)

    # Check if we can read /proc
    if not os.path.isfile('/proc/meminfo'):
        print("Error: /proc/meminfo not available", file=sys.stderr)
        print("This script requires the procfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Get memory info
    meminfo = read_meminfo()
    if meminfo is None:
        print("Error: Unable to read memory information", file=sys.stderr)
        sys.exit(2)

    # Get swap rates (optional)
    swap_rates = None
    if not args.no_sample:
        swap_rates = get_swap_rates(args.sample_interval)

    # Analyze
    analysis = analyze_swap(
        meminfo,
        swap_rates,
        warn_percent=args.warn,
        crit_percent=args.crit,
        swap_rate_warn=args.swap_rate_warn
    )

    # Output
    if args.format == 'json':
        output_json(analysis)
    elif args.format == 'table':
        output_table(analysis, args.warn_only)
    else:
        output_plain(analysis, args.warn_only, args.verbose)

    # Exit code
    if analysis['status'] in ['critical', 'warning']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
