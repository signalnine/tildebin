#!/usr/bin/env python3
"""
Monitor swap usage and memory pressure indicators.

This script monitors swap space usage and related memory pressure metrics
to help identify systems experiencing memory exhaustion. Useful for:

- Detecting excessive swap usage indicating insufficient RAM
- Identifying memory pressure before OOM killer activation
- Tracking swap I/O activity which can cause performance degradation
- Finding systems that need memory upgrades or workload reduction

The script analyzes /proc/meminfo for swap usage and /proc/vmstat for
swap activity (page in/out rates). High swap usage or frequent swap I/O
indicates memory pressure and potential performance issues.

Exit codes:
    0 - Swap usage is within acceptable range, no memory pressure
    1 - High swap usage or excessive swap activity detected
    2 - Usage error or /proc filesystem not available
"""

import argparse
import sys
import json
import os


def read_proc_meminfo():
    """Read memory statistics from /proc/meminfo.

    Returns:
        dict: Memory statistics in KB
    """
    try:
        meminfo = {}
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if ':' in line:
                    key, value = line.split(':', 1)
                    # Extract numeric value (remove 'kB' suffix)
                    value = value.strip().split()[0]
                    meminfo[key.strip()] = int(value)
        return meminfo
    except FileNotFoundError:
        print("Error: /proc/meminfo not found (non-Linux system?)", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading /proc/meminfo: {e}", file=sys.stderr)
        sys.exit(2)


def read_proc_vmstat():
    """Read VM statistics from /proc/vmstat.

    Returns:
        dict: VM statistics
    """
    try:
        vmstat = {}
        with open('/proc/vmstat', 'r') as f:
            for line in f:
                if ' ' in line:
                    key, value = line.strip().split(None, 1)
                    vmstat[key] = int(value)
        return vmstat
    except FileNotFoundError:
        # /proc/vmstat might not exist on all systems
        return {}
    except Exception as e:
        print(f"Warning: Could not read /proc/vmstat: {e}", file=sys.stderr)
        return {}


def analyze_swap_usage(meminfo, swap_threshold_pct, swap_critical_pct):
    """Analyze swap usage and return issues.

    Args:
        meminfo: Dictionary of memory statistics
        swap_threshold_pct: Warning threshold percentage
        swap_critical_pct: Critical threshold percentage

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    swap_total = meminfo.get('SwapTotal', 0)
    swap_free = meminfo.get('SwapFree', 0)
    swap_cached = meminfo.get('SwapCached', 0)

    # Calculate swap usage
    swap_used = swap_total - swap_free

    # Handle systems without swap
    if swap_total == 0:
        return [{
            'severity': 'INFO',
            'metric': 'swap_total',
            'value': 0,
            'message': 'No swap space configured (may be intentional for containerized workloads)'
        }]

    # Calculate usage percentage
    swap_used_pct = (swap_used / swap_total * 100) if swap_total > 0 else 0

    # Check swap usage thresholds
    if swap_used_pct >= swap_critical_pct:
        issues.append({
            'severity': 'CRITICAL',
            'metric': 'swap_usage',
            'value': swap_used_pct,
            'threshold': swap_critical_pct,
            'message': f'Swap usage is critically high: {swap_used_pct:.1f}% '
                      f'({swap_used} KB / {swap_total} KB)'
        })
    elif swap_used_pct >= swap_threshold_pct:
        issues.append({
            'severity': 'WARNING',
            'metric': 'swap_usage',
            'value': swap_used_pct,
            'threshold': swap_threshold_pct,
            'message': f'Swap usage is elevated: {swap_used_pct:.1f}% '
                      f'({swap_used} KB / {swap_total} KB)'
        })

    # Check swap cache (high cache indicates recent swap activity)
    if swap_cached > 0:
        swap_cached_pct = (swap_cached / swap_total * 100) if swap_total > 0 else 0
        if swap_cached_pct > 5:  # More than 5% cached is notable
            issues.append({
                'severity': 'INFO',
                'metric': 'swap_cached',
                'value': swap_cached_pct,
                'message': f'Swap cache active: {swap_cached_pct:.1f}% '
                          f'({swap_cached} KB cached, indicates recent swap I/O)'
            })

    return issues


def analyze_memory_pressure(meminfo):
    """Analyze overall memory pressure indicators.

    Args:
        meminfo: Dictionary of memory statistics

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    mem_total = meminfo.get('MemTotal', 0)
    mem_available = meminfo.get('MemAvailable', 0)

    if mem_total == 0:
        return issues

    # Calculate available memory percentage
    mem_available_pct = (mem_available / mem_total * 100)

    # Warn if available memory is very low
    if mem_available_pct < 5:
        issues.append({
            'severity': 'CRITICAL',
            'metric': 'mem_available',
            'value': mem_available_pct,
            'message': f'Very low available memory: {mem_available_pct:.1f}% '
                      f'({mem_available} KB / {mem_total} KB) - OOM risk'
        })
    elif mem_available_pct < 10:
        issues.append({
            'severity': 'WARNING',
            'metric': 'mem_available',
            'value': mem_available_pct,
            'message': f'Low available memory: {mem_available_pct:.1f}% '
                      f'({mem_available} KB / {mem_total} KB)'
        })

    return issues


def format_bytes(kb):
    """Format KB value to human readable format."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb} KB"


def output_plain(meminfo, vmstat, issues, verbose, warn_only):
    """Output results in plain text format."""
    swap_total = meminfo.get('SwapTotal', 0)
    swap_free = meminfo.get('SwapFree', 0)
    swap_used = swap_total - swap_free
    swap_cached = meminfo.get('SwapCached', 0)

    mem_total = meminfo.get('MemTotal', 0)
    mem_available = meminfo.get('MemAvailable', 0)

    if not warn_only or issues:
        print(f"Swap: {format_bytes(swap_used)} / {format_bytes(swap_total)} "
              f"({(swap_used / swap_total * 100) if swap_total > 0 else 0:.1f}% used)")

        if swap_cached > 0:
            print(f"Swap cached: {format_bytes(swap_cached)}")

        if verbose:
            print(f"Memory available: {format_bytes(mem_available)} / {format_bytes(mem_total)} "
                  f"({(mem_available / mem_total * 100):.1f}%)")

            # Show swap in/out from vmstat if available
            if vmstat:
                pswpin = vmstat.get('pswpin', 0)
                pswpout = vmstat.get('pswpout', 0)
                if pswpin > 0 or pswpout > 0:
                    print(f"Swap I/O since boot: {pswpin} pages in, {pswpout} pages out")

        print()

    # Print issues
    for issue in issues:
        severity = issue['severity']
        message = issue['message']

        # Skip INFO messages in warn-only mode
        if warn_only and severity == 'INFO':
            continue

        prefix = {
            'CRITICAL': '[CRITICAL]',
            'WARNING': '[WARNING]',
            'INFO': '[INFO]'
        }.get(severity, '[UNKNOWN]')

        print(f"{prefix} {message}")


def output_json(meminfo, vmstat, issues, verbose):
    """Output results in JSON format."""
    swap_total = meminfo.get('SwapTotal', 0)
    swap_free = meminfo.get('SwapFree', 0)
    swap_used = swap_total - swap_free

    result = {
        'swap': {
            'total_kb': swap_total,
            'used_kb': swap_used,
            'free_kb': swap_free,
            'cached_kb': meminfo.get('SwapCached', 0),
            'usage_percent': (swap_used / swap_total * 100) if swap_total > 0 else 0
        },
        'memory': {
            'total_kb': meminfo.get('MemTotal', 0),
            'available_kb': meminfo.get('MemAvailable', 0),
            'available_percent': (meminfo.get('MemAvailable', 0) / meminfo.get('MemTotal', 1) * 100)
        },
        'issues': issues
    }

    if verbose and vmstat:
        result['vmstat'] = {
            'pswpin': vmstat.get('pswpin', 0),
            'pswpout': vmstat.get('pswpout', 0)
        }

    print(json.dumps(result, indent=2))


def output_table(meminfo, vmstat, issues, verbose, warn_only):
    """Output results in table format."""
    swap_total = meminfo.get('SwapTotal', 0)
    swap_free = meminfo.get('SwapFree', 0)
    swap_used = swap_total - swap_free
    swap_cached = meminfo.get('SwapCached', 0)

    mem_total = meminfo.get('MemTotal', 0)
    mem_available = meminfo.get('MemAvailable', 0)

    if not warn_only or issues:
        print("=" * 70)
        print("SWAP USAGE SUMMARY")
        print("=" * 70)
        print(f"{'Metric':<25} {'Value':<20} {'Percentage':<15}")
        print("-" * 70)
        print(f"{'Swap Total':<25} {format_bytes(swap_total):<20} {'100.0%':<15}")
        print(f"{'Swap Used':<25} {format_bytes(swap_used):<20} "
              f"{(swap_used / swap_total * 100) if swap_total > 0 else 0:.1f}%")
        print(f"{'Swap Free':<25} {format_bytes(swap_free):<20} "
              f"{(swap_free / swap_total * 100) if swap_total > 0 else 0:.1f}%")

        if swap_cached > 0:
            print(f"{'Swap Cached':<25} {format_bytes(swap_cached):<20} "
                  f"{(swap_cached / swap_total * 100) if swap_total > 0 else 0:.1f}%")

        if verbose:
            print()
            print(f"{'Memory Available':<25} {format_bytes(mem_available):<20} "
                  f"{(mem_available / mem_total * 100):.1f}%")

            if vmstat:
                pswpin = vmstat.get('pswpin', 0)
                pswpout = vmstat.get('pswpout', 0)
                print(f"{'Swap Pages In':<25} {pswpin:<20}")
                print(f"{'Swap Pages Out':<25} {pswpout:<20}")

        print("=" * 70)
        print()

    # Print issues
    if issues:
        print("ISSUES DETECTED")
        print("=" * 70)
        for issue in issues:
            severity = issue['severity']

            # Skip INFO messages in warn-only mode
            if warn_only and severity == 'INFO':
                continue

            print(f"[{severity}] {issue['message']}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor swap usage and memory pressure indicators',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check swap usage with default thresholds
  %(prog)s --warn 60 --crit 80  # Custom thresholds
  %(prog)s --format json        # JSON output for monitoring tools
  %(prog)s --verbose            # Show additional memory statistics
  %(prog)s --warn-only          # Only show warnings/errors

Thresholds:
  --warn: Percentage of swap usage to trigger warning (default: 50%%)
  --crit: Percentage of swap usage to trigger critical alert (default: 75%%)

Exit codes:
  0 - Swap usage within acceptable range
  1 - High swap usage or memory pressure detected
  2 - Usage error or /proc filesystem unavailable
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed memory and swap statistics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--warn',
        type=float,
        default=50.0,
        metavar='PCT',
        help='Warning threshold for swap usage percentage (default: 50%%)'
    )

    parser.add_argument(
        '--crit',
        type=float,
        default=75.0,
        metavar='PCT',
        help='Critical threshold for swap usage percentage (default: 75%%)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn < 0 or args.warn > 100:
        print("Error: --warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.crit < 0 or args.crit > 100:
        print("Error: --crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.warn >= args.crit:
        print("Error: --warn must be less than --crit", file=sys.stderr)
        sys.exit(2)

    # Read system information
    meminfo = read_proc_meminfo()
    vmstat = read_proc_vmstat()

    # Analyze swap and memory
    issues = []
    issues.extend(analyze_swap_usage(meminfo, args.warn, args.crit))
    issues.extend(analyze_memory_pressure(meminfo))

    # Output results
    if args.format == 'json':
        output_json(meminfo, vmstat, issues, args.verbose)
    elif args.format == 'table':
        output_table(meminfo, vmstat, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(meminfo, vmstat, issues, args.verbose, args.warn_only)

    # Determine exit code based on issues
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
