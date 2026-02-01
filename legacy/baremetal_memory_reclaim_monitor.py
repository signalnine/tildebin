#!/usr/bin/env python3
"""
Monitor kernel memory reclamation activity and detect memory pressure.

This script analyzes /proc/vmstat to track memory reclamation metrics including:
- kswapd activity (background reclaim)
- Direct reclaim events (synchronous, blocks applications)
- Page scan rates (how aggressively the kernel is looking for free memory)
- Compaction activity (memory defragmentation)

Memory reclamation activity is an early indicator of memory pressure. High direct
reclaim rates indicate applications are being blocked waiting for memory, which
causes latency spikes. High kswapd activity indicates the system is working hard
to keep free memory available.

Useful for large-scale baremetal environments to detect memory pressure before
it impacts application performance or triggers the OOM killer.

Exit codes:
    0 - No memory pressure detected (healthy state)
    1 - Memory pressure or high reclaim activity detected
    2 - Missing /proc/vmstat or usage error
"""

import argparse
import sys
import json
import os


def read_proc_vmstat():
    """Read VM statistics from /proc/vmstat.

    Returns:
        dict: VM statistics as key-value pairs
    """
    try:
        vmstat = {}
        with open('/proc/vmstat', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2:
                    vmstat[parts[0]] = int(parts[1])
        return vmstat
    except FileNotFoundError:
        print("Error: /proc/vmstat not found (non-Linux system?)", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Permission denied reading /proc/vmstat", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading /proc/vmstat: {e}", file=sys.stderr)
        sys.exit(2)


def read_proc_meminfo():
    """Read memory information from /proc/meminfo.

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
        print("Error: /proc/meminfo not found", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading /proc/meminfo: {e}", file=sys.stderr)
        sys.exit(2)


def calculate_reclaim_metrics(vmstat):
    """Calculate memory reclaim metrics from vmstat.

    Args:
        vmstat: Dictionary of vmstat values

    Returns:
        dict: Calculated reclaim metrics
    """
    metrics = {}

    # kswapd activity (background reclaim)
    # These are cumulative since boot
    metrics['kswapd_steal'] = vmstat.get('pgsteal_kswapd', 0)
    metrics['kswapd_scan'] = vmstat.get('pgscan_kswapd', 0)

    # Direct reclaim (synchronous, application-blocking)
    metrics['direct_steal'] = vmstat.get('pgsteal_direct', 0)
    metrics['direct_scan'] = vmstat.get('pgscan_direct', 0)

    # Also check older kernel naming convention
    if metrics['kswapd_steal'] == 0:
        metrics['kswapd_steal'] = vmstat.get('pgsteal_kswapd_normal', 0) + \
                                   vmstat.get('pgsteal_kswapd_movable', 0) + \
                                   vmstat.get('pgsteal_kswapd_dma', 0) + \
                                   vmstat.get('pgsteal_kswapd_dma32', 0)

    if metrics['direct_steal'] == 0:
        metrics['direct_steal'] = vmstat.get('pgsteal_direct_normal', 0) + \
                                   vmstat.get('pgsteal_direct_movable', 0) + \
                                   vmstat.get('pgsteal_direct_dma', 0) + \
                                   vmstat.get('pgsteal_direct_dma32', 0)

    if metrics['kswapd_scan'] == 0:
        metrics['kswapd_scan'] = vmstat.get('pgscan_kswapd_normal', 0) + \
                                  vmstat.get('pgscan_kswapd_movable', 0) + \
                                  vmstat.get('pgscan_kswapd_dma', 0) + \
                                  vmstat.get('pgscan_kswapd_dma32', 0)

    if metrics['direct_scan'] == 0:
        metrics['direct_scan'] = vmstat.get('pgscan_direct_normal', 0) + \
                                  vmstat.get('pgscan_direct_movable', 0) + \
                                  vmstat.get('pgscan_direct_dma', 0) + \
                                  vmstat.get('pgscan_direct_dma32', 0)

    # Total reclaim activity
    metrics['total_steal'] = metrics['kswapd_steal'] + metrics['direct_steal']
    metrics['total_scan'] = metrics['kswapd_scan'] + metrics['direct_scan']

    # Reclaim efficiency (pages reclaimed per page scanned)
    # Higher is better - indicates less work to reclaim memory
    if metrics['total_scan'] > 0:
        metrics['reclaim_efficiency'] = metrics['total_steal'] / metrics['total_scan'] * 100
    else:
        metrics['reclaim_efficiency'] = 100.0

    # Compaction activity (memory defragmentation)
    metrics['compact_stall'] = vmstat.get('compact_stall', 0)
    metrics['compact_fail'] = vmstat.get('compact_fail', 0)
    metrics['compact_success'] = vmstat.get('compact_success', 0)

    # OOM killer invocations
    metrics['oom_kill'] = vmstat.get('oom_kill', 0)

    # Page allocation stalls
    metrics['allocstall'] = vmstat.get('allocstall', 0)
    if metrics['allocstall'] == 0:
        # Try zone-specific stalls
        metrics['allocstall'] = vmstat.get('allocstall_normal', 0) + \
                                vmstat.get('allocstall_movable', 0) + \
                                vmstat.get('allocstall_dma', 0) + \
                                vmstat.get('allocstall_dma32', 0)

    # Pageout (write to swap)
    metrics['pswpout'] = vmstat.get('pswpout', 0)
    metrics['pswpin'] = vmstat.get('pswpin', 0)

    return metrics


def analyze_reclaim_activity(metrics, thresholds, meminfo):
    """Analyze reclaim metrics and return issues.

    Args:
        metrics: Dictionary of reclaim metrics
        thresholds: Dictionary of threshold values
        meminfo: Dictionary of memory info

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    # Check for OOM kills (always critical)
    if metrics['oom_kill'] > 0:
        issues.append({
            'severity': 'CRITICAL',
            'metric': 'oom_kill',
            'value': metrics['oom_kill'],
            'message': f"OOM killer has been invoked {metrics['oom_kill']} time(s) since boot"
        })

    # Check direct reclaim activity (high values indicate application blocking)
    if metrics['direct_scan'] > thresholds['direct_reclaim']:
        issues.append({
            'severity': 'WARNING',
            'metric': 'direct_scan',
            'value': metrics['direct_scan'],
            'threshold': thresholds['direct_reclaim'],
            'message': f"High direct reclaim activity: {metrics['direct_scan']:,} pages scanned "
                      f"(applications may be blocking on memory allocation)"
        })

    # Check allocation stalls
    if metrics['allocstall'] > thresholds['allocstall']:
        issues.append({
            'severity': 'WARNING',
            'metric': 'allocstall',
            'value': metrics['allocstall'],
            'threshold': thresholds['allocstall'],
            'message': f"High allocation stalls: {metrics['allocstall']:,} "
                      f"(processes blocked waiting for memory)"
        })

    # Check reclaim efficiency
    if metrics['total_scan'] > 10000:  # Only check if there's meaningful activity
        if metrics['reclaim_efficiency'] < thresholds['efficiency']:
            issues.append({
                'severity': 'WARNING',
                'metric': 'reclaim_efficiency',
                'value': metrics['reclaim_efficiency'],
                'threshold': thresholds['efficiency'],
                'message': f"Low reclaim efficiency: {metrics['reclaim_efficiency']:.1f}% "
                          f"(kernel scanning many pages to reclaim few)"
            })

    # Check compaction failures
    if metrics['compact_stall'] > thresholds['compact_stall']:
        failure_rate = 0
        if metrics['compact_stall'] > 0:
            failure_rate = metrics['compact_fail'] / metrics['compact_stall'] * 100

        if failure_rate > 50:
            issues.append({
                'severity': 'WARNING',
                'metric': 'compact_fail',
                'value': failure_rate,
                'message': f"High compaction failure rate: {failure_rate:.1f}% "
                          f"({metrics['compact_fail']:,} failures / {metrics['compact_stall']:,} attempts)"
            })

    # Check available memory (context for reclaim activity)
    mem_total = meminfo.get('MemTotal', 0)
    mem_available = meminfo.get('MemAvailable', 0)
    if mem_total > 0:
        avail_pct = (mem_available / mem_total) * 100
        if avail_pct < 5:
            issues.append({
                'severity': 'CRITICAL',
                'metric': 'mem_available',
                'value': avail_pct,
                'message': f"Very low available memory: {avail_pct:.1f}% - imminent OOM risk"
            })
        elif avail_pct < 10:
            issues.append({
                'severity': 'WARNING',
                'metric': 'mem_available',
                'value': avail_pct,
                'message': f"Low available memory: {avail_pct:.1f}%"
            })

    return issues


def format_pages(pages):
    """Format page count to human readable format (assuming 4KB pages)."""
    bytes_val = pages * 4096
    if bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.1f} GB"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.1f} MB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KB"
    else:
        return f"{bytes_val} B"


def output_plain(metrics, meminfo, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only or issues:
        print("Memory Reclaim Activity (since boot):")
        print(f"  kswapd pages scanned: {metrics['kswapd_scan']:,} ({format_pages(metrics['kswapd_scan'])})")
        print(f"  kswapd pages stolen:  {metrics['kswapd_steal']:,} ({format_pages(metrics['kswapd_steal'])})")
        print(f"  Direct reclaim scan:  {metrics['direct_scan']:,} ({format_pages(metrics['direct_scan'])})")
        print(f"  Direct reclaim steal: {metrics['direct_steal']:,} ({format_pages(metrics['direct_steal'])})")
        print(f"  Reclaim efficiency:   {metrics['reclaim_efficiency']:.1f}%")
        print()

        if verbose:
            print("Additional Metrics:")
            print(f"  Allocation stalls:    {metrics['allocstall']:,}")
            print(f"  Compaction stalls:    {metrics['compact_stall']:,}")
            print(f"  Compaction failures:  {metrics['compact_fail']:,}")
            print(f"  Compaction successes: {metrics['compact_success']:,}")
            print(f"  OOM kills:            {metrics['oom_kill']}")
            print(f"  Swap pages in:        {metrics['pswpin']:,}")
            print(f"  Swap pages out:       {metrics['pswpout']:,}")
            print()

            mem_total = meminfo.get('MemTotal', 0)
            mem_available = meminfo.get('MemAvailable', 0)
            if mem_total > 0:
                avail_pct = (mem_available / mem_total) * 100
                print(f"Current Memory Status:")
                print(f"  Available: {mem_available:,} KB ({avail_pct:.1f}%)")
            print()

    if issues:
        print("Detected Issues:")
        for issue in issues:
            severity = issue['severity']
            if warn_only and severity == 'INFO':
                continue
            print(f"  [{severity}] {issue['message']}")
    elif not warn_only:
        print("[OK] No memory pressure detected")


def output_json(metrics, meminfo, issues, verbose):
    """Output results in JSON format."""
    result = {
        'reclaim': {
            'kswapd_scan': metrics['kswapd_scan'],
            'kswapd_steal': metrics['kswapd_steal'],
            'direct_scan': metrics['direct_scan'],
            'direct_steal': metrics['direct_steal'],
            'total_scan': metrics['total_scan'],
            'total_steal': metrics['total_steal'],
            'efficiency_percent': round(metrics['reclaim_efficiency'], 2)
        },
        'memory': {
            'total_kb': meminfo.get('MemTotal', 0),
            'available_kb': meminfo.get('MemAvailable', 0),
            'available_percent': round(
                (meminfo.get('MemAvailable', 0) / meminfo.get('MemTotal', 1)) * 100, 2
            )
        },
        'issues': issues,
        'has_issues': len([i for i in issues if i['severity'] != 'INFO']) > 0
    }

    if verbose:
        result['additional'] = {
            'allocstall': metrics['allocstall'],
            'compact_stall': metrics['compact_stall'],
            'compact_fail': metrics['compact_fail'],
            'compact_success': metrics['compact_success'],
            'oom_kill': metrics['oom_kill'],
            'pswpin': metrics['pswpin'],
            'pswpout': metrics['pswpout']
        }

    print(json.dumps(result, indent=2))


def output_table(metrics, meminfo, issues, verbose, warn_only):
    """Output results in table format."""
    if not warn_only or issues:
        print("=" * 70)
        print("MEMORY RECLAIM ACTIVITY (since boot)")
        print("=" * 70)
        print(f"{'Metric':<30} {'Pages':<15} {'Size':<15}")
        print("-" * 70)
        print(f"{'kswapd pages scanned':<30} {metrics['kswapd_scan']:<15,} {format_pages(metrics['kswapd_scan']):<15}")
        print(f"{'kswapd pages stolen':<30} {metrics['kswapd_steal']:<15,} {format_pages(metrics['kswapd_steal']):<15}")
        print(f"{'Direct reclaim scanned':<30} {metrics['direct_scan']:<15,} {format_pages(metrics['direct_scan']):<15}")
        print(f"{'Direct reclaim stolen':<30} {metrics['direct_steal']:<15,} {format_pages(metrics['direct_steal']):<15}")
        print("-" * 70)
        print(f"{'Reclaim efficiency':<30} {metrics['reclaim_efficiency']:.1f}%")
        print("=" * 70)

        if verbose:
            print()
            print("ADDITIONAL METRICS")
            print("-" * 70)
            print(f"{'Allocation stalls':<30} {metrics['allocstall']:,}")
            print(f"{'Compaction stalls':<30} {metrics['compact_stall']:,}")
            print(f"{'Compaction failures':<30} {metrics['compact_fail']:,}")
            print(f"{'Compaction successes':<30} {metrics['compact_success']:,}")
            print(f"{'OOM kills':<30} {metrics['oom_kill']}")
            print(f"{'Swap pages in':<30} {metrics['pswpin']:,}")
            print(f"{'Swap pages out':<30} {metrics['pswpout']:,}")
            print("-" * 70)

        print()

    if issues:
        print("ISSUES DETECTED")
        print("=" * 70)
        for issue in issues:
            severity = issue['severity']
            if warn_only and severity == 'INFO':
                continue
            print(f"[{severity}] {issue['message']}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor kernel memory reclamation activity and detect memory pressure',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check reclaim activity with default thresholds
  %(prog)s --format json            # JSON output for monitoring tools
  %(prog)s --verbose                # Show additional metrics
  %(prog)s --warn-only              # Only show if issues detected
  %(prog)s --direct-reclaim 50000   # Custom direct reclaim threshold

Thresholds:
  --direct-reclaim: Direct reclaim pages scanned threshold (default: 100000)
  --allocstall: Allocation stall count threshold (default: 1000)
  --efficiency: Minimum reclaim efficiency percentage (default: 10)
  --compact-stall: Compaction stall count threshold (default: 10000)

Memory Reclaim Overview:
  kswapd: Background kernel thread that reclaims memory proactively
  Direct reclaim: Synchronous reclaim that blocks the allocating process
  High direct reclaim indicates memory pressure affecting application latency

Exit codes:
  0 - No memory pressure detected
  1 - Memory pressure or high reclaim activity detected
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
        help='Show additional memory reclaim statistics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--direct-reclaim',
        type=int,
        default=100000,
        metavar='N',
        help='Direct reclaim pages scanned threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--allocstall',
        type=int,
        default=1000,
        metavar='N',
        help='Allocation stall count threshold (default: %(default)s)'
    )

    parser.add_argument(
        '--efficiency',
        type=float,
        default=10.0,
        metavar='PCT',
        help='Minimum reclaim efficiency percentage (default: %(default)s)'
    )

    parser.add_argument(
        '--compact-stall',
        type=int,
        default=10000,
        metavar='N',
        help='Compaction stall count threshold (default: %(default)s)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.direct_reclaim < 0:
        print("Error: --direct-reclaim must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.allocstall < 0:
        print("Error: --allocstall must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.efficiency < 0 or args.efficiency > 100:
        print("Error: --efficiency must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.compact_stall < 0:
        print("Error: --compact-stall must be non-negative", file=sys.stderr)
        sys.exit(2)

    thresholds = {
        'direct_reclaim': args.direct_reclaim,
        'allocstall': args.allocstall,
        'efficiency': args.efficiency,
        'compact_stall': args.compact_stall
    }

    # Read system information
    vmstat = read_proc_vmstat()
    meminfo = read_proc_meminfo()

    # Calculate metrics
    metrics = calculate_reclaim_metrics(vmstat)

    # Analyze for issues
    issues = analyze_reclaim_activity(metrics, thresholds, meminfo)

    # Output results
    if args.format == 'json':
        output_json(metrics, meminfo, issues, args.verbose)
    elif args.format == 'table':
        output_table(metrics, meminfo, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(metrics, meminfo, issues, args.verbose, args.warn_only)

    # Determine exit code
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
