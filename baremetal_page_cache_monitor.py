#!/usr/bin/env python3
"""
Monitor Linux page cache usage, dirty pages, and memory pressure indicators.

This script analyzes the kernel page cache to detect memory pressure, excessive
dirty pages, and cache efficiency issues. Critical for database servers, file
servers, and any workload sensitive to I/O performance.

The page cache is the kernel's mechanism for caching disk data in RAM. Issues
detected by this script include:

- High dirty page ratio: Too many pages waiting to be written to disk, which
  can cause I/O storms during writeback or data loss on crash
- Low cache hit rates: Poor cache efficiency indicating thrashing
- Memory pressure: Cache being evicted faster than it can be effective
- Writeback stalls: Dirty page limits being hit, causing sync writes

Useful for:
- Database servers (PostgreSQL, MySQL, MongoDB)
- File servers and NAS systems
- Build servers with heavy disk I/O
- Any system experiencing I/O latency spikes

Exit codes:
    0 - Page cache is healthy
    1 - Warnings or issues detected (high dirty ratio, pressure)
    2 - Usage error or /proc filesystem not available
"""

import argparse
import sys
import json
import os


def read_meminfo():
    """Parse /proc/meminfo and return relevant values.

    Returns:
        dict: Memory information in KB
    """
    meminfo = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    # Parse value, handling "1234 kB" format
                    parts = value.strip().split()
                    if parts:
                        try:
                            meminfo[key] = int(parts[0])
                        except ValueError:
                            pass
    except FileNotFoundError:
        print("Error: /proc/meminfo not found", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Permission denied reading /proc/meminfo", file=sys.stderr)
        sys.exit(2)

    return meminfo


def read_vmstat():
    """Parse /proc/vmstat for page cache statistics.

    Returns:
        dict: VM statistics
    """
    vmstat = {}
    try:
        with open('/proc/vmstat', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2:
                    try:
                        vmstat[parts[0]] = int(parts[1])
                    except ValueError:
                        pass
    except FileNotFoundError:
        # vmstat is optional
        pass
    except PermissionError:
        pass

    return vmstat


def read_dirty_limits():
    """Read dirty page writeback thresholds from sysctl.

    Returns:
        dict: Dirty page limits
    """
    limits = {
        'dirty_ratio': None,
        'dirty_background_ratio': None,
        'dirty_bytes': None,
        'dirty_background_bytes': None,
        'dirty_expire_centisecs': None,
        'dirty_writeback_centisecs': None,
    }

    sysctl_paths = {
        'dirty_ratio': '/proc/sys/vm/dirty_ratio',
        'dirty_background_ratio': '/proc/sys/vm/dirty_background_ratio',
        'dirty_bytes': '/proc/sys/vm/dirty_bytes',
        'dirty_background_bytes': '/proc/sys/vm/dirty_background_bytes',
        'dirty_expire_centisecs': '/proc/sys/vm/dirty_expire_centisecs',
        'dirty_writeback_centisecs': '/proc/sys/vm/dirty_writeback_centisecs',
    }

    for key, path in sysctl_paths.items():
        try:
            with open(path, 'r') as f:
                limits[key] = int(f.read().strip())
        except (FileNotFoundError, ValueError, PermissionError):
            pass

    return limits


def calculate_cache_stats(meminfo):
    """Calculate page cache statistics from meminfo.

    Args:
        meminfo: Dictionary from read_meminfo()

    Returns:
        dict: Calculated cache statistics
    """
    stats = {}

    # Total memory
    total_mem = meminfo.get('MemTotal', 0)
    stats['total_memory_kb'] = total_mem

    # Page cache = Cached + Buffers (traditional definition)
    # In newer kernels, Cached includes Shmem
    cached = meminfo.get('Cached', 0)
    buffers = meminfo.get('Buffers', 0)
    stats['cached_kb'] = cached
    stats['buffers_kb'] = buffers
    stats['page_cache_kb'] = cached + buffers

    # Dirty pages
    dirty = meminfo.get('Dirty', 0)
    writeback = meminfo.get('Writeback', 0)
    stats['dirty_kb'] = dirty
    stats['writeback_kb'] = writeback
    stats['dirty_total_kb'] = dirty + writeback

    # Active/Inactive cache
    stats['active_kb'] = meminfo.get('Active', 0)
    stats['inactive_kb'] = meminfo.get('Inactive', 0)
    stats['active_file_kb'] = meminfo.get('Active(file)', 0)
    stats['inactive_file_kb'] = meminfo.get('Inactive(file)', 0)

    # Available memory (kernel's estimate of memory available for new allocations)
    stats['available_kb'] = meminfo.get('MemAvailable', 0)
    stats['free_kb'] = meminfo.get('MemFree', 0)

    # Slab (kernel data structures cache)
    stats['slab_kb'] = meminfo.get('Slab', 0)
    stats['sreclaimable_kb'] = meminfo.get('SReclaimable', 0)
    stats['sunreclaim_kb'] = meminfo.get('SUnreclaim', 0)

    # Calculate ratios
    if total_mem > 0:
        stats['cache_ratio'] = (stats['page_cache_kb'] / total_mem) * 100
        stats['dirty_ratio'] = (stats['dirty_total_kb'] / total_mem) * 100
        stats['available_ratio'] = (stats['available_kb'] / total_mem) * 100
    else:
        stats['cache_ratio'] = 0
        stats['dirty_ratio'] = 0
        stats['available_ratio'] = 0

    # Dirty ratio relative to cache (not total memory)
    if stats['page_cache_kb'] > 0:
        stats['dirty_cache_ratio'] = (stats['dirty_total_kb'] / stats['page_cache_kb']) * 100
    else:
        stats['dirty_cache_ratio'] = 0

    return stats


def analyze_cache(stats, limits, vmstat, thresholds):
    """Analyze cache statistics and return issues.

    Args:
        stats: Cache statistics from calculate_cache_stats()
        limits: Dirty limits from read_dirty_limits()
        vmstat: VM stats from read_vmstat()
        thresholds: User-defined thresholds

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    # Check dirty page ratio (relative to total memory)
    dirty_pct = stats['dirty_ratio']
    if dirty_pct >= thresholds['dirty_critical']:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'high_dirty_pages',
            'value': round(dirty_pct, 2),
            'threshold': thresholds['dirty_critical'],
            'message': f"Critical dirty page ratio: {dirty_pct:.1f}% of memory "
                      f"({format_size(stats['dirty_total_kb'])} dirty/writeback)"
        })
    elif dirty_pct >= thresholds['dirty_warning']:
        issues.append({
            'severity': 'WARNING',
            'type': 'high_dirty_pages',
            'value': round(dirty_pct, 2),
            'threshold': thresholds['dirty_warning'],
            'message': f"Elevated dirty page ratio: {dirty_pct:.1f}% of memory "
                      f"({format_size(stats['dirty_total_kb'])} dirty/writeback)"
        })

    # Check if dirty pages are near the configured limit
    if limits['dirty_ratio'] and limits['dirty_ratio'] > 0:
        limit_usage = (dirty_pct / limits['dirty_ratio']) * 100
        if limit_usage >= 80:
            issues.append({
                'severity': 'WARNING',
                'type': 'near_dirty_limit',
                'value': round(limit_usage, 1),
                'message': f"Dirty pages at {limit_usage:.0f}% of kernel limit "
                          f"(vm.dirty_ratio={limits['dirty_ratio']}%)"
            })

    # Check writeback in progress
    if stats['writeback_kb'] > 0:
        writeback_mb = stats['writeback_kb'] / 1024
        if writeback_mb > thresholds['writeback_warning_mb']:
            issues.append({
                'severity': 'INFO',
                'type': 'active_writeback',
                'value': round(writeback_mb, 1),
                'message': f"Active writeback in progress: {format_size(stats['writeback_kb'])}"
            })

    # Check available memory (indicates overall memory pressure)
    available_pct = stats['available_ratio']
    if available_pct < thresholds['available_critical']:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'low_available_memory',
            'value': round(available_pct, 1),
            'threshold': thresholds['available_critical'],
            'message': f"Critical: Only {available_pct:.1f}% memory available "
                      f"({format_size(stats['available_kb'])})"
        })
    elif available_pct < thresholds['available_warning']:
        issues.append({
            'severity': 'WARNING',
            'type': 'low_available_memory',
            'value': round(available_pct, 1),
            'threshold': thresholds['available_warning'],
            'message': f"Low available memory: {available_pct:.1f}% "
                      f"({format_size(stats['available_kb'])})"
        })

    # Check page cache effectiveness (active vs inactive file cache)
    if stats['active_file_kb'] + stats['inactive_file_kb'] > 0:
        active_ratio = (stats['active_file_kb'] /
                       (stats['active_file_kb'] + stats['inactive_file_kb'])) * 100
        if active_ratio < 20 and stats['page_cache_kb'] > 1024 * 1024:  # Only if cache > 1GB
            issues.append({
                'severity': 'INFO',
                'type': 'low_active_cache',
                'value': round(active_ratio, 1),
                'message': f"Low active file cache ratio ({active_ratio:.0f}%) - "
                          f"possible cache thrashing"
            })

    # Check for page allocation pressure from vmstat
    pgsteal = vmstat.get('pgsteal_kswapd', 0) + vmstat.get('pgsteal_direct', 0)
    pgscan = vmstat.get('pgscan_kswapd', 0) + vmstat.get('pgscan_direct', 0)
    if pgscan > 0:
        steal_ratio = (pgsteal / pgscan) * 100
        # Low steal ratio with high scan indicates memory pressure
        if steal_ratio < 50 and pgscan > 10000:
            issues.append({
                'severity': 'INFO',
                'type': 'page_reclaim_pressure',
                'value': round(steal_ratio, 1),
                'message': f"Page reclaim efficiency low ({steal_ratio:.0f}% steal/scan ratio)"
            })

    return issues


def format_size(kb):
    """Format KB value to human-readable size."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f} GB"
    elif kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb} KB"


def output_plain(stats, limits, issues, verbose, warn_only):
    """Output results in plain text format."""
    lines = []

    if not warn_only:
        lines.append(f"Page Cache: {format_size(stats['page_cache_kb'])} "
                    f"({stats['cache_ratio']:.1f}% of memory)")
        lines.append(f"  Cached: {format_size(stats['cached_kb'])}")
        lines.append(f"  Buffers: {format_size(stats['buffers_kb'])}")
        lines.append("")

        lines.append(f"Dirty Pages: {format_size(stats['dirty_total_kb'])} "
                    f"({stats['dirty_ratio']:.2f}% of memory)")
        lines.append(f"  Dirty: {format_size(stats['dirty_kb'])}")
        lines.append(f"  Writeback: {format_size(stats['writeback_kb'])}")
        lines.append("")

        lines.append(f"Available Memory: {format_size(stats['available_kb'])} "
                    f"({stats['available_ratio']:.1f}%)")
        lines.append("")

        if verbose:
            lines.append("File Cache Activity:")
            lines.append(f"  Active(file): {format_size(stats['active_file_kb'])}")
            lines.append(f"  Inactive(file): {format_size(stats['inactive_file_kb'])}")
            lines.append("")

            if limits['dirty_ratio']:
                lines.append("Dirty Page Limits:")
                lines.append(f"  dirty_ratio: {limits['dirty_ratio']}%")
                lines.append(f"  dirty_background_ratio: {limits['dirty_background_ratio']}%")
                if limits['dirty_expire_centisecs']:
                    lines.append(f"  dirty_expire: {limits['dirty_expire_centisecs'] / 100:.1f}s")
                lines.append("")

    # Issues
    for issue in issues:
        if warn_only and issue['severity'] == 'INFO':
            continue
        lines.append(f"[{issue['severity']}] {issue['message']}")

    if not issues and not warn_only:
        lines.append("No page cache issues detected.")

    print('\n'.join(lines))


def output_json(stats, limits, issues, verbose):
    """Output results in JSON format."""
    result = {
        'page_cache': {
            'total_kb': stats['page_cache_kb'],
            'cached_kb': stats['cached_kb'],
            'buffers_kb': stats['buffers_kb'],
            'cache_ratio': round(stats['cache_ratio'], 2),
        },
        'dirty_pages': {
            'dirty_kb': stats['dirty_kb'],
            'writeback_kb': stats['writeback_kb'],
            'total_kb': stats['dirty_total_kb'],
            'ratio': round(stats['dirty_ratio'], 2),
            'cache_ratio': round(stats['dirty_cache_ratio'], 2),
        },
        'memory': {
            'total_kb': stats['total_memory_kb'],
            'available_kb': stats['available_kb'],
            'free_kb': stats['free_kb'],
            'available_ratio': round(stats['available_ratio'], 2),
        },
        'issues': issues,
    }

    if verbose:
        result['file_cache'] = {
            'active_kb': stats['active_file_kb'],
            'inactive_kb': stats['inactive_file_kb'],
        }
        result['limits'] = {
            'dirty_ratio': limits['dirty_ratio'],
            'dirty_background_ratio': limits['dirty_background_ratio'],
            'dirty_expire_centisecs': limits['dirty_expire_centisecs'],
        }

    print(json.dumps(result, indent=2))


def output_table(stats, limits, issues, verbose, warn_only):
    """Output results in table format."""
    lines = []

    if not warn_only:
        lines.append("=" * 60)
        lines.append("PAGE CACHE STATUS")
        lines.append("=" * 60)
        lines.append(f"{'Metric':<25} {'Value':<20} {'Percent':<15}")
        lines.append("-" * 60)
        lines.append(f"{'Page Cache':<25} {format_size(stats['page_cache_kb']):<20} "
                    f"{stats['cache_ratio']:.1f}%")
        lines.append(f"{'  Cached':<25} {format_size(stats['cached_kb']):<20}")
        lines.append(f"{'  Buffers':<25} {format_size(stats['buffers_kb']):<20}")
        lines.append(f"{'Dirty Pages':<25} {format_size(stats['dirty_total_kb']):<20} "
                    f"{stats['dirty_ratio']:.2f}%")
        lines.append(f"{'  In Writeback':<25} {format_size(stats['writeback_kb']):<20}")
        lines.append(f"{'Available Memory':<25} {format_size(stats['available_kb']):<20} "
                    f"{stats['available_ratio']:.1f}%")
        lines.append("=" * 60)
        lines.append("")

    if issues:
        lines.append("ISSUES DETECTED")
        lines.append("-" * 60)
        for issue in issues:
            if warn_only and issue['severity'] == 'INFO':
                continue
            lines.append(f"[{issue['severity']}] {issue['message']}")
        lines.append("")

    print('\n'.join(lines))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor Linux page cache usage and dirty pages',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Check page cache status
  %(prog)s --format json          # JSON output for monitoring
  %(prog)s --verbose              # Show detailed statistics
  %(prog)s --dirty-warn 5         # Warn if dirty pages > 5%% of memory
  %(prog)s --warn-only            # Only show warnings/errors

Thresholds:
  --dirty-warn: Dirty page ratio warning threshold (default: 10%%)
  --dirty-crit: Dirty page ratio critical threshold (default: 20%%)
  --avail-warn: Available memory warning threshold (default: 10%%)
  --avail-crit: Available memory critical threshold (default: 5%%)

Common tuning:
  # Reduce dirty page ratio for databases
  sysctl -w vm.dirty_ratio=5
  sysctl -w vm.dirty_background_ratio=2

  # Increase for write-heavy workloads with battery backup
  sysctl -w vm.dirty_ratio=40
  sysctl -w vm.dirty_background_ratio=10

Exit codes:
  0 - Page cache healthy
  1 - Warnings or issues detected
  2 - Usage error or missing /proc filesystem
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
        help='Show detailed statistics including limits and file cache activity'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors'
    )

    parser.add_argument(
        '--dirty-warn',
        type=float,
        default=10.0,
        metavar='PCT',
        help='Dirty page ratio warning threshold (default: 10%%)'
    )

    parser.add_argument(
        '--dirty-crit',
        type=float,
        default=20.0,
        metavar='PCT',
        help='Dirty page ratio critical threshold (default: 20%%)'
    )

    parser.add_argument(
        '--avail-warn',
        type=float,
        default=10.0,
        metavar='PCT',
        help='Available memory warning threshold (default: 10%%)'
    )

    parser.add_argument(
        '--avail-crit',
        type=float,
        default=5.0,
        metavar='PCT',
        help='Available memory critical threshold (default: 5%%)'
    )

    parser.add_argument(
        '--writeback-warn',
        type=float,
        default=100.0,
        metavar='MB',
        help='Active writeback warning threshold in MB (default: 100)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.dirty_warn < 0 or args.dirty_warn > 100:
        print("Error: --dirty-warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)
    if args.dirty_crit < 0 or args.dirty_crit > 100:
        print("Error: --dirty-crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)
    if args.dirty_warn >= args.dirty_crit:
        print("Error: --dirty-warn must be less than --dirty-crit", file=sys.stderr)
        sys.exit(2)
    if args.avail_warn < 0 or args.avail_warn > 100:
        print("Error: --avail-warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)
    if args.avail_crit < 0 or args.avail_crit > 100:
        print("Error: --avail-crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)
    if args.avail_crit >= args.avail_warn:
        print("Error: --avail-crit must be less than --avail-warn", file=sys.stderr)
        sys.exit(2)

    thresholds = {
        'dirty_warning': args.dirty_warn,
        'dirty_critical': args.dirty_crit,
        'available_warning': args.avail_warn,
        'available_critical': args.avail_crit,
        'writeback_warning_mb': args.writeback_warn,
    }

    # Gather information
    meminfo = read_meminfo()
    vmstat = read_vmstat()
    limits = read_dirty_limits()
    stats = calculate_cache_stats(meminfo)

    # Analyze
    issues = analyze_cache(stats, limits, vmstat, thresholds)

    # Output
    if args.format == 'json':
        output_json(stats, limits, issues, args.verbose)
    elif args.format == 'table':
        output_table(stats, limits, issues, args.verbose, args.warn_only)
    else:
        output_plain(stats, limits, issues, args.verbose, args.warn_only)

    # Exit code
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
