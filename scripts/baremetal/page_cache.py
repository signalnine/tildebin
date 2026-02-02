#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [memory, cache, dirty-pages, writeback, io]
#   requires: []
#   privilege: none
#   related: [memory_usage, disk_io_latency, proc_pressure]
#   brief: Monitor page cache usage and dirty page pressure

"""
Monitor Linux page cache usage, dirty pages, and memory pressure indicators.

Analyzes the kernel page cache to detect memory pressure, excessive dirty
pages, and cache efficiency issues. Critical for database servers, file
servers, and any workload sensitive to I/O performance.

Issues detected:
- High dirty page ratio: Too many pages waiting to be written to disk
- Low cache hit rates: Poor cache efficiency indicating thrashing
- Memory pressure: Cache being evicted faster than it can be effective
- Writeback stalls: Dirty page limits being hit, causing sync writes
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_meminfo(context: Context) -> dict[str, int]:
    """Parse /proc/meminfo and return relevant values in KB."""
    meminfo = {}
    try:
        content = context.read_file('/proc/meminfo')
        for line in content.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                parts = value.strip().split()
                if parts:
                    try:
                        meminfo[key] = int(parts[0])
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
    return meminfo


def read_vmstat(context: Context) -> dict[str, int]:
    """Parse /proc/vmstat for page cache statistics."""
    vmstat = {}
    try:
        content = context.read_file('/proc/vmstat')
        for line in content.split('\n'):
            parts = line.strip().split()
            if len(parts) == 2:
                try:
                    vmstat[parts[0]] = int(parts[1])
                except ValueError:
                    pass
    except (FileNotFoundError, PermissionError):
        pass
    return vmstat


def read_dirty_limits(context: Context) -> dict[str, int | None]:
    """Read dirty page writeback thresholds from sysctl."""
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
            content = context.read_file(path)
            limits[key] = int(content.strip())
        except (FileNotFoundError, ValueError, PermissionError):
            pass

    return limits


def calculate_cache_stats(meminfo: dict[str, int]) -> dict[str, Any]:
    """Calculate page cache statistics from meminfo."""
    stats = {}

    total_mem = meminfo.get('MemTotal', 0)
    stats['total_memory_kb'] = total_mem

    cached = meminfo.get('Cached', 0)
    buffers = meminfo.get('Buffers', 0)
    stats['cached_kb'] = cached
    stats['buffers_kb'] = buffers
    stats['page_cache_kb'] = cached + buffers

    dirty = meminfo.get('Dirty', 0)
    writeback = meminfo.get('Writeback', 0)
    stats['dirty_kb'] = dirty
    stats['writeback_kb'] = writeback
    stats['dirty_total_kb'] = dirty + writeback

    stats['active_kb'] = meminfo.get('Active', 0)
    stats['inactive_kb'] = meminfo.get('Inactive', 0)
    stats['active_file_kb'] = meminfo.get('Active(file)', 0)
    stats['inactive_file_kb'] = meminfo.get('Inactive(file)', 0)

    stats['available_kb'] = meminfo.get('MemAvailable', 0)
    stats['free_kb'] = meminfo.get('MemFree', 0)

    stats['slab_kb'] = meminfo.get('Slab', 0)
    stats['sreclaimable_kb'] = meminfo.get('SReclaimable', 0)
    stats['sunreclaim_kb'] = meminfo.get('SUnreclaim', 0)

    if total_mem > 0:
        stats['cache_ratio'] = (stats['page_cache_kb'] / total_mem) * 100
        stats['dirty_ratio'] = (stats['dirty_total_kb'] / total_mem) * 100
        stats['available_ratio'] = (stats['available_kb'] / total_mem) * 100
    else:
        stats['cache_ratio'] = 0
        stats['dirty_ratio'] = 0
        stats['available_ratio'] = 0

    if stats['page_cache_kb'] > 0:
        stats['dirty_cache_ratio'] = (stats['dirty_total_kb'] / stats['page_cache_kb']) * 100
    else:
        stats['dirty_cache_ratio'] = 0

    return stats


def format_size(kb: int) -> str:
    """Format KB value to human-readable size."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.1f}GB"
    elif kb >= 1024:
        return f"{kb / 1024:.1f}MB"
    else:
        return f"{kb}KB"


def analyze_cache(stats: dict, limits: dict, thresholds: dict) -> list[dict]:
    """Analyze cache statistics and return issues."""
    issues = []

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
            'message': f"Elevated dirty page ratio: {dirty_pct:.1f}% of memory"
        })

    if limits['dirty_ratio'] and limits['dirty_ratio'] > 0:
        limit_usage = (dirty_pct / limits['dirty_ratio']) * 100
        if limit_usage >= 80:
            issues.append({
                'severity': 'WARNING',
                'type': 'near_dirty_limit',
                'value': round(limit_usage, 1),
                'message': f"Dirty pages at {limit_usage:.0f}% of kernel limit"
            })

    available_pct = stats['available_ratio']
    if available_pct < thresholds['available_critical']:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'low_available_memory',
            'value': round(available_pct, 1),
            'threshold': thresholds['available_critical'],
            'message': f"Critical: Only {available_pct:.1f}% memory available"
        })
    elif available_pct < thresholds['available_warning']:
        issues.append({
            'severity': 'WARNING',
            'type': 'low_available_memory',
            'value': round(available_pct, 1),
            'threshold': thresholds['available_warning'],
            'message': f"Low available memory: {available_pct:.1f}%"
        })

    return issues


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
    parser = argparse.ArgumentParser(description="Monitor page cache usage and dirty pages")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed statistics")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--dirty-warn", type=float, default=10.0,
                        help="Dirty page ratio warning threshold")
    parser.add_argument("--dirty-crit", type=float, default=20.0,
                        help="Dirty page ratio critical threshold")
    parser.add_argument("--avail-warn", type=float, default=10.0,
                        help="Available memory warning threshold")
    parser.add_argument("--avail-crit", type=float, default=5.0,
                        help="Available memory critical threshold")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.dirty_warn >= opts.dirty_crit:
        output.error("--dirty-warn must be less than --dirty-crit")
        return 2
    if opts.avail_crit >= opts.avail_warn:
        output.error("--avail-crit must be less than --avail-warn")
        return 2

    thresholds = {
        'dirty_warning': opts.dirty_warn,
        'dirty_critical': opts.dirty_crit,
        'available_warning': opts.avail_warn,
        'available_critical': opts.avail_crit,
    }

    # Gather information
    meminfo = read_meminfo(context)
    if not meminfo:
        output.error("/proc/meminfo not available")
        return 2

    vmstat = read_vmstat(context)
    limits = read_dirty_limits(context)
    stats = calculate_cache_stats(meminfo)

    # Analyze
    issues = analyze_cache(stats, limits, thresholds)

    # Build result
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
        },
        'memory': {
            'total_kb': stats['total_memory_kb'],
            'available_kb': stats['available_kb'],
            'available_ratio': round(stats['available_ratio'], 2),
        },
        'issues': issues,
    }

    if opts.verbose:
        result['file_cache'] = {
            'active_kb': stats['active_file_kb'],
            'inactive_kb': stats['inactive_file_kb'],
        }
        result['limits'] = {
            'dirty_ratio': limits['dirty_ratio'],
            'dirty_background_ratio': limits['dirty_background_ratio'],
        }

    output.emit(result)

    # Set summary
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical:
        output.set_summary(f"Critical: {issues[0]['message']}")
        return 1
    elif has_warning:
        output.set_summary(f"Warning: {len(issues)} issue(s) detected")
        return 1
    else:
        output.set_summary(f"Page cache healthy, {stats['dirty_ratio']:.1f}% dirty")
        return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
