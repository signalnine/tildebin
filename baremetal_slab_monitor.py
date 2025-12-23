#!/usr/bin/env python3
"""
Monitor kernel slab allocator health and detect memory fragmentation issues.

The slab allocator is the Linux kernel's object-caching memory allocator.
Monitoring slab usage helps identify kernel memory pressure, memory leaks
in kernel modules, and potential fragmentation issues before they cause
system instability.

This script parses /proc/slabinfo to analyze:
- Total slab memory consumption
- Per-cache memory usage and object counts
- Active vs total object ratios (efficiency)
- Slabs with high growth or unusual patterns
- Memory fragmentation indicators

Common slab caches to monitor:
- dentry: Directory entry cache (filesystem metadata)
- inode_cache: Inode cache (file metadata)
- buffer_head: Buffer cache headers
- task_struct: Process descriptors
- kmalloc-*: General kernel allocations
- TCP/UDP/skbuff: Network buffers

Useful for:
- Detecting kernel memory leaks
- Identifying runaway caches (dentry storms, inode leaks)
- Pre-maintenance system health verification
- Capacity planning for kernel memory usage
- Troubleshooting OOM issues with high slab consumption

Exit codes:
    0 - Slab usage within normal parameters
    1 - Warnings or issues detected
    2 - Usage error or missing data sources
"""

import argparse
import sys
import os
import json


def parse_slabinfo():
    """
    Parse /proc/slabinfo and return slab cache statistics.

    /proc/slabinfo format (version 2.1):
    # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab>
    # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables ...
    """
    caches = {}

    try:
        with open('/proc/slabinfo', 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None, "slabinfo not found"
    except PermissionError:
        return None, "permission denied reading slabinfo (try running as root)"

    # Skip header lines
    for line in lines:
        line = line.strip()

        # Skip comments and headers
        if line.startswith('#') or line.startswith('slabinfo'):
            continue

        # Handle lines with tunables section (colon separator)
        if ':' in line:
            line = line.split(':')[0]

        parts = line.split()
        if len(parts) < 6:
            continue

        try:
            name = parts[0]
            active_objs = int(parts[1])
            num_objs = int(parts[2])
            obj_size = int(parts[3])
            objs_per_slab = int(parts[4])
            pages_per_slab = int(parts[5])

            # Calculate memory usage
            # Memory = num_objs * obj_size (approximate, actual is slab-aligned)
            memory_bytes = num_objs * obj_size

            # Calculate active ratio
            active_ratio = 0.0
            if num_objs > 0:
                active_ratio = active_objs / num_objs

            # Calculate number of slabs
            num_slabs = 0
            if objs_per_slab > 0:
                num_slabs = (num_objs + objs_per_slab - 1) // objs_per_slab

            caches[name] = {
                'name': name,
                'active_objs': active_objs,
                'num_objs': num_objs,
                'obj_size': obj_size,
                'objs_per_slab': objs_per_slab,
                'pages_per_slab': pages_per_slab,
                'memory_bytes': memory_bytes,
                'memory_mb': round(memory_bytes / (1024 * 1024), 2),
                'active_ratio': round(active_ratio, 3),
                'num_slabs': num_slabs,
            }
        except (ValueError, IndexError):
            continue

    return caches, None


def get_meminfo():
    """Get total memory info for context."""
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    parts = line.split()
                    return int(parts[1]) * 1024  # Convert kB to bytes
    except (FileNotFoundError, PermissionError, ValueError):
        pass
    return None


def analyze_slabs(caches, warn_pct, crit_pct, warn_ratio, top_n):
    """
    Analyze slab caches for issues.

    Returns tuple of (summary, issues, top_caches).
    """
    total_memory = get_meminfo()
    total_slab_bytes = sum(c['memory_bytes'] for c in caches.values())
    total_slab_mb = total_slab_bytes / (1024 * 1024)

    # Calculate slab as percentage of total memory
    slab_pct = 0.0
    if total_memory and total_memory > 0:
        slab_pct = (total_slab_bytes / total_memory) * 100

    summary = {
        'total_caches': len(caches),
        'total_slab_mb': round(total_slab_mb, 2),
        'total_slab_bytes': total_slab_bytes,
        'slab_pct_of_memory': round(slab_pct, 2),
        'total_memory_mb': round(total_memory / (1024 * 1024), 2) if total_memory else None,
    }

    issues = []

    # Check overall slab usage
    if slab_pct >= crit_pct:
        issues.append({
            'severity': 'CRITICAL',
            'cache': 'TOTAL',
            'message': f"Slab memory at {slab_pct:.1f}% of total memory (critical threshold: {crit_pct}%)",
            'memory_mb': round(total_slab_mb, 2),
        })
    elif slab_pct >= warn_pct:
        issues.append({
            'severity': 'WARNING',
            'cache': 'TOTAL',
            'message': f"Slab memory at {slab_pct:.1f}% of total memory (warning threshold: {warn_pct}%)",
            'memory_mb': round(total_slab_mb, 2),
        })

    # Check individual caches for low efficiency (possible fragmentation)
    for name, cache in caches.items():
        # Only check caches with significant memory usage (> 1MB)
        if cache['memory_mb'] < 1:
            continue

        # Check for low active ratio (fragmentation indicator)
        if cache['active_ratio'] < warn_ratio and cache['num_objs'] > 100:
            issues.append({
                'severity': 'WARNING',
                'cache': name,
                'message': f"Low active ratio {cache['active_ratio']:.1%} ({cache['active_objs']}/{cache['num_objs']} objects)",
                'memory_mb': cache['memory_mb'],
            })

    # Known problematic caches to watch
    watch_caches = {
        'dentry': 500,  # Warn if dentry cache > 500MB
        'inode_cache': 500,  # Warn if inode cache > 500MB
        'buffer_head': 200,  # Warn if buffer_head > 200MB
        'ext4_inode_cache': 300,
        'xfs_inode': 300,
    }

    for cache_name, threshold_mb in watch_caches.items():
        if cache_name in caches:
            cache = caches[cache_name]
            if cache['memory_mb'] > threshold_mb:
                issues.append({
                    'severity': 'WARNING',
                    'cache': cache_name,
                    'message': f"Cache using {cache['memory_mb']:.1f}MB (threshold: {threshold_mb}MB)",
                    'memory_mb': cache['memory_mb'],
                })

    # Get top N caches by memory usage
    sorted_caches = sorted(caches.values(), key=lambda x: x['memory_bytes'], reverse=True)
    top_caches = sorted_caches[:top_n]

    return summary, issues, top_caches


def format_bytes(bytes_val):
    """Format bytes to human-readable string."""
    if bytes_val >= 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f}GB"
    elif bytes_val >= 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.2f}MB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.2f}KB"
    else:
        return f"{bytes_val}B"


def output_plain(summary, issues, top_caches, warn_only=False, verbose=False):
    """Output results in plain text format."""
    lines = []

    if not warn_only:
        lines.append("Kernel Slab Allocator Status:")
        lines.append("")
        lines.append(f"  Total caches: {summary['total_caches']}")
        lines.append(f"  Total slab memory: {format_bytes(summary['total_slab_bytes'])}")

        if summary['total_memory_mb']:
            lines.append(f"  Slab % of memory: {summary['slab_pct_of_memory']:.1f}%")

        lines.append("")
        lines.append(f"Top {len(top_caches)} caches by memory usage:")

        for cache in top_caches:
            ratio_str = f"{cache['active_ratio']:.0%}" if cache['num_objs'] > 0 else "N/A"
            lines.append(
                f"  {cache['name']:<30} {format_bytes(cache['memory_bytes']):>10} "
                f"({cache['active_objs']:>8}/{cache['num_objs']:<8} objs, {ratio_str} active)"
            )

        lines.append("")

    if issues:
        critical = [i for i in issues if i['severity'] == 'CRITICAL']
        warnings = [i for i in issues if i['severity'] == 'WARNING']

        if critical:
            lines.append(f"CRITICAL Issues ({len(critical)}):")
            for issue in critical:
                lines.append(f"  !!! [{issue['cache']}] {issue['message']}")
            lines.append("")

        if warnings:
            lines.append(f"Warnings ({len(warnings)}):")
            for issue in warnings:
                lines.append(f"  [{issue['cache']}] {issue['message']}")
            lines.append("")
    elif not warn_only:
        lines.append("No slab issues detected.")

    return '\n'.join(lines)


def output_json(summary, issues, top_caches, all_caches=None):
    """Output results in JSON format."""
    result = {
        'summary': summary,
        'issues': issues,
        'top_caches': top_caches,
    }
    if all_caches:
        result['all_caches'] = all_caches
    return json.dumps(result, indent=2)


def output_table(summary, issues, top_caches, warn_only=False):
    """Output results in table format."""
    lines = []

    if not warn_only:
        lines.append(f"Slab Memory: {format_bytes(summary['total_slab_bytes'])} "
                     f"({summary['slab_pct_of_memory']:.1f}% of system memory)")
        lines.append("")
        lines.append(f"{'Cache Name':<30} {'Memory':>12} {'Active':>10} {'Total':>10} {'Ratio':>8}")
        lines.append("-" * 74)

        for cache in top_caches:
            ratio_str = f"{cache['active_ratio']:.1%}" if cache['num_objs'] > 0 else "N/A"
            lines.append(
                f"{cache['name']:<30} "
                f"{format_bytes(cache['memory_bytes']):>12} "
                f"{cache['active_objs']:>10} "
                f"{cache['num_objs']:>10} "
                f"{ratio_str:>8}"
            )

        lines.append("")

    if issues:
        lines.append(f"{'Severity':<10} {'Cache':<25} {'Message':<40}")
        lines.append("-" * 75)

        for issue in issues:
            lines.append(f"{issue['severity']:<10} {issue['cache']:<25} {issue['message']:<40}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor kernel slab allocator health and detect memory fragmentation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic slab analysis
  %(prog)s --format json            # JSON output for automation
  %(prog)s --top 20                 # Show top 20 caches
  %(prog)s --warn-pct 15            # Warn if slab > 15%% of memory
  %(prog)s --warn-only              # Only show issues

Common slab caches:
  dentry          - Directory entry cache (path lookups)
  inode_cache     - Inode cache (file metadata)
  buffer_head     - Buffer cache headers
  kmalloc-*       - General kernel allocations
  task_struct     - Process control blocks
  radix_tree_node - Radix tree nodes (page cache)

Exit codes:
  0 - Slab usage within normal parameters
  1 - Warnings or issues detected
  2 - Usage error or missing data sources

Notes:
  - Requires read access to /proc/slabinfo (usually root)
  - Low active ratio may indicate memory fragmentation
  - Large dentry/inode caches are often normal with many files
  - High slab usage with OOM events indicates kernel memory pressure
        """
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )

    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top caches to display (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-pct",
        type=float,
        default=25.0,
        help="Warning threshold for slab as %% of total memory (default: %(default)s)"
    )

    parser.add_argument(
        "--crit-pct",
        type=float,
        default=40.0,
        help="Critical threshold for slab as %% of total memory (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-ratio",
        type=float,
        default=0.5,
        help="Warning threshold for active object ratio (default: %(default)s)"
    )

    parser.add_argument(
        "--all-caches",
        action="store_true",
        help="Include all caches in JSON output"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.top < 1:
        print("Error: --top must be at least 1", file=sys.stderr)
        sys.exit(2)

    if not 0 < args.warn_pct < 100:
        print("Error: --warn-pct must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if not 0 < args.crit_pct <= 100:
        print("Error: --crit-pct must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.warn_pct >= args.crit_pct:
        print("Error: --warn-pct must be less than --crit-pct", file=sys.stderr)
        sys.exit(2)

    if not 0 < args.warn_ratio < 1:
        print("Error: --warn-ratio must be between 0 and 1", file=sys.stderr)
        sys.exit(2)

    # Parse slabinfo
    caches, error = parse_slabinfo()

    if caches is None:
        print(f"Error: {error}", file=sys.stderr)
        print("Try running as root: sudo %(prog)s", file=sys.stderr)
        sys.exit(2)

    if not caches:
        print("Error: No slab caches found", file=sys.stderr)
        sys.exit(2)

    # Analyze
    summary, issues, top_caches = analyze_slabs(
        caches, args.warn_pct, args.crit_pct, args.warn_ratio, args.top
    )

    # Output
    if args.format == "json":
        all_caches = list(caches.values()) if args.all_caches else None
        output = output_json(summary, issues, top_caches, all_caches)
    elif args.format == "table":
        output = output_table(summary, issues, top_caches, warn_only=args.warn_only)
    else:
        output = output_plain(summary, issues, top_caches, warn_only=args.warn_only, verbose=args.verbose)

    print(output)

    # Exit based on findings
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
