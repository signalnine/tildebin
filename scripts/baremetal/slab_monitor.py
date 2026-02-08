#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [health, memory, kernel, slab, performance]
#   related: [memory_usage, memory_fragmentation]
#   brief: Monitor kernel slab allocator health and detect memory issues

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

Exit codes:
    0 - Slab usage within normal parameters
    1 - Warnings or issues detected
    2 - Usage error or missing data sources
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_slabinfo(content: str) -> tuple[dict[str, Any] | None, str | None]:
    """
    Parse /proc/slabinfo and return slab cache statistics.

    /proc/slabinfo format (version 2.1):
    # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab>
    # name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables ...
    """
    caches: dict[str, Any] = {}

    # Skip header lines
    for line in content.strip().split('\n'):
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

    if not caches:
        return None, "no valid caches found in slabinfo"

    return caches, None


def parse_meminfo_total(content: str) -> int | None:
    """Get total memory from meminfo for context."""
    for line in content.strip().split('\n'):
        if line.startswith('MemTotal:'):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1]) * 1024  # Convert kB to bytes
    return None


def analyze_slabs(
    caches: dict[str, Any],
    total_memory: int | None,
    warn_pct: float,
    crit_pct: float,
    warn_ratio: float,
    top_n: int
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Analyze slab caches for issues.

    Returns tuple of (summary, issues, top_caches).
    """
    total_slab_bytes = sum(c['memory_bytes'] for c in caches.values())
    total_slab_mb = total_slab_bytes / (1024 * 1024)

    # Calculate slab as percentage of total memory
    slab_pct = 0.0
    if total_memory and total_memory > 0:
        slab_pct = (total_slab_bytes / total_memory) * 100

    summary: dict[str, Any] = {
        'total_caches': len(caches),
        'total_slab_mb': round(total_slab_mb, 2),
        'total_slab_bytes': total_slab_bytes,
        'slab_pct_of_memory': round(slab_pct, 2),
        'total_memory_mb': round(total_memory / (1024 * 1024), 2) if total_memory else None,
    }

    issues: list[dict[str, Any]] = []

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


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable string."""
    if bytes_val >= 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f}GB"
    elif bytes_val >= 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.2f}MB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.2f}KB"
    else:
        return f"{bytes_val}B"


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
        description="Monitor kernel slab allocator health and detect memory fragmentation",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)"
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
        help="Number of top caches to display (default: 10)"
    )
    parser.add_argument(
        "--warn-pct",
        type=float,
        default=25.0,
        help="Warning threshold for slab as %% of total memory (default: 25)"
    )
    parser.add_argument(
        "--crit-pct",
        type=float,
        default=40.0,
        help="Critical threshold for slab as %% of total memory (default: 40)"
    )
    parser.add_argument(
        "--warn-ratio",
        type=float,
        default=0.5,
        help="Warning threshold for active object ratio (default: 0.5)"
    )
    parser.add_argument(
        "--all-caches",
        action="store_true",
        help="Include all caches in JSON output"
    )
    parser.add_argument(
        "--slabinfo-file",
        help="Path to slabinfo file (for testing)"
    )
    parser.add_argument(
        "--meminfo-file",
        help="Path to meminfo file (for testing)"
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if opts.top < 1:
        output.error("--top must be at least 1")
        return 2

    if not 0 < opts.warn_pct < 100:
        output.error("--warn-pct must be between 0 and 100")
        return 2

    if not 0 < opts.crit_pct <= 100:
        output.error("--crit-pct must be between 0 and 100")
        return 2

    if opts.warn_pct >= opts.crit_pct:
        output.error("--warn-pct must be less than --crit-pct")
        return 2

    if not 0 < opts.warn_ratio < 1:
        output.error("--warn-ratio must be between 0 and 1")
        return 2

    # Parse slabinfo
    try:
        slabinfo_path = opts.slabinfo_file or "/proc/slabinfo"
        slabinfo_content = context.read_file(slabinfo_path)
    except FileNotFoundError:
        output.error("slabinfo not found")
        return 2
    except PermissionError:
        output.error("permission denied reading slabinfo (try running as root)")
        return 2
    except Exception as e:
        output.error(f"Error reading slabinfo: {e}")
        return 2

    caches, error = parse_slabinfo(slabinfo_content)

    if caches is None:
        output.error(f"Error: {error}")
        return 2

    if not caches:
        output.error("No slab caches found")
        return 2

    # Get total memory for context
    total_memory: int | None = None
    try:
        meminfo_path = opts.meminfo_file or "/proc/meminfo"
        meminfo_content = context.read_file(meminfo_path)
        total_memory = parse_meminfo_total(meminfo_content)
    except Exception:
        pass  # Continue without total memory context

    # Analyze
    summary, issues, top_caches = analyze_slabs(
        caches, total_memory, opts.warn_pct, opts.crit_pct, opts.warn_ratio, opts.top
    )

    # Build result for output
    result: dict[str, Any] = {
        'summary': summary,
        'issues': issues,
        'top_caches': top_caches,
    }
    if opts.all_caches:
        result['all_caches'] = list(caches.values())

    output.emit(result)

    # Output
    if opts.format == "table":
        _output_table(summary, issues, top_caches, opts.warn_only)
    else:
        output.render(opts.format, "Slab Allocator Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")
    output.set_summary(
        f"slab={summary['total_slab_mb']:.1f}MB ({summary['slab_pct_of_memory']:.1f}%), status={status}"
    )

    # Exit based on findings
    if has_critical or has_warning:
        return 1
    else:
        return 0


def _output_table(
    summary: dict[str, Any],
    issues: list[dict[str, Any]],
    top_caches: list[dict[str, Any]],
    warn_only: bool,
) -> None:
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

    print('\n'.join(lines))


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
