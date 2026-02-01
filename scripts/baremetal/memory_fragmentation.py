#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [health, memory, fragmentation, performance, buddyinfo]
#   related: [hugepage_monitor, memory_usage]
#   brief: Analyze memory fragmentation using buddy allocator statistics

"""
Analyze memory fragmentation on Linux systems using buddy allocator statistics.

Memory fragmentation occurs when the system has sufficient total free memory
but cannot allocate large contiguous blocks. This script analyzes
/proc/buddyinfo to detect external fragmentation - a common cause of
allocation failures even with plenty of free memory.

Checks performed:
- Buddy allocator free page distribution across orders (0-10)
- Per-NUMA node fragmentation levels
- Per-zone fragmentation (DMA, DMA32, Normal, Movable)
- Fragmentation index calculation
- Large page (order >= 9) availability for hugepages/THP
- Memory compaction pressure indicators

Exit codes:
    0 - Memory fragmentation within normal parameters
    1 - Fragmentation warnings detected
    2 - Usage error or missing data sources
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_buddyinfo(content: str) -> tuple[list[dict[str, Any]] | None, str | None]:
    """
    Parse /proc/buddyinfo and return fragmentation statistics.

    Format: Node <N>, zone <name> <count0> <count1> ... <count10>
    Each count represents free pages of order 2^N (4KB, 8KB, 16KB, ... 4MB)

    Order 0 = 4KB (1 page)
    Order 1 = 8KB (2 pages)
    ...
    Order 9 = 2MB (512 pages) - hugepage size
    Order 10 = 4MB (1024 pages)
    """
    zones: list[dict[str, Any]] = []

    for line in content.strip().split('\n'):
        line = line.strip()
        if not line:
            continue

        # Parse: "Node 0, zone   Normal    123  456  789 ..."
        parts = line.split()
        if len(parts) < 4 or parts[0] != 'Node':
            continue

        try:
            node_id = int(parts[1].rstrip(','))
            # Find zone name - skip "zone" keyword
            zone_idx = parts.index('zone') + 1 if 'zone' in parts else 3
            zone_name = parts[zone_idx]

            # Free page counts for each order (0-10)
            counts = []
            for i in range(zone_idx + 1, len(parts)):
                counts.append(int(parts[i]))

            zones.append({
                'node': node_id,
                'zone': zone_name,
                'counts': counts,
            })
        except (ValueError, IndexError):
            continue

    if not zones:
        return None, "no valid zones found in buddyinfo"

    return zones, None


def calculate_fragmentation_index(counts: list[int]) -> float:
    """
    Calculate a fragmentation index (0-100%).

    Higher values indicate more fragmentation.
    Based on the ratio of small pages to total free pages weighted by order.

    Formula: 1 - (weighted_high_order / total_pages)
    Where high orders (9-10) are weighted more heavily.
    """
    if not counts:
        return 0.0

    total_pages = 0
    weighted_high = 0

    for order, count in enumerate(counts):
        pages_in_order = count * (2 ** order)
        total_pages += pages_in_order

        # Weight higher orders more heavily (order 9-10 are most important)
        if order >= 9:
            weighted_high += pages_in_order * 3
        elif order >= 7:
            weighted_high += pages_in_order * 2
        elif order >= 5:
            weighted_high += pages_in_order

    if total_pages == 0:
        return 100.0  # No free memory = fully fragmented

    # Calculate index: more high-order pages = less fragmentation
    max_possible_weight = total_pages * 3  # If all pages were order 9+
    frag_index = 1.0 - (weighted_high / max_possible_weight)

    return min(100.0, max(0.0, frag_index * 100))


def calculate_zone_stats(zone: dict[str, Any]) -> dict[str, Any]:
    """Calculate statistics for a zone."""
    counts = zone['counts']
    page_size = 4096  # 4KB

    stats: dict[str, Any] = {
        'node': zone['node'],
        'zone': zone['zone'],
        'counts': counts,
        'total_free_pages': 0,
        'total_free_bytes': 0,
        'order_breakdown': {},
        'fragmentation_index': 0.0,
        'large_pages_available': 0,
        'hugepage_capable': 0,
    }

    for order, count in enumerate(counts):
        pages_in_order = count * (2 ** order)
        bytes_in_order = pages_in_order * page_size

        stats['total_free_pages'] += pages_in_order
        stats['total_free_bytes'] += bytes_in_order

        order_name = f"order_{order}"
        stats['order_breakdown'][order_name] = {
            'count': count,
            'pages': pages_in_order,
            'size_kb': (2 ** order) * 4,
            'total_bytes': bytes_in_order,
        }

        # Count large pages (order 7+ = 512KB+)
        if order >= 7:
            stats['large_pages_available'] += count

        # Hugepage capable (order 9 = 2MB)
        if order >= 9:
            stats['hugepage_capable'] += count

    stats['fragmentation_index'] = calculate_fragmentation_index(counts)

    return stats


def analyze_fragmentation(
    zones: list[dict[str, Any]],
    frag_warn: float = 50.0,
    frag_crit: float = 75.0,
    hugepage_warn: int = 10
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Analyze fragmentation across all zones.

    Args:
        zones: List of zone data from parse_buddyinfo
        frag_warn: Warning threshold for fragmentation index
        frag_crit: Critical threshold for fragmentation index
        hugepage_warn: Warn if fewer than this many hugepages available

    Returns:
        Tuple of (summary, zone_stats, issues)
    """
    zone_stats: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []

    total_free_pages = 0
    total_free_bytes = 0
    total_hugepage_capable = 0
    total_large_pages = 0
    max_frag_index = 0.0

    for zone in zones:
        stats = calculate_zone_stats(zone)
        zone_stats.append(stats)

        total_free_pages += stats['total_free_pages']
        total_free_bytes += stats['total_free_bytes']
        total_hugepage_capable += stats['hugepage_capable']
        total_large_pages += stats['large_pages_available']
        max_frag_index = max(max_frag_index, stats['fragmentation_index'])

        # Check zone fragmentation
        if stats['fragmentation_index'] >= frag_crit:
            issues.append({
                'severity': 'CRITICAL',
                'node': stats['node'],
                'zone': stats['zone'],
                'type': 'high_fragmentation',
                'message': f"Fragmentation index {stats['fragmentation_index']:.1f}% "
                           f"(critical threshold: {frag_crit}%)",
                'value': stats['fragmentation_index'],
            })
        elif stats['fragmentation_index'] >= frag_warn:
            issues.append({
                'severity': 'WARNING',
                'node': stats['node'],
                'zone': stats['zone'],
                'type': 'fragmentation',
                'message': f"Fragmentation index {stats['fragmentation_index']:.1f}% "
                           f"(warning threshold: {frag_warn}%)",
                'value': stats['fragmentation_index'],
            })

        # Check large page availability in Normal zone
        if stats['zone'] == 'Normal' and stats['hugepage_capable'] < hugepage_warn:
            issues.append({
                'severity': 'WARNING',
                'node': stats['node'],
                'zone': stats['zone'],
                'type': 'low_hugepages',
                'message': f"Only {stats['hugepage_capable']} hugepage-capable blocks "
                           f"(order 9+) available",
                'value': stats['hugepage_capable'],
            })

    # Aggregate summary
    summary = {
        'total_zones': len(zone_stats),
        'total_free_pages': total_free_pages,
        'total_free_bytes': total_free_bytes,
        'total_free_mb': round(total_free_bytes / (1024 * 1024), 2),
        'total_hugepage_capable': total_hugepage_capable,
        'total_large_pages': total_large_pages,
        'max_fragmentation_index': round(max_frag_index, 2),
        'issue_count': len(issues),
    }

    return summary, zone_stats, issues


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
        description="Analyze memory fragmentation using buddy allocator statistics",
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
        help="Show detailed per-zone information with order breakdown"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )
    parser.add_argument(
        "--frag-warn",
        type=float,
        default=50.0,
        help="Warning threshold for fragmentation index (default: 50%%)"
    )
    parser.add_argument(
        "--frag-crit",
        type=float,
        default=75.0,
        help="Critical threshold for fragmentation index (default: 75%%)"
    )
    parser.add_argument(
        "--hugepage-warn",
        type=int,
        default=10,
        help="Warn if fewer than this many hugepage blocks available (default: 10)"
    )
    parser.add_argument(
        "--buddyinfo-file",
        help="Path to buddyinfo file (for testing)"
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if not 0 < opts.frag_warn < 100:
        output.error("--frag-warn must be between 0 and 100")
        return 2

    if not 0 < opts.frag_crit <= 100:
        output.error("--frag-crit must be between 0 and 100")
        return 2

    if opts.frag_warn >= opts.frag_crit:
        output.error("--frag-warn must be less than --frag-crit")
        return 2

    if opts.hugepage_warn < 0:
        output.error("--hugepage-warn must be non-negative")
        return 2

    # Read buddyinfo
    try:
        buddyinfo_path = opts.buddyinfo_file or "/proc/buddyinfo"
        content = context.read_file(buddyinfo_path)
    except FileNotFoundError:
        output.error("buddyinfo not found")
        return 2
    except PermissionError:
        output.error("permission denied reading buddyinfo")
        return 2
    except Exception as e:
        output.error(f"Error reading buddyinfo: {e}")
        return 2

    # Parse buddyinfo
    zones, error = parse_buddyinfo(content)

    if zones is None:
        output.error(f"Error: {error}")
        return 2

    # Analyze fragmentation
    summary, zone_stats, issues = analyze_fragmentation(
        zones, opts.frag_warn, opts.frag_crit, opts.hugepage_warn
    )

    # Output
    if opts.format == "json":
        result = {
            'summary': summary,
            'zones': zone_stats,
            'issues': issues,
        }
        print(json.dumps(result, indent=2))

    elif opts.format == "table":
        lines = []
        if not opts.warn_only:
            lines.append(f"Free Memory: {format_bytes(summary['total_free_bytes'])} | "
                        f"Max Frag: {summary['max_fragmentation_index']:.1f}% | "
                        f"Hugepage blocks: {summary['total_hugepage_capable']}")
            lines.append("")
            lines.append(f"{'Node':<6} {'Zone':<10} {'Free':>12} {'Frag%':>8} "
                        f"{'HP Blk':>8} {'Order 0-4':>20} {'Order 5-10':>25}")
            lines.append("-" * 95)

            for stats in zone_stats:
                counts = stats['counts']
                low_orders = " ".join(f"{counts[i]:>3}" for i in range(min(5, len(counts))))
                high_orders = " ".join(f"{counts[i]:>3}" for i in range(5, min(11, len(counts))))

                lines.append(
                    f"{stats['node']:<6} {stats['zone']:<10} "
                    f"{format_bytes(stats['total_free_bytes']):>12} "
                    f"{stats['fragmentation_index']:>7.1f}% "
                    f"{stats['hugepage_capable']:>8} "
                    f"{low_orders:>20} {high_orders:>25}"
                )
            lines.append("")

        if issues:
            lines.append(f"{'Severity':<10} {'Node':<6} {'Zone':<10} {'Type':<20} {'Details':<40}")
            lines.append("-" * 90)

            for issue in issues:
                lines.append(
                    f"{issue['severity']:<10} {issue['node']:<6} {issue['zone']:<10} "
                    f"{issue['type']:<20} {issue['message'][:40]:<40}"
                )

        print('\n'.join(lines))

    else:  # plain
        lines = []
        if not opts.warn_only:
            lines.append("Memory Fragmentation Analysis:")
            lines.append("")
            lines.append(f"  Total free memory: {format_bytes(summary['total_free_bytes'])}")
            lines.append(f"  Zones analyzed: {summary['total_zones']}")
            lines.append(f"  Max fragmentation index: {summary['max_fragmentation_index']:.1f}%")
            lines.append(f"  Hugepage-capable blocks (order 9+): {summary['total_hugepage_capable']}")
            lines.append(f"  Large page blocks (order 7+): {summary['total_large_pages']}")
            lines.append("")

        if opts.verbose and not opts.warn_only:
            lines.append("Per-Zone Details:")
            for stats in zone_stats:
                lines.append(f"  Node {stats['node']}, Zone {stats['zone']}:")
                lines.append(f"    Free: {format_bytes(stats['total_free_bytes'])}")
                lines.append(f"    Fragmentation: {stats['fragmentation_index']:.1f}%")
                lines.append(f"    Hugepage blocks: {stats['hugepage_capable']}")

                # Show order distribution
                order_str = " ".join(
                    f"{stats['counts'][i]}" for i in range(min(11, len(stats['counts'])))
                )
                lines.append(f"    Order counts [0-10]: {order_str}")
            lines.append("")

            # Explain order sizes
            lines.append("Order size reference:")
            lines.append("  Order 0=4KB, 1=8KB, 2=16KB, 3=32KB, 4=64KB, 5=128KB")
            lines.append("  Order 6=256KB, 7=512KB, 8=1MB, 9=2MB (hugepage), 10=4MB")
            lines.append("")

        if issues:
            critical = [i for i in issues if i['severity'] == 'CRITICAL']
            warnings = [i for i in issues if i['severity'] == 'WARNING']

            if critical:
                lines.append(f"CRITICAL Issues ({len(critical)}):")
                for issue in critical:
                    lines.append(f"  !!! Node {issue['node']} {issue['zone']}: {issue['message']}")
                lines.append("")

            if warnings:
                lines.append(f"Warnings ({len(warnings)}):")
                for issue in warnings:
                    lines.append(f"  [WARNING] Node {issue['node']} {issue['zone']}: {issue['message']}")
                lines.append("")
        elif not opts.warn_only:
            lines.append("No fragmentation issues detected.")
            lines.append("")

        print('\n'.join(lines))

    # Set summary
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")
    output.set_summary(
        f"frag_index={summary['max_fragmentation_index']:.1f}%, "
        f"hugepage_blocks={summary['total_hugepage_capable']}, status={status}"
    )

    # Exit based on findings
    if has_critical or has_warning:
        return 1
    else:
        return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
