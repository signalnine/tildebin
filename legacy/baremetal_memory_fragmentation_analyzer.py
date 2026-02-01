#!/usr/bin/env python3
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

Useful for:
- Diagnosing "out of memory" with high free memory (fragmentation)
- Monitoring systems using hugepages or THP
- Identifying need for memory compaction
- Pre-maintenance system health verification
- Database/VM workloads requiring large allocations

Exit codes:
    0 - Memory fragmentation within normal parameters
    1 - Fragmentation warnings detected
    2 - Usage error or missing data sources
"""

import argparse
import sys
import os
import json


def parse_buddyinfo():
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
    zones = []

    try:
        with open('/proc/buddyinfo', 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None, "buddyinfo not found"
    except PermissionError:
        return None, "permission denied reading buddyinfo"

    for line in lines:
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


def calculate_fragmentation_index(counts):
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


def calculate_zone_stats(zone):
    """Calculate statistics for a zone."""
    counts = zone['counts']
    page_size = 4096  # 4KB

    stats = {
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


def analyze_fragmentation(zones, frag_warn=50.0, frag_crit=75.0, hugepage_warn=10):
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
    zone_stats = []
    issues = []

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


def output_plain(summary, zone_stats, issues, warn_only=False, verbose=False):
    """Output results in plain text format."""
    lines = []

    if not warn_only:
        lines.append("Memory Fragmentation Analysis:")
        lines.append("")
        lines.append(f"  Total free memory: {format_bytes(summary['total_free_bytes'])}")
        lines.append(f"  Zones analyzed: {summary['total_zones']}")
        lines.append(f"  Max fragmentation index: {summary['max_fragmentation_index']:.1f}%")
        lines.append(f"  Hugepage-capable blocks (order 9+): {summary['total_hugepage_capable']}")
        lines.append(f"  Large page blocks (order 7+): {summary['total_large_pages']}")
        lines.append("")

    if verbose and not warn_only:
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
    elif not warn_only:
        lines.append("No fragmentation issues detected.")
        lines.append("")

    return '\n'.join(lines)


def output_json(summary, zone_stats, issues):
    """Output results in JSON format."""
    result = {
        'summary': summary,
        'zones': zone_stats,
        'issues': issues,
    }
    return json.dumps(result, indent=2)


def output_table(summary, zone_stats, issues, warn_only=False):
    """Output results in table format."""
    lines = []

    if not warn_only:
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

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze memory fragmentation using buddy allocator statistics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic fragmentation analysis
  %(prog)s --format json            # JSON output for automation
  %(prog)s --verbose                # Show per-zone details with order breakdown
  %(prog)s --frag-warn 40           # Warn if fragmentation > 40%%
  %(prog)s --warn-only              # Only show issues

Understanding fragmentation:
  Memory fragmentation occurs when free memory is split into small chunks,
  preventing large contiguous allocations. The fragmentation index measures
  the distribution of free pages across different sizes (orders).

  Order 9 (2MB) is particularly important for hugepages and THP.
  Low order 9+ counts with high total free memory indicates fragmentation.

Exit codes:
  0 - Memory fragmentation within normal parameters
  1 - Fragmentation warnings detected
  2 - Usage error or missing data sources

See also:
  /proc/buddyinfo - Raw buddy allocator statistics
  /proc/pagetypeinfo - Page mobility information
  /sys/kernel/mm/transparent_hugepage/ - THP settings
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
        help="Warning threshold for fragmentation index (default: %(default)s%%)"
    )

    parser.add_argument(
        "--frag-crit",
        type=float,
        default=75.0,
        help="Critical threshold for fragmentation index (default: %(default)s%%)"
    )

    parser.add_argument(
        "--hugepage-warn",
        type=int,
        default=10,
        help="Warn if fewer than this many hugepage blocks available (default: %(default)s)"
    )

    args = parser.parse_args()

    # Validate arguments
    if not 0 < args.frag_warn < 100:
        print("Error: --frag-warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if not 0 < args.frag_crit <= 100:
        print("Error: --frag-crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.frag_warn >= args.frag_crit:
        print("Error: --frag-warn must be less than --frag-crit", file=sys.stderr)
        sys.exit(2)

    if args.hugepage_warn < 0:
        print("Error: --hugepage-warn must be non-negative", file=sys.stderr)
        sys.exit(2)

    # Parse buddyinfo
    zones, error = parse_buddyinfo()

    if zones is None:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    # Analyze fragmentation
    summary, zone_stats, issues = analyze_fragmentation(
        zones, args.frag_warn, args.frag_crit, args.hugepage_warn
    )

    # Output
    if args.format == "json":
        output = output_json(summary, zone_stats, issues)
    elif args.format == "table":
        output = output_table(summary, zone_stats, issues, warn_only=args.warn_only)
    else:
        output = output_plain(summary, zone_stats, issues,
                              warn_only=args.warn_only, verbose=args.verbose)

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
