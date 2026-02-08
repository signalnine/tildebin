#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [health, memory, hugepages, performance, thp]
#   related: [memory_fragmentation, memory_usage]
#   brief: Monitor hugepage allocation and usage on Linux systems

"""
Monitor hugepage allocation and usage on Linux systems.

Hugepages are large memory pages (typically 2MB or 1GB) that reduce TLB misses
and improve performance for memory-intensive applications like databases,
virtual machines, and scientific computing workloads.

This script monitors:
- Configured vs allocated hugepages
- Hugepage usage percentage
- Per-NUMA node hugepage distribution (when available)
- Transparent Huge Pages (THP) status and defrag settings
- Hugepage reservation status

Exit codes:
    0 - Hugepages healthy, no issues detected
    1 - Warnings or issues detected (fragmentation, low availability)
    2 - Usage error or missing dependencies
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_meminfo_hugepages(content: str) -> dict[str, Any]:
    """Parse /proc/meminfo for hugepage information."""
    hugepages: dict[str, Any] = {
        'total': 0,
        'free': 0,
        'reserved': 0,
        'surplus': 0,
        'pagesize_kb': 2048,  # Default 2MB
    }

    for line in content.strip().split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value_parts = value.strip().split()
            try:
                num_value = int(value_parts[0])
            except (ValueError, IndexError):
                continue

            if key == 'HugePages_Total':
                hugepages['total'] = num_value
            elif key == 'HugePages_Free':
                hugepages['free'] = num_value
            elif key == 'HugePages_Rsvd':
                hugepages['reserved'] = num_value
            elif key == 'HugePages_Surp':
                hugepages['surplus'] = num_value
            elif key == 'Hugepagesize':
                hugepages['pagesize_kb'] = num_value

    # Calculate derived values
    hugepages['used'] = hugepages['total'] - hugepages['free']
    hugepages['available'] = hugepages['free'] - hugepages['reserved']
    hugepages['total_kb'] = hugepages['total'] * hugepages['pagesize_kb']
    hugepages['used_kb'] = hugepages['used'] * hugepages['pagesize_kb']
    hugepages['free_kb'] = hugepages['free'] * hugepages['pagesize_kb']

    return hugepages


def parse_thp_setting(content: str) -> str | None:
    """Parse THP setting from sysfs content (e.g., '[always] madvise never')."""
    for option in content.split():
        if option.startswith('[') and option.endswith(']'):
            return option[1:-1]
    return None


def parse_vmstat_thp(content: str) -> dict[str, int]:
    """Parse THP-related statistics from /proc/vmstat."""
    stats: dict[str, int] = {}
    for line in content.strip().split('\n'):
        parts = line.strip().split()
        if len(parts) == 2:
            key, value = parts
            # Collect hugepage-related stats
            if 'thp_' in key or 'htlb_' in key or 'hugepage' in key.lower():
                try:
                    stats[key] = int(value)
                except ValueError:
                    pass
    return stats


def format_size(kb: int) -> str:
    """Format KB value to human-readable format."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.0f}GB"
    elif kb >= 1024:
        return f"{kb / 1024:.0f}MB"
    else:
        return f"{kb}KB"


def analyze_hugepages(
    hugepages: dict[str, Any],
    vmstat: dict[str, int],
    thresholds: dict[str, Any]
) -> list[dict[str, Any]]:
    """Analyze hugepage status and return issues."""
    issues: list[dict[str, Any]] = []

    # Check if hugepages are configured
    if hugepages['total'] == 0:
        issues.append({
            'severity': 'INFO',
            'type': 'no_hugepages',
            'message': 'No static hugepages configured (may be using THP only)'
        })
        return issues

    # Check hugepage availability
    usage_percent = (hugepages['used'] / hugepages['total'] * 100) if hugepages['total'] > 0 else 0

    if usage_percent >= thresholds['critical']:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'high_usage',
            'usage_percent': usage_percent,
            'message': f"Hugepage usage critically high: {usage_percent:.1f}% "
                      f"({hugepages['used']}/{hugepages['total']} pages)"
        })
    elif usage_percent >= thresholds['warning']:
        issues.append({
            'severity': 'WARNING',
            'type': 'high_usage',
            'usage_percent': usage_percent,
            'message': f"Hugepage usage elevated: {usage_percent:.1f}% "
                      f"({hugepages['used']}/{hugepages['total']} pages)"
        })

    # Check for low available pages (free - reserved)
    if hugepages['available'] < thresholds['min_available']:
        issues.append({
            'severity': 'WARNING',
            'type': 'low_available',
            'available': hugepages['available'],
            'message': f"Low available hugepages: {hugepages['available']} pages "
                      f"(free: {hugepages['free']}, reserved: {hugepages['reserved']})"
        })

    # Check for surplus pages (indicates allocation pressure)
    if hugepages['surplus'] > 0:
        issues.append({
            'severity': 'INFO',
            'type': 'surplus_pages',
            'surplus': hugepages['surplus'],
            'message': f"Surplus hugepages allocated: {hugepages['surplus']} pages "
                      f"(indicates overcommit usage)"
        })

    # Check THP allocation failures from vmstat
    thp_collapse_fail = vmstat.get('thp_collapse_fail', 0)
    if thp_collapse_fail > 1000:
        issues.append({
            'severity': 'WARNING',
            'type': 'thp_fragmentation',
            'collapse_fail': thp_collapse_fail,
            'message': f"THP collapse failures detected: {thp_collapse_fail} "
                      f"(memory fragmentation may be impacting hugepage allocation)"
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
    parser = argparse.ArgumentParser(
        description='Monitor hugepage allocation and usage on Linux systems',
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed per-size and NUMA information'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors'
    )
    parser.add_argument(
        '--warn',
        type=float,
        default=80.0,
        metavar='PCT',
        help='Warning threshold for usage percentage (default: 80%%)'
    )
    parser.add_argument(
        '--crit',
        type=float,
        default=95.0,
        metavar='PCT',
        help='Critical threshold for usage percentage (default: 95%%)'
    )
    parser.add_argument(
        '--min-available',
        type=int,
        default=10,
        metavar='N',
        help='Minimum available hugepages before warning (default: 10)'
    )
    parser.add_argument(
        '--meminfo-file',
        help='Path to meminfo file (for testing)'
    )
    parser.add_argument(
        '--thp-enabled-file',
        help='Path to THP enabled file (for testing)'
    )
    parser.add_argument(
        '--thp-defrag-file',
        help='Path to THP defrag file (for testing)'
    )
    parser.add_argument(
        '--vmstat-file',
        help='Path to vmstat file (for testing)'
    )

    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0 or opts.warn > 100:
        output.error("--warn must be between 0 and 100")
        return 2

    if opts.crit < 0 or opts.crit > 100:
        output.error("--crit must be between 0 and 100")
        return 2

    if opts.warn >= opts.crit:
        output.error("--warn must be less than --crit")
        return 2

    if opts.min_available < 0:
        output.error("--min-available must be non-negative")
        return 2

    thresholds = {
        'warning': opts.warn,
        'critical': opts.crit,
        'min_available': opts.min_available
    }

    # Read meminfo
    try:
        meminfo_path = opts.meminfo_file or "/proc/meminfo"
        meminfo_content = context.read_file(meminfo_path)
    except FileNotFoundError:
        output.error("/proc/meminfo not found (non-Linux system?)")
        return 2
    except Exception as e:
        output.error(f"Error reading /proc/meminfo: {e}")
        return 2

    hugepages = parse_meminfo_hugepages(meminfo_content)

    # Read THP status
    thp: dict[str, str | None] = {
        'enabled': None,
        'defrag': None,
    }

    try:
        thp_enabled_path = opts.thp_enabled_file or "/sys/kernel/mm/transparent_hugepage/enabled"
        thp_content = context.read_file(thp_enabled_path)
        thp['enabled'] = parse_thp_setting(thp_content)
    except FileNotFoundError:
        pass  # THP may not be available

    try:
        thp_defrag_path = opts.thp_defrag_file or "/sys/kernel/mm/transparent_hugepage/defrag"
        defrag_content = context.read_file(thp_defrag_path)
        thp['defrag'] = parse_thp_setting(defrag_content)
    except FileNotFoundError:
        pass

    # Read vmstat for THP statistics
    vmstat: dict[str, int] = {}
    try:
        vmstat_path = opts.vmstat_file or "/proc/vmstat"
        vmstat_content = context.read_file(vmstat_path)
        vmstat = parse_vmstat_thp(vmstat_content)
    except FileNotFoundError:
        pass

    # Analyze
    issues = analyze_hugepages(hugepages, vmstat, thresholds)

    # Output
    result: dict[str, Any] = {
        'hugepages': hugepages,
        'transparent_huge_pages': thp,
        'issues': issues
    }
    if opts.verbose:
        result['vmstat'] = vmstat
    output.emit(result)

    if opts.format == 'table':
        lines = []
        if not opts.warn_only:
            lines.append("=" * 70)
            lines.append("HUGEPAGE STATUS")
            lines.append("=" * 70)
            lines.append(f"{'Metric':<25} {'Value':<20} {'Details':<25}")
            lines.append("-" * 70)
            lines.append(f"{'Total Pages':<25} {hugepages['total']:<20} "
                        f"{format_size(hugepages['total_kb'])}")
            lines.append(f"{'Used Pages':<25} {hugepages['used']:<20} "
                        f"{format_size(hugepages['used_kb'])}")
            lines.append(f"{'Free Pages':<25} {hugepages['free']:<20}")
            lines.append(f"{'Reserved Pages':<25} {hugepages['reserved']:<20}")
            lines.append(f"{'Available Pages':<25} {hugepages['available']:<20}")
            lines.append(f"{'Page Size':<25} {format_size(hugepages['pagesize_kb']):<20}")
            if hugepages['surplus'] > 0:
                lines.append(f"{'Surplus Pages':<25} {hugepages['surplus']:<20}")
            lines.append("")

            if thp['enabled']:
                lines.append(f"{'THP Enabled':<25} {thp['enabled']:<20}")
                if thp['defrag']:
                    lines.append(f"{'THP Defrag':<25} {thp['defrag']:<20}")
            lines.append("=" * 70)
            lines.append("")

        if issues:
            lines.append("ISSUES DETECTED")
            lines.append("-" * 70)
            for issue in issues:
                if opts.warn_only and issue['severity'] == 'INFO':
                    continue
                lines.append(f"[{issue['severity']}] {issue['message']}")
            lines.append("")

        print('\n'.join(lines))
    else:
        output.render(opts.format, "Hugepage Allocation and Usage Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)
    status = "critical" if has_critical else ("warning" if has_warning else "healthy")

    if hugepages['total'] > 0:
        usage_pct = (hugepages['used'] / hugepages['total']) * 100
        output.set_summary(f"usage={usage_pct:.1f}%, available={hugepages['available']}, status={status}")
    else:
        output.set_summary(f"no static hugepages configured, status={status}")

    # Exit based on findings
    if has_critical or has_warning:
        return 1
    else:
        return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
