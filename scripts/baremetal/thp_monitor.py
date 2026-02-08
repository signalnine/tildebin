#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [memory, thp, hugepages, compaction, performance]
#   requires: []
#   privilege: user
#   related: [hugepage_monitor, memory_fragmentation, memory_reclaim_monitor]
#   brief: Monitor THP compaction stalls and allocation efficiency

"""
Monitor Transparent Huge Page (THP) compaction stalls and allocation efficiency.

THP allows the Linux kernel to automatically promote regular pages into
hugepages. While this can improve performance by reducing TLB misses, it can
also cause latency spikes due to compaction stalls when the kernel cannot
find contiguous memory for hugepage allocation.

This script monitors:
- THP enabled/defrag settings from sysfs
- Compaction stall and failure counts from /proc/vmstat
- THP fault allocation vs fallback ratio
- khugepaged collapse allocation success/failure ratio
- khugepaged tuning parameters (pages_to_scan, scan_sleep_millisecs)

Exit codes:
    0 - THP operating normally, no issues detected
    1 - Warnings detected (high compaction stalls, high fallback ratio)
    2 - Usage error or THP not available
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_thp_setting(content: str) -> str | None:
    """Parse THP setting from sysfs content (e.g., 'always [madvise] never').

    Returns the word inside square brackets, or None if not found.
    """
    for word in content.split():
        if word.startswith('[') and word.endswith(']'):
            return word[1:-1]
    return None


def parse_vmstat(content: str, keys: set[str]) -> dict[str, int]:
    """Parse /proc/vmstat and extract only the specified keys.

    Args:
        content: Raw content of /proc/vmstat
        keys: Set of key names to extract

    Returns:
        Dictionary of key -> int value for matched keys.
    """
    stats: dict[str, int] = {}
    for line in content.strip().split('\n'):
        parts = line.strip().split()
        if len(parts) == 2 and parts[0] in keys:
            try:
                stats[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return stats


def analyze_thp(
    enabled: str | None,
    defrag: str | None,
    vmstat: dict[str, int],
    compact_stall_threshold: int,
) -> list[dict[str, Any]]:
    """Analyze THP settings and vmstat counters for issues.

    Args:
        enabled: THP enabled setting (always/madvise/never)
        defrag: THP defrag setting (always/defer/defer+madvise/madvise/never)
        vmstat: Parsed vmstat counters
        compact_stall_threshold: Threshold for compact_stall WARNING

    Returns:
        List of issue dicts with severity, type, and message.
    """
    issues: list[dict[str, Any]] = []

    # THP disabled entirely
    if enabled == 'never':
        issues.append({
            'severity': 'INFO',
            'type': 'thp_disabled',
            'message': 'Transparent Huge Pages are disabled (enabled=never)',
        })
        return issues

    # THP enabled=always with high compaction stalls
    compact_stall = vmstat.get('compact_stall', 0)
    if enabled == 'always' and compact_stall > compact_stall_threshold:
        issues.append({
            'severity': 'WARNING',
            'type': 'high_compaction_stalls',
            'compact_stall': compact_stall,
            'message': (
                f"High compaction stalls with THP enabled=always: "
                f"{compact_stall} stalls (threshold: {compact_stall_threshold})"
            ),
        })

    # THP fault fallback ratio
    thp_fault_alloc = vmstat.get('thp_fault_alloc', 0)
    thp_fault_fallback = vmstat.get('thp_fault_fallback', 0)
    total_fault = thp_fault_alloc + thp_fault_fallback
    if total_fault > 0:
        fallback_ratio = thp_fault_fallback / total_fault
        if fallback_ratio > 0.5:
            issues.append({
                'severity': 'WARNING',
                'type': 'high_fallback_ratio',
                'thp_fault_alloc': thp_fault_alloc,
                'thp_fault_fallback': thp_fault_fallback,
                'fallback_ratio': round(fallback_ratio * 100, 1),
                'message': (
                    f"High THP fault fallback ratio: {fallback_ratio * 100:.1f}% "
                    f"({thp_fault_fallback}/{total_fault} allocations fell back to small pages)"
                ),
            })

    # khugepaged collapse failure ratio
    thp_collapse_alloc = vmstat.get('thp_collapse_alloc', 0)
    thp_collapse_alloc_failed = vmstat.get('thp_collapse_alloc_failed', 0)
    total_collapse = thp_collapse_alloc + thp_collapse_alloc_failed
    if total_collapse > 0:
        collapse_fail_ratio = thp_collapse_alloc_failed / total_collapse
        if collapse_fail_ratio > 0.5:
            issues.append({
                'severity': 'WARNING',
                'type': 'high_collapse_failure',
                'thp_collapse_alloc': thp_collapse_alloc,
                'thp_collapse_alloc_failed': thp_collapse_alloc_failed,
                'collapse_fail_ratio': round(collapse_fail_ratio * 100, 1),
                'message': (
                    f"High khugepaged collapse failure ratio: {collapse_fail_ratio * 100:.1f}% "
                    f"({thp_collapse_alloc_failed}/{total_collapse} collapses failed)"
                ),
            })

    # THP defrag=always can cause latency spikes
    if defrag == 'always':
        issues.append({
            'severity': 'INFO',
            'type': 'defrag_always',
            'message': (
                'THP defrag=always can cause latency spikes; '
                'consider defer+madvise or madvise'
            ),
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
        description='Monitor THP compaction stalls and allocation efficiency',
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)',
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed vmstat counters and khugepaged tuning',
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors',
    )
    parser.add_argument(
        '--compact-stall-threshold',
        type=int,
        default=10000,
        metavar='N',
        help='Compaction stall count WARNING threshold (default: 10000)',
    )

    opts = parser.parse_args(args)

    # Check THP support
    thp_enabled_path = '/sys/kernel/mm/transparent_hugepage/enabled'
    if not context.file_exists(thp_enabled_path):
        output.error('THP not available (no /sys/kernel/mm/transparent_hugepage/enabled)')
        return 2

    # Read THP enabled setting
    try:
        enabled_content = context.read_file(thp_enabled_path)
    except Exception as e:
        output.error(f'Error reading THP enabled: {e}')
        return 2

    enabled = parse_thp_setting(enabled_content)

    # Read THP defrag setting
    defrag: str | None = None
    thp_defrag_path = '/sys/kernel/mm/transparent_hugepage/defrag'
    try:
        defrag_content = context.read_file(thp_defrag_path)
        defrag = parse_thp_setting(defrag_content)
    except FileNotFoundError:
        pass

    # Read vmstat counters
    vmstat_keys = {
        'compact_stall',
        'compact_fail',
        'compact_success',
        'thp_fault_alloc',
        'thp_fault_fallback',
        'thp_collapse_alloc',
        'thp_collapse_alloc_failed',
    }
    vmstat: dict[str, int] = {}
    try:
        vmstat_content = context.read_file('/proc/vmstat')
        vmstat = parse_vmstat(vmstat_content, vmstat_keys)
    except FileNotFoundError:
        pass

    # Read khugepaged tuning parameters
    khugepaged: dict[str, int] = {}
    pages_to_scan_path = '/sys/kernel/mm/transparent_hugepage/khugepaged/pages_to_scan'
    scan_sleep_path = '/sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs'
    try:
        pages_to_scan = context.read_file(pages_to_scan_path)
        khugepaged['pages_to_scan'] = int(pages_to_scan.strip())
    except (FileNotFoundError, ValueError):
        pass
    try:
        scan_sleep = context.read_file(scan_sleep_path)
        khugepaged['scan_sleep_millisecs'] = int(scan_sleep.strip())
    except (FileNotFoundError, ValueError):
        pass

    # Analyze
    issues = analyze_thp(enabled, defrag, vmstat, opts.compact_stall_threshold)

    # Determine status
    has_warning = any(i['severity'] == 'WARNING' for i in issues)
    status = 'warning' if has_warning else 'healthy'

    # Output
    if opts.format == 'json':
        result: dict[str, Any] = {
            'thp_settings': {
                'enabled': enabled,
                'defrag': defrag,
            },
            'vmstat': vmstat,
            'khugepaged': khugepaged,
            'status': status,
            'issues': issues,
        }
        print(json.dumps(result, indent=2))

    elif opts.format == 'table':
        lines = []
        if not opts.warn_only:
            lines.append('=' * 70)
            lines.append('THP COMPACTION MONITOR')
            lines.append('=' * 70)
            lines.append(f"{'Setting':<30} {'Value':<40}")
            lines.append('-' * 70)
            lines.append(f"{'THP Enabled':<30} {enabled or 'unknown':<40}")
            lines.append(f"{'THP Defrag':<30} {defrag or 'unknown':<40}")
            if khugepaged:
                for key, val in khugepaged.items():
                    lines.append(f"{'khugepaged.' + key:<30} {val:<40}")
            lines.append('')

            lines.append(f"{'Compaction Counter':<30} {'Value':<40}")
            lines.append('-' * 70)
            for key in ['compact_stall', 'compact_fail', 'compact_success']:
                lines.append(f"{key:<30} {vmstat.get(key, 0):<40}")
            lines.append('')

            lines.append(f"{'THP Counter':<30} {'Value':<40}")
            lines.append('-' * 70)
            for key in ['thp_fault_alloc', 'thp_fault_fallback',
                        'thp_collapse_alloc', 'thp_collapse_alloc_failed']:
                lines.append(f"{key:<30} {vmstat.get(key, 0):<40}")
            lines.append('=' * 70)
            lines.append('')

        if issues:
            for issue in issues:
                if opts.warn_only and issue['severity'] == 'INFO':
                    continue
                lines.append(f"[{issue['severity']}] {issue['message']}")
            lines.append('')

        print('\n'.join(lines))

    else:  # plain
        lines = []
        if not opts.warn_only:
            lines.append(f"THP Enabled: {enabled or 'unknown'}")
            lines.append(f"THP Defrag: {defrag or 'unknown'}")
            lines.append('')

            compact_stall = vmstat.get('compact_stall', 0)
            compact_fail = vmstat.get('compact_fail', 0)
            compact_success = vmstat.get('compact_success', 0)
            lines.append(f"Compaction: {compact_stall} stalls, "
                        f"{compact_success} successes, {compact_fail} failures")

            thp_fault_alloc = vmstat.get('thp_fault_alloc', 0)
            thp_fault_fallback = vmstat.get('thp_fault_fallback', 0)
            total_fault = thp_fault_alloc + thp_fault_fallback
            if total_fault > 0:
                fallback_pct = thp_fault_fallback / total_fault * 100
                lines.append(f"THP Faults: {thp_fault_alloc} alloc, "
                            f"{thp_fault_fallback} fallback ({fallback_pct:.1f}% fallback)")
            else:
                lines.append(f"THP Faults: {thp_fault_alloc} alloc, "
                            f"{thp_fault_fallback} fallback")

            thp_collapse_alloc = vmstat.get('thp_collapse_alloc', 0)
            thp_collapse_alloc_failed = vmstat.get('thp_collapse_alloc_failed', 0)
            lines.append(f"khugepaged: {thp_collapse_alloc} collapses, "
                        f"{thp_collapse_alloc_failed} failures")

            if opts.verbose and khugepaged:
                lines.append('')
                lines.append('khugepaged tuning:')
                for key, val in khugepaged.items():
                    lines.append(f"  {key}: {val}")

            lines.append('')

        # Issues
        warning_issues = [i for i in issues if i['severity'] == 'WARNING']
        info_issues = [i for i in issues if i['severity'] == 'INFO']

        if warning_issues:
            for issue in warning_issues:
                lines.append(f"[WARNING] {issue['message']}")
            lines.append('')

        if info_issues and not opts.warn_only:
            for issue in info_issues:
                lines.append(f"[INFO] {issue['message']}")
            lines.append('')

        if not issues and not opts.warn_only:
            lines.append('No THP issues detected.')

        print('\n'.join(lines))

    # Set summary
    output.set_summary(f"enabled={enabled}, defrag={defrag}, status={status}")

    if has_warning:
        return 1
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
