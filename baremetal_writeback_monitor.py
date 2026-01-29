#!/usr/bin/env python3
"""
Monitor kernel writeback cache behavior and dirty page pressure.

This script monitors the Linux kernel's writeback subsystem by analyzing:
- Dirty page counts and ratios vs configured thresholds
- Background writeback activity and throttling
- Per-BDI (backing device info) writeback statistics
- Writeback congestion indicators

High dirty page ratios can cause:
- Application stalls when dirty_ratio threshold is hit
- Increased I/O latency spikes
- Memory pressure as pages cannot be reclaimed
- Risk of data loss on sudden power failure

Exit codes:
    0 - Writeback metrics within normal thresholds
    1 - Warning or critical thresholds exceeded
    2 - Usage error or missing data sources
"""

import argparse
import glob
import json
import os
import sys


def read_file(path):
    """Read file contents, return None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError, PermissionError):
        return None


def read_int(path, default=0):
    """Read integer from file, return default if unavailable."""
    content = read_file(path)
    if content is not None:
        try:
            return int(content)
        except ValueError:
            pass
    return default


def get_meminfo():
    """Parse /proc/meminfo and return dict of values in bytes."""
    meminfo = {}
    content = read_file('/proc/meminfo')
    if not content:
        return meminfo

    for line in content.split('\n'):
        if ':' not in line:
            continue
        parts = line.split(':')
        key = parts[0].strip()
        value_parts = parts[1].strip().split()
        if value_parts:
            try:
                value = int(value_parts[0])
                # Convert kB to bytes if unit present
                if len(value_parts) > 1 and value_parts[1].lower() == 'kb':
                    value *= 1024
                meminfo[key] = value
            except ValueError:
                continue

    return meminfo


def get_vm_settings():
    """Read vm.dirty_* sysctl settings."""
    settings = {}

    # Dirty thresholds (percentage of total memory)
    settings['dirty_background_ratio'] = read_int(
        '/proc/sys/vm/dirty_background_ratio', 10
    )
    settings['dirty_ratio'] = read_int(
        '/proc/sys/vm/dirty_ratio', 20
    )

    # Dirty thresholds (absolute bytes, 0 means use ratio)
    settings['dirty_background_bytes'] = read_int(
        '/proc/sys/vm/dirty_background_bytes', 0
    )
    settings['dirty_bytes'] = read_int(
        '/proc/sys/vm/dirty_bytes', 0
    )

    # Writeback timing
    settings['dirty_expire_centisecs'] = read_int(
        '/proc/sys/vm/dirty_expire_centisecs', 3000
    )
    settings['dirty_writeback_centisecs'] = read_int(
        '/proc/sys/vm/dirty_writeback_centisecs', 500
    )

    return settings


def get_bdi_stats():
    """Get per-BDI (backing device info) writeback statistics."""
    bdi_list = []

    bdi_base = '/sys/class/bdi'
    if not os.path.exists(bdi_base):
        return bdi_list

    try:
        for bdi_name in os.listdir(bdi_base):
            bdi_path = os.path.join(bdi_base, bdi_name)
            if not os.path.isdir(bdi_path):
                continue

            bdi_info = {
                'name': bdi_name,
                'read_ahead_kb': read_int(f'{bdi_path}/read_ahead_kb'),
                'min_ratio': read_int(f'{bdi_path}/min_ratio'),
                'max_ratio': read_int(f'{bdi_path}/max_ratio'),
            }

            # Get stats if available
            stats_path = f'{bdi_path}/stats'
            if os.path.exists(stats_path):
                for stat_file in ['BdiWriteback', 'BdiReclaimable', 'BdiDirtyThresh',
                                  'BdiDirtied', 'BdiWritten']:
                    stat_val = read_int(f'{stats_path}/{stat_file}')
                    if stat_val is not None:
                        bdi_info[stat_file.lower()] = stat_val

            bdi_list.append(bdi_info)
    except (OSError, PermissionError):
        pass

    return bdi_list


def get_vmstat():
    """Parse /proc/vmstat for writeback-related counters."""
    vmstat = {}
    content = read_file('/proc/vmstat')
    if not content:
        return vmstat

    # Counters we care about
    wb_counters = [
        'nr_dirty', 'nr_writeback', 'nr_writeback_temp',
        'nr_dirty_threshold', 'nr_dirty_background_threshold',
        'pgpgin', 'pgpgout', 'pswpin', 'pswpout',
        'nr_vmscan_write', 'nr_written',
    ]

    for line in content.split('\n'):
        parts = line.split()
        if len(parts) >= 2 and parts[0] in wb_counters:
            try:
                vmstat[parts[0]] = int(parts[1])
            except ValueError:
                continue

    return vmstat


def analyze_writeback(meminfo, vmstat, settings, warn_dirty_pct, crit_dirty_pct):
    """
    Analyze writeback state and identify issues.

    Returns dict with status, issues, and metrics.
    """
    result = {
        'status': 'ok',
        'issues': [],
        'metrics': {},
    }

    total_mem = meminfo.get('MemTotal', 0)
    if total_mem == 0:
        result['status'] = 'error'
        result['issues'].append('Cannot determine total memory')
        return result

    # Get dirty page counts (in pages, convert to bytes using 4KB page size)
    page_size = 4096
    nr_dirty = vmstat.get('nr_dirty', 0) * page_size
    nr_writeback = vmstat.get('nr_writeback', 0) * page_size
    nr_writeback_temp = vmstat.get('nr_writeback_temp', 0) * page_size

    # Alternative: use meminfo Dirty/Writeback (already in bytes from our parser)
    if nr_dirty == 0:
        nr_dirty = meminfo.get('Dirty', 0)
    if nr_writeback == 0:
        nr_writeback = meminfo.get('Writeback', 0)

    # Calculate thresholds
    if settings['dirty_bytes'] > 0:
        dirty_thresh = settings['dirty_bytes']
    else:
        dirty_thresh = (total_mem * settings['dirty_ratio']) // 100

    if settings['dirty_background_bytes'] > 0:
        bg_thresh = settings['dirty_background_bytes']
    else:
        bg_thresh = (total_mem * settings['dirty_background_ratio']) // 100

    # Calculate current dirty percentage
    dirty_pct = (nr_dirty / total_mem) * 100 if total_mem > 0 else 0
    writeback_pct = (nr_writeback / total_mem) * 100 if total_mem > 0 else 0

    # Store metrics
    result['metrics'] = {
        'total_memory_bytes': total_mem,
        'dirty_bytes': nr_dirty,
        'dirty_pct': round(dirty_pct, 2),
        'writeback_bytes': nr_writeback,
        'writeback_pct': round(writeback_pct, 2),
        'writeback_temp_bytes': nr_writeback_temp,
        'dirty_threshold_bytes': dirty_thresh,
        'dirty_threshold_pct': settings['dirty_ratio'],
        'dirty_bg_threshold_bytes': bg_thresh,
        'dirty_bg_threshold_pct': settings['dirty_background_ratio'],
        'dirty_expire_secs': settings['dirty_expire_centisecs'] / 100,
        'writeback_interval_secs': settings['dirty_writeback_centisecs'] / 100,
    }

    # Check against user-specified thresholds
    if dirty_pct >= crit_dirty_pct:
        result['status'] = 'critical'
        result['issues'].append(
            f'Dirty pages critical: {dirty_pct:.1f}% >= {crit_dirty_pct}% threshold'
        )
    elif dirty_pct >= warn_dirty_pct:
        if result['status'] == 'ok':
            result['status'] = 'warning'
        result['issues'].append(
            f'Dirty pages elevated: {dirty_pct:.1f}% >= {warn_dirty_pct}% threshold'
        )

    # Check if approaching kernel dirty_ratio (process throttling threshold)
    ratio_to_limit = (nr_dirty / dirty_thresh) * 100 if dirty_thresh > 0 else 0
    result['metrics']['ratio_to_dirty_limit_pct'] = round(ratio_to_limit, 2)

    if ratio_to_limit >= 90:
        if result['status'] == 'ok':
            result['status'] = 'critical'
        result['issues'].append(
            f'Approaching dirty_ratio limit: {ratio_to_limit:.1f}% of threshold '
            f'(processes will be throttled at 100%)'
        )
    elif ratio_to_limit >= 75:
        if result['status'] == 'ok':
            result['status'] = 'warning'
        result['issues'].append(
            f'Dirty pages at {ratio_to_limit:.1f}% of dirty_ratio limit'
        )

    # Check if background writeback is overwhelmed
    bg_ratio = (nr_dirty / bg_thresh) * 100 if bg_thresh > 0 else 0
    result['metrics']['ratio_to_bg_limit_pct'] = round(bg_ratio, 2)

    if bg_ratio >= 100:
        # We're past the background threshold, writeback should be active
        if nr_writeback == 0:
            if result['status'] == 'ok':
                result['status'] = 'warning'
            result['issues'].append(
                'Dirty pages exceed background threshold but no writeback active'
            )

    # Check for excessive writeback (I/O congestion indicator)
    if writeback_pct > 5:
        if result['status'] == 'ok':
            result['status'] = 'warning'
        result['issues'].append(
            f'High writeback volume: {writeback_pct:.1f}% of memory in flight'
        )

    return result


def format_bytes(bytes_val):
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_val) < 1024.0:
            return f'{bytes_val:.1f}{unit}'
        bytes_val /= 1024.0
    return f'{bytes_val:.1f}PB'


def output_plain(result, bdi_stats, verbose=False, warn_only=False):
    """Output results in plain text format."""
    lines = []
    metrics = result['metrics']

    if result['issues']:
        status = result['status'].upper()
        lines.append(f'{status} - Writeback Issues Detected:')
        for issue in result['issues']:
            lines.append(f'  - {issue}')
        lines.append('')

    if not warn_only or result['issues']:
        lines.append('Writeback Metrics:')
        lines.append(f"  Dirty pages:     {format_bytes(metrics['dirty_bytes'])} "
                     f"({metrics['dirty_pct']:.1f}% of memory)")
        lines.append(f"  In writeback:    {format_bytes(metrics['writeback_bytes'])} "
                     f"({metrics['writeback_pct']:.1f}% of memory)")
        lines.append(f"  Dirty limit:     {format_bytes(metrics['dirty_threshold_bytes'])} "
                     f"({metrics['dirty_threshold_pct']}% of memory)")
        lines.append(f"  BG threshold:    {format_bytes(metrics['dirty_bg_threshold_bytes'])} "
                     f"({metrics['dirty_bg_threshold_pct']}% of memory)")
        lines.append(f"  Usage of limit:  {metrics['ratio_to_dirty_limit_pct']:.1f}%")
        lines.append('')

    if verbose and bdi_stats:
        lines.append('Per-Device Backing Info:')
        for bdi in bdi_stats:
            lines.append(f"  {bdi['name']}: read_ahead={bdi['read_ahead_kb']}KB, "
                         f"min_ratio={bdi['min_ratio']}%, max_ratio={bdi['max_ratio']}%")
        lines.append('')

    if not result['issues'] and not warn_only:
        lines.append('Writeback operating normally.')

    return '\n'.join(lines)


def output_json(result, bdi_stats, settings):
    """Output results in JSON format."""
    output = {
        'status': result['status'],
        'issues': result['issues'],
        'metrics': result['metrics'],
        'settings': settings,
        'bdi_devices': bdi_stats,
    }
    return json.dumps(output, indent=2)


def output_table(result, warn_only=False):
    """Output results in table format."""
    lines = []
    metrics = result['metrics']

    if not warn_only or result['issues']:
        lines.append(f"{'Metric':<25} {'Value':<20} {'Percent':<15} {'Status':<10}")
        lines.append('-' * 70)

        # Determine status indicators
        dirty_status = 'OK'
        if result['status'] == 'critical':
            dirty_status = 'CRITICAL'
        elif result['status'] == 'warning':
            dirty_status = 'WARNING'

        lines.append(
            f"{'Dirty Pages':<25} "
            f"{format_bytes(metrics['dirty_bytes']):<20} "
            f"{metrics['dirty_pct']:.1f}%{'':<10} "
            f"{dirty_status:<10}"
        )
        lines.append(
            f"{'Writeback Active':<25} "
            f"{format_bytes(metrics['writeback_bytes']):<20} "
            f"{metrics['writeback_pct']:.1f}%{'':<10} "
            f"{'-':<10}"
        )
        lines.append(
            f"{'Dirty Threshold':<25} "
            f"{format_bytes(metrics['dirty_threshold_bytes']):<20} "
            f"{metrics['dirty_threshold_pct']}%{'':<11} "
            f"{'-':<10}"
        )
        lines.append(
            f"{'Usage of Limit':<25} "
            f"{'-':<20} "
            f"{metrics['ratio_to_dirty_limit_pct']:.1f}%{'':<10} "
            f"{'-':<10}"
        )

    if result['issues']:
        lines.append('')
        lines.append('Issues:')
        for issue in result['issues']:
            lines.append(f'  - {issue}')

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor kernel writeback cache and dirty page pressure',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Check writeback with default thresholds
  %(prog)s --warn-pct 10             # Warn when dirty pages > 10%%
  %(prog)s --crit-pct 15             # Critical when dirty pages > 15%%
  %(prog)s --format json             # JSON output for automation
  %(prog)s --verbose                 # Include per-device BDI statistics

Understanding thresholds:
  The kernel has two dirty page thresholds:
  - dirty_background_ratio: When exceeded, background writeback starts
  - dirty_ratio: When exceeded, processes writing are throttled

  This monitor checks against user-specified thresholds (--warn-pct, --crit-pct)
  and also warns when approaching the kernel's dirty_ratio limit.

Exit codes:
  0 - Writeback metrics within normal thresholds
  1 - Warning or critical thresholds exceeded
  2 - Usage error or missing data sources
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
        help='Show detailed information including per-device stats'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues detected'
    )

    parser.add_argument(
        '--warn-pct',
        type=float,
        default=5.0,
        help='Warning threshold for dirty pages as %% of memory (default: %(default)s)'
    )

    parser.add_argument(
        '--crit-pct',
        type=float,
        default=10.0,
        help='Critical threshold for dirty pages as %% of memory (default: %(default)s)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn_pct < 0 or args.warn_pct > 100:
        print('Error: --warn-pct must be between 0 and 100', file=sys.stderr)
        sys.exit(2)

    if args.crit_pct < 0 or args.crit_pct > 100:
        print('Error: --crit-pct must be between 0 and 100', file=sys.stderr)
        sys.exit(2)

    if args.warn_pct > args.crit_pct:
        print('Error: --warn-pct cannot exceed --crit-pct', file=sys.stderr)
        sys.exit(2)

    # Check for required data sources
    if not os.path.exists('/proc/meminfo'):
        print('Error: /proc/meminfo not available', file=sys.stderr)
        sys.exit(2)

    # Gather data
    meminfo = get_meminfo()
    vmstat = get_vmstat()
    settings = get_vm_settings()
    bdi_stats = get_bdi_stats()

    if not meminfo:
        print('Error: Cannot read memory information', file=sys.stderr)
        sys.exit(2)

    # Analyze
    result = analyze_writeback(
        meminfo, vmstat, settings,
        args.warn_pct, args.crit_pct
    )

    # Output
    if args.format == 'json':
        output = output_json(result, bdi_stats, settings)
    elif args.format == 'table':
        output = output_table(result, warn_only=args.warn_only)
    else:
        output = output_plain(result, bdi_stats,
                              verbose=args.verbose, warn_only=args.warn_only)

    if output:
        print(output)

    # Exit code
    if result['status'] == 'critical':
        sys.exit(1)
    elif result['status'] == 'warning':
        sys.exit(1)
    elif result['status'] == 'error':
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
