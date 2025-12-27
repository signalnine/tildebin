#!/usr/bin/env python3
"""
Monitor hugepage allocation and usage on Linux systems.

Hugepages are large memory pages (typically 2MB or 1GB) that reduce TLB misses
and improve performance for memory-intensive applications like databases,
virtual machines, and scientific computing workloads.

This script monitors:
- Configured vs allocated hugepages
- Hugepage fragmentation (allocation failures)
- Per-NUMA node hugepage distribution
- Transparent Huge Pages (THP) status and defrag settings
- Hugepage reservation status

Useful for:
- Database servers (PostgreSQL, MySQL, Oracle)
- Virtual machine hosts (KVM/QEMU)
- High-performance computing workloads
- In-memory caching systems (Redis, Memcached with hugepages)

Exit codes:
    0 - Hugepages healthy, no issues detected
    1 - Warnings or issues detected (fragmentation, low availability)
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import glob


def read_sysfs_file(path):
    """Read a sysfs/proc file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def read_int_file(path, default=0):
    """Read an integer from a sysfs/proc file."""
    content = read_sysfs_file(path)
    if content is not None:
        try:
            return int(content)
        except ValueError:
            pass
    return default


def get_meminfo_hugepages():
    """Parse /proc/meminfo for hugepage information."""
    hugepages = {
        'total': 0,
        'free': 0,
        'reserved': 0,
        'surplus': 0,
        'pagesize_kb': 2048,  # Default 2MB
    }

    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
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
    except FileNotFoundError:
        print("Error: /proc/meminfo not found (non-Linux system?)", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading /proc/meminfo: {e}", file=sys.stderr)
        sys.exit(2)

    # Calculate derived values
    hugepages['used'] = hugepages['total'] - hugepages['free']
    hugepages['available'] = hugepages['free'] - hugepages['reserved']
    hugepages['total_kb'] = hugepages['total'] * hugepages['pagesize_kb']
    hugepages['used_kb'] = hugepages['used'] * hugepages['pagesize_kb']
    hugepages['free_kb'] = hugepages['free'] * hugepages['pagesize_kb']

    return hugepages


def get_hugepage_sizes():
    """Get available hugepage sizes from /sys/kernel/mm/hugepages/."""
    sizes = []
    hugepages_dir = '/sys/kernel/mm/hugepages'

    if not os.path.exists(hugepages_dir):
        return sizes

    try:
        for entry in os.listdir(hugepages_dir):
            if entry.startswith('hugepages-'):
                # Parse size from directory name (e.g., hugepages-2048kB)
                size_str = entry.replace('hugepages-', '').replace('kB', '')
                try:
                    size_kb = int(size_str)
                    sizes.append({
                        'size_kb': size_kb,
                        'path': os.path.join(hugepages_dir, entry)
                    })
                except ValueError:
                    continue
    except OSError:
        pass

    return sorted(sizes, key=lambda x: x['size_kb'])


def get_hugepage_details(size_info):
    """Get detailed hugepage info for a specific size."""
    path = size_info['path']
    size_kb = size_info['size_kb']

    details = {
        'size_kb': size_kb,
        'size_human': format_size(size_kb),
        'nr_hugepages': read_int_file(os.path.join(path, 'nr_hugepages')),
        'nr_hugepages_mempolicy': read_int_file(os.path.join(path, 'nr_hugepages_mempolicy')),
        'nr_overcommit_hugepages': read_int_file(os.path.join(path, 'nr_overcommit_hugepages')),
        'free_hugepages': read_int_file(os.path.join(path, 'free_hugepages')),
        'resv_hugepages': read_int_file(os.path.join(path, 'resv_hugepages')),
        'surplus_hugepages': read_int_file(os.path.join(path, 'surplus_hugepages')),
    }

    # Calculate usage
    details['used'] = details['nr_hugepages'] - details['free_hugepages']
    details['available'] = details['free_hugepages'] - details['resv_hugepages']
    if details['nr_hugepages'] > 0:
        details['usage_percent'] = (details['used'] / details['nr_hugepages']) * 100
    else:
        details['usage_percent'] = 0.0

    return details


def get_numa_hugepages():
    """Get per-NUMA node hugepage information."""
    numa_info = []
    node_pattern = '/sys/devices/system/node/node[0-9]*'

    for node_path in sorted(glob.glob(node_pattern)):
        node_name = os.path.basename(node_path)
        node_id = int(node_name.replace('node', ''))

        hugepages_path = os.path.join(node_path, 'hugepages')
        if not os.path.exists(hugepages_path):
            continue

        node_data = {
            'node_id': node_id,
            'sizes': []
        }

        try:
            for size_dir in os.listdir(hugepages_path):
                if size_dir.startswith('hugepages-'):
                    size_path = os.path.join(hugepages_path, size_dir)
                    size_str = size_dir.replace('hugepages-', '').replace('kB', '')
                    try:
                        size_kb = int(size_str)
                    except ValueError:
                        continue

                    size_data = {
                        'size_kb': size_kb,
                        'size_human': format_size(size_kb),
                        'nr_hugepages': read_int_file(os.path.join(size_path, 'nr_hugepages')),
                        'free_hugepages': read_int_file(os.path.join(size_path, 'free_hugepages')),
                        'surplus_hugepages': read_int_file(os.path.join(size_path, 'surplus_hugepages')),
                    }
                    size_data['used'] = size_data['nr_hugepages'] - size_data['free_hugepages']
                    node_data['sizes'].append(size_data)
        except OSError:
            continue

        if node_data['sizes']:
            numa_info.append(node_data)

    return numa_info


def get_thp_status():
    """Get Transparent Huge Pages (THP) status."""
    thp = {
        'enabled': None,
        'defrag': None,
        'shmem_enabled': None,
    }

    # Read THP enabled status
    enabled_content = read_sysfs_file('/sys/kernel/mm/transparent_hugepage/enabled')
    if enabled_content:
        # Parse [always] madvise never format
        for option in enabled_content.split():
            if option.startswith('[') and option.endswith(']'):
                thp['enabled'] = option[1:-1]
                break

    # Read defrag setting
    defrag_content = read_sysfs_file('/sys/kernel/mm/transparent_hugepage/defrag')
    if defrag_content:
        for option in defrag_content.split():
            if option.startswith('[') and option.endswith(']'):
                thp['defrag'] = option[1:-1]
                break

    # Read shmem_enabled
    shmem_content = read_sysfs_file('/sys/kernel/mm/transparent_hugepage/shmem_enabled')
    if shmem_content:
        for option in shmem_content.split():
            if option.startswith('[') and option.endswith(']'):
                thp['shmem_enabled'] = option[1:-1]
                break

    return thp


def get_vmstat_hugepage_info():
    """Get hugepage-related statistics from /proc/vmstat."""
    stats = {}

    try:
        with open('/proc/vmstat', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2:
                    key, value = parts
                    # Collect hugepage-related stats
                    if 'thp_' in key or 'htlb_' in key or 'hugepage' in key.lower():
                        try:
                            stats[key] = int(value)
                        except ValueError:
                            pass
    except (IOError, OSError):
        pass

    return stats


def format_size(kb):
    """Format KB value to human-readable format."""
    if kb >= 1024 * 1024:
        return f"{kb / (1024 * 1024):.0f}GB"
    elif kb >= 1024:
        return f"{kb / 1024:.0f}MB"
    else:
        return f"{kb}KB"


def analyze_hugepages(hugepages, sizes, numa_info, vmstat, thresholds):
    """Analyze hugepage status and return issues."""
    issues = []

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
    thp_split_page = vmstat.get('thp_split_page', 0)
    if thp_collapse_fail > 1000:
        issues.append({
            'severity': 'WARNING',
            'type': 'thp_fragmentation',
            'collapse_fail': thp_collapse_fail,
            'message': f"THP collapse failures detected: {thp_collapse_fail} "
                      f"(memory fragmentation may be impacting hugepage allocation)"
        })

    # Check NUMA balance for hugepages
    if len(numa_info) >= 2:
        # Check if hugepages are imbalanced across NUMA nodes
        for size_kb in set(s['size_kb'] for n in numa_info for s in n['sizes']):
            totals = []
            for node in numa_info:
                for size in node['sizes']:
                    if size['size_kb'] == size_kb:
                        totals.append((node['node_id'], size['nr_hugepages']))
                        break

            if len(totals) >= 2:
                max_pages = max(t[1] for t in totals)
                min_pages = min(t[1] for t in totals)
                if max_pages > 0 and min_pages == 0:
                    issues.append({
                        'severity': 'WARNING',
                        'type': 'numa_imbalance',
                        'size_kb': size_kb,
                        'message': f"Hugepages ({format_size(size_kb)}) not distributed across all NUMA nodes"
                    })

    return issues


def output_plain(hugepages, sizes, numa_info, thp, vmstat, issues, verbose, warn_only):
    """Output results in plain text format."""
    lines = []

    if not warn_only:
        # Summary
        lines.append(f"Hugepages: {hugepages['used']}/{hugepages['total']} "
                    f"({format_size(hugepages['pagesize_kb'])} pages)")
        if hugepages['total'] > 0:
            usage_pct = (hugepages['used'] / hugepages['total']) * 100
            lines.append(f"Usage: {usage_pct:.1f}% used, "
                        f"{hugepages['free']} free, {hugepages['reserved']} reserved")
            lines.append(f"Memory: {format_size(hugepages['used_kb'])} used / "
                        f"{format_size(hugepages['total_kb'])} total")
        lines.append("")

        # THP status
        if thp['enabled']:
            lines.append(f"Transparent Huge Pages: {thp['enabled']}")
            if thp['defrag']:
                lines.append(f"THP Defrag: {thp['defrag']}")
            lines.append("")

        # Verbose: per-size details
        if verbose and sizes:
            lines.append("Hugepage Sizes:")
            for size in sizes:
                details = get_hugepage_details(size)
                lines.append(f"  {details['size_human']}: "
                           f"{details['used']}/{details['nr_hugepages']} used "
                           f"({details['usage_percent']:.1f}%)")
            lines.append("")

        # Verbose: per-NUMA details
        if verbose and numa_info:
            lines.append("Per-NUMA Node:")
            for node in numa_info:
                for size in node['sizes']:
                    if size['nr_hugepages'] > 0:
                        lines.append(f"  Node {node['node_id']} ({size['size_human']}): "
                                   f"{size['used']}/{size['nr_hugepages']} used")
            lines.append("")

    # Issues
    for issue in issues:
        if warn_only and issue['severity'] == 'INFO':
            continue
        prefix = f"[{issue['severity']}]"
        lines.append(f"{prefix} {issue['message']}")

    if not issues and not warn_only:
        lines.append("No hugepage issues detected.")

    print('\n'.join(lines))


def output_json(hugepages, sizes, numa_info, thp, vmstat, issues, verbose):
    """Output results in JSON format."""
    result = {
        'hugepages': hugepages,
        'transparent_huge_pages': thp,
        'issues': issues
    }

    if verbose:
        result['sizes'] = [get_hugepage_details(s) for s in sizes]
        result['numa'] = numa_info
        result['vmstat'] = vmstat

    print(json.dumps(result, indent=2))


def output_table(hugepages, sizes, numa_info, thp, vmstat, issues, verbose, warn_only):
    """Output results in table format."""
    lines = []

    if not warn_only:
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
            if warn_only and issue['severity'] == 'INFO':
                continue
            lines.append(f"[{issue['severity']}] {issue['message']}")
        lines.append("")

    print('\n'.join(lines))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor hugepage allocation and usage on Linux systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check hugepage status
  %(prog)s --format json        # JSON output for monitoring
  %(prog)s --verbose            # Show per-size and NUMA details
  %(prog)s --warn 70 --crit 90  # Custom usage thresholds
  %(prog)s --warn-only          # Only show warnings/errors

Thresholds:
  --warn: Usage percentage to trigger warning (default: 80%%)
  --crit: Usage percentage to trigger critical alert (default: 95%%)
  --min-available: Minimum free pages before warning (default: 10)

Exit codes:
  0 - Hugepages healthy
  1 - Warnings or issues detected
  2 - Usage error or missing dependencies

Notes:
  - Static hugepages are configured via /proc/sys/vm/nr_hugepages
  - THP (Transparent Huge Pages) are managed dynamically by the kernel
  - High surplus count indicates overcommit pressure
  - NUMA-aware hugepage allocation improves locality
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

    args = parser.parse_args()

    # Validate thresholds
    if args.warn < 0 or args.warn > 100:
        print("Error: --warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.crit < 0 or args.crit > 100:
        print("Error: --crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.warn >= args.crit:
        print("Error: --warn must be less than --crit", file=sys.stderr)
        sys.exit(2)

    if args.min_available < 0:
        print("Error: --min-available must be non-negative", file=sys.stderr)
        sys.exit(2)

    thresholds = {
        'warning': args.warn,
        'critical': args.crit,
        'min_available': args.min_available
    }

    # Gather information
    hugepages = get_meminfo_hugepages()
    sizes = get_hugepage_sizes()
    numa_info = get_numa_hugepages()
    thp = get_thp_status()
    vmstat = get_vmstat_hugepage_info()

    # Analyze
    issues = analyze_hugepages(hugepages, sizes, numa_info, vmstat, thresholds)

    # Output
    if args.format == 'json':
        output_json(hugepages, sizes, numa_info, thp, vmstat, issues, args.verbose)
    elif args.format == 'table':
        output_table(hugepages, sizes, numa_info, thp, vmstat, issues, args.verbose, args.warn_only)
    else:
        output_plain(hugepages, sizes, numa_info, thp, vmstat, issues, args.verbose, args.warn_only)

    # Exit based on findings
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
