#!/usr/bin/env python3
"""
Monitor kernel vmalloc memory usage to detect exhaustion before failures.

Vmalloc exhaustion can cause cryptic "unable to allocate memory" errors that
appear even when the system has plenty of RAM. This script monitors:
- Total vmalloc space usage
- Largest free contiguous block (for large allocations)
- Top vmalloc consumers (modules, subsystems)
- Warning thresholds for approaching exhaustion

Common causes of vmalloc exhaustion:
- Too many network interfaces/iptables rules
- Kernel modules with large allocations
- eBPF programs and maps
- Graphics drivers
- File systems (especially with many mount points)

Useful for monitoring large baremetal fleets where vmalloc exhaustion can
cause intermittent failures that are hard to diagnose.

Exit codes:
    0 - No issues detected
    1 - Warnings or issues found
    2 - Missing dependencies or usage error
"""

import argparse
import sys
import os
import json
import re
from pathlib import Path


def parse_meminfo():
    """Parse /proc/meminfo for vmalloc statistics"""
    meminfo = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    key = parts[0].strip()
                    # Parse value (remove 'kB' suffix)
                    value_str = parts[1].strip().split()[0]
                    meminfo[key] = int(value_str)
    except (FileNotFoundError, PermissionError) as e:
        print(f"Error: Cannot read /proc/meminfo: {e}", file=sys.stderr)
        return None
    return meminfo


def parse_vmallocinfo():
    """
    Parse /proc/vmallocinfo to get allocation details.

    Returns list of allocations with size and caller info.
    Requires root privileges.
    """
    allocations = []
    try:
        with open('/proc/vmallocinfo', 'r') as f:
            for line in f:
                # Format: 0xaddr-0xaddr   size caller
                match = re.match(
                    r'0x[0-9a-f]+-0x[0-9a-f]+\s+(\d+)\s+(.*)',
                    line.strip()
                )
                if match:
                    size = int(match.group(1))
                    caller = match.group(2).strip()
                    allocations.append({
                        'size': size,
                        'caller': caller,
                    })
    except FileNotFoundError:
        return None
    except PermissionError:
        # Need root to read vmallocinfo
        return None
    return allocations


def get_vmalloc_info():
    """
    Get vmalloc information from /proc/meminfo and /proc/vmallocinfo.

    Returns dict with:
    - total: total vmalloc space (from VmallocTotal)
    - used: used vmalloc space (from VmallocUsed)
    - chunk: largest contiguous free block (from VmallocChunk)
    - allocations: list of individual allocations (if readable)
    """
    meminfo = parse_meminfo()
    if meminfo is None:
        return None

    result = {
        'total_kb': meminfo.get('VmallocTotal', 0),
        'used_kb': meminfo.get('VmallocUsed', 0),
        'chunk_kb': meminfo.get('VmallocChunk', 0),
    }

    # Calculate free space and percentages
    result['free_kb'] = result['total_kb'] - result['used_kb']
    if result['total_kb'] > 0:
        result['used_pct'] = (result['used_kb'] / result['total_kb']) * 100
        result['free_pct'] = (result['free_kb'] / result['total_kb']) * 100
    else:
        result['used_pct'] = 0
        result['free_pct'] = 100

    # Try to get detailed allocations (requires root)
    allocations = parse_vmallocinfo()
    result['allocations'] = allocations
    result['has_details'] = allocations is not None

    return result


def analyze_top_consumers(allocations, top_n=10):
    """
    Analyze vmalloc allocations to find top consumers.

    Groups allocations by caller/module and returns top consumers.
    """
    if allocations is None:
        return None

    # Group by caller function/module
    consumers = {}
    for alloc in allocations:
        caller = alloc['caller']
        # Extract module name or function
        # Format varies: "module+offset" or "function+offset/size"
        key = caller.split('+')[0].split('/')[0]
        if not key:
            key = 'unknown'

        if key not in consumers:
            consumers[key] = {'total_size': 0, 'count': 0}
        consumers[key]['total_size'] += alloc['size']
        consumers[key]['count'] += 1

    # Sort by total size
    sorted_consumers = sorted(
        consumers.items(),
        key=lambda x: x[1]['total_size'],
        reverse=True
    )

    return [
        {'name': name, **stats}
        for name, stats in sorted_consumers[:top_n]
    ]


def format_bytes(bytes_val):
    """Format bytes in human-readable form"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}TB"


def format_kb(kb_val):
    """Format KB value in human-readable form"""
    return format_bytes(kb_val * 1024)


def check_issues(info, warn_pct=80, crit_pct=95, min_chunk_mb=32):
    """
    Check for vmalloc issues.

    Args:
        info: vmalloc info dict
        warn_pct: warning threshold for usage percentage
        crit_pct: critical threshold for usage percentage
        min_chunk_mb: minimum acceptable contiguous block size in MB

    Returns:
        (status, issues) where status is 'healthy', 'warning', or 'critical'
    """
    issues = []

    # Check usage percentage
    if info['used_pct'] >= crit_pct:
        issues.append({
            'severity': 'critical',
            'message': f"Vmalloc usage at {info['used_pct']:.1f}% "
                       f"({format_kb(info['used_kb'])} of {format_kb(info['total_kb'])})"
        })
    elif info['used_pct'] >= warn_pct:
        issues.append({
            'severity': 'warning',
            'message': f"Vmalloc usage at {info['used_pct']:.1f}% "
                       f"({format_kb(info['used_kb'])} of {format_kb(info['total_kb'])})"
        })

    # Check largest contiguous block
    chunk_mb = info['chunk_kb'] / 1024
    if chunk_mb < min_chunk_mb:
        # Fragmentation issue
        issues.append({
            'severity': 'warning',
            'message': f"Largest free contiguous block only {chunk_mb:.1f}MB "
                       f"(threshold: {min_chunk_mb}MB) - may cause large allocation failures"
        })

    # Determine overall status
    if any(i['severity'] == 'critical' for i in issues):
        status = 'critical'
    elif issues:
        status = 'warning'
    else:
        status = 'healthy'

    return status, issues


def output_plain(info, status, issues, top_consumers, verbose=False, warn_only=False):
    """Output in plain text format"""
    if warn_only and status == 'healthy':
        print("No vmalloc issues detected")
        return

    print(f"Vmalloc Memory Status: {status.upper()}")
    print()

    # Basic stats
    print(f"Total:     {format_kb(info['total_kb']):>12}")
    print(f"Used:      {format_kb(info['used_kb']):>12} ({info['used_pct']:.1f}%)")
    print(f"Free:      {format_kb(info['free_kb']):>12} ({info['free_pct']:.1f}%)")
    print(f"Largest:   {format_kb(info['chunk_kb']):>12} (contiguous)")
    print()

    # Issues
    if issues:
        print("Issues:")
        for issue in issues:
            marker = "!!" if issue['severity'] == 'critical' else "!"
            print(f"  {marker} {issue['message']}")
        print()

    # Top consumers (if available and verbose)
    if top_consumers and (verbose or status != 'healthy'):
        print("Top Vmalloc Consumers:")
        for consumer in top_consumers[:5]:
            print(f"  {consumer['name']:<30} {format_bytes(consumer['total_size']):>10} "
                  f"({consumer['count']} allocations)")
        print()

    if not info['has_details']:
        print("Note: Run as root for detailed allocation breakdown")


def output_json(info, status, issues, top_consumers, warn_only=False):
    """Output in JSON format"""
    if warn_only and status == 'healthy':
        print(json.dumps({'status': 'healthy', 'message': 'No issues detected'}))
        return

    output = {
        'status': status,
        'total_kb': info['total_kb'],
        'used_kb': info['used_kb'],
        'free_kb': info['free_kb'],
        'chunk_kb': info['chunk_kb'],
        'used_pct': round(info['used_pct'], 2),
        'free_pct': round(info['free_pct'], 2),
        'issues': issues,
        'top_consumers': top_consumers if top_consumers else [],
        'has_details': info['has_details'],
    }

    print(json.dumps(output, indent=2))


def output_table(info, status, issues, top_consumers, warn_only=False):
    """Output in table format"""
    if warn_only and status == 'healthy':
        print("No vmalloc issues detected")
        return

    print(f"Vmalloc Status: {status.upper()}")
    print()

    print(f"{'Metric':<20} {'Value':>15} {'Percent':>10}")
    print("-" * 48)
    print(f"{'Total Space':<20} {format_kb(info['total_kb']):>15} {'':>10}")
    print(f"{'Used':<20} {format_kb(info['used_kb']):>15} {info['used_pct']:>9.1f}%")
    print(f"{'Free':<20} {format_kb(info['free_kb']):>15} {info['free_pct']:>9.1f}%")
    print(f"{'Largest Contiguous':<20} {format_kb(info['chunk_kb']):>15} {'':>10}")

    if issues:
        print()
        print("Issues:")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")

    if top_consumers:
        print()
        print(f"{'Top Consumer':<30} {'Size':>12} {'Count':>8}")
        print("-" * 52)
        for consumer in top_consumers[:5]:
            print(f"{consumer['name']:<30} "
                  f"{format_bytes(consumer['total_size']):>12} "
                  f"{consumer['count']:>8}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Monitor kernel vmalloc memory usage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Check vmalloc status
  %(prog)s --format json             # JSON output
  %(prog)s --warn-only               # Only show if issues exist
  %(prog)s -v                        # Verbose with top consumers
  %(prog)s --warn-pct 70             # Custom warning threshold

Common causes of vmalloc exhaustion:
  - Many network interfaces or iptables rules
  - Kernel modules with large allocations
  - eBPF programs and maps
  - Graphics/DRM drivers
  - Many mount points or complex filesystems

Exit codes:
  0 - No issues detected
  1 - Warnings or issues found
  2 - Missing dependencies or usage error
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
        help='Show detailed statistics including top consumers'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only produce output if issues are detected'
    )

    parser.add_argument(
        '--warn-pct',
        type=float,
        default=80.0,
        metavar='PCT',
        help='Warning threshold percentage (default: %(default)s)'
    )

    parser.add_argument(
        '--crit-pct',
        type=float,
        default=95.0,
        metavar='PCT',
        help='Critical threshold percentage (default: %(default)s)'
    )

    parser.add_argument(
        '--min-chunk',
        type=float,
        default=32.0,
        metavar='MB',
        help='Minimum acceptable contiguous block in MB (default: %(default)s)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn_pct >= args.crit_pct:
        print("Error: --warn-pct must be less than --crit-pct", file=sys.stderr)
        sys.exit(2)

    # Check if /proc/meminfo exists
    if not Path('/proc/meminfo').exists():
        print("Error: /proc/meminfo not found (not a Linux system?)",
              file=sys.stderr)
        sys.exit(2)

    # Get vmalloc info
    info = get_vmalloc_info()
    if info is None:
        print("Error: Could not read vmalloc information", file=sys.stderr)
        sys.exit(2)

    # Check if VmallocTotal is available
    if info['total_kb'] == 0:
        print("Error: VmallocTotal not found in /proc/meminfo", file=sys.stderr)
        sys.exit(2)

    # Analyze top consumers if we have detailed info
    top_consumers = None
    if info['allocations']:
        top_consumers = analyze_top_consumers(info['allocations'])

    # Check for issues
    status, issues = check_issues(
        info,
        warn_pct=args.warn_pct,
        crit_pct=args.crit_pct,
        min_chunk_mb=args.min_chunk
    )

    # Output results
    if args.format == 'json':
        output_json(info, status, issues, top_consumers, args.warn_only)
    elif args.format == 'table':
        output_table(info, status, issues, top_consumers, args.warn_only)
    else:  # plain
        output_plain(info, status, issues, top_consumers, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if status in ('warning', 'critical') else 0)


if __name__ == "__main__":
    main()
