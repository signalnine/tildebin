#!/usr/bin/env python3
"""
Monitor memory health and ECC errors on baremetal systems.

Checks for ECC (Error-Correcting Code) memory errors, memory pressure,
and swap usage. Critical for detecting failing DIMMs before data corruption
occurs in large-scale baremetal environments.

Exit codes:
  0 - Success (no memory errors detected)
  1 - Warning/Critical memory issues detected
  2 - Usage error or missing dependencies
"""

import argparse
import glob
import json
import os
import re
import sys


def check_edac_available():
    """Check if EDAC (Error Detection and Correction) interface is available."""
    return os.path.exists('/sys/devices/system/edac/mc')


def get_memory_controllers():
    """Get list of memory controller directories."""
    mc_dirs = glob.glob('/sys/devices/system/edac/mc/mc[0-9]*')
    return sorted(mc_dirs)


def read_sysfs_file(path):
    """Read a sysfs file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def get_meminfo():
    """Parse /proc/meminfo for memory usage statistics."""
    meminfo = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                match = re.match(r'^(\w+):\s+(\d+)', line)
                if match:
                    key = match.group(1)
                    value = int(match.group(2))  # Value in kB
                    meminfo[key] = value
    except (IOError, OSError):
        pass
    return meminfo


def get_memory_pressure():
    """
    Analyze memory pressure from /proc/meminfo.

    Returns dict with total, available, used, swap info, and pressure status.
    """
    meminfo = get_meminfo()

    if not meminfo:
        return None

    total = meminfo.get('MemTotal', 0)
    available = meminfo.get('MemAvailable', 0)
    swap_total = meminfo.get('SwapTotal', 0)
    swap_free = meminfo.get('SwapFree', 0)

    used = total - available
    used_percent = (used / total * 100) if total > 0 else 0

    swap_used = swap_total - swap_free
    swap_used_percent = (swap_used / swap_total * 100) if swap_total > 0 else 0

    # Determine pressure status
    status = 'OK'
    issues = []

    if used_percent > 95:
        status = 'CRITICAL'
        issues.append(f'Memory usage critical: {used_percent:.1f}%')
    elif used_percent > 90:
        status = 'WARNING'
        issues.append(f'Memory usage high: {used_percent:.1f}%')

    if swap_total > 0 and swap_used_percent > 50:
        if status == 'OK':
            status = 'WARNING'
        issues.append(f'Swap usage high: {swap_used_percent:.1f}%')

    if swap_total > 0 and swap_used_percent > 80:
        status = 'CRITICAL'
        issues.append(f'Swap usage critical: {swap_used_percent:.1f}%')

    return {
        'total_kb': total,
        'available_kb': available,
        'used_kb': used,
        'used_percent': used_percent,
        'swap_total_kb': swap_total,
        'swap_used_kb': swap_used,
        'swap_used_percent': swap_used_percent,
        'status': status,
        'issues': issues
    }


def get_mc_info(mc_path):
    """
    Get memory controller information from EDAC sysfs.

    Returns dict with controller name, size, correctable/uncorrectable error counts.
    """
    mc_name = os.path.basename(mc_path)
    mc_num = mc_name.replace('mc', '')

    info = {
        'controller': mc_num,
        'controller_name': read_sysfs_file(f'{mc_path}/mc_name') or 'Unknown',
        'size_mb': read_sysfs_file(f'{mc_path}/size_mb') or 'Unknown',
        'ce_count': 0,  # Correctable errors
        'ue_count': 0,  # Uncorrectable errors
        'ce_noinfo_count': 0,
        'ue_noinfo_count': 0,
        'status': 'OK',
        'dimms': []
    }

    # Read error counts
    ce_count = read_sysfs_file(f'{mc_path}/ce_count')
    if ce_count:
        info['ce_count'] = int(ce_count)

    ue_count = read_sysfs_file(f'{mc_path}/ue_count')
    if ue_count:
        info['ue_count'] = int(ue_count)

    ce_noinfo = read_sysfs_file(f'{mc_path}/ce_noinfo_count')
    if ce_noinfo:
        info['ce_noinfo_count'] = int(ce_noinfo)

    ue_noinfo = read_sysfs_file(f'{mc_path}/ue_noinfo_count')
    if ue_noinfo:
        info['ue_noinfo_count'] = int(ue_noinfo)

    # Get DIMM information
    dimm_dirs = glob.glob(f'{mc_path}/dimm[0-9]*')
    for dimm_path in sorted(dimm_dirs):
        dimm_info = get_dimm_info(dimm_path)
        if dimm_info:
            info['dimms'].append(dimm_info)

    # Determine status
    total_ce = info['ce_count'] + info['ce_noinfo_count']
    total_ue = info['ue_count'] + info['ue_noinfo_count']

    if total_ue > 0:
        info['status'] = 'CRITICAL'
    elif total_ce > 100:
        info['status'] = 'CRITICAL'
    elif total_ce > 10:
        info['status'] = 'WARNING'

    return info


def get_dimm_info(dimm_path):
    """
    Get DIMM-specific information from EDAC sysfs.

    Returns dict with DIMM location, label, size, and error counts.
    """
    dimm_name = os.path.basename(dimm_path)

    info = {
        'dimm': dimm_name,
        'label': read_sysfs_file(f'{dimm_path}/dimm_label') or 'Unknown',
        'location': read_sysfs_file(f'{dimm_path}/dimm_location') or 'Unknown',
        'size': read_sysfs_file(f'{dimm_path}/size') or '0',
        'mem_type': read_sysfs_file(f'{dimm_path}/dimm_mem_type') or 'Unknown',
        'ce_count': 0,
        'ue_count': 0,
        'status': 'OK'
    }

    # Read error counts
    ce_count = read_sysfs_file(f'{dimm_path}/dimm_ce_count')
    if ce_count:
        info['ce_count'] = int(ce_count)

    ue_count = read_sysfs_file(f'{dimm_path}/dimm_ue_count')
    if ue_count:
        info['ue_count'] = int(ue_count)

    # Skip DIMMs with no size (not populated)
    if info['size'] == '0':
        return None

    # Determine status
    if info['ue_count'] > 0:
        info['status'] = 'CRITICAL'
    elif info['ce_count'] > 100:
        info['status'] = 'CRITICAL'
    elif info['ce_count'] > 10:
        info['status'] = 'WARNING'
    elif info['ce_count'] > 0:
        info['status'] = 'WARNING'

    return info


def format_bytes(kb):
    """Convert KB to human-readable format."""
    if kb < 1024:
        return f"{kb} KB"
    elif kb < 1024 * 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb / 1024 / 1024:.1f} GB"


def output_plain(memory_pressure, mc_data, warn_only=False, verbose=False):
    """Output results in plain text format."""
    output_lines = []

    # Memory pressure summary
    if memory_pressure:
        if not warn_only or memory_pressure['status'] != 'OK':
            output_lines.append("=== Memory Usage ===")
            output_lines.append(f"Total: {format_bytes(memory_pressure['total_kb'])}")
            output_lines.append(f"Used: {format_bytes(memory_pressure['used_kb'])} "
                              f"({memory_pressure['used_percent']:.1f}%)")
            output_lines.append(f"Available: {format_bytes(memory_pressure['available_kb'])}")

            if memory_pressure['swap_total_kb'] > 0:
                output_lines.append(f"Swap: {format_bytes(memory_pressure['swap_used_kb'])} / "
                                  f"{format_bytes(memory_pressure['swap_total_kb'])} "
                                  f"({memory_pressure['swap_used_percent']:.1f}%)")

            output_lines.append(f"Status: {memory_pressure['status']}")

            if memory_pressure['issues']:
                for issue in memory_pressure['issues']:
                    output_lines.append(f"  - {issue}")
            output_lines.append("")

    # ECC error summary
    if mc_data:
        has_errors = any(mc['status'] != 'OK' for mc in mc_data)

        if not warn_only or has_errors:
            output_lines.append("=== ECC Memory Errors ===")

            for mc in mc_data:
                if warn_only and mc['status'] == 'OK':
                    continue

                total_ce = mc['ce_count'] + mc['ce_noinfo_count']
                total_ue = mc['ue_count'] + mc['ue_noinfo_count']

                output_lines.append(f"Controller {mc['controller']} ({mc['controller_name']}): "
                                  f"{mc['status']}")
                output_lines.append(f"  Size: {mc['size_mb']} MB")
                output_lines.append(f"  Correctable Errors: {total_ce}")
                output_lines.append(f"  Uncorrectable Errors: {total_ue}")

                # Show DIMM details if verbose or if there are errors
                if verbose or any(d['status'] != 'OK' for d in mc['dimms']):
                    for dimm in mc['dimms']:
                        if warn_only and dimm['status'] == 'OK':
                            continue

                        if dimm['ce_count'] > 0 or dimm['ue_count'] > 0 or verbose:
                            output_lines.append(f"    {dimm['label']} ({dimm['location']}): "
                                              f"{dimm['status']}")
                            output_lines.append(f"      Size: {dimm['size']} MB, Type: {dimm['mem_type']}")
                            if dimm['ce_count'] > 0 or dimm['ue_count'] > 0:
                                output_lines.append(f"      CE: {dimm['ce_count']}, UE: {dimm['ue_count']}")
                output_lines.append("")

    if not output_lines:
        if warn_only:
            return "No memory issues detected."
        else:
            return "No memory information available."

    return '\n'.join(output_lines)


def output_json(memory_pressure, mc_data, warn_only=False):
    """Output results in JSON format."""
    result = {
        'memory_pressure': memory_pressure,
        'memory_controllers': mc_data
    }

    if warn_only:
        if memory_pressure and memory_pressure['status'] == 'OK':
            result['memory_pressure'] = None

        if mc_data:
            result['memory_controllers'] = [
                mc for mc in mc_data if mc['status'] != 'OK'
            ]

    return json.dumps(result, indent=2)


def output_table(memory_pressure, mc_data, warn_only=False):
    """Output results in table format."""
    lines = []

    # Memory pressure table
    if memory_pressure and (not warn_only or memory_pressure['status'] != 'OK'):
        lines.append("MEMORY USAGE")
        lines.append("-" * 70)
        lines.append(f"{'Metric':<20} {'Value':<30} {'Status':<20}")
        lines.append("-" * 70)
        lines.append(f"{'Total Memory':<20} {format_bytes(memory_pressure['total_kb']):<30} {'':<20}")
        lines.append(f"{'Used Memory':<20} "
                    f"{format_bytes(memory_pressure['used_kb'])} ({memory_pressure['used_percent']:.1f}%):<30 "
                    f"{memory_pressure['status']:<20}")
        if memory_pressure['swap_total_kb'] > 0:
            lines.append(f"{'Swap Usage':<20} "
                        f"{format_bytes(memory_pressure['swap_used_kb'])} ({memory_pressure['swap_used_percent']:.1f}%):<30 "
                        f"{'':<20}")
        lines.append("")

    # ECC errors table
    if mc_data:
        has_errors = any(mc['status'] != 'OK' for mc in mc_data)

        if not warn_only or has_errors:
            lines.append("ECC MEMORY ERRORS")
            lines.append("-" * 70)
            lines.append(f"{'Controller':<15} {'CE Count':<12} {'UE Count':<12} {'Status':<15}")
            lines.append("-" * 70)

            for mc in mc_data:
                if warn_only and mc['status'] == 'OK':
                    continue

                total_ce = mc['ce_count'] + mc['ce_noinfo_count']
                total_ue = mc['ue_count'] + mc['ue_noinfo_count']

                lines.append(f"{mc['controller_name']:<15} {total_ce:<12} {total_ue:<12} {mc['status']:<15}")

    if not lines:
        return "No memory issues detected." if warn_only else "No memory information available."

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor memory health and ECC errors on baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check memory health and ECC errors
  %(prog)s

  # Show only issues (warnings/critical)
  %(prog)s --warn-only

  # Output in JSON format for monitoring systems
  %(prog)s --format json

  # Show detailed DIMM information
  %(prog)s --verbose

  # Table format with warnings only
  %(prog)s --format table --warn-only

Exit codes:
  0 - No memory errors detected
  1 - Memory warnings or errors detected
  2 - Usage error or missing dependencies

Notes:
  - Requires EDAC kernel modules loaded for ECC error detection
  - On systems without ECC support, only memory pressure is reported
  - Correctable errors (CE) > 10 trigger WARNING, > 100 trigger CRITICAL
  - Any uncorrectable errors (UE) trigger CRITICAL status
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--warn-only',
        action='store_true',
        help='Only show memory issues (warnings/critical)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed DIMM information'
    )

    args = parser.parse_args()

    # Get memory pressure information
    memory_pressure = get_memory_pressure()

    # Get ECC error information
    mc_data = []
    if check_edac_available():
        mc_dirs = get_memory_controllers()
        for mc_path in mc_dirs:
            mc_info = get_mc_info(mc_path)
            if mc_info:
                mc_data.append(mc_info)

    # If no EDAC and no meminfo, error out
    if not memory_pressure and not mc_data:
        print("Error: Could not read memory information", file=sys.stderr)
        print("Ensure /proc/meminfo is available", file=sys.stderr)
        return 2

    # Output results
    if args.format == 'json':
        output = output_json(memory_pressure, mc_data, args.warn_only)
    elif args.format == 'table':
        output = output_table(memory_pressure, mc_data, args.warn_only)
    else:
        output = output_plain(memory_pressure, mc_data, args.warn_only, args.verbose)

    print(output)

    # Determine exit code
    has_issues = False

    if memory_pressure and memory_pressure['status'] != 'OK':
        has_issues = True

    if any(mc['status'] != 'OK' for mc in mc_data):
        has_issues = True

    return 1 if has_issues else 0


if __name__ == '__main__':
    sys.exit(main())
