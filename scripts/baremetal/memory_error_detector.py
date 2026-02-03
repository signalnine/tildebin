#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [memory, ecc, edac, hardware, reliability]
#   requires: []
#   privilege: root
#   related: [memory_leak_detector, memory_reclaim_monitor]
#   brief: Detect and report memory errors (ECC/EDAC)

"""
Detect and report memory errors (ECC/EDAC) on baremetal systems.

Memory errors are a leading indicator of hardware failure. This script monitors:
- EDAC (Error Detection and Correction) subsystem
- Correctable and uncorrectable errors per DIMM
- Memory controller statistics
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_edac_available(context: Context) -> bool:
    """Check if EDAC subsystem is available."""
    return context.file_exists('/sys/devices/system/edac/mc')


def read_sysfs(context: Context, path: str) -> str | None:
    """Read a value from sysfs."""
    try:
        return context.read_file(path).strip()
    except (FileNotFoundError, PermissionError):
        return None


def read_sysfs_int(context: Context, path: str) -> int | None:
    """Read an integer value from sysfs."""
    val = read_sysfs(context, path)
    if val is not None:
        try:
            return int(val)
        except ValueError:
            pass
    return None


def get_memory_controllers(context: Context) -> list[str]:
    """Get list of memory controllers from EDAC."""
    mc_path = '/sys/devices/system/edac/mc'
    if not context.file_exists(mc_path):
        return []

    controllers = []
    try:
        entries = context.glob('mc*', mc_path)
        for entry in entries:
            import os
            controllers.append(os.path.basename(entry))
    except Exception:
        pass

    return sorted(controllers)


def get_mc_info(context: Context, mc: str) -> dict[str, Any]:
    """Get information about a memory controller."""
    mc_path = f'/sys/devices/system/edac/mc/{mc}'

    info = {
        'name': mc,
        'mc_name': read_sysfs(context, f'{mc_path}/mc_name'),
        'size_mb': read_sysfs(context, f'{mc_path}/size_mb'),
        'seconds_since_reset': read_sysfs_int(context, f'{mc_path}/seconds_since_reset'),
        'ue_count': read_sysfs_int(context, f'{mc_path}/ue_count'),
        'ue_noinfo_count': read_sysfs_int(context, f'{mc_path}/ue_noinfo_count'),
        'ce_count': read_sysfs_int(context, f'{mc_path}/ce_count'),
        'ce_noinfo_count': read_sysfs_int(context, f'{mc_path}/ce_noinfo_count'),
        'dimms': [],
    }

    # Get DIMM information (newer EDAC format)
    try:
        dimm_entries = context.glob('dimm*', mc_path)
        for dimm_path in dimm_entries:
            import os
            dimm_name = os.path.basename(dimm_path)
            dimm_info = {
                'name': dimm_name,
                'size': read_sysfs(context, f'{dimm_path}/size'),
                'dimm_label': read_sysfs(context, f'{dimm_path}/dimm_label'),
                'dimm_location': read_sysfs(context, f'{dimm_path}/dimm_location'),
                'dimm_mem_type': read_sysfs(context, f'{dimm_path}/dimm_mem_type'),
                'dimm_ce_count': read_sysfs_int(context, f'{dimm_path}/dimm_ce_count'),
                'dimm_ue_count': read_sysfs_int(context, f'{dimm_path}/dimm_ue_count'),
            }
            info['dimms'].append(dimm_info)
    except Exception:
        pass

    return info


def analyze_errors(mc_data: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze memory error data and generate report."""
    analysis = {
        'total_ce': 0,
        'total_ue': 0,
        'controllers_with_errors': [],
        'dimms_with_errors': [],
        'severity': 'ok',
        'recommendations': [],
    }

    for mc in mc_data:
        mc_ce = mc.get('ce_count') or 0
        mc_ue = mc.get('ue_count') or 0

        analysis['total_ce'] += mc_ce
        analysis['total_ue'] += mc_ue

        if mc_ce > 0 or mc_ue > 0:
            analysis['controllers_with_errors'].append({
                'name': mc['name'],
                'ce_count': mc_ce,
                'ue_count': mc_ue,
            })

        # Check DIMMs
        for dimm in mc.get('dimms', []):
            dimm_ce = dimm.get('dimm_ce_count') or 0
            dimm_ue = dimm.get('dimm_ue_count') or 0

            if dimm_ce > 0 or dimm_ue > 0:
                analysis['dimms_with_errors'].append({
                    'controller': mc['name'],
                    'dimm': dimm['name'],
                    'label': dimm.get('dimm_label') or dimm.get('dimm_location') or 'unknown',
                    'ce_count': dimm_ce,
                    'ue_count': dimm_ue,
                })

    # Determine severity
    if analysis['total_ue'] > 0:
        analysis['severity'] = 'critical'
        analysis['recommendations'].append(
            'CRITICAL: Uncorrectable memory errors detected. '
            'Schedule immediate DIMM replacement to prevent data corruption.'
        )
    elif analysis['total_ce'] > 100:
        analysis['severity'] = 'warning'
        analysis['recommendations'].append(
            'WARNING: High correctable error count (>100). '
            'This indicates DIMM degradation. Plan for replacement.'
        )
    elif analysis['total_ce'] > 0:
        analysis['severity'] = 'info'
        analysis['recommendations'].append(
            'INFO: Some correctable errors detected. '
            'Monitor for increasing error rates.'
        )

    return analysis


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no errors, 1 = errors detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Detect and report memory errors (ECC/EDAC)'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed DIMM and controller information')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Check EDAC availability
    if not check_edac_available(context):
        output.warning('EDAC subsystem not available')
        output.emit({
            'edac_available': False,
            'memory_controllers': [],
            'analysis': {'severity': 'unknown', 'total_ce': 0, 'total_ue': 0},
        })

        output.render(opts.format, "Detect and report memory errors (ECC/EDAC)")
        return 0  # Not an error - just no ECC support

    # Collect memory controller data
    controllers = get_memory_controllers(context)
    mc_data = [get_mc_info(context, mc) for mc in controllers]

    # Analyze errors
    analysis = analyze_errors(mc_data)

    # Build output
    data = {
        'edac_available': True,
        'summary': {
            'controller_count': len(mc_data),
            'total_ce': analysis['total_ce'],
            'total_ue': analysis['total_ue'],
            'severity': analysis['severity'],
        },
        'controllers_with_errors': analysis['controllers_with_errors'],
        'dimms_with_errors': analysis['dimms_with_errors'],
        'recommendations': analysis['recommendations'],
    }

    if opts.verbose:
        data['memory_controllers'] = mc_data

    output.emit(data)

    # Set summary
    if analysis['total_ue'] > 0 or analysis['total_ce'] > 0:
        output.set_summary(
            f"CE={analysis['total_ce']}, UE={analysis['total_ue']} "
            f"({analysis['severity']})"
        )
    else:
        output.set_summary('No memory errors detected')

    # Exit code based on findings
    if analysis['total_ue'] > 0 or analysis['total_ce'] > 0:

        output.render(opts.format, "Detect and report memory errors (ECC/EDAC)")
        return 1

    output.render(opts.format, "Detect and report memory errors (ECC/EDAC)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
