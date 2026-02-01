#!/usr/bin/env python3
"""
Detect and report memory errors (ECC/EDAC) on baremetal systems.

Memory errors are a leading indicator of hardware failure. This script monitors:
- EDAC (Error Detection and Correction) subsystem for correctable/uncorrectable errors
- MCE (Machine Check Exception) logs for hardware-reported memory issues
- DIMM-level error tracking to identify failing memory modules

In large baremetal environments, catching memory errors early allows proactive
DIMM replacement before the errors cascade into system crashes or data corruption.

Key metrics:
- Correctable Errors (CE): Single-bit errors that ECC can fix. High counts
  indicate DIMM degradation and predict future uncorrectable errors.
- Uncorrectable Errors (UE): Multi-bit errors that ECC cannot fix. These often
  cause system crashes or data corruption.

Exit codes:
    0 - No memory errors detected (or no EDAC support)
    1 - Memory errors detected
    2 - Usage error or missing permissions
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional


def check_edac_available() -> bool:
    """Check if EDAC subsystem is available."""
    return os.path.isdir('/sys/devices/system/edac/mc')


def read_sysfs(path: str) -> Optional[str]:
    """Read a value from sysfs."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError, PermissionError):
        return None


def read_sysfs_int(path: str) -> Optional[int]:
    """Read an integer value from sysfs."""
    val = read_sysfs(path)
    if val is not None:
        try:
            return int(val)
        except ValueError:
            pass
    return None


def get_memory_controllers() -> List[str]:
    """Get list of memory controllers from EDAC."""
    mc_path = '/sys/devices/system/edac/mc'
    if not os.path.isdir(mc_path):
        return []

    controllers = []
    try:
        for entry in os.listdir(mc_path):
            if entry.startswith('mc'):
                controllers.append(entry)
    except OSError:
        pass

    return sorted(controllers)


def get_mc_info(mc: str) -> Dict[str, Any]:
    """Get information about a memory controller."""
    mc_path = f'/sys/devices/system/edac/mc/{mc}'

    info = {
        'name': mc,
        'mc_name': read_sysfs(f'{mc_path}/mc_name'),
        'size_mb': read_sysfs(f'{mc_path}/size_mb'),
        'seconds_since_reset': read_sysfs_int(f'{mc_path}/seconds_since_reset'),
        'ue_count': read_sysfs_int(f'{mc_path}/ue_count'),
        'ue_noinfo_count': read_sysfs_int(f'{mc_path}/ue_noinfo_count'),
        'ce_count': read_sysfs_int(f'{mc_path}/ce_count'),
        'ce_noinfo_count': read_sysfs_int(f'{mc_path}/ce_noinfo_count'),
        'csrows': [],
        'dimms': [],
    }

    # Get CSROW (Chip Select Row) information
    try:
        for entry in os.listdir(mc_path):
            if entry.startswith('csrow'):
                csrow_info = get_csrow_info(mc_path, entry)
                if csrow_info:
                    info['csrows'].append(csrow_info)
    except OSError:
        pass

    # Get DIMM information (newer EDAC format)
    try:
        for entry in os.listdir(mc_path):
            if entry.startswith('dimm'):
                dimm_info = get_dimm_info(mc_path, entry)
                if dimm_info:
                    info['dimms'].append(dimm_info)
    except OSError:
        pass

    return info


def get_csrow_info(mc_path: str, csrow: str) -> Optional[Dict[str, Any]]:
    """Get information about a CSROW."""
    csrow_path = f'{mc_path}/{csrow}'

    if not os.path.isdir(csrow_path):
        return None

    info = {
        'name': csrow,
        'size_mb': read_sysfs(f'{csrow_path}/size_mb'),
        'mem_type': read_sysfs(f'{csrow_path}/mem_type'),
        'edac_mode': read_sysfs(f'{csrow_path}/edac_mode'),
        'ue_count': read_sysfs_int(f'{csrow_path}/ue_count'),
        'ce_count': read_sysfs_int(f'{csrow_path}/ce_count'),
        'channels': [],
    }

    # Get channel information
    try:
        for entry in os.listdir(csrow_path):
            if entry.startswith('ch'):
                ch_path = f'{csrow_path}/{entry}'
                ch_info = {
                    'name': entry,
                    'ce_count': read_sysfs_int(f'{ch_path}/ce_count'),
                    'dimm_label': read_sysfs(f'{ch_path}/dimm_label'),
                }
                info['channels'].append(ch_info)
    except OSError:
        pass

    return info


def get_dimm_info(mc_path: str, dimm: str) -> Optional[Dict[str, Any]]:
    """Get information about a DIMM."""
    dimm_path = f'{mc_path}/{dimm}'

    if not os.path.isdir(dimm_path):
        return None

    info = {
        'name': dimm,
        'size': read_sysfs(f'{dimm_path}/size'),
        'dimm_label': read_sysfs(f'{dimm_path}/dimm_label'),
        'dimm_location': read_sysfs(f'{dimm_path}/dimm_location'),
        'dimm_mem_type': read_sysfs(f'{dimm_path}/dimm_mem_type'),
        'dimm_dev_type': read_sysfs(f'{dimm_path}/dimm_dev_type'),
        'dimm_edac_mode': read_sysfs(f'{dimm_path}/dimm_edac_mode'),
        'dimm_ce_count': read_sysfs_int(f'{dimm_path}/dimm_ce_count'),
        'dimm_ue_count': read_sysfs_int(f'{dimm_path}/dimm_ue_count'),
    }

    return info


def check_mcelog() -> List[Dict[str, Any]]:
    """Check for recent MCE (Machine Check Exception) events related to memory."""
    mce_events = []

    # Try reading from /var/log/mcelog
    mcelog_paths = ['/var/log/mcelog', '/var/log/mcelog.log']

    for mcelog_path in mcelog_paths:
        if os.path.exists(mcelog_path):
            try:
                with open(mcelog_path, 'r') as f:
                    content = f.read()

                # Parse MCE events (simplified parsing)
                # Look for memory-related MCE events
                if 'MEMORY' in content or 'memory' in content:
                    mce_events.append({
                        'source': mcelog_path,
                        'has_memory_events': True,
                        'content_preview': content[:500] if content else '',
                    })
            except (OSError, PermissionError):
                pass

    # Try checking dmesg for EDAC/MCE messages
    dmesg_errors = check_dmesg_memory_errors()
    if dmesg_errors:
        mce_events.extend(dmesg_errors)

    return mce_events


def check_dmesg_memory_errors() -> List[Dict[str, Any]]:
    """Check dmesg for memory-related errors."""
    errors = []

    # Try to read from /var/log/dmesg or kernel ring buffer file
    dmesg_paths = [
        '/var/log/dmesg',
        '/var/log/kern.log',
    ]

    for dmesg_path in dmesg_paths:
        if os.path.exists(dmesg_path):
            try:
                with open(dmesg_path, 'r') as f:
                    for line in f:
                        line_lower = line.lower()
                        if any(x in line_lower for x in ['edac', 'mce:', 'memory error',
                                                          'dimm', 'ecc', 'ce error',
                                                          'ue error', 'corrected error']):
                            errors.append({
                                'source': dmesg_path,
                                'message': line.strip(),
                            })
            except (OSError, PermissionError):
                pass

    return errors


def analyze_errors(mc_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze memory error data and generate report."""
    analysis = {
        'total_ce': 0,
        'total_ue': 0,
        'controllers_with_errors': [],
        'dimms_with_errors': [],
        'csrows_with_errors': [],
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

        # Check CSROWs
        for csrow in mc.get('csrows', []):
            csrow_ce = csrow.get('ce_count') or 0
            csrow_ue = csrow.get('ue_count') or 0

            if csrow_ce > 0 or csrow_ue > 0:
                analysis['csrows_with_errors'].append({
                    'controller': mc['name'],
                    'csrow': csrow['name'],
                    'ce_count': csrow_ce,
                    'ue_count': csrow_ue,
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


def output_plain(mc_data: List[Dict[str, Any]], analysis: Dict[str, Any],
                 mce_events: List[Dict[str, Any]], verbose: bool, warn_only: bool) -> None:
    """Output results in plain text format."""
    if warn_only and analysis['severity'] == 'ok':
        return

    print("Memory Error Detector (EDAC)")
    print("=" * 70)
    print()

    if not mc_data:
        print("No EDAC memory controllers found.")
        print()
        print("Possible reasons:")
        print("  - System does not support ECC memory")
        print("  - EDAC kernel modules not loaded (try: modprobe edac_core)")
        print("  - Running in a VM without memory error emulation")
        return

    # Summary
    print(f"Memory Controllers: {len(mc_data)}")
    print(f"Total Correctable Errors: {analysis['total_ce']}")
    print(f"Total Uncorrectable Errors: {analysis['total_ue']}")
    print(f"Status: {analysis['severity'].upper()}")
    print()

    # Show errors by controller
    if analysis['controllers_with_errors']:
        print("Controllers with Errors:")
        for mc in analysis['controllers_with_errors']:
            print(f"  {mc['name']}: CE={mc['ce_count']}, UE={mc['ue_count']}")
        print()

    # Show errors by DIMM
    if analysis['dimms_with_errors']:
        print("DIMMs with Errors:")
        for dimm in analysis['dimms_with_errors']:
            print(f"  {dimm['controller']}/{dimm['dimm']} ({dimm['label']}): "
                  f"CE={dimm['ce_count']}, UE={dimm['ue_count']}")
        print()

    # Show MCE events
    if mce_events:
        print("MCE/Dmesg Memory Events:")
        for event in mce_events[:5]:  # Limit output
            if 'message' in event:
                print(f"  {event['source']}: {event['message'][:80]}")
            elif 'has_memory_events' in event:
                print(f"  {event['source']}: Memory events found in log")
        print()

    # Recommendations
    if analysis['recommendations']:
        print("Recommendations:")
        for rec in analysis['recommendations']:
            print(f"  - {rec}")
        print()

    # Verbose output
    if verbose and not warn_only:
        print("Detailed Controller Information:")
        print("-" * 70)
        for mc in mc_data:
            print(f"\n{mc['name']}: {mc.get('mc_name') or 'Unknown'}")
            print(f"  Size: {mc.get('size_mb') or 'N/A'} MB")
            print(f"  Uptime: {mc.get('seconds_since_reset') or 'N/A'} seconds")
            print(f"  CE: {mc.get('ce_count') or 0}, UE: {mc.get('ue_count') or 0}")

            for dimm in mc.get('dimms', []):
                label = dimm.get('dimm_label') or dimm.get('dimm_location') or 'unlabeled'
                print(f"    {dimm['name']} ({label}): "
                      f"{dimm.get('size') or 'N/A'}, "
                      f"CE={dimm.get('dimm_ce_count') or 0}, "
                      f"UE={dimm.get('dimm_ue_count') or 0}")


def output_json(mc_data: List[Dict[str, Any]], analysis: Dict[str, Any],
                mce_events: List[Dict[str, Any]]) -> None:
    """Output results in JSON format."""
    result = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'controller_count': len(mc_data),
            'total_ce': analysis['total_ce'],
            'total_ue': analysis['total_ue'],
            'severity': analysis['severity'],
        },
        'analysis': analysis,
        'memory_controllers': mc_data,
        'mce_events': mce_events,
    }
    print(json.dumps(result, indent=2))


def output_table(mc_data: List[Dict[str, Any]], analysis: Dict[str, Any],
                 warn_only: bool) -> None:
    """Output results in table format."""
    if warn_only and analysis['severity'] == 'ok':
        print("No memory errors detected")
        return

    print(f"{'Controller':<10} {'Type':<15} {'Size':<10} {'CE':<10} {'UE':<10} {'Status':<10}")
    print("=" * 70)

    for mc in mc_data:
        ce = mc.get('ce_count') or 0
        ue = mc.get('ue_count') or 0
        status = 'CRITICAL' if ue > 0 else ('WARNING' if ce > 100 else ('INFO' if ce > 0 else 'OK'))

        if warn_only and status == 'OK':
            continue

        mc_type = mc.get('mc_name') or 'Unknown'
        if len(mc_type) > 13:
            mc_type = mc_type[:13] + '..'
        size = mc.get('size_mb') or 'N/A'

        print(f"{mc['name']:<10} {mc_type:<15} {str(size):<10} {ce:<10} {ue:<10} {status:<10}")

    print()
    print(f"Total: CE={analysis['total_ce']}, UE={analysis['total_ue']}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Detect and report memory errors (ECC/EDAC) on baremetal systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Check for memory errors
  %(prog)s --format json          Output in JSON for monitoring
  %(prog)s -v                     Show detailed DIMM information
  %(prog)s -w                     Only show if errors detected

Understanding memory errors:
  Correctable (CE): Single-bit errors fixed by ECC. Safe but indicate wear.
  Uncorrectable (UE): Multi-bit errors. May cause crashes or data corruption.

Thresholds:
  OK:       0 errors
  INFO:     1-100 correctable errors
  WARNING:  >100 correctable errors (DIMM showing wear)
  CRITICAL: Any uncorrectable errors (replace DIMM immediately)

Exit codes:
  0 - No memory errors detected
  1 - Memory errors detected
  2 - Usage error or missing permissions
"""
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed DIMM and controller information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if errors detected'
    )

    parser.add_argument(
        '--check-mce',
        action='store_true',
        help='Also check MCE logs and dmesg for memory events'
    )

    args = parser.parse_args()

    # Check EDAC availability
    if not check_edac_available():
        if args.format == 'json':
            print(json.dumps({
                'error': 'EDAC not available',
                'memory_controllers': [],
                'analysis': {'severity': 'unknown', 'total_ce': 0, 'total_ue': 0},
            }, indent=2))
        else:
            print("EDAC subsystem not available", file=sys.stderr)
            print("Possible causes:", file=sys.stderr)
            print("  - System does not have ECC memory", file=sys.stderr)
            print("  - EDAC modules not loaded (try: modprobe edac_core)", file=sys.stderr)
            print("  - Running in a VM", file=sys.stderr)
        sys.exit(0)  # Not an error - just no ECC support

    # Collect memory controller data
    controllers = get_memory_controllers()
    mc_data = [get_mc_info(mc) for mc in controllers]

    # Check MCE logs if requested
    mce_events = []
    if args.check_mce:
        mce_events = check_mcelog()

    # Analyze errors
    analysis = analyze_errors(mc_data)

    # Output results
    if args.format == 'json':
        output_json(mc_data, analysis, mce_events)
    elif args.format == 'table':
        output_table(mc_data, analysis, args.warn_only)
    else:
        output_plain(mc_data, analysis, mce_events, args.verbose, args.warn_only)

    # Exit code based on findings
    if analysis['total_ue'] > 0 or analysis['total_ce'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
