#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [storage, dm-integrity, dm-verity, integrity, security]
#   requires: [dmsetup]
#   privilege: root
#   related: [disk_encryption, file_integrity, lvm_health]
#   brief: Monitor dm-integrity and dm-verity device status

"""
Monitor dm-integrity and dm-verity device status.

Checks device-mapper integrity and verity targets for corruption
or mismatch events. dm-integrity provides sector-level data integrity
and dm-verity provides read-only verified boot filesystem support.

Exit codes:
    0 - All integrity/verity devices healthy or none found
    1 - Integrity mismatches or verity corruption detected
    2 - Error or dmsetup not available
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_dm_table(table_output: str) -> list[dict[str, str]]:
    """Parse dmsetup table output for integrity/verity targets.

    Format: 'device_name: start length target_type args...'
    Returns list of devices with name, target_type.
    """
    devices = []
    for line in table_output.strip().split('\n'):
        line = line.strip()
        if not line:
            continue

        # Parse 'name: start length target_type ...'
        if ':' not in line:
            continue

        name, _, rest = line.partition(':')
        name = name.strip()
        parts = rest.strip().split()

        if len(parts) < 3:
            continue

        target_type = parts[2]  # start length target_type
        if target_type in ('integrity', 'verity'):
            devices.append({
                'name': name,
                'target_type': target_type,
            })

    return devices


def parse_integrity_status(status_line: str) -> dict[str, Any]:
    """Parse dmsetup status for an integrity target.

    Example: 'data-integrity: 0 1048576 integrity 5 mismatches'
    """
    result: dict[str, Any] = {'mismatches': 0}

    match = re.search(r'(\d+)\s+mismatches?', status_line)
    if match:
        result['mismatches'] = int(match.group(1))

    return result


def parse_verity_status(status_line: str) -> dict[str, Any]:
    """Parse dmsetup status for a verity target.

    Status contains 'V' for verified or 'C' for corrupted.
    Example: 'root-verity: 0 2097152 verity V'
    """
    result: dict[str, Any] = {'corrupted': False, 'verified': False}

    # Look for V (verified) or C (corrupted) after the verity target type
    if re.search(r'verity\s+C', status_line):
        result['corrupted'] = True
    elif re.search(r'verity\s+V', status_line):
        result['verified'] = True

    return result


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
        description="Monitor dm-integrity and dm-verity device status"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show device details")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    if not context.check_tool('dmsetup'):
        output.error("dmsetup not found (install device-mapper)")
        output.render(opts.format, "dm-integrity/dm-verity Status")
        return 2

    # Get device-mapper table
    try:
        table_result = context.run(['dmsetup', 'table'], check=True)
    except Exception as e:
        output.error(f"Failed to run dmsetup table: {e}")
        output.render(opts.format, "dm-integrity/dm-verity Status")
        return 2

    devices = parse_dm_table(table_result.stdout)

    if not devices:
        output.emit({'devices': [], 'issues': []})
        output.set_summary("no integrity/verity devices found")
        output.render(opts.format, "dm-integrity/dm-verity Status")
        return 0

    # Check status of each device
    issues: list[dict[str, Any]] = []
    device_details = []

    for device in devices:
        dev_name = device['name']
        try:
            status_result = context.run(
                ['dmsetup', 'status', dev_name], check=True
            )
        except Exception:
            continue

        status_line = status_result.stdout.strip()
        detail: dict[str, Any] = {
            'name': dev_name,
            'target_type': device['target_type'],
        }

        if device['target_type'] == 'integrity':
            parsed = parse_integrity_status(status_line)
            detail['mismatches'] = parsed['mismatches']
            if parsed['mismatches'] > 0:
                issues.append({
                    'severity': 'CRITICAL',
                    'type': 'integrity_mismatch',
                    'device': dev_name,
                    'mismatches': parsed['mismatches'],
                    'message': f"{dev_name}: {parsed['mismatches']} integrity mismatches detected",
                })

        elif device['target_type'] == 'verity':
            parsed = parse_verity_status(status_line)
            detail['corrupted'] = parsed['corrupted']
            detail['verified'] = parsed['verified']
            if parsed['corrupted']:
                issues.append({
                    'severity': 'CRITICAL',
                    'type': 'verity_corruption',
                    'device': dev_name,
                    'message': f"{dev_name}: dm-verity corruption detected",
                })

        device_details.append(detail)

    output.emit({'devices': device_details, 'issues': issues})

    # Summary
    if issues:
        output.set_summary(f"{len(issues)} issues across {len(devices)} devices")
    else:
        output.set_summary(f"{len(devices)} devices, all healthy")

    output.render(opts.format, "dm-integrity/dm-verity Status")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
