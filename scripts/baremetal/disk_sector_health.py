#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage, sectors, hardware]
#   requires: [smartctl]
#   privilege: root
#   related: [disk_health, ssd_wear, disk_life_predictor]
#   brief: Monitor disk sector health metrics to predict disk failure

"""
Monitor disk sector health metrics to predict imminent disk failure.

Focuses on the SMART attributes most predictive of disk failure:
- Reallocated Sector Count (ID 5): Bad sectors remapped to spare areas
- Current Pending Sector Count (ID 197): Unstable sectors awaiting reallocation
- Uncorrectable Sector Count (ID 198): Sectors that couldn't be read/written

These three attributes are the strongest predictors of imminent disk failure.
Even a single reallocated or pending sector warrants attention.

For NVMe drives, monitors:
- Media and Data Integrity Errors
- Available Spare percentage

Returns exit code 1 if sector issues are detected.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# SMART attribute IDs for sector health
REALLOCATED_SECTOR_COUNT = 5
CURRENT_PENDING_SECTOR = 197
UNCORRECTABLE_SECTOR_COUNT = 198
REPORTED_UNCORRECT = 187

# Thresholds for severity
THRESHOLDS = {
    'critical': {
        REALLOCATED_SECTOR_COUNT: 50,
        CURRENT_PENDING_SECTOR: 10,
        UNCORRECTABLE_SECTOR_COUNT: 10,
    }
}


def get_disk_list(context: Context) -> list[str]:
    """Get list of disks from smartctl --scan."""
    result = context.run(['smartctl', '--scan'], check=False)
    if result.returncode != 0:
        return []

    disks = []
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if parts:
            disks.append(parts[0])
    return disks


def parse_smart_attributes(stdout: str) -> dict[int, int]:
    """Parse SMART attributes from smartctl -A output."""
    attributes = {}

    in_attributes = False
    for line in stdout.split('\n'):
        if 'ID#' in line and 'ATTRIBUTE_NAME' in line:
            in_attributes = True
            continue

        if not in_attributes:
            continue

        if not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 10:
            try:
                attr_id = int(parts[0])
                raw_str = parts[9]
                raw_value = int(raw_str.split('/')[0].split()[0])
                attributes[attr_id] = raw_value
            except (ValueError, IndexError):
                continue

    return attributes


def parse_nvme_smart(stdout: str) -> dict[str, int]:
    """Parse NVMe SMART data from smartctl output."""
    data = {}

    for line in stdout.split('\n'):
        line = line.strip()
        if 'Media and Data Integrity Errors:' in line:
            try:
                data['media_errors'] = int(line.split(':')[1].strip().replace(',', ''))
            except (ValueError, IndexError):
                pass
        elif 'Available Spare:' in line and 'Threshold' not in line:
            try:
                value = line.split(':')[1].strip().rstrip('%')
                data['available_spare'] = int(value)
            except (ValueError, IndexError):
                pass
        elif 'Percentage Used:' in line:
            try:
                value = line.split(':')[1].strip().rstrip('%')
                data['percentage_used'] = int(value)
            except (ValueError, IndexError):
                pass

    return data


def analyze_disk(device: str, context: Context) -> dict[str, Any]:
    """Analyze a single disk for sector health issues."""
    result = {
        'device': device,
        'type': 'unknown',
        'model': 'unknown',
        'serial': 'unknown',
        'healthy': True,
        'issues': [],
        'attributes': {},
    }

    # Get disk info and SMART data
    cmd_result = context.run(['smartctl', '-i', '-A', '-H', device], check=False)
    stdout = cmd_result.stdout

    if cmd_result.returncode != 0 and 'No such device' in cmd_result.stderr:
        result['issues'].append({
            'severity': 'ERROR',
            'message': 'Device not found or not accessible',
        })
        result['healthy'] = False
        return result

    # Parse model and serial
    for line in stdout.split('\n'):
        if 'Device Model:' in line or 'Model Number:' in line:
            result['model'] = line.split(':', 1)[1].strip()
        elif 'Serial Number:' in line or 'Serial number:' in line:
            result['serial'] = line.split(':', 1)[1].strip()
        elif 'Rotation Rate:' in line:
            if 'Solid State' in line:
                result['type'] = 'ssd'
            else:
                result['type'] = 'hdd'
        elif 'NVMe Version:' in line or '/dev/nvme' in device:
            result['type'] = 'nvme'

    # Check overall SMART status
    if 'SMART overall-health self-assessment test result: FAILED' in stdout:
        result['issues'].append({
            'severity': 'CRITICAL',
            'message': 'SMART self-assessment FAILED - imminent drive failure',
        })
        result['healthy'] = False

    # Handle NVMe vs SATA/SAS
    if result['type'] == 'nvme' or '/dev/nvme' in device:
        result['type'] = 'nvme'
        nvme_data = parse_nvme_smart(stdout)
        result['attributes'] = nvme_data

        if 'media_errors' in nvme_data and nvme_data['media_errors'] > 0:
            severity = 'CRITICAL' if nvme_data['media_errors'] > 10 else 'WARNING'
            result['issues'].append({
                'severity': severity,
                'attribute': 'media_errors',
                'value': nvme_data['media_errors'],
                'message': f"Media/data integrity errors: {nvme_data['media_errors']}",
            })
            result['healthy'] = False

        if 'available_spare' in nvme_data and nvme_data['available_spare'] < 10:
            result['issues'].append({
                'severity': 'CRITICAL',
                'attribute': 'available_spare',
                'value': nvme_data['available_spare'],
                'message': f"Available spare below 10%: {nvme_data['available_spare']}%",
            })
            result['healthy'] = False
        elif 'available_spare' in nvme_data and nvme_data['available_spare'] < 20:
            result['issues'].append({
                'severity': 'WARNING',
                'attribute': 'available_spare',
                'value': nvme_data['available_spare'],
                'message': f"Available spare below 20%: {nvme_data['available_spare']}%",
            })
    else:
        # SATA/SAS drive - parse SMART attributes
        attributes = parse_smart_attributes(stdout)
        result['attributes'] = attributes

        # Check critical sector health attributes
        sector_attrs = [
            (REALLOCATED_SECTOR_COUNT, 'Reallocated_Sector_Ct'),
            (CURRENT_PENDING_SECTOR, 'Current_Pending_Sector'),
            (UNCORRECTABLE_SECTOR_COUNT, 'Offline_Uncorrectable'),
            (REPORTED_UNCORRECT, 'Reported_Uncorrect'),
        ]

        for attr_id, attr_name in sector_attrs:
            if attr_id in attributes:
                value = attributes[attr_id]
                if value > 0:
                    critical_threshold = THRESHOLDS['critical'].get(attr_id, 10)
                    severity = 'CRITICAL' if value >= critical_threshold else 'WARNING'

                    result['issues'].append({
                        'severity': severity,
                        'attribute': attr_name,
                        'attribute_id': attr_id,
                        'value': value,
                        'message': f"{attr_name} (ID {attr_id}): {value}",
                    })
                    result['healthy'] = False

    return result


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor disk sector health metrics")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-d", "--device", help="Check specific device only")
    opts = parser.parse_args(args)

    # Check for smartctl
    if not context.check_tool('smartctl'):
        output.error("smartctl not found. Install smartmontools package.")

        output.render(opts.format, "Monitor disk sector health metrics to predict disk failure")
        return 2

    # Get disks to check
    if opts.device:
        disks = [opts.device]
    else:
        disks = get_disk_list(context)
        if not disks:
            output.error("No disks found by smartctl --scan")
            return 2

    # Analyze each disk
    results = []
    for disk in disks:
        result = analyze_disk(disk, context)
        results.append(result)

    # Build output data
    healthy_count = sum(1 for d in results if d['healthy'])
    issues_count = sum(1 for d in results if not d['healthy'])

    data = {
        'disks': results,
        'summary': {
            'total': len(results),
            'healthy': healthy_count,
            'issues': issues_count,
        },
    }

    if not opts.verbose:
        # Simplify output in non-verbose mode
        for disk in data['disks']:
            disk.pop('serial', None)
            disk['attributes'] = {}

    output.emit(data)

    # Generate summary
    if issues_count > 0:
        output.set_summary(f"{issues_count}/{len(results)} disks with sector issues")
    else:
        output.set_summary(f"{len(results)} disks healthy")

    output.render(opts.format, "Monitor disk sector health metrics to predict disk failure")

    return 1 if issues_count > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
