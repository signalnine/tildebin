#!/usr/bin/env python3
# boxctl:
#   category: baremetal/storage
#   tags: [storage, smart, disk, health, trend, prediction]
#   requires: [smartctl]
#   privilege: root
#   related: [disk_health, disk_life_predictor, ssd_wear, nvme_health]
#   brief: Analyze SMART attribute trends for early disk failure detection

"""
Analyze SMART attribute trends for early disk failure detection.

Goes beyond simple pass/fail SMART checks to examine critical attribute
raw values and proximity to thresholds. Key indicators of impending
failure include growing reallocated sector counts, pending sectors,
and attributes approaching their failure thresholds.

Uses smartctl JSON output for structured data parsing.

Exit codes:
    0 - All drives healthy
    1 - Concerning SMART trends detected
    2 - Error or smartctl not available
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Critical SMART attribute IDs and their significance
CRITICAL_ATTRS = {
    5: ('Reallocated_Sector_Ct', 0, 100),    # (name, warn_threshold, crit_threshold)
    197: ('Current_Pending_Sector', 0, None),  # Any non-zero is warning
    198: ('Offline_Uncorrectable', 0, None),   # Any non-zero is critical
}


def parse_scan_output(scan_json: str) -> list[dict[str, str]]:
    """Parse smartctl --scan --json output.

    Returns list of device dicts with 'name' and 'type' keys.
    """
    try:
        data = json.loads(scan_json)
    except (json.JSONDecodeError, TypeError):
        return []

    devices = data.get('devices', [])
    return [
        {'name': d.get('name', ''), 'type': d.get('type', '')}
        for d in devices
        if isinstance(d, dict) and d.get('name')
    ]


def parse_smart_attributes(attrs_json: str) -> list[dict[str, Any]]:
    """Parse smartctl -A --json output for SMART attribute table.

    Returns list of attribute dicts with id, name, value, worst, thresh, raw.
    """
    try:
        data = json.loads(attrs_json)
    except (json.JSONDecodeError, TypeError):
        return []

    table = data.get('ata_smart_attributes', {}).get('table', [])
    attrs = []
    for entry in table:
        if not isinstance(entry, dict):
            continue
        raw = entry.get('raw', {})
        raw_value = raw.get('value', 0) if isinstance(raw, dict) else 0
        attrs.append({
            'id': entry.get('id', 0),
            'name': entry.get('name', 'Unknown'),
            'value': entry.get('value', 0),
            'worst': entry.get('worst', 0),
            'thresh': entry.get('thresh', 0),
            'raw': raw_value,
        })
    return attrs


def analyze_drive(attrs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analyze SMART attributes for a single drive.

    Returns list of issues with severity, type, and message.
    """
    issues = []

    for attr in attrs:
        attr_id = attr['id']

        # Check critical attributes by raw value
        if attr_id in CRITICAL_ATTRS:
            name, warn_raw, crit_raw = CRITICAL_ATTRS[attr_id]

            if attr_id == 5:  # Reallocated_Sector_Ct
                if crit_raw is not None and attr['raw'] > crit_raw:
                    issues.append({
                        'severity': 'CRITICAL',
                        'type': f'{name}_critical',
                        'attribute': name,
                        'raw_value': attr['raw'],
                        'message': f"{name}: {attr['raw']} reallocated sectors (>100 is critical)",
                    })
                elif attr['raw'] > warn_raw:
                    issues.append({
                        'severity': 'WARNING',
                        'type': f'{name}_warning',
                        'attribute': name,
                        'raw_value': attr['raw'],
                        'message': f"{name}: {attr['raw']} reallocated sectors detected",
                    })

            elif attr_id == 197:  # Current_Pending_Sector
                if attr['raw'] > 0:
                    issues.append({
                        'severity': 'WARNING',
                        'type': 'pending_sectors',
                        'attribute': name,
                        'raw_value': attr['raw'],
                        'message': f"{name}: {attr['raw']} pending sectors awaiting reallocation",
                    })

            elif attr_id == 198:  # Offline_Uncorrectable
                if attr['raw'] > 0:
                    issues.append({
                        'severity': 'CRITICAL',
                        'type': 'uncorrectable_sectors',
                        'attribute': name,
                        'raw_value': attr['raw'],
                        'message': f"{name}: {attr['raw']} uncorrectable sectors",
                    })

        # Check value approaching threshold (within 10% of total range)
        value = attr['value']
        thresh = attr['thresh']
        if thresh > 0 and value > 0:
            margin = value - thresh
            total_range = 100  # SMART values are typically 0-100 or 0-253
            if 0 < margin <= (total_range * 0.10):
                issues.append({
                    'severity': 'WARNING',
                    'type': 'near_threshold',
                    'attribute': attr['name'],
                    'value': value,
                    'thresh': thresh,
                    'message': (
                        f"{attr['name']}: value {value} approaching "
                        f"threshold {thresh} (margin: {margin})"
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
        description="Analyze SMART attribute trends for early disk failure detection"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all attributes")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    if not context.check_tool('smartctl'):
        output.error("smartctl not found (install smartmontools)")
        output.render(opts.format, "SMART Trend Analysis")
        return 2

    # Scan for drives
    try:
        scan_result = context.run(['smartctl', '--scan', '--json'], check=True)
    except Exception as e:
        output.error(f"Failed to scan drives: {e}")
        output.render(opts.format, "SMART Trend Analysis")
        return 2

    devices = parse_scan_output(scan_result.stdout)
    if not devices:
        output.emit({'drives': [], 'issues': []})
        output.set_summary("no drives found")
        output.render(opts.format, "SMART Trend Analysis")
        return 0

    # Check each drive
    all_drives = []
    all_issues: list[dict[str, Any]] = []

    for device in devices:
        dev_name = device['name']
        try:
            attr_result = context.run(
                ['smartctl', '-A', dev_name, '--json'], check=True
            )
        except Exception:
            continue

        attrs = parse_smart_attributes(attr_result.stdout)
        drive_issues = analyze_drive(attrs)

        drive_data: dict[str, Any] = {
            'device': dev_name,
            'issue_count': len(drive_issues),
            'issues': drive_issues,
        }
        if opts.verbose:
            drive_data['attributes'] = attrs

        all_drives.append(drive_data)
        for issue in drive_issues:
            issue['device'] = dev_name
            all_issues.append(issue)

    output.emit({'drives': all_drives, 'issues': all_issues})

    # Summary
    critical = sum(1 for i in all_issues if i['severity'] == 'CRITICAL')
    warning = sum(1 for i in all_issues if i['severity'] == 'WARNING')
    if critical > 0:
        output.set_summary(f"{len(devices)} drives, {critical} critical, {warning} warnings")
    elif warning > 0:
        output.set_summary(f"{len(devices)} drives, {warning} warnings")
    else:
        output.set_summary(f"{len(devices)} drives, all healthy")

    output.render(opts.format, "SMART Trend Analysis")

    return 1 if (critical > 0 or warning > 0) else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
