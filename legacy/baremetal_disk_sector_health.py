#!/usr/bin/env python3
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

Useful for:
- Early warning of disk degradation before data loss
- Proactive disk replacement in large fleets
- Compliance with SLA requirements for hardware health
- Maintenance window planning

Exit codes:
    0 - All disks healthy (no sector issues)
    1 - Sector issues detected (warnings or critical)
    2 - Missing dependency or usage error
"""

import argparse
import json
import subprocess
import sys
from typing import Dict, List, Optional, Tuple


# SMART attribute IDs for sector health
REALLOCATED_SECTOR_COUNT = 5
CURRENT_PENDING_SECTOR = 197
UNCORRECTABLE_SECTOR_COUNT = 198
REPORTED_UNCORRECT = 187  # Alternative name on some drives

# Thresholds for severity (any non-zero is concerning, but we escalate)
THRESHOLDS = {
    'warning': {
        REALLOCATED_SECTOR_COUNT: 1,
        CURRENT_PENDING_SECTOR: 1,
        UNCORRECTABLE_SECTOR_COUNT: 1,
    },
    'critical': {
        REALLOCATED_SECTOR_COUNT: 50,
        CURRENT_PENDING_SECTOR: 10,
        UNCORRECTABLE_SECTOR_COUNT: 10,
    }
}


def run_command(cmd: List[str]) -> Tuple[int, str, str]:
    """Execute a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def check_smartctl_available() -> bool:
    """Check if smartctl is available."""
    returncode, _, _ = run_command(['which', 'smartctl'])
    return returncode == 0


def get_disk_list() -> List[str]:
    """Get list of disks from smartctl --scan."""
    returncode, stdout, _ = run_command(['smartctl', '--scan'])
    if returncode != 0:
        return []

    disks = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue
        # Format: /dev/sda -d sat # /dev/sda, ATA device
        parts = line.split()
        if parts:
            disks.append(parts[0])
    return disks


def parse_smart_attributes(stdout: str) -> Dict[int, int]:
    """Parse SMART attributes from smartctl -A output.

    Returns dict mapping attribute ID to raw value.
    """
    attributes = {}

    in_attributes = False
    for line in stdout.split('\n'):
        # Look for attribute table header
        if 'ID#' in line and 'ATTRIBUTE_NAME' in line:
            in_attributes = True
            continue

        if not in_attributes:
            continue

        # Skip empty lines
        if not line.strip():
            continue

        # Parse attribute line
        # Format: ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
        parts = line.split()
        if len(parts) >= 10:
            try:
                attr_id = int(parts[0])
                # Raw value is the last column, may contain additional info
                raw_str = parts[9]
                # Handle formats like "0" or "0/0/0" or "0 (Min/Max 0/0)"
                raw_value = int(raw_str.split('/')[0].split()[0])
                attributes[attr_id] = raw_value
            except (ValueError, IndexError):
                continue

    return attributes


def parse_nvme_smart(stdout: str) -> Dict[str, int]:
    """Parse NVMe SMART data from smartctl output.

    Returns dict with nvme-specific health metrics.
    """
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


def analyze_disk(device: str) -> Dict:
    """Analyze a single disk for sector health issues.

    Returns dict with disk info and any issues found.
    """
    result = {
        'device': device,
        'type': 'unknown',
        'model': 'unknown',
        'serial': 'unknown',
        'healthy': True,
        'issues': [],
        'attributes': {}
    }

    # Get disk info and SMART data
    returncode, stdout, stderr = run_command(['smartctl', '-i', '-A', '-H', device])

    if returncode != 0 and 'No such device' in stderr:
        result['issues'].append({
            'severity': 'ERROR',
            'message': 'Device not found or not accessible'
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
    if 'SMART overall-health self-assessment test result: PASSED' in stdout:
        pass  # Good
    elif 'SMART overall-health self-assessment test result: FAILED' in stdout:
        result['issues'].append({
            'severity': 'CRITICAL',
            'message': 'SMART self-assessment FAILED - imminent drive failure'
        })
        result['healthy'] = False

    # Handle NVMe vs SATA/SAS
    if result['type'] == 'nvme' or '/dev/nvme' in device:
        result['type'] = 'nvme'
        nvme_data = parse_nvme_smart(stdout)
        result['attributes'] = nvme_data

        # Check NVMe health metrics
        if 'media_errors' in nvme_data and nvme_data['media_errors'] > 0:
            severity = 'CRITICAL' if nvme_data['media_errors'] > 10 else 'WARNING'
            result['issues'].append({
                'severity': severity,
                'attribute': 'media_errors',
                'value': nvme_data['media_errors'],
                'message': f"Media/data integrity errors: {nvme_data['media_errors']}"
            })
            result['healthy'] = False

        if 'available_spare' in nvme_data and nvme_data['available_spare'] < 10:
            result['issues'].append({
                'severity': 'CRITICAL',
                'attribute': 'available_spare',
                'value': nvme_data['available_spare'],
                'message': f"Available spare below 10%: {nvme_data['available_spare']}%"
            })
            result['healthy'] = False
        elif 'available_spare' in nvme_data and nvme_data['available_spare'] < 20:
            result['issues'].append({
                'severity': 'WARNING',
                'attribute': 'available_spare',
                'value': nvme_data['available_spare'],
                'message': f"Available spare below 20%: {nvme_data['available_spare']}%"
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
                    # Determine severity
                    critical_threshold = THRESHOLDS['critical'].get(attr_id, 10)
                    if value >= critical_threshold:
                        severity = 'CRITICAL'
                    else:
                        severity = 'WARNING'

                    result['issues'].append({
                        'severity': severity,
                        'attribute': attr_name,
                        'attribute_id': attr_id,
                        'value': value,
                        'message': f"{attr_name} (ID {attr_id}): {value}"
                    })
                    result['healthy'] = False

    return result


def output_plain(results: List[Dict], warn_only: bool = False, verbose: bool = False):
    """Output results in plain text format."""
    if not warn_only:
        print("Disk Sector Health Report")
        print("=" * 60)
        print()

    has_issues = False

    for disk in results:
        if warn_only and disk['healthy']:
            continue

        if not warn_only or verbose:
            print(f"Device: {disk['device']}")
            print(f"  Type: {disk['type']}")
            print(f"  Model: {disk['model']}")
            if verbose:
                print(f"  Serial: {disk['serial']}")

        if disk['issues']:
            has_issues = True
            for issue in disk['issues']:
                print(f"  [{issue['severity']}] {issue['message']}")
        elif not warn_only:
            print("  Status: HEALTHY")

        if not warn_only:
            print()

    if not has_issues and not warn_only:
        print("All disks healthy - no sector issues detected")


def output_table(results: List[Dict], warn_only: bool = False):
    """Output results in table format."""
    print(f"{'Device':<12} {'Type':<6} {'Model':<25} {'Status':<10} {'Issues':<30}")
    print("-" * 85)

    for disk in results:
        if warn_only and disk['healthy']:
            continue

        status = "HEALTHY" if disk['healthy'] else "ISSUES"
        model = disk['model'][:24] if disk['model'] else 'unknown'

        if disk['issues']:
            # Show first issue
            first_issue = disk['issues'][0]
            issue_str = f"[{first_issue['severity']}] {first_issue.get('attribute', first_issue['message'][:20])}"
        else:
            issue_str = "-"

        print(f"{disk['device']:<12} {disk['type']:<6} {model:<25} {status:<10} {issue_str:<30}")

        # Show additional issues
        for issue in disk['issues'][1:]:
            issue_str = f"[{issue['severity']}] {issue.get('attribute', issue['message'][:20])}"
            print(f"{'':<12} {'':<6} {'':<25} {'':<10} {issue_str:<30}")


def output_json(results: List[Dict], warn_only: bool = False):
    """Output results in JSON format."""
    if warn_only:
        results = [d for d in results if not d['healthy']]

    output = {
        'disks': results,
        'summary': {
            'total': len(results),
            'healthy': sum(1 for d in results if d['healthy']),
            'issues': sum(1 for d in results if not d['healthy'])
        }
    }
    print(json.dumps(output, indent=2))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor disk sector health metrics to predict disk failure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Key SMART attributes monitored:
  - Reallocated Sector Count (ID 5): Bad sectors remapped
  - Current Pending Sector (ID 197): Sectors awaiting reallocation
  - Uncorrectable Sector Count (ID 198): Unreadable sectors

For NVMe:
  - Media and Data Integrity Errors
  - Available Spare percentage

Examples:
  %(prog)s                    # Check all disks
  %(prog)s -d /dev/sda        # Check specific disk
  %(prog)s --format json      # JSON output
  %(prog)s --warn-only        # Only show disks with issues

Exit codes:
  0 - All disks healthy
  1 - Sector issues detected
  2 - Missing dependency (smartctl)
"""
    )

    parser.add_argument(
        "-d", "--device",
        help="Check specific device only (e.g., /dev/sda)"
    )

    parser.add_argument(
        "-f", "--format",
        choices=["plain", "table", "json"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show disks with issues"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )

    args = parser.parse_args()

    # Check for smartctl
    if not check_smartctl_available():
        print("Error: smartctl not found in PATH", file=sys.stderr)
        print("Install smartmontools: sudo apt-get install smartmontools", file=sys.stderr)
        sys.exit(2)

    # Get disks to check
    if args.device:
        disks = [args.device]
    else:
        disks = get_disk_list()
        if not disks:
            print("No disks found by smartctl --scan", file=sys.stderr)
            sys.exit(1)

    # Analyze each disk
    results = []
    for disk in disks:
        result = analyze_disk(disk)
        results.append(result)

    # Output results
    if args.format == 'json':
        output_json(results, args.warn_only)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.warn_only, args.verbose)

    # Exit code based on findings
    has_issues = any(not d['healthy'] for d in results)
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
