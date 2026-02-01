#!/usr/bin/env python3
"""
Monitor disk lifecycle metrics for hardware refresh planning.

Tracks power-on hours, estimated age, and provides lifecycle predictions
based on SMART data. Useful for large-scale baremetal fleet management
to plan hardware refresh and avoid surprise failures.

Exit codes:
    0 - All disks healthy, no lifecycle concerns
    1 - Some disks approaching end-of-life or have lifecycle warnings
    2 - Missing dependency (smartctl not found)
"""

import argparse
import subprocess
import sys
import json
import re
from datetime import datetime, timedelta


def run_command(cmd):
    """Execute a command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def check_smartctl_available():
    """Check if smartctl is installed"""
    returncode, _, _ = run_command("which smartctl")
    return returncode == 0


def get_disk_list():
    """Get list of disk devices"""
    returncode, stdout, stderr = run_command(
        "lsblk -d -n -o NAME,TYPE | grep disk | awk '{print $1}'"
    )
    if returncode != 0:
        return []

    disks = [
        "/dev/{}".format(disk.strip())
        for disk in stdout.strip().split('\n')
        if disk.strip()
    ]
    return disks


def get_disk_info(disk):
    """Get basic disk information"""
    returncode, stdout, stderr = run_command(
        "lsblk -n -o SIZE,MODEL {} | head -1".format(disk)
    )

    if returncode != 0:
        return "N/A", "N/A"

    parts = stdout.strip().split(None, 1)
    size = parts[0] if len(parts) > 0 else "N/A"
    model = parts[1].strip() if len(parts) > 1 else "N/A"

    return size, model


def get_smart_info(disk):
    """Get SMART information including power-on hours and other lifecycle data"""
    returncode, stdout, stderr = run_command("smartctl -i -A {}".format(disk))

    info = {
        'power_on_hours': None,
        'power_cycle_count': None,
        'start_stop_count': None,
        'reallocated_sectors': None,
        'pending_sectors': None,
        'serial': None,
        'firmware': None,
        'rotation_rate': None,
        'form_factor': None,
        'smart_supported': True,
        'is_ssd': False,
        'wear_leveling': None,
        'media_wearout': None,
    }

    if "SMART support is: Unavailable" in stdout or "SMART support is: Disabled" in stdout:
        info['smart_supported'] = False
        return info

    # Parse serial number
    match = re.search(r'Serial Number:\s+(\S+)', stdout)
    if match:
        info['serial'] = match.group(1)

    # Parse firmware version
    match = re.search(r'Firmware Version:\s+(\S+)', stdout)
    if match:
        info['firmware'] = match.group(1)

    # Parse rotation rate (0 or Solid State = SSD)
    match = re.search(r'Rotation Rate:\s+(.+)', stdout)
    if match:
        rate = match.group(1).strip()
        info['rotation_rate'] = rate
        if 'Solid State' in rate or rate == '0':
            info['is_ssd'] = True

    # Parse form factor
    match = re.search(r'Form Factor:\s+(.+)', stdout)
    if match:
        info['form_factor'] = match.group(1).strip()

    # Parse SMART attributes
    # Power-On Hours (attribute 9)
    match = re.search(r'^\s*9\s+Power_On_Hours\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', stdout, re.MULTILINE)
    if match:
        info['power_on_hours'] = int(match.group(1))

    # Power Cycle Count (attribute 12)
    match = re.search(r'^\s*12\s+Power_Cycle_Count\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', stdout, re.MULTILINE)
    if match:
        info['power_cycle_count'] = int(match.group(1))

    # Start/Stop Count (attribute 4)
    match = re.search(r'^\s*4\s+Start_Stop_Count\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', stdout, re.MULTILINE)
    if match:
        info['start_stop_count'] = int(match.group(1))

    # Reallocated Sectors (attribute 5)
    match = re.search(r'^\s*5\s+Reallocated_Sector_Ct\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', stdout, re.MULTILINE)
    if match:
        info['reallocated_sectors'] = int(match.group(1))

    # Current Pending Sectors (attribute 197)
    match = re.search(r'^\s*197\s+Current_Pending_Sector\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', stdout, re.MULTILINE)
    if match:
        info['pending_sectors'] = int(match.group(1))

    # SSD Wear Leveling Count (attribute 177)
    match = re.search(r'^\s*177\s+Wear_Leveling_Count\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', stdout, re.MULTILINE)
    if match:
        info['wear_leveling'] = int(match.group(1))
        info['is_ssd'] = True

    # Media Wearout Indicator (attribute 233)
    match = re.search(r'^\s*233\s+Media_Wearout_Indicator\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', stdout, re.MULTILINE)
    if match:
        info['media_wearout'] = int(match.group(1))
        info['is_ssd'] = True

    return info


def calculate_lifecycle_status(smart_info, warn_hours=35000, critical_hours=50000,
                                ssd_warn_hours=20000, ssd_critical_hours=40000):
    """
    Calculate lifecycle status and recommendations.

    Default thresholds:
    - HDD: 35,000 hours warning (4 years), 50,000 hours critical (~5.7 years)
    - SSD: 20,000 hours warning (~2.3 years), 40,000 hours critical (~4.6 years)
    """
    status = {
        'lifecycle_status': 'unknown',
        'estimated_age_years': None,
        'hours_remaining_estimate': None,
        'recommendation': None,
        'concerns': []
    }

    if not smart_info['smart_supported']:
        status['lifecycle_status'] = 'unknown'
        status['recommendation'] = 'SMART not available - manual inspection recommended'
        return status

    poh = smart_info.get('power_on_hours')
    if poh is None:
        status['lifecycle_status'] = 'unknown'
        status['recommendation'] = 'Power-on hours not available'
        return status

    # Calculate age in years (assuming 24/7 operation)
    hours_per_year = 8760
    status['estimated_age_years'] = round(poh / hours_per_year, 1)

    # Determine thresholds based on disk type
    is_ssd = smart_info.get('is_ssd', False)
    if is_ssd:
        warn_threshold = ssd_warn_hours
        critical_threshold = ssd_critical_hours
    else:
        warn_threshold = warn_hours
        critical_threshold = critical_hours

    # Determine lifecycle status
    if poh >= critical_threshold:
        status['lifecycle_status'] = 'critical'
        status['recommendation'] = 'Schedule immediate replacement'
        status['hours_remaining_estimate'] = 0
    elif poh >= warn_threshold:
        status['lifecycle_status'] = 'warning'
        status['hours_remaining_estimate'] = critical_threshold - poh
        status['recommendation'] = 'Plan replacement within {} months'.format(
            round(status['hours_remaining_estimate'] / 730)  # ~730 hours per month
        )
    else:
        status['lifecycle_status'] = 'healthy'
        status['hours_remaining_estimate'] = warn_threshold - poh
        status['recommendation'] = 'No action needed'

    # Check for additional concerns
    if smart_info.get('reallocated_sectors', 0) > 0:
        status['concerns'].append('Reallocated sectors: {}'.format(
            smart_info['reallocated_sectors']
        ))
        if status['lifecycle_status'] == 'healthy':
            status['lifecycle_status'] = 'warning'
            status['recommendation'] = 'Monitor closely - sector reallocation detected'

    if smart_info.get('pending_sectors', 0) > 0:
        status['concerns'].append('Pending sectors: {}'.format(
            smart_info['pending_sectors']
        ))
        status['lifecycle_status'] = 'warning'
        status['recommendation'] = 'Monitor closely - pending sector reallocation'

    # SSD-specific concerns
    if is_ssd and smart_info.get('wear_leveling') is not None:
        wear = smart_info['wear_leveling']
        if wear < 50:
            status['concerns'].append('SSD wear leveling at {}%'.format(wear))
            status['lifecycle_status'] = 'critical'
            status['recommendation'] = 'SSD nearing end of life - replace soon'
        elif wear < 80:
            status['concerns'].append('SSD wear leveling at {}%'.format(wear))
            if status['lifecycle_status'] == 'healthy':
                status['lifecycle_status'] = 'warning'

    return status


def format_hours(hours):
    """Format hours into human-readable string"""
    if hours is None:
        return "N/A"

    years = hours // 8760
    remaining = hours % 8760
    months = remaining // 730
    days = (remaining % 730) // 24

    parts = []
    if years > 0:
        parts.append("{}y".format(years))
    if months > 0:
        parts.append("{}m".format(months))
    if days > 0 and years == 0:
        parts.append("{}d".format(days))

    return " ".join(parts) if parts else "0d"


def main():
    parser = argparse.ArgumentParser(
        description="Monitor disk lifecycle for hardware refresh planning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    Check all disks
  %(prog)s -d /dev/sda        Check specific disk
  %(prog)s --format json      Output as JSON
  %(prog)s --warn-only        Only show disks with warnings
  %(prog)s --warn-hours 30000 Custom warning threshold
        """
    )
    parser.add_argument("-d", "--disk",
                        help="Specific disk to check (e.g., /dev/sda)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed SMART information")
    parser.add_argument("--format", choices=["plain", "json", "table"],
                        default="plain",
                        help="Output format (default: plain)")
    parser.add_argument("--warn-only", action="store_true",
                        help="Only show disks with lifecycle warnings")
    parser.add_argument("--warn-hours", type=int, default=35000,
                        help="Hours threshold for warning (HDD, default: 35000)")
    parser.add_argument("--critical-hours", type=int, default=50000,
                        help="Hours threshold for critical (HDD, default: 50000)")
    parser.add_argument("--ssd-warn-hours", type=int, default=20000,
                        help="Hours threshold for warning (SSD, default: 20000)")
    parser.add_argument("--ssd-critical-hours", type=int, default=40000,
                        help="Hours threshold for critical (SSD, default: 40000)")

    args = parser.parse_args()

    # Check if smartctl is available
    if not check_smartctl_available():
        print("Error: smartctl is not installed. Please install smartmontools package.",
              file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt-get install smartmontools", file=sys.stderr)
        print("  RHEL/CentOS: sudo yum install smartmontools", file=sys.stderr)
        sys.exit(2)

    # Get disk list
    if args.disk:
        disks = [args.disk]
    else:
        disks = get_disk_list()

    if not disks:
        print("No disks found", file=sys.stderr)
        sys.exit(1)

    results = []
    has_warnings = False

    for disk in disks:
        size, model = get_disk_info(disk)
        smart_info = get_smart_info(disk)
        lifecycle = calculate_lifecycle_status(
            smart_info,
            warn_hours=args.warn_hours,
            critical_hours=args.critical_hours,
            ssd_warn_hours=args.ssd_warn_hours,
            ssd_critical_hours=args.ssd_critical_hours
        )

        disk_result = {
            'disk': disk,
            'size': size,
            'model': model,
            'serial': smart_info.get('serial'),
            'type': 'SSD' if smart_info.get('is_ssd') else 'HDD',
            'power_on_hours': smart_info.get('power_on_hours'),
            'power_on_hours_formatted': format_hours(smart_info.get('power_on_hours')),
            'power_cycle_count': smart_info.get('power_cycle_count'),
            'lifecycle_status': lifecycle['lifecycle_status'],
            'estimated_age_years': lifecycle['estimated_age_years'],
            'hours_remaining_estimate': lifecycle.get('hours_remaining_estimate'),
            'recommendation': lifecycle['recommendation'],
            'concerns': lifecycle['concerns'],
            'smart_supported': smart_info['smart_supported'],
        }

        if args.verbose:
            disk_result['firmware'] = smart_info.get('firmware')
            disk_result['form_factor'] = smart_info.get('form_factor')
            disk_result['reallocated_sectors'] = smart_info.get('reallocated_sectors')
            disk_result['pending_sectors'] = smart_info.get('pending_sectors')
            if smart_info.get('is_ssd'):
                disk_result['wear_leveling'] = smart_info.get('wear_leveling')

        if lifecycle['lifecycle_status'] in ('warning', 'critical'):
            has_warnings = True

        if not args.warn_only or lifecycle['lifecycle_status'] in ('warning', 'critical', 'unknown'):
            results.append(disk_result)

    # Output results
    if args.format == "json":
        print(json.dumps(results, indent=2))
    elif args.format == "table":
        # Table header
        print("{:<12} {:<8} {:<25} {:<12} {:<10} {:<10}".format(
            "DISK", "TYPE", "MODEL", "POH", "AGE", "STATUS"
        ))
        print("-" * 80)
        for r in results:
            status_marker = ""
            if r['lifecycle_status'] == 'critical':
                status_marker = " [!]"
            elif r['lifecycle_status'] == 'warning':
                status_marker = " [*]"

            print("{:<12} {:<8} {:<25} {:<12} {:<10} {:<10}".format(
                r['disk'],
                r['type'],
                (r['model'] or 'N/A')[:25],
                str(r['power_on_hours'] or 'N/A'),
                "{}y".format(r['estimated_age_years']) if r['estimated_age_years'] else 'N/A',
                r['lifecycle_status'] + status_marker
            ))
    else:
        # Plain text output
        for r in results:
            status_symbol = {
                'healthy': '+',
                'warning': '*',
                'critical': '!',
                'unknown': '?'
            }.get(r['lifecycle_status'], '?')

            print("[{}] {} - {} {} ({})".format(
                status_symbol,
                r['disk'],
                r['size'],
                r['model'] or 'Unknown',
                r['type']
            ))

            if r['smart_supported']:
                poh = r['power_on_hours']
                if poh is not None:
                    print("    Power-on hours: {} ({})".format(
                        poh,
                        r['power_on_hours_formatted']
                    ))
                    if r['estimated_age_years']:
                        print("    Estimated age: {} years".format(
                            r['estimated_age_years']
                        ))

                print("    Status: {} - {}".format(
                    r['lifecycle_status'].upper(),
                    r['recommendation']
                ))

                if r['concerns']:
                    print("    Concerns:")
                    for concern in r['concerns']:
                        print("      - {}".format(concern))

                if args.verbose:
                    if r.get('serial'):
                        print("    Serial: {}".format(r['serial']))
                    if r.get('power_cycle_count'):
                        print("    Power cycles: {}".format(r['power_cycle_count']))
                    if r.get('firmware'):
                        print("    Firmware: {}".format(r['firmware']))
            else:
                print("    SMART not available")

            print()

    # Exit with appropriate code
    sys.exit(1 if has_warnings else 0)


if __name__ == "__main__":
    main()
