#!/usr/bin/env python3
"""
Monitor SSD wear levels and endurance metrics using SMART attributes.

This script reads SSD-specific SMART attributes to estimate remaining drive life
and identify drives approaching end of life. Critical for proactive replacement
in large baremetal environments.

Key metrics monitored:
- Media Wearout Indicator (Intel)
- Wear Leveling Count (Samsung, generic)
- Percentage Used Endurance Indicator
- Total LBAs Written / Host Writes
- Available Reserved Space
- SSD Life Left

Exit codes:
    0 - All SSDs healthy (wear < warning threshold)
    1 - One or more SSDs have warnings or errors
    2 - Missing dependencies or usage error
"""

import argparse
import json
import re
import subprocess
import sys


def run_command(cmd):
    """Execute a command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def check_smartctl_available():
    """Check if smartctl is installed."""
    returncode, _, _ = run_command("which smartctl")
    return returncode == 0


def get_disk_list():
    """Get list of disk devices."""
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


def is_ssd(disk):
    """Check if a disk is an SSD (not rotational)."""
    # Extract device name without /dev/
    device_name = disk.replace('/dev/', '')
    # Handle NVMe devices (nvme0n1 -> nvme0)
    if device_name.startswith('nvme'):
        # NVMe devices are always SSDs
        return True

    # Check rotational flag for SATA/SAS drives
    returncode, stdout, _ = run_command(
        "cat /sys/block/{}/queue/rotational 2>/dev/null".format(device_name)
    )
    if returncode == 0 and stdout.strip() == '0':
        return True
    return False


def get_disk_info(disk):
    """Get basic disk information."""
    returncode, stdout, _ = run_command(
        "lsblk -n -o SIZE,MODEL {} 2>/dev/null | head -1".format(disk)
    )

    if returncode != 0:
        return "N/A", "N/A"

    parts = stdout.strip().split(None, 1)
    size = parts[0] if len(parts) > 0 else "N/A"
    model = parts[1].strip() if len(parts) > 1 else "N/A"

    return size, model


def get_nvme_wear_info(disk):
    """Get wear info from NVMe device using smartctl."""
    returncode, stdout, _ = run_command("smartctl -A {}".format(disk))

    if returncode != 0 and "Unable to detect" not in stdout:
        return None

    wear_info = {
        'percentage_used': None,
        'available_spare': None,
        'data_written_tb': None,
        'power_on_hours': None,
        'media_errors': None,
        'wear_level': None,
    }

    for line in stdout.split('\n'):
        line_lower = line.lower()

        # Percentage Used
        if 'percentage used' in line_lower:
            match = re.search(r'(\d+)%?', line)
            if match:
                wear_info['percentage_used'] = int(match.group(1))
                # Wear level is 100 - percentage_used
                wear_info['wear_level'] = 100 - int(match.group(1))

        # Available Spare
        elif 'available spare:' in line_lower and 'threshold' not in line_lower:
            match = re.search(r'(\d+)%?', line)
            if match:
                wear_info['available_spare'] = int(match.group(1))

        # Data Written (convert to TB)
        elif 'data units written' in line_lower:
            match = re.search(r'[\d,]+', line)
            if match:
                units = int(match.group().replace(',', ''))
                # Each unit is 512KB * 1000 = 512000 bytes
                tb_written = (units * 512000) / (1024**4)
                wear_info['data_written_tb'] = round(tb_written, 2)

        # Power On Hours
        elif 'power on hours' in line_lower:
            match = re.search(r'[\d,]+', line)
            if match:
                wear_info['power_on_hours'] = int(match.group().replace(',', ''))

        # Media Errors
        elif 'media and data integrity errors' in line_lower:
            match = re.search(r'(\d+)', line)
            if match:
                wear_info['media_errors'] = int(match.group(1))

    return wear_info


def get_sata_ssd_wear_info(disk):
    """Get wear info from SATA SSD using SMART attributes."""
    returncode, stdout, _ = run_command("smartctl -A {}".format(disk))

    if returncode != 0:
        return None

    wear_info = {
        'percentage_used': None,
        'available_spare': None,
        'data_written_tb': None,
        'power_on_hours': None,
        'media_errors': None,
        'wear_level': None,
    }

    # SMART attribute IDs for SSD wear
    # Different vendors use different attributes
    wear_attrs = {
        '177': 'Wear_Leveling_Count',      # Samsung, Crucial
        '173': 'Wear_Leveling_Count',      # SanDisk
        '231': 'SSD_Life_Left',            # Intel, Kingston
        '232': 'Available_Reservd_Space',  # Intel
        '233': 'Media_Wearout_Indicator',  # Intel
        '241': 'Total_LBAs_Written',       # Generic
        '246': 'Total_LBAs_Written',       # Some drives
        '9': 'Power_On_Hours',             # Standard
        '5': 'Reallocated_Sector_Ct',      # Standard - indicates wear
    }

    reallocated_sectors = 0
    total_lbas_written = None
    power_on_hours = None

    for line in stdout.split('\n'):
        parts = line.split()
        if len(parts) >= 10:
            attr_id = parts[0]

            if attr_id in wear_attrs:
                raw_value = parts[9]
                normalized_value = parts[3]  # Normalized value (0-100 or 0-200)

                try:
                    raw_int = int(raw_value)
                    norm_int = int(normalized_value)
                except ValueError:
                    continue

                # Wear Leveling Count (177, 173) - normalized value indicates remaining life
                if attr_id in ['177', '173']:
                    wear_info['wear_level'] = norm_int
                    wear_info['percentage_used'] = 100 - norm_int if norm_int <= 100 else None

                # SSD Life Left (231)
                elif attr_id == '231':
                    wear_info['wear_level'] = norm_int
                    wear_info['percentage_used'] = 100 - norm_int if norm_int <= 100 else None

                # Available Reserved Space (232)
                elif attr_id == '232':
                    wear_info['available_spare'] = norm_int

                # Media Wearout Indicator (233)
                elif attr_id == '233':
                    wear_info['wear_level'] = norm_int
                    wear_info['percentage_used'] = 100 - norm_int if norm_int <= 100 else None

                # Total LBAs Written (241, 246)
                elif attr_id in ['241', '246']:
                    total_lbas_written = raw_int

                # Power On Hours (9)
                elif attr_id == '9':
                    power_on_hours = raw_int

                # Reallocated Sectors (5)
                elif attr_id == '5':
                    reallocated_sectors = raw_int

    # Convert LBAs written to TB (512 bytes per LBA)
    if total_lbas_written:
        tb_written = (total_lbas_written * 512) / (1024**4)
        wear_info['data_written_tb'] = round(tb_written, 2)

    wear_info['power_on_hours'] = power_on_hours

    # Use reallocated sectors as an error indicator
    if reallocated_sectors > 0:
        wear_info['media_errors'] = reallocated_sectors

    return wear_info


def get_ssd_wear_info(disk):
    """Get wear information for an SSD."""
    # Check if it's NVMe
    if 'nvme' in disk:
        return get_nvme_wear_info(disk)
    else:
        return get_sata_ssd_wear_info(disk)


def analyze_wear(wear_info, warn_threshold, critical_threshold):
    """Analyze wear info and determine status."""
    status = 'healthy'
    warnings = []

    if wear_info is None:
        return 'unknown', ['Unable to read SMART data']

    wear_level = wear_info.get('wear_level')
    percentage_used = wear_info.get('percentage_used')
    available_spare = wear_info.get('available_spare')
    media_errors = wear_info.get('media_errors')

    # Check wear level / percentage used
    if wear_level is not None:
        if wear_level <= critical_threshold:
            status = 'critical'
            warnings.append('Wear level critical: {}% remaining'.format(wear_level))
        elif wear_level <= warn_threshold:
            status = 'warning'
            warnings.append('Wear level low: {}% remaining'.format(wear_level))

    if percentage_used is not None and percentage_used >= (100 - critical_threshold):
        status = 'critical'
        warnings.append('{}% of rated endurance used'.format(percentage_used))
    elif percentage_used is not None and percentage_used >= (100 - warn_threshold):
        if status != 'critical':
            status = 'warning'
        warnings.append('{}% of rated endurance used'.format(percentage_used))

    # Check available spare
    if available_spare is not None and available_spare < 10:
        status = 'critical'
        warnings.append('Low available spare: {}%'.format(available_spare))
    elif available_spare is not None and available_spare < 20:
        if status != 'critical':
            status = 'warning'
        warnings.append('Available spare declining: {}%'.format(available_spare))

    # Check media errors
    if media_errors is not None and media_errors > 0:
        status = 'critical'
        warnings.append('Media errors detected: {}'.format(media_errors))

    return status, warnings


def main():
    parser = argparse.ArgumentParser(
        description='Monitor SSD wear levels and endurance metrics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Check all SSDs
  %(prog)s -d /dev/nvme0n1     # Check specific SSD
  %(prog)s --warn 20           # Warn when 20%% life remaining
  %(prog)s --format json       # JSON output for monitoring systems

Exit codes:
  0 - All SSDs healthy
  1 - Warnings or errors detected
  2 - Missing dependencies or usage error
"""
    )
    parser.add_argument(
        '-d', '--disk',
        help='Specific disk to check (e.g., /dev/nvme0n1, /dev/sda)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed wear metrics'
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
        help='Only show SSDs with warnings or critical status'
    )
    parser.add_argument(
        '--warn',
        type=int,
        default=20,
        metavar='PERCENT',
        help='Warning threshold for remaining life (default: 20%%)'
    )
    parser.add_argument(
        '--critical',
        type=int,
        default=10,
        metavar='PERCENT',
        help='Critical threshold for remaining life (default: 10%%)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn < args.critical:
        print("Error: Warning threshold must be >= critical threshold",
              file=sys.stderr)
        sys.exit(2)

    # Check if smartctl is available
    if not check_smartctl_available():
        print("Error: smartctl is not installed. Please install smartmontools.",
              file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt-get install smartmontools",
              file=sys.stderr)
        print("  RHEL/CentOS: sudo yum install smartmontools", file=sys.stderr)
        sys.exit(2)

    # Get disk list
    if args.disk:
        if not is_ssd(args.disk):
            print("Warning: {} may not be an SSD".format(args.disk),
                  file=sys.stderr)
        disks = [args.disk]
    else:
        all_disks = get_disk_list()
        disks = [d for d in all_disks if is_ssd(d)]

    if not disks:
        if args.format == 'json':
            print(json.dumps({'ssds': [], 'message': 'No SSDs found'}))
        else:
            print("No SSDs found")
        sys.exit(0)

    results = []
    has_warnings = False

    for disk in disks:
        size, model = get_disk_info(disk)
        wear_info = get_ssd_wear_info(disk)
        status, warnings = analyze_wear(
            wear_info, args.warn, args.critical
        )

        result = {
            'disk': disk,
            'size': size,
            'model': model,
            'status': status,
            'warnings': warnings,
            'wear_level': wear_info.get('wear_level') if wear_info else None,
            'percentage_used': wear_info.get('percentage_used') if wear_info else None,
            'available_spare': wear_info.get('available_spare') if wear_info else None,
            'data_written_tb': wear_info.get('data_written_tb') if wear_info else None,
            'power_on_hours': wear_info.get('power_on_hours') if wear_info else None,
            'media_errors': wear_info.get('media_errors') if wear_info else None,
        }

        if status in ['warning', 'critical', 'unknown']:
            has_warnings = True

        if not args.warn_only or status != 'healthy':
            results.append(result)

    # Output results
    if args.format == 'json':
        output = {
            'ssds': results,
            'summary': {
                'total': len(disks),
                'checked': len(results),
                'healthy': sum(1 for r in results if r['status'] == 'healthy'),
                'warning': sum(1 for r in results if r['status'] == 'warning'),
                'critical': sum(1 for r in results if r['status'] == 'critical'),
                'unknown': sum(1 for r in results if r['status'] == 'unknown'),
            }
        }
        print(json.dumps(output, indent=2))

    elif args.format == 'table':
        # Table header
        print("{:<15} {:<8} {:<25} {:<10} {:<8} {:<10}".format(
            'DEVICE', 'SIZE', 'MODEL', 'STATUS', 'LIFE %', 'WRITTEN'
        ))
        print("-" * 80)

        for r in results:
            life_str = '{}%'.format(r['wear_level']) if r['wear_level'] is not None else 'N/A'
            written_str = '{}TB'.format(r['data_written_tb']) if r['data_written_tb'] is not None else 'N/A'

            print("{:<15} {:<8} {:<25} {:<10} {:<8} {:<10}".format(
                r['disk'],
                r['size'],
                r['model'][:25] if r['model'] else 'N/A',
                r['status'].upper(),
                life_str,
                written_str
            ))

    else:  # plain
        for r in results:
            # Status symbol
            if r['status'] == 'healthy':
                symbol = '[OK]'
            elif r['status'] == 'warning':
                symbol = '[WARN]'
            elif r['status'] == 'critical':
                symbol = '[CRIT]'
            else:
                symbol = '[????]'

            # Life remaining
            life_str = ''
            if r['wear_level'] is not None:
                life_str = ' - {}% life remaining'.format(r['wear_level'])
            elif r['percentage_used'] is not None:
                life_str = ' - {}% used'.format(r['percentage_used'])

            print("{} {} ({} {}){}".format(
                symbol,
                r['disk'],
                r['size'],
                r['model'] or 'Unknown',
                life_str
            ))

            # Print warnings
            for warning in r['warnings']:
                print("  ! {}".format(warning))

            # Verbose output
            if args.verbose:
                if r['data_written_tb'] is not None:
                    print("  Data written: {} TB".format(r['data_written_tb']))
                if r['power_on_hours'] is not None:
                    days = r['power_on_hours'] // 24
                    print("  Power on: {} hours ({} days)".format(
                        r['power_on_hours'], days
                    ))
                if r['available_spare'] is not None:
                    print("  Available spare: {}%".format(r['available_spare']))

    # Exit code
    if has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
