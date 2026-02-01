#!/usr/bin/env python3
# Monitor disk health using SMART attributes and system information

import argparse
import subprocess
import sys
import json
import re


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
    returncode, stdout, stderr = run_command("lsblk -d -n -o NAME,TYPE | grep disk | awk '{print $1}'")
    if returncode != 0:
        print("Error getting disk list: {}".format(stderr))
        return []

    disks = ["/dev/{}".format(disk.strip()) for disk in stdout.strip().split('\n') if disk.strip()]
    return disks


def get_smart_status(disk):
    """Get SMART status for a disk"""
    returncode, stdout, stderr = run_command("smartctl -H {}".format(disk))

    if "SMART support is: Unavailable" in stdout or "SMART support is: Disabled" in stdout:
        return "UNAVAILABLE"

    if "SMART overall-health self-assessment test result: PASSED" in stdout:
        return "PASSED"
    elif "SMART overall-health self-assessment test result: FAILED" in stdout:
        return "FAILED"
    else:
        return "UNKNOWN"


def get_smart_attributes(disk):
    """Get critical SMART attributes"""
    returncode, stdout, stderr = run_command("smartctl -A {}".format(disk))

    if returncode != 0:
        return {}

    attributes = {}
    critical_attrs = {
        '5': 'Reallocated_Sector_Ct',
        '187': 'Reported_Uncorrect',
        '188': 'Command_Timeout',
        '197': 'Current_Pending_Sector',
        '198': 'Offline_Uncorrectable',
        '199': 'UDMA_CRC_Error_Count'
    }

    for line in stdout.split('\n'):
        parts = line.split()
        if len(parts) >= 10 and parts[0] in critical_attrs:
            attr_id = parts[0]
            attr_name = critical_attrs[attr_id]
            raw_value = parts[9]
            attributes[attr_name] = raw_value

    return attributes


def get_disk_temperature(disk):
    """Get disk temperature if available"""
    returncode, stdout, stderr = run_command("smartctl -A {} | grep -i temperature".format(disk))

    if returncode != 0:
        return "N/A"

    # Try to extract temperature value
    match = re.search(r'(\d+)\s*(?:Celsius|C)', stdout)
    if match:
        return "{}°C".format(match.group(1))

    return "N/A"


def get_disk_info(disk):
    """Get basic disk information"""
    returncode, stdout, stderr = run_command("lsblk -n -o SIZE,MODEL {} | head -1".format(disk))

    if returncode != 0:
        return "N/A", "N/A"

    parts = stdout.strip().split(None, 1)
    size = parts[0] if len(parts) > 0 else "N/A"
    model = parts[1].strip() if len(parts) > 1 else "N/A"

    return size, model


def main():
    parser = argparse.ArgumentParser(description="Check disk health using SMART attributes")
    parser.add_argument("-d", "--disk",
                        help="Specific disk to check (e.g., /dev/sda)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed SMART attributes")
    parser.add_argument("--format", choices=["plain", "json"], default="plain",
                        help="Output format (default: plain)")
    parser.add_argument("--warn-only", action="store_true",
                        help="Only show disks with warnings or failures")

    args = parser.parse_args()

    # Check if smartctl is available
    if not check_smartctl_available():
        print("Error: smartctl is not installed. Please install smartmontools package.")
        print("  Ubuntu/Debian: sudo apt-get install smartmontools")
        print("  RHEL/CentOS: sudo yum install smartmontools")
        sys.exit(1)

    # Get disk list
    if args.disk:
        disks = [args.disk]
    else:
        disks = get_disk_list()

    if not disks:
        print("No disks found")
        sys.exit(1)

    results = []

    for disk in disks:
        smart_status = get_smart_status(disk)
        temperature = get_disk_temperature(disk)
        size, model = get_disk_info(disk)
        attributes = get_smart_attributes(disk) if args.verbose else {}

        disk_result = {
            'disk': disk,
            'size': size,
            'model': model,
            'smart_status': smart_status,
            'temperature': temperature,
            'attributes': attributes
        }

        # Check for warning conditions
        warning = False
        if smart_status == "FAILED":
            warning = True
        elif attributes:
            # Check if any critical attributes are non-zero
            for attr_name, value in attributes.items():
                try:
                    if int(value) > 0:
                        warning = True
                        break
                except ValueError:
                    pass

        disk_result['warning'] = warning

        if not args.warn_only or warning:
            results.append(disk_result)

    # Output results
    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        # Plain text output
        for result in results:
            status_symbol = "✓" if result['smart_status'] == "PASSED" else "✗"
            warning_marker = " [WARNING]" if result['warning'] else ""

            print("{} {} - {} {} - SMART: {}{}".format(
                status_symbol,
                result['disk'],
                result['size'],
                result['model'],
                result['smart_status'],
                warning_marker
            ))

            if result['temperature'] != "N/A":
                print("  Temperature: {}".format(result['temperature']))

            if args.verbose and result['attributes']:
                print("  Critical Attributes:")
                for attr_name, value in result['attributes'].items():
                    marker = " <!>" if value != "0" else ""
                    print("    {}: {}{}".format(attr_name, value, marker))

            print()

    # Exit with error if any disk has warnings
    if any(r['warning'] for r in results):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
