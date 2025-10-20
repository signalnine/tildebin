#!/usr/bin/env python3
# Check status of hardware and software RAID arrays

import argparse
import subprocess
import sys
import json
import os
import re


def run_command(cmd):
    """Execute a command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def check_mdadm_available():
    """Check if mdadm is installed (for software RAID)"""
    returncode, _, _ = run_command("which mdadm")
    return returncode == 0


def check_megacli_available():
    """Check if MegaCli is installed (for LSI/Broadcom hardware RAID)"""
    returncode, _, _ = run_command("which megacli || which MegaCli || which MegaCli64")
    return returncode == 0


def check_hpacucli_available():
    """Check if hpacucli/ssacli is installed (for HP hardware RAID)"""
    returncode, _, _ = run_command("which hpacucli || which ssacli || which hpssacli")
    return returncode == 0


def get_software_raid_status():
    """Get status of software RAID arrays (mdadm)"""
    if not os.path.exists("/proc/mdstat"):
        return []

    returncode, stdout, stderr = run_command("cat /proc/mdstat")
    if returncode != 0:
        return []

    arrays = []
    current_array = None

    for line in stdout.split('\n'):
        # Match array line (e.g., "md0 : active raid1 sda1[0] sdb1[1]")
        array_match = re.match(r'^(md\d+)\s*:\s*(\w+)\s+(\w+)\s+(.+)$', line)
        if array_match:
            if current_array:
                arrays.append(current_array)

            array_name = array_match.group(1)
            state = array_match.group(2)
            raid_level = array_match.group(3)
            devices = array_match.group(4)

            current_array = {
                'name': array_name,
                'type': 'software',
                'state': state,
                'level': raid_level,
                'devices': devices.strip(),
                'status': 'healthy' if state == 'active' else 'degraded',
                'progress': None
            }

        # Match progress line (e.g., "[==>..................]  recovery = 13.0%")
        elif current_array and '[' in line and ']' in line:
            progress_match = re.search(r'(\w+)\s*=\s*([\d.]+)%', line)
            if progress_match:
                operation = progress_match.group(1)
                percentage = progress_match.group(2)
                current_array['progress'] = "{}: {}%".format(operation, percentage)
                current_array['status'] = 'rebuilding'

    if current_array:
        arrays.append(current_array)

    return arrays


def get_megacli_raid_status():
    """Get status of LSI/Broadcom hardware RAID"""
    if not check_megacli_available():
        return []

    # Try different MegaCli command names
    for cmd_name in ['megacli', 'MegaCli', 'MegaCli64']:
        returncode, _, _ = run_command("which {}".format(cmd_name))
        if returncode == 0:
            megacli_cmd = cmd_name
            break
    else:
        return []

    arrays = []

    # Get adapter count
    returncode, stdout, stderr = run_command("{} -adpCount -NoLog".format(megacli_cmd))
    if returncode != 0:
        return []

    adapter_match = re.search(r'Controller Count:\s*(\d+)', stdout)
    if not adapter_match:
        return []

    adapter_count = int(adapter_match.group(1))

    for adapter_id in range(adapter_count):
        # Get virtual drive info
        returncode, stdout, stderr = run_command(
            "{} -LDInfo -Lall -a{} -NoLog".format(megacli_cmd, adapter_id)
        )

        if returncode != 0:
            continue

        # Parse virtual drives
        ld_pattern = r'Virtual Drive:\s*(\d+).*?RAID Level\s*:\s*Primary-(\d+).*?State\s*:\s*(\w+)'
        matches = re.finditer(ld_pattern, stdout, re.DOTALL)

        for match in matches:
            vd_id = match.group(1)
            raid_level = match.group(2)
            state = match.group(3)

            arrays.append({
                'name': "Adapter{}_VD{}".format(adapter_id, vd_id),
                'type': 'hardware-lsi',
                'level': "RAID{}".format(raid_level),
                'state': state,
                'status': 'healthy' if state == 'Optimal' else 'degraded',
                'devices': 'N/A'
            })

    return arrays


def get_hp_raid_status():
    """Get status of HP hardware RAID"""
    if not check_hpacucli_available():
        return []

    # Try different HP CLI command names
    for cmd_name in ['hpacucli', 'ssacli', 'hpssacli']:
        returncode, _, _ = run_command("which {}".format(cmd_name))
        if returncode == 0:
            hp_cmd = cmd_name
            break
    else:
        return []

    arrays = []

    # Get controller info
    returncode, stdout, stderr = run_command("{} ctrl all show config".format(hp_cmd))
    if returncode != 0:
        return []

    # Parse output for logical drives
    current_controller = None
    for line in stdout.split('\n'):
        ctrl_match = re.search(r'Smart Array (\w+)', line)
        if ctrl_match:
            current_controller = ctrl_match.group(1)

        ld_match = re.search(r'logicaldrive\s+(\d+)\s+\(([\d.]+\s+\w+),\s+(\w+),\s+(\w+)\)', line)
        if ld_match and current_controller:
            ld_id = ld_match.group(1)
            size = ld_match.group(2)
            raid_level = ld_match.group(3)
            status = ld_match.group(4)

            arrays.append({
                'name': "{}_LD{}".format(current_controller, ld_id),
                'type': 'hardware-hp',
                'level': raid_level,
                'state': status,
                'status': 'healthy' if status == 'OK' else 'degraded',
                'devices': size
            })

    return arrays


def main():
    parser = argparse.ArgumentParser(description="Check status of hardware and software RAID arrays")
    parser.add_argument("-t", "--type", choices=["all", "software", "hardware"],
                        default="all",
                        help="Type of RAID to check (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain",
                        help="Output format (default: plain)")
    parser.add_argument("--warn-only", action="store_true",
                        help="Only show arrays with warnings or failures")

    args = parser.parse_args()

    # Check if running as root (required for many RAID commands)
    if os.geteuid() != 0 and args.type in ["all", "hardware"]:
        print("Warning: Not running as root. Hardware RAID detection may be limited.")
        print("Run with sudo for complete hardware RAID information.")
        print()

    all_arrays = []

    # Check software RAID
    if args.type in ["all", "software"]:
        sw_arrays = get_software_raid_status()
        all_arrays.extend(sw_arrays)

    # Check hardware RAID
    if args.type in ["all", "hardware"]:
        # Try MegaCli (LSI/Broadcom)
        mega_arrays = get_megacli_raid_status()
        all_arrays.extend(mega_arrays)

        # Try HP RAID
        hp_arrays = get_hp_raid_status()
        all_arrays.extend(hp_arrays)

    if not all_arrays:
        print("No RAID arrays detected")
        print()
        print("Software RAID: Check if mdadm is installed and /proc/mdstat exists")
        print("Hardware RAID: Ensure appropriate tools are installed:")
        print("  - LSI/Broadcom: MegaCli")
        print("  - HP: hpacucli/ssacli")
        sys.exit(0)

    # Filter arrays if warn-only mode
    if args.warn_only:
        all_arrays = [a for a in all_arrays if a['status'] != 'healthy']

    # Output results
    if args.format == "json":
        print(json.dumps(all_arrays, indent=2))
    else:
        print("RAID Array Status:")
        print("=" * 80)
        print()

        for array in all_arrays:
            status_symbol = "✓" if array['status'] == 'healthy' else "✗"

            print("{} {} ({}) - Level: {} - State: {}".format(
                status_symbol,
                array['name'],
                array['type'],
                array['level'],
                array['state']
            ))

            if args.verbose:
                print("  Status: {}".format(array['status']))
                if array.get('devices'):
                    print("  Devices: {}".format(array['devices']))
                if array.get('progress'):
                    print("  Progress: {}".format(array['progress']))

            print()

    # Exit with error if any array is degraded
    if any(a['status'] != 'healthy' for a in all_arrays):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
