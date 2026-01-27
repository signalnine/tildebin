#!/usr/bin/env python3
"""
Collect firmware version inventory from baremetal systems.

This script gathers firmware and version information including:
- BIOS/UEFI version and release date
- BMC/IPMI firmware version (if accessible)
- CPU microcode version
- Storage controller firmware
- Network adapter firmware
- GPU firmware (if applicable)

Useful for:
- Fleet-wide firmware version tracking
- Security vulnerability assessment (identifying outdated firmware)
- Compliance reporting and audit trails
- Pre-upgrade validation and planning
- Hardware lifecycle management

Exit codes:
    0 - Inventory collected successfully
    1 - Some components could not be queried (partial data)
    2 - Missing dependencies or usage error
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime


def run_command(cmd, check=False):
    """Execute a command and return output."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}"
    except Exception as e:
        return -1, "", str(e)


def read_file(path):
    """Read contents of a file, return None if not accessible."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError, PermissionError):
        return None


def get_bios_info():
    """Get BIOS/UEFI information from DMI."""
    info = {
        'vendor': None,
        'version': None,
        'release_date': None,
        'revision': None,
    }

    # Try reading from sysfs first (doesn't require root for some fields)
    dmi_path = '/sys/class/dmi/id'
    if os.path.isdir(dmi_path):
        info['vendor'] = read_file(f'{dmi_path}/bios_vendor')
        info['version'] = read_file(f'{dmi_path}/bios_version')
        info['release_date'] = read_file(f'{dmi_path}/bios_date')

    # Try dmidecode for more details (requires root)
    returncode, stdout, _ = run_command(['dmidecode', '-t', 'bios'])
    if returncode == 0:
        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith('Vendor:'):
                info['vendor'] = line.split(':', 1)[1].strip()
            elif line.startswith('Version:'):
                info['version'] = line.split(':', 1)[1].strip()
            elif line.startswith('Release Date:'):
                info['release_date'] = line.split(':', 1)[1].strip()
            elif line.startswith('BIOS Revision:'):
                info['revision'] = line.split(':', 1)[1].strip()

    return info


def get_baseboard_info():
    """Get baseboard/motherboard information."""
    info = {
        'manufacturer': None,
        'product_name': None,
        'version': None,
        'serial_number': None,
    }

    dmi_path = '/sys/class/dmi/id'
    if os.path.isdir(dmi_path):
        info['manufacturer'] = read_file(f'{dmi_path}/board_vendor')
        info['product_name'] = read_file(f'{dmi_path}/board_name')
        info['version'] = read_file(f'{dmi_path}/board_version')
        # Serial may require root
        info['serial_number'] = read_file(f'{dmi_path}/board_serial')

    return info


def get_system_info():
    """Get system/chassis information."""
    info = {
        'manufacturer': None,
        'product_name': None,
        'version': None,
        'serial_number': None,
        'uuid': None,
    }

    dmi_path = '/sys/class/dmi/id'
    if os.path.isdir(dmi_path):
        info['manufacturer'] = read_file(f'{dmi_path}/sys_vendor')
        info['product_name'] = read_file(f'{dmi_path}/product_name')
        info['version'] = read_file(f'{dmi_path}/product_version')
        info['serial_number'] = read_file(f'{dmi_path}/product_serial')
        info['uuid'] = read_file(f'{dmi_path}/product_uuid')

    return info


def get_cpu_microcode():
    """Get CPU microcode version."""
    info = {
        'version': None,
        'date': None,
    }

    # Read from /proc/cpuinfo
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('microcode'):
                    parts = line.split(':')
                    if len(parts) == 2:
                        info['version'] = parts[1].strip()
                    break
    except (IOError, OSError):
        pass

    # Try to get update date from dmesg
    returncode, stdout, _ = run_command(['dmesg'])
    if returncode == 0:
        for line in stdout.split('\n'):
            if 'microcode' in line.lower() and 'updated' in line.lower():
                # Extract date if present
                info['date'] = line.strip()
                break

    return info


def get_bmc_info():
    """Get BMC/IPMI firmware information."""
    info = {
        'version': None,
        'manufacturer': None,
        'available': False,
    }

    # Try ipmitool
    returncode, stdout, _ = run_command(['ipmitool', 'mc', 'info'])
    if returncode == 0:
        info['available'] = True
        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith('Firmware Revision'):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    info['version'] = parts[1].strip()
            elif line.startswith('Manufacturer Name'):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    info['manufacturer'] = parts[1].strip()

    return info


def get_storage_firmware():
    """Get storage controller and drive firmware versions."""
    devices = []

    # Get NVMe drives
    nvme_path = '/sys/class/nvme'
    if os.path.isdir(nvme_path):
        try:
            for nvme in os.listdir(nvme_path):
                dev_info = {
                    'type': 'nvme',
                    'device': nvme,
                    'model': read_file(f'{nvme_path}/{nvme}/model'),
                    'firmware': read_file(f'{nvme_path}/{nvme}/firmware_rev'),
                    'serial': read_file(f'{nvme_path}/{nvme}/serial'),
                }
                devices.append(dev_info)
        except (IOError, OSError):
            pass

    # Try smartctl for SATA drives
    returncode, stdout, _ = run_command(['smartctl', '--scan'])
    if returncode == 0:
        for line in stdout.split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 1:
                device = parts[0]
                if '/dev/nvme' in device:
                    continue  # Already covered above

                rc, info_out, _ = run_command(['smartctl', '-i', device])
                if rc == 0:
                    dev_info = {
                        'type': 'sata',
                        'device': device,
                        'model': None,
                        'firmware': None,
                        'serial': None,
                    }
                    for info_line in info_out.split('\n'):
                        if 'Device Model:' in info_line or 'Product:' in info_line:
                            dev_info['model'] = info_line.split(':', 1)[1].strip()
                        elif 'Firmware Version:' in info_line or 'Revision:' in info_line:
                            dev_info['firmware'] = info_line.split(':', 1)[1].strip()
                        elif 'Serial Number:' in info_line or 'Serial number:' in info_line:
                            dev_info['serial'] = info_line.split(':', 1)[1].strip()
                    devices.append(dev_info)

    return devices


def get_network_firmware():
    """Get network adapter firmware versions."""
    devices = []

    # Try ethtool for each network interface
    net_path = '/sys/class/net'
    if os.path.isdir(net_path):
        try:
            for iface in os.listdir(net_path):
                # Skip virtual interfaces
                if iface.startswith(('lo', 'docker', 'br-', 'veth', 'virbr')):
                    continue

                # Check if it's a physical device
                device_path = f'{net_path}/{iface}/device'
                if not os.path.isdir(device_path):
                    continue

                dev_info = {
                    'interface': iface,
                    'driver': read_file(f'{net_path}/{iface}/device/driver/module/name') or
                              os.path.basename(os.readlink(f'{net_path}/{iface}/device/driver')) if os.path.islink(f'{net_path}/{iface}/device/driver') else None,
                    'firmware': None,
                    'bus_info': None,
                }

                # Get firmware version using ethtool
                returncode, stdout, _ = run_command(['ethtool', '-i', iface])
                if returncode == 0:
                    for line in stdout.split('\n'):
                        if line.startswith('firmware-version:'):
                            dev_info['firmware'] = line.split(':', 1)[1].strip()
                        elif line.startswith('driver:'):
                            dev_info['driver'] = line.split(':', 1)[1].strip()
                        elif line.startswith('bus-info:'):
                            dev_info['bus_info'] = line.split(':', 1)[1].strip()

                devices.append(dev_info)
        except (IOError, OSError):
            pass

    return devices


def get_gpu_firmware():
    """Get GPU firmware versions."""
    devices = []

    # Check for NVIDIA GPUs
    returncode, stdout, _ = run_command(['nvidia-smi', '--query-gpu=name,vbios_version,driver_version', '--format=csv,noheader'])
    if returncode == 0:
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 3:
                devices.append({
                    'type': 'nvidia',
                    'name': parts[0],
                    'vbios': parts[1],
                    'driver': parts[2],
                })

    # Check for AMD GPUs via sysfs
    drm_path = '/sys/class/drm'
    if os.path.isdir(drm_path):
        try:
            for card in os.listdir(drm_path):
                if not card.startswith('card') or '-' in card:
                    continue
                device_path = f'{drm_path}/{card}/device'
                if os.path.isdir(device_path):
                    vbios = read_file(f'{device_path}/vbios_version')
                    if vbios:
                        devices.append({
                            'type': 'amd',
                            'name': card,
                            'vbios': vbios,
                            'driver': read_file(f'{device_path}/driver/module/name'),
                        })
        except (IOError, OSError):
            pass

    return devices


def get_kernel_info():
    """Get kernel version and related info."""
    info = {
        'release': None,
        'version': None,
        'machine': None,
    }

    returncode, stdout, _ = run_command(['uname', '-r'])
    if returncode == 0:
        info['release'] = stdout.strip()

    returncode, stdout, _ = run_command(['uname', '-v'])
    if returncode == 0:
        info['version'] = stdout.strip()

    returncode, stdout, _ = run_command(['uname', '-m'])
    if returncode == 0:
        info['machine'] = stdout.strip()

    return info


def collect_inventory():
    """Collect full firmware inventory."""
    inventory = {
        'collected_at': datetime.now().isoformat(),
        'hostname': None,
        'kernel': get_kernel_info(),
        'system': get_system_info(),
        'baseboard': get_baseboard_info(),
        'bios': get_bios_info(),
        'cpu_microcode': get_cpu_microcode(),
        'bmc': get_bmc_info(),
        'storage': get_storage_firmware(),
        'network': get_network_firmware(),
        'gpu': get_gpu_firmware(),
    }

    # Get hostname
    returncode, stdout, _ = run_command(['hostname', '-f'])
    if returncode == 0:
        inventory['hostname'] = stdout.strip()
    else:
        returncode, stdout, _ = run_command(['hostname'])
        if returncode == 0:
            inventory['hostname'] = stdout.strip()

    return inventory


def has_data(value):
    """Check if a value contains meaningful data."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, dict):
        return any(has_data(v) for v in value.values())
    return True


def output_plain(inventory, verbose=False):
    """Output inventory in plain text format."""
    print("Firmware Inventory Report")
    print("=" * 60)
    print(f"Hostname: {inventory.get('hostname', 'unknown')}")
    print(f"Collected: {inventory.get('collected_at', 'unknown')}")
    print()

    # Kernel
    kernel = inventory.get('kernel', {})
    if has_data(kernel):
        print("KERNEL:")
        print(f"  Release: {kernel.get('release', 'unknown')}")
        if verbose and kernel.get('version'):
            print(f"  Version: {kernel.get('version')}")
        print()

    # System
    system = inventory.get('system', {})
    if has_data(system):
        print("SYSTEM:")
        print(f"  Manufacturer: {system.get('manufacturer', 'unknown')}")
        print(f"  Product: {system.get('product_name', 'unknown')}")
        if verbose:
            print(f"  Version: {system.get('version', 'unknown')}")
            if system.get('serial_number'):
                print(f"  Serial: {system.get('serial_number')}")
        print()

    # BIOS
    bios = inventory.get('bios', {})
    if has_data(bios):
        print("BIOS/UEFI:")
        print(f"  Vendor: {bios.get('vendor', 'unknown')}")
        print(f"  Version: {bios.get('version', 'unknown')}")
        print(f"  Date: {bios.get('release_date', 'unknown')}")
        if verbose and bios.get('revision'):
            print(f"  Revision: {bios.get('revision')}")
        print()

    # CPU Microcode
    microcode = inventory.get('cpu_microcode', {})
    if has_data(microcode):
        print("CPU MICROCODE:")
        print(f"  Version: {microcode.get('version', 'unknown')}")
        print()

    # BMC
    bmc = inventory.get('bmc', {})
    if bmc.get('available'):
        print("BMC/IPMI:")
        print(f"  Manufacturer: {bmc.get('manufacturer', 'unknown')}")
        print(f"  Firmware: {bmc.get('version', 'unknown')}")
        print()

    # Storage
    storage = inventory.get('storage', [])
    if storage:
        print("STORAGE DEVICES:")
        for dev in storage:
            print(f"  {dev.get('device', 'unknown')} ({dev.get('type', 'unknown')})")
            print(f"    Model: {dev.get('model', 'unknown')}")
            print(f"    Firmware: {dev.get('firmware', 'unknown')}")
            if verbose and dev.get('serial'):
                print(f"    Serial: {dev.get('serial')}")
        print()

    # Network
    network = inventory.get('network', [])
    if network:
        print("NETWORK ADAPTERS:")
        for dev in network:
            print(f"  {dev.get('interface', 'unknown')}")
            print(f"    Driver: {dev.get('driver', 'unknown')}")
            print(f"    Firmware: {dev.get('firmware', 'unknown')}")
            if verbose and dev.get('bus_info'):
                print(f"    Bus: {dev.get('bus_info')}")
        print()

    # GPU
    gpu = inventory.get('gpu', [])
    if gpu:
        print("GPU DEVICES:")
        for dev in gpu:
            print(f"  {dev.get('name', 'unknown')} ({dev.get('type', 'unknown')})")
            print(f"    VBIOS: {dev.get('vbios', 'unknown')}")
            print(f"    Driver: {dev.get('driver', 'unknown')}")
        print()


def output_json(inventory):
    """Output inventory in JSON format."""
    print(json.dumps(inventory, indent=2))


def output_table(inventory):
    """Output inventory in compact table format."""
    print(f"{'Component':<20} {'Type':<15} {'Version/Firmware':<30}")
    print("-" * 65)

    # System
    system = inventory.get('system', {})
    print(f"{'System':<20} {'Platform':<15} {system.get('product_name', 'unknown')[:30]:<30}")

    # BIOS
    bios = inventory.get('bios', {})
    print(f"{'BIOS':<20} {'Firmware':<15} {bios.get('version', 'unknown')[:30]:<30}")

    # Microcode
    microcode = inventory.get('cpu_microcode', {})
    if microcode.get('version'):
        print(f"{'CPU Microcode':<20} {'Firmware':<15} {microcode.get('version', 'unknown')[:30]:<30}")

    # BMC
    bmc = inventory.get('bmc', {})
    if bmc.get('available'):
        print(f"{'BMC':<20} {'IPMI':<15} {bmc.get('version', 'unknown')[:30]:<30}")

    # Storage
    for dev in inventory.get('storage', []):
        name = dev.get('device', 'unknown')[:20]
        print(f"{name:<20} {dev.get('type', 'disk'):<15} {str(dev.get('firmware', 'unknown'))[:30]:<30}")

    # Network
    for dev in inventory.get('network', []):
        name = dev.get('interface', 'unknown')[:20]
        print(f"{name:<20} {'NIC':<15} {str(dev.get('firmware', 'unknown'))[:30]:<30}")

    # GPU
    for dev in inventory.get('gpu', []):
        name = dev.get('name', 'unknown')[:20]
        print(f"{name:<20} {'GPU':<15} {str(dev.get('vbios', 'unknown'))[:30]:<30}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Collect firmware version inventory from baremetal systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Collect and display inventory
  %(prog)s --format json             # JSON output for automation
  %(prog)s --format table            # Compact table format
  %(prog)s -v                        # Verbose output with serials

Notes:
  - Some information requires root access (dmidecode, ipmitool)
  - Storage firmware requires smartmontools
  - Network firmware requires ethtool
  - GPU info requires nvidia-smi or AMD GPU sysfs

Exit codes:
  0 - Inventory collected successfully
  1 - Some components could not be queried
  2 - Usage error
"""
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show additional details (serial numbers, versions)"
    )

    args = parser.parse_args()

    # Collect inventory
    inventory = collect_inventory()

    # Output results
    if args.format == 'json':
        output_json(inventory)
    elif args.format == 'table':
        output_table(inventory)
    else:
        output_plain(inventory, args.verbose)

    # Check if we got meaningful data
    has_bios = has_data(inventory.get('bios'))
    has_system = has_data(inventory.get('system'))

    # Exit 1 if we couldn't get basic info
    if not has_bios and not has_system:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
