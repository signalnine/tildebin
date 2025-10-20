#!/usr/bin/env python3
# Generate hardware inventory for baremetal systems

import argparse
import subprocess
import sys
import json
import os
import re
from datetime import datetime


def run_command(cmd):
    """Execute a command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def get_system_info():
    """Get basic system information"""
    info = {}

    # Hostname
    returncode, stdout, _ = run_command("hostname")
    info['hostname'] = stdout.strip() if returncode == 0 else "unknown"

    # Kernel
    returncode, stdout, _ = run_command("uname -r")
    info['kernel'] = stdout.strip() if returncode == 0 else "unknown"

    # OS
    returncode, stdout, _ = run_command("lsb_release -d 2>/dev/null | cut -f2")
    if returncode == 0 and stdout.strip():
        info['os'] = stdout.strip()
    else:
        returncode, stdout, _ = run_command("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
        info['os'] = stdout.strip() if returncode == 0 else "unknown"

    # Uptime
    returncode, stdout, _ = run_command("uptime -p")
    info['uptime'] = stdout.strip() if returncode == 0 else "unknown"

    return info


def get_cpu_info():
    """Get CPU information"""
    info = {}

    # CPU model
    returncode, stdout, _ = run_command("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2")
    info['model'] = stdout.strip() if returncode == 0 else "unknown"

    # CPU count
    returncode, stdout, _ = run_command("grep -c processor /proc/cpuinfo")
    info['cores'] = int(stdout.strip()) if returncode == 0 else 0

    # CPU architecture
    returncode, stdout, _ = run_command("uname -m")
    info['architecture'] = stdout.strip() if returncode == 0 else "unknown"

    return info


def get_memory_info():
    """Get memory information"""
    info = {}

    returncode, stdout, _ = run_command("free -h | grep Mem:")
    if returncode == 0:
        parts = stdout.split()
        if len(parts) >= 2:
            info['total'] = parts[1]
            info['used'] = parts[2] if len(parts) >= 3 else "unknown"
            info['available'] = parts[6] if len(parts) >= 7 else "unknown"
    else:
        info['total'] = "unknown"
        info['used'] = "unknown"
        info['available'] = "unknown"

    # Get memory type if dmidecode is available
    if os.geteuid() == 0:
        returncode, stdout, _ = run_command("dmidecode -t memory | grep 'Type:' | head -1")
        if returncode == 0:
            type_match = re.search(r'Type:\s*(\w+)', stdout)
            if type_match:
                info['type'] = type_match.group(1)

    return info


def get_disk_info():
    """Get disk information"""
    disks = []

    returncode, stdout, _ = run_command("lsblk -d -n -o NAME,SIZE,TYPE,MODEL | grep disk")
    if returncode == 0:
        for line in stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split(None, 3)
            if len(parts) >= 3:
                disk = {
                    'device': "/dev/{}".format(parts[0]),
                    'size': parts[1],
                    'model': parts[3].strip() if len(parts) >= 4 else "unknown"
                }
                disks.append(disk)

    return disks


def get_network_info():
    """Get network interface information"""
    interfaces = []

    # Get interface list
    returncode, stdout, _ = run_command("ip -o link show | awk -F': ' '{print $2}'")
    if returncode != 0:
        return interfaces

    for iface in stdout.strip().split('\n'):
        iface = iface.strip()
        if not iface or iface == 'lo':
            continue

        interface = {'name': iface}

        # Get MAC address
        returncode, stdout, _ = run_command("cat /sys/class/net/{}/address 2>/dev/null".format(iface))
        interface['mac'] = stdout.strip() if returncode == 0 else "unknown"

        # Get speed
        returncode, stdout, _ = run_command("cat /sys/class/net/{}/speed 2>/dev/null".format(iface))
        if returncode == 0 and stdout.strip() and stdout.strip() != "-1":
            interface['speed'] = "{}Mbps".format(stdout.strip())
        else:
            interface['speed'] = "unknown"

        # Get state
        returncode, stdout, _ = run_command("cat /sys/class/net/{}/operstate 2>/dev/null".format(iface))
        interface['state'] = stdout.strip() if returncode == 0 else "unknown"

        # Get IP address
        returncode, stdout, _ = run_command("ip -4 addr show {} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}'".format(iface))
        interface['ipv4'] = stdout.strip() if returncode == 0 and stdout.strip() else "none"

        interfaces.append(interface)

    return interfaces


def get_pci_devices():
    """Get PCI device information"""
    devices = []

    returncode, stdout, _ = run_command("lspci")
    if returncode != 0:
        return devices

    for line in stdout.strip().split('\n'):
        if not line:
            continue

        # Parse PCI ID and description
        match = re.match(r'^([\w:.]+)\s+(.+)$', line)
        if match:
            devices.append({
                'id': match.group(1),
                'description': match.group(2)
            })

    return devices


def get_dmidecode_info():
    """Get additional hardware info from dmidecode (requires root)"""
    info = {}

    if os.geteuid() != 0:
        return info

    # System manufacturer
    returncode, stdout, _ = run_command("dmidecode -s system-manufacturer")
    info['manufacturer'] = stdout.strip() if returncode == 0 else "unknown"

    # System product name
    returncode, stdout, _ = run_command("dmidecode -s system-product-name")
    info['product'] = stdout.strip() if returncode == 0 else "unknown"

    # System serial number
    returncode, stdout, _ = run_command("dmidecode -s system-serial-number")
    info['serial'] = stdout.strip() if returncode == 0 else "unknown"

    # BIOS version
    returncode, stdout, _ = run_command("dmidecode -s bios-version")
    info['bios'] = stdout.strip() if returncode == 0 else "unknown"

    return info


def main():
    parser = argparse.ArgumentParser(description="Generate hardware inventory for baremetal systems")
    parser.add_argument("--format", choices=["plain", "json"], default="plain",
                        help="Output format (default: plain)")
    parser.add_argument("-o", "--output",
                        help="Output file (default: stdout)")
    parser.add_argument("--include-pci", action="store_true",
                        help="Include PCI device listing")

    args = parser.parse_args()

    # Collect all information
    inventory = {
        'timestamp': datetime.now().isoformat(),
        'system': get_system_info(),
        'cpu': get_cpu_info(),
        'memory': get_memory_info(),
        'disks': get_disk_info(),
        'network': get_network_info(),
        'hardware': get_dmidecode_info()
    }

    if args.include_pci:
        inventory['pci_devices'] = get_pci_devices()

    # Output results
    output_text = ""

    if args.format == "json":
        output_text = json.dumps(inventory, indent=2)
    else:
        # Plain text format
        lines = []
        lines.append("=" * 80)
        lines.append("SYSTEM INVENTORY")
        lines.append("=" * 80)
        lines.append("Generated: {}".format(inventory['timestamp']))
        lines.append("")

        lines.append("SYSTEM INFORMATION:")
        lines.append("  Hostname: {}".format(inventory['system']['hostname']))
        lines.append("  OS: {}".format(inventory['system']['os']))
        lines.append("  Kernel: {}".format(inventory['system']['kernel']))
        lines.append("  Uptime: {}".format(inventory['system']['uptime']))

        if inventory['hardware']:
            lines.append("")
            lines.append("HARDWARE:")
            lines.append("  Manufacturer: {}".format(inventory['hardware'].get('manufacturer', 'unknown')))
            lines.append("  Product: {}".format(inventory['hardware'].get('product', 'unknown')))
            lines.append("  Serial: {}".format(inventory['hardware'].get('serial', 'unknown')))
            lines.append("  BIOS: {}".format(inventory['hardware'].get('bios', 'unknown')))

        lines.append("")
        lines.append("CPU:")
        lines.append("  Model: {}".format(inventory['cpu']['model']))
        lines.append("  Cores: {}".format(inventory['cpu']['cores']))
        lines.append("  Architecture: {}".format(inventory['cpu']['architecture']))

        lines.append("")
        lines.append("MEMORY:")
        lines.append("  Total: {}".format(inventory['memory']['total']))
        lines.append("  Used: {}".format(inventory['memory']['used']))
        lines.append("  Available: {}".format(inventory['memory']['available']))
        if 'type' in inventory['memory']:
            lines.append("  Type: {}".format(inventory['memory']['type']))

        lines.append("")
        lines.append("DISKS:")
        for disk in inventory['disks']:
            lines.append("  {} - {} - {}".format(
                disk['device'],
                disk['size'],
                disk['model']
            ))

        lines.append("")
        lines.append("NETWORK INTERFACES:")
        for iface in inventory['network']:
            lines.append("  {} - {} - {} - {} - {}".format(
                iface['name'],
                iface['state'],
                iface['mac'],
                iface['speed'],
                iface['ipv4']
            ))

        if 'pci_devices' in inventory:
            lines.append("")
            lines.append("PCI DEVICES:")
            for device in inventory['pci_devices']:
                lines.append("  {} - {}".format(device['id'], device['description']))

        lines.append("")
        lines.append("=" * 80)

        output_text = '\n'.join(lines)

    # Write output
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(output_text)
            print("Inventory saved to: {}".format(args.output))
        except Exception as e:
            print("Error writing to file: {}".format(e))
            sys.exit(1)
    else:
        print(output_text)

    sys.exit(0)


if __name__ == "__main__":
    main()
