#!/usr/bin/env python3
# Monitor network interface health and performance

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


def get_interface_list():
    """Get list of network interfaces"""
    returncode, stdout, stderr = run_command("ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}'")
    if returncode != 0:
        return []

    interfaces = [iface.strip() for iface in stdout.strip().split('\n') if iface.strip() and iface.strip() != 'lo']
    return interfaces


def get_interface_stats(iface):
    """Get interface statistics from ethtool"""
    stats = {
        'rx_errors': 0,
        'rx_dropped': 0,
        'rx_overruns': 0,
        'rx_frame': 0,
        'tx_errors': 0,
        'tx_dropped': 0,
        'tx_overruns': 0,
        'tx_carrier': 0,
        'rx_packets': 0,
        'tx_packets': 0
    }

    # Get stats from ip command
    returncode, stdout, stderr = run_command("ip -s link show {}".format(iface))
    if returncode == 0:
        lines = stdout.split('\n')
        for i, line in enumerate(lines):
            if 'RX:' in line and i + 1 < len(lines):
                # Next line has RX stats: bytes packets errors dropped overrun mcast
                parts = lines[i + 1].split()
                if len(parts) >= 5:
                    stats['rx_packets'] = int(parts[1]) if parts[1].isdigit() else 0
                    stats['rx_errors'] = int(parts[2]) if parts[2].isdigit() else 0
                    stats['rx_dropped'] = int(parts[3]) if parts[3].isdigit() else 0
                    stats['rx_overruns'] = int(parts[4]) if parts[4].isdigit() else 0
            elif 'TX:' in line and i + 1 < len(lines):
                # Next line has TX stats: bytes packets errors dropped carrier collsns
                parts = lines[i + 1].split()
                if len(parts) >= 5:
                    stats['tx_packets'] = int(parts[1]) if parts[1].isdigit() else 0
                    stats['tx_errors'] = int(parts[2]) if parts[2].isdigit() else 0
                    stats['tx_dropped'] = int(parts[3]) if parts[3].isdigit() else 0
                    stats['tx_overruns'] = int(parts[4]) if parts[4].isdigit() else 0
                    if len(parts) > 5:
                        stats['tx_carrier'] = int(parts[5]) if parts[5].isdigit() else 0

    return stats


def get_interface_status(iface):
    """Get interface status (up/down)"""
    returncode, stdout, stderr = run_command("ip link show {} | grep -oP 'state \\K\\w+'".format(iface))
    if returncode == 0:
        status = stdout.strip()
        if status:
            return status
    return "UNKNOWN"


def get_interface_speed(iface):
    """Get interface speed using ethtool"""
    # Check if ethtool is available
    returncode, _, _ = run_command("which ethtool")
    if returncode != 0:
        return "N/A"

    returncode, stdout, stderr = run_command("ethtool {} 2>/dev/null | grep -E 'Speed:'".format(iface))
    if returncode == 0 and stdout:
        match = re.search(r'Speed:\s*(\S+)', stdout)
        if match:
            return match.group(1)

    return "N/A"


def get_interface_duplex(iface):
    """Get interface duplex mode using ethtool"""
    # Check if ethtool is available
    returncode, _, _ = run_command("which ethtool")
    if returncode != 0:
        return "N/A"

    returncode, stdout, stderr = run_command("ethtool {} 2>/dev/null | grep -E 'Duplex:'".format(iface))
    if returncode == 0 and stdout:
        match = re.search(r'Duplex:\s*(\S+)', stdout)
        if match:
            return match.group(1)

    return "N/A"


def get_interface_mtu(iface):
    """Get interface MTU"""
    returncode, stdout, stderr = run_command("ip link show {} | grep -oP 'mtu \\K\\d+'".format(iface))
    if returncode == 0 and stdout:
        return stdout.strip()
    return "N/A"


def get_interface_ip(iface):
    """Get IPv4 address of interface"""
    returncode, stdout, stderr = run_command("ip addr show {} | grep -oP 'inet \\K[^ ]+'".format(iface))
    if returncode == 0 and stdout:
        return stdout.strip().split('\n')[0]
    return "N/A"


def check_interface_health(iface):
    """Check overall health of an interface"""
    status = get_interface_status(iface)
    stats = get_interface_stats(iface)

    # Determine if interface has issues
    has_errors = (
        stats['rx_errors'] > 0 or
        stats['rx_dropped'] > 0 or
        stats['rx_overruns'] > 0 or
        stats['rx_frame'] > 0 or
        stats['tx_errors'] > 0 or
        stats['tx_dropped'] > 0 or
        stats['tx_overruns'] > 0 or
        stats['tx_carrier'] > 0
    )

    is_down = status != "UP"

    health_status = "healthy"
    if is_down:
        health_status = "down"
    elif has_errors:
        health_status = "degraded"

    return health_status, is_down, has_errors


def main():
    parser = argparse.ArgumentParser(description="Monitor network interface health and errors")
    parser.add_argument("-i", "--interface",
                        help="Specific interface to check (e.g., eth0)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed statistics")
    parser.add_argument("--format", choices=["plain", "json"], default="plain",
                        help="Output format (default: plain)")
    parser.add_argument("--warn-only", action="store_true",
                        help="Only show interfaces with warnings or errors")

    args = parser.parse_args()

    # Get interface list
    if args.interface:
        interfaces = [args.interface]
    else:
        interfaces = get_interface_list()

    if not interfaces:
        print("No network interfaces found")
        sys.exit(0)

    results = []

    for iface in interfaces:
        health_status, is_down, has_errors = check_interface_health(iface)
        speed = get_interface_speed(iface)
        duplex = get_interface_duplex(iface)
        mtu = get_interface_mtu(iface)
        ip_addr = get_interface_ip(iface)
        stats = get_interface_stats(iface)
        status = get_interface_status(iface)

        interface_result = {
            'interface': iface,
            'status': status,
            'health': health_status,
            'ip_address': ip_addr,
            'mtu': mtu,
            'speed': speed,
            'duplex': duplex,
            'stats': stats
        }

        if not args.warn_only or health_status != "healthy":
            results.append(interface_result)

    # Output results
    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        # Plain text output
        print("Network Interface Health Status:")
        print("=" * 80)
        print()

        for result in results:
            health_symbol = "✓" if result['health'] == "healthy" else "✗"
            status_indicator = "UP" if result['status'] == "UP" else "DOWN"

            print("{} {} ({}) - {} - Speed: {} {}".format(
                health_symbol,
                result['interface'],
                status_indicator,
                result['health'].upper(),
                result['speed'],
                result['duplex']
            ))

            if result['ip_address'] != "N/A":
                print("  IP: {}".format(result['ip_address']))

            print("  MTU: {} - Duplex: {}".format(result['mtu'], result['duplex']))

            if args.verbose or result['health'] != "healthy":
                stats = result['stats']
                print("  RX: {} packets, {} errors, {} dropped, {} overruns".format(
                    stats['rx_packets'],
                    stats['rx_errors'],
                    stats['rx_dropped'],
                    stats['rx_overruns']
                ))
                print("  TX: {} packets, {} errors, {} dropped, {} overruns, {} carrier".format(
                    stats['tx_packets'],
                    stats['tx_errors'],
                    stats['tx_dropped'],
                    stats['tx_overruns'],
                    stats['tx_carrier']
                ))

            print()

    # Exit with error if any interface is degraded
    if any(r['health'] != 'healthy' for r in results):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
