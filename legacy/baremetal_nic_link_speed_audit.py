#!/usr/bin/env python3
"""
Audit NIC link speeds to detect interfaces negotiating at suboptimal speeds.

Identifies network interfaces that may be running slower than expected due to:
- Cable issues (damaged, wrong category, too long)
- Switch port misconfigurations
- Auto-negotiation failures
- Hardware problems

This is critical for large baremetal environments where NICs silently
degrading to 100Mb or 1Gb instead of 10Gb/25Gb causes major performance issues.

Exit codes:
    0 - All interfaces at expected speeds (or no physical interfaces)
    1 - One or more interfaces at suboptimal speeds
    2 - Usage error or missing dependency
"""

import argparse
import json
import os
import re
import subprocess
import sys


def run_command(cmd):
    """Execute a command and return output."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def check_ethtool_available():
    """Check if ethtool is available."""
    returncode, _, _ = run_command(['which', 'ethtool'])
    return returncode == 0


def get_physical_interfaces():
    """Get list of physical network interfaces (excluding virtual/loopback)."""
    interfaces = []

    # Read from /sys/class/net
    net_path = '/sys/class/net'
    if not os.path.exists(net_path):
        return interfaces

    for iface in os.listdir(net_path):
        iface_path = os.path.join(net_path, iface)

        # Skip loopback
        if iface == 'lo':
            continue

        # Check if it's a physical device (has a device symlink)
        device_path = os.path.join(iface_path, 'device')
        if not os.path.exists(device_path):
            # Virtual interface (bridge, veth, bond, vlan, etc.)
            continue

        # Skip virtual device types
        iface_type_path = os.path.join(iface_path, 'type')
        if os.path.exists(iface_type_path):
            try:
                with open(iface_type_path) as f:
                    iface_type = f.read().strip()
                    # Type 1 is Ethernet, skip others like tunnels
                    if iface_type != '1':
                        continue
            except (IOError, OSError):
                pass

        interfaces.append(iface)

    return sorted(interfaces)


def parse_speed(speed_str):
    """Parse speed string and return value in Mbps."""
    if not speed_str or speed_str in ('Unknown!', 'N/A', ''):
        return None

    # Handle formats like "10000Mb/s", "1000Mb/s", "100Mb/s"
    match = re.match(r'(\d+)\s*Mb/s', speed_str, re.IGNORECASE)
    if match:
        return int(match.group(1))

    # Handle formats like "10Gb/s", "25Gb/s"
    match = re.match(r'(\d+)\s*Gb/s', speed_str, re.IGNORECASE)
    if match:
        return int(match.group(1)) * 1000

    return None


def get_interface_info(iface):
    """Get link information for an interface using ethtool."""
    info = {
        'interface': iface,
        'speed': None,
        'speed_raw': 'Unknown',
        'link_detected': False,
        'duplex': 'Unknown',
        'auto_negotiation': None,
        'supported_speeds': [],
        'max_supported_speed': None,
        'driver': 'Unknown',
    }

    # Get driver info
    driver_path = f'/sys/class/net/{iface}/device/driver'
    if os.path.exists(driver_path):
        try:
            driver_link = os.readlink(driver_path)
            info['driver'] = os.path.basename(driver_link)
        except OSError:
            pass

    # Get ethtool output
    returncode, stdout, _ = run_command(['ethtool', iface])
    if returncode != 0:
        return info

    for line in stdout.split('\n'):
        line = line.strip()

        if line.startswith('Speed:'):
            speed_raw = line.split(':', 1)[1].strip()
            info['speed_raw'] = speed_raw
            info['speed'] = parse_speed(speed_raw)

        elif line.startswith('Link detected:'):
            value = line.split(':', 1)[1].strip().lower()
            info['link_detected'] = value == 'yes'

        elif line.startswith('Duplex:'):
            info['duplex'] = line.split(':', 1)[1].strip()

        elif line.startswith('Auto-negotiation:'):
            value = line.split(':', 1)[1].strip().lower()
            info['auto_negotiation'] = value == 'on'

        elif line.startswith('Supported link modes:'):
            # Parse supported speeds
            speeds_str = line.split(':', 1)[1].strip()
            info['supported_speeds'].extend(parse_supported_speeds(speeds_str))

        elif not line.startswith('Supported') and 'baseT' in line:
            # Continuation of supported link modes
            info['supported_speeds'].extend(parse_supported_speeds(line))

    # Get max supported speed
    if info['supported_speeds']:
        info['max_supported_speed'] = max(info['supported_speeds'])

    return info


def parse_supported_speeds(line):
    """Parse supported link mode speeds from ethtool output."""
    speeds = []

    # Match patterns like 10baseT, 100baseT, 1000baseT, 10000baseT, 25000baseT
    for match in re.finditer(r'(\d+)base', line, re.IGNORECASE):
        speed = int(match.group(1))
        if speed not in speeds:
            speeds.append(speed)

    return speeds


def analyze_interface(info, min_expected_speed=None):
    """Analyze interface and determine if speed is suboptimal."""
    issues = []
    status = 'ok'

    # No link detected
    if not info['link_detected']:
        return 'no_link', ['No link detected']

    # Speed unknown
    if info['speed'] is None:
        return 'unknown', ['Speed could not be determined']

    # Check against minimum expected speed
    if min_expected_speed and info['speed'] < min_expected_speed:
        issues.append(
            f"Speed {info['speed']}Mb/s below minimum expected {min_expected_speed}Mb/s"
        )
        status = 'suboptimal'

    # Check against max supported speed
    if info['max_supported_speed'] and info['speed'] < info['max_supported_speed']:
        ratio = info['speed'] / info['max_supported_speed']
        if ratio < 0.5:  # Running at less than half max speed
            issues.append(
                f"Speed {info['speed']}Mb/s is {ratio:.0%} of max supported "
                f"{info['max_supported_speed']}Mb/s"
            )
            if status == 'ok':
                status = 'suboptimal'

    # Check duplex - half duplex is usually a problem
    if info['duplex'].lower() == 'half':
        issues.append('Half duplex detected (usually indicates negotiation issue)')
        status = 'suboptimal'

    return status, issues


def format_speed(speed_mbps):
    """Format speed in human-readable form."""
    if speed_mbps is None:
        return 'Unknown'
    if speed_mbps >= 1000:
        return f"{speed_mbps // 1000}Gb/s"
    return f"{speed_mbps}Mb/s"


def output_plain(results, verbose=False):
    """Output results in plain text format."""
    print("NIC Link Speed Audit")
    print("=" * 70)
    print()

    if not results:
        print("No physical network interfaces found.")
        return

    suboptimal_count = 0

    for r in results:
        status_symbol = '✓' if r['status'] == 'ok' else '✗'
        if r['status'] == 'no_link':
            status_symbol = '-'

        speed_display = r['info']['speed_raw']
        max_speed = format_speed(r['info']['max_supported_speed'])

        print(f"{status_symbol} {r['interface']}: {speed_display}", end='')
        if r['info']['max_supported_speed']:
            print(f" (max: {max_speed})", end='')
        print(f" [{r['info']['duplex']}]")

        if r['issues']:
            suboptimal_count += 1
            for issue in r['issues']:
                print(f"  WARNING: {issue}")

        if verbose:
            print(f"  Driver: {r['info']['driver']}")
            if r['info']['auto_negotiation'] is not None:
                autoneg = 'on' if r['info']['auto_negotiation'] else 'off'
                print(f"  Auto-negotiation: {autoneg}")
            if r['info']['supported_speeds']:
                speeds = ', '.join(
                    format_speed(s) for s in sorted(r['info']['supported_speeds'])
                )
                print(f"  Supported speeds: {speeds}")
            print()

    print()
    print(f"Summary: {len(results)} interfaces checked, "
          f"{suboptimal_count} with issues")


def output_json(results):
    """Output results in JSON format."""
    output = {
        'interfaces': results,
        'summary': {
            'total': len(results),
            'ok': sum(1 for r in results if r['status'] == 'ok'),
            'suboptimal': sum(1 for r in results if r['status'] == 'suboptimal'),
            'no_link': sum(1 for r in results if r['status'] == 'no_link'),
            'unknown': sum(1 for r in results if r['status'] == 'unknown'),
        }
    }
    print(json.dumps(output, indent=2))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Audit NIC link speeds to detect suboptimal negotiation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      Check all physical NICs
  %(prog)s --min-speed 10000    Flag any NIC below 10Gb/s
  %(prog)s -i eth0 -v           Check specific interface with details
  %(prog)s --format json        Output in JSON format
        """
    )

    parser.add_argument(
        '-i', '--interface',
        help='Specific interface to check (default: all physical NICs)'
    )
    parser.add_argument(
        '--min-speed',
        type=int,
        metavar='MBPS',
        help='Minimum expected speed in Mbps (e.g., 10000 for 10Gb/s)'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: %(default)s)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed interface information'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show interfaces with issues'
    )

    args = parser.parse_args()

    # Check for ethtool
    if not check_ethtool_available():
        print("Error: ethtool not found in PATH", file=sys.stderr)
        print("Install with: sudo apt-get install ethtool", file=sys.stderr)
        sys.exit(2)

    # Get interfaces to check
    if args.interface:
        interfaces = [args.interface]
        # Verify interface exists
        if not os.path.exists(f'/sys/class/net/{args.interface}'):
            print(f"Error: Interface '{args.interface}' not found",
                  file=sys.stderr)
            sys.exit(2)
    else:
        interfaces = get_physical_interfaces()

    # Analyze each interface
    results = []
    has_issues = False

    for iface in interfaces:
        info = get_interface_info(iface)
        status, issues = analyze_interface(info, args.min_speed)

        result = {
            'interface': iface,
            'status': status,
            'issues': issues,
            'info': info,
        }

        if status in ('suboptimal', 'unknown'):
            has_issues = True

        if not args.warn_only or issues:
            results.append(result)

    # Output results
    if args.format == 'json':
        output_json(results)
    else:
        output_plain(results, args.verbose)

    # Exit code based on findings
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
