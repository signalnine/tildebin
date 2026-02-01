#!/usr/bin/env python3
"""
Detect MTU mismatches across network interfaces.

MTU (Maximum Transmission Unit) mismatches are a common cause of network problems
in large baremetal environments. When interfaces along a network path have different
MTUs, packets may be fragmented or dropped, causing:
- Silent packet loss with jumbo frames
- Reduced throughput on high-speed links
- TCP performance degradation (PMTUD failures)
- Inconsistent behavior across hosts

This script detects:
- Interfaces with non-standard MTUs (not 1500 or 9000)
- Inconsistent MTUs within bond/team/bridge groups
- Interfaces where MTU doesn't match expected jumbo frame settings
- VLAN interfaces with MTU larger than parent interface

For jumbo frame environments (10G/25G/40G/100G networks):
- Standard jumbo MTU: 9000
- Some switches require: 9216

For standard networks:
- Ethernet default: 1500

Exit codes:
    0 - No MTU issues detected
    1 - MTU mismatches or issues found
    2 - Usage error or required tools not available
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


def read_sysfs(path: str) -> Optional[str]:
    """Read a value from sysfs."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError, PermissionError):
        return None


def get_interface_mtu(iface: str) -> Optional[int]:
    """Get MTU for an interface from sysfs."""
    mtu_str = read_sysfs(f'/sys/class/net/{iface}/mtu')
    if mtu_str and mtu_str.isdigit():
        return int(mtu_str)
    return None


def get_interface_operstate(iface: str) -> str:
    """Get operational state of interface."""
    state = read_sysfs(f'/sys/class/net/{iface}/operstate')
    return state if state else 'unknown'


def get_interface_type(iface: str) -> Optional[int]:
    """Get interface type (ARPHRD_ value)."""
    type_str = read_sysfs(f'/sys/class/net/{iface}/type')
    if type_str and type_str.isdigit():
        return int(type_str)
    return None


def get_interface_speed(iface: str) -> Optional[int]:
    """Get interface speed in Mbps."""
    speed_str = read_sysfs(f'/sys/class/net/{iface}/speed')
    if speed_str and speed_str.lstrip('-').isdigit():
        speed = int(speed_str)
        # Speed of -1 means unknown
        return speed if speed > 0 else None
    return None


def is_virtual_interface(iface: str) -> bool:
    """Check if interface is virtual (no /sys/class/net/{iface}/device)."""
    return not os.path.exists(f'/sys/class/net/{iface}/device')


def is_bond_master(iface: str) -> bool:
    """Check if interface is a bond master."""
    return os.path.exists(f'/sys/class/net/{iface}/bonding')


def is_bridge(iface: str) -> bool:
    """Check if interface is a bridge."""
    return os.path.exists(f'/sys/class/net/{iface}/bridge')


def is_vlan(iface: str) -> bool:
    """Check if interface is a VLAN."""
    # VLAN interfaces typically have a dot in their name or exist in /proc/net/vlan
    if '.' in iface:
        return True
    if os.path.exists(f'/proc/net/vlan/{iface}'):
        return True
    return False


def get_vlan_parent(iface: str) -> Optional[str]:
    """Get parent interface for a VLAN."""
    # Try /proc/net/vlan first
    vlan_file = f'/proc/net/vlan/{iface}'
    if os.path.exists(vlan_file):
        try:
            with open(vlan_file, 'r') as f:
                for line in f:
                    if 'Device:' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
        except (OSError, IOError):
            pass

    # Try parsing interface name (e.g., eth0.100)
    if '.' in iface:
        return iface.rsplit('.', 1)[0]

    return None


def get_bond_slaves(iface: str) -> List[str]:
    """Get list of slave interfaces for a bond."""
    slaves_str = read_sysfs(f'/sys/class/net/{iface}/bonding/slaves')
    if slaves_str:
        return slaves_str.split()
    return []


def get_bridge_ports(iface: str) -> List[str]:
    """Get list of ports for a bridge."""
    brif_path = f'/sys/class/net/{iface}/brif'
    if os.path.isdir(brif_path):
        try:
            return os.listdir(brif_path)
        except OSError:
            pass
    return []


def get_all_interfaces() -> List[str]:
    """Get list of all network interfaces."""
    net_path = '/sys/class/net'
    if not os.path.isdir(net_path):
        return []
    try:
        return [iface for iface in os.listdir(net_path)
                if iface != 'lo' and not iface.startswith('veth')]
    except OSError:
        return []


def classify_mtu(mtu: int) -> str:
    """Classify MTU value."""
    if mtu == 1500:
        return 'standard'
    elif mtu == 9000:
        return 'jumbo'
    elif mtu == 9216:
        return 'jumbo-extended'
    elif mtu < 1500:
        return 'reduced'
    elif 1500 < mtu < 9000:
        return 'custom'
    elif mtu > 9216:
        return 'oversized'
    return 'unknown'


def analyze_interfaces(expected_mtu: Optional[int] = None,
                       jumbo_expected: bool = False) -> Dict[str, Any]:
    """Analyze all interfaces for MTU issues."""
    analysis = {
        'interfaces': {},
        'issues': [],
        'warnings': [],
        'summary': {
            'total_interfaces': 0,
            'standard_mtu': 0,
            'jumbo_mtu': 0,
            'other_mtu': 0,
            'bonds': 0,
            'bridges': 0,
            'vlans': 0,
        },
    }

    interfaces = get_all_interfaces()
    analysis['summary']['total_interfaces'] = len(interfaces)

    # Collect interface data
    for iface in interfaces:
        mtu = get_interface_mtu(iface)
        if mtu is None:
            continue

        operstate = get_interface_operstate(iface)
        speed = get_interface_speed(iface)
        is_virtual = is_virtual_interface(iface)
        iface_type = get_interface_type(iface)

        info = {
            'name': iface,
            'mtu': mtu,
            'mtu_class': classify_mtu(mtu),
            'operstate': operstate,
            'speed_mbps': speed,
            'is_virtual': is_virtual,
            'type': 'physical',
        }

        # Classify interface type
        if is_bond_master(iface):
            info['type'] = 'bond'
            info['slaves'] = get_bond_slaves(iface)
            analysis['summary']['bonds'] += 1
        elif is_bridge(iface):
            info['type'] = 'bridge'
            info['ports'] = get_bridge_ports(iface)
            analysis['summary']['bridges'] += 1
        elif is_vlan(iface):
            info['type'] = 'vlan'
            info['parent'] = get_vlan_parent(iface)
            analysis['summary']['vlans'] += 1

        # Count MTU types
        if mtu == 1500:
            analysis['summary']['standard_mtu'] += 1
        elif mtu in (9000, 9216):
            analysis['summary']['jumbo_mtu'] += 1
        else:
            analysis['summary']['other_mtu'] += 1

        analysis['interfaces'][iface] = info

    # Check for issues

    # 1. Check expected MTU if specified
    if expected_mtu is not None:
        for iface, info in analysis['interfaces'].items():
            if info['operstate'] == 'up' and info['mtu'] != expected_mtu:
                analysis['issues'].append({
                    'type': 'unexpected_mtu',
                    'severity': 'error',
                    'interface': iface,
                    'expected': expected_mtu,
                    'actual': info['mtu'],
                    'message': f"{iface}: MTU {info['mtu']} does not match expected {expected_mtu}",
                })

    # 2. Check jumbo frame expectation for high-speed interfaces
    if jumbo_expected:
        for iface, info in analysis['interfaces'].items():
            if info['operstate'] == 'up' and info['speed_mbps']:
                if info['speed_mbps'] >= 10000 and info['mtu'] == 1500:
                    analysis['warnings'].append({
                        'type': 'no_jumbo_on_high_speed',
                        'severity': 'warning',
                        'interface': iface,
                        'speed_mbps': info['speed_mbps'],
                        'mtu': info['mtu'],
                        'message': f"{iface}: {info['speed_mbps']}Mbps link using standard MTU (1500) instead of jumbo frames",
                    })

    # 3. Check bond slave MTU consistency
    for iface, info in analysis['interfaces'].items():
        if info['type'] == 'bond' and info.get('slaves'):
            master_mtu = info['mtu']
            for slave in info['slaves']:
                slave_info = analysis['interfaces'].get(slave)
                if slave_info and slave_info['mtu'] != master_mtu:
                    analysis['issues'].append({
                        'type': 'bond_mtu_mismatch',
                        'severity': 'error',
                        'interface': slave,
                        'bond': iface,
                        'bond_mtu': master_mtu,
                        'slave_mtu': slave_info['mtu'],
                        'message': f"{slave}: MTU {slave_info['mtu']} mismatches bond {iface} MTU {master_mtu}",
                    })

    # 4. Check bridge port MTU consistency
    for iface, info in analysis['interfaces'].items():
        if info['type'] == 'bridge' and info.get('ports'):
            bridge_mtu = info['mtu']
            for port in info['ports']:
                port_info = analysis['interfaces'].get(port)
                if port_info and port_info['mtu'] != bridge_mtu:
                    analysis['warnings'].append({
                        'type': 'bridge_mtu_mismatch',
                        'severity': 'warning',
                        'interface': port,
                        'bridge': iface,
                        'bridge_mtu': bridge_mtu,
                        'port_mtu': port_info['mtu'],
                        'message': f"{port}: MTU {port_info['mtu']} differs from bridge {iface} MTU {bridge_mtu}",
                    })

    # 5. Check VLAN MTU not exceeding parent
    for iface, info in analysis['interfaces'].items():
        if info['type'] == 'vlan' and info.get('parent'):
            parent_info = analysis['interfaces'].get(info['parent'])
            if parent_info and info['mtu'] > parent_info['mtu']:
                analysis['issues'].append({
                    'type': 'vlan_mtu_exceeds_parent',
                    'severity': 'error',
                    'interface': iface,
                    'parent': info['parent'],
                    'vlan_mtu': info['mtu'],
                    'parent_mtu': parent_info['mtu'],
                    'message': f"{iface}: VLAN MTU {info['mtu']} exceeds parent {info['parent']} MTU {parent_info['mtu']}",
                })

    # 6. Detect mixed MTU environments (both jumbo and standard on active interfaces)
    active_mtus = set()
    for iface, info in analysis['interfaces'].items():
        if info['operstate'] == 'up' and info['type'] == 'physical':
            active_mtus.add(info['mtu'])

    if 1500 in active_mtus and any(m >= 9000 for m in active_mtus):
        analysis['warnings'].append({
            'type': 'mixed_mtu_environment',
            'severity': 'warning',
            'mtus_found': sorted(active_mtus),
            'message': f"Mixed MTU environment detected: {sorted(active_mtus)} - verify this is intentional",
        })

    # 7. Check for unusual MTU values
    for iface, info in analysis['interfaces'].items():
        mtu = info['mtu']
        if mtu < 576:  # Below minimum IP MTU
            analysis['issues'].append({
                'type': 'mtu_too_small',
                'severity': 'error',
                'interface': iface,
                'mtu': mtu,
                'message': f"{iface}: MTU {mtu} is below minimum IP requirement (576)",
            })
        elif mtu > 9216 and info['operstate'] == 'up':
            analysis['warnings'].append({
                'type': 'mtu_oversized',
                'severity': 'warning',
                'interface': iface,
                'mtu': mtu,
                'message': f"{iface}: MTU {mtu} exceeds typical jumbo frame size (9216)",
            })

    return analysis


def output_plain(analysis: Dict, verbose: bool, warn_only: bool) -> None:
    """Output results in plain text format."""
    if warn_only and not analysis['issues'] and not analysis['warnings']:
        return

    print("MTU Mismatch Detector")
    print("=" * 60)
    print()

    # Show issues first
    if analysis['issues']:
        print("ISSUES:")
        for issue in analysis['issues']:
            print(f"  [ERROR] {issue['message']}")
        print()

    if analysis['warnings']:
        print("WARNINGS:")
        for warning in analysis['warnings']:
            print(f"  [WARN] {warning['message']}")
        print()

    if not warn_only:
        # Summary
        summary = analysis['summary']
        print("Summary:")
        print(f"  Total interfaces: {summary['total_interfaces']}")
        print(f"  Standard MTU (1500): {summary['standard_mtu']}")
        print(f"  Jumbo MTU (9000/9216): {summary['jumbo_mtu']}")
        print(f"  Other MTU: {summary['other_mtu']}")
        if summary['bonds'] > 0:
            print(f"  Bond interfaces: {summary['bonds']}")
        if summary['bridges'] > 0:
            print(f"  Bridge interfaces: {summary['bridges']}")
        if summary['vlans'] > 0:
            print(f"  VLAN interfaces: {summary['vlans']}")
        print()

        if verbose:
            print("Interface Details:")
            print("-" * 60)
            print(f"{'Interface':<15} {'MTU':>6} {'Type':<10} {'State':<8} {'Speed':<10}")
            print("-" * 60)

            for iface, info in sorted(analysis['interfaces'].items()):
                speed = f"{info['speed_mbps']}M" if info['speed_mbps'] else "N/A"
                print(f"{iface:<15} {info['mtu']:>6} {info['type']:<10} {info['operstate']:<8} {speed:<10}")
            print()

    if not analysis['issues'] and not analysis['warnings']:
        print("Status: OK - No MTU mismatches detected")


def output_json(analysis: Dict) -> None:
    """Output results in JSON format."""
    has_issues = len(analysis['issues']) > 0
    has_warnings = len(analysis['warnings']) > 0

    if has_issues:
        status = 'error'
    elif has_warnings:
        status = 'warning'
    else:
        status = 'ok'

    result = {
        'status': status,
        'summary': analysis['summary'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'interfaces': analysis['interfaces'],
    }

    print(json.dumps(result, indent=2))


def output_table(analysis: Dict, warn_only: bool) -> None:
    """Output results in table format."""
    if warn_only and not analysis['issues'] and not analysis['warnings']:
        print("No MTU issues detected")
        return

    print(f"{'Interface':<15} {'MTU':>6} {'Class':<12} {'Type':<10} {'State':<8} {'Status':<10}")
    print("=" * 70)

    for iface, info in sorted(analysis['interfaces'].items()):
        # Determine status
        status = 'OK'
        for issue in analysis['issues']:
            if issue.get('interface') == iface:
                status = 'ERROR'
                break
        if status == 'OK':
            for warning in analysis['warnings']:
                if warning.get('interface') == iface:
                    status = 'WARN'
                    break

        if warn_only and status == 'OK':
            continue

        print(f"{iface:<15} {info['mtu']:>6} {info['mtu_class']:<12} {info['type']:<10} {info['operstate']:<8} {status:<10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Detect MTU mismatches across network interfaces",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Check all interfaces for MTU issues
  %(prog)s --expected 9000        Verify all interfaces have MTU 9000
  %(prog)s --jumbo-expected       Warn if high-speed links lack jumbo frames
  %(prog)s --format json          Output in JSON for monitoring systems
  %(prog)s --verbose              Show detailed interface information
  %(prog)s --warn-only            Only show issues and warnings

Common MTU values:
  1500  - Standard Ethernet (default)
  9000  - Jumbo frames (common for 10G+)
  9216  - Extended jumbo (some vendors)

MTU issues can cause:
  - Packet fragmentation (performance loss)
  - Silent packet drops (jumbo frames on standard network)
  - TCP PMTUD failures (black hole connections)
  - Inconsistent behavior across hosts

Exit codes:
  0 - No MTU issues detected
  1 - MTU mismatches or issues found
  2 - Usage error or system requirements not met
"""
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed interface information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show issues and warnings'
    )

    parser.add_argument(
        '--expected',
        type=int,
        metavar='MTU',
        help='Expected MTU value for all interfaces'
    )

    parser.add_argument(
        '--jumbo-expected',
        action='store_true',
        help='Expect jumbo frames on high-speed (10G+) interfaces'
    )

    args = parser.parse_args()

    # Validate expected MTU
    if args.expected is not None:
        if args.expected < 68 or args.expected > 65535:
            print("Error: --expected MTU must be between 68 and 65535", file=sys.stderr)
            sys.exit(2)

    # Check for sysfs
    if not os.path.isdir('/sys/class/net'):
        print("Error: /sys/class/net not available", file=sys.stderr)
        print("This script requires a Linux system with sysfs", file=sys.stderr)
        sys.exit(2)

    # Analyze interfaces
    analysis = analyze_interfaces(
        expected_mtu=args.expected,
        jumbo_expected=args.jumbo_expected
    )

    # Output results
    if args.format == 'json':
        output_json(analysis)
    elif args.format == 'table':
        output_table(analysis, args.warn_only)
    else:
        output_plain(analysis, args.verbose, args.warn_only)

    # Determine exit code
    if analysis['issues']:
        sys.exit(1)
    elif analysis['warnings']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
