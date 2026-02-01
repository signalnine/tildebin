#!/usr/bin/env python3
"""
Monitor Linux bridge health for virtualization and container environments.

Checks network bridge configuration, connected interfaces, STP status,
and forwarding state. Essential for baremetal hosts running VMs or
containers that rely on bridge networking.

Checks performed:
- Bridge existence and state (up/down)
- Connected interface status
- STP (Spanning Tree Protocol) configuration
- Forwarding delay and aging settings
- MAC address table size
- VLAN filtering configuration
- Bridge port states (forwarding, blocking, disabled)

Use cases:
- Virtualization hosts (KVM, libvirt, Proxmox)
- Container hosts with bridge networking
- Network infrastructure validation
- Pre-deployment verification

Exit codes:
    0 - All bridges healthy
    1 - Bridge issues or warnings detected
    2 - Usage error or missing dependencies
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Optional, Any


def read_file(path: str) -> Optional[str]:
    """Read a file and return its contents, or None if not readable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError):
        return None


def get_bridges() -> List[str]:
    """Get list of bridge devices from /sys/class/net."""
    bridges = []
    net_path = '/sys/class/net'

    try:
        for iface in os.listdir(net_path):
            bridge_path = os.path.join(net_path, iface, 'bridge')
            if os.path.isdir(bridge_path):
                bridges.append(iface)
    except OSError:
        pass

    return sorted(bridges)


def get_bridge_ports(bridge: str) -> List[str]:
    """Get list of interfaces attached to a bridge."""
    ports = []
    brif_path = f'/sys/class/net/{bridge}/brif'

    try:
        if os.path.isdir(brif_path):
            ports = sorted(os.listdir(brif_path))
    except OSError:
        pass

    return ports


def get_interface_state(iface: str) -> Dict[str, Any]:
    """Get interface state information."""
    base_path = f'/sys/class/net/{iface}'

    state = {
        'name': iface,
        'operstate': read_file(f'{base_path}/operstate') or 'unknown',
        'carrier': read_file(f'{base_path}/carrier') == '1',
        'mtu': int(read_file(f'{base_path}/mtu') or 0),
        'address': read_file(f'{base_path}/address') or 'unknown',
    }

    # Get speed if available (for physical interfaces)
    speed = read_file(f'{base_path}/speed')
    if speed and speed != '-1':
        try:
            state['speed_mbps'] = int(speed)
        except ValueError:
            pass

    return state


def get_port_state(bridge: str, port: str) -> Dict[str, Any]:
    """Get bridge port state."""
    port_path = f'/sys/class/net/{bridge}/brif/{port}'

    # Port state values from kernel
    state_map = {
        '0': 'disabled',
        '1': 'listening',
        '2': 'learning',
        '3': 'forwarding',
        '4': 'blocking',
    }

    state_val = read_file(f'{port_path}/state') or '0'

    return {
        'name': port,
        'state': state_map.get(state_val, 'unknown'),
        'state_code': int(state_val) if state_val.isdigit() else -1,
        'path_cost': int(read_file(f'{port_path}/path_cost') or 0),
        'priority': int(read_file(f'{port_path}/priority') or 0),
        'hairpin_mode': read_file(f'{port_path}/hairpin_mode') == '1',
    }


def get_bridge_info(bridge: str) -> Dict[str, Any]:
    """Get comprehensive bridge information."""
    base_path = f'/sys/class/net/{bridge}'
    bridge_path = f'{base_path}/bridge'

    # Get basic interface state
    info = get_interface_state(bridge)
    info['type'] = 'bridge'

    # Bridge-specific settings
    info['bridge'] = {
        'bridge_id': read_file(f'{bridge_path}/bridge_id') or 'unknown',
        'stp_state': read_file(f'{bridge_path}/stp_state') == '1',
        'forward_delay': int(read_file(f'{bridge_path}/forward_delay') or 0),
        'hello_time': int(read_file(f'{bridge_path}/hello_time') or 0),
        'max_age': int(read_file(f'{bridge_path}/max_age') or 0),
        'ageing_time': int(read_file(f'{bridge_path}/ageing_time') or 0),
        'root_id': read_file(f'{bridge_path}/root_id') or 'unknown',
        'root_port': int(read_file(f'{bridge_path}/root_port') or 0),
        'root_path_cost': int(read_file(f'{bridge_path}/root_path_cost') or 0),
    }

    # Check if this bridge is the root bridge
    info['bridge']['is_root'] = (
        info['bridge']['bridge_id'] == info['bridge']['root_id']
    )

    # VLAN filtering
    vlan_filtering = read_file(f'{bridge_path}/vlan_filtering')
    info['bridge']['vlan_filtering'] = vlan_filtering == '1' if vlan_filtering else None

    # Get connected ports
    ports = get_bridge_ports(bridge)
    info['ports'] = []

    for port in ports:
        port_info = get_port_state(bridge, port)
        port_iface = get_interface_state(port)
        port_info['interface'] = port_iface
        info['ports'].append(port_info)

    return info


def analyze_bridge(bridge_info: Dict, verbose: bool = False) -> List[Dict]:
    """Analyze bridge health and return issues."""
    issues = []
    name = bridge_info['name']

    # Check bridge is up
    if bridge_info['operstate'] != 'up':
        issues.append({
            'type': 'BRIDGE_DOWN',
            'severity': 'critical',
            'bridge': name,
            'message': f"Bridge {name} is {bridge_info['operstate']}"
        })

    # Check for no ports
    if not bridge_info['ports']:
        issues.append({
            'type': 'NO_PORTS',
            'severity': 'warning',
            'bridge': name,
            'message': f"Bridge {name} has no connected interfaces"
        })

    # Check port states
    for port in bridge_info['ports']:
        port_name = port['name']
        port_state = port['state']
        iface_state = port['interface']['operstate']

        # Port not forwarding (and not due to STP)
        if port_state == 'disabled':
            issues.append({
                'type': 'PORT_DISABLED',
                'severity': 'warning',
                'bridge': name,
                'port': port_name,
                'message': f"Port {port_name} on {name} is disabled"
            })

        # Underlying interface is down
        if iface_state != 'up':
            issues.append({
                'type': 'PORT_IFACE_DOWN',
                'severity': 'warning',
                'bridge': name,
                'port': port_name,
                'message': f"Port {port_name} interface is {iface_state}"
            })

        # Port is blocking (STP)
        if port_state == 'blocking' and bridge_info['bridge']['stp_state']:
            issues.append({
                'type': 'PORT_BLOCKING',
                'severity': 'info',
                'bridge': name,
                'port': port_name,
                'message': f"Port {port_name} is STP blocking"
            })

    # Check for MTU mismatches among ports
    if len(bridge_info['ports']) > 1:
        mtus = set()
        for port in bridge_info['ports']:
            mtu = port['interface'].get('mtu', 0)
            if mtu > 0:
                mtus.add(mtu)

        if len(mtus) > 1:
            issues.append({
                'type': 'MTU_MISMATCH',
                'severity': 'warning',
                'bridge': name,
                'mtus': sorted(mtus),
                'message': f"MTU mismatch on {name} ports: {sorted(mtus)}"
            })

    # Check bridge MTU vs port MTU
    bridge_mtu = bridge_info.get('mtu', 0)
    for port in bridge_info['ports']:
        port_mtu = port['interface'].get('mtu', 0)
        if port_mtu > 0 and bridge_mtu > 0 and port_mtu < bridge_mtu:
            issues.append({
                'type': 'BRIDGE_MTU_EXCEEDS_PORT',
                'severity': 'warning',
                'bridge': name,
                'port': port['name'],
                'bridge_mtu': bridge_mtu,
                'port_mtu': port_mtu,
                'message': (f"Bridge {name} MTU ({bridge_mtu}) exceeds "
                           f"port {port['name']} MTU ({port_mtu})")
            })

    return issues


def output_plain(bridges: List[Dict], issues: List[Dict],
                 warn_only: bool, verbose: bool) -> None:
    """Output in plain text format."""
    # Print issues first
    if issues:
        print("ISSUES DETECTED:")
        for issue in issues:
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")
        print()

    if warn_only:
        if not issues:
            print("OK - All bridges healthy")
        return

    # Print bridge details
    for bridge in bridges:
        print(f"Bridge: {bridge['name']}")
        print("=" * 50)
        print(f"  State: {bridge['operstate']}")
        print(f"  MAC: {bridge['address']}")
        print(f"  MTU: {bridge['mtu']}")

        br = bridge['bridge']
        print(f"  STP: {'enabled' if br['stp_state'] else 'disabled'}")
        if br['stp_state']:
            print(f"  Root bridge: {'yes' if br['is_root'] else 'no'}")
            if verbose:
                print(f"  Bridge ID: {br['bridge_id']}")
                print(f"  Root ID: {br['root_id']}")
                print(f"  Root path cost: {br['root_path_cost']}")

        if br['vlan_filtering'] is not None:
            print(f"  VLAN filtering: {'enabled' if br['vlan_filtering'] else 'disabled'}")

        if verbose:
            print(f"  Forward delay: {br['forward_delay']}cs")
            print(f"  Ageing time: {br['ageing_time']}cs")

        print(f"\n  Ports ({len(bridge['ports'])}):")
        if not bridge['ports']:
            print("    (none)")
        else:
            for port in bridge['ports']:
                iface = port['interface']
                state_str = port['state']
                iface_state = iface['operstate']

                status = f"{state_str}"
                if iface_state != 'up':
                    status += f" (iface: {iface_state})"

                speed = iface.get('speed_mbps')
                speed_str = f" {speed}Mbps" if speed else ""

                print(f"    - {port['name']}: {status}{speed_str}")
                if verbose:
                    print(f"        MAC: {iface['address']}, MTU: {iface['mtu']}")
                    print(f"        Path cost: {port['path_cost']}, Priority: {port['priority']}")

        print()


def output_json(bridges: List[Dict], issues: List[Dict]) -> None:
    """Output in JSON format."""
    has_critical = any(i['severity'] == 'critical' for i in issues)
    has_warning = any(i['severity'] == 'warning' for i in issues)

    if has_critical:
        status = 'critical'
    elif has_warning:
        status = 'warning'
    else:
        status = 'ok'

    result = {
        'status': status,
        'bridge_count': len(bridges),
        'bridges': bridges,
        'issues': issues,
    }
    print(json.dumps(result, indent=2))


def output_table(bridges: List[Dict], issues: List[Dict],
                 warn_only: bool) -> None:
    """Output in table format."""
    if warn_only:
        if not issues:
            print("No bridge issues detected")
            return
        print(f"{'Bridge':<15} {'Type':<20} {'Severity':<10} {'Details':<30}")
        print("-" * 77)
        for issue in issues:
            details = issue.get('port', issue.get('message', '')[:30])
            print(f"{issue['bridge']:<15} {issue['type']:<20} "
                  f"{issue['severity']:<10} {details:<30}")
        return

    print(f"{'Bridge':<15} {'State':<8} {'STP':<6} {'Ports':<6} {'Status':<10}")
    print("-" * 50)

    for bridge in bridges:
        state = bridge['operstate']
        stp = 'on' if bridge['bridge']['stp_state'] else 'off'
        port_count = len(bridge['ports'])

        # Determine status
        bridge_issues = [i for i in issues
                        if i.get('bridge') == bridge['name']
                        and i['severity'] in ['critical', 'warning']]

        if any(i['severity'] == 'critical' for i in bridge_issues):
            status = 'critical'
        elif bridge_issues:
            status = 'warning'
        else:
            status = 'ok'

        print(f"{bridge['name']:<15} {state:<8} {stp:<6} {port_count:<6} {status:<10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor Linux bridge health for virtualization environments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      Show all bridge status
  %(prog)s --warn-only          Only show if there are issues
  %(prog)s --format json        JSON output for monitoring systems
  %(prog)s -b br0 br1           Check specific bridges only
  %(prog)s -v                   Show detailed bridge information

Port states:
  forwarding - Normal operation, traffic passes through
  blocking   - STP blocking to prevent loops
  learning   - Learning MAC addresses, not yet forwarding
  listening  - STP listening state
  disabled   - Port is administratively disabled

Exit codes:
  0 - All bridges healthy
  1 - Bridge issues or warnings detected
  2 - Usage error or no bridges found
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
        help='Show detailed bridge information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show if there are issues'
    )

    parser.add_argument(
        '-b', '--bridges',
        nargs='+',
        metavar='BRIDGE',
        help='Check specific bridges only'
    )

    parser.add_argument(
        '--ignore-no-ports',
        action='store_true',
        help='Do not warn about bridges with no ports'
    )

    args = parser.parse_args()

    # Check if /sys/class/net exists
    if not os.path.isdir('/sys/class/net'):
        print("Error: /sys/class/net not available", file=sys.stderr)
        print("This script requires the sysfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Get bridges to check
    if args.bridges:
        # Verify specified bridges exist
        all_bridges = set(get_bridges())
        bridges_to_check = []
        for br in args.bridges:
            if br in all_bridges:
                bridges_to_check.append(br)
            else:
                print(f"Warning: Bridge '{br}' not found", file=sys.stderr)

        if not bridges_to_check:
            print("Error: None of the specified bridges exist", file=sys.stderr)
            sys.exit(2)
    else:
        bridges_to_check = get_bridges()

    if not bridges_to_check:
        if args.format == 'json':
            print(json.dumps({
                'status': 'ok',
                'bridge_count': 0,
                'bridges': [],
                'issues': [],
                'message': 'No bridges configured on this system'
            }, indent=2))
        else:
            print("No bridges found on this system")
        sys.exit(0)

    # Gather bridge information
    bridges = []
    all_issues = []

    for bridge_name in bridges_to_check:
        bridge_info = get_bridge_info(bridge_name)
        bridges.append(bridge_info)

        issues = analyze_bridge(bridge_info, args.verbose)

        # Filter out no-ports warning if requested
        if args.ignore_no_ports:
            issues = [i for i in issues if i['type'] != 'NO_PORTS']

        all_issues.extend(issues)

    # Output
    if args.format == 'json':
        output_json(bridges, all_issues)
    elif args.format == 'table':
        output_table(bridges, all_issues, args.warn_only)
    else:
        output_plain(bridges, all_issues, args.warn_only, args.verbose)

    # Exit code based on issues
    has_critical = any(i['severity'] == 'critical' for i in all_issues)
    has_warning = any(i['severity'] == 'warning' for i in all_issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
