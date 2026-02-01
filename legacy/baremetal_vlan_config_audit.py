#!/usr/bin/env python3
"""
Audit VLAN configuration and health on baremetal systems.

Detects VLAN misconfigurations that commonly cause network isolation issues:
- VLAN interfaces with parent interface down
- MTU mismatches between VLAN and parent interface
- Orphaned VLANs (parent interface no longer exists)
- VLAN ID conflicts or duplicates
- VLAN interfaces without IP addresses configured
- Carrier/link status issues

This is critical for datacenter environments where VLAN misconfigurations
can silently break network segmentation and cause hard-to-diagnose issues.

Exit codes:
    0 - All VLANs healthy (or no VLANs configured)
    1 - One or more VLANs have configuration issues
    2 - Usage error or missing dependency
"""

import argparse
import json
import os
import re
import sys


def read_file(path):
    """Safely read a file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def get_interface_operstate(iface):
    """Get the operational state of an interface."""
    state = read_file(f'/sys/class/net/{iface}/operstate')
    return state if state else 'unknown'


def get_interface_carrier(iface):
    """Check if interface has carrier (link detected)."""
    carrier = read_file(f'/sys/class/net/{iface}/carrier')
    try:
        return int(carrier) == 1
    except (TypeError, ValueError):
        return False


def get_interface_mtu(iface):
    """Get MTU of an interface."""
    mtu = read_file(f'/sys/class/net/{iface}/mtu')
    try:
        return int(mtu)
    except (TypeError, ValueError):
        return None


def get_interface_flags(iface):
    """Get interface flags (UP, BROADCAST, etc.)."""
    flags = read_file(f'/sys/class/net/{iface}/flags')
    try:
        return int(flags, 16)
    except (TypeError, ValueError):
        return 0


def interface_is_up(iface):
    """Check if interface is administratively UP."""
    flags = get_interface_flags(iface)
    # IFF_UP = 0x1
    return bool(flags & 0x1)


def get_interface_addresses(iface):
    """Get IP addresses configured on an interface."""
    addresses = []

    # Try to read from /proc/net/fib_trie or use ip command output parsing
    # For simplicity, check if address files exist in sysfs
    addr_path = f'/sys/class/net/{iface}/address'
    if os.path.exists(addr_path):
        # MAC address exists, interface is real
        pass

    # Check for IPv4 addresses by looking at routing
    # This is a simplified check - presence of interface in routes
    try:
        with open('/proc/net/route', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 1 and parts[0] == iface:
                    addresses.append('ipv4_route_present')
                    break
    except (IOError, OSError):
        pass

    # Check for IPv6 addresses
    try:
        with open('/proc/net/if_inet6', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6 and parts[5] == iface:
                    # Skip link-local addresses (fe80::)
                    addr = parts[0]
                    if not addr.startswith('fe80'):
                        addresses.append('ipv6_configured')
                        break
    except (IOError, OSError):
        pass

    return addresses


def get_vlan_interfaces():
    """
    Get all VLAN interfaces and their configuration.

    VLANs can be identified by:
    1. /proc/net/vlan/config (8021q module)
    2. Interface naming patterns (eth0.100, vlan100, etc.)
    3. Sysfs VLAN information
    """
    vlans = []

    # Method 1: Check /proc/net/vlan/config (most reliable if 8021q loaded)
    vlan_config_path = '/proc/net/vlan/config'
    if os.path.exists(vlan_config_path):
        try:
            with open(vlan_config_path, 'r') as f:
                for line in f:
                    # Format: "vlan_iface | vlan_id | parent_iface"
                    # Skip header lines
                    if '|' not in line or 'Name-Type' in line:
                        continue

                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 3:
                        vlan_iface = parts[0]
                        try:
                            vlan_id = int(parts[1])
                        except ValueError:
                            continue
                        parent_iface = parts[2]

                        vlans.append({
                            'interface': vlan_iface,
                            'vlan_id': vlan_id,
                            'parent': parent_iface,
                            'source': 'proc_vlan_config'
                        })
        except (IOError, OSError):
            pass

    # Method 2: Check sysfs for VLAN links
    net_path = '/sys/class/net'
    if os.path.exists(net_path):
        for iface in os.listdir(net_path):
            # Skip if already found via /proc/net/vlan/config
            if any(v['interface'] == iface for v in vlans):
                continue

            # Check for VLAN naming patterns
            # Pattern 1: parent.vlanid (e.g., eth0.100)
            match = re.match(r'^(.+)\.(\d+)$', iface)
            if match:
                parent = match.group(1)
                vlan_id = int(match.group(2))

                # Verify parent exists
                if os.path.exists(f'/sys/class/net/{parent}'):
                    vlans.append({
                        'interface': iface,
                        'vlan_id': vlan_id,
                        'parent': parent,
                        'source': 'naming_pattern'
                    })
                continue

            # Pattern 2: vlanXXX or VLANXXX
            match = re.match(r'^[vV][lL][aA][nN](\d+)$', iface)
            if match:
                vlan_id = int(match.group(1))
                # Try to find parent from sysfs link
                link_path = f'/sys/class/net/{iface}/lower_*'
                import glob
                lower_links = glob.glob(f'/sys/class/net/{iface}/lower_*')
                parent = None
                if lower_links:
                    parent = os.path.basename(lower_links[0]).replace('lower_', '')

                vlans.append({
                    'interface': iface,
                    'vlan_id': vlan_id,
                    'parent': parent,
                    'source': 'naming_pattern'
                })

    return vlans


def analyze_vlan(vlan):
    """Analyze a VLAN interface for configuration issues."""
    issues = []
    status = 'ok'
    info = {
        'interface': vlan['interface'],
        'vlan_id': vlan['vlan_id'],
        'parent': vlan['parent'],
        'parent_exists': False,
        'parent_up': False,
        'vlan_up': False,
        'vlan_carrier': False,
        'mtu': None,
        'parent_mtu': None,
        'has_addresses': False,
    }

    iface = vlan['interface']
    parent = vlan['parent']

    # Check if VLAN interface exists
    if not os.path.exists(f'/sys/class/net/{iface}'):
        issues.append('VLAN interface does not exist in sysfs')
        return 'error', issues, info

    # Get VLAN interface state
    info['vlan_up'] = interface_is_up(iface)
    info['vlan_carrier'] = get_interface_carrier(iface)
    info['mtu'] = get_interface_mtu(iface)
    info['operstate'] = get_interface_operstate(iface)
    info['has_addresses'] = len(get_interface_addresses(iface)) > 0

    # Check parent interface
    if parent:
        info['parent_exists'] = os.path.exists(f'/sys/class/net/{parent}')

        if not info['parent_exists']:
            issues.append(f"Parent interface '{parent}' does not exist (orphaned VLAN)")
            status = 'error'
        else:
            info['parent_up'] = interface_is_up(parent)
            info['parent_mtu'] = get_interface_mtu(parent)
            info['parent_operstate'] = get_interface_operstate(parent)

            # Check if parent is up
            if not info['parent_up']:
                issues.append(f"Parent interface '{parent}' is administratively DOWN")
                status = 'warning'

            # Check parent operstate
            if info.get('parent_operstate') == 'down':
                issues.append(f"Parent interface '{parent}' has no link")
                if status == 'ok':
                    status = 'warning'

            # Check MTU mismatch
            if info['mtu'] and info['parent_mtu']:
                if info['mtu'] > info['parent_mtu']:
                    issues.append(
                        f"VLAN MTU ({info['mtu']}) exceeds parent MTU ({info['parent_mtu']})"
                    )
                    if status == 'ok':
                        status = 'warning'
    else:
        issues.append('Could not determine parent interface')
        if status == 'ok':
            status = 'warning'

    # Check if VLAN interface is up
    if not info['vlan_up']:
        issues.append('VLAN interface is administratively DOWN')
        if status == 'ok':
            status = 'warning'

    # Check for carrier/link
    if info['vlan_up'] and not info['vlan_carrier'] and info.get('operstate') == 'down':
        issues.append('VLAN interface has no carrier (link down)')
        if status == 'ok':
            status = 'warning'

    # Check if IP addresses are configured
    if info['vlan_up'] and not info['has_addresses']:
        issues.append('VLAN interface has no IP addresses configured')
        if status == 'ok':
            status = 'info'

    return status, issues, info


def check_vlan_id_conflicts(vlans):
    """Check for duplicate VLAN IDs on the same parent interface."""
    conflicts = []

    # Group by parent
    by_parent = {}
    for vlan in vlans:
        parent = vlan.get('parent') or 'unknown'
        if parent not in by_parent:
            by_parent[parent] = []
        by_parent[parent].append(vlan)

    # Check for duplicate VLAN IDs on same parent
    for parent, vlan_list in by_parent.items():
        vlan_ids = {}
        for vlan in vlan_list:
            vid = vlan['vlan_id']
            if vid in vlan_ids:
                conflicts.append({
                    'vlan_id': vid,
                    'parent': parent,
                    'interfaces': [vlan_ids[vid], vlan['interface']]
                })
            else:
                vlan_ids[vid] = vlan['interface']

    return conflicts


def output_plain(results, conflicts, verbose=False, warn_only=False):
    """Output results in plain text format."""
    print("VLAN Configuration Audit")
    print("=" * 70)
    print()

    if not results:
        print("No VLAN interfaces found.")
        return

    issue_count = 0

    for r in results:
        if warn_only and r['status'] == 'ok':
            continue

        status_symbol = {
            'ok': '✓',
            'info': 'ℹ',
            'warning': '⚠',
            'error': '✗'
        }.get(r['status'], '?')

        vlan_id = r['info']['vlan_id']
        parent = r['info']['parent'] or 'unknown'
        mtu = r['info']['mtu'] or 'N/A'

        print(f"{status_symbol} {r['interface']}: VLAN {vlan_id} on {parent} (MTU: {mtu})")

        if r['issues']:
            issue_count += 1
            for issue in r['issues']:
                print(f"  → {issue}")

        if verbose:
            info = r['info']
            print(f"  State: {'UP' if info['vlan_up'] else 'DOWN'} "
                  f"(operstate: {info.get('operstate', 'N/A')})")
            if info['parent']:
                print(f"  Parent state: {'UP' if info['parent_up'] else 'DOWN'} "
                      f"(operstate: {info.get('parent_operstate', 'N/A')})")
                if info['parent_mtu']:
                    print(f"  Parent MTU: {info['parent_mtu']}")
            print()

    # Report conflicts
    if conflicts:
        print()
        print("VLAN ID Conflicts Detected:")
        for c in conflicts:
            print(f"  ✗ VLAN {c['vlan_id']} on {c['parent']}: "
                  f"configured on {', '.join(c['interfaces'])}")
        issue_count += len(conflicts)

    print()
    total = len(results)
    ok_count = sum(1 for r in results if r['status'] == 'ok')
    print(f"Summary: {total} VLANs checked, {ok_count} healthy, {issue_count} with issues")


def output_json(results, conflicts):
    """Output results in JSON format."""
    output = {
        'vlans': results,
        'conflicts': conflicts,
        'summary': {
            'total': len(results),
            'ok': sum(1 for r in results if r['status'] == 'ok'),
            'info': sum(1 for r in results if r['status'] == 'info'),
            'warning': sum(1 for r in results if r['status'] == 'warning'),
            'error': sum(1 for r in results if r['status'] == 'error'),
            'conflicts': len(conflicts),
        }
    }
    print(json.dumps(output, indent=2))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Audit VLAN configuration and health on baremetal systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      Audit all VLAN interfaces
  %(prog)s -v                   Show detailed VLAN information
  %(prog)s --format json        Output in JSON format
  %(prog)s -w                   Only show VLANs with issues
        """
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
        help='Show detailed VLAN information'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show VLANs with issues'
    )

    args = parser.parse_args()

    # Check that we can access sysfs
    if not os.path.exists('/sys/class/net'):
        print("Error: /sys/class/net not accessible", file=sys.stderr)
        sys.exit(2)

    # Get all VLAN interfaces
    vlans = get_vlan_interfaces()

    # Analyze each VLAN
    results = []
    has_issues = False

    for vlan in vlans:
        status, issues, info = analyze_vlan(vlan)

        result = {
            'interface': vlan['interface'],
            'status': status,
            'issues': issues,
            'info': info,
        }

        if status in ('warning', 'error'):
            has_issues = True

        results.append(result)

    # Check for VLAN ID conflicts
    conflicts = check_vlan_id_conflicts(vlans)
    if conflicts:
        has_issues = True

    # Output results
    if args.format == 'json':
        output_json(results, conflicts)
    else:
        output_plain(results, conflicts, args.verbose, args.warn_only)

    # Exit code based on findings
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
