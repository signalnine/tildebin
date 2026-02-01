#!/usr/bin/env python3
"""
Audit network interface driver settings, offloads, and ring buffers using ethtool.

This script checks for common network performance issues caused by:
- Mismatched driver versions across interfaces
- Disabled performance-critical offloads (TSO, GSO, GRO, etc.)
- Suboptimal ring buffer sizes that could cause packet drops
- MTU inconsistencies across bonded interfaces
- Missing or disabled checksum offloading

Useful for large-scale baremetal environments where network performance
issues often stem from inconsistent driver/firmware configurations.

Exit codes:
    0 - All interfaces healthy, no issues detected
    1 - Warnings or issues detected (suboptimal settings, inconsistencies)
    2 - Usage error or ethtool not available
"""

import argparse
import subprocess
import sys
import json
import re
from collections import defaultdict


def run_command(cmd):
    """Execute a command and return output"""
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
    """Check if ethtool is available"""
    returncode, _, _ = run_command(['which', 'ethtool'])
    return returncode == 0


def get_physical_interfaces():
    """Get list of physical network interfaces (excluding virtual)"""
    returncode, stdout, stderr = run_command(['ip', 'link', 'show'])
    if returncode != 0:
        return []

    interfaces = []
    for line in stdout.split('\n'):
        # Match lines like "2: eth0: <BROADCAST..."
        match = re.match(r'^\d+:\s+([^:@]+)', line)
        if match:
            iface = match.group(1).strip()
            # Skip loopback, virtual, and container interfaces
            if iface in ['lo']:
                continue
            if iface.startswith(('veth', 'docker', 'br-', 'virbr', 'vnet')):
                continue
            interfaces.append(iface)

    return interfaces


def get_driver_info(iface):
    """Get driver information for an interface"""
    returncode, stdout, stderr = run_command(['ethtool', '-i', iface])
    if returncode != 0:
        return None

    info = {}
    for line in stdout.split('\n'):
        if ':' in line:
            key, _, value = line.partition(':')
            info[key.strip().lower().replace(' ', '_')] = value.strip()

    return info


def get_offload_settings(iface):
    """Get offload settings for an interface"""
    returncode, stdout, stderr = run_command(['ethtool', '-k', iface])
    if returncode != 0:
        return None

    offloads = {}
    for line in stdout.split('\n'):
        if ':' in line:
            key, _, value = line.partition(':')
            key = key.strip()
            value = value.strip()
            # Parse value, handling "[fixed]" and "[not requested]" annotations
            is_on = value.startswith('on')
            is_fixed = '[fixed]' in value
            offloads[key] = {
                'enabled': is_on,
                'fixed': is_fixed,
                'raw': value
            }

    return offloads


def get_ring_buffer_settings(iface):
    """Get ring buffer settings for an interface"""
    returncode, stdout, stderr = run_command(['ethtool', '-g', iface])
    if returncode != 0:
        return None

    settings = {
        'preset_max': {},
        'current': {}
    }

    section = None
    for line in stdout.split('\n'):
        line = line.strip()
        if 'Pre-set maximums' in line:
            section = 'preset_max'
        elif 'Current hardware settings' in line:
            section = 'current'
        elif section and ':' in line:
            key, _, value = line.partition(':')
            key = key.strip().lower()
            try:
                settings[section][key] = int(value.strip())
            except ValueError:
                settings[section][key] = value.strip()

    return settings


def get_link_settings(iface):
    """Get link settings (speed, duplex, etc.) for an interface"""
    returncode, stdout, stderr = run_command(['ethtool', iface])
    if returncode != 0:
        return None

    settings = {}
    for line in stdout.split('\n'):
        if ':' in line:
            key, _, value = line.partition(':')
            key = key.strip().lower().replace(' ', '_')
            settings[key] = value.strip()

    return settings


def get_interface_mtu(iface):
    """Get MTU for an interface"""
    returncode, stdout, stderr = run_command(['ip', 'link', 'show', iface])
    if returncode != 0:
        return None

    match = re.search(r'mtu\s+(\d+)', stdout)
    if match:
        return int(match.group(1))
    return None


def get_bond_members(iface):
    """Get member interfaces of a bond"""
    try:
        with open(f'/sys/class/net/{iface}/bonding/slaves', 'r') as f:
            return f.read().strip().split()
    except (FileNotFoundError, IOError):
        return []


def is_bond_interface(iface):
    """Check if interface is a bond master"""
    try:
        with open(f'/sys/class/net/{iface}/bonding/slaves', 'r'):
            return True
    except (FileNotFoundError, IOError):
        return False


def audit_interface(iface, verbose=False):
    """Audit a single interface and return findings"""
    findings = {
        'interface': iface,
        'issues': [],
        'warnings': [],
        'info': {}
    }

    # Get driver info
    driver_info = get_driver_info(iface)
    if driver_info:
        findings['info']['driver'] = driver_info.get('driver', 'unknown')
        findings['info']['version'] = driver_info.get('version', 'unknown')
        findings['info']['firmware_version'] = driver_info.get('firmware-version', 'unknown')
    else:
        findings['warnings'].append('Could not retrieve driver information')

    # Get link settings
    link_settings = get_link_settings(iface)
    if link_settings:
        speed = link_settings.get('speed', 'Unknown')
        duplex = link_settings.get('duplex', 'Unknown')
        findings['info']['speed'] = speed
        findings['info']['duplex'] = duplex

        # Check for half-duplex (almost always a problem)
        if duplex.lower() == 'half':
            findings['issues'].append(f'Half-duplex detected - likely autonegotiation mismatch')

        # Check for link down
        if link_settings.get('link_detected', '').lower() == 'no':
            findings['issues'].append('Link not detected')

    # Get MTU
    mtu = get_interface_mtu(iface)
    if mtu:
        findings['info']['mtu'] = mtu

    # Get offload settings
    offloads = get_offload_settings(iface)
    if offloads:
        findings['info']['offloads'] = {}

        # Critical offloads that should typically be enabled for performance
        critical_offloads = [
            ('tcp-segmentation-offload', 'TSO'),
            ('generic-segmentation-offload', 'GSO'),
            ('generic-receive-offload', 'GRO'),
            ('rx-checksumming', 'RX checksum'),
            ('tx-checksumming', 'TX checksum'),
            ('scatter-gather', 'Scatter-gather'),
        ]

        for offload_key, offload_name in critical_offloads:
            if offload_key in offloads:
                offload = offloads[offload_key]
                findings['info']['offloads'][offload_key] = offload['enabled']

                if not offload['enabled'] and not offload['fixed']:
                    findings['warnings'].append(
                        f'{offload_name} ({offload_key}) is disabled - may impact performance'
                    )

        # Check for LRO which can cause issues with routing/bridging
        if 'large-receive-offload' in offloads:
            lro = offloads['large-receive-offload']
            if lro['enabled']:
                findings['warnings'].append(
                    'LRO enabled - may cause issues with routing/bridging/forwarding'
                )

    # Get ring buffer settings
    ring_settings = get_ring_buffer_settings(iface)
    if ring_settings and ring_settings.get('preset_max') and ring_settings.get('current'):
        findings['info']['ring_buffers'] = ring_settings

        # Check if RX ring is significantly below maximum
        max_rx = ring_settings['preset_max'].get('rx', 0)
        current_rx = ring_settings['current'].get('rx', 0)

        if isinstance(max_rx, int) and isinstance(current_rx, int) and max_rx > 0:
            rx_ratio = current_rx / max_rx
            if rx_ratio < 0.5:
                findings['warnings'].append(
                    f'RX ring buffer at {current_rx}/{max_rx} ({rx_ratio:.0%}) - '
                    f'consider increasing to reduce packet drops under load'
                )

        # Check TX ring similarly
        max_tx = ring_settings['preset_max'].get('tx', 0)
        current_tx = ring_settings['current'].get('tx', 0)

        if isinstance(max_tx, int) and isinstance(current_tx, int) and max_tx > 0:
            tx_ratio = current_tx / max_tx
            if tx_ratio < 0.5:
                findings['warnings'].append(
                    f'TX ring buffer at {current_tx}/{max_tx} ({tx_ratio:.0%}) - '
                    f'consider increasing for high-throughput workloads'
                )

    return findings


def check_driver_consistency(all_findings):
    """Check for driver version inconsistencies across similar interfaces"""
    issues = []

    # Group by driver
    driver_versions = defaultdict(list)
    for finding in all_findings:
        driver = finding['info'].get('driver', 'unknown')
        version = finding['info'].get('version', 'unknown')
        if driver != 'unknown':
            driver_versions[driver].append({
                'interface': finding['interface'],
                'version': version
            })

    # Check for version mismatches within same driver
    for driver, interfaces in driver_versions.items():
        versions = set(i['version'] for i in interfaces)
        if len(versions) > 1:
            iface_list = ', '.join(f"{i['interface']}={i['version']}" for i in interfaces)
            issues.append(
                f'Driver {driver} has version inconsistency: {iface_list}'
            )

    return issues


def check_bond_mtu_consistency(all_findings):
    """Check for MTU mismatches in bond interfaces"""
    issues = []

    for finding in all_findings:
        iface = finding['interface']
        if is_bond_interface(iface):
            bond_mtu = finding['info'].get('mtu')
            members = get_bond_members(iface)

            member_mtus = {}
            for member in members:
                member_mtu = get_interface_mtu(member)
                if member_mtu:
                    member_mtus[member] = member_mtu

            # Check for mismatches
            if bond_mtu and member_mtus:
                mismatched = [
                    f"{m}={mtu}"
                    for m, mtu in member_mtus.items()
                    if mtu != bond_mtu
                ]
                if mismatched:
                    issues.append(
                        f'Bond {iface} (MTU={bond_mtu}) has members with different MTUs: '
                        f'{", ".join(mismatched)}'
                    )

    return issues


def output_plain(all_findings, global_issues, warn_only=False, verbose=False):
    """Output results in plain text format"""
    has_issues = False

    print("Network Interface Ethtool Audit")
    print("=" * 70)
    print()

    # Global issues first
    if global_issues:
        print("GLOBAL ISSUES:")
        for issue in global_issues:
            print(f"  [!] {issue}")
        print()
        has_issues = True

    # Per-interface findings
    for finding in all_findings:
        iface = finding['interface']
        issues = finding['issues']
        warnings = finding['warnings']
        info = finding['info']

        # Skip healthy interfaces if warn_only
        if warn_only and not issues and not warnings:
            continue

        # Determine status symbol
        if issues:
            symbol = "X"
            status = "ISSUES"
            has_issues = True
        elif warnings:
            symbol = "!"
            status = "WARNINGS"
            has_issues = True
        else:
            symbol = "OK"
            status = "HEALTHY"

        # Header line
        driver = info.get('driver', 'unknown')
        version = info.get('version', '')
        speed = info.get('speed', 'N/A')
        print(f"[{symbol}] {iface} - {status}")
        print(f"    Driver: {driver} {version}")
        print(f"    Speed: {speed}, MTU: {info.get('mtu', 'N/A')}")

        # Ring buffers if verbose or issues
        if verbose and 'ring_buffers' in info:
            rb = info['ring_buffers']
            current = rb.get('current', {})
            preset = rb.get('preset_max', {})
            rx_cur = current.get('rx', 'N/A')
            rx_max = preset.get('rx', 'N/A')
            tx_cur = current.get('tx', 'N/A')
            tx_max = preset.get('tx', 'N/A')
            print(f"    Ring buffers: RX={rx_cur}/{rx_max}, TX={tx_cur}/{tx_max}")

        # Offloads if verbose
        if verbose and 'offloads' in info:
            offloads = info['offloads']
            enabled = [k for k, v in offloads.items() if v]
            disabled = [k for k, v in offloads.items() if not v]
            if enabled:
                print(f"    Offloads ON: {', '.join(enabled[:5])}")
            if disabled:
                print(f"    Offloads OFF: {', '.join(disabled[:5])}")

        # Issues
        for issue in issues:
            print(f"    [ISSUE] {issue}")

        # Warnings
        for warning in warnings:
            print(f"    [WARN] {warning}")

        print()

    # Summary
    total = len(all_findings)
    with_issues = sum(1 for f in all_findings if f['issues'])
    with_warnings = sum(1 for f in all_findings if f['warnings'] and not f['issues'])
    healthy = total - with_issues - with_warnings

    print("-" * 70)
    print(f"Summary: {total} interfaces - {healthy} healthy, {with_warnings} warnings, {with_issues} issues")

    return has_issues


def output_json(all_findings, global_issues):
    """Output results in JSON format"""
    result = {
        'global_issues': global_issues,
        'interfaces': all_findings,
        'summary': {
            'total': len(all_findings),
            'with_issues': sum(1 for f in all_findings if f['issues']),
            'with_warnings': sum(1 for f in all_findings if f['warnings']),
            'healthy': sum(1 for f in all_findings if not f['issues'] and not f['warnings'])
        }
    }
    print(json.dumps(result, indent=2))

    return bool(global_issues) or any(f['issues'] or f['warnings'] for f in all_findings)


def main():
    parser = argparse.ArgumentParser(
        description="Audit network interface driver settings, offloads, and ring buffers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Audit all physical interfaces
  %(prog)s -i eth0            # Audit specific interface
  %(prog)s --format json      # Output in JSON format
  %(prog)s -v                 # Verbose output with ring buffer details
  %(prog)s --warn-only        # Only show interfaces with issues

Exit codes:
  0 - All interfaces healthy
  1 - Warnings or issues detected
  2 - ethtool not available or usage error
"""
    )

    parser.add_argument(
        "-i", "--interface",
        help="Specific interface to audit (default: all physical interfaces)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including all offloads and ring buffers"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: %(default)s)"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show interfaces with warnings or issues"
    )

    args = parser.parse_args()

    # Check for ethtool
    if not check_ethtool_available():
        print("Error: ethtool not found in PATH", file=sys.stderr)
        print("Install with: sudo apt-get install ethtool", file=sys.stderr)
        sys.exit(2)

    # Get interfaces to audit
    if args.interface:
        interfaces = [args.interface]
    else:
        interfaces = get_physical_interfaces()

    if not interfaces:
        print("No network interfaces found to audit")
        sys.exit(0)

    # Audit each interface
    all_findings = []
    for iface in interfaces:
        finding = audit_interface(iface, verbose=args.verbose)
        all_findings.append(finding)

    # Check for global issues (cross-interface)
    global_issues = []
    global_issues.extend(check_driver_consistency(all_findings))
    global_issues.extend(check_bond_mtu_consistency(all_findings))

    # Output results
    if args.format == "json":
        has_issues = output_json(all_findings, global_issues)
    else:
        has_issues = output_plain(
            all_findings,
            global_issues,
            warn_only=args.warn_only,
            verbose=args.verbose
        )

    # Exit with appropriate code
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
