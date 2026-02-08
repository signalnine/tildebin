#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [network, lacp, bonding, link-aggregation, health]
#   requires: []
#   privilege: user
#   related: [bond_health_monitor, nic_link_speed, link_flap]
#   brief: Detailed LACP bond health including partner and PDU analysis

"""
Detailed LACP bond health including partner and PDU analysis.

Goes beyond basic bond health to examine LACP-specific details: partner MAC
consistency across slaves, aggregator ID alignment, and MII link status.
Misconfigured switch LAGs often show as inconsistent partner MACs.

Reads from /proc/net/bonding/* files.

Exit codes:
    0 - All LACP bonds healthy or no bonds found
    1 - LACP issues detected
    2 - Error or missing dependencies
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_bonding_file(content: str) -> dict[str, Any]:
    """Parse a /proc/net/bonding/* file.

    Returns dict with mode, lacp_rate, and list of slaves.
    """
    result: dict[str, Any] = {
        'mode': '',
        'lacp_rate': '',
        'slaves': [],
    }

    # Parse bonding mode
    mode_match = re.search(r'Bonding Mode:\s*(.+)', content)
    if mode_match:
        result['mode'] = mode_match.group(1).strip()

    # Parse LACP rate
    lacp_match = re.search(r'LACP rate:\s*(\w+)', content)
    if lacp_match:
        result['lacp_rate'] = lacp_match.group(1).strip()

    # Parse slave sections
    slave_blocks = re.split(r'Slave Interface:\s*', content)[1:]
    for block in slave_blocks:
        slave: dict[str, Any] = {}

        # Interface name is the first line
        lines = block.strip().split('\n')
        if lines:
            slave['interface'] = lines[0].strip()

        # MII Status
        mii_match = re.search(r'MII Status:\s*(\w+)', block)
        if mii_match:
            slave['mii_status'] = mii_match.group(1).strip()

        # Aggregator ID
        agg_match = re.search(r'Aggregator ID:\s*(\d+)', block)
        if agg_match:
            slave['aggregator_id'] = int(agg_match.group(1))

        # Partner Mac Address
        partner_match = re.search(r'Partner Mac Address:\s*([\da-fA-F:]+)', block)
        if partner_match:
            slave['partner_mac'] = partner_match.group(1).strip().lower()

        result['slaves'].append(slave)

    return result


def analyze_bond(name: str, bond: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze a single bond for LACP health issues.

    Returns list of issue dicts.
    """
    issues = []
    slaves = bond['slaves']

    # Check if this is LACP mode
    if '802.3ad' not in bond['mode']:
        issues.append({
            'severity': 'INFO',
            'type': 'non_lacp',
            'bond': name,
            'message': f"{name}: bonding mode is '{bond['mode']}' (not LACP/802.3ad)",
        })
        return issues

    if not slaves:
        return issues

    # Check MII status
    for slave in slaves:
        if slave.get('mii_status', '').lower() == 'down':
            issues.append({
                'severity': 'CRITICAL',
                'type': 'slave_down',
                'bond': name,
                'slave': slave.get('interface', 'unknown'),
                'message': f"{name}: slave {slave.get('interface', 'unknown')} MII Status is down",
            })

    # Check Partner Mac consistency
    partner_macs = set()
    for slave in slaves:
        mac = slave.get('partner_mac')
        if mac and mac != '00:00:00:00:00:00':
            partner_macs.add(mac)

    if len(partner_macs) > 1:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'partner_mac_mismatch',
            'bond': name,
            'partner_macs': sorted(partner_macs),
            'message': (
                f"{name}: inconsistent Partner Mac across slaves: "
                f"{', '.join(sorted(partner_macs))} (switch LAG misconfigured?)"
            ),
        })

    # Check Aggregator ID consistency
    agg_ids = set()
    for slave in slaves:
        agg_id = slave.get('aggregator_id')
        if agg_id is not None:
            agg_ids.add(agg_id)

    if len(agg_ids) > 1:
        issues.append({
            'severity': 'WARNING',
            'type': 'split_aggregation',
            'bond': name,
            'aggregator_ids': sorted(agg_ids),
            'message': (
                f"{name}: split aggregation detected, "
                f"Aggregator IDs: {sorted(agg_ids)}"
            ),
        })

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Detailed LACP bond health including partner and PDU analysis"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all slave details")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Find bond interfaces
    bond_files = context.glob('*', '/proc/net/bonding')

    if not bond_files:
        output.emit({'bonds': [], 'issues': []})
        output.set_summary("no bond interfaces found")
        output.render(opts.format, "LACP Bond Health")
        return 0

    all_bonds = []
    all_issues: list[dict[str, Any]] = []

    for bond_path in sorted(bond_files):
        bond_name = bond_path.split('/')[-1]
        try:
            content = context.read_file(bond_path)
        except Exception:
            continue

        bond = parse_bonding_file(content)
        bond['name'] = bond_name
        bond_issues = analyze_bond(bond_name, bond)

        all_bonds.append(bond)
        all_issues.extend(bond_issues)

    output.emit({'bonds': all_bonds, 'issues': all_issues})

    # Summary
    critical = sum(1 for i in all_issues if i['severity'] == 'CRITICAL')
    warning = sum(1 for i in all_issues if i['severity'] == 'WARNING')
    if critical > 0:
        output.set_summary(f"{len(all_bonds)} bonds, {critical} critical, {warning} warnings")
    elif warning > 0:
        output.set_summary(f"{len(all_bonds)} bonds, {warning} warnings")
    else:
        output.set_summary(f"{len(all_bonds)} bonds, all healthy")

    output.render(opts.format, "LACP Bond Health")

    has_issues = any(i['severity'] in ('CRITICAL', 'WARNING') for i in all_issues)
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
