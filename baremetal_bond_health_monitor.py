#!/usr/bin/env python3
"""
Monitor network bond health and detect configuration issues.

This script provides comprehensive monitoring of network bonding interfaces,
including bond mode verification, slave health tracking, failover readiness,
and detailed diagnostics for troubleshooting bond-related issues.

Exit codes:
    0 - All bonds healthy
    1 - Bond degradation or errors detected
    2 - Missing dependencies or usage error
"""

import argparse
import json
import os
import re
import subprocess
import sys


def run_command(cmd):
    """Execute a command and return output"""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def check_bonding_available():
    """Check if bonding module is loaded"""
    if not os.path.exists("/proc/net/bonding"):
        return False
    return True


def get_bond_list():
    """Get list of all bonded interfaces"""
    if not os.path.exists("/proc/net/bonding"):
        return []

    try:
        bonds = os.listdir("/proc/net/bonding")
        return [b for b in bonds if b != ".." and b != "."]
    except Exception:
        return []


def parse_bond_file(bond_name):
    """Parse /proc/net/bonding/<bond> file for detailed information"""
    bond_file = f"/proc/net/bonding/{bond_name}"

    if not os.path.exists(bond_file):
        return None

    try:
        with open(bond_file, 'r') as f:
            content = f.read()
    except Exception as e:
        return None

    bond_info = {
        'name': bond_name,
        'mode': 'unknown',
        'mii_status': 'unknown',
        'mii_polling_interval': 0,
        'slaves': [],
        'primary': None,
        'active_slave': None,
        'errors': [],
        'warnings': []
    }

    # Parse bonding mode
    mode_match = re.search(r'Bonding Mode:\s*([^\n]+)', content)
    if mode_match:
        bond_info['mode'] = mode_match.group(1).strip()

    # Parse MII status
    mii_match = re.search(r'^MII Status:\s*(\w+)', content, re.MULTILINE)
    if mii_match:
        bond_info['mii_status'] = mii_match.group(1).strip()

    # Parse MII polling interval
    interval_match = re.search(r'MII Polling Interval \(ms\):\s*(\d+)', content)
    if interval_match:
        bond_info['mii_polling_interval'] = int(interval_match.group(1))

    # Parse primary slave
    primary_match = re.search(r'Primary Slave:\s*(\S+)', content)
    if primary_match:
        primary = primary_match.group(1).strip()
        if primary != 'None':
            bond_info['primary'] = primary

    # Parse currently active slave
    active_match = re.search(r'Currently Active Slave:\s*(\S+)', content)
    if active_match:
        active = active_match.group(1).strip()
        if active != 'None':
            bond_info['active_slave'] = active

    # Parse slave interfaces
    slave_pattern = r'Slave Interface:\s*(\S+).*?MII Status:\s*(\w+)'
    for match in re.finditer(slave_pattern, content, re.DOTALL):
        slave_name = match.group(1).strip()
        slave_status = match.group(2).strip()

        # Get additional slave details
        slave_section_start = match.start()
        next_slave_match = re.search(r'Slave Interface:', content[slave_section_start + 1:])
        if next_slave_match:
            slave_section_end = slave_section_start + 1 + next_slave_match.start()
        else:
            slave_section_end = len(content)

        slave_section = content[slave_section_start:slave_section_end]

        # Parse link failure count
        link_failure_match = re.search(r'Link Failure Count:\s*(\d+)', slave_section)
        link_failure_count = int(link_failure_match.group(1)) if link_failure_match else 0

        # Parse speed and duplex
        speed_match = re.search(r'Speed:\s*(\S+)', slave_section)
        speed = speed_match.group(1) if speed_match else 'Unknown'

        duplex_match = re.search(r'Duplex:\s*(\S+)', slave_section)
        duplex = duplex_match.group(1) if duplex_match else 'Unknown'

        slave_info = {
            'name': slave_name,
            'status': slave_status,
            'link_failure_count': link_failure_count,
            'speed': speed,
            'duplex': duplex
        }

        bond_info['slaves'].append(slave_info)

    return bond_info


def analyze_bond_health(bond_info):
    """Analyze bond health and add warnings/errors"""
    if not bond_info:
        return bond_info

    # Check MII status
    if bond_info['mii_status'] != 'up':
        bond_info['errors'].append(f"Bond MII status is {bond_info['mii_status']}")

    # Check if any slaves exist
    if len(bond_info['slaves']) == 0:
        bond_info['errors'].append("No slave interfaces configured")
        return bond_info

    # Count active slaves
    active_slaves = [s for s in bond_info['slaves'] if s['status'] == 'up']
    down_slaves = [s for s in bond_info['slaves'] if s['status'] != 'up']

    # Check for down slaves
    if len(down_slaves) > 0:
        for slave in down_slaves:
            bond_info['warnings'].append(f"Slave {slave['name']} is {slave['status']}")

    # Check for link failures
    for slave in bond_info['slaves']:
        if slave['link_failure_count'] > 0:
            bond_info['warnings'].append(
                f"Slave {slave['name']} has {slave['link_failure_count']} link failures"
            )

    # Check for speed/duplex mismatches
    speeds = [s['speed'] for s in active_slaves if s['speed'] != 'Unknown']
    duplexes = [s['duplex'] for s in active_slaves if s['duplex'] != 'Unknown']

    if len(set(speeds)) > 1:
        bond_info['warnings'].append(
            f"Speed mismatch detected: {', '.join(set(speeds))}"
        )

    if len(set(duplexes)) > 1:
        bond_info['warnings'].append(
            f"Duplex mismatch detected: {', '.join(set(duplexes))}"
        )

    # Mode-specific checks
    if 'active-backup' in bond_info['mode'].lower():
        if len(active_slaves) == 0:
            bond_info['errors'].append("No active slaves in active-backup mode")
        elif len(active_slaves) < len(bond_info['slaves']):
            bond_info['warnings'].append(
                f"Only {len(active_slaves)}/{len(bond_info['slaves'])} slaves active"
            )

    elif '802.3ad' in bond_info['mode'].lower() or 'lacp' in bond_info['mode'].lower():
        # LACP mode requires at least 2 slaves
        if len(bond_info['slaves']) < 2:
            bond_info['warnings'].append("LACP mode should have at least 2 slaves")

        if len(active_slaves) < 2:
            bond_info['warnings'].append(
                f"Only {len(active_slaves)} active slaves in LACP mode"
            )

    # Check MII polling interval
    if bond_info['mii_polling_interval'] == 0:
        bond_info['warnings'].append("MII polling disabled (interval = 0)")
    elif bond_info['mii_polling_interval'] > 1000:
        bond_info['warnings'].append(
            f"MII polling interval is high ({bond_info['mii_polling_interval']}ms)"
        )

    return bond_info


def output_plain(bonds, verbose=False, warn_only=False):
    """Output results in plain text format"""
    print("Network Bond Health Monitor")
    print("=" * 80)
    print()

    if not bonds:
        print("No bonded interfaces found")
        print()
        print("To create a bond interface:")
        print("  1. Load bonding module: modprobe bonding")
        print("  2. Configure in /etc/network/interfaces or use NetworkManager")
        return

    for bond in bonds:
        # Skip if warn-only and no issues
        if warn_only and not bond['errors'] and not bond['warnings']:
            continue

        # Determine status symbol
        if bond['errors']:
            status_symbol = "✗"
            status_text = "ERROR"
        elif bond['warnings']:
            status_symbol = "⚠"
            status_text = "WARNING"
        else:
            status_symbol = "✓"
            status_text = "HEALTHY"

        # Print bond header
        print(f"{status_symbol} {bond['name']} - {status_text}")
        print(f"  Mode: {bond['mode']}")
        print(f"  MII Status: {bond['mii_status']}")
        print(f"  Slaves: {len(bond['slaves'])} total, "
              f"{len([s for s in bond['slaves'] if s['status'] == 'up'])} active")

        if bond['active_slave']:
            print(f"  Active Slave: {bond['active_slave']}")

        if bond['primary']:
            print(f"  Primary: {bond['primary']}")

        # Print errors
        if bond['errors']:
            print(f"  ERRORS:")
            for error in bond['errors']:
                print(f"    • {error}")

        # Print warnings
        if bond['warnings']:
            print(f"  WARNINGS:")
            for warning in bond['warnings']:
                print(f"    • {warning}")

        # Print slave details in verbose mode
        if verbose:
            print(f"  Slave Details:")
            for slave in bond['slaves']:
                status_marker = "✓" if slave['status'] == 'up' else "✗"
                print(f"    {status_marker} {slave['name']}: {slave['status']} - "
                      f"{slave['speed']} {slave['duplex']} - "
                      f"{slave['link_failure_count']} link failures")

        print()


def output_json(bonds):
    """Output results in JSON format"""
    print(json.dumps(bonds, indent=2))


def output_table(bonds):
    """Output results in table format"""
    # Header
    print(f"{'Bond':<12} {'Status':<10} {'Mode':<20} {'Slaves':<8} {'Active':<8} {'Issues':<10}")
    print("-" * 80)

    for bond in bonds:
        # Determine status
        if bond['errors']:
            status = "ERROR"
        elif bond['warnings']:
            status = "WARNING"
        else:
            status = "HEALTHY"

        # Count issues
        issue_count = len(bond['errors']) + len(bond['warnings'])

        # Count active slaves
        active_count = len([s for s in bond['slaves'] if s['status'] == 'up'])

        print(f"{bond['name']:<12} {status:<10} {bond['mode']:<20} "
              f"{len(bond['slaves']):<8} {active_count:<8} {issue_count:<10}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Monitor network bond health and detect configuration issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Check all bonds
  %(prog)s -b bond0           # Check specific bond
  %(prog)s -v                 # Verbose output with slave details
  %(prog)s --format json      # JSON output for monitoring systems
  %(prog)s --warn-only        # Only show bonds with issues
        """
    )

    parser.add_argument(
        "-b", "--bond",
        help="Specific bond interface to check (e.g., bond0)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed slave information"
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show bonds with warnings or errors"
    )

    args = parser.parse_args()

    # Check if bonding is available
    if not check_bonding_available():
        print("Error: Network bonding not available", file=sys.stderr)
        print("Ensure bonding module is loaded: modprobe bonding", file=sys.stderr)
        sys.exit(2)

    # Get bond list
    if args.bond:
        bonds_to_check = [args.bond]
    else:
        bonds_to_check = get_bond_list()

    # Parse and analyze bonds
    bond_results = []
    for bond_name in bonds_to_check:
        bond_info = parse_bond_file(bond_name)
        if bond_info:
            bond_info = analyze_bond_health(bond_info)
            bond_results.append(bond_info)

    # Output results
    if args.format == "json":
        output_json(bond_results)
    elif args.format == "table":
        output_table(bond_results)
    else:  # plain
        output_plain(bond_results, verbose=args.verbose, warn_only=args.warn_only)

    # Determine exit code
    has_errors = any(bond['errors'] for bond in bond_results)
    has_warnings = any(bond['warnings'] for bond in bond_results)

    if has_errors or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
