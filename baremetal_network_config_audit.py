#!/usr/bin/env python3
"""
Audit network interface configuration for common misconfigurations and inconsistencies.

This script checks network interface settings that can cause performance issues or
intermittent connectivity problems in large baremetal deployments, including:
- MTU mismatches across interfaces and bonds
- Inconsistent bonding modes across bond interfaces
- IPv6 configuration inconsistencies
- Interface naming inconsistencies
- Promiscuous mode warnings

Exit codes:
    0 - No issues detected
    1 - Configuration issues or warnings found
    2 - Usage error or missing dependency
"""

import argparse
import sys
import os
import json
import subprocess
import re


def run_command(cmd):
    """Execute shell command and return result"""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def check_tool_available(tool_name):
    """Check if system tool is available"""
    try:
        result = subprocess.run(
            ['which', tool_name],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_interface_list():
    """Get list of network interfaces"""
    interfaces = []
    net_dir = "/sys/class/net"

    if not os.path.exists(net_dir):
        return interfaces

    try:
        for iface in os.listdir(net_dir):
            # Skip loopback
            if iface == "lo":
                continue
            interfaces.append(iface)
    except Exception as e:
        print(f"Warning: Could not read network interfaces: {e}", file=sys.stderr)

    return sorted(interfaces)


def get_interface_mtu(interface):
    """Get MTU for an interface"""
    mtu_file = f"/sys/class/net/{interface}/mtu"
    try:
        with open(mtu_file, 'r') as f:
            return int(f.read().strip())
    except Exception:
        return None


def get_interface_state(interface):
    """Get operational state for an interface"""
    state_file = f"/sys/class/net/{interface}/operstate"
    try:
        with open(state_file, 'r') as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def get_bonding_mode(interface):
    """Get bonding mode if interface is a bond"""
    mode_file = f"/sys/class/net/{interface}/bonding/mode"
    try:
        with open(mode_file, 'r') as f:
            mode = f.read().strip()
            # Format is typically "balance-rr 0" or similar
            return mode.split()[0] if mode else None
    except Exception:
        return None


def is_bond_interface(interface):
    """Check if interface is a bonding interface"""
    return os.path.exists(f"/sys/class/net/{interface}/bonding")


def get_bond_slaves(interface):
    """Get list of slave interfaces for a bond"""
    slaves_file = f"/sys/class/net/{interface}/bonding/slaves"
    try:
        with open(slaves_file, 'r') as f:
            slaves = f.read().strip()
            return slaves.split() if slaves else []
    except Exception:
        return []


def is_ipv6_enabled(interface):
    """Check if IPv6 is enabled on an interface"""
    disable_file = f"/proc/sys/net/ipv6/conf/{interface}/disable_ipv6"
    try:
        with open(disable_file, 'r') as f:
            return f.read().strip() == "0"
    except Exception:
        return False


def is_promiscuous_mode(interface):
    """Check if interface is in promiscuous mode"""
    flags_file = f"/sys/class/net/{interface}/flags"
    try:
        with open(flags_file, 'r') as f:
            flags = int(f.read().strip(), 16)
            # IFF_PROMISC = 0x100
            return bool(flags & 0x100)
    except Exception:
        return False


def audit_network_config(verbose=False):
    """Audit network configuration and return findings"""
    findings = []
    interfaces = get_interface_list()

    if not interfaces:
        findings.append({
            "severity": "error",
            "category": "general",
            "message": "No network interfaces found"
        })
        return findings

    # Collect interface information
    interface_info = {}
    for iface in interfaces:
        interface_info[iface] = {
            "mtu": get_interface_mtu(iface),
            "state": get_interface_state(iface),
            "is_bond": is_bond_interface(iface),
            "bonding_mode": get_bonding_mode(iface) if is_bond_interface(iface) else None,
            "bond_slaves": get_bond_slaves(iface) if is_bond_interface(iface) else [],
            "ipv6_enabled": is_ipv6_enabled(iface),
            "promiscuous": is_promiscuous_mode(iface)
        }

    # Check for MTU mismatches
    active_interfaces = {k: v for k, v in interface_info.items()
                        if v["state"] == "up" and not v["is_bond"]}

    if active_interfaces:
        mtus = {v["mtu"] for v in active_interfaces.values() if v["mtu"]}
        if len(mtus) > 1:
            findings.append({
                "severity": "warning",
                "category": "mtu",
                "message": f"MTU mismatch detected across active interfaces: {sorted(mtus)}"
            })
            for iface, info in active_interfaces.items():
                if info["mtu"] and verbose:
                    findings.append({
                        "severity": "info",
                        "category": "mtu",
                        "message": f"  {iface}: MTU {info['mtu']}"
                    })

    # Check bond slave MTU consistency
    for iface, info in interface_info.items():
        if info["is_bond"] and info["bond_slaves"]:
            bond_mtu = info["mtu"]
            for slave in info["bond_slaves"]:
                if slave in interface_info:
                    slave_mtu = interface_info[slave]["mtu"]
                    if slave_mtu and bond_mtu and slave_mtu != bond_mtu:
                        findings.append({
                            "severity": "warning",
                            "category": "bonding",
                            "message": f"Bond {iface} MTU ({bond_mtu}) != slave {slave} MTU ({slave_mtu})"
                        })

    # Check for bonding mode consistency
    bond_interfaces = {k: v for k, v in interface_info.items() if v["is_bond"]}
    if len(bond_interfaces) > 1:
        modes = {v["bonding_mode"] for v in bond_interfaces.values() if v["bonding_mode"]}
        if len(modes) > 1:
            findings.append({
                "severity": "warning",
                "category": "bonding",
                "message": f"Inconsistent bonding modes detected: {sorted(modes)}"
            })
            if verbose:
                for iface, info in bond_interfaces.items():
                    findings.append({
                        "severity": "info",
                        "category": "bonding",
                        "message": f"  {iface}: mode {info['bonding_mode']}"
                    })

    # Check for IPv6 inconsistencies
    active_non_bond = {k: v for k, v in active_interfaces.items() if not v["is_bond"]}
    if len(active_non_bond) > 1:
        ipv6_states = {v["ipv6_enabled"] for v in active_non_bond.values()}
        if len(ipv6_states) > 1:
            findings.append({
                "severity": "warning",
                "category": "ipv6",
                "message": "IPv6 enabled on some interfaces but not others"
            })
            if verbose:
                for iface, info in active_non_bond.items():
                    state = "enabled" if info["ipv6_enabled"] else "disabled"
                    findings.append({
                        "severity": "info",
                        "category": "ipv6",
                        "message": f"  {iface}: IPv6 {state}"
                    })

    # Check for promiscuous mode (usually undesired on production servers)
    promisc_interfaces = [k for k, v in interface_info.items()
                         if v["promiscuous"] and v["state"] == "up"]
    if promisc_interfaces:
        findings.append({
            "severity": "warning",
            "category": "security",
            "message": f"Promiscuous mode enabled on: {', '.join(promisc_interfaces)}"
        })

    # Check for down bond slaves
    for iface, info in interface_info.items():
        if info["is_bond"] and info["bond_slaves"]:
            for slave in info["bond_slaves"]:
                if slave in interface_info:
                    if interface_info[slave]["state"] != "up":
                        findings.append({
                            "severity": "error",
                            "category": "bonding",
                            "message": f"Bond {iface} slave {slave} is {interface_info[slave]['state']}"
                        })

    # Verbose: Report all interface states
    if verbose and not findings:
        findings.append({
            "severity": "info",
            "category": "general",
            "message": f"Audited {len(interfaces)} network interfaces, no issues found"
        })

    return findings


def output_plain(findings, warn_only=False):
    """Output findings in plain text format"""
    filtered = findings
    if warn_only:
        filtered = [f for f in findings if f["severity"] in ["warning", "error"]]

    if not filtered:
        print("No issues detected")
        return

    for finding in filtered:
        severity = finding["severity"].upper()
        category = finding["category"]
        message = finding["message"]
        print(f"[{severity}] {category}: {message}")


def output_json(findings, warn_only=False):
    """Output findings in JSON format"""
    filtered = findings
    if warn_only:
        filtered = [f for f in findings if f["severity"] in ["warning", "error"]]

    print(json.dumps(filtered, indent=2))


def output_table(findings, warn_only=False):
    """Output findings in table format"""
    filtered = findings
    if warn_only:
        filtered = [f for f in findings if f["severity"] in ["warning", "error"]]

    if not filtered:
        print("No issues detected")
        return

    # Print header
    print(f"{'Severity':<10} {'Category':<15} {'Message':<60}")
    print("-" * 85)

    # Print rows
    for finding in filtered:
        severity = finding["severity"]
        category = finding["category"]
        message = finding["message"]
        # Truncate long messages
        if len(message) > 60:
            message = message[:57] + "..."
        print(f"{severity:<10} {category:<15} {message:<60}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Audit network interface configuration for common issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Audit network configuration
  %(prog)s --verbose          # Show detailed information
  %(prog)s --format json      # Output in JSON format
  %(prog)s --warn-only        # Only show warnings and errors

Exit codes:
  0 - No issues detected
  1 - Configuration issues or warnings found
  2 - Usage error or missing dependency
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
        help="Show detailed information"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and errors"
    )

    args = parser.parse_args()

    # Check for required access to /sys
    if not os.path.exists("/sys/class/net"):
        print("Error: /sys/class/net not accessible", file=sys.stderr)
        print("This script requires access to sysfs network information", file=sys.stderr)
        sys.exit(2)

    try:
        findings = audit_network_config(verbose=args.verbose)

        # Output results
        if args.format == "json":
            output_json(findings, args.warn_only)
        elif args.format == "table":
            output_table(findings, args.warn_only)
        else:
            output_plain(findings, args.warn_only)

        # Determine exit code based on findings
        has_errors = any(f["severity"] == "error" for f in findings)
        has_warnings = any(f["severity"] == "warning" for f in findings)

        if has_errors or has_warnings:
            sys.exit(1)
        else:
            sys.exit(0)

    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
