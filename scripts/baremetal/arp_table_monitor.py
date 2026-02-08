#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, arp, security]
#   brief: Monitor ARP table health and detect anomalies

"""
Monitor ARP table health and detect anomalies on Linux systems.

Analyzes the ARP (Address Resolution Protocol) cache to identify:
- Stale or incomplete ARP entries indicating network issues
- ARP table size approaching system limits
- Duplicate MAC addresses (potential ARP spoofing)
- Gateway reachability via ARP

Exit codes:
    0: ARP table healthy, no issues detected
    1: ARP issues or warnings detected
    2: Usage error or missing dependencies
"""

import argparse
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_arp_entries(context: Context) -> list[dict]:
    """
    Get ARP table entries from /proc/net/arp.

    Returns list of dicts with keys:
    - ip_address: IP address
    - hw_type: Hardware type (usually 0x1 for Ethernet)
    - flags: Flags (0x2 = complete, 0x0 = incomplete)
    - hw_address: MAC address
    - mask: Mask (usually *)
    - device: Network interface
    """
    entries = []

    content = context.read_file("/proc/net/arp")
    lines = content.strip().split("\n")
    if len(lines) < 2:
        return entries

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            entries.append(
                {
                    "ip_address": parts[0],
                    "hw_type": parts[1],
                    "flags": parts[2],
                    "hw_address": parts[3],
                    "mask": parts[4],
                    "device": parts[5],
                    "state": "complete" if parts[2] == "0x2" else "incomplete",
                }
            )

    return entries


def get_arp_cache_limits(context: Context) -> dict:
    """Get ARP cache threshold values from sysctl."""
    limits = {}

    sysctl_paths = {
        "gc_thresh1": "/proc/sys/net/ipv4/neigh/default/gc_thresh1",
        "gc_thresh2": "/proc/sys/net/ipv4/neigh/default/gc_thresh2",
        "gc_thresh3": "/proc/sys/net/ipv4/neigh/default/gc_thresh3",
    }

    for name, path in sysctl_paths.items():
        try:
            content = context.read_file(path)
            limits[name] = int(content.strip())
        except (FileNotFoundError, IOError, ValueError):
            limits[name] = 0

    return limits


def get_default_gateways(context: Context) -> list[dict]:
    """Get default gateway IP addresses."""
    gateways = []

    try:
        content = context.read_file("/proc/net/route")
    except (FileNotFoundError, IOError):
        return gateways

    lines = content.strip().split("\n")
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            # Default route has destination 00000000
            if parts[1] == "00000000":
                # Gateway is in hex, little-endian
                gw_hex = parts[2]
                try:
                    # Convert hex gateway to IP
                    gw_bytes = bytes.fromhex(gw_hex)
                    gw_ip = ".".join(str(b) for b in reversed(gw_bytes))
                    if gw_ip != "0.0.0.0":
                        gateways.append({"ip": gw_ip, "interface": parts[0]})
                except (ValueError, IndexError):
                    pass

    return gateways


def analyze_arp_table(
    entries: list[dict],
    limits: dict,
    gateways: list[dict],
) -> dict:
    """
    Analyze ARP table for issues.

    Returns dict with:
    - issues: List of detected issues
    - stats: Statistics about the ARP table
    """
    issues = []
    stats = {
        "total_entries": len(entries),
        "complete": 0,
        "incomplete": 0,
        "by_interface": defaultdict(int),
    }

    mac_to_ips: dict[str, list[str]] = defaultdict(list)

    # Analyze each entry
    for entry in entries:
        state = entry["state"]
        stats["by_interface"][entry["device"]] += 1

        if state == "complete":
            stats["complete"] += 1
            mac = entry["hw_address"].lower()
            ip = entry["ip_address"]

            # Track MAC-IP mappings
            if mac != "00:00:00:00:00:00":
                mac_to_ips[mac].append(ip)
        else:
            stats["incomplete"] += 1

    # Check for duplicate MACs (potential spoofing)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            issues.append(
                {
                    "severity": "WARNING",
                    "category": "duplicate_mac",
                    "message": f"MAC {mac} has multiple IPs: {', '.join(ips)}",
                    "details": {"mac": mac, "ips": ips},
                }
            )

    # Check for incomplete entries
    incomplete = [e for e in entries if e["state"] == "incomplete"]
    if incomplete:
        incomplete_ips = [e["ip_address"] for e in incomplete]
        issues.append(
            {
                "severity": "WARNING",
                "category": "incomplete_entries",
                "message": f"{len(incomplete)} incomplete ARP entries (resolution failed)",
                "details": {"count": len(incomplete), "ips": incomplete_ips[:10]},
            }
        )

    # Check ARP table size against thresholds
    if limits:
        total = stats["total_entries"]
        thresh2 = limits.get("gc_thresh2", 0)
        thresh3 = limits.get("gc_thresh3", 0)

        if thresh3 > 0 and total >= thresh3:
            issues.append(
                {
                    "severity": "CRITICAL",
                    "category": "arp_table_full",
                    "message": f"ARP table at hard limit ({total}/{thresh3})",
                    "details": {"current": total, "limit": thresh3},
                }
            )
        elif thresh2 > 0 and total >= thresh2:
            issues.append(
                {
                    "severity": "WARNING",
                    "category": "arp_table_high",
                    "message": f"ARP table above soft limit ({total}/{thresh2})",
                    "details": {"current": total, "limit": thresh2},
                }
            )

    # Check gateway reachability
    for gw in gateways:
        gw_ip = gw["ip"]
        gw_iface = gw["interface"]

        # Find gateway in ARP table
        gw_entry = None
        for entry in entries:
            if entry["ip_address"] == gw_ip:
                gw_entry = entry
                break

        if gw_entry is None:
            issues.append(
                {
                    "severity": "WARNING",
                    "category": "gateway_not_in_arp",
                    "message": f"Gateway {gw_ip} ({gw_iface}) not in ARP table",
                    "details": {"gateway": gw_ip, "interface": gw_iface},
                }
            )
        elif gw_entry["state"] == "incomplete":
            issues.append(
                {
                    "severity": "CRITICAL",
                    "category": "gateway_unreachable",
                    "message": f"Gateway {gw_ip} ARP resolution incomplete",
                    "details": {"gateway": gw_ip, "interface": gw_iface},
                }
            )

    # Check for broadcast MAC in unicast entries
    for entry in entries:
        mac = entry["hw_address"].lower()
        if mac == "ff:ff:ff:ff:ff:ff":
            issues.append(
                {
                    "severity": "WARNING",
                    "category": "broadcast_mac",
                    "message": f"IP {entry['ip_address']} has broadcast MAC",
                    "details": {"ip": entry["ip_address"], "device": entry["device"]},
                }
            )

    return {
        "issues": issues,
        "stats": stats,
        "limits": limits,
        "gateways": gateways,
    }


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
        description="Monitor ARP table health and detect anomalies"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show warnings and critical issues",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed output including all ARP entries",
    )

    opts = parser.parse_args(args)

    # Read ARP table
    try:
        entries = get_arp_entries(context)
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/net/arp: {e}")
        return 2

    # Get ARP cache limits
    limits = get_arp_cache_limits(context)

    # Get default gateways
    gateways = get_default_gateways(context)

    # Analyze
    analysis = analyze_arp_table(entries, limits, gateways)
    issues = analysis["issues"]
    stats = analysis["stats"]

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total_entries": stats["total_entries"],
            "complete": stats["complete"],
            "incomplete": stats["incomplete"],
            "by_interface": dict(stats["by_interface"]),
        },
        "limits": limits,
        "gateways": gateways,
        "issues": issues,
        "issue_count": len(issues),
        "has_critical": any(i["severity"] == "CRITICAL" for i in issues),
        "has_warnings": any(i["severity"] == "WARNING" for i in issues),
        "healthy": len(issues) == 0,
    }

    if opts.verbose:
        result["entries"] = entries

    output.emit(result)

    # Output handling
    if opts.format == "table":
        if not opts.warn_only or issues:
            lines = []
            lines.append(f"{'METRIC':<30} {'VALUE':<30}")
            lines.append("-" * 60)
            lines.append(f"{'Total ARP entries':<30} {stats['total_entries']:<30}")
            lines.append(f"{'Complete entries':<30} {stats['complete']:<30}")
            lines.append(f"{'Incomplete entries':<30} {stats['incomplete']:<30}")

            for iface, count in sorted(stats["by_interface"].items()):
                lines.append(f"{'Entries on ' + iface:<30} {count:<30}")

            lines.append("")

            if issues:
                lines.append(f"{'SEVERITY':<12} {'CATEGORY':<25} {'MESSAGE':<50}")
                lines.append("-" * 87)
                for issue in issues:
                    sev = issue["severity"]
                    cat = issue["category"][:25]
                    msg = issue["message"][:50]
                    lines.append(f"{sev:<12} {cat:<25} {msg:<50}")
            else:
                lines.append("No issues detected")

            print("\n".join(lines))
    else:
        output.render(opts.format, "ARP Table Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    output.set_summary(
        f"entries={stats['total_entries']}, issues={len(issues)}"
    )

    # Exit code based on issues
    if any(i["severity"] == "CRITICAL" for i in issues):
        return 1
    elif any(i["severity"] == "WARNING" for i in issues):
        return 1
    else:
        return 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
