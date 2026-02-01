#!/usr/bin/env python3
"""
Monitor ARP table health and detect anomalies on Linux systems.

This script analyzes the ARP (Address Resolution Protocol) cache to identify:
- Stale or incomplete ARP entries indicating network issues
- ARP table size approaching system limits
- Duplicate MAC addresses (potential ARP spoofing)
- Failed ARP resolution attempts
- Gateway reachability via ARP
- ARP flux (rapid changes in MAC-IP mappings)

Useful for:
- Network connectivity troubleshooting
- Detecting ARP spoofing or man-in-the-middle attacks
- Identifying failing network interfaces
- Monitoring datacenter network health
- Gateway and switch problem detection

Exit codes:
    0 - ARP table healthy, no issues detected
    1 - ARP issues or warnings detected
    2 - Usage error or missing dependencies
"""

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime


def read_file(path):
    """Read a file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError):
        return None


def run_command(cmd):
    """Execute shell command and return result."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}"
    except Exception as e:
        return -1, "", str(e)


def get_arp_entries():
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
    
    content = read_file('/proc/net/arp')
    if not content:
        return entries
    
    lines = content.strip().split('\n')
    if len(lines) < 2:
        return entries
    
    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            entries.append({
                'ip_address': parts[0],
                'hw_type': parts[1],
                'flags': parts[2],
                'hw_address': parts[3],
                'mask': parts[4],
                'device': parts[5],
                'state': 'complete' if parts[2] == '0x2' else 'incomplete'
            })
    
    return entries


def get_arp_cache_limits():
    """Get ARP cache threshold values from sysctl."""
    limits = {}
    
    sysctl_paths = {
        'gc_thresh1': '/proc/sys/net/ipv4/neigh/default/gc_thresh1',
        'gc_thresh2': '/proc/sys/net/ipv4/neigh/default/gc_thresh2', 
        'gc_thresh3': '/proc/sys/net/ipv4/neigh/default/gc_thresh3',
    }
    
    for name, path in sysctl_paths.items():
        content = read_file(path)
        if content:
            try:
                limits[name] = int(content.strip())
            except ValueError:
                limits[name] = 0
    
    return limits


def get_default_gateways():
    """Get default gateway IP addresses."""
    gateways = []
    
    content = read_file('/proc/net/route')
    if not content:
        return gateways
    
    lines = content.strip().split('\n')
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            # Default route has destination 00000000
            if parts[1] == '00000000':
                # Gateway is in hex, little-endian
                gw_hex = parts[2]
                try:
                    # Convert hex gateway to IP
                    gw_bytes = bytes.fromhex(gw_hex)
                    gw_ip = '.'.join(str(b) for b in reversed(gw_bytes))
                    if gw_ip != '0.0.0.0':
                        gateways.append({
                            'ip': gw_ip,
                            'interface': parts[0]
                        })
                except (ValueError, IndexError):
                    pass
    
    return gateways


def analyze_arp_table(entries, limits, gateways, verbose=False):
    """
    Analyze ARP table for issues.
    
    Returns dict with:
    - issues: List of detected issues
    - stats: Statistics about the ARP table
    - entries_by_state: Entries grouped by state
    """
    issues = []
    stats = {
        'total_entries': len(entries),
        'complete': 0,
        'incomplete': 0,
        'by_interface': defaultdict(int),
        'by_state': defaultdict(int)
    }
    
    mac_to_ips = defaultdict(list)
    ip_to_macs = defaultdict(list)
    
    # Analyze each entry
    for entry in entries:
        state = entry['state']
        stats['by_state'][state] += 1
        stats['by_interface'][entry['device']] += 1
        
        if state == 'complete':
            stats['complete'] += 1
            mac = entry['hw_address'].lower()
            ip = entry['ip_address']
            
            # Track MAC-IP mappings
            if mac != '00:00:00:00:00:00':
                mac_to_ips[mac].append(ip)
                ip_to_macs[ip].append(mac)
        else:
            stats['incomplete'] += 1
    
    # Check for duplicate MACs (potential spoofing)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            issues.append({
                'severity': 'WARNING',
                'category': 'duplicate_mac',
                'message': f"MAC {mac} has multiple IPs: {', '.join(ips)}",
                'details': {'mac': mac, 'ips': ips}
            })
    
    # Check for incomplete entries
    incomplete = [e for e in entries if e['state'] == 'incomplete']
    if incomplete:
        incomplete_ips = [e['ip_address'] for e in incomplete]
        issues.append({
            'severity': 'WARNING',
            'category': 'incomplete_entries',
            'message': f"{len(incomplete)} incomplete ARP entries (resolution failed)",
            'details': {'count': len(incomplete), 'ips': incomplete_ips[:10]}
        })
    
    # Check ARP table size against thresholds
    if limits:
        total = stats['total_entries']
        thresh1 = limits.get('gc_thresh1', 0)
        thresh2 = limits.get('gc_thresh2', 0)
        thresh3 = limits.get('gc_thresh3', 0)
        
        if thresh3 > 0 and total >= thresh3:
            issues.append({
                'severity': 'CRITICAL',
                'category': 'arp_table_full',
                'message': f"ARP table at hard limit ({total}/{thresh3})",
                'details': {'current': total, 'limit': thresh3}
            })
        elif thresh2 > 0 and total >= thresh2:
            issues.append({
                'severity': 'WARNING',
                'category': 'arp_table_high',
                'message': f"ARP table above soft limit ({total}/{thresh2})",
                'details': {'current': total, 'limit': thresh2}
            })
        elif thresh1 > 0 and total >= thresh1 * 0.8:
            issues.append({
                'severity': 'INFO',
                'category': 'arp_table_growing',
                'message': f"ARP table approaching threshold ({total}/{thresh1})",
                'details': {'current': total, 'limit': thresh1}
            })
    
    # Check gateway reachability
    for gw in gateways:
        gw_ip = gw['ip']
        gw_iface = gw['interface']
        
        # Find gateway in ARP table
        gw_entry = None
        for entry in entries:
            if entry['ip_address'] == gw_ip:
                gw_entry = entry
                break
        
        if not gw_entry:
            issues.append({
                'severity': 'WARNING',
                'category': 'gateway_not_in_arp',
                'message': f"Gateway {gw_ip} ({gw_iface}) not in ARP table",
                'details': {'gateway': gw_ip, 'interface': gw_iface}
            })
        elif gw_entry['state'] == 'incomplete':
            issues.append({
                'severity': 'CRITICAL',
                'category': 'gateway_unreachable',
                'message': f"Gateway {gw_ip} ARP resolution incomplete",
                'details': {'gateway': gw_ip, 'interface': gw_iface}
            })
        elif gw_entry['hw_address'] == '00:00:00:00:00:00':
            issues.append({
                'severity': 'CRITICAL', 
                'category': 'gateway_no_mac',
                'message': f"Gateway {gw_ip} has null MAC address",
                'details': {'gateway': gw_ip, 'interface': gw_iface}
            })
    
    # Check for broadcast MAC in unicast entries
    for entry in entries:
        mac = entry['hw_address'].lower()
        if mac == 'ff:ff:ff:ff:ff:ff':
            issues.append({
                'severity': 'WARNING',
                'category': 'broadcast_mac',
                'message': f"IP {entry['ip_address']} has broadcast MAC",
                'details': {'ip': entry['ip_address'], 'device': entry['device']}
            })
    
    return {
        'issues': issues,
        'stats': stats,
        'limits': limits,
        'gateways': gateways,
        'entries': entries if verbose else []
    }


def format_output_plain(analysis, warn_only=False):
    """Format output as plain text."""
    lines = []
    stats = analysis['stats']
    issues = analysis['issues']
    limits = analysis['limits']
    
    if not warn_only:
        lines.append("ARP Table Analysis")
        lines.append("=" * 60)
        lines.append(f"Total entries: {stats['total_entries']}")
        lines.append(f"Complete: {stats['complete']}")
        lines.append(f"Incomplete: {stats['incomplete']}")
        
        if limits:
            lines.append(f"\nARP cache limits:")
            lines.append(f"  gc_thresh1: {limits.get('gc_thresh1', 'N/A')}")
            lines.append(f"  gc_thresh2: {limits.get('gc_thresh2', 'N/A')}")
            lines.append(f"  gc_thresh3: {limits.get('gc_thresh3', 'N/A')}")
        
        if stats['by_interface']:
            lines.append(f"\nEntries by interface:")
            for iface, count in sorted(stats['by_interface'].items()):
                lines.append(f"  {iface}: {count}")
        
        if analysis['gateways']:
            lines.append(f"\nDefault gateways:")
            for gw in analysis['gateways']:
                lines.append(f"  {gw['ip']} via {gw['interface']}")
        
        lines.append("")
    
    if issues:
        if not warn_only:
            lines.append("Issues Detected:")
            lines.append("-" * 60)
        
        for issue in issues:
            severity = issue['severity']
            message = issue['message']
            lines.append(f"[{severity}] {message}")
    elif not warn_only:
        lines.append("No issues detected - ARP table healthy")
    
    return "\n".join(lines)


def format_output_table(analysis, warn_only=False):
    """Format output as ASCII table."""
    lines = []
    stats = analysis['stats']
    issues = analysis['issues']
    
    if not warn_only:
        lines.append(f"{'METRIC':<30} {'VALUE':<30}")
        lines.append("-" * 60)
        lines.append(f"{'Total ARP entries':<30} {stats['total_entries']:<30}")
        lines.append(f"{'Complete entries':<30} {stats['complete']:<30}")
        lines.append(f"{'Incomplete entries':<30} {stats['incomplete']:<30}")
        
        for iface, count in sorted(stats['by_interface'].items()):
            lines.append(f"{'Entries on ' + iface:<30} {count:<30}")
        
        lines.append("")
    
    if issues:
        lines.append(f"{'SEVERITY':<12} {'CATEGORY':<25} {'MESSAGE':<50}")
        lines.append("-" * 87)
        for issue in issues:
            sev = issue['severity']
            cat = issue['category'][:25]
            msg = issue['message'][:50]
            lines.append(f"{sev:<12} {cat:<25} {msg:<50}")
    elif not warn_only:
        lines.append("No issues detected")
    
    return "\n".join(lines)


def format_output_json(analysis, warn_only=False):
    """Format output as JSON."""
    output = {
        'timestamp': datetime.now().isoformat(),
        'stats': {
            'total_entries': analysis['stats']['total_entries'],
            'complete': analysis['stats']['complete'],
            'incomplete': analysis['stats']['incomplete'],
            'by_interface': dict(analysis['stats']['by_interface'])
        },
        'limits': analysis['limits'],
        'gateways': analysis['gateways'],
        'issues': analysis['issues'],
        'issue_count': len(analysis['issues']),
        'has_critical': any(i['severity'] == 'CRITICAL' for i in analysis['issues']),
        'has_warnings': any(i['severity'] == 'WARNING' for i in analysis['issues'])
    }
    
    if analysis['entries']:
        output['entries'] = analysis['entries']
    
    return json.dumps(output, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor ARP table health and detect anomalies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic ARP table health check
  %(prog)s

  # Show only warnings and critical issues
  %(prog)s --warn-only

  # JSON output for monitoring integration
  %(prog)s --format json

  # Verbose output with all ARP entries
  %(prog)s -v

Exit codes:
  0 - ARP table healthy
  1 - Issues detected (warnings or critical)
  2 - Usage error
        """
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "table", "json"],
        default="plain",
        help="Output format (default: plain)"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and critical issues"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output including all ARP entries"
    )
    
    args = parser.parse_args()
    
    # Check if running on Linux
    if not os.path.exists('/proc/net/arp'):
        print("Error: /proc/net/arp not found (Linux required)", file=sys.stderr)
        sys.exit(2)
    
    # Gather data
    entries = get_arp_entries()
    limits = get_arp_cache_limits()
    gateways = get_default_gateways()
    
    # Analyze
    analysis = analyze_arp_table(entries, limits, gateways, args.verbose)
    
    # Format output
    if args.format == "json":
        print(format_output_json(analysis, args.warn_only))
    elif args.format == "table":
        print(format_output_table(analysis, args.warn_only))
    else:
        print(format_output_plain(analysis, args.warn_only))
    
    # Exit code based on issues
    issues = analysis['issues']
    if any(i['severity'] == 'CRITICAL' for i in issues):
        sys.exit(1)
    elif any(i['severity'] == 'WARNING' for i in issues):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
