#!/usr/bin/env python3
"""
Monitor listening ports and detect unexpected services on baremetal systems.

This script analyzes /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, and /proc/net/udp6
to identify all listening ports and their associated processes. It helps detect:
- Unexpected services binding to ports
- Missing expected services
- Services binding to all interfaces vs localhost
- Port conflicts across processes

Useful for large-scale baremetal environments to audit service exposure,
detect rogue processes, and verify expected services are running.

Exit codes:
    0 - No issues detected (or all expected ports found)
    1 - Unexpected ports found or expected ports missing
    2 - Missing required /proc files or usage error
"""

import argparse
import sys
import json
import os
from collections import defaultdict

# TCP state for LISTEN
LISTEN_STATE = '0A'


def build_inode_to_process_map():
    """Build a mapping of socket inodes to process info."""
    inode_map = {}
    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            fd_dir = f'/proc/{pid}/fd'
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        link = os.readlink(f'{fd_dir}/{fd}')
                        if link.startswith('socket:['):
                            # Extract inode from socket:[inode]
                            inode = link[8:-1]
                            if inode not in inode_map:
                                # Get process name
                                try:
                                    with open(f'/proc/{pid}/comm', 'r') as f:
                                        name = f.read().strip()
                                except (OSError, IOError):
                                    name = '-'
                                inode_map[inode] = {'pid': int(pid), 'name': name}
                    except (OSError, IOError):
                        continue
            except (OSError, IOError):
                continue
    except (OSError, IOError):
        pass
    return inode_map


def get_process_info(inode, inode_map):
    """Get process name and PID from socket inode using pre-built map."""
    return inode_map.get(inode, {'pid': None, 'name': '-'})


def hex_to_ip(hex_str):
    """Convert hex IP address to dotted decimal notation."""
    # Handle IPv4
    if len(hex_str) == 8:
        # Little-endian byte order
        parts = [str(int(hex_str[i:i+2], 16)) for i in range(6, -1, -2)]
        return '.'.join(parts)
    # Handle IPv6
    elif len(hex_str) == 32:
        # IPv6 addresses in /proc are in network byte order per 32-bit word
        parts = []
        for i in range(0, 32, 8):
            word = hex_str[i:i+8]
            # Reverse bytes within each 32-bit word
            reversed_word = ''.join([word[j:j+2] for j in range(6, -1, -2)])
            parts.append(reversed_word[:4])
            parts.append(reversed_word[4:])
        ip = ':'.join(parts)
        # Compress IPv6 address
        if ip == '0000:0000:0000:0000:0000:0000:0000:0000':
            return '::'
        if ip == '0000:0000:0000:0000:0000:0000:0000:0001':
            return '::1'
        if ip.startswith('0000:0000:0000:0000:0000:ffff:'):
            # IPv4-mapped IPv6
            ipv4_hex = ip.replace(':', '')[-8:]
            parts = [str(int(ipv4_hex[i:i+2], 16)) for i in range(0, 8, 2)]
            return '::ffff:' + '.'.join(parts)
        return ip
    return hex_str


def parse_listening_ports(file_path, protocol):
    """Parse /proc/net socket file for listening ports."""
    listening = []
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None
    except PermissionError:
        return None

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue

        # For TCP, check if state is LISTEN (0A)
        # For UDP, all entries are considered "listening"
        if protocol.startswith('tcp'):
            state = parts[3]
            if state != LISTEN_STATE:
                continue

        # Extract local address and port
        local_addr = parts[1]
        addr_parts = local_addr.split(':')
        hex_ip = addr_parts[0]
        hex_port = addr_parts[1]

        ip = hex_to_ip(hex_ip)
        port = int(hex_port, 16)

        # Get inode for process lookup
        inode = parts[9]

        listening.append({
            'protocol': protocol,
            'ip': ip,
            'port': port,
            'inode': inode,
            'bind_type': 'all' if ip in ('0.0.0.0', '::', '0000:0000:0000:0000:0000:0000:0000:0000') else 'local'
        })

    return listening


def analyze_ports(listening_ports, expected_ports, unexpected_ports):
    """Analyze listening ports against expected/unexpected lists."""
    issues = []
    found_ports = set()

    for entry in listening_ports:
        port = entry['port']
        found_ports.add(port)

        # Check for unexpected ports
        if unexpected_ports and port in unexpected_ports:
            issues.append({
                'severity': 'warning',
                'type': 'unexpected_port',
                'port': port,
                'protocol': entry['protocol'],
                'process': entry.get('process', {}).get('name', '-'),
                'message': f"Unexpected port {port}/{entry['protocol']} bound by {entry.get('process', {}).get('name', '-')}"
            })

    # Check for missing expected ports
    if expected_ports:
        missing = expected_ports - found_ports
        for port in missing:
            issues.append({
                'severity': 'error',
                'type': 'missing_port',
                'port': port,
                'message': f"Expected port {port} is not listening"
            })

    return issues


def output_plain(listening_ports, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only or issues:
        print("Listening Ports:")
        print(f"{'Proto':<8} {'Address':<40} {'Port':>6} {'PID':>8} {'Process':<20} {'Bind'}")
        print("-" * 95)
        for entry in sorted(listening_ports, key=lambda x: (x['port'], x['protocol'])):
            proc = entry.get('process', {})
            pid = proc.get('pid', '-')
            name = proc.get('name', '-')
            pid_str = str(pid) if pid else '-'
            print(f"{entry['protocol']:<8} {entry['ip']:<40} {entry['port']:>6} {pid_str:>8} {name:<20} {entry['bind_type']}")

    if issues:
        print(f"\nIssues Found ({len(issues)}):")
        for issue in issues:
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")
    elif not warn_only:
        print(f"\n[OK] {len(listening_ports)} listening ports found, no issues detected")


def output_json(listening_ports, issues):
    """Output results in JSON format."""
    result = {
        'listening_ports': listening_ports,
        'issues': issues,
        'summary': {
            'total_ports': len(listening_ports),
            'tcp_ports': len([p for p in listening_ports if p['protocol'].startswith('tcp')]),
            'udp_ports': len([p for p in listening_ports if p['protocol'].startswith('udp')]),
            'all_interfaces': len([p for p in listening_ports if p['bind_type'] == 'all']),
            'localhost_only': len([p for p in listening_ports if p['bind_type'] == 'local']),
            'issue_count': len(issues)
        },
        'has_issues': len(issues) > 0
    }
    print(json.dumps(result, indent=2))


def output_table(listening_ports, issues, warn_only):
    """Output results in table format."""
    if not warn_only or issues:
        # Group by port
        by_port = defaultdict(list)
        for entry in listening_ports:
            by_port[entry['port']].append(entry)

        print(f"{'Port':>6} {'Proto':<8} {'Process':<20} {'Bind':<10} {'Address'}")
        print("-" * 80)
        for port in sorted(by_port.keys()):
            for entry in by_port[port]:
                proc = entry.get('process', {})
                name = proc.get('name', '-')
                print(f"{entry['port']:>6} {entry['protocol']:<8} {name:<20} {entry['bind_type']:<10} {entry['ip']}")

    if issues:
        print(f"\nIssues ({len(issues)}):")
        print(f"{'Severity':<10} {'Type':<15} {'Port':>6} {'Message'}")
        print("-" * 60)
        for issue in issues:
            print(f"{issue['severity']:<10} {issue['type']:<15} {issue['port']:>6} {issue['message']}")


def parse_port_list(port_string):
    """Parse comma-separated port list."""
    if not port_string:
        return set()
    ports = set()
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            # Range like 80-443
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return ports


def main():
    parser = argparse.ArgumentParser(
        description="Monitor listening ports and detect unexpected services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # List all listening ports
  %(prog)s --format json                # Output in JSON format
  %(prog)s --expected 22,80,443         # Verify expected ports are listening
  %(prog)s --unexpected 23,3389         # Alert if unexpected ports found
  %(prog)s --tcp-only                   # Only show TCP ports
  %(prog)s -w                           # Only show if issues detected
  %(prog)s --show-all-interfaces        # Only show ports bound to all interfaces

Exit codes:
  0 - No issues detected
  1 - Unexpected ports or missing expected ports
  2 - Missing /proc files or usage error
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
        help="Only output if issues are detected"
    )

    parser.add_argument(
        "--expected",
        metavar="PORTS",
        help="Comma-separated list of expected ports (e.g., 22,80,443 or 8000-8010)"
    )

    parser.add_argument(
        "--unexpected",
        metavar="PORTS",
        help="Comma-separated list of unexpected ports to alert on"
    )

    parser.add_argument(
        "--tcp-only",
        action="store_true",
        help="Only show TCP listening ports"
    )

    parser.add_argument(
        "--udp-only",
        action="store_true",
        help="Only show UDP listening ports"
    )

    parser.add_argument(
        "--show-all-interfaces",
        action="store_true",
        help="Only show ports bound to all interfaces (0.0.0.0 or ::)"
    )

    parser.add_argument(
        "--port",
        type=int,
        metavar="PORT",
        help="Filter to specific port number"
    )

    args = parser.parse_args()

    if args.tcp_only and args.udp_only:
        print("Error: Cannot specify both --tcp-only and --udp-only", file=sys.stderr)
        sys.exit(2)

    # Parse port lists
    expected_ports = parse_port_list(args.expected)
    unexpected_ports = parse_port_list(args.unexpected)

    # Collect listening ports from all sources
    all_listening = []
    sources = []

    if not args.udp_only:
        sources.extend([
            ('/proc/net/tcp', 'tcp'),
            ('/proc/net/tcp6', 'tcp6')
        ])

    if not args.tcp_only:
        sources.extend([
            ('/proc/net/udp', 'udp'),
            ('/proc/net/udp6', 'udp6')
        ])

    for file_path, protocol in sources:
        result = parse_listening_ports(file_path, protocol)
        if result is None:
            print(f"Error: Cannot read {file_path}", file=sys.stderr)
            print("This script requires access to /proc/net files", file=sys.stderr)
            sys.exit(2)
        all_listening.extend(result)

    # Build inode-to-process map once (much faster than per-socket lookup)
    inode_map = build_inode_to_process_map()

    # Look up process info for each listening port
    for entry in all_listening:
        entry['process'] = get_process_info(entry['inode'], inode_map)
        del entry['inode']  # Remove internal field

    # Apply filters
    if args.show_all_interfaces:
        all_listening = [e for e in all_listening if e['bind_type'] == 'all']

    if args.port:
        all_listening = [e for e in all_listening if e['port'] == args.port]

    # Analyze for issues
    issues = analyze_ports(all_listening, expected_ports, unexpected_ports)

    # Output results
    if args.format == "json":
        output_json(all_listening, issues)
    elif args.format == "table":
        output_table(all_listening, issues, args.warn_only)
    else:  # plain
        output_plain(all_listening, issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
