#!/usr/bin/env python3
"""
Analyze TCP and UDP socket states on baremetal systems.

Provides detailed analysis of socket states to help identify:
- Connection leaks (too many ESTABLISHED connections)
- TIME_WAIT accumulation (common after high traffic or misconfigured apps)
- CLOSE_WAIT buildup (indicates application not closing connections)
- Socket exhaustion risks (approaching ephemeral port limits)
- Listening port inventory

This script reads from /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, and
/proc/net/udp6 to gather socket information without requiring external tools.

Exit codes:
    0 - No issues detected (socket counts within thresholds)
    1 - Socket state issues detected (exceeds warning thresholds)
    2 - Missing /proc files or usage error
"""

import argparse
import sys
import json
import os
from collections import defaultdict

# TCP state codes as defined in the kernel
TCP_STATES = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING',
}


def read_proc_file(path):
    """Read a /proc file and return its contents."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None


def hex_to_ip(hex_ip, ipv6=False):
    """Convert hex IP address to human-readable format."""
    if ipv6:
        # IPv6 addresses are stored as 4 32-bit words in little-endian
        if len(hex_ip) != 32:
            return hex_ip
        try:
            parts = []
            for i in range(0, 32, 8):
                word = hex_ip[i:i+8]
                # Convert to big-endian
                word = ''.join(reversed([word[j:j+2] for j in range(0, 8, 2)]))
                parts.append(word)
            ip = ':'.join(parts)
            # Simplify IPv6 address
            return ip
        except (ValueError, IndexError):
            return hex_ip
    else:
        # IPv4: stored as little-endian hex
        try:
            ip_int = int(hex_ip, 16)
            # Reverse byte order (little-endian to big-endian)
            octets = [
                (ip_int >> 0) & 0xFF,
                (ip_int >> 8) & 0xFF,
                (ip_int >> 16) & 0xFF,
                (ip_int >> 24) & 0xFF,
            ]
            return '.'.join(str(o) for o in octets)
        except ValueError:
            return hex_ip


def hex_to_port(hex_port):
    """Convert hex port to integer."""
    try:
        return int(hex_port, 16)
    except ValueError:
        return 0


def parse_proc_net_tcp(path, ipv6=False):
    """Parse /proc/net/tcp or /proc/net/tcp6."""
    content = read_proc_file(path)
    if content is None:
        return None

    sockets = []
    lines = content.strip().split('\n')

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue

        try:
            # Format: sl local_address rem_address st tx_queue:rx_queue ...
            local = parts[1].split(':')
            remote = parts[2].split(':')
            state_hex = parts[3]

            socket_info = {
                'local_ip': hex_to_ip(local[0], ipv6),
                'local_port': hex_to_port(local[1]),
                'remote_ip': hex_to_ip(remote[0], ipv6),
                'remote_port': hex_to_port(remote[1]),
                'state': TCP_STATES.get(state_hex.upper(), f'UNKNOWN({state_hex})'),
                'state_hex': state_hex,
                'ipv6': ipv6,
            }
            sockets.append(socket_info)
        except (IndexError, ValueError):
            continue

    return sockets


def parse_proc_net_udp(path, ipv6=False):
    """Parse /proc/net/udp or /proc/net/udp6."""
    content = read_proc_file(path)
    if content is None:
        return None

    sockets = []
    lines = content.strip().split('\n')

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue

        try:
            local = parts[1].split(':')
            remote = parts[2].split(':')

            socket_info = {
                'local_ip': hex_to_ip(local[0], ipv6),
                'local_port': hex_to_port(local[1]),
                'remote_ip': hex_to_ip(remote[0], ipv6),
                'remote_port': hex_to_port(remote[1]),
                'state': 'ESTABLISHED' if hex_to_port(remote[1]) != 0 else 'LISTEN',
                'ipv6': ipv6,
            }
            sockets.append(socket_info)
        except (IndexError, ValueError):
            continue

    return sockets


def get_ephemeral_port_range():
    """Get the ephemeral port range from kernel."""
    content = read_proc_file('/proc/sys/net/ipv4/ip_local_port_range')
    if content:
        try:
            parts = content.strip().split()
            return int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            pass
    # Default range
    return 32768, 60999


def analyze_sockets(tcp_sockets, udp_sockets, warn_thresholds):
    """Analyze socket states and generate report."""
    # Count TCP states
    tcp_states = defaultdict(int)
    tcp_by_port = defaultdict(lambda: defaultdict(int))

    for sock in tcp_sockets:
        state = sock['state']
        tcp_states[state] += 1
        # Group by local port for listening, remote port for outgoing
        if state == 'LISTEN':
            tcp_by_port[sock['local_port']][state] += 1
        else:
            tcp_by_port[sock['remote_port']][state] += 1

    # Count UDP
    udp_listening = 0
    udp_established = 0
    for sock in udp_sockets:
        if sock['state'] == 'LISTEN':
            udp_listening += 1
        else:
            udp_established += 1

    # Get ephemeral port range
    eph_low, eph_high = get_ephemeral_port_range()
    ephemeral_range = eph_high - eph_low + 1

    # Count ephemeral ports in use (outgoing connections)
    ephemeral_in_use = 0
    for sock in tcp_sockets:
        if sock['state'] not in ('LISTEN',):
            port = sock['local_port']
            if eph_low <= port <= eph_high:
                ephemeral_in_use += 1

    ephemeral_pct = (ephemeral_in_use / ephemeral_range) * 100 if ephemeral_range > 0 else 0

    # Detect issues
    issues = []

    # Check TIME_WAIT count
    time_wait = tcp_states.get('TIME_WAIT', 0)
    if time_wait >= warn_thresholds['time_wait']:
        issues.append({
            'severity': 'warning',
            'category': 'time_wait',
            'message': f"High TIME_WAIT count: {time_wait} (threshold: {warn_thresholds['time_wait']})",
            'value': time_wait,
            'threshold': warn_thresholds['time_wait'],
        })

    # Check CLOSE_WAIT count (often indicates application bug)
    close_wait = tcp_states.get('CLOSE_WAIT', 0)
    if close_wait >= warn_thresholds['close_wait']:
        issues.append({
            'severity': 'warning',
            'category': 'close_wait',
            'message': f"High CLOSE_WAIT count: {close_wait} (may indicate app not closing connections)",
            'value': close_wait,
            'threshold': warn_thresholds['close_wait'],
        })

    # Check ESTABLISHED count
    established = tcp_states.get('ESTABLISHED', 0)
    if established >= warn_thresholds['established']:
        issues.append({
            'severity': 'warning',
            'category': 'established',
            'message': f"High ESTABLISHED count: {established}",
            'value': established,
            'threshold': warn_thresholds['established'],
        })

    # Check ephemeral port exhaustion
    if ephemeral_pct >= warn_thresholds['ephemeral_pct']:
        issues.append({
            'severity': 'critical' if ephemeral_pct >= 90 else 'warning',
            'category': 'ephemeral_ports',
            'message': f"Ephemeral port usage: {ephemeral_pct:.1f}% ({ephemeral_in_use}/{ephemeral_range})",
            'value': ephemeral_pct,
            'threshold': warn_thresholds['ephemeral_pct'],
        })

    # Check SYN_RECV (potential SYN flood)
    syn_recv = tcp_states.get('SYN_RECV', 0)
    if syn_recv >= warn_thresholds['syn_recv']:
        issues.append({
            'severity': 'warning',
            'category': 'syn_recv',
            'message': f"High SYN_RECV count: {syn_recv} (potential SYN flood or slow clients)",
            'value': syn_recv,
            'threshold': warn_thresholds['syn_recv'],
        })

    # Determine overall status
    status = 'ok'
    for issue in issues:
        if issue['severity'] == 'critical':
            status = 'critical'
            break
        elif issue['severity'] == 'warning':
            status = 'warning'

    result = {
        'status': status,
        'tcp_states': dict(tcp_states),
        'tcp_total': len(tcp_sockets),
        'udp_listening': udp_listening,
        'udp_established': udp_established,
        'udp_total': len(udp_sockets),
        'ephemeral_ports': {
            'in_use': ephemeral_in_use,
            'range_low': eph_low,
            'range_high': eph_high,
            'total_range': ephemeral_range,
            'usage_pct': round(ephemeral_pct, 2),
        },
        'top_ports': get_top_ports(tcp_sockets, 5),
    }

    return result, issues


def get_top_ports(sockets, limit=5):
    """Get top ports by connection count."""
    port_counts = defaultdict(int)

    for sock in sockets:
        if sock['state'] == 'LISTEN':
            continue
        # Count by remote port (service being connected to)
        port_counts[sock['remote_port']] += 1

    sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
    return [{'port': p, 'count': c} for p, c in sorted_ports[:limit]]


def get_listening_ports(tcp_sockets, udp_sockets):
    """Get list of listening ports."""
    tcp_listen = set()
    udp_listen = set()

    for sock in tcp_sockets:
        if sock['state'] == 'LISTEN':
            tcp_listen.add(sock['local_port'])

    for sock in udp_sockets:
        if sock['state'] == 'LISTEN':
            udp_listen.add(sock['local_port'])

    return sorted(tcp_listen), sorted(udp_listen)


def output_plain(result, issues, tcp_sockets, udp_sockets, verbose, warn_only):
    """Output results in plain text format."""
    if warn_only and not issues:
        return

    status_str = result['status'].upper()
    print(f"Socket State Analysis [{status_str}]")
    print("=" * 60)

    # TCP state summary
    print("\nTCP Socket States:")
    states = result['tcp_states']
    for state in ['ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'LISTEN',
                  'FIN_WAIT1', 'FIN_WAIT2', 'SYN_SENT', 'SYN_RECV',
                  'LAST_ACK', 'CLOSING']:
        count = states.get(state, 0)
        if count > 0 or state in ['ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'LISTEN']:
            print(f"  {state:<15} {count:>6}")

    print(f"\n  Total TCP: {result['tcp_total']}")

    # UDP summary
    print(f"\nUDP Sockets:")
    print(f"  Listening:    {result['udp_listening']:>6}")
    print(f"  Established:  {result['udp_established']:>6}")
    print(f"  Total UDP:    {result['udp_total']:>6}")

    # Ephemeral port usage
    eph = result['ephemeral_ports']
    print(f"\nEphemeral Ports ({eph['range_low']}-{eph['range_high']}):")
    print(f"  In use:       {eph['in_use']:>6} / {eph['total_range']}")
    print(f"  Usage:        {eph['usage_pct']:>5.1f}%")

    # Top destination ports
    if result['top_ports'] and verbose:
        print("\nTop Destination Ports:")
        for entry in result['top_ports']:
            print(f"  Port {entry['port']:<6} {entry['count']:>6} connections")

    # Listening ports
    if verbose:
        tcp_listen, udp_listen = get_listening_ports(tcp_sockets, udp_sockets)
        if tcp_listen:
            print(f"\nTCP Listening Ports: {', '.join(str(p) for p in tcp_listen[:15])}")
            if len(tcp_listen) > 15:
                print(f"  ... and {len(tcp_listen) - 15} more")
        if udp_listen:
            print(f"UDP Listening Ports: {', '.join(str(p) for p in udp_listen[:15])}")
            if len(udp_listen) > 15:
                print(f"  ... and {len(udp_listen) - 15} more")

    # Issues
    if issues:
        print(f"\nIssues ({len(issues)}):")
        for issue in issues:
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")
    elif not warn_only:
        print("\n[OK] Socket states within normal thresholds")


def output_json(result, issues, tcp_sockets, udp_sockets, verbose):
    """Output results in JSON format."""
    output = {
        'status': result['status'],
        'summary': {
            'tcp_total': result['tcp_total'],
            'udp_total': result['udp_total'],
            'ephemeral_usage_pct': result['ephemeral_ports']['usage_pct'],
        },
        'tcp_states': result['tcp_states'],
        'udp': {
            'listening': result['udp_listening'],
            'established': result['udp_established'],
        },
        'ephemeral_ports': result['ephemeral_ports'],
        'top_destination_ports': result['top_ports'],
        'issues': issues,
        'has_issues': len(issues) > 0,
    }

    if verbose:
        tcp_listen, udp_listen = get_listening_ports(tcp_sockets, udp_sockets)
        output['listening_ports'] = {
            'tcp': tcp_listen,
            'udp': udp_listen,
        }

    print(json.dumps(output, indent=2))


def output_table(result, issues, warn_only):
    """Output results in table format."""
    if warn_only and not issues:
        return

    print(f"{'State':<15} {'Count':>10}")
    print("-" * 26)

    for state in ['ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'LISTEN',
                  'FIN_WAIT1', 'FIN_WAIT2', 'SYN_SENT', 'SYN_RECV']:
        count = result['tcp_states'].get(state, 0)
        print(f"{state:<15} {count:>10}")

    print("-" * 26)
    print(f"{'TCP Total':<15} {result['tcp_total']:>10}")
    print(f"{'UDP Total':<15} {result['udp_total']:>10}")

    eph = result['ephemeral_ports']
    print(f"{'Ephemeral %':<15} {eph['usage_pct']:>9.1f}%")

    if issues:
        print()
        for issue in issues:
            print(f"[{issue['severity'].upper()}] {issue['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze TCP and UDP socket states on baremetal systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Basic socket state analysis
  %(prog)s --format json          # JSON output for automation
  %(prog)s -v                     # Verbose output with listening ports
  %(prog)s --warn-time-wait 5000  # Custom TIME_WAIT warning threshold
  %(prog)s -w                     # Only output if issues detected

What to look for:
  - High TIME_WAIT: Normal after bursts, but persistent high counts
    may need tcp_tw_reuse or connection pooling
  - High CLOSE_WAIT: Application bug - not calling close() on sockets
  - High ESTABLISHED: May indicate connection leak or high load
  - Ephemeral port exhaustion: Risk of connection failures

Exit codes:
  0 - No issues detected
  1 - Socket state issues detected
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
        help="Show detailed information including listening ports"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if issues are detected"
    )

    parser.add_argument(
        "--warn-time-wait",
        type=int,
        default=10000,
        metavar="N",
        help="TIME_WAIT warning threshold (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-close-wait",
        type=int,
        default=100,
        metavar="N",
        help="CLOSE_WAIT warning threshold (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-established",
        type=int,
        default=50000,
        metavar="N",
        help="ESTABLISHED warning threshold (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-ephemeral-pct",
        type=float,
        default=80.0,
        metavar="PCT",
        help="Ephemeral port usage warning threshold %% (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-syn-recv",
        type=int,
        default=500,
        metavar="N",
        help="SYN_RECV warning threshold (default: %(default)s)"
    )

    args = parser.parse_args()

    # Read TCP sockets
    tcp4 = parse_proc_net_tcp('/proc/net/tcp', ipv6=False)
    tcp6 = parse_proc_net_tcp('/proc/net/tcp6', ipv6=True)

    if tcp4 is None and tcp6 is None:
        print("Error: Cannot read /proc/net/tcp or /proc/net/tcp6", file=sys.stderr)
        print("This script requires access to /proc filesystem", file=sys.stderr)
        sys.exit(2)

    tcp_sockets = (tcp4 or []) + (tcp6 or [])

    # Read UDP sockets
    udp4 = parse_proc_net_udp('/proc/net/udp', ipv6=False)
    udp6 = parse_proc_net_udp('/proc/net/udp6', ipv6=True)
    udp_sockets = (udp4 or []) + (udp6 or [])

    # Warning thresholds
    warn_thresholds = {
        'time_wait': args.warn_time_wait,
        'close_wait': args.warn_close_wait,
        'established': args.warn_established,
        'ephemeral_pct': args.warn_ephemeral_pct,
        'syn_recv': args.warn_syn_recv,
    }

    # Analyze sockets
    result, issues = analyze_sockets(tcp_sockets, udp_sockets, warn_thresholds)

    # Output results
    if args.format == "json":
        output_json(result, issues, tcp_sockets, udp_sockets, args.verbose)
    elif args.format == "table":
        output_table(result, issues, args.warn_only)
    else:
        output_plain(result, issues, tcp_sockets, udp_sockets, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
