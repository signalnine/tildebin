#!/usr/bin/env python3
"""
Monitor UDP socket usage to detect resource exhaustion and anomalies.

Analyzes /proc/net/udp and /proc/net/udp6 to provide visibility into UDP
socket states across the system. Identifies processes with high socket counts,
queue buildup, and potential resource exhaustion.

Key features:
- Reports UDP socket counts by local port
- Identifies processes holding many UDP sockets
- Detects receive queue buildup (packets waiting to be read)
- Detects transmit queue buildup (packets waiting to be sent)
- Supports filtering by port or process

Use cases:
- Detecting UDP socket leaks in long-running services
- Identifying receive queue buildup on DNS/NTP/SNMP servers
- Finding services not draining UDP buffers
- Pre-incident visibility into UDP resource pressure
- Capacity planning for high-UDP workloads

Exit codes:
    0 - No UDP issues detected
    1 - UDP warnings or threshold exceeded
    2 - Usage error or unable to read socket information
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple


def read_proc_file(path: str) -> Optional[str]:
    """Read a /proc file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (OSError, IOError, PermissionError):
        return None


def hex_to_ip(hex_ip: str) -> str:
    """Convert hex IP address to dotted decimal notation."""
    # Handle IPv4
    if len(hex_ip) == 8:
        # Little-endian byte order in /proc/net/udp
        ip_int = int(hex_ip, 16)
        return '.'.join([
            str((ip_int >> 0) & 0xFF),
            str((ip_int >> 8) & 0xFF),
            str((ip_int >> 16) & 0xFF),
            str((ip_int >> 24) & 0xFF),
        ])
    # Handle IPv6 (simplified - just return shortened form)
    elif len(hex_ip) == 32:
        return 'ipv6'
    return hex_ip


def hex_to_port(hex_port: str) -> int:
    """Convert hex port to integer."""
    return int(hex_port, 16)


def get_inode_to_pid_map() -> Dict[int, Tuple[int, str]]:
    """Build a map from socket inode to (pid, command name)."""
    inode_map = {}

    try:
        for pid_dir in os.listdir('/proc'):
            if not pid_dir.isdigit():
                continue

            pid = int(pid_dir)
            fd_dir = f'/proc/{pid}/fd'

            # Get command name
            comm = None
            try:
                with open(f'/proc/{pid}/comm', 'r') as f:
                    comm = f.read().strip()
            except (OSError, IOError, PermissionError):
                comm = 'unknown'

            # Scan file descriptors for socket inodes
            try:
                for fd in os.listdir(fd_dir):
                    fd_path = f'{fd_dir}/{fd}'
                    try:
                        link = os.readlink(fd_path)
                        if link.startswith('socket:['):
                            inode = int(link[8:-1])
                            inode_map[inode] = (pid, comm)
                    except (OSError, IOError, PermissionError):
                        continue
            except (OSError, IOError, PermissionError):
                continue
    except OSError:
        pass

    return inode_map


def parse_udp_sockets(ipv6: bool = False) -> List[Dict[str, Any]]:
    """Parse /proc/net/udp or /proc/net/udp6."""
    path = '/proc/net/udp6' if ipv6 else '/proc/net/udp'
    content = read_proc_file(path)
    if not content:
        return []

    sockets = []
    lines = content.strip().split('\n')[1:]  # Skip header

    for line in lines:
        parts = line.split()
        if len(parts) < 13:
            continue

        try:
            # Parse local address
            local_addr = parts[1]
            local_ip, local_port = local_addr.split(':')
            local_port = hex_to_port(local_port)

            # Parse remote address
            remote_addr = parts[2]
            remote_ip, remote_port = remote_addr.split(':')
            remote_port = hex_to_port(remote_port)

            # Parse queues (tx_queue:rx_queue in hex)
            queue_info = parts[4]
            tx_queue_hex, rx_queue_hex = queue_info.split(':')
            tx_queue = int(tx_queue_hex, 16)
            rx_queue = int(rx_queue_hex, 16)

            # Get inode
            inode = int(parts[9])

            # Get drops if available (field 12, 0-indexed)
            drops = 0
            if len(parts) > 12:
                try:
                    drops = int(parts[12])
                except ValueError:
                    drops = 0

            sockets.append({
                'local_ip': hex_to_ip(local_ip),
                'local_port': local_port,
                'remote_ip': hex_to_ip(remote_ip),
                'remote_port': remote_port,
                'tx_queue': tx_queue,
                'rx_queue': rx_queue,
                'drops': drops,
                'inode': inode,
                'ipv6': ipv6,
            })
        except (ValueError, IndexError):
            continue

    return sockets


def get_all_sockets() -> List[Dict[str, Any]]:
    """Get all UDP sockets (IPv4 and IPv6)."""
    sockets = parse_udp_sockets(ipv6=False)
    sockets.extend(parse_udp_sockets(ipv6=True))
    return sockets


def enrich_with_process_info(sockets: List[Dict],
                              inode_map: Dict[int, Tuple[int, str]]) -> None:
    """Add process information to sockets."""
    for sock in sockets:
        inode = sock.get('inode', 0)
        if inode in inode_map:
            pid, comm = inode_map[inode]
            sock['pid'] = pid
            sock['process'] = comm
        else:
            sock['pid'] = None
            sock['process'] = None


def filter_sockets(sockets: List[Dict],
                    port_filter: Optional[int] = None,
                    process_filter: Optional[str] = None) -> List[Dict]:
    """Filter sockets by port or process."""
    filtered = sockets

    if port_filter is not None:
        filtered = [s for s in filtered
                    if s['local_port'] == port_filter or s['remote_port'] == port_filter]

    if process_filter:
        pattern = re.compile(process_filter, re.IGNORECASE)
        filtered = [s for s in filtered
                    if s.get('process') and pattern.search(s['process'])]

    return filtered


def analyze_sockets(sockets: List[Dict],
                     socket_warn: int,
                     rx_queue_warn: int,
                     tx_queue_warn: int) -> Dict[str, Any]:
    """Analyze sockets and generate summary."""
    # Count by process
    process_counts = defaultdict(lambda: {
        'count': 0,
        'total_rx_queue': 0,
        'total_tx_queue': 0,
        'total_drops': 0,
    })
    for sock in sockets:
        proc = sock.get('process') or 'unknown'
        process_counts[proc]['count'] += 1
        process_counts[proc]['total_rx_queue'] += sock['rx_queue']
        process_counts[proc]['total_tx_queue'] += sock['tx_queue']
        process_counts[proc]['total_drops'] += sock['drops']

    # Count by local port
    port_counts = defaultdict(lambda: {
        'count': 0,
        'total_rx_queue': 0,
        'total_tx_queue': 0,
    })
    for sock in sockets:
        port = sock['local_port']
        port_counts[port]['count'] += 1
        port_counts[port]['total_rx_queue'] += sock['rx_queue']
        port_counts[port]['total_tx_queue'] += sock['tx_queue']

    # Calculate totals
    total_rx_queue = sum(s['rx_queue'] for s in sockets)
    total_tx_queue = sum(s['tx_queue'] for s in sockets)
    total_drops = sum(s['drops'] for s in sockets)

    # Identify issues
    issues = []

    total_count = len(sockets)
    if total_count >= socket_warn:
        issues.append({
            'type': 'SOCKET_COUNT_HIGH',
            'severity': 'warning',
            'count': total_count,
            'threshold': socket_warn,
            'message': f'High UDP socket count: {total_count} (threshold: {socket_warn})'
        })

    if total_rx_queue >= rx_queue_warn:
        issues.append({
            'type': 'RX_QUEUE_HIGH',
            'severity': 'warning',
            'bytes': total_rx_queue,
            'threshold': rx_queue_warn,
            'message': f'High total RX queue: {total_rx_queue} bytes (threshold: {rx_queue_warn})'
        })

    if total_tx_queue >= tx_queue_warn:
        issues.append({
            'type': 'TX_QUEUE_HIGH',
            'severity': 'warning',
            'bytes': total_tx_queue,
            'threshold': tx_queue_warn,
            'message': f'High total TX queue: {total_tx_queue} bytes (threshold: {tx_queue_warn})'
        })

    # Find sockets with significant queue buildup
    for sock in sockets:
        if sock['rx_queue'] >= 100000:  # 100KB
            proc = sock.get('process') or 'unknown'
            issues.append({
                'type': 'SOCKET_RX_QUEUE_HIGH',
                'severity': 'warning',
                'process': proc,
                'port': sock['local_port'],
                'bytes': sock['rx_queue'],
                'message': f'Socket on port {sock["local_port"]} ({proc}) has {sock["rx_queue"]} bytes in RX queue'
            })

    # Find processes with many sockets
    for proc, stats in process_counts.items():
        if stats['count'] >= 100:
            issues.append({
                'type': 'PROCESS_SOCKET_HIGH',
                'severity': 'warning',
                'process': proc,
                'count': stats['count'],
                'message': f'Process "{proc}" has {stats["count"]} UDP sockets'
            })

    return {
        'total': len(sockets),
        'total_rx_queue': total_rx_queue,
        'total_tx_queue': total_tx_queue,
        'total_drops': total_drops,
        'process_counts': {k: dict(v) for k, v in process_counts.items()},
        'port_counts': {k: dict(v) for k, v in port_counts.items()},
        'issues': issues,
    }


def format_bytes(num: int) -> str:
    """Format bytes in human-readable form."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num) < 1024.0:
            return f"{num:.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}TB"


def output_plain(analysis: Dict, sockets: List[Dict],
                  warn_only: bool, verbose: bool, top_n: int) -> None:
    """Output in plain text format."""
    issues = analysis['issues']
    process_counts = analysis['process_counts']

    # Print issues first
    if issues:
        print("ISSUES DETECTED:")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")
        print()

    if warn_only and not issues:
        print("OK - No UDP socket issues detected")
        return

    # Summary
    print("UDP Socket Summary:")
    print(f"  Total sockets:     {analysis['total']:>10}")
    print(f"  Total RX queue:    {format_bytes(analysis['total_rx_queue']):>10}")
    print(f"  Total TX queue:    {format_bytes(analysis['total_tx_queue']):>10}")
    print(f"  Total drops:       {analysis['total_drops']:>10}")
    print()

    # Top processes by socket count
    if process_counts and not warn_only:
        print("Top Processes by Socket Count:")
        sorted_procs = sorted(
            process_counts.items(),
            key=lambda x: x[1].get('count', 0),
            reverse=True
        )[:top_n]

        print(f"  {'Process':<20} {'Sockets':>8} {'RX Queue':>12} {'TX Queue':>12}")
        print("  " + "-" * 56)
        for proc, stats in sorted_procs:
            print(f"  {proc:<20} {stats.get('count', 0):>8} "
                  f"{format_bytes(stats.get('total_rx_queue', 0)):>12} "
                  f"{format_bytes(stats.get('total_tx_queue', 0)):>12}")
        print()

    # Top ports by socket count
    port_counts = analysis['port_counts']
    if port_counts and not warn_only:
        print("Top Ports by Socket Count:")
        sorted_ports = sorted(
            port_counts.items(),
            key=lambda x: x[1].get('count', 0),
            reverse=True
        )[:top_n]

        print(f"  {'Port':<10} {'Sockets':>8} {'RX Queue':>12} {'TX Queue':>12}")
        print("  " + "-" * 46)
        for port, stats in sorted_ports:
            print(f"  {port:<10} {stats.get('count', 0):>8} "
                  f"{format_bytes(stats.get('total_rx_queue', 0)):>12} "
                  f"{format_bytes(stats.get('total_tx_queue', 0)):>12}")
        print()

    # Verbose: show individual sockets
    if verbose and sockets:
        print(f"Individual Sockets (showing up to {top_n}):")
        print(f"  {'Port':>6} {'RX Queue':>12} {'TX Queue':>12} {'Process':<15}")
        print("  " + "-" * 50)
        # Sort by RX queue descending
        sorted_sockets = sorted(sockets, key=lambda x: x['rx_queue'], reverse=True)
        for sock in sorted_sockets[:top_n]:
            proc = sock.get('process') or 'unknown'
            if len(proc) > 15:
                proc = proc[:12] + '...'
            print(f"  {sock['local_port']:>6} "
                  f"{format_bytes(sock['rx_queue']):>12} "
                  f"{format_bytes(sock['tx_queue']):>12} "
                  f"{proc:<15}")


def output_json(analysis: Dict, sockets: List[Dict]) -> None:
    """Output in JSON format."""
    status = 'warning' if analysis['issues'] else 'ok'

    result = {
        'status': status,
        'summary': {
            'total_sockets': analysis['total'],
            'total_rx_queue': analysis['total_rx_queue'],
            'total_tx_queue': analysis['total_tx_queue'],
            'total_drops': analysis['total_drops'],
            'issue_count': len(analysis['issues']),
        },
        'issues': analysis['issues'],
        'by_process': analysis['process_counts'],
        'by_port': {str(k): v for k, v in analysis['port_counts'].items()},
        'sockets': sockets,
    }
    print(json.dumps(result, indent=2))


def output_table(analysis: Dict, sockets: List[Dict],
                  warn_only: bool, top_n: int) -> None:
    """Output in table format."""
    issues = analysis['issues']

    if warn_only:
        if not issues:
            print("No UDP socket issues detected")
            return
        print(f"{'Type':<25} {'Severity':<10} {'Value':>12} {'Threshold':>12}")
        print("-" * 63)
        for issue in issues:
            issue_type = issue.get('type', 'UNKNOWN')
            value = issue.get('count', issue.get('bytes', 0))
            threshold = issue.get('threshold', 0)
            print(f"{issue_type:<25} {issue['severity']:<10} {value:>12} {threshold:>12}")
        return

    # Port table
    port_counts = analysis['port_counts']
    print(f"{'Port':<10} {'Sockets':>10} {'RX Queue':>15} {'TX Queue':>15}")
    print("-" * 54)
    sorted_ports = sorted(
        port_counts.items(),
        key=lambda x: x[1].get('count', 0),
        reverse=True
    )[:top_n]
    for port, stats in sorted_ports:
        print(f"{port:<10} {stats.get('count', 0):>10} "
              f"{format_bytes(stats.get('total_rx_queue', 0)):>15} "
              f"{format_bytes(stats.get('total_tx_queue', 0)):>15}")
    print("-" * 54)
    print(f"{'TOTAL':<10} {analysis['total']:>10} "
          f"{format_bytes(analysis['total_rx_queue']):>15} "
          f"{format_bytes(analysis['total_tx_queue']):>15}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor UDP socket usage for issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         Show UDP socket summary
  %(prog)s --warn-only             Only show if there are issues
  %(prog)s --port 53               Filter to sockets on port 53 (DNS)
  %(prog)s --process named         Filter to named processes
  %(prog)s --format json           JSON output for monitoring systems
  %(prog)s --socket-warn 500       Warn if socket count exceeds 500

Exit codes:
  0 - No UDP socket issues detected
  1 - UDP warnings or threshold exceeded
  2 - Usage error or unable to read socket information
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
        help='Show individual sockets'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show if there are issues'
    )

    parser.add_argument(
        '--port',
        type=int,
        metavar='PORT',
        help='Filter to sockets on this port'
    )

    parser.add_argument(
        '--process',
        type=str,
        metavar='PATTERN',
        help='Filter to processes matching pattern (regex)'
    )

    parser.add_argument(
        '--socket-warn',
        type=int,
        default=1000,
        metavar='N',
        help='Warn if socket count exceeds N (default: 1000)'
    )

    parser.add_argument(
        '--rx-queue-warn',
        type=int,
        default=1048576,
        metavar='BYTES',
        help='Warn if total RX queue exceeds BYTES (default: 1048576 / 1MB)'
    )

    parser.add_argument(
        '--tx-queue-warn',
        type=int,
        default=1048576,
        metavar='BYTES',
        help='Warn if total TX queue exceeds BYTES (default: 1048576 / 1MB)'
    )

    parser.add_argument(
        '--top',
        type=int,
        default=10,
        metavar='N',
        help='Show top N processes/ports (default: 10)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.socket_warn < 0:
        print("Error: --socket-warn must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.rx_queue_warn < 0:
        print("Error: --rx-queue-warn must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.tx_queue_warn < 0:
        print("Error: --tx-queue-warn must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.top < 0:
        print("Error: --top must be non-negative", file=sys.stderr)
        sys.exit(2)

    # Validate regex pattern
    if args.process:
        try:
            re.compile(args.process)
        except re.error as e:
            print(f"Error: Invalid process pattern: {e}", file=sys.stderr)
            sys.exit(2)

    # Check if we can read /proc
    if not os.path.isfile('/proc/net/udp'):
        print("Error: /proc/net/udp not available", file=sys.stderr)
        print("This script requires the procfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Get sockets
    sockets = get_all_sockets()

    # Build inode to process map
    inode_map = get_inode_to_pid_map()

    # Enrich with process info
    enrich_with_process_info(sockets, inode_map)

    # Apply filters
    sockets = filter_sockets(
        sockets,
        port_filter=args.port,
        process_filter=args.process
    )

    # Analyze
    analysis = analyze_sockets(
        sockets,
        socket_warn=args.socket_warn,
        rx_queue_warn=args.rx_queue_warn,
        tx_queue_warn=args.tx_queue_warn
    )

    # Output
    if args.format == 'json':
        output_json(analysis, sockets)
    elif args.format == 'table':
        output_table(analysis, sockets, args.warn_only, args.top)
    else:
        output_plain(analysis, sockets, args.warn_only, args.verbose, args.top)

    # Exit code based on issues
    if analysis['issues']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
