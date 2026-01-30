#!/usr/bin/env python3
"""
Monitor TCP connection states to detect connection leaks and pressure.

Analyzes /proc/net/tcp and /proc/net/tcp6 to provide visibility into TCP
connection states across the system. Identifies processes with high connection
counts, TIME_WAIT accumulation, and connection state anomalies.

Key features:
- Reports connection counts by state (ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.)
- Identifies processes with high connection counts
- Detects TIME_WAIT accumulation (potential port exhaustion)
- Detects CLOSE_WAIT accumulation (application not closing connections)
- Supports filtering by port, process, or state

Use cases:
- Detecting connection leaks in long-running services
- Identifying port exhaustion risk from TIME_WAIT buildup
- Finding services not properly closing connections (CLOSE_WAIT)
- Pre-incident visibility into connection pressure
- Capacity planning for high-connection workloads

Exit codes:
    0 - No connection issues detected
    1 - Connection warnings or threshold exceeded
    2 - Usage error or unable to read connection information
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# TCP state constants from include/net/tcp_states.h
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
        # Little-endian byte order in /proc/net/tcp
        ip_int = int(hex_ip, 16)
        return '.'.join([
            str((ip_int >> 0) & 0xFF),
            str((ip_int >> 8) & 0xFF),
            str((ip_int >> 16) & 0xFF),
            str((ip_int >> 24) & 0xFF),
        ])
    # Handle IPv6 (simplified - just return shortened form)
    elif len(hex_ip) == 32:
        # For display purposes, just show abbreviated form
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


def parse_tcp_connections(ipv6: bool = False) -> List[Dict[str, Any]]:
    """Parse /proc/net/tcp or /proc/net/tcp6."""
    path = '/proc/net/tcp6' if ipv6 else '/proc/net/tcp'
    content = read_proc_file(path)
    if not content:
        return []

    connections = []
    lines = content.strip().split('\n')[1:]  # Skip header

    for line in lines:
        parts = line.split()
        if len(parts) < 12:
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

            # Get state
            state_hex = parts[3].upper()
            state = TCP_STATES.get(state_hex, f'UNKNOWN({state_hex})')

            # Get inode
            inode = int(parts[9])

            connections.append({
                'local_ip': hex_to_ip(local_ip),
                'local_port': local_port,
                'remote_ip': hex_to_ip(remote_ip),
                'remote_port': remote_port,
                'state': state,
                'inode': inode,
                'ipv6': ipv6,
            })
        except (ValueError, IndexError):
            continue

    return connections


def get_all_connections() -> List[Dict[str, Any]]:
    """Get all TCP connections (IPv4 and IPv6)."""
    connections = parse_tcp_connections(ipv6=False)
    connections.extend(parse_tcp_connections(ipv6=True))
    return connections


def enrich_with_process_info(connections: List[Dict],
                              inode_map: Dict[int, Tuple[int, str]]) -> None:
    """Add process information to connections."""
    for conn in connections:
        inode = conn.get('inode', 0)
        if inode in inode_map:
            pid, comm = inode_map[inode]
            conn['pid'] = pid
            conn['process'] = comm
        else:
            conn['pid'] = None
            conn['process'] = None


def filter_connections(connections: List[Dict],
                        port_filter: Optional[int] = None,
                        process_filter: Optional[str] = None,
                        state_filter: Optional[str] = None) -> List[Dict]:
    """Filter connections by port, process, or state."""
    filtered = connections

    if port_filter is not None:
        filtered = [c for c in filtered
                    if c['local_port'] == port_filter or c['remote_port'] == port_filter]

    if process_filter:
        pattern = re.compile(process_filter, re.IGNORECASE)
        filtered = [c for c in filtered
                    if c.get('process') and pattern.search(c['process'])]

    if state_filter:
        state_upper = state_filter.upper()
        filtered = [c for c in filtered if c['state'] == state_upper]

    return filtered


def analyze_connections(connections: List[Dict],
                         time_wait_warn: int,
                         close_wait_warn: int,
                         total_warn: int) -> Dict[str, Any]:
    """Analyze connections and generate summary."""
    # Count by state
    state_counts = defaultdict(int)
    for conn in connections:
        state_counts[conn['state']] += 1

    # Count by process
    process_counts = defaultdict(lambda: defaultdict(int))
    for conn in connections:
        proc = conn.get('process') or 'unknown'
        process_counts[proc]['total'] += 1
        process_counts[proc][conn['state']] += 1

    # Count by local port (for listening services)
    port_counts = defaultdict(lambda: defaultdict(int))
    for conn in connections:
        if conn['state'] == 'LISTEN':
            port = conn['local_port']
            port_counts[port]['listeners'] += 1
        elif conn['state'] == 'ESTABLISHED':
            port = conn['local_port']
            port_counts[port]['established'] += 1

    # Identify issues
    issues = []

    time_wait_count = state_counts.get('TIME_WAIT', 0)
    if time_wait_count >= time_wait_warn:
        issues.append({
            'type': 'TIME_WAIT_HIGH',
            'severity': 'warning',
            'count': time_wait_count,
            'threshold': time_wait_warn,
            'message': f'High TIME_WAIT count: {time_wait_count} (threshold: {time_wait_warn})'
        })

    close_wait_count = state_counts.get('CLOSE_WAIT', 0)
    if close_wait_count >= close_wait_warn:
        issues.append({
            'type': 'CLOSE_WAIT_HIGH',
            'severity': 'warning',
            'count': close_wait_count,
            'threshold': close_wait_warn,
            'message': f'High CLOSE_WAIT count: {close_wait_count} (threshold: {close_wait_warn})'
        })

    total_count = len(connections)
    if total_count >= total_warn:
        issues.append({
            'type': 'TOTAL_HIGH',
            'severity': 'warning',
            'count': total_count,
            'threshold': total_warn,
            'message': f'High total connection count: {total_count} (threshold: {total_warn})'
        })

    # Find processes with high CLOSE_WAIT (potential leak)
    for proc, counts in process_counts.items():
        proc_close_wait = counts.get('CLOSE_WAIT', 0)
        if proc_close_wait >= 10:
            issues.append({
                'type': 'PROCESS_CLOSE_WAIT',
                'severity': 'warning',
                'process': proc,
                'count': proc_close_wait,
                'message': f'Process "{proc}" has {proc_close_wait} CLOSE_WAIT connections'
            })

    return {
        'total': len(connections),
        'state_counts': dict(state_counts),
        'process_counts': {k: dict(v) for k, v in process_counts.items()},
        'port_counts': {k: dict(v) for k, v in port_counts.items()},
        'issues': issues,
    }


def output_plain(analysis: Dict, connections: List[Dict],
                  warn_only: bool, verbose: bool, top_n: int) -> None:
    """Output in plain text format."""
    issues = analysis['issues']
    state_counts = analysis['state_counts']
    process_counts = analysis['process_counts']

    # Print issues first
    if issues:
        print("ISSUES DETECTED:")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")
        print()

    if warn_only and not issues:
        print("OK - No connection issues detected")
        return

    # State summary
    print("Connection States:")
    for state in ['ESTABLISHED', 'LISTEN', 'TIME_WAIT', 'CLOSE_WAIT',
                  'FIN_WAIT1', 'FIN_WAIT2', 'SYN_SENT', 'SYN_RECV',
                  'LAST_ACK', 'CLOSING', 'CLOSE']:
        count = state_counts.get(state, 0)
        if count > 0:
            print(f"  {state:<12} {count:>6}")
    print(f"  {'TOTAL':<12} {analysis['total']:>6}")
    print()

    # Top processes by connection count
    if process_counts and not warn_only:
        print("Top Processes by Connection Count:")
        sorted_procs = sorted(
            process_counts.items(),
            key=lambda x: x[1].get('total', 0),
            reverse=True
        )[:top_n]

        print(f"  {'Process':<20} {'Total':>8} {'ESTAB':>8} {'T_WAIT':>8} {'C_WAIT':>8}")
        print("  " + "-" * 56)
        for proc, counts in sorted_procs:
            print(f"  {proc:<20} {counts.get('total', 0):>8} "
                  f"{counts.get('ESTABLISHED', 0):>8} "
                  f"{counts.get('TIME_WAIT', 0):>8} "
                  f"{counts.get('CLOSE_WAIT', 0):>8}")
        print()

    # Verbose: show individual connections
    if verbose and connections:
        print(f"Individual Connections (showing up to {top_n}):")
        print(f"  {'State':<12} {'Local Port':>10} {'Remote':>15} {'Process':<15}")
        print("  " + "-" * 56)
        for conn in connections[:top_n]:
            remote = f"{conn['remote_ip']}:{conn['remote_port']}"
            if len(remote) > 15:
                remote = remote[:12] + '...'
            proc = conn.get('process') or 'unknown'
            if len(proc) > 15:
                proc = proc[:12] + '...'
            print(f"  {conn['state']:<12} {conn['local_port']:>10} "
                  f"{remote:>15} {proc:<15}")


def output_json(analysis: Dict, connections: List[Dict]) -> None:
    """Output in JSON format."""
    status = 'warning' if analysis['issues'] else 'ok'

    result = {
        'status': status,
        'summary': {
            'total_connections': analysis['total'],
            'state_counts': analysis['state_counts'],
            'issue_count': len(analysis['issues']),
        },
        'issues': analysis['issues'],
        'by_process': analysis['process_counts'],
        'connections': connections,
    }
    print(json.dumps(result, indent=2))


def output_table(analysis: Dict, connections: List[Dict],
                  warn_only: bool, top_n: int) -> None:
    """Output in table format."""
    issues = analysis['issues']

    if warn_only:
        if not issues:
            print("No connection issues detected")
            return
        print(f"{'Type':<20} {'Severity':<10} {'Count':>8} {'Threshold':>10}")
        print("-" * 52)
        for issue in issues:
            issue_type = issue.get('type', 'UNKNOWN')
            print(f"{issue_type:<20} {issue['severity']:<10} "
                  f"{issue.get('count', 0):>8} {issue.get('threshold', 0):>10}")
        return

    # State table
    print(f"{'State':<12} {'Count':>10} {'Percent':>10}")
    print("-" * 34)
    total = analysis['total'] or 1
    for state, count in sorted(analysis['state_counts'].items(),
                                key=lambda x: -x[1]):
        pct = (count / total) * 100
        print(f"{state:<12} {count:>10} {pct:>9.1f}%")
    print("-" * 34)
    print(f"{'TOTAL':<12} {total:>10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor TCP connection states for issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         Show connection state summary
  %(prog)s --warn-only             Only show if there are issues
  %(prog)s --port 80               Filter to connections on port 80
  %(prog)s --process nginx         Filter to nginx processes
  %(prog)s --state TIME_WAIT       Show only TIME_WAIT connections
  %(prog)s --format json           JSON output for monitoring systems
  %(prog)s --time-wait-warn 5000   Warn if TIME_WAIT exceeds 5000

Exit codes:
  0 - No connection issues detected
  1 - Connection warnings or threshold exceeded
  2 - Usage error or unable to read connection information
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
        help='Show individual connections'
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
        help='Filter to connections on this port'
    )

    parser.add_argument(
        '--process',
        type=str,
        metavar='PATTERN',
        help='Filter to processes matching pattern (regex)'
    )

    parser.add_argument(
        '--state',
        type=str,
        metavar='STATE',
        help='Filter to connections in this state (e.g., ESTABLISHED, TIME_WAIT)'
    )

    parser.add_argument(
        '--time-wait-warn',
        type=int,
        default=10000,
        metavar='N',
        help='Warn if TIME_WAIT count exceeds N (default: 10000)'
    )

    parser.add_argument(
        '--close-wait-warn',
        type=int,
        default=100,
        metavar='N',
        help='Warn if CLOSE_WAIT count exceeds N (default: 100)'
    )

    parser.add_argument(
        '--total-warn',
        type=int,
        default=50000,
        metavar='N',
        help='Warn if total connection count exceeds N (default: 50000)'
    )

    parser.add_argument(
        '--top',
        type=int,
        default=10,
        metavar='N',
        help='Show top N processes/connections (default: 10)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.time_wait_warn < 0:
        print("Error: --time-wait-warn must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.close_wait_warn < 0:
        print("Error: --close-wait-warn must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.total_warn < 0:
        print("Error: --total-warn must be non-negative", file=sys.stderr)
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

    # Validate state
    if args.state:
        valid_states = list(TCP_STATES.values())
        if args.state.upper() not in valid_states:
            print(f"Error: Invalid state '{args.state}'", file=sys.stderr)
            print(f"Valid states: {', '.join(valid_states)}", file=sys.stderr)
            sys.exit(2)

    # Check if we can read /proc
    if not os.path.isfile('/proc/net/tcp'):
        print("Error: /proc/net/tcp not available", file=sys.stderr)
        print("This script requires the procfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Get connections
    connections = get_all_connections()

    # Build inode to process map
    inode_map = get_inode_to_pid_map()

    # Enrich with process info
    enrich_with_process_info(connections, inode_map)

    # Apply filters
    connections = filter_connections(
        connections,
        port_filter=args.port,
        process_filter=args.process,
        state_filter=args.state
    )

    # Analyze
    analysis = analyze_connections(
        connections,
        time_wait_warn=args.time_wait_warn,
        close_wait_warn=args.close_wait_warn,
        total_warn=args.total_warn
    )

    # Output
    if args.format == 'json':
        output_json(analysis, connections)
    elif args.format == 'table':
        output_table(analysis, connections, args.warn_only, args.top)
    else:
        output_plain(analysis, connections, args.warn_only, args.verbose, args.top)

    # Exit code based on issues
    if analysis['issues']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
