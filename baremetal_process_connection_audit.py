#!/usr/bin/env python3
"""
Audit active network connections per process on baremetal systems.

This script analyzes /proc/net/tcp and /proc/net/tcp6 to identify all ESTABLISHED,
SYN_SENT, and other non-LISTEN connections with their owning processes. It helps:
- Identify which processes have active outbound connections
- Detect processes with excessive connection counts
- Find unexpected outbound connections (security auditing)
- Troubleshoot connectivity issues by mapping connections to processes
- Audit network behavior of applications

Unlike listening port monitors, this script focuses on ACTIVE connections to show
what your processes are actually communicating with.

Exit codes:
    0 - No issues detected
    1 - Processes exceed connection thresholds or unexpected connections found
    2 - Missing required /proc files or usage error
"""

import argparse
import sys
import json
import os
from collections import defaultdict

# TCP state mapping from /proc/net/tcp
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

# States to include (exclude LISTEN - that's for listening port monitor)
ACTIVE_STATES = {'01', '02', '03', '04', '05', '06', '08', '09', '0B'}


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
                                # Get command line for more detail
                                try:
                                    with open(f'/proc/{pid}/cmdline', 'r') as f:
                                        cmdline = f.read().replace('\x00', ' ').strip()
                                except (OSError, IOError):
                                    cmdline = ''
                                inode_map[inode] = {
                                    'pid': int(pid),
                                    'name': name,
                                    'cmdline': cmdline[:100] if cmdline else name
                                }
                    except (OSError, IOError):
                        continue
            except (OSError, IOError):
                continue
    except (OSError, IOError):
        pass
    return inode_map


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


def parse_connections(file_path, protocol):
    """Parse /proc/net socket file for active (non-LISTEN) connections."""
    connections = []
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

        state_hex = parts[3]
        # Only include active (non-LISTEN) states
        if state_hex not in ACTIVE_STATES:
            continue

        state_name = TCP_STATES.get(state_hex, 'UNKNOWN')

        # Extract local address and port
        local_addr = parts[1]
        local_parts = local_addr.split(':')
        local_ip = hex_to_ip(local_parts[0])
        local_port = int(local_parts[1], 16)

        # Extract remote address and port
        remote_addr = parts[2]
        remote_parts = remote_addr.split(':')
        remote_ip = hex_to_ip(remote_parts[0])
        remote_port = int(remote_parts[1], 16)

        # Get inode for process lookup
        inode = parts[9]

        connections.append({
            'protocol': protocol,
            'state': state_name,
            'local_ip': local_ip,
            'local_port': local_port,
            'remote_ip': remote_ip,
            'remote_port': remote_port,
            'inode': inode,
        })

    return connections


def analyze_connections(connections, max_per_process, max_to_single_host):
    """Analyze connections and detect potential issues."""
    issues = []

    # Group by process
    by_process = defaultdict(list)
    for conn in connections:
        proc = conn.get('process', {})
        key = (proc.get('pid'), proc.get('name', '-'))
        by_process[key].append(conn)

    # Check for processes with too many connections
    for (pid, name), conns in by_process.items():
        if len(conns) > max_per_process:
            issues.append({
                'severity': 'warning',
                'type': 'excessive_connections',
                'pid': pid,
                'process': name,
                'count': len(conns),
                'threshold': max_per_process,
                'message': f"Process {name} (PID {pid}) has {len(conns)} connections (threshold: {max_per_process})"
            })

        # Check connections to single remote host
        remote_counts = defaultdict(int)
        for conn in conns:
            remote_counts[conn['remote_ip']] += 1

        for remote_ip, count in remote_counts.items():
            if count > max_to_single_host:
                issues.append({
                    'severity': 'info',
                    'type': 'many_to_single_host',
                    'pid': pid,
                    'process': name,
                    'remote_ip': remote_ip,
                    'count': count,
                    'threshold': max_to_single_host,
                    'message': f"Process {name} has {count} connections to {remote_ip}"
                })

    return issues


def get_process_summary(connections):
    """Generate per-process connection summary."""
    by_process = defaultdict(lambda: {
        'connections': [],
        'remote_hosts': set(),
        'remote_ports': set(),
        'states': defaultdict(int)
    })

    for conn in connections:
        proc = conn.get('process', {})
        key = (proc.get('pid'), proc.get('name', '-'))
        summary = by_process[key]
        summary['connections'].append(conn)
        summary['remote_hosts'].add(conn['remote_ip'])
        summary['remote_ports'].add(conn['remote_port'])
        summary['states'][conn['state']] += 1
        summary['pid'] = proc.get('pid')
        summary['name'] = proc.get('name', '-')
        summary['cmdline'] = proc.get('cmdline', '')

    # Convert sets to counts for JSON serialization
    result = []
    for key, summary in sorted(by_process.items(), key=lambda x: -len(x[1]['connections'])):
        result.append({
            'pid': summary['pid'],
            'name': summary['name'],
            'cmdline': summary['cmdline'],
            'connection_count': len(summary['connections']),
            'unique_remote_hosts': len(summary['remote_hosts']),
            'unique_remote_ports': len(summary['remote_ports']),
            'state_breakdown': dict(summary['states']),
            'top_remotes': get_top_remotes(summary['connections'], 5)
        })

    return result


def get_top_remotes(connections, limit):
    """Get top remote hosts by connection count."""
    counts = defaultdict(int)
    for conn in connections:
        key = f"{conn['remote_ip']}:{conn['remote_port']}"
        counts[key] += 1

    return [
        {'remote': k, 'count': v}
        for k, v in sorted(counts.items(), key=lambda x: -x[1])[:limit]
    ]


def output_plain(connections, process_summary, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only or issues:
        print("Process Connection Summary:")
        print(f"{'PID':>8} {'Process':<20} {'Conns':>6} {'Hosts':>6} {'Ports':>6} {'Top Remote'}")
        print("-" * 85)

        for proc in process_summary[:20]:  # Top 20 processes
            pid = proc['pid'] if proc['pid'] else '-'
            top_remote = proc['top_remotes'][0]['remote'] if proc['top_remotes'] else '-'
            print(f"{str(pid):>8} {proc['name']:<20} {proc['connection_count']:>6} "
                  f"{proc['unique_remote_hosts']:>6} {proc['unique_remote_ports']:>6} {top_remote}")

        if len(process_summary) > 20:
            print(f"  ... and {len(process_summary) - 20} more processes")

        print(f"\nTotal: {len(connections)} active connections across {len(process_summary)} processes")

        if verbose:
            # Show state breakdown
            state_counts = defaultdict(int)
            for conn in connections:
                state_counts[conn['state']] += 1
            print("\nState Distribution:")
            for state, count in sorted(state_counts.items(), key=lambda x: -x[1]):
                print(f"  {state:<15} {count:>6}")

    if issues:
        print(f"\nIssues Detected ({len(issues)}):")
        for issue in issues:
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")
    elif not warn_only:
        print("\n[OK] No anomalies detected")


def output_json(connections, process_summary, issues):
    """Output results in JSON format."""
    state_counts = defaultdict(int)
    for conn in connections:
        state_counts[conn['state']] += 1

    result = {
        'process_summary': process_summary,
        'state_counts': dict(state_counts),
        'issues': issues,
        'summary': {
            'total_connections': len(connections),
            'total_processes': len(process_summary),
            'established': state_counts.get('ESTABLISHED', 0),
            'time_wait': state_counts.get('TIME_WAIT', 0),
            'close_wait': state_counts.get('CLOSE_WAIT', 0),
        },
        'has_issues': len(issues) > 0
    }
    print(json.dumps(result, indent=2))


def output_table(connections, process_summary, issues, verbose, warn_only):
    """Output results in table format with connection details."""
    if not warn_only or issues:
        if verbose:
            # Show individual connections
            print(f"{'PID':>8} {'Process':<15} {'State':<12} {'Local':<22} {'Remote'}")
            print("-" * 90)
            for conn in sorted(connections, key=lambda x: (x.get('process', {}).get('name', ''), x['state']))[:50]:
                proc = conn.get('process', {})
                pid = str(proc.get('pid', '-'))
                name = proc.get('name', '-')[:15]
                local = f"{conn['local_ip']}:{conn['local_port']}"
                remote = f"{conn['remote_ip']}:{conn['remote_port']}"
                print(f"{pid:>8} {name:<15} {conn['state']:<12} {local:<22} {remote}")

            if len(connections) > 50:
                print(f"  ... and {len(connections) - 50} more connections")
        else:
            # Show process summary
            print(f"{'PID':>8} {'Process':<20} {'Connections':>12} {'Unique Hosts':>12}")
            print("-" * 55)
            for proc in process_summary:
                pid = str(proc['pid']) if proc['pid'] else '-'
                print(f"{pid:>8} {proc['name']:<20} {proc['connection_count']:>12} {proc['unique_remote_hosts']:>12}")

    if issues:
        print(f"\nIssues ({len(issues)}):")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Audit active network connections per process",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Show process connection summary
  %(prog)s --format json                # Output in JSON format
  %(prog)s -v                           # Show individual connections
  %(prog)s --max-per-process 500        # Alert if process has >500 connections
  %(prog)s --process nginx              # Filter to specific process name
  %(prog)s --remote-port 443            # Filter to connections on port 443
  %(prog)s --state ESTABLISHED          # Filter to specific TCP state
  %(prog)s -w                           # Only show if issues detected

Exit codes:
  0 - No issues detected
  1 - Processes exceed thresholds
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
        help="Show individual connections instead of summary"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if issues are detected"
    )

    parser.add_argument(
        "--max-per-process",
        type=int,
        default=1000,
        metavar="N",
        help="Alert if a process has more than N connections (default: %(default)s)"
    )

    parser.add_argument(
        "--max-to-single-host",
        type=int,
        default=100,
        metavar="N",
        help="Alert if process has >N connections to single host (default: %(default)s)"
    )

    parser.add_argument(
        "--process",
        metavar="NAME",
        help="Filter to connections owned by specific process name"
    )

    parser.add_argument(
        "--pid",
        type=int,
        metavar="PID",
        help="Filter to connections owned by specific PID"
    )

    parser.add_argument(
        "--remote-port",
        type=int,
        metavar="PORT",
        help="Filter to connections to specific remote port"
    )

    parser.add_argument(
        "--remote-ip",
        metavar="IP",
        help="Filter to connections to specific remote IP"
    )

    parser.add_argument(
        "--state",
        choices=list(TCP_STATES.values()),
        help="Filter to specific TCP state"
    )

    parser.add_argument(
        "--exclude-loopback",
        action="store_true",
        help="Exclude connections to localhost/127.0.0.1/::1"
    )

    args = parser.parse_args()

    # Collect connections from TCP files
    all_connections = []

    for file_path, protocol in [('/proc/net/tcp', 'tcp'), ('/proc/net/tcp6', 'tcp6')]:
        connections = parse_connections(file_path, protocol)
        if connections is None:
            print(f"Error: Cannot read {file_path}", file=sys.stderr)
            print("This script requires access to /proc/net files", file=sys.stderr)
            sys.exit(2)
        all_connections.extend(connections)

    # Build inode-to-process map
    inode_map = build_inode_to_process_map()

    # Look up process info for each connection
    for conn in all_connections:
        conn['process'] = inode_map.get(conn['inode'], {'pid': None, 'name': '-', 'cmdline': ''})
        del conn['inode']

    # Apply filters
    if args.process:
        all_connections = [c for c in all_connections
                          if args.process.lower() in c['process'].get('name', '').lower()]

    if args.pid:
        all_connections = [c for c in all_connections
                          if c['process'].get('pid') == args.pid]

    if args.remote_port:
        all_connections = [c for c in all_connections
                          if c['remote_port'] == args.remote_port]

    if args.remote_ip:
        all_connections = [c for c in all_connections
                          if c['remote_ip'] == args.remote_ip]

    if args.state:
        all_connections = [c for c in all_connections
                          if c['state'] == args.state]

    if args.exclude_loopback:
        loopback = {'127.0.0.1', '::1', '::ffff:127.0.0.1'}
        all_connections = [c for c in all_connections
                          if c['remote_ip'] not in loopback]

    # Generate process summary
    process_summary = get_process_summary(all_connections)

    # Analyze for issues
    issues = analyze_connections(all_connections, args.max_per_process, args.max_to_single_host)

    # Output results
    if args.format == "json":
        output_json(all_connections, process_summary, issues)
    elif args.format == "table":
        output_table(all_connections, process_summary, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(all_connections, process_summary, issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
