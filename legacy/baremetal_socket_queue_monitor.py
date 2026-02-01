#!/usr/bin/env python3
"""
Monitor socket queue depths to identify applications with backed-up buffers.

This script analyzes socket receive and send queue depths using /proc/net data
and ss command output to identify:
- Sockets with large receive queues (slow consumers)
- Sockets with large send queues (network congestion or slow peers)
- Listening sockets with accept queue backlog
- Per-process socket queue statistics

Large socket queues can indicate:
- Application unable to keep up with incoming data
- Network congestion causing send buffers to fill
- Slow peers not acknowledging data
- Memory pressure from excessive buffering

Exit codes:
    0 - All socket queues within thresholds
    1 - Warning or critical queue depths detected
    2 - Usage error or missing data sources
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict


def read_file(path):
    """Read file contents, return None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError, PermissionError):
        return None


def get_process_name(pid):
    """Get process command name from /proc."""
    comm = read_file(f'/proc/{pid}/comm')
    if comm:
        return comm.strip()
    return None


def get_process_cmdline(pid):
    """Get process command line from /proc."""
    cmdline = read_file(f'/proc/{pid}/cmdline')
    if cmdline:
        return cmdline.replace('\x00', ' ').strip()
    return None


def parse_ss_output(protocol='tcp'):
    """
    Parse ss command output to get socket queue information.

    Returns list of socket info dicts with queue depths and process info.
    """
    sockets = []

    try:
        # Use ss with extended info (-e) and process info (-p)
        cmd = ['ss', '-n', '-a', '-e', '-p']
        if protocol == 'tcp':
            cmd.append('-t')
        elif protocol == 'udp':
            cmd.append('-u')

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return sockets

        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:
            return sockets

        # Skip header line
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue

            state = parts[0]
            recv_q = int(parts[1]) if parts[1].isdigit() else 0
            send_q = int(parts[2]) if parts[2].isdigit() else 0
            local_addr = parts[3]
            peer_addr = parts[4] if len(parts) > 4 else '*:*'

            # Extract process info if available
            pid = None
            process_name = None
            process_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if process_match:
                process_name = process_match.group(1)
                pid = int(process_match.group(2))

            socket_info = {
                'protocol': protocol,
                'state': state,
                'recv_q': recv_q,
                'send_q': send_q,
                'local_addr': local_addr,
                'peer_addr': peer_addr,
                'pid': pid,
                'process': process_name,
            }

            sockets.append(socket_info)

    except FileNotFoundError:
        pass
    except Exception:
        pass

    return sockets


def parse_proc_net_tcp():
    """
    Parse /proc/net/tcp for TCP socket queue information.

    This provides socket info even without ss command privileges.
    Returns list of socket info dicts.
    """
    sockets = []

    for path, version in [('/proc/net/tcp', '4'), ('/proc/net/tcp6', '6')]:
        content = read_file(path)
        if not content:
            continue

        lines = content.strip().split('\n')
        if len(lines) < 2:
            continue

        # Skip header
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 12:
                continue

            # Parse local address and port
            local_parts = parts[1].split(':')
            if len(local_parts) != 2:
                continue

            # Parse remote address and port
            remote_parts = parts[2].split(':')
            if len(remote_parts) != 2:
                continue

            # Parse queue depths (tx_queue:rx_queue)
            queue_parts = parts[4].split(':')
            if len(queue_parts) != 2:
                continue

            tx_queue = int(queue_parts[0], 16)
            rx_queue = int(queue_parts[1], 16)

            # Parse state
            state_hex = int(parts[3], 16)
            state_map = {
                1: 'ESTABLISHED',
                2: 'SYN_SENT',
                3: 'SYN_RECV',
                4: 'FIN_WAIT1',
                5: 'FIN_WAIT2',
                6: 'TIME_WAIT',
                7: 'CLOSE',
                8: 'CLOSE_WAIT',
                9: 'LAST_ACK',
                10: 'LISTEN',
                11: 'CLOSING',
            }
            state = state_map.get(state_hex, f'UNKNOWN({state_hex})')

            # Get inode for process lookup
            inode = parts[9]

            # Convert hex IP to readable format
            def hex_to_ip(hex_ip, version):
                if version == '4':
                    # IPv4: little-endian hex
                    ip_int = int(hex_ip, 16)
                    return '.'.join(str((ip_int >> (8 * i)) & 0xFF) for i in range(4))
                else:
                    # IPv6: more complex, simplified here
                    return hex_ip

            local_ip = hex_to_ip(local_parts[0], version)
            local_port = int(local_parts[1], 16)
            remote_ip = hex_to_ip(remote_parts[0], version)
            remote_port = int(remote_parts[1], 16)

            socket_info = {
                'protocol': f'tcp{version}',
                'state': state,
                'recv_q': rx_queue,
                'send_q': tx_queue,
                'local_addr': f'{local_ip}:{local_port}',
                'peer_addr': f'{remote_ip}:{remote_port}',
                'inode': inode,
            }

            sockets.append(socket_info)

    return sockets


def find_socket_owner(inode):
    """Find the process owning a socket by inode."""
    try:
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue

            pid = entry
            fd_path = f'/proc/{pid}/fd'

            try:
                for fd in os.listdir(fd_path):
                    try:
                        link = os.readlink(f'{fd_path}/{fd}')
                        if f'socket:[{inode}]' in link:
                            return int(pid), get_process_name(pid)
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue
    except Exception:
        pass

    return None, None


def analyze_sockets(sockets, recv_warn, recv_crit, send_warn, send_crit,
                    listen_warn, listen_crit, min_queue):
    """
    Analyze sockets and identify those with concerning queue depths.

    Returns dict with categorized issues.
    """
    issues = {
        'critical': [],
        'warning': [],
        'info': [],
    }

    # Aggregate stats by process
    process_stats = defaultdict(lambda: {
        'total_recv_q': 0,
        'total_send_q': 0,
        'socket_count': 0,
        'max_recv_q': 0,
        'max_send_q': 0,
    })

    for sock in sockets:
        recv_q = sock['recv_q']
        send_q = sock['send_q']
        state = sock['state']

        # Skip sockets below minimum threshold
        if recv_q < min_queue and send_q < min_queue:
            continue

        # Track per-process stats
        if sock.get('pid') or sock.get('process'):
            key = sock.get('process') or f'pid:{sock.get("pid")}'
            process_stats[key]['total_recv_q'] += recv_q
            process_stats[key]['total_send_q'] += send_q
            process_stats[key]['socket_count'] += 1
            process_stats[key]['max_recv_q'] = max(
                process_stats[key]['max_recv_q'], recv_q
            )
            process_stats[key]['max_send_q'] = max(
                process_stats[key]['max_send_q'], send_q
            )

        issue = {
            'socket': sock,
            'reasons': [],
        }

        severity = None

        # Check receive queue for LISTEN sockets (accept backlog)
        if state == 'LISTEN':
            if recv_q >= listen_crit:
                issue['reasons'].append(
                    f'Listen backlog critical: {recv_q} pending connections'
                )
                severity = 'critical'
            elif recv_q >= listen_warn:
                issue['reasons'].append(
                    f'Listen backlog warning: {recv_q} pending connections'
                )
                severity = 'warning'
        else:
            # Check receive queue for established connections
            if recv_q >= recv_crit:
                issue['reasons'].append(
                    f'Receive queue critical: {recv_q} bytes buffered'
                )
                severity = 'critical'
            elif recv_q >= recv_warn:
                issue['reasons'].append(
                    f'Receive queue warning: {recv_q} bytes buffered'
                )
                severity = 'warning' if not severity else severity

        # Check send queue
        if send_q >= send_crit:
            issue['reasons'].append(
                f'Send queue critical: {send_q} bytes buffered'
            )
            severity = 'critical'
        elif send_q >= send_warn:
            issue['reasons'].append(
                f'Send queue warning: {send_q} bytes buffered'
            )
            severity = 'warning' if not severity else severity

        if issue['reasons']:
            issues[severity or 'info'].append(issue)

    return issues, dict(process_stats)


def format_size(bytes_val):
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(bytes_val) < 1024.0:
            return f'{bytes_val:.1f}{unit}'
        bytes_val /= 1024.0
    return f'{bytes_val:.1f}TB'


def output_plain(issues, process_stats, warn_only=False, verbose=False):
    """Output results in plain text format."""
    lines = []

    critical = issues['critical']
    warnings = issues['warning']

    if critical:
        lines.append(f'CRITICAL Socket Queue Issues ({len(critical)}):')
        for issue in critical:
            sock = issue['socket']
            proc_info = f" [{sock.get('process', 'unknown')}]" if sock.get('process') else ''
            lines.append(
                f"  {sock['protocol']} {sock['local_addr']} -> {sock['peer_addr']}"
                f" state={sock['state']}{proc_info}"
            )
            lines.append(f"    Recv-Q: {format_size(sock['recv_q'])}  "
                        f"Send-Q: {format_size(sock['send_q'])}")
            for reason in issue['reasons']:
                lines.append(f"    - {reason}")
        lines.append('')

    if warnings:
        lines.append(f'WARNING Socket Queue Issues ({len(warnings)}):')
        for issue in warnings:
            sock = issue['socket']
            proc_info = f" [{sock.get('process', 'unknown')}]" if sock.get('process') else ''
            lines.append(
                f"  {sock['protocol']} {sock['local_addr']} -> {sock['peer_addr']}"
                f" state={sock['state']}{proc_info}"
            )
            lines.append(f"    Recv-Q: {format_size(sock['recv_q'])}  "
                        f"Send-Q: {format_size(sock['send_q'])}")
            if verbose:
                for reason in issue['reasons']:
                    lines.append(f"    - {reason}")
        lines.append('')

    if verbose and process_stats:
        lines.append('Per-Process Socket Statistics:')
        sorted_procs = sorted(
            process_stats.items(),
            key=lambda x: x[1]['total_recv_q'] + x[1]['total_send_q'],
            reverse=True
        )[:10]
        for proc, stats in sorted_procs:
            lines.append(
                f"  {proc}: {stats['socket_count']} sockets, "
                f"total recv={format_size(stats['total_recv_q'])}, "
                f"total send={format_size(stats['total_send_q'])}"
            )
        lines.append('')

    if not critical and not warnings:
        if not warn_only:
            lines.append('All socket queues within normal thresholds.')
    else:
        lines.append(
            f'Summary: {len(critical)} critical, {len(warnings)} warnings'
        )

    return '\n'.join(lines)


def output_json(issues, process_stats):
    """Output results in JSON format."""
    result = {
        'issues': {
            'critical': [
                {
                    'socket': i['socket'],
                    'reasons': i['reasons'],
                }
                for i in issues['critical']
            ],
            'warning': [
                {
                    'socket': i['socket'],
                    'reasons': i['reasons'],
                }
                for i in issues['warning']
            ],
        },
        'process_stats': process_stats,
        'summary': {
            'critical_count': len(issues['critical']),
            'warning_count': len(issues['warning']),
        },
    }
    return json.dumps(result, indent=2)


def output_table(issues, warn_only=False):
    """Output results in table format."""
    lines = []

    all_issues = issues['critical'] + issues['warning']

    if all_issues or not warn_only:
        lines.append(
            f"{'Proto':<6} {'State':<12} {'Local Address':<25} "
            f"{'Peer Address':<25} {'Recv-Q':<10} {'Send-Q':<10} {'Process':<15}"
        )
        lines.append('-' * 113)

    for issue in all_issues:
        sock = issue['socket']
        lines.append(
            f"{sock['protocol']:<6} "
            f"{sock['state']:<12} "
            f"{sock['local_addr'][:24]:<25} "
            f"{sock['peer_addr'][:24]:<25} "
            f"{format_size(sock['recv_q']):<10} "
            f"{format_size(sock['send_q']):<10} "
            f"{(sock.get('process') or '-')[:14]:<15}"
        )

    if not all_issues and not warn_only:
        lines.append('All socket queues within normal thresholds.')

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor socket queue depths to identify buffering issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Check all TCP sockets with defaults
  %(prog)s --protocol udp            # Check UDP sockets
  %(prog)s --recv-warn 65536         # Warn when recv queue > 64KB
  %(prog)s --format json             # JSON output for automation
  %(prog)s --verbose                 # Include per-process statistics

Threshold defaults:
  Receive queue: warning=1MB, critical=10MB
  Send queue:    warning=1MB, critical=10MB
  Listen backlog: warning=128, critical=1024 pending connections

Exit codes:
  0 - All socket queues within thresholds
  1 - Warning or critical queue depths detected
  2 - Usage error or missing data sources
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including per-process stats'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show sockets with queue issues'
    )

    parser.add_argument(
        '--protocol',
        choices=['tcp', 'udp', 'all'],
        default='tcp',
        help='Protocol to monitor (default: %(default)s)'
    )

    parser.add_argument(
        '--recv-warn',
        type=int,
        default=1048576,
        help='Receive queue warning threshold in bytes (default: %(default)s = 1MB)'
    )

    parser.add_argument(
        '--recv-crit',
        type=int,
        default=10485760,
        help='Receive queue critical threshold in bytes (default: %(default)s = 10MB)'
    )

    parser.add_argument(
        '--send-warn',
        type=int,
        default=1048576,
        help='Send queue warning threshold in bytes (default: %(default)s = 1MB)'
    )

    parser.add_argument(
        '--send-crit',
        type=int,
        default=10485760,
        help='Send queue critical threshold in bytes (default: %(default)s = 10MB)'
    )

    parser.add_argument(
        '--listen-warn',
        type=int,
        default=128,
        help='Listen backlog warning threshold (default: %(default)s connections)'
    )

    parser.add_argument(
        '--listen-crit',
        type=int,
        default=1024,
        help='Listen backlog critical threshold (default: %(default)s connections)'
    )

    parser.add_argument(
        '--min-queue',
        type=int,
        default=1024,
        help='Minimum queue depth to analyze (default: %(default)s bytes)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.recv_warn < 0 or args.recv_crit < 0:
        print('Error: Receive thresholds must be non-negative', file=sys.stderr)
        sys.exit(2)

    if args.send_warn < 0 or args.send_crit < 0:
        print('Error: Send thresholds must be non-negative', file=sys.stderr)
        sys.exit(2)

    if args.listen_warn < 0 or args.listen_crit < 0:
        print('Error: Listen thresholds must be non-negative', file=sys.stderr)
        sys.exit(2)

    if args.min_queue < 0:
        print('Error: Minimum queue must be non-negative', file=sys.stderr)
        sys.exit(2)

    if args.recv_warn > args.recv_crit:
        print('Error: Receive warning threshold cannot exceed critical', file=sys.stderr)
        sys.exit(2)

    if args.send_warn > args.send_crit:
        print('Error: Send warning threshold cannot exceed critical', file=sys.stderr)
        sys.exit(2)

    if args.listen_warn > args.listen_crit:
        print('Error: Listen warning threshold cannot exceed critical', file=sys.stderr)
        sys.exit(2)

    # Collect socket information
    sockets = []

    # Try ss command first (more reliable with process info)
    if args.protocol in ('tcp', 'all'):
        sockets.extend(parse_ss_output('tcp'))
    if args.protocol in ('udp', 'all'):
        sockets.extend(parse_ss_output('udp'))

    # Fall back to /proc/net if ss didn't work
    if not sockets:
        if args.protocol in ('tcp', 'all'):
            proc_sockets = parse_proc_net_tcp()
            # Try to find owners for sockets with significant queues
            for sock in proc_sockets:
                if sock['recv_q'] >= args.min_queue or sock['send_q'] >= args.min_queue:
                    if sock.get('inode'):
                        pid, proc_name = find_socket_owner(sock['inode'])
                        if pid:
                            sock['pid'] = pid
                            sock['process'] = proc_name
            sockets.extend(proc_sockets)

    if not sockets:
        # Check if we have basic /proc access
        if not os.path.exists('/proc/net'):
            print('Error: /proc/net not available', file=sys.stderr)
            sys.exit(2)
        # No sockets found but system is accessible
        if args.format == 'json':
            print(json.dumps({'issues': {'critical': [], 'warning': []},
                             'process_stats': {}, 'summary': {'critical_count': 0, 'warning_count': 0}}))
        elif not args.warn_only:
            print('No sockets found to analyze.')
        sys.exit(0)

    # Analyze sockets
    issues, process_stats = analyze_sockets(
        sockets,
        args.recv_warn, args.recv_crit,
        args.send_warn, args.send_crit,
        args.listen_warn, args.listen_crit,
        args.min_queue
    )

    # Output results
    if args.format == 'json':
        output = output_json(issues, process_stats)
    elif args.format == 'table':
        output = output_table(issues, warn_only=args.warn_only)
    else:
        output = output_plain(issues, process_stats,
                             warn_only=args.warn_only, verbose=args.verbose)

    print(output)

    # Exit based on findings
    if issues['critical']:
        sys.exit(1)
    elif issues['warning']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
