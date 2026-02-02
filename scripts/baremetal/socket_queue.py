#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [socket, queue, network, tcp, udp, backlog]
#   requires: [ss]
#   privilege: none
#   related: [socket_buffer, tcp_connection_monitor, listening_port_monitor]
#   brief: Monitor socket queue depths to identify buffering issues

"""
Monitor socket queue depths to identify applications with backed-up buffers.

This script analyzes socket receive and send queue depths using ss command
output to identify:
- Sockets with large receive queues (slow consumers)
- Sockets with large send queues (network congestion or slow peers)
- Listening sockets with accept queue backlog
- Per-process socket queue statistics

Large socket queues can indicate:
- Application unable to keep up with incoming data
- Network congestion causing send buffers to fill
- Slow peers not acknowledging data
- Memory pressure from excessive buffering
"""

import argparse
import re
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def format_size(bytes_val: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(bytes_val) < 1024.0:
            return f'{bytes_val:.1f}{unit}'
        bytes_val /= 1024.0
    return f'{bytes_val:.1f}TB'


def parse_ss_output(output_text: str, protocol: str = 'tcp') -> list[dict]:
    """Parse ss command output to get socket queue information."""
    sockets = []
    lines = output_text.strip().split('\n')

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

    return sockets


def analyze_sockets(
    sockets: list[dict],
    recv_warn: int,
    recv_crit: int,
    send_warn: int,
    send_crit: int,
    listen_warn: int,
    listen_crit: int,
    min_queue: int
) -> tuple[dict, dict]:
    """Analyze sockets and identify those with concerning queue depths."""
    issues = {
        'critical': [],
        'warning': [],
    }

    process_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {
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
        # For LISTEN sockets, recv_q is connection count, not bytes, so don't apply min_queue
        if state != 'LISTEN' and recv_q < min_queue and send_q < min_queue:
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

        if issue['reasons'] and severity:
            issues[severity].append(issue)

    return issues, dict(process_stats)


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
        description="Monitor socket queue depths to identify buffering issues"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--protocol", choices=["tcp", "udp", "all"], default="tcp",
                        help="Protocol to monitor (default: tcp)")
    parser.add_argument("--recv-warn", type=int, default=1048576,
                        help="Receive queue warning threshold (default: 1MB)")
    parser.add_argument("--recv-crit", type=int, default=10485760,
                        help="Receive queue critical threshold (default: 10MB)")
    parser.add_argument("--send-warn", type=int, default=1048576,
                        help="Send queue warning threshold (default: 1MB)")
    parser.add_argument("--send-crit", type=int, default=10485760,
                        help="Send queue critical threshold (default: 10MB)")
    parser.add_argument("--listen-warn", type=int, default=128,
                        help="Listen backlog warning threshold (default: 128)")
    parser.add_argument("--listen-crit", type=int, default=1024,
                        help="Listen backlog critical threshold (default: 1024)")
    parser.add_argument("--min-queue", type=int, default=1024,
                        help="Minimum queue depth to analyze (default: 1024)")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.recv_warn > opts.recv_crit:
        output.error("Receive warning threshold cannot exceed critical")
        return 2
    if opts.send_warn > opts.send_crit:
        output.error("Send warning threshold cannot exceed critical")
        return 2
    if opts.listen_warn > opts.listen_crit:
        output.error("Listen warning threshold cannot exceed critical")
        return 2

    # Check for ss command
    if not context.check_tool("ss"):
        output.error("ss command not found")
        return 2

    # Collect socket information
    sockets = []

    try:
        if opts.protocol in ('tcp', 'all'):
            result = context.run(['ss', '-n', '-a', '-e', '-p', '-t'], check=False)
            if result.returncode == 0:
                sockets.extend(parse_ss_output(result.stdout, 'tcp'))

        if opts.protocol in ('udp', 'all'):
            result = context.run(['ss', '-n', '-a', '-e', '-p', '-u'], check=False)
            if result.returncode == 0:
                sockets.extend(parse_ss_output(result.stdout, 'udp'))
    except Exception as e:
        output.error(f"Failed to run ss command: {e}")
        return 2

    if not sockets:
        output.emit({
            'status': 'ok',
            'issues': {'critical': [], 'warning': []},
            'process_stats': {},
            'summary': {'critical_count': 0, 'warning_count': 0}
        })
        output.set_summary("No sockets found to analyze")
        return 0

    # Analyze sockets
    issues, process_stats = analyze_sockets(
        sockets,
        opts.recv_warn, opts.recv_crit,
        opts.send_warn, opts.send_crit,
        opts.listen_warn, opts.listen_crit,
        opts.min_queue
    )

    # Build result
    result = {
        'status': 'ok',
        'issues': {
            'critical': [
                {'socket': i['socket'], 'reasons': i['reasons']}
                for i in issues['critical']
            ],
            'warning': [
                {'socket': i['socket'], 'reasons': i['reasons']}
                for i in issues['warning']
            ],
        },
        'process_stats': process_stats if opts.verbose else {},
        'summary': {
            'critical_count': len(issues['critical']),
            'warning_count': len(issues['warning']),
        },
    }

    if issues['critical']:
        result['status'] = 'critical'
    elif issues['warning']:
        result['status'] = 'warning'

    output.emit(result)

    # Set summary
    crit = len(issues['critical'])
    warn = len(issues['warning'])
    if crit > 0 or warn > 0:
        output.set_summary(f"{crit} critical, {warn} warnings")
    else:
        output.set_summary("All socket queues within normal thresholds")

    # Return exit code
    if issues['critical'] or issues['warning']:
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
