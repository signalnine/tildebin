#!/usr/bin/env python3
"""
Monitor network queuing discipline (qdisc) statistics for packet drops and overlimits.

This script analyzes traffic control (tc) qdisc statistics to identify:
- Interfaces with high packet drop rates
- Queues experiencing overlimit events
- Backlog buildup indicating congestion
- Misconfigurations in traffic shaping

High qdisc drops can indicate:
- Network congestion at egress
- Misconfigured rate limiting
- Insufficient queue sizes
- Application sending faster than link capacity

Exit codes:
    0 - All qdiscs healthy, no significant drops
    1 - Warning or critical drop rates detected
    2 - Usage error or tc command unavailable
"""

import argparse
import json
import os
import re
import subprocess
import sys


def check_tc_available():
    """Check if tc command is available."""
    try:
        result = subprocess.run(
            ['which', 'tc'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_interfaces():
    """Get list of network interfaces from /sys/class/net."""
    interfaces = []
    try:
        net_path = '/sys/class/net'
        if os.path.exists(net_path):
            for iface in os.listdir(net_path):
                # Skip loopback by default
                if iface != 'lo':
                    interfaces.append(iface)
    except (IOError, OSError, PermissionError):
        pass
    return sorted(interfaces)


def parse_tc_qdisc_output(interface):
    """
    Parse tc -s qdisc show dev <interface> output.

    Returns list of qdisc info dicts with statistics.
    """
    qdiscs = []

    try:
        result = subprocess.run(
            ['tc', '-s', 'qdisc', 'show', 'dev', interface],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return qdiscs

        output = result.stdout
        if not output.strip():
            return qdiscs

        # Parse tc output - each qdisc block starts with "qdisc"
        current_qdisc = None

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # New qdisc definition line
            # Example: qdisc fq_codel 0: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64
            if line.startswith('qdisc '):
                if current_qdisc:
                    qdiscs.append(current_qdisc)

                parts = line.split()
                qdisc_type = parts[1] if len(parts) > 1 else 'unknown'
                handle = parts[2] if len(parts) > 2 else ''

                # Parse parent/root
                parent = 'root'
                if 'parent' in line:
                    parent_match = re.search(r'parent\s+(\S+)', line)
                    if parent_match:
                        parent = parent_match.group(1)

                current_qdisc = {
                    'interface': interface,
                    'type': qdisc_type,
                    'handle': handle.rstrip(':'),
                    'parent': parent,
                    'sent_bytes': 0,
                    'sent_packets': 0,
                    'dropped': 0,
                    'overlimits': 0,
                    'requeues': 0,
                    'backlog_bytes': 0,
                    'backlog_packets': 0,
                    'qlen': 0,
                }

            # Statistics line
            # Example: Sent 1234567 bytes 12345 pkt (dropped 0, overlimits 0 requeues 0)
            elif current_qdisc and 'Sent' in line:
                sent_match = re.search(
                    r'Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt',
                    line
                )
                if sent_match:
                    current_qdisc['sent_bytes'] = int(sent_match.group(1))
                    current_qdisc['sent_packets'] = int(sent_match.group(2))

                dropped_match = re.search(r'dropped\s+(\d+)', line)
                if dropped_match:
                    current_qdisc['dropped'] = int(dropped_match.group(1))

                overlimits_match = re.search(r'overlimits\s+(\d+)', line)
                if overlimits_match:
                    current_qdisc['overlimits'] = int(overlimits_match.group(1))

                requeues_match = re.search(r'requeues\s+(\d+)', line)
                if requeues_match:
                    current_qdisc['requeues'] = int(requeues_match.group(1))

            # Backlog line
            # Example: backlog 0b 0p requeues 0
            elif current_qdisc and 'backlog' in line:
                backlog_match = re.search(
                    r'backlog\s+(\d+)b\s+(\d+)p',
                    line
                )
                if backlog_match:
                    current_qdisc['backlog_bytes'] = int(backlog_match.group(1))
                    current_qdisc['backlog_packets'] = int(backlog_match.group(2))

                qlen_match = re.search(r'qlen\s+(\d+)', line)
                if qlen_match:
                    current_qdisc['qlen'] = int(qlen_match.group(1))

        # Don't forget the last qdisc
        if current_qdisc:
            qdiscs.append(current_qdisc)

    except FileNotFoundError:
        pass
    except Exception:
        pass

    return qdiscs


def get_all_qdisc_stats(interfaces=None, include_loopback=False):
    """Get qdisc statistics for all interfaces."""
    all_qdiscs = []

    if interfaces is None:
        interfaces = get_interfaces()
        if include_loopback:
            interfaces.append('lo')

    for iface in interfaces:
        qdiscs = parse_tc_qdisc_output(iface)
        all_qdiscs.extend(qdiscs)

    return all_qdiscs


def calculate_drop_rate(qdisc):
    """Calculate drop rate as percentage of sent packets."""
    sent = qdisc['sent_packets']
    dropped = qdisc['dropped']

    if sent == 0 and dropped == 0:
        return 0.0
    if sent == 0:
        return 100.0  # All dropped, none sent

    return (dropped / (sent + dropped)) * 100.0


def analyze_qdiscs(qdiscs, drop_warn, drop_crit, backlog_warn, backlog_crit,
                   min_packets):
    """
    Analyze qdiscs and identify those with concerning statistics.

    Returns dict with categorized issues.
    """
    issues = {
        'critical': [],
        'warning': [],
        'info': [],
    }

    for qdisc in qdiscs:
        # Skip qdiscs with minimal traffic
        total_packets = qdisc['sent_packets'] + qdisc['dropped']
        if total_packets < min_packets:
            continue

        issue = {
            'qdisc': qdisc,
            'reasons': [],
        }

        severity = None
        drop_rate = calculate_drop_rate(qdisc)

        # Check drop rate
        if drop_rate >= drop_crit:
            issue['reasons'].append(
                f'Drop rate critical: {drop_rate:.2f}% '
                f'({qdisc["dropped"]} dropped of {total_packets} total)'
            )
            severity = 'critical'
        elif drop_rate >= drop_warn:
            issue['reasons'].append(
                f'Drop rate warning: {drop_rate:.2f}% '
                f'({qdisc["dropped"]} dropped of {total_packets} total)'
            )
            severity = 'warning' if not severity else severity

        # Check backlog
        backlog = qdisc['backlog_packets']
        if backlog >= backlog_crit:
            issue['reasons'].append(
                f'Backlog critical: {backlog} packets queued '
                f'({format_size(qdisc["backlog_bytes"])})'
            )
            severity = 'critical'
        elif backlog >= backlog_warn:
            issue['reasons'].append(
                f'Backlog warning: {backlog} packets queued '
                f'({format_size(qdisc["backlog_bytes"])})'
            )
            severity = 'warning' if not severity else severity

        # Check overlimits (indicates rate limiting in action)
        if qdisc['overlimits'] > 0 and qdisc['overlimits'] > qdisc['sent_packets'] * 0.1:
            overlimit_pct = (qdisc['overlimits'] / max(qdisc['sent_packets'], 1)) * 100
            issue['reasons'].append(
                f'High overlimit rate: {overlimit_pct:.1f}% '
                f'({qdisc["overlimits"]} overlimits)'
            )
            if not severity:
                severity = 'info'

        if issue['reasons']:
            issues[severity or 'info'].append(issue)

    return issues


def format_size(bytes_val):
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(bytes_val) < 1024.0:
            return f'{bytes_val:.1f}{unit}'
        bytes_val /= 1024.0
    return f'{bytes_val:.1f}TB'


def format_count(count):
    """Format large numbers with K/M/G suffixes."""
    for unit in ['', 'K', 'M', 'G']:
        if abs(count) < 1000.0:
            if unit == '':
                return str(int(count))
            return f'{count:.1f}{unit}'
        count /= 1000.0
    return f'{count:.1f}T'


def output_plain(qdiscs, issues, warn_only=False, verbose=False):
    """Output results in plain text format."""
    lines = []

    critical = issues['critical']
    warnings = issues['warning']

    if critical:
        lines.append(f'CRITICAL Qdisc Issues ({len(critical)}):')
        for issue in critical:
            qdisc = issue['qdisc']
            lines.append(
                f"  {qdisc['interface']} {qdisc['type']} "
                f"handle {qdisc['handle']} parent {qdisc['parent']}"
            )
            lines.append(
                f"    Sent: {format_count(qdisc['sent_packets'])} pkts "
                f"({format_size(qdisc['sent_bytes'])})  "
                f"Dropped: {format_count(qdisc['dropped'])} pkts"
            )
            for reason in issue['reasons']:
                lines.append(f"    - {reason}")
        lines.append('')

    if warnings:
        lines.append(f'WARNING Qdisc Issues ({len(warnings)}):')
        for issue in warnings:
            qdisc = issue['qdisc']
            lines.append(
                f"  {qdisc['interface']} {qdisc['type']} "
                f"handle {qdisc['handle']} parent {qdisc['parent']}"
            )
            lines.append(
                f"    Sent: {format_count(qdisc['sent_packets'])} pkts "
                f"({format_size(qdisc['sent_bytes'])})  "
                f"Dropped: {format_count(qdisc['dropped'])} pkts"
            )
            if verbose:
                for reason in issue['reasons']:
                    lines.append(f"    - {reason}")
        lines.append('')

    if verbose and qdiscs:
        lines.append('All Qdisc Statistics:')
        for qdisc in qdiscs:
            if qdisc['sent_packets'] == 0 and qdisc['dropped'] == 0:
                continue
            drop_rate = calculate_drop_rate(qdisc)
            lines.append(
                f"  {qdisc['interface']:<15} {qdisc['type']:<12} "
                f"sent={format_count(qdisc['sent_packets']):<8} "
                f"dropped={format_count(qdisc['dropped']):<8} "
                f"drop_rate={drop_rate:.2f}%"
            )
        lines.append('')

    if not critical and not warnings:
        if not warn_only:
            lines.append('All qdiscs healthy - no significant packet drops detected.')
    else:
        lines.append(
            f'Summary: {len(critical)} critical, {len(warnings)} warnings'
        )

    return '\n'.join(lines)


def output_json(qdiscs, issues):
    """Output results in JSON format."""
    result = {
        'qdiscs': qdiscs,
        'issues': {
            'critical': [
                {
                    'qdisc': i['qdisc'],
                    'reasons': i['reasons'],
                    'drop_rate': calculate_drop_rate(i['qdisc']),
                }
                for i in issues['critical']
            ],
            'warning': [
                {
                    'qdisc': i['qdisc'],
                    'reasons': i['reasons'],
                    'drop_rate': calculate_drop_rate(i['qdisc']),
                }
                for i in issues['warning']
            ],
        },
        'summary': {
            'total_qdiscs': len(qdiscs),
            'critical_count': len(issues['critical']),
            'warning_count': len(issues['warning']),
            'total_dropped': sum(q['dropped'] for q in qdiscs),
            'total_sent': sum(q['sent_packets'] for q in qdiscs),
        },
    }
    return json.dumps(result, indent=2)


def output_table(qdiscs, issues, warn_only=False):
    """Output results in table format."""
    lines = []

    # Combine critical and warning issues
    all_issues = issues['critical'] + issues['warning']
    issue_qdiscs = {id(i['qdisc']) for i in all_issues}

    # If warn_only, only show problematic qdiscs
    display_qdiscs = qdiscs if not warn_only else [
        i['qdisc'] for i in all_issues
    ]

    if display_qdiscs or not warn_only:
        lines.append(
            f"{'Interface':<15} {'Type':<12} {'Handle':<8} "
            f"{'Sent Pkts':<12} {'Dropped':<10} {'Drop %':<8} "
            f"{'Backlog':<10} {'Status':<10}"
        )
        lines.append('-' * 95)

    for qdisc in display_qdiscs:
        if qdisc['sent_packets'] == 0 and qdisc['dropped'] == 0:
            if warn_only:
                continue

        drop_rate = calculate_drop_rate(qdisc)
        status = 'OK'
        if id(qdisc) in issue_qdiscs:
            for issue in all_issues:
                if id(issue['qdisc']) == id(qdisc):
                    status = 'CRITICAL' if issue in issues['critical'] else 'WARNING'
                    break

        lines.append(
            f"{qdisc['interface']:<15} "
            f"{qdisc['type']:<12} "
            f"{qdisc['handle']:<8} "
            f"{format_count(qdisc['sent_packets']):<12} "
            f"{format_count(qdisc['dropped']):<10} "
            f"{drop_rate:<7.2f}% "
            f"{qdisc['backlog_packets']:<10} "
            f"{status:<10}"
        )

    if not display_qdiscs and not warn_only:
        lines.append('No qdisc statistics available.')

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor network qdisc statistics for packet drops and congestion',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Check all interfaces with defaults
  %(prog)s -i eth0 -i eth1           # Check specific interfaces
  %(prog)s --drop-warn 0.1           # Warn at 0.1%% drop rate
  %(prog)s --format json             # JSON output for automation
  %(prog)s --verbose                 # Include all qdisc statistics

Threshold defaults:
  Drop rate: warning=1%%, critical=5%%
  Backlog: warning=1000 packets, critical=10000 packets

Exit codes:
  0 - All qdiscs healthy
  1 - Warning or critical drop rates detected
  2 - Usage error or tc command unavailable
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
        help='Show detailed information including all qdisc stats'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show qdiscs with issues'
    )

    parser.add_argument(
        '-i', '--interface',
        action='append',
        dest='interfaces',
        metavar='IFACE',
        help='Interface to monitor (can be specified multiple times)'
    )

    parser.add_argument(
        '--include-loopback',
        action='store_true',
        help='Include loopback interface in monitoring'
    )

    parser.add_argument(
        '--drop-warn',
        type=float,
        default=1.0,
        help='Drop rate warning threshold in percent (default: %(default)s%%)'
    )

    parser.add_argument(
        '--drop-crit',
        type=float,
        default=5.0,
        help='Drop rate critical threshold in percent (default: %(default)s%%)'
    )

    parser.add_argument(
        '--backlog-warn',
        type=int,
        default=1000,
        help='Backlog warning threshold in packets (default: %(default)s)'
    )

    parser.add_argument(
        '--backlog-crit',
        type=int,
        default=10000,
        help='Backlog critical threshold in packets (default: %(default)s)'
    )

    parser.add_argument(
        '--min-packets',
        type=int,
        default=1000,
        help='Minimum packets to consider for analysis (default: %(default)s)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.drop_warn < 0 or args.drop_crit < 0:
        print('Error: Drop thresholds must be non-negative', file=sys.stderr)
        sys.exit(2)

    if args.drop_warn > 100 or args.drop_crit > 100:
        print('Error: Drop thresholds cannot exceed 100%%', file=sys.stderr)
        sys.exit(2)

    if args.drop_warn > args.drop_crit:
        print('Error: Drop warning threshold cannot exceed critical',
              file=sys.stderr)
        sys.exit(2)

    if args.backlog_warn < 0 or args.backlog_crit < 0:
        print('Error: Backlog thresholds must be non-negative', file=sys.stderr)
        sys.exit(2)

    if args.backlog_warn > args.backlog_crit:
        print('Error: Backlog warning threshold cannot exceed critical',
              file=sys.stderr)
        sys.exit(2)

    if args.min_packets < 0:
        print('Error: Minimum packets must be non-negative', file=sys.stderr)
        sys.exit(2)

    # Check if tc command is available
    if not check_tc_available():
        print('Error: tc command not found', file=sys.stderr)
        print('Install with: sudo apt-get install iproute2', file=sys.stderr)
        sys.exit(2)

    # Get qdisc statistics
    qdiscs = get_all_qdisc_stats(
        interfaces=args.interfaces,
        include_loopback=args.include_loopback
    )

    if not qdiscs:
        if args.format == 'json':
            print(json.dumps({
                'qdiscs': [],
                'issues': {'critical': [], 'warning': []},
                'summary': {
                    'total_qdiscs': 0,
                    'critical_count': 0,
                    'warning_count': 0,
                    'total_dropped': 0,
                    'total_sent': 0,
                }
            }, indent=2))
        elif not args.warn_only:
            print('No qdisc statistics available.')
        sys.exit(0)

    # Analyze qdiscs
    issues = analyze_qdiscs(
        qdiscs,
        args.drop_warn, args.drop_crit,
        args.backlog_warn, args.backlog_crit,
        args.min_packets
    )

    # Output results
    if args.format == 'json':
        output = output_json(qdiscs, issues)
    elif args.format == 'table':
        output = output_table(qdiscs, issues, warn_only=args.warn_only)
    else:
        output = output_plain(qdiscs, issues,
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
