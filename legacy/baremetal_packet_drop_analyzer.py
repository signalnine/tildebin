#!/usr/bin/env python3
"""
Analyze per-interface packet drops and their causes on baremetal systems.

This script provides detailed breakdown of packet drops by interface and reason,
helping distinguish between driver bugs, misconfigurations, resource exhaustion,
and potential attacks (e.g., SYN floods).

Packet drops can occur at multiple levels:
- rx_dropped: Packets dropped before delivery to protocol stack
- rx_errors: Packets with errors (CRC, frame alignment, etc.)
- rx_missed: Packets missed due to lack of receive buffers
- rx_fifo_errors: FIFO overruns (NIC buffer exhaustion)
- tx_dropped: Packets dropped during transmission
- tx_errors: Transmission errors
- tx_carrier_errors: Loss of carrier during transmission
- tx_fifo_errors: TX FIFO underruns

Exit codes:
    0 - No drops detected or all drops within thresholds
    1 - Drops detected above warning threshold
    2 - Missing /sys or usage error
"""

import argparse
import sys
import json
import os
import time


def get_interface_list():
    """Get list of network interfaces from /sys/class/net."""
    try:
        interfaces = []
        net_path = '/sys/class/net'
        if not os.path.exists(net_path):
            return None

        for iface in os.listdir(net_path):
            # Skip loopback
            if iface == 'lo':
                continue
            # Skip virtual interfaces unless they look like bonds or bridges
            if iface.startswith('veth') or iface.startswith('docker'):
                continue
            # Skip bonding_masters (not a real interface)
            if iface == 'bonding_masters':
                continue
            # Verify it's a real interface (has statistics directory)
            stats_path = os.path.join(net_path, iface, 'statistics')
            if not os.path.isdir(stats_path):
                continue
            interfaces.append(iface)

        return sorted(interfaces)
    except (PermissionError, OSError):
        return None


def read_sys_stat(iface, stat_name):
    """Read a statistic from /sys/class/net/<iface>/statistics/."""
    path = f'/sys/class/net/{iface}/statistics/{stat_name}'
    try:
        with open(path, 'r') as f:
            return int(f.read().strip())
    except (FileNotFoundError, PermissionError, ValueError, NotADirectoryError, OSError):
        return 0


def get_interface_stats(iface):
    """Get all relevant statistics for an interface."""
    stats = {
        # RX statistics
        'rx_packets': read_sys_stat(iface, 'rx_packets'),
        'rx_bytes': read_sys_stat(iface, 'rx_bytes'),
        'rx_dropped': read_sys_stat(iface, 'rx_dropped'),
        'rx_errors': read_sys_stat(iface, 'rx_errors'),
        'rx_missed_errors': read_sys_stat(iface, 'rx_missed_errors'),
        'rx_fifo_errors': read_sys_stat(iface, 'rx_fifo_errors'),
        'rx_length_errors': read_sys_stat(iface, 'rx_length_errors'),
        'rx_over_errors': read_sys_stat(iface, 'rx_over_errors'),
        'rx_crc_errors': read_sys_stat(iface, 'rx_crc_errors'),
        'rx_frame_errors': read_sys_stat(iface, 'rx_frame_errors'),

        # TX statistics
        'tx_packets': read_sys_stat(iface, 'tx_packets'),
        'tx_bytes': read_sys_stat(iface, 'tx_bytes'),
        'tx_dropped': read_sys_stat(iface, 'tx_dropped'),
        'tx_errors': read_sys_stat(iface, 'tx_errors'),
        'tx_fifo_errors': read_sys_stat(iface, 'tx_fifo_errors'),
        'tx_carrier_errors': read_sys_stat(iface, 'tx_carrier_errors'),
        'tx_aborted_errors': read_sys_stat(iface, 'tx_aborted_errors'),
        'tx_window_errors': read_sys_stat(iface, 'tx_window_errors'),
        'tx_heartbeat_errors': read_sys_stat(iface, 'tx_heartbeat_errors'),

        # Collisions
        'collisions': read_sys_stat(iface, 'collisions'),
    }
    return stats


def calculate_drop_rates(before, after, interval):
    """Calculate per-second drop rates between two samples."""
    rates = {}
    for key in before:
        diff = after[key] - before[key]
        if diff < 0:  # Counter wrap
            diff = 0
        rates[key] = diff / interval
    return rates


def get_interface_operstate(iface):
    """Get operational state of interface."""
    path = f'/sys/class/net/{iface}/operstate'
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return 'unknown'


def analyze_interface(iface, stats, rates, warn_rate, crit_rate):
    """Analyze interface drops and generate issues."""
    issues = []

    # Calculate total drops
    total_rx_drops = (stats['rx_dropped'] + stats['rx_errors'] +
                      stats['rx_missed_errors'] + stats['rx_fifo_errors'])
    total_tx_drops = (stats['tx_dropped'] + stats['tx_errors'] +
                      stats['tx_fifo_errors'] + stats['tx_carrier_errors'])

    # Drop rates
    rx_drop_rate = (rates['rx_dropped'] + rates['rx_errors'] +
                    rates['rx_missed_errors'] + rates['rx_fifo_errors'])
    tx_drop_rate = (rates['tx_dropped'] + rates['tx_errors'] +
                    rates['tx_fifo_errors'] + rates['tx_carrier_errors'])

    # Check for significant drops
    drop_categories = [
        ('rx_dropped', 'RX dropped (before protocol stack)',
         'May indicate kernel/driver buffer exhaustion or netfilter drops'),
        ('rx_errors', 'RX errors (generic)',
         'May indicate cable/transceiver issues or driver bugs'),
        ('rx_missed_errors', 'RX missed (no buffer space)',
         'NIC ran out of receive buffers - consider increasing ring buffer'),
        ('rx_fifo_errors', 'RX FIFO errors (NIC buffer overflow)',
         'NIC hardware buffer overflow - traffic rate exceeds processing'),
        ('rx_crc_errors', 'RX CRC errors',
         'Physical layer issues - check cables, connectors, transceivers'),
        ('rx_frame_errors', 'RX frame errors',
         'Frame alignment errors - possible duplex mismatch or cable issues'),
        ('rx_length_errors', 'RX length errors',
         'Invalid frame length - possible MTU mismatch or corruption'),
        ('rx_over_errors', 'RX overrun errors',
         'Ring buffer overrun - increase rx ring buffer size'),
        ('tx_dropped', 'TX dropped',
         'Packets dropped during transmission - queue full or policy'),
        ('tx_errors', 'TX errors (generic)',
         'Transmission errors - check link status and driver'),
        ('tx_fifo_errors', 'TX FIFO underrun',
         'TX buffer underrun - possible CPU/bus contention'),
        ('tx_carrier_errors', 'TX carrier errors',
         'Lost carrier during transmission - link instability'),
        ('tx_aborted_errors', 'TX aborted',
         'Transmission aborted - excessive collisions or other issues'),
        ('collisions', 'Collisions',
         'Network collisions - possible duplex mismatch (should be 0 on full-duplex)'),
    ]

    for stat_name, description, hint in drop_categories:
        count = stats.get(stat_name, 0)
        rate = rates.get(stat_name, 0)

        if rate >= crit_rate:
            issues.append({
                'severity': 'critical',
                'interface': iface,
                'category': stat_name,
                'description': description,
                'hint': hint,
                'count': count,
                'rate_per_sec': round(rate, 2),
                'message': f"{iface}: {description} at {rate:.2f}/sec (total: {count:,})"
            })
        elif rate >= warn_rate:
            issues.append({
                'severity': 'warning',
                'interface': iface,
                'category': stat_name,
                'description': description,
                'hint': hint,
                'count': count,
                'rate_per_sec': round(rate, 2),
                'message': f"{iface}: {description} at {rate:.2f}/sec (total: {count:,})"
            })

    # Determine overall status
    if any(i['severity'] == 'critical' for i in issues):
        status = 'critical'
    elif issues:
        status = 'warning'
    else:
        status = 'ok'

    return {
        'interface': iface,
        'operstate': get_interface_operstate(iface),
        'status': status,
        'totals': {
            'rx_packets': stats['rx_packets'],
            'tx_packets': stats['tx_packets'],
            'rx_bytes': stats['rx_bytes'],
            'tx_bytes': stats['tx_bytes'],
            'total_rx_drops': total_rx_drops,
            'total_tx_drops': total_tx_drops,
        },
        'rates': {
            'rx_packets_per_sec': round(rates['rx_packets'], 2),
            'tx_packets_per_sec': round(rates['tx_packets'], 2),
            'rx_drop_rate': round(rx_drop_rate, 2),
            'tx_drop_rate': round(tx_drop_rate, 2),
        },
        'drop_breakdown': {
            'rx_dropped': stats['rx_dropped'],
            'rx_errors': stats['rx_errors'],
            'rx_missed': stats['rx_missed_errors'],
            'rx_fifo': stats['rx_fifo_errors'],
            'rx_crc': stats['rx_crc_errors'],
            'rx_frame': stats['rx_frame_errors'],
            'tx_dropped': stats['tx_dropped'],
            'tx_errors': stats['tx_errors'],
            'tx_fifo': stats['tx_fifo_errors'],
            'tx_carrier': stats['tx_carrier_errors'],
            'collisions': stats['collisions'],
        },
        'issues': issues
    }, issues


def output_plain(results, all_issues, interval, verbose, warn_only):
    """Output results in plain text format."""
    if warn_only and not all_issues:
        return

    print("Packet Drop Analysis")
    print("=" * 70)
    print(f"Sample interval: {interval}s")
    print()

    for result in results:
        if warn_only and result['status'] == 'ok':
            continue

        status_symbol = {'ok': 'OK', 'warning': 'WARN', 'critical': 'CRIT'}
        symbol = status_symbol.get(result['status'], '??')

        print(f"[{symbol}] {result['interface']} ({result['operstate']})")

        rates = result['rates']
        totals = result['totals']

        print(f"  Traffic: {rates['rx_packets_per_sec']:.0f} rx/s, "
              f"{rates['tx_packets_per_sec']:.0f} tx/s")

        if totals['total_rx_drops'] > 0 or totals['total_tx_drops'] > 0 or verbose:
            print(f"  Drops:   {rates['rx_drop_rate']:.2f} rx/s, "
                  f"{rates['tx_drop_rate']:.2f} tx/s "
                  f"(totals: {totals['total_rx_drops']:,} rx, "
                  f"{totals['total_tx_drops']:,} tx)")

        if verbose:
            breakdown = result['drop_breakdown']
            print(f"  RX breakdown:")
            print(f"    dropped={breakdown['rx_dropped']:,} "
                  f"errors={breakdown['rx_errors']:,} "
                  f"missed={breakdown['rx_missed']:,} "
                  f"fifo={breakdown['rx_fifo']:,}")
            print(f"    crc={breakdown['rx_crc']:,} "
                  f"frame={breakdown['rx_frame']:,}")
            print(f"  TX breakdown:")
            print(f"    dropped={breakdown['tx_dropped']:,} "
                  f"errors={breakdown['tx_errors']:,} "
                  f"fifo={breakdown['tx_fifo']:,} "
                  f"carrier={breakdown['tx_carrier']:,}")
            if breakdown['collisions'] > 0:
                print(f"    collisions={breakdown['collisions']:,}")

        for issue in result['issues']:
            severity = issue['severity'].upper()
            print(f"    [{severity}] {issue['description']}: "
                  f"{issue['rate_per_sec']}/sec")
            if verbose:
                print(f"           Hint: {issue['hint']}")

        print()

    # Summary
    total_issues = len(all_issues)
    if total_issues > 0:
        critical = len([i for i in all_issues if i['severity'] == 'critical'])
        warning = len([i for i in all_issues if i['severity'] == 'warning'])
        print(f"Summary: {total_issues} issue(s) detected "
              f"({critical} critical, {warning} warning)")
    elif not warn_only:
        print("Summary: No packet drop issues detected")


def output_json(results, all_issues, interval):
    """Output results in JSON format."""
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'sample_interval_sec': interval,
        'interfaces': results,
        'issues': all_issues,
        'summary': {
            'interfaces_checked': len(results),
            'interfaces_with_issues': len([r for r in results if r['status'] != 'ok']),
            'total_issues': len(all_issues),
            'critical_count': len([i for i in all_issues if i['severity'] == 'critical']),
            'warning_count': len([i for i in all_issues if i['severity'] == 'warning']),
        },
        'has_issues': len(all_issues) > 0
    }
    print(json.dumps(output, indent=2))


def output_table(results, all_issues, warn_only):
    """Output results in table format."""
    if warn_only and not all_issues:
        return

    # Header
    print(f"{'Interface':<12} {'State':<8} {'Status':<6} "
          f"{'RX pkt/s':>10} {'TX pkt/s':>10} "
          f"{'RX drop/s':>10} {'TX drop/s':>10} "
          f"{'Total RX drops':>14} {'Total TX drops':>14}")
    print("-" * 110)

    for result in results:
        if warn_only and result['status'] == 'ok':
            continue

        rates = result['rates']
        totals = result['totals']

        print(f"{result['interface']:<12} {result['operstate']:<8} "
              f"{result['status'].upper():<6} "
              f"{rates['rx_packets_per_sec']:>10.0f} "
              f"{rates['tx_packets_per_sec']:>10.0f} "
              f"{rates['rx_drop_rate']:>10.2f} "
              f"{rates['tx_drop_rate']:>10.2f} "
              f"{totals['total_rx_drops']:>14,} "
              f"{totals['total_tx_drops']:>14,}")

    if all_issues:
        print()
        print(f"Issues ({len(all_issues)}):")
        for issue in all_issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze per-interface packet drops and their causes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Sample for 1 second, show all interfaces
  %(prog)s -i 5                         # Sample for 5 seconds (more accurate)
  %(prog)s -I eth0                      # Check specific interface
  %(prog)s --format json                # Output in JSON format
  %(prog)s --warn 1 --crit 10           # Custom thresholds (1/sec warn, 10/sec crit)
  %(prog)s -w                           # Only output if issues detected
  %(prog)s -v                           # Show detailed breakdown

Common causes of packet drops:
  rx_dropped    - Kernel buffer exhaustion, netfilter drops, socket buffer full
  rx_missed     - NIC hardware buffer exhaustion (increase ring buffer)
  rx_fifo       - NIC cannot keep up with traffic rate
  rx_crc        - Physical layer issues (cables, transceivers)
  tx_dropped    - Transmit queue full, traffic shaping, policy
  tx_carrier    - Link flapping or cable issues
  collisions    - Duplex mismatch (should be 0 on full-duplex links)

Remediation hints:
  - Increase ring buffers: ethtool -G <iface> rx <size> tx <size>
  - Check for CPU affinity issues with interrupts
  - Verify duplex settings match on both ends
  - Check cable and transceiver quality

Exit codes:
  0 - No drops detected or all within thresholds
  1 - Drops detected above warning threshold
  2 - Missing /sys filesystem or usage error
        """
    )

    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="Sampling interval in seconds (default: %(default)s)"
    )

    parser.add_argument(
        "-I", "--interface",
        metavar="IFACE",
        help="Specific interface to check (default: all interfaces)"
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
        help="Show detailed breakdown and hints"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if issues are detected"
    )

    parser.add_argument(
        "--warn",
        type=float,
        default=1.0,
        metavar="RATE",
        help="Warning threshold (drops/sec) (default: %(default)s)"
    )

    parser.add_argument(
        "--crit",
        type=float,
        default=10.0,
        metavar="RATE",
        help="Critical threshold (drops/sec) (default: %(default)s)"
    )

    parser.add_argument(
        "--include-virtual",
        action="store_true",
        help="Include virtual interfaces (veth, docker, etc.)"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.interval <= 0:
        print("Error: Interval must be positive", file=sys.stderr)
        sys.exit(2)

    if args.warn >= args.crit:
        print("Error: Warning threshold must be less than critical threshold",
              file=sys.stderr)
        sys.exit(2)

    # Get interface list
    if args.interface:
        interfaces = [args.interface]
        # Verify interface exists
        if not os.path.exists(f'/sys/class/net/{args.interface}'):
            print(f"Error: Interface '{args.interface}' not found", file=sys.stderr)
            sys.exit(2)
    else:
        interfaces = get_interface_list()
        if interfaces is None:
            print("Error: Cannot read /sys/class/net", file=sys.stderr)
            print("This script requires access to /sys filesystem", file=sys.stderr)
            sys.exit(2)

        if not interfaces:
            print("No network interfaces found", file=sys.stderr)
            sys.exit(2)

    # Take first sample
    before_stats = {}
    for iface in interfaces:
        before_stats[iface] = get_interface_stats(iface)

    # Wait for sampling interval
    time.sleep(args.interval)

    # Take second sample
    after_stats = {}
    for iface in interfaces:
        after_stats[iface] = get_interface_stats(iface)

    # Analyze each interface
    results = []
    all_issues = []

    for iface in interfaces:
        rates = calculate_drop_rates(
            before_stats[iface],
            after_stats[iface],
            args.interval
        )
        result, issues = analyze_interface(
            iface,
            after_stats[iface],
            rates,
            args.warn,
            args.crit
        )
        results.append(result)
        all_issues.extend(issues)

    # Output results
    if args.format == "json":
        output_json(results, all_issues, args.interval)
    elif args.format == "table":
        output_table(results, all_issues, args.warn_only)
    else:
        output_plain(results, all_issues, args.interval, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if all_issues else 0)


if __name__ == "__main__":
    main()
