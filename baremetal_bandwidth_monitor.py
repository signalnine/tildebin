#!/usr/bin/env python3
"""
Monitor network interface bandwidth utilization and throughput on baremetal systems.

This script samples /proc/net/dev over a configurable interval to calculate:
- Bytes per second (RX/TX)
- Packets per second (RX/TX)
- Bandwidth utilization percentage (if speed known)
- Saturation warnings when utilization exceeds thresholds

Useful for large-scale baremetal environments to:
- Detect network bottlenecks and saturation
- Monitor traffic patterns across interfaces
- Identify high-bandwidth consumers
- Capacity planning and trending

Exit codes:
    0 - No issues detected (utilization within thresholds)
    1 - Bandwidth utilization exceeds warning threshold
    2 - Missing /proc/net/dev or usage error
"""

import argparse
import sys
import json
import time
import os
import subprocess


def get_interface_stats():
    """Read interface statistics from /proc/net/dev."""
    stats = {}
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None
    except PermissionError:
        return None

    # Skip header lines (first 2 lines)
    for line in lines[2:]:
        line = line.strip()
        if not line:
            continue

        # Format: iface: rx_bytes rx_packets ... tx_bytes tx_packets ...
        parts = line.split(':')
        if len(parts) != 2:
            continue

        iface = parts[0].strip()
        values = parts[1].split()

        if len(values) >= 16:
            stats[iface] = {
                'rx_bytes': int(values[0]),
                'rx_packets': int(values[1]),
                'rx_errors': int(values[2]),
                'rx_dropped': int(values[3]),
                'tx_bytes': int(values[8]),
                'tx_packets': int(values[9]),
                'tx_errors': int(values[10]),
                'tx_dropped': int(values[11]),
            }

    return stats


def get_interface_speed(iface):
    """Get interface speed in bits per second using sysfs or ethtool."""
    # Try sysfs first (doesn't require ethtool)
    speed_file = f'/sys/class/net/{iface}/speed'
    try:
        with open(speed_file, 'r') as f:
            speed_mbps = int(f.read().strip())
            if speed_mbps > 0:
                return speed_mbps * 1_000_000  # Convert Mbps to bps
    except (FileNotFoundError, ValueError, PermissionError, OSError):
        pass

    # Fall back to ethtool
    try:
        result = subprocess.run(
            ['ethtool', iface],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Speed:' in line:
                    # Parse "Speed: 1000Mb/s" or "Speed: 10000Mb/s"
                    speed_str = line.split(':')[1].strip()
                    if 'Mb/s' in speed_str:
                        speed_mbps = int(speed_str.replace('Mb/s', ''))
                        return speed_mbps * 1_000_000
                    elif 'Gb/s' in speed_str:
                        speed_gbps = int(speed_str.replace('Gb/s', ''))
                        return speed_gbps * 1_000_000_000
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        pass

    return None


def get_interface_operstate(iface):
    """Check if interface is up."""
    operstate_file = f'/sys/class/net/{iface}/operstate'
    try:
        with open(operstate_file, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return 'unknown'


def format_bytes(bytes_val):
    """Format bytes to human-readable string."""
    if bytes_val >= 1_000_000_000:
        return f"{bytes_val / 1_000_000_000:.2f} GB/s"
    elif bytes_val >= 1_000_000:
        return f"{bytes_val / 1_000_000:.2f} MB/s"
    elif bytes_val >= 1_000:
        return f"{bytes_val / 1_000:.2f} KB/s"
    else:
        return f"{bytes_val:.0f} B/s"


def format_speed(bps):
    """Format bits per second to human-readable string."""
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.0f} Gbps"
    elif bps >= 1_000_000:
        return f"{bps / 1_000_000:.0f} Mbps"
    elif bps >= 1_000:
        return f"{bps / 1_000:.0f} Kbps"
    else:
        return f"{bps:.0f} bps"


def calculate_rates(before, after, interval):
    """Calculate per-second rates from two samples."""
    rates = {}
    for iface in after:
        if iface not in before:
            continue

        b = before[iface]
        a = after[iface]

        # Handle counter wraps (32-bit or 64-bit counters)
        def safe_diff(new, old):
            diff = new - old
            if diff < 0:
                # Assume 64-bit counter wrap
                diff = (2**64 + new) - old
            return diff

        rx_bytes = safe_diff(a['rx_bytes'], b['rx_bytes'])
        tx_bytes = safe_diff(a['tx_bytes'], b['tx_bytes'])
        rx_packets = safe_diff(a['rx_packets'], b['rx_packets'])
        tx_packets = safe_diff(a['tx_packets'], b['tx_packets'])

        rates[iface] = {
            'rx_bytes_sec': rx_bytes / interval,
            'tx_bytes_sec': tx_bytes / interval,
            'rx_packets_sec': rx_packets / interval,
            'tx_packets_sec': tx_packets / interval,
            'rx_bits_sec': (rx_bytes * 8) / interval,
            'tx_bits_sec': (tx_bytes * 8) / interval,
        }

    return rates


def analyze_bandwidth(rates, warn_threshold, crit_threshold):
    """Analyze bandwidth utilization and generate warnings."""
    results = []
    issues = []

    for iface, rate in rates.items():
        # Skip loopback
        if iface == 'lo':
            continue

        operstate = get_interface_operstate(iface)
        speed_bps = get_interface_speed(iface)

        result = {
            'interface': iface,
            'operstate': operstate,
            'rx_bytes_sec': rate['rx_bytes_sec'],
            'tx_bytes_sec': rate['tx_bytes_sec'],
            'rx_packets_sec': rate['rx_packets_sec'],
            'tx_packets_sec': rate['tx_packets_sec'],
            'rx_bits_sec': rate['rx_bits_sec'],
            'tx_bits_sec': rate['tx_bits_sec'],
            'speed_bps': speed_bps,
            'rx_utilization_pct': None,
            'tx_utilization_pct': None,
            'status': 'ok'
        }

        # Calculate utilization if speed is known
        if speed_bps and speed_bps > 0:
            rx_util = (rate['rx_bits_sec'] / speed_bps) * 100
            tx_util = (rate['tx_bits_sec'] / speed_bps) * 100
            result['rx_utilization_pct'] = round(rx_util, 2)
            result['tx_utilization_pct'] = round(tx_util, 2)

            max_util = max(rx_util, tx_util)

            if max_util >= crit_threshold:
                result['status'] = 'critical'
                issues.append({
                    'severity': 'critical',
                    'interface': iface,
                    'message': f"{iface}: {max_util:.1f}% utilization exceeds critical threshold ({crit_threshold}%)",
                    'rx_util': rx_util,
                    'tx_util': tx_util
                })
            elif max_util >= warn_threshold:
                result['status'] = 'warning'
                issues.append({
                    'severity': 'warning',
                    'interface': iface,
                    'message': f"{iface}: {max_util:.1f}% utilization exceeds warning threshold ({warn_threshold}%)",
                    'rx_util': rx_util,
                    'tx_util': tx_util
                })

        results.append(result)

    return results, issues


def output_plain(results, issues, verbose, warn_only):
    """Output results in plain text format."""
    if warn_only and not issues:
        return

    print("Network Bandwidth Monitor")
    print("=" * 80)

    # Filter results for warn-only mode
    display_results = results
    if warn_only:
        warning_ifaces = {i['interface'] for i in issues}
        display_results = [r for r in results if r['interface'] in warning_ifaces]

    for r in sorted(display_results, key=lambda x: x['interface']):
        status_symbol = "OK" if r['status'] == 'ok' else r['status'].upper()
        speed_str = format_speed(r['speed_bps']) if r['speed_bps'] else 'N/A'

        print(f"\n{r['interface']} ({r['operstate']}) - Link: {speed_str} [{status_symbol}]")

        rx_rate = format_bytes(r['rx_bytes_sec'])
        tx_rate = format_bytes(r['tx_bytes_sec'])
        print(f"  RX: {rx_rate} ({r['rx_packets_sec']:.0f} pps)")
        print(f"  TX: {tx_rate} ({r['tx_packets_sec']:.0f} pps)")

        if r['rx_utilization_pct'] is not None:
            print(f"  Utilization: RX {r['rx_utilization_pct']:.1f}% | TX {r['tx_utilization_pct']:.1f}%")

    if issues:
        print(f"\nIssues ({len(issues)}):")
        for issue in issues:
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")
    elif not warn_only:
        print(f"\n[OK] All {len(results)} interfaces within thresholds")


def output_json(results, issues, interval):
    """Output results in JSON format."""
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'sample_interval_sec': interval,
        'interfaces': results,
        'issues': issues,
        'summary': {
            'total_interfaces': len(results),
            'interfaces_up': len([r for r in results if r['operstate'] == 'up']),
            'warning_count': len([i for i in issues if i['severity'] == 'warning']),
            'critical_count': len([i for i in issues if i['severity'] == 'critical']),
        },
        'has_issues': len(issues) > 0
    }
    print(json.dumps(output, indent=2))


def output_table(results, issues, warn_only):
    """Output results in table format."""
    if warn_only and not issues:
        return

    # Filter results for warn-only mode
    display_results = results
    if warn_only:
        warning_ifaces = {i['interface'] for i in issues}
        display_results = [r for r in results if r['interface'] in warning_ifaces]

    print(f"{'Interface':<12} {'State':<6} {'RX Rate':>12} {'TX Rate':>12} {'RX Util':>8} {'TX Util':>8} {'Status':<10}")
    print("-" * 80)

    for r in sorted(display_results, key=lambda x: x['interface']):
        rx_rate = format_bytes(r['rx_bytes_sec'])
        tx_rate = format_bytes(r['tx_bytes_sec'])
        rx_util = f"{r['rx_utilization_pct']:.1f}%" if r['rx_utilization_pct'] is not None else 'N/A'
        tx_util = f"{r['tx_utilization_pct']:.1f}%" if r['tx_utilization_pct'] is not None else 'N/A'
        state = r['operstate'][:6]

        print(f"{r['interface']:<12} {state:<6} {rx_rate:>12} {tx_rate:>12} {rx_util:>8} {tx_util:>8} {r['status']:<10}")

    if issues:
        print(f"\nIssues ({len(issues)}):")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor network interface bandwidth utilization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Sample for 1 second, show all interfaces
  %(prog)s -i 5                         # Sample for 5 seconds (more accurate)
  %(prog)s --interface eth0             # Monitor specific interface
  %(prog)s --format json                # Output in JSON format
  %(prog)s --warn 70 --crit 90          # Custom thresholds
  %(prog)s -w                           # Only show if issues detected

Exit codes:
  0 - No issues detected (utilization within thresholds)
  1 - Bandwidth utilization exceeds warning threshold
  2 - Missing /proc/net/dev or usage error
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
        "--interface",
        metavar="IFACE",
        help="Monitor specific interface only"
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
        "--warn",
        type=float,
        default=80.0,
        metavar="PCT",
        help="Warning threshold percentage (default: %(default)s)"
    )

    parser.add_argument(
        "--crit",
        type=float,
        default=95.0,
        metavar="PCT",
        help="Critical threshold percentage (default: %(default)s)"
    )

    parser.add_argument(
        "--exclude-down",
        action="store_true",
        help="Exclude interfaces that are not up"
    )

    args = parser.parse_args()

    if args.interval <= 0:
        print("Error: Interval must be positive", file=sys.stderr)
        sys.exit(2)

    if args.warn >= args.crit:
        print("Error: Warning threshold must be less than critical threshold", file=sys.stderr)
        sys.exit(2)

    # Take first sample
    before = get_interface_stats()
    if before is None:
        print("Error: Cannot read /proc/net/dev", file=sys.stderr)
        print("This script requires access to /proc/net/dev", file=sys.stderr)
        sys.exit(2)

    # Wait for sampling interval
    time.sleep(args.interval)

    # Take second sample
    after = get_interface_stats()
    if after is None:
        print("Error: Cannot read /proc/net/dev", file=sys.stderr)
        sys.exit(2)

    # Calculate rates
    rates = calculate_rates(before, after, args.interval)

    # Filter to specific interface if requested
    if args.interface:
        if args.interface not in rates:
            print(f"Error: Interface '{args.interface}' not found", file=sys.stderr)
            available = [i for i in rates.keys() if i != 'lo']
            if available:
                print(f"Available interfaces: {', '.join(available)}", file=sys.stderr)
            sys.exit(2)
        rates = {args.interface: rates[args.interface]}

    # Analyze bandwidth
    results, issues = analyze_bandwidth(rates, args.warn, args.crit)

    # Exclude down interfaces if requested
    if args.exclude_down:
        results = [r for r in results if r['operstate'] == 'up']
        affected_ifaces = {r['interface'] for r in results}
        issues = [i for i in issues if i['interface'] in affected_ifaces]

    # Output results
    if args.format == "json":
        output_json(results, issues, args.interval)
    elif args.format == "table":
        output_table(results, issues, args.warn_only)
    else:
        output_plain(results, issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
