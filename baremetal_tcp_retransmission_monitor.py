#!/usr/bin/env python3
"""
Monitor TCP retransmission rates to detect network issues on baremetal systems.

TCP retransmissions indicate packet loss, network congestion, or connectivity
problems. High retransmission rates can cause:
- Application timeouts and slowdowns
- Reduced throughput and increased latency
- Connection failures and request errors

This script reads TCP statistics from /proc/net/snmp and /proc/net/netstat
to calculate retransmission rates and detect problematic patterns.

Exit codes:
    0 - No issues detected (retransmission rate within thresholds)
    1 - Retransmission rate exceeds warning threshold
    2 - Missing /proc files or usage error
"""

import argparse
import sys
import json
import time


def read_proc_file(path):
    """Read a /proc file and return its contents."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None


def parse_proc_snmp():
    """Parse /proc/net/snmp for TCP statistics."""
    content = read_proc_file('/proc/net/snmp')
    if content is None:
        return None

    stats = {}
    lines = content.strip().split('\n')

    # Lines come in pairs: header line then value line
    i = 0
    while i < len(lines) - 1:
        header_line = lines[i]
        value_line = lines[i + 1]

        if header_line.startswith('Tcp:') and value_line.startswith('Tcp:'):
            headers = header_line.split()[1:]  # Skip "Tcp:" prefix
            values = value_line.split()[1:]

            for h, v in zip(headers, values):
                try:
                    stats[h] = int(v)
                except ValueError:
                    stats[h] = 0

        i += 2

    return stats


def parse_proc_netstat():
    """Parse /proc/net/netstat for extended TCP statistics."""
    content = read_proc_file('/proc/net/netstat')
    if content is None:
        return None

    stats = {}
    lines = content.strip().split('\n')

    # Lines come in pairs: header line then value line
    i = 0
    while i < len(lines) - 1:
        header_line = lines[i]
        value_line = lines[i + 1]

        if header_line.startswith('TcpExt:') and value_line.startswith('TcpExt:'):
            headers = header_line.split()[1:]  # Skip "TcpExt:" prefix
            values = value_line.split()[1:]

            for h, v in zip(headers, values):
                try:
                    stats[h] = int(v)
                except ValueError:
                    stats[h] = 0

        i += 2

    return stats


def get_tcp_stats():
    """Get combined TCP statistics from /proc."""
    snmp = parse_proc_snmp()
    netstat = parse_proc_netstat()

    if snmp is None:
        return None

    # Combine stats
    stats = snmp.copy()
    if netstat:
        stats.update(netstat)

    return stats


def calculate_rates(before, after, interval):
    """Calculate per-second rates from two samples."""
    if before is None or after is None:
        return None

    rates = {}

    # Key metrics for retransmission analysis
    metrics = [
        'OutSegs',        # Total segments sent
        'RetransSegs',    # Retransmitted segments
        'InSegs',         # Total segments received
        'OutRsts',        # RST segments sent
        'InErrs',         # Segments received with errors
        'TCPLostRetransmit',   # Retransmits lost
        'TCPFastRetrans',      # Fast retransmits
        'TCPSlowStartRetrans', # Slow start retransmits
        'TCPTimeouts',         # Timeouts
        'TCPSpuriousRTOs',     # Spurious RTOs
    ]

    for metric in metrics:
        if metric in before and metric in after:
            diff = after[metric] - before[metric]
            # Handle counter wrap (unlikely but possible)
            if diff < 0:
                diff = 0
            rates[metric] = diff / interval
        else:
            rates[metric] = 0

    # Also store absolute values for context
    rates['_totals'] = {
        'OutSegs': after.get('OutSegs', 0),
        'RetransSegs': after.get('RetransSegs', 0),
        'InSegs': after.get('InSegs', 0),
    }

    return rates


def analyze_retransmissions(rates, warn_pct, crit_pct):
    """Analyze retransmission rates and generate warnings."""
    if rates is None:
        return None, []

    issues = []
    out_segs = rates.get('OutSegs', 0)
    retrans_segs = rates.get('RetransSegs', 0)

    # Calculate retransmission percentage
    retrans_pct = 0.0
    if out_segs > 0:
        retrans_pct = (retrans_segs / out_segs) * 100

    # Determine status
    status = 'ok'
    if retrans_pct >= crit_pct:
        status = 'critical'
        issues.append({
            'severity': 'critical',
            'message': f"TCP retransmission rate {retrans_pct:.2f}% exceeds critical threshold ({crit_pct}%)",
            'metric': 'retrans_pct',
            'value': retrans_pct,
            'threshold': crit_pct
        })
    elif retrans_pct >= warn_pct:
        status = 'warning'
        issues.append({
            'severity': 'warning',
            'message': f"TCP retransmission rate {retrans_pct:.2f}% exceeds warning threshold ({warn_pct}%)",
            'metric': 'retrans_pct',
            'value': retrans_pct,
            'threshold': warn_pct
        })

    # Check for high timeout rate
    timeouts = rates.get('TCPTimeouts', 0)
    if timeouts > 10:  # More than 10 timeouts/sec is concerning
        issues.append({
            'severity': 'warning',
            'message': f"High TCP timeout rate: {timeouts:.1f}/sec",
            'metric': 'TCPTimeouts',
            'value': timeouts,
            'threshold': 10
        })

    # Check for RST storm
    out_rsts = rates.get('OutRsts', 0)
    if out_segs > 0 and out_rsts > 100:  # More than 100 RSTs/sec
        issues.append({
            'severity': 'warning',
            'message': f"High RST rate: {out_rsts:.1f}/sec (may indicate connection issues)",
            'metric': 'OutRsts',
            'value': out_rsts,
            'threshold': 100
        })

    result = {
        'status': status,
        'retransmission_pct': round(retrans_pct, 4),
        'segments_out_per_sec': round(out_segs, 2),
        'retransmits_per_sec': round(retrans_segs, 2),
        'segments_in_per_sec': round(rates.get('InSegs', 0), 2),
        'timeouts_per_sec': round(rates.get('TCPTimeouts', 0), 2),
        'fast_retrans_per_sec': round(rates.get('TCPFastRetrans', 0), 2),
        'slow_start_retrans_per_sec': round(rates.get('TCPSlowStartRetrans', 0), 2),
        'rsts_out_per_sec': round(rates.get('OutRsts', 0), 2),
        'errors_in_per_sec': round(rates.get('InErrs', 0), 2),
        'totals': rates.get('_totals', {})
    }

    return result, issues


def output_plain(result, issues, interval, verbose, warn_only):
    """Output results in plain text format."""
    if warn_only and not issues:
        return

    print("TCP Retransmission Monitor")
    print("=" * 60)
    print(f"Sample interval: {interval}s")
    print()

    status_symbol = "OK" if result['status'] == 'ok' else result['status'].upper()
    print(f"Status: [{status_symbol}]")
    print()

    print("Retransmission Metrics:")
    print(f"  Retransmission rate: {result['retransmission_pct']:.4f}%")
    print(f"  Segments out/sec:    {result['segments_out_per_sec']:.2f}")
    print(f"  Retransmits/sec:     {result['retransmits_per_sec']:.2f}")
    print(f"  Segments in/sec:     {result['segments_in_per_sec']:.2f}")

    if verbose:
        print()
        print("Detailed Metrics:")
        print(f"  TCP timeouts/sec:        {result['timeouts_per_sec']:.2f}")
        print(f"  Fast retransmits/sec:    {result['fast_retrans_per_sec']:.2f}")
        print(f"  Slow start retrans/sec:  {result['slow_start_retrans_per_sec']:.2f}")
        print(f"  RST segments out/sec:    {result['rsts_out_per_sec']:.2f}")
        print(f"  Errors in/sec:           {result['errors_in_per_sec']:.2f}")
        print()
        print("Cumulative Totals:")
        totals = result.get('totals', {})
        print(f"  Total segments out:      {totals.get('OutSegs', 0):,}")
        print(f"  Total retransmits:       {totals.get('RetransSegs', 0):,}")
        print(f"  Total segments in:       {totals.get('InSegs', 0):,}")

    if issues:
        print()
        print(f"Issues ({len(issues)}):")
        for issue in issues:
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")
    elif not warn_only:
        print()
        print("[OK] TCP retransmission rate within thresholds")


def output_json(result, issues, interval):
    """Output results in JSON format."""
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'sample_interval_sec': interval,
        'metrics': result,
        'issues': issues,
        'summary': {
            'status': result['status'],
            'retransmission_pct': result['retransmission_pct'],
            'warning_count': len([i for i in issues if i['severity'] == 'warning']),
            'critical_count': len([i for i in issues if i['severity'] == 'critical']),
        },
        'has_issues': len(issues) > 0
    }
    print(json.dumps(output, indent=2))


def output_table(result, issues, warn_only):
    """Output results in table format."""
    if warn_only and not issues:
        return

    print(f"{'Metric':<25} {'Value':>15} {'Unit':<10}")
    print("-" * 50)
    print(f"{'Retransmission Rate':<25} {result['retransmission_pct']:>15.4f} {'%':<10}")
    print(f"{'Segments Out':<25} {result['segments_out_per_sec']:>15.2f} {'/sec':<10}")
    print(f"{'Retransmits':<25} {result['retransmits_per_sec']:>15.2f} {'/sec':<10}")
    print(f"{'Segments In':<25} {result['segments_in_per_sec']:>15.2f} {'/sec':<10}")
    print(f"{'Timeouts':<25} {result['timeouts_per_sec']:>15.2f} {'/sec':<10}")
    print(f"{'Fast Retrans':<25} {result['fast_retrans_per_sec']:>15.2f} {'/sec':<10}")
    print(f"{'RST Out':<25} {result['rsts_out_per_sec']:>15.2f} {'/sec':<10}")

    if issues:
        print()
        print(f"Issues ({len(issues)}):")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor TCP retransmission rates to detect network issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Sample for 1 second, show results
  %(prog)s -i 5                         # Sample for 5 seconds (more accurate)
  %(prog)s --format json                # Output in JSON format
  %(prog)s --warn 1 --crit 5            # Custom thresholds (1%% warn, 5%% crit)
  %(prog)s -w                           # Only output if issues detected
  %(prog)s -v                           # Show detailed metrics

What to look for:
  - Retransmission rate > 1%% indicates packet loss or congestion
  - High timeouts suggest network latency or connectivity issues
  - High RST rate may indicate connection problems or port scans

Exit codes:
  0 - No issues detected (retransmission rate within thresholds)
  1 - Retransmission rate exceeds warning threshold
  2 - Missing /proc files or usage error
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
        default=1.0,
        metavar="PCT",
        help="Warning threshold percentage (default: %(default)s)"
    )

    parser.add_argument(
        "--crit",
        type=float,
        default=5.0,
        metavar="PCT",
        help="Critical threshold percentage (default: %(default)s)"
    )

    args = parser.parse_args()

    if args.interval <= 0:
        print("Error: Interval must be positive", file=sys.stderr)
        sys.exit(2)

    if args.warn >= args.crit:
        print("Error: Warning threshold must be less than critical threshold",
              file=sys.stderr)
        sys.exit(2)

    # Take first sample
    before = get_tcp_stats()
    if before is None:
        print("Error: Cannot read /proc/net/snmp", file=sys.stderr)
        print("This script requires access to /proc filesystem", file=sys.stderr)
        sys.exit(2)

    # Wait for sampling interval
    time.sleep(args.interval)

    # Take second sample
    after = get_tcp_stats()
    if after is None:
        print("Error: Cannot read /proc/net/snmp", file=sys.stderr)
        sys.exit(2)

    # Calculate rates
    rates = calculate_rates(before, after, args.interval)

    # Analyze retransmissions
    result, issues = analyze_retransmissions(rates, args.warn, args.crit)

    if result is None:
        print("Error: Failed to analyze TCP statistics", file=sys.stderr)
        sys.exit(2)

    # Output results
    if args.format == "json":
        output_json(result, issues, args.interval)
    elif args.format == "table":
        output_table(result, issues, args.warn_only)
    else:
        output_plain(result, issues, args.interval, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
