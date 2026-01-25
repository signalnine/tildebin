#!/usr/bin/env python3
"""
Monitor ephemeral port usage and detect exhaustion risk on baremetal systems.

This script analyzes TCP/UDP connections to track ephemeral (dynamic) port usage
against the configured kernel range. It helps detect:
- Ephemeral port exhaustion risk before services fail
- High port usage by specific remote destinations
- TIME_WAIT accumulation consuming the port range
- Per-user port consumption (when running as root)

Ephemeral port exhaustion causes connection failures with "Cannot assign requested
address" errors. This is common in high-throughput services, load balancers, and
systems making many outbound connections.

Exit codes:
    0 - Port usage within safe thresholds
    1 - High usage or exhaustion risk detected
    2 - Missing required /proc files or usage error
"""

import argparse
import sys
import json
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


def get_ephemeral_port_range():
    """Read the kernel's ephemeral port range from /proc/sys/net/ipv4/ip_local_port_range."""
    try:
        with open('/proc/sys/net/ipv4/ip_local_port_range', 'r') as f:
            line = f.read().strip()
            parts = line.split()
            return int(parts[0]), int(parts[1])
    except (FileNotFoundError, PermissionError, IndexError, ValueError):
        # Default Linux range
        return 32768, 60999


def parse_socket_file(file_path, protocol):
    """Parse /proc/net socket file and extract connection information."""
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

        # Extract local address and port
        local_addr = parts[1]
        local_port = int(local_addr.split(':')[1], 16)

        # Extract remote address and port
        remote_addr = parts[2]
        remote_ip_hex = remote_addr.split(':')[0]
        remote_port = int(remote_addr.split(':')[1], 16)

        # Extract state (for TCP)
        state_hex = parts[3]
        state_name = TCP_STATES.get(state_hex, 'UNKNOWN')

        # Extract UID
        uid = int(parts[7]) if len(parts) > 7 else 0

        # Convert remote IP
        if len(remote_ip_hex) == 8:
            # IPv4 little-endian
            remote_ip = '.'.join(str(int(remote_ip_hex[i:i+2], 16))
                                 for i in range(6, -1, -2))
        else:
            remote_ip = 'ipv6'

        connections.append({
            'local_port': local_port,
            'remote_ip': remote_ip,
            'remote_port': remote_port,
            'state': state_name,
            'protocol': protocol,
            'uid': uid
        })

    return connections


def analyze_ephemeral_usage(connections, port_range):
    """Analyze ephemeral port usage from connections."""
    low, high = port_range
    total_available = high - low + 1

    ephemeral_ports = set()
    by_remote = defaultdict(int)
    by_state = defaultdict(int)
    by_uid = defaultdict(int)

    for conn in connections:
        port = conn['local_port']
        # Check if this is an ephemeral port (outbound connection)
        if low <= port <= high:
            ephemeral_ports.add(port)
            if conn['remote_ip'] != '0.0.0.0' and conn['remote_port'] != 0:
                remote_key = f"{conn['remote_ip']}:{conn['remote_port']}"
                by_remote[remote_key] += 1
            by_state[conn['state']] += 1
            by_uid[conn['uid']] += 1

    used = len(ephemeral_ports)
    usage_percent = (used / total_available) * 100 if total_available > 0 else 0

    return {
        'port_range': {'low': low, 'high': high},
        'total_available': total_available,
        'used': used,
        'free': total_available - used,
        'usage_percent': round(usage_percent, 2),
        'by_state': dict(by_state),
        'by_remote': dict(sorted(by_remote.items(), key=lambda x: x[1], reverse=True)[:10]),
        'by_uid': dict(sorted(by_uid.items(), key=lambda x: x[1], reverse=True)[:5])
    }


def detect_issues(analysis, thresholds):
    """Detect issues based on usage thresholds."""
    issues = []

    if analysis['usage_percent'] >= thresholds['critical']:
        issues.append({
            'severity': 'critical',
            'type': 'exhaustion_imminent',
            'usage_percent': analysis['usage_percent'],
            'threshold': thresholds['critical'],
            'message': f"CRITICAL: Ephemeral port exhaustion imminent ({analysis['usage_percent']}% used, {analysis['free']} free)"
        })
    elif analysis['usage_percent'] >= thresholds['warning']:
        issues.append({
            'severity': 'warning',
            'type': 'high_usage',
            'usage_percent': analysis['usage_percent'],
            'threshold': thresholds['warning'],
            'message': f"High ephemeral port usage ({analysis['usage_percent']}% used, {analysis['free']} free)"
        })

    # Check for TIME_WAIT accumulation
    time_wait = analysis['by_state'].get('TIME_WAIT', 0)
    time_wait_percent = (time_wait / analysis['total_available']) * 100 if analysis['total_available'] > 0 else 0
    if time_wait_percent >= thresholds['time_wait_percent']:
        issues.append({
            'severity': 'warning',
            'type': 'time_wait_accumulation',
            'count': time_wait,
            'percent': round(time_wait_percent, 2),
            'message': f"TIME_WAIT accumulation: {time_wait} ports ({round(time_wait_percent, 1)}% of range)"
        })

    return issues


def output_plain(analysis, issues, verbose, warn_only):
    """Output results in plain text format."""
    if warn_only and not issues:
        return

    print("Ephemeral Port Usage:")
    print(f"  Range: {analysis['port_range']['low']}-{analysis['port_range']['high']} ({analysis['total_available']} ports)")
    print(f"  Used:  {analysis['used']} ({analysis['usage_percent']}%)")
    print(f"  Free:  {analysis['free']}")

    if verbose or analysis['by_state']:
        print("\nBy Connection State:")
        for state, count in sorted(analysis['by_state'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {state:<15} {count:>6}")

    if verbose and analysis['by_remote']:
        print("\nTop Remote Destinations:")
        for remote, count in list(analysis['by_remote'].items())[:5]:
            print(f"  {remote:<35} {count:>6} ports")

    if issues:
        print("\nIssues Detected:")
        for issue in issues:
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")
    else:
        print("\n[OK] Ephemeral port usage is healthy")


def output_json(analysis, issues):
    """Output results in JSON format."""
    result = {
        'ephemeral_ports': analysis,
        'issues': issues,
        'has_issues': len(issues) > 0,
        'healthy': len(issues) == 0
    }
    print(json.dumps(result, indent=2))


def output_table(analysis, issues, warn_only):
    """Output results in table format."""
    if warn_only and not issues:
        return

    print(f"{'Metric':<25} {'Value':>15}")
    print("-" * 42)
    print(f"{'Port Range':<25} {analysis['port_range']['low']}-{analysis['port_range']['high']:>5}")
    print(f"{'Total Available':<25} {analysis['total_available']:>15}")
    print(f"{'Used':<25} {analysis['used']:>15}")
    print(f"{'Free':<25} {analysis['free']:>15}")
    print(f"{'Usage %':<25} {analysis['usage_percent']:>14}%")

    if analysis['by_state']:
        print("\n" + f"{'State':<15} {'Count':>10}")
        print("-" * 27)
        for state, count in sorted(analysis['by_state'].items(), key=lambda x: x[1], reverse=True):
            print(f"{state:<15} {count:>10}")

    if issues:
        print("\n" + f"{'Severity':<12} {'Issue'}")
        print("-" * 60)
        for issue in issues:
            print(f"{issue['severity'].upper():<12} {issue['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor ephemeral port usage and detect exhaustion risk",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check ephemeral port usage
  %(prog)s --format json            # Output in JSON format
  %(prog)s --warning 60 --critical 80  # Custom thresholds
  %(prog)s -v                       # Verbose output with top destinations
  %(prog)s --warn-only              # Only output if issues detected

Exit codes:
  0 - Usage within safe thresholds
  1 - High usage or issues detected
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
        help="Show detailed information including top destinations"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if issues are detected"
    )

    parser.add_argument(
        "--warning",
        type=float,
        default=70.0,
        metavar="PERCENT",
        help="Warning threshold percentage (default: %(default)s)"
    )

    parser.add_argument(
        "--critical",
        type=float,
        default=85.0,
        metavar="PERCENT",
        help="Critical threshold percentage (default: %(default)s)"
    )

    parser.add_argument(
        "--time-wait-percent",
        type=float,
        default=30.0,
        metavar="PERCENT",
        help="TIME_WAIT accumulation warning threshold (default: %(default)s)"
    )

    args = parser.parse_args()

    if args.warning >= args.critical:
        print("Error: Warning threshold must be less than critical threshold", file=sys.stderr)
        sys.exit(2)

    # Get ephemeral port range
    port_range = get_ephemeral_port_range()

    # Parse socket files
    all_connections = []

    for file_path, protocol in [('/proc/net/tcp', 'tcp'), ('/proc/net/tcp6', 'tcp6')]:
        connections = parse_socket_file(file_path, protocol)
        if connections is None:
            print(f"Error: Cannot read {file_path}", file=sys.stderr)
            print("This script requires access to /proc/net files", file=sys.stderr)
            sys.exit(2)
        all_connections.extend(connections)

    # Analyze usage
    analysis = analyze_ephemeral_usage(all_connections, port_range)

    # Define thresholds
    thresholds = {
        'warning': args.warning,
        'critical': args.critical,
        'time_wait_percent': args.time_wait_percent
    }

    # Detect issues
    issues = detect_issues(analysis, thresholds)

    # Output results
    if args.format == "json":
        output_json(analysis, issues)
    elif args.format == "table":
        output_table(analysis, issues, args.warn_only)
    else:  # plain
        output_plain(analysis, issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
