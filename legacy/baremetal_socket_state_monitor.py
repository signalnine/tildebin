#!/usr/bin/env python3
"""
Monitor TCP/UDP socket state distribution and detect connection anomalies.

This script analyzes /proc/net/tcp, /proc/net/tcp6, and /proc/net/udp to track
socket state distribution and identify potential connection issues such as:
- Excessive TIME_WAIT sockets (port exhaustion risk)
- High CLOSE_WAIT counts (file descriptor leaks)
- Unusual ESTABLISHED connection buildups
- SYN_RECV accumulation (potential SYN flood)

Useful for large-scale baremetal environments to detect connection leaks,
port exhaustion, and other network resource issues before they impact services.

Exit codes:
    0 - No issues detected (healthy state)
    1 - Anomalies or warnings detected
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

def parse_socket_file(file_path):
    """Parse /proc/net socket file and extract state information."""
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None
    except PermissionError:
        return None

    # Skip header line
    socket_states = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue

        # Extract state (4th column in hex)
        state_hex = parts[3]
        state_name = TCP_STATES.get(state_hex, 'UNKNOWN')

        # Extract local address and port
        local_addr = parts[1]

        socket_states.append({
            'state': state_name,
            'local_addr': local_addr
        })

    return socket_states

def analyze_socket_states(socket_data):
    """Analyze socket states and return statistics."""
    state_counts = defaultdict(int)

    for socket in socket_data:
        state_counts[socket['state']] += 1

    return dict(state_counts)

def detect_anomalies(state_counts, thresholds):
    """Detect anomalies based on state counts and thresholds."""
    issues = []

    time_wait = state_counts.get('TIME_WAIT', 0)
    if time_wait > thresholds['time_wait']:
        issues.append({
            'severity': 'warning',
            'state': 'TIME_WAIT',
            'count': time_wait,
            'threshold': thresholds['time_wait'],
            'message': f"Excessive TIME_WAIT sockets ({time_wait}) may lead to port exhaustion"
        })

    close_wait = state_counts.get('CLOSE_WAIT', 0)
    if close_wait > thresholds['close_wait']:
        issues.append({
            'severity': 'warning',
            'state': 'CLOSE_WAIT',
            'count': close_wait,
            'threshold': thresholds['close_wait'],
            'message': f"High CLOSE_WAIT count ({close_wait}) indicates file descriptor leaks"
        })

    syn_recv = state_counts.get('SYN_RECV', 0)
    if syn_recv > thresholds['syn_recv']:
        issues.append({
            'severity': 'warning',
            'state': 'SYN_RECV',
            'count': syn_recv,
            'threshold': thresholds['syn_recv'],
            'message': f"High SYN_RECV count ({syn_recv}) may indicate SYN flood attack"
        })

    established = state_counts.get('ESTABLISHED', 0)
    if established > thresholds['established']:
        issues.append({
            'severity': 'info',
            'state': 'ESTABLISHED',
            'count': established,
            'threshold': thresholds['established'],
            'message': f"High ESTABLISHED connections ({established}) - verify expected load"
        })

    return issues

def output_plain(state_counts, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only or issues:
        print("Socket State Distribution:")
        for state in sorted(state_counts.keys()):
            count = state_counts[state]
            print(f"  {state:<15} {count:>6}")

    if issues:
        print("\nDetected Issues:")
        for issue in issues:
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")
            if verbose:
                print(f"           Current: {issue['count']}, Threshold: {issue['threshold']}")
    elif not warn_only:
        print("\n[OK] No anomalies detected")

def output_json(state_counts, issues):
    """Output results in JSON format."""
    result = {
        'state_counts': state_counts,
        'issues': issues,
        'total_sockets': sum(state_counts.values()),
        'has_issues': len(issues) > 0
    }
    print(json.dumps(result, indent=2))

def output_table(state_counts, issues, warn_only):
    """Output results in table format."""
    if not warn_only or issues:
        print(f"{'State':<15} {'Count':>10}")
        print("-" * 25)
        for state in sorted(state_counts.keys()):
            count = state_counts[state]
            print(f"{state:<15} {count:>10}")
        print("-" * 25)
        print(f"{'TOTAL':<15} {sum(state_counts.values()):>10}")

    if issues:
        print("\nIssues Detected:")
        print(f"{'Severity':<12} {'State':<15} {'Count':>8} {'Message'}")
        print("-" * 70)
        for issue in issues:
            print(f"{issue['severity']:<12} {issue['state']:<15} {issue['count']:>8} {issue['message']}")

def main():
    parser = argparse.ArgumentParser(
        description="Monitor TCP/UDP socket state distribution and detect connection anomalies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check socket states with default thresholds
  %(prog)s --format json            # Output results in JSON format
  %(prog)s --time-wait 2000         # Custom TIME_WAIT threshold
  %(prog)s --warn-only              # Only show if issues detected
  %(prog)s -v                       # Verbose output with threshold details

Exit codes:
  0 - No issues detected
  1 - Anomalies or warnings detected
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
        help="Show detailed information including thresholds"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only output if issues are detected"
    )

    # Threshold arguments
    parser.add_argument(
        "--time-wait",
        type=int,
        default=1000,
        metavar="N",
        help="TIME_WAIT threshold (default: %(default)s)"
    )

    parser.add_argument(
        "--close-wait",
        type=int,
        default=100,
        metavar="N",
        help="CLOSE_WAIT threshold (default: %(default)s)"
    )

    parser.add_argument(
        "--syn-recv",
        type=int,
        default=100,
        metavar="N",
        help="SYN_RECV threshold (default: %(default)s)"
    )

    parser.add_argument(
        "--established",
        type=int,
        default=5000,
        metavar="N",
        help="ESTABLISHED threshold (default: %(default)s)"
    )

    args = parser.parse_args()

    # Define thresholds
    thresholds = {
        'time_wait': args.time_wait,
        'close_wait': args.close_wait,
        'syn_recv': args.syn_recv,
        'established': args.established
    }

    # Parse socket files
    all_sockets = []

    for file_path in ['/proc/net/tcp', '/proc/net/tcp6']:
        socket_data = parse_socket_file(file_path)
        if socket_data is None:
            print(f"Error: Cannot read {file_path}", file=sys.stderr)
            print("This script requires access to /proc/net files", file=sys.stderr)
            sys.exit(2)
        all_sockets.extend(socket_data)

    # Analyze socket states
    state_counts = analyze_socket_states(all_sockets)

    # Detect anomalies
    issues = detect_anomalies(state_counts, thresholds)

    # Output results
    if args.format == "json":
        output_json(state_counts, issues)
    elif args.format == "table":
        output_table(state_counts, issues, args.warn_only)
    else:  # plain
        output_plain(state_counts, issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    sys.exit(1 if issues else 0)

if __name__ == "__main__":
    main()
