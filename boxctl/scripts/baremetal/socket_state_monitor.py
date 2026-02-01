#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, tcp, sockets]
#   brief: Monitor TCP/UDP socket state distribution and detect anomalies

"""
Monitor TCP/UDP socket state distribution and detect connection anomalies.

Analyzes /proc/net/tcp and /proc/net/tcp6 to track socket state distribution
and identify potential connection issues such as:
- Excessive TIME_WAIT sockets (port exhaustion risk)
- High CLOSE_WAIT counts (file descriptor leaks)
- SYN_RECV accumulation (potential SYN flood)

Exit codes:
    0: No issues detected (healthy state)
    1: Anomalies or warnings detected
    2: Missing required /proc files or usage error
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


# TCP state mapping from /proc/net/tcp
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def parse_socket_file(content: str) -> list[dict]:
    """Parse /proc/net socket file and extract state information."""
    socket_states = []
    lines = content.strip().split("\n")

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue

        # Extract state (4th column in hex)
        state_hex = parts[3]
        state_name = TCP_STATES.get(state_hex, "UNKNOWN")

        # Extract local address
        local_addr = parts[1]

        socket_states.append({"state": state_name, "local_addr": local_addr})

    return socket_states


def analyze_socket_states(socket_data: list[dict]) -> dict[str, int]:
    """Analyze socket states and return statistics."""
    state_counts: dict[str, int] = defaultdict(int)

    for socket in socket_data:
        state_counts[socket["state"]] += 1

    return dict(state_counts)


def detect_anomalies(state_counts: dict[str, int], thresholds: dict) -> list[dict]:
    """Detect anomalies based on state counts and thresholds."""
    issues = []

    time_wait = state_counts.get("TIME_WAIT", 0)
    if time_wait > thresholds["time_wait"]:
        issues.append(
            {
                "severity": "warning",
                "state": "TIME_WAIT",
                "count": time_wait,
                "threshold": thresholds["time_wait"],
                "message": f"Excessive TIME_WAIT sockets ({time_wait}) may lead to port exhaustion",
            }
        )

    close_wait = state_counts.get("CLOSE_WAIT", 0)
    if close_wait > thresholds["close_wait"]:
        issues.append(
            {
                "severity": "warning",
                "state": "CLOSE_WAIT",
                "count": close_wait,
                "threshold": thresholds["close_wait"],
                "message": f"High CLOSE_WAIT count ({close_wait}) indicates file descriptor leaks",
            }
        )

    syn_recv = state_counts.get("SYN_RECV", 0)
    if syn_recv > thresholds["syn_recv"]:
        issues.append(
            {
                "severity": "warning",
                "state": "SYN_RECV",
                "count": syn_recv,
                "threshold": thresholds["syn_recv"],
                "message": f"High SYN_RECV count ({syn_recv}) may indicate SYN flood attack",
            }
        )

    established = state_counts.get("ESTABLISHED", 0)
    if established > thresholds["established"]:
        issues.append(
            {
                "severity": "info",
                "state": "ESTABLISHED",
                "count": established,
                "threshold": thresholds["established"],
                "message": f"High ESTABLISHED connections ({established}) - verify expected load",
            }
        )

    return issues


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
        description="Monitor TCP/UDP socket state distribution and detect anomalies"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information including thresholds",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only output if issues are detected",
    )
    parser.add_argument(
        "--time-wait",
        type=int,
        default=1000,
        metavar="N",
        help="TIME_WAIT threshold (default: 1000)",
    )
    parser.add_argument(
        "--close-wait",
        type=int,
        default=100,
        metavar="N",
        help="CLOSE_WAIT threshold (default: 100)",
    )
    parser.add_argument(
        "--syn-recv",
        type=int,
        default=100,
        metavar="N",
        help="SYN_RECV threshold (default: 100)",
    )
    parser.add_argument(
        "--established",
        type=int,
        default=5000,
        metavar="N",
        help="ESTABLISHED threshold (default: 5000)",
    )

    opts = parser.parse_args(args)

    # Define thresholds
    thresholds = {
        "time_wait": opts.time_wait,
        "close_wait": opts.close_wait,
        "syn_recv": opts.syn_recv,
        "established": opts.established,
    }

    # Parse socket files
    all_sockets = []

    for file_path in ["/proc/net/tcp", "/proc/net/tcp6"]:
        try:
            content = context.read_file(file_path)
            socket_data = parse_socket_file(content)
            all_sockets.extend(socket_data)
        except (FileNotFoundError, IOError) as e:
            output.error(f"Cannot read {file_path}: {e}")
            return 2

    # Analyze socket states
    state_counts = analyze_socket_states(all_sockets)

    # Detect anomalies
    issues = detect_anomalies(state_counts, thresholds)

    # Build result
    total_sockets = sum(state_counts.values())
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "state_counts": state_counts,
        "total_sockets": total_sockets,
        "issues": issues,
        "issue_count": len(issues),
        "status": "warning" if issues else "healthy",
        "healthy": len(issues) == 0,
    }

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or issues:
            print(json.dumps(result, indent=2))
    elif opts.format == "table":
        if not opts.warn_only or issues:
            lines = []
            lines.append(f"{'State':<15} {'Count':>10}")
            lines.append("-" * 25)
            for state in sorted(state_counts.keys()):
                count = state_counts[state]
                lines.append(f"{state:<15} {count:>10}")
            lines.append("-" * 25)
            lines.append(f"{'TOTAL':<15} {total_sockets:>10}")

            if issues:
                lines.append("")
                lines.append("Issues Detected:")
                lines.append(f"{'Severity':<12} {'State':<15} {'Count':>8} {'Message'}")
                lines.append("-" * 70)
                for issue in issues:
                    lines.append(
                        f"{issue['severity']:<12} {issue['state']:<15} "
                        f"{issue['count']:>8} {issue['message']}"
                    )

            print("\n".join(lines))
    else:  # plain
        if not opts.warn_only or issues:
            lines = []
            lines.append("Socket State Distribution:")
            for state in sorted(state_counts.keys()):
                count = state_counts[state]
                lines.append(f"  {state:<15} {count:>6}")

            if issues:
                lines.append("")
                lines.append("Detected Issues:")
                for issue in issues:
                    severity = issue["severity"].upper()
                    lines.append(f"  [{severity}] {issue['message']}")
                    if opts.verbose:
                        lines.append(
                            f"           Current: {issue['count']}, "
                            f"Threshold: {issue['threshold']}"
                        )
            else:
                lines.append("")
                lines.append("[OK] No anomalies detected")

            print("\n".join(lines))

    # Set summary
    output.set_summary(f"total={total_sockets}, issues={len(issues)}")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
