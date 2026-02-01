#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, tcp, connections]
#   brief: Monitor TCP connection states to detect connection leaks and pressure

"""
Monitor TCP connection states to detect connection leaks and pressure.

Analyzes /proc/net/tcp and /proc/net/tcp6 to provide visibility into TCP
connection states across the system. Identifies connection state anomalies
like TIME_WAIT accumulation (port exhaustion) and CLOSE_WAIT (connection leaks).

Exit codes:
    0: No connection issues detected
    1: Connection warnings or threshold exceeded
    2: Usage error or unable to read connection information
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


# TCP state constants from include/net/tcp_states.h
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


def hex_to_ip(hex_ip: str) -> str:
    """Convert hex IP address to dotted decimal notation."""
    if len(hex_ip) == 8:
        # Little-endian byte order in /proc/net/tcp
        ip_int = int(hex_ip, 16)
        return ".".join(
            [
                str((ip_int >> 0) & 0xFF),
                str((ip_int >> 8) & 0xFF),
                str((ip_int >> 16) & 0xFF),
                str((ip_int >> 24) & 0xFF),
            ]
        )
    elif len(hex_ip) == 32:
        return "ipv6"
    return hex_ip


def hex_to_port(hex_port: str) -> int:
    """Convert hex port to integer."""
    return int(hex_port, 16)


def parse_tcp_connections(content: str) -> list[dict]:
    """Parse /proc/net/tcp or /proc/net/tcp6 content."""
    connections = []
    lines = content.strip().split("\n")[1:]  # Skip header

    for line in lines:
        parts = line.split()
        if len(parts) < 12:
            continue

        try:
            # Parse local address
            local_addr = parts[1]
            local_ip, local_port = local_addr.split(":")
            local_port = hex_to_port(local_port)

            # Parse remote address
            remote_addr = parts[2]
            remote_ip, remote_port = remote_addr.split(":")
            remote_port = hex_to_port(remote_port)

            # Get state
            state_hex = parts[3].upper()
            state = TCP_STATES.get(state_hex, f"UNKNOWN({state_hex})")

            # Get inode
            inode = int(parts[9])

            connections.append(
                {
                    "local_ip": hex_to_ip(local_ip),
                    "local_port": local_port,
                    "remote_ip": hex_to_ip(remote_ip),
                    "remote_port": remote_port,
                    "state": state,
                    "inode": inode,
                }
            )
        except (ValueError, IndexError):
            continue

    return connections


def filter_connections(
    connections: list[dict],
    port_filter: int | None = None,
    state_filter: str | None = None,
) -> list[dict]:
    """Filter connections by port or state."""
    filtered = connections

    if port_filter is not None:
        filtered = [
            c
            for c in filtered
            if c["local_port"] == port_filter or c["remote_port"] == port_filter
        ]

    if state_filter:
        state_upper = state_filter.upper()
        filtered = [c for c in filtered if c["state"] == state_upper]

    return filtered


def analyze_connections(
    connections: list[dict],
    time_wait_warn: int,
    close_wait_warn: int,
    total_warn: int,
) -> dict:
    """Analyze connections and generate summary."""
    # Count by state
    state_counts: dict[str, int] = defaultdict(int)
    for conn in connections:
        state_counts[conn["state"]] += 1

    # Identify issues
    issues = []
    warnings = []

    time_wait_count = state_counts.get("TIME_WAIT", 0)
    if time_wait_count >= time_wait_warn:
        issues.append(
            f"High TIME_WAIT count: {time_wait_count} (threshold: {time_wait_warn})"
        )

    close_wait_count = state_counts.get("CLOSE_WAIT", 0)
    if close_wait_count >= close_wait_warn:
        issues.append(
            f"High CLOSE_WAIT count: {close_wait_count} (threshold: {close_wait_warn})"
        )

    total_count = len(connections)
    if total_count >= total_warn:
        issues.append(
            f"High total connection count: {total_count} (threshold: {total_warn})"
        )

    status = "critical" if issues else ("warning" if warnings else "healthy")

    return {
        "total": len(connections),
        "state_counts": dict(state_counts),
        "issues": issues,
        "warnings": warnings,
        "status": status,
    }


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
        description="Monitor TCP connection states for issues"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show individual connections"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show if there are issues",
    )
    parser.add_argument(
        "--port", type=int, metavar="PORT", help="Filter to connections on this port"
    )
    parser.add_argument(
        "--state",
        type=str,
        metavar="STATE",
        help="Filter to connections in this state (e.g., ESTABLISHED, TIME_WAIT)",
    )
    parser.add_argument(
        "--time-wait-warn",
        type=int,
        default=10000,
        metavar="N",
        help="Warn if TIME_WAIT count exceeds N (default: 10000)",
    )
    parser.add_argument(
        "--close-wait-warn",
        type=int,
        default=100,
        metavar="N",
        help="Warn if CLOSE_WAIT count exceeds N (default: 100)",
    )
    parser.add_argument(
        "--total-warn",
        type=int,
        default=50000,
        metavar="N",
        help="Warn if total connection count exceeds N (default: 50000)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Show top N connections (default: 10)",
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if opts.time_wait_warn < 0:
        output.error("--time-wait-warn must be non-negative")
        return 2
    if opts.close_wait_warn < 0:
        output.error("--close-wait-warn must be non-negative")
        return 2
    if opts.total_warn < 0:
        output.error("--total-warn must be non-negative")
        return 2
    if opts.top < 0:
        output.error("--top must be non-negative")
        return 2

    # Validate state
    if opts.state:
        valid_states = list(TCP_STATES.values())
        if opts.state.upper() not in valid_states:
            output.error(f"Invalid state '{opts.state}'")
            return 2

    # Read /proc/net/tcp
    try:
        tcp_content = context.read_file("/proc/net/tcp")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/net/tcp: {e}")
        return 2

    # Read /proc/net/tcp6 (optional)
    try:
        tcp6_content = context.read_file("/proc/net/tcp6")
    except (FileNotFoundError, IOError):
        tcp6_content = ""

    # Parse connections
    connections = parse_tcp_connections(tcp_content)
    if tcp6_content:
        connections.extend(parse_tcp_connections(tcp6_content))

    # Apply filters
    connections = filter_connections(
        connections, port_filter=opts.port, state_filter=opts.state
    )

    # Analyze
    analysis = analyze_connections(
        connections,
        time_wait_warn=opts.time_wait_warn,
        close_wait_warn=opts.close_wait_warn,
        total_warn=opts.total_warn,
    )

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_connections": analysis["total"],
        "state_counts": analysis["state_counts"],
        "issues": analysis["issues"],
        "warnings": analysis["warnings"],
        "status": analysis["status"],
        "healthy": len(analysis["issues"]) == 0,
    }

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            lines = []
            lines.append("TCP Connection Monitor")
            lines.append("=" * 40)
            lines.append("")

            # State summary
            lines.append("Connection States:")
            for state in [
                "ESTABLISHED",
                "LISTEN",
                "TIME_WAIT",
                "CLOSE_WAIT",
                "FIN_WAIT1",
                "FIN_WAIT2",
                "SYN_SENT",
                "SYN_RECV",
                "LAST_ACK",
                "CLOSING",
                "CLOSE",
            ]:
                count = analysis["state_counts"].get(state, 0)
                if count > 0:
                    lines.append(f"  {state:<12} {count:>6}")
            lines.append(f"  {'TOTAL':<12} {analysis['total']:>6}")
            lines.append("")

            if analysis["issues"]:
                lines.append("ISSUES:")
                for issue in analysis["issues"]:
                    lines.append(f"  [!] {issue}")
                lines.append("")

            if analysis["warnings"]:
                lines.append("WARNINGS:")
                for warning in analysis["warnings"]:
                    lines.append(f"  [*] {warning}")
                lines.append("")

            if not analysis["issues"] and not analysis["warnings"]:
                lines.append("[OK] No connection issues detected")

            if opts.verbose and connections:
                lines.append("")
                lines.append(f"Connections (showing up to {opts.top}):")
                lines.append(
                    f"  {'State':<12} {'Local Port':>10} {'Remote':>15}"
                )
                lines.append("  " + "-" * 40)
                for conn in connections[: opts.top]:
                    remote = f"{conn['remote_ip']}:{conn['remote_port']}"
                    if len(remote) > 15:
                        remote = remote[:12] + "..."
                    lines.append(
                        f"  {conn['state']:<12} {conn['local_port']:>10} {remote:>15}"
                    )

            print("\n".join(lines))

    # Set summary
    output.set_summary(f"status={analysis['status']}, total={analysis['total']}")

    return 1 if analysis["issues"] else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
