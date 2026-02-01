#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, ports, connections]
#   brief: Monitor ephemeral port usage and detect exhaustion risk

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
    0: Port usage within safe thresholds
    1: High usage or exhaustion risk detected
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


def get_ephemeral_port_range(context: Context) -> tuple[int, int]:
    """Read the kernel's ephemeral port range.

    Args:
        context: Execution context

    Returns:
        tuple: (low, high) port range
    """
    try:
        content = context.read_file("/proc/sys/net/ipv4/ip_local_port_range")
        parts = content.strip().split()
        return int(parts[0]), int(parts[1])
    except (FileNotFoundError, PermissionError, IndexError, ValueError):
        # Default Linux range
        return 32768, 60999


def parse_socket_file(content: str, protocol: str) -> list[dict]:
    """Parse /proc/net socket file content.

    Args:
        content: File content
        protocol: Protocol name (tcp, tcp6)

    Returns:
        list: List of connection dicts
    """
    connections = []
    lines = content.strip().split("\n")[1:]  # Skip header

    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue

        try:
            # Extract local address and port
            local_addr = parts[1]
            local_port = int(local_addr.split(":")[1], 16)

            # Extract remote address and port
            remote_addr = parts[2]
            remote_ip_hex = remote_addr.split(":")[0]
            remote_port = int(remote_addr.split(":")[1], 16)

            # Extract state
            state_hex = parts[3].upper()
            state_name = TCP_STATES.get(state_hex, "UNKNOWN")

            # Extract UID
            uid = int(parts[7]) if len(parts) > 7 else 0

            # Convert remote IP
            if len(remote_ip_hex) == 8:
                # IPv4 little-endian
                remote_ip = ".".join(
                    str(int(remote_ip_hex[i : i + 2], 16)) for i in range(6, -1, -2)
                )
            else:
                remote_ip = "ipv6"

            connections.append(
                {
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": state_name,
                    "protocol": protocol,
                    "uid": uid,
                }
            )
        except (ValueError, IndexError):
            continue

    return connections


def analyze_ephemeral_usage(
    connections: list[dict], port_range: tuple[int, int]
) -> dict:
    """Analyze ephemeral port usage from connections.

    Args:
        connections: List of parsed connections
        port_range: (low, high) ephemeral port range

    Returns:
        dict: Analysis results
    """
    low, high = port_range
    total_available = high - low + 1

    ephemeral_ports = set()
    by_remote: dict[str, int] = defaultdict(int)
    by_state: dict[str, int] = defaultdict(int)
    by_uid: dict[int, int] = defaultdict(int)

    for conn in connections:
        port = conn["local_port"]
        # Check if this is an ephemeral port (outbound connection)
        if low <= port <= high:
            ephemeral_ports.add(port)
            if conn["remote_ip"] != "0.0.0.0" and conn["remote_port"] != 0:
                remote_key = f"{conn['remote_ip']}:{conn['remote_port']}"
                by_remote[remote_key] += 1
            by_state[conn["state"]] += 1
            by_uid[conn["uid"]] += 1

    used = len(ephemeral_ports)
    usage_percent = (used / total_available) * 100 if total_available > 0 else 0

    return {
        "port_range": {"low": low, "high": high},
        "total_available": total_available,
        "used": used,
        "free": total_available - used,
        "usage_percent": round(usage_percent, 2),
        "by_state": dict(by_state),
        "by_remote": dict(
            sorted(by_remote.items(), key=lambda x: x[1], reverse=True)[:10]
        ),
        "by_uid": dict(sorted(by_uid.items(), key=lambda x: x[1], reverse=True)[:5]),
    }


def detect_issues(analysis: dict, thresholds: dict) -> list:
    """Detect issues based on usage thresholds.

    Args:
        analysis: Analysis results
        thresholds: Threshold configuration

    Returns:
        list: List of issues
    """
    issues = []

    if analysis["usage_percent"] >= thresholds["critical"]:
        issues.append(
            {
                "severity": "CRITICAL",
                "type": "exhaustion_imminent",
                "usage_percent": analysis["usage_percent"],
                "threshold": thresholds["critical"],
                "message": f"Ephemeral port exhaustion imminent ({analysis['usage_percent']}% used, {analysis['free']} free)",
            }
        )
    elif analysis["usage_percent"] >= thresholds["warning"]:
        issues.append(
            {
                "severity": "WARNING",
                "type": "high_usage",
                "usage_percent": analysis["usage_percent"],
                "threshold": thresholds["warning"],
                "message": f"High ephemeral port usage ({analysis['usage_percent']}% used, {analysis['free']} free)",
            }
        )

    # Check for TIME_WAIT accumulation
    time_wait = analysis["by_state"].get("TIME_WAIT", 0)
    time_wait_percent = (
        (time_wait / analysis["total_available"]) * 100
        if analysis["total_available"] > 0
        else 0
    )
    if time_wait_percent >= thresholds["time_wait_percent"]:
        issues.append(
            {
                "severity": "WARNING",
                "type": "time_wait_accumulation",
                "count": time_wait,
                "percent": round(time_wait_percent, 2),
                "message": f"TIME_WAIT accumulation: {time_wait} ports ({round(time_wait_percent, 1)}% of range)",
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
        description="Monitor ephemeral port usage and detect exhaustion risk"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information including top destinations",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only output if issues are detected",
    )
    parser.add_argument(
        "--warning",
        type=float,
        default=70.0,
        metavar="PERCENT",
        help="Warning threshold percentage (default: 70)",
    )
    parser.add_argument(
        "--critical",
        type=float,
        default=85.0,
        metavar="PERCENT",
        help="Critical threshold percentage (default: 85)",
    )
    parser.add_argument(
        "--time-wait-percent",
        type=float,
        default=30.0,
        metavar="PERCENT",
        help="TIME_WAIT accumulation warning threshold (default: 30)",
    )

    opts = parser.parse_args(args)

    if opts.warning >= opts.critical:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    # Get ephemeral port range
    port_range = get_ephemeral_port_range(context)

    # Parse socket files
    all_connections = []

    for file_path, protocol in [("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")]:
        try:
            content = context.read_file(file_path)
            connections = parse_socket_file(content, protocol)
            all_connections.extend(connections)
        except FileNotFoundError:
            if file_path == "/proc/net/tcp":
                output.error(f"Cannot read {file_path}")
                return 2
            # tcp6 is optional
            continue
        except (PermissionError, IOError) as e:
            output.error(f"Cannot read {file_path}: {e}")
            return 2

    # Analyze usage
    analysis = analyze_ephemeral_usage(all_connections, port_range)

    # Define thresholds
    thresholds = {
        "warning": opts.warning,
        "critical": opts.critical,
        "time_wait_percent": opts.time_wait_percent,
    }

    # Detect issues
    issues = detect_issues(analysis, thresholds)

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ephemeral_ports": analysis,
        "issues": issues,
        "has_issues": len(issues) > 0,
        "healthy": len(issues) == 0,
    }

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or issues:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or issues:
            lines = []
            lines.append("Ephemeral Port Usage Monitor")
            lines.append("=" * 50)
            lines.append("")
            lines.append(
                f"Range: {analysis['port_range']['low']}-{analysis['port_range']['high']} ({analysis['total_available']} ports)"
            )
            lines.append(f"Used:  {analysis['used']} ({analysis['usage_percent']}%)")
            lines.append(f"Free:  {analysis['free']}")
            lines.append("")

            if analysis["by_state"]:
                lines.append("By Connection State:")
                for state, count in sorted(
                    analysis["by_state"].items(), key=lambda x: x[1], reverse=True
                ):
                    lines.append(f"  {state:<15} {count:>6}")
                lines.append("")

            if opts.verbose and analysis["by_remote"]:
                lines.append("Top Remote Destinations:")
                for remote, count in list(analysis["by_remote"].items())[:5]:
                    lines.append(f"  {remote:<35} {count:>6} ports")
                lines.append("")

            if issues:
                lines.append("Issues Detected:")
                for issue in issues:
                    severity = issue["severity"]
                    lines.append(f"  [{severity}] {issue['message']}")
            else:
                lines.append("[OK] Ephemeral port usage is healthy")

            print("\n".join(lines))

    # Set summary
    output.set_summary(f"usage={analysis['usage_percent']}%, used={analysis['used']}")

    # Exit with appropriate code
    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
