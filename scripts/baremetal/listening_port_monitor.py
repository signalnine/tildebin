#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, ports, security]
#   brief: Monitor listening ports and detect unexpected services

"""
Monitor listening ports and detect unexpected services on baremetal systems.

Analyzes /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, and /proc/net/udp6
to identify all listening ports. Helps detect:
- Unexpected services binding to ports
- Missing expected services
- Services binding to all interfaces vs localhost

Exit codes:
    0: No issues detected (or all expected ports found)
    1: Unexpected ports found or expected ports missing
    2: Missing required /proc files or usage error
"""

import argparse
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


# TCP state for LISTEN
LISTEN_STATE = "0A"


def hex_to_ip(hex_str: str) -> str:
    """Convert hex IP address to dotted decimal notation."""
    # Handle IPv4
    if len(hex_str) == 8:
        # Little-endian byte order
        parts = [str(int(hex_str[i : i + 2], 16)) for i in range(6, -1, -2)]
        return ".".join(parts)
    # Handle IPv6
    elif len(hex_str) == 32:
        # IPv6 addresses in /proc are in network byte order per 32-bit word
        parts = []
        for i in range(0, 32, 8):
            word = hex_str[i : i + 8]
            # Reverse bytes within each 32-bit word
            reversed_word = "".join([word[j : j + 2] for j in range(6, -1, -2)])
            parts.append(reversed_word[:4])
            parts.append(reversed_word[4:])
        ip = ":".join(parts)
        # Compress common IPv6 addresses
        if ip == "0000:0000:0000:0000:0000:0000:0000:0000":
            return "::"
        if ip == "0000:0000:0000:0000:0000:0000:0000:0001":
            return "::1"
        return ip
    return hex_str


def parse_listening_ports(content: str, protocol: str) -> list[dict]:
    """Parse /proc/net socket file for listening ports."""
    listening = []
    lines = content.strip().split("\n")

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue

        # For TCP, check if state is LISTEN (0A)
        # For UDP, all entries are considered "listening"
        if protocol.startswith("tcp"):
            state = parts[3]
            if state != LISTEN_STATE:
                continue

        # Extract local address and port
        local_addr = parts[1]
        addr_parts = local_addr.split(":")
        hex_ip = addr_parts[0]
        hex_port = addr_parts[1]

        ip = hex_to_ip(hex_ip)
        port = int(hex_port, 16)

        # Get inode for process lookup (if available)
        inode = parts[9] if len(parts) > 9 else "0"

        # Determine bind type
        bind_type = "all"
        if ip in ("127.0.0.1", "::1"):
            bind_type = "local"
        elif ip not in ("0.0.0.0", "::"):
            bind_type = "specific"

        listening.append(
            {
                "protocol": protocol,
                "ip": ip,
                "port": port,
                "inode": inode,
                "bind_type": bind_type,
            }
        )

    return listening


def parse_port_list(port_string: str | None) -> set[int]:
    """Parse comma-separated port list."""
    if not port_string:
        return set()
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            # Range like 80-443
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return ports


def analyze_ports(
    listening_ports: list[dict],
    expected_ports: set[int],
    unexpected_ports: set[int],
) -> list[dict]:
    """Analyze listening ports against expected/unexpected lists."""
    issues = []
    found_ports = set()

    for entry in listening_ports:
        port = entry["port"]
        found_ports.add(port)

        # Check for unexpected ports
        if unexpected_ports and port in unexpected_ports:
            issues.append(
                {
                    "severity": "warning",
                    "type": "unexpected_port",
                    "port": port,
                    "protocol": entry["protocol"],
                    "message": f"Unexpected port {port}/{entry['protocol']} is listening",
                }
            )

    # Check for missing expected ports
    if expected_ports:
        missing = expected_ports - found_ports
        for port in missing:
            issues.append(
                {
                    "severity": "error",
                    "type": "missing_port",
                    "port": port,
                    "message": f"Expected port {port} is not listening",
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
        description="Monitor listening ports and detect unexpected services"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed information"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only output if issues are detected",
    )
    parser.add_argument(
        "--expected",
        metavar="PORTS",
        help="Comma-separated list of expected ports (e.g., 22,80,443 or 8000-8010)",
    )
    parser.add_argument(
        "--unexpected",
        metavar="PORTS",
        help="Comma-separated list of unexpected ports to alert on",
    )
    parser.add_argument(
        "--tcp-only", action="store_true", help="Only show TCP listening ports"
    )
    parser.add_argument(
        "--udp-only", action="store_true", help="Only show UDP listening ports"
    )
    parser.add_argument(
        "--show-all-interfaces",
        action="store_true",
        help="Only show ports bound to all interfaces (0.0.0.0 or ::)",
    )
    parser.add_argument(
        "--port", type=int, metavar="PORT", help="Filter to specific port number"
    )

    opts = parser.parse_args(args)

    if opts.tcp_only and opts.udp_only:
        output.error("Cannot specify both --tcp-only and --udp-only")
        return 2

    # Parse port lists
    try:
        expected_ports = parse_port_list(opts.expected)
        unexpected_ports = parse_port_list(opts.unexpected)
    except ValueError as e:
        output.error(f"Invalid port specification: {e}")
        return 2

    # Collect listening ports from all sources
    all_listening: list[dict] = []
    sources = []

    if not opts.udp_only:
        sources.extend([("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")])

    if not opts.tcp_only:
        sources.extend([("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp6")])

    for file_path, protocol in sources:
        try:
            content = context.read_file(file_path)
            result = parse_listening_ports(content, protocol)
            all_listening.extend(result)
        except (FileNotFoundError, IOError) as e:
            output.error(f"Cannot read {file_path}: {e}")
            return 2

    # Remove inode field from output (internal use only)
    for entry in all_listening:
        del entry["inode"]

    # Apply filters
    if opts.show_all_interfaces:
        all_listening = [e for e in all_listening if e["bind_type"] == "all"]

    if opts.port:
        all_listening = [e for e in all_listening if e["port"] == opts.port]

    # Analyze for issues
    issues = analyze_ports(all_listening, expected_ports, unexpected_ports)

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "listening_ports": all_listening,
        "issues": issues,
        "summary": {
            "total_ports": len(all_listening),
            "tcp_ports": len([p for p in all_listening if p["protocol"].startswith("tcp")]),
            "udp_ports": len([p for p in all_listening if p["protocol"].startswith("udp")]),
            "all_interfaces": len([p for p in all_listening if p["bind_type"] == "all"]),
            "localhost_only": len([p for p in all_listening if p["bind_type"] == "local"]),
            "issue_count": len(issues),
        },
        "status": "warning" if issues else "healthy",
        "healthy": len(issues) == 0,
    }

    # Output handling
    output.emit(result)
    if opts.format == "table":
        if not opts.warn_only or issues:
            lines = []
            # Group by port
            by_port: dict[int, list[dict]] = defaultdict(list)
            for entry in all_listening:
                by_port[entry["port"]].append(entry)

            lines.append(
                f"{'Port':>6} {'Proto':<8} {'Bind':<10} {'Address'}"
            )
            lines.append("-" * 60)
            for port in sorted(by_port.keys()):
                for entry in by_port[port]:
                    lines.append(
                        f"{entry['port']:>6} {entry['protocol']:<8} "
                        f"{entry['bind_type']:<10} {entry['ip']}"
                    )

            if issues:
                lines.append("")
                lines.append(f"Issues ({len(issues)}):")
                lines.append(
                    f"{'Severity':<10} {'Type':<15} {'Port':>6} {'Message'}"
                )
                lines.append("-" * 60)
                for issue in issues:
                    lines.append(
                        f"{issue['severity']:<10} {issue['type']:<15} "
                        f"{issue['port']:>6} {issue['message']}"
                    )

            print("\n".join(lines))
    else:
        output.render(opts.format, "Listening Port Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    output.set_summary(
        f"ports={len(all_listening)}, issues={len(issues)}"
    )

    return 1 if issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
