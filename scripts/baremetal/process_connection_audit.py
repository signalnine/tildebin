#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [network, audit, connections, process]
#   brief: Audit active network connections per process on baremetal systems

"""
Audit active network connections per process on baremetal systems.

This script analyzes /proc/net/tcp and /proc/net/tcp6 to identify all ESTABLISHED,
SYN_SENT, and other non-LISTEN connections with their owning processes. It helps:
- Identify which processes have active outbound connections
- Detect processes with excessive connection counts
- Find unexpected outbound connections (security auditing)
- Troubleshoot connectivity issues by mapping connections to processes
- Audit network behavior of applications

Unlike listening port monitors, this script focuses on ACTIVE connections to show
what your processes are actually communicating with.

Exit codes:
    0: No issues detected
    1: Processes exceed connection thresholds or unexpected connections found
    2: Missing required /proc files or usage error
"""

import argparse
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

# States to include (exclude LISTEN)
ACTIVE_STATES = {"01", "02", "03", "04", "05", "06", "08", "09", "0B"}


def hex_to_ip(hex_str: str) -> str:
    """Convert hex IP address to dotted decimal notation."""
    if len(hex_str) == 8:
        # IPv4 - little-endian byte order
        parts = [str(int(hex_str[i : i + 2], 16)) for i in range(6, -1, -2)]
        return ".".join(parts)
    elif len(hex_str) == 32:
        # IPv6
        parts = []
        for i in range(0, 32, 8):
            word = hex_str[i : i + 8]
            reversed_word = "".join([word[j : j + 2] for j in range(6, -1, -2)])
            parts.append(reversed_word[:4])
            parts.append(reversed_word[4:])
        ip = ":".join(parts)
        if ip == "0000:0000:0000:0000:0000:0000:0000:0000":
            return "::"
        if ip == "0000:0000:0000:0000:0000:0000:0000:0001":
            return "::1"
        if ip.startswith("0000:0000:0000:0000:0000:ffff:"):
            ipv4_hex = ip.replace(":", "")[-8:]
            parts = [str(int(ipv4_hex[i : i + 2], 16)) for i in range(0, 8, 2)]
            return "::ffff:" + ".".join(parts)
        return ip
    return hex_str


def parse_connections(content: str, protocol: str) -> list[dict]:
    """Parse /proc/net socket content for active connections."""
    connections = []
    lines = content.split("\n")

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue

        state_hex = parts[3]
        if state_hex not in ACTIVE_STATES:
            continue

        state_name = TCP_STATES.get(state_hex, "UNKNOWN")

        # Extract local address and port
        local_parts = parts[1].split(":")
        local_ip = hex_to_ip(local_parts[0])
        local_port = int(local_parts[1], 16)

        # Extract remote address and port
        remote_parts = parts[2].split(":")
        remote_ip = hex_to_ip(remote_parts[0])
        remote_port = int(remote_parts[1], 16)

        # Get inode for process lookup
        inode = parts[9]

        connections.append(
            {
                "protocol": protocol,
                "state": state_name,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "inode": inode,
            }
        )

    return connections


def build_inode_to_process_map(context: Context) -> dict[str, dict]:
    """Build a mapping of socket inodes to process info."""
    inode_map: dict[str, dict] = {}

    try:
        proc_entries = context.glob("[0-9]*", root="/proc")
    except (IOError, OSError):
        return inode_map

    for entry in proc_entries:
        try:
            pid = int(entry.split("/")[-1])
        except ValueError:
            continue

        fd_dir = f"/proc/{pid}/fd"
        try:
            # Try to glob fd entries
            fd_entries = context.glob("*", root=fd_dir)
        except (IOError, OSError):
            continue

        for fd_path in fd_entries:
            try:
                # Read symlink target
                link = context.readlink(fd_path)
                if not link:
                    continue
                if link.startswith("socket:["):
                    inode = link[8:-1]
                    if inode not in inode_map:
                        # Get process name
                        name = "-"
                        try:
                            name = context.read_file(f"/proc/{pid}/comm").strip()
                        except (FileNotFoundError, IOError):
                            pass

                        cmdline = name
                        try:
                            cmdline_raw = context.read_file(f"/proc/{pid}/cmdline")
                            cmdline = cmdline_raw.replace("\x00", " ").strip()
                            if len(cmdline) > 100:
                                cmdline = cmdline[:97] + "..."
                            if not cmdline:
                                cmdline = name
                        except (FileNotFoundError, IOError):
                            pass

                        inode_map[inode] = {
                            "pid": pid,
                            "name": name,
                            "cmdline": cmdline,
                        }
            except (FileNotFoundError, IOError):
                continue

    return inode_map


def analyze_connections(
    connections: list[dict], max_per_process: int, max_to_single_host: int
) -> list[dict]:
    """Analyze connections and detect potential issues."""
    issues = []

    # Group by process
    by_process: dict[tuple, list[dict]] = defaultdict(list)
    for conn in connections:
        proc = conn.get("process", {})
        key = (proc.get("pid"), proc.get("name", "-"))
        by_process[key].append(conn)

    for (pid, name), conns in by_process.items():
        if len(conns) > max_per_process:
            issues.append(
                {
                    "severity": "warning",
                    "type": "excessive_connections",
                    "pid": pid,
                    "process": name,
                    "count": len(conns),
                    "threshold": max_per_process,
                    "message": f"Process {name} (PID {pid}) has {len(conns)} connections "
                    f"(threshold: {max_per_process})",
                }
            )

        # Check connections to single remote host
        remote_counts: dict[str, int] = defaultdict(int)
        for conn in conns:
            remote_counts[conn["remote_ip"]] += 1

        for remote_ip, count in remote_counts.items():
            if count > max_to_single_host:
                issues.append(
                    {
                        "severity": "info",
                        "type": "many_to_single_host",
                        "pid": pid,
                        "process": name,
                        "remote_ip": remote_ip,
                        "count": count,
                        "threshold": max_to_single_host,
                        "message": f"Process {name} has {count} connections to {remote_ip}",
                    }
                )

    return issues


def get_process_summary(connections: list[dict]) -> list[dict]:
    """Generate per-process connection summary."""
    by_process: dict[tuple, dict] = defaultdict(
        lambda: {
            "connections": [],
            "remote_hosts": set(),
            "remote_ports": set(),
            "states": defaultdict(int),
        }
    )

    for conn in connections:
        proc = conn.get("process", {})
        key = (proc.get("pid"), proc.get("name", "-"))
        summary = by_process[key]
        summary["connections"].append(conn)
        summary["remote_hosts"].add(conn["remote_ip"])
        summary["remote_ports"].add(conn["remote_port"])
        summary["states"][conn["state"]] += 1
        summary["pid"] = proc.get("pid")
        summary["name"] = proc.get("name", "-")
        summary["cmdline"] = proc.get("cmdline", "")

    result = []
    for key, summary in sorted(
        by_process.items(), key=lambda x: -len(x[1]["connections"])
    ):
        result.append(
            {
                "pid": summary["pid"],
                "name": summary["name"],
                "cmdline": summary["cmdline"],
                "connection_count": len(summary["connections"]),
                "unique_remote_hosts": len(summary["remote_hosts"]),
                "unique_remote_ports": len(summary["remote_ports"]),
                "state_breakdown": dict(summary["states"]),
                "top_remotes": _get_top_remotes(summary["connections"], 5),
            }
        )

    return result


def _get_top_remotes(connections: list[dict], limit: int) -> list[dict]:
    """Get top remote hosts by connection count."""
    counts: dict[str, int] = defaultdict(int)
    for conn in connections:
        key = f"{conn['remote_ip']}:{conn['remote_port']}"
        counts[key] += 1

    return [
        {"remote": k, "count": v}
        for k, v in sorted(counts.items(), key=lambda x: -x[1])[:limit]
    ]


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit active network connections per process"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show individual connections instead of summary",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only output if issues are detected",
    )
    parser.add_argument(
        "--max-per-process",
        type=int,
        default=1000,
        metavar="N",
        help="Alert if a process has more than N connections (default: 1000)",
    )
    parser.add_argument(
        "--max-to-single-host",
        type=int,
        default=100,
        metavar="N",
        help="Alert if process has >N connections to single host (default: 100)",
    )
    parser.add_argument(
        "--process",
        metavar="NAME",
        help="Filter to connections owned by specific process name",
    )
    parser.add_argument(
        "--pid",
        type=int,
        metavar="PID",
        help="Filter to connections owned by specific PID",
    )
    parser.add_argument(
        "--remote-port",
        type=int,
        metavar="PORT",
        help="Filter to connections to specific remote port",
    )
    parser.add_argument(
        "--remote-ip",
        metavar="IP",
        help="Filter to connections to specific remote IP",
    )
    parser.add_argument(
        "--state",
        choices=list(TCP_STATES.values()),
        help="Filter to specific TCP state",
    )
    parser.add_argument(
        "--exclude-loopback",
        action="store_true",
        help="Exclude connections to localhost/127.0.0.1/::1",
    )

    opts = parser.parse_args(args)

    # Collect connections from TCP files
    all_connections = []

    for file_path, protocol in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp6"),
    ]:
        try:
            content = context.read_file(file_path)
            connections = parse_connections(content, protocol)
            all_connections.extend(connections)
        except FileNotFoundError:
            output.error(f"Cannot read {file_path}")
            output.error("This script requires access to /proc/net files")
            return 2
        except IOError as e:
            output.error(f"Error reading {file_path}: {e}")
            return 2

    # Build inode-to-process map
    inode_map = build_inode_to_process_map(context)

    # Look up process info for each connection
    for conn in all_connections:
        conn["process"] = inode_map.get(
            conn["inode"], {"pid": None, "name": "-", "cmdline": ""}
        )
        del conn["inode"]

    # Apply filters
    if opts.process:
        all_connections = [
            c
            for c in all_connections
            if opts.process.lower() in c["process"].get("name", "").lower()
        ]

    if opts.pid:
        all_connections = [
            c for c in all_connections if c["process"].get("pid") == opts.pid
        ]

    if opts.remote_port:
        all_connections = [
            c for c in all_connections if c["remote_port"] == opts.remote_port
        ]

    if opts.remote_ip:
        all_connections = [
            c for c in all_connections if c["remote_ip"] == opts.remote_ip
        ]

    if opts.state:
        all_connections = [c for c in all_connections if c["state"] == opts.state]

    if opts.exclude_loopback:
        loopback = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}
        all_connections = [
            c for c in all_connections if c["remote_ip"] not in loopback
        ]

    # Generate process summary
    process_summary = get_process_summary(all_connections)

    # Analyze for issues
    issues = analyze_connections(
        all_connections, opts.max_per_process, opts.max_to_single_host
    )

    # Build result for output
    state_counts: dict[str, int] = defaultdict(int)
    for conn in all_connections:
        state_counts[conn["state"]] += 1

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "process_summary": process_summary,
        "state_counts": dict(state_counts),
        "issues": issues,
        "summary": {
            "total_connections": len(all_connections),
            "total_processes": len(process_summary),
            "established": state_counts.get("ESTABLISHED", 0),
            "time_wait": state_counts.get("TIME_WAIT", 0),
            "close_wait": state_counts.get("CLOSE_WAIT", 0),
        },
        "has_issues": len(issues) > 0,
    }

    output.emit(result)

    # Handle warn-only mode
    if opts.warn_only and not issues:
        return 0

    # Output results
    if opts.format == "table":
        _output_table(all_connections, process_summary, issues, opts.verbose, opts.warn_only)
    else:
        output.render(opts.format, "Process Connection Audit", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    if issues:
        output.set_summary(f"Found {len(issues)} connection issue(s)")
    else:
        output.set_summary(
            f"Total: {len(all_connections)} active connections across "
            f"{len(process_summary)} processes"
        )

    return 1 if issues else 0



def _output_table(
    connections: list[dict],
    process_summary: list[dict],
    issues: list[dict],
    verbose: bool,
    warn_only: bool,
) -> None:
    """Output results in table format."""
    if not warn_only or issues:
        if verbose:
            print(
                f"{'PID':>8} {'Process':<15} {'State':<12} {'Local':<22} {'Remote'}"
            )
            print("-" * 90)
            for conn in sorted(
                connections,
                key=lambda x: (x.get("process", {}).get("name", ""), x["state"]),
            )[:50]:
                proc = conn.get("process", {})
                pid = str(proc.get("pid", "-"))
                name = proc.get("name", "-")[:15]
                local = f"{conn['local_ip']}:{conn['local_port']}"
                remote = f"{conn['remote_ip']}:{conn['remote_port']}"
                print(
                    f"{pid:>8} {name:<15} {conn['state']:<12} {local:<22} {remote}"
                )

            if len(connections) > 50:
                print(f"  ... and {len(connections) - 50} more connections")
        else:
            print(f"{'PID':>8} {'Process':<20} {'Connections':>12} {'Unique Hosts':>12}")
            print("-" * 55)
            for proc in process_summary:
                pid = str(proc["pid"]) if proc["pid"] else "-"
                print(
                    f"{pid:>8} {proc['name']:<20} {proc['connection_count']:>12} "
                    f"{proc['unique_remote_hosts']:>12}"
                )

    if issues:
        print(f"\nIssues ({len(issues)}):")
        for issue in issues:
            print(f"  [{issue['severity'].upper()}] {issue['message']}")


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
