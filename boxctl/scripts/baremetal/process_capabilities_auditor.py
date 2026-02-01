#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [security, capabilities, audit, process]
#   brief: Audit Linux process capabilities for security monitoring

"""
Audit Linux process capabilities for security monitoring.

Scans running processes to identify those with elevated capabilities beyond
standard user permissions. Essential for security audits in large-scale
baremetal environments where privilege escalation risks must be monitored.

Capabilities checked include:
- CAP_SYS_ADMIN (broad system administration)
- CAP_NET_ADMIN (network configuration)
- CAP_NET_RAW (raw socket access)
- CAP_DAC_OVERRIDE (bypass file permissions)
- CAP_SETUID/CAP_SETGID (change process credentials)
- And all other Linux capabilities

Exit codes:
    0: No unexpected privileged processes found
    1: Processes with elevated capabilities detected
    2: Usage error or missing dependency
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


# Linux capability definitions (from linux/capability.h)
CAPABILITIES = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

# High-risk capabilities that warrant attention
HIGH_RISK_CAPS = {
    "CAP_SYS_ADMIN",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_SETUID",
    "CAP_SETGID",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_CHOWN",
    "CAP_FOWNER",
    "CAP_SETPCAP",
    "CAP_BPF",
}


def parse_capability_hex(hex_str: str) -> list[str]:
    """Parse capability hex string to list of capability names."""
    try:
        cap_bits = int(hex_str, 16)
    except ValueError:
        return []

    caps = []
    for bit, name in CAPABILITIES.items():
        if cap_bits & (1 << bit):
            caps.append(name)

    return caps


def parse_status_file(content: str) -> dict:
    """Parse /proc/[pid]/status content into a dict."""
    result = {}
    for line in content.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def get_process_info(
    pid: int, status_content: str, comm: str | None = None, cmdline: str | None = None
) -> dict | None:
    """Parse process info from status content."""
    try:
        status = parse_status_file(status_content)

        # Get name
        name = status.get("Name", comm or "unknown")

        # Get UID
        uid = None
        uid_line = status.get("Uid", "")
        if uid_line:
            parts = uid_line.split()
            if parts:
                uid = int(parts[0])

        # Parse capabilities
        cap_eff = parse_capability_hex(status.get("CapEff", "0"))
        cap_prm = parse_capability_hex(status.get("CapPrm", "0"))
        cap_inh = parse_capability_hex(status.get("CapInh", "0"))
        cap_bnd = parse_capability_hex(status.get("CapBnd", "0"))
        cap_amb = parse_capability_hex(status.get("CapAmb", "0"))

        # Resolve username
        username = str(uid) if uid is not None else "unknown"
        if uid is not None:
            try:
                import pwd

                username = pwd.getpwuid(uid).pw_name
            except (KeyError, ImportError):
                pass

        return {
            "pid": pid,
            "comm": name,
            "cmdline": cmdline or name,
            "uid": uid,
            "user": username,
            "cap_effective": cap_eff,
            "cap_permitted": cap_prm,
            "cap_inheritable": cap_inh,
            "cap_bounding": cap_bnd,
            "cap_ambient": cap_amb,
        }
    except (ValueError, IndexError, KeyError):
        return None


def analyze_process(
    proc_info: dict, include_root: bool = False, cap_filter: str | None = None
) -> dict | None:
    """Analyze process capabilities and return findings."""
    if proc_info is None:
        return None

    # Skip root processes unless explicitly included
    if not include_root and proc_info.get("uid") == 0:
        return None

    # Get effective capabilities
    effective_caps = set(proc_info.get("cap_effective", []))

    # If no capabilities, skip
    if not effective_caps:
        return None

    # Filter by specific capability if requested
    if cap_filter:
        if cap_filter not in effective_caps:
            return None

    # Identify high-risk capabilities
    high_risk = effective_caps & HIGH_RISK_CAPS

    return {
        "pid": proc_info["pid"],
        "comm": proc_info["comm"],
        "cmdline": proc_info.get("cmdline", proc_info["comm"]),
        "uid": proc_info.get("uid"),
        "user": proc_info.get("user", "unknown"),
        "effective_caps": sorted(effective_caps),
        "permitted_caps": sorted(proc_info.get("cap_permitted", [])),
        "inheritable_caps": sorted(proc_info.get("cap_inheritable", [])),
        "ambient_caps": sorted(proc_info.get("cap_ambient", [])),
        "high_risk_caps": sorted(high_risk),
        "cap_count": len(effective_caps),
        "high_risk_count": len(high_risk),
    }


def collect_privileged_processes(
    context: Context,
    include_root: bool = False,
    cap_filter: str | None = None,
    user_filter: str | None = None,
    comm_filter: str | None = None,
    high_risk_only: bool = False,
) -> list[dict]:
    """Collect all processes with elevated capabilities."""
    results = []

    # Get list of PIDs from /proc
    try:
        proc_entries = context.glob("[0-9]*", root="/proc")
    except (IOError, OSError):
        return results

    for entry in proc_entries:
        try:
            pid = int(entry.split("/")[-1])
        except ValueError:
            continue

        # Read status file
        try:
            status_content = context.read_file(f"/proc/{pid}/status")
        except (FileNotFoundError, IOError):
            continue

        # Try to get comm and cmdline
        comm = None
        cmdline = None
        try:
            comm = context.read_file(f"/proc/{pid}/comm").strip()
        except (FileNotFoundError, IOError):
            pass
        try:
            cmdline_raw = context.read_file(f"/proc/{pid}/cmdline")
            cmdline = cmdline_raw.replace("\x00", " ").strip()
            if len(cmdline) > 200:
                cmdline = cmdline[:197] + "..."
        except (FileNotFoundError, IOError):
            pass

        proc_info = get_process_info(pid, status_content, comm, cmdline)
        if proc_info is None:
            continue

        # Apply user filter
        if user_filter and proc_info.get("user") != user_filter:
            continue

        # Apply comm filter
        if comm_filter and comm_filter.lower() not in proc_info.get("comm", "").lower():
            continue

        analysis = analyze_process(proc_info, include_root, cap_filter)
        if analysis is None:
            continue

        # Apply high-risk only filter
        if high_risk_only and not analysis["high_risk_caps"]:
            continue

        results.append(analysis)

    # Sort by high-risk count, then total cap count
    results.sort(key=lambda x: (-x["high_risk_count"], -x["cap_count"]))

    return results


def generate_summary(processes: list[dict]) -> dict:
    """Generate summary statistics."""
    if not processes:
        return {
            "total_privileged_processes": 0,
            "processes_with_high_risk": 0,
            "unique_capabilities_found": 0,
            "unique_high_risk_caps": 0,
            "most_common_caps": [],
        }

    all_caps = []
    high_risk_caps = []
    for p in processes:
        all_caps.extend(p["effective_caps"])
        high_risk_caps.extend(p["high_risk_caps"])

    # Count capability frequency
    cap_counts: dict[str, int] = {}
    for cap in all_caps:
        cap_counts[cap] = cap_counts.get(cap, 0) + 1

    most_common = sorted(cap_counts.items(), key=lambda x: -x[1])[:10]

    return {
        "total_privileged_processes": len(processes),
        "processes_with_high_risk": sum(1 for p in processes if p["high_risk_caps"]),
        "unique_capabilities_found": len(set(all_caps)),
        "unique_high_risk_caps": len(set(high_risk_caps)),
        "most_common_caps": [{"cap": cap, "count": count} for cap, count in most_common],
    }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no high-risk processes, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit Linux process capabilities for security monitoring"
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
        help="Show detailed information including command lines",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only produce output if high-risk capabilities found",
    )
    parser.add_argument(
        "--include-root",
        action="store_true",
        help="Include root processes (uid 0) in analysis",
    )
    parser.add_argument(
        "--high-risk-only",
        action="store_true",
        help="Only show processes with high-risk capabilities",
    )
    parser.add_argument(
        "--cap",
        metavar="CAPABILITY",
        help="Filter by specific capability (e.g., CAP_NET_RAW)",
    )
    parser.add_argument("-u", "--user", help="Filter by username")
    parser.add_argument("-c", "--comm", help="Filter by process name pattern")
    parser.add_argument(
        "--list-caps",
        action="store_true",
        help="List all known capabilities and exit",
    )

    opts = parser.parse_args(args)

    # Handle --list-caps
    if opts.list_caps:
        print("Linux Capabilities:")
        print("-" * 50)
        for bit, name in sorted(CAPABILITIES.items()):
            risk = " [HIGH RISK]" if name in HIGH_RISK_CAPS else ""
            print(f"  {bit:2d}: {name}{risk}")
        return 0

    # Validate capability filter
    cap_filter = None
    if opts.cap:
        cap_upper = opts.cap.upper()
        if not cap_upper.startswith("CAP_"):
            cap_upper = "CAP_" + cap_upper
        if cap_upper not in CAPABILITIES.values():
            output.error(f"Unknown capability '{opts.cap}'")
            output.error("Use --list-caps to see available capabilities")
            return 2
        cap_filter = cap_upper

    # Collect data
    try:
        processes = collect_privileged_processes(
            context,
            include_root=opts.include_root,
            cap_filter=cap_filter,
            user_filter=opts.user,
            comm_filter=opts.comm,
            high_risk_only=opts.high_risk_only,
        )
    except Exception as e:
        output.error(f"Failed to scan processes: {e}")
        return 2

    summary = generate_summary(processes)

    # Handle warn-only
    if opts.warn_only and summary["processes_with_high_risk"] == 0:
        return 0

    # Output results
    if opts.format == "json":
        _output_json(processes, summary)
    elif opts.format == "table":
        _output_table(processes, summary, opts.warn_only)
    else:
        _output_plain(processes, summary, opts.verbose, opts.warn_only)

    # Set summary
    if summary["processes_with_high_risk"] > 0:
        output.set_summary(
            f"Found {summary['processes_with_high_risk']} process(es) with high-risk capabilities"
        )
    else:
        output.set_summary("No processes with high-risk capabilities found")

    # Exit code based on findings
    return 1 if summary["processes_with_high_risk"] > 0 else 0


def _output_plain(
    processes: list[dict], summary: dict, verbose: bool, warn_only: bool
) -> None:
    """Output results in plain text format."""
    if warn_only and summary["processes_with_high_risk"] == 0:
        print("No high-risk privileged processes found.")
        return

    print("Process Capabilities Audit")
    print("=" * 70)
    print(f"Privileged processes found: {summary['total_privileged_processes']}")
    print(f"Processes with high-risk caps: {summary['processes_with_high_risk']}")
    print(f"Unique capabilities found: {summary['unique_capabilities_found']}")
    print()

    if summary["most_common_caps"]:
        print("Most common capabilities:")
        for item in summary["most_common_caps"][:5]:
            risk_marker = " [HIGH RISK]" if item["cap"] in HIGH_RISK_CAPS else ""
            print(f"  {item['cap']}: {item['count']} processes{risk_marker}")
        print()

    if processes:
        print("Privileged Processes:")
        print("-" * 70)

        for proc in processes:
            risk_str = ""
            if proc["high_risk_caps"]:
                risk_str = f" [!] HIGH RISK: {len(proc['high_risk_caps'])} caps"

            print(f"PID {proc['pid']}: {proc['comm']} (user: {proc['user']}){risk_str}")
            caps_str = ", ".join(proc["effective_caps"][:5])
            print(f"  Effective caps ({proc['cap_count']}): {caps_str}")
            if len(proc["effective_caps"]) > 5:
                print(f"    ... and {len(proc['effective_caps']) - 5} more")

            if verbose:
                if proc["cmdline"] and proc["cmdline"] != proc["comm"]:
                    print(f"  Command: {proc['cmdline'][:60]}...")
                if proc["high_risk_caps"]:
                    print(f"  High-risk: {', '.join(proc['high_risk_caps'])}")

            print()


def _output_json(processes: list[dict], summary: dict) -> None:
    """Output results in JSON format."""
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "processes": processes,
        "high_risk_capabilities": sorted(HIGH_RISK_CAPS),
    }
    print(json.dumps(result, indent=2))


def _output_table(processes: list[dict], summary: dict, warn_only: bool) -> None:
    """Output results in table format."""
    if warn_only and summary["processes_with_high_risk"] == 0:
        print("No high-risk privileged processes found.")
        return

    print("=" * 90)
    print("PROCESS CAPABILITIES AUDIT")
    print("=" * 90)
    print()

    print(f"{'Metric':<40} {'Value':<20}")
    print("-" * 60)
    print(f"{'Privileged processes':<40} {summary['total_privileged_processes']:<20}")
    print(
        f"{'With high-risk capabilities':<40} {summary['processes_with_high_risk']:<20}"
    )
    print(f"{'Unique capabilities found':<40} {summary['unique_capabilities_found']:<20}")
    print()

    if processes:
        print("=" * 90)
        print(
            f"{'PID':<8} {'Process':<20} {'User':<12} {'Caps':<6} {'Risk':<6} {'High-Risk Capabilities'}"
        )
        print("-" * 90)

        for proc in processes:
            high_risk_str = ", ".join(proc["high_risk_caps"][:3])
            if len(proc["high_risk_caps"]) > 3:
                high_risk_str += f"... (+{len(proc['high_risk_caps']) - 3})"

            print(
                f"{proc['pid']:<8} {proc['comm'][:20]:<20} {proc['user'][:12]:<12} "
                f"{proc['cap_count']:<6} {proc['high_risk_count']:<6} {high_risk_str}"
            )


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
