#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [health, process, signal, monitoring]
#   brief: Monitor process signal dispositions on baremetal systems

"""
Monitor process signal dispositions on baremetal systems.

Detects processes with potentially problematic signal handling configurations:
- Processes ignoring SIGTERM (won't gracefully shut down)
- Processes blocking critical signals (may not respond to shutdown requests)
- Long-running processes with unusual signal masks

This is useful for:
- Pre-deployment checks to ensure services will gracefully terminate
- Detecting misbehaving applications that won't respond to signals
- Identifying potential issues before node drains or rolling restarts
- Security auditing (processes ignoring termination signals)

Signal information is read from /proc/<pid>/status (SigBlk, SigIgn, SigCgt).

Exit codes:
    0: No processes with concerning signal dispositions found
    1: Processes with concerning signal dispositions detected
    2: Usage error or missing dependencies
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


# Signal number to name mapping (Linux x86_64)
SIGNAL_NAMES = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGUSR1",
    11: "SIGSEGV",
    12: "SIGUSR2",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
    16: "SIGSTKFLT",
    17: "SIGCHLD",
    18: "SIGCONT",
    19: "SIGSTOP",
    20: "SIGTSTP",
    21: "SIGTTIN",
    22: "SIGTTOU",
    23: "SIGURG",
    24: "SIGXCPU",
    25: "SIGXFSZ",
    26: "SIGVTALRM",
    27: "SIGPROF",
    28: "SIGWINCH",
    29: "SIGIO",
    30: "SIGPWR",
    31: "SIGSYS",
}

# Signals that are concerning if ignored
CONCERNING_IGNORED_SIGNALS = {
    15: "SIGTERM",
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
}

# Signals that are concerning if blocked
CONCERNING_BLOCKED_SIGNALS = {
    15: "SIGTERM",
    1: "SIGHUP",
    2: "SIGINT",
}

# Process names that commonly and legitimately ignore signals
EXPECTED_SIGNAL_IGNORERS = {
    "systemd",
    "init",
    "dockerd",
    "containerd",
    "runc",
    "kubelet",
    "kube-proxy",
    "crio",
    "podman",
}


def parse_signal_mask(hex_mask: str) -> set[int]:
    """Parse a signal mask from hex string to set of signal numbers."""
    try:
        mask = int(hex_mask, 16)
        signals = set()
        for signum in range(1, 65):
            if mask & (1 << (signum - 1)):
                signals.add(signum)
        return signals
    except (ValueError, TypeError):
        return set()


def get_signal_name(signum: int) -> str:
    """Get human-readable signal name."""
    return SIGNAL_NAMES.get(signum, f"SIG{signum}")


def parse_status_content(content: str) -> dict:
    """Parse /proc/[pid]/status content into a dict."""
    status = {}
    for line in content.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            status[key.strip()] = value.strip()
    return status


def get_process_signal_info(
    pid: int, status_content: str, context: Context
) -> dict | None:
    """Get signal disposition information for a process."""
    try:
        status = parse_status_content(status_content)

        # Parse signal masks
        sig_blk = parse_signal_mask(status.get("SigBlk", "0"))
        sig_ign = parse_signal_mask(status.get("SigIgn", "0"))
        sig_cgt = parse_signal_mask(status.get("SigCgt", "0"))

        # Get process name
        name = status.get("Name", "<unknown>")

        # Get PPID
        ppid = int(status.get("PPid", 0))

        # Get command line
        cmdline = f"[{name}]"
        try:
            cmdline_raw = context.read_file(f"/proc/{pid}/cmdline")
            cmdline = cmdline_raw.replace("\x00", " ").strip()
            if not cmdline:
                cmdline = f"[{name}]"
        except (FileNotFoundError, IOError):
            pass

        # Get process owner
        username = "<unknown>"
        try:
            uid_line = status.get("Uid", "")
            if uid_line:
                uid = int(uid_line.split()[0])
                try:
                    import pwd

                    username = pwd.getpwuid(uid).pw_name
                except (KeyError, ImportError):
                    username = str(uid)
        except (ValueError, IndexError):
            pass

        return {
            "pid": pid,
            "name": name,
            "cmdline": cmdline,
            "user": username,
            "ppid": ppid,
            "blocked": sig_blk,
            "ignored": sig_ign,
            "caught": sig_cgt,
        }

    except (ValueError, KeyError):
        return None


def analyze_process_signals(
    proc_info: dict, check_blocked: bool = True, check_ignored: bool = True
) -> dict:
    """Analyze signal dispositions for concerning patterns."""
    issues = []
    severity = "ok"

    name = proc_info["name"]

    # Check ignored signals
    if check_ignored:
        concerning_ignored = proc_info["ignored"] & set(CONCERNING_IGNORED_SIGNALS.keys())
        for signum in concerning_ignored:
            signame = CONCERNING_IGNORED_SIGNALS[signum]
            if signum == 15:
                if name not in EXPECTED_SIGNAL_IGNORERS:
                    issues.append(
                        {
                            "type": "ignored",
                            "signal": signame,
                            "signum": signum,
                            "severity": "high",
                            "message": f"Process ignores {signame} - will not gracefully terminate",
                        }
                    )
                    severity = "high"
            else:
                if name not in EXPECTED_SIGNAL_IGNORERS:
                    issues.append(
                        {
                            "type": "ignored",
                            "signal": signame,
                            "signum": signum,
                            "severity": "medium",
                            "message": f"Process ignores {signame}",
                        }
                    )
                    if severity != "high":
                        severity = "medium"

    # Check blocked signals
    if check_blocked:
        concerning_blocked = proc_info["blocked"] & set(CONCERNING_BLOCKED_SIGNALS.keys())
        for signum in concerning_blocked:
            signame = CONCERNING_BLOCKED_SIGNALS[signum]
            if signum == 15:
                issues.append(
                    {
                        "type": "blocked",
                        "signal": signame,
                        "signum": signum,
                        "severity": "medium",
                        "message": f"Process blocks {signame} - may delay graceful termination",
                    }
                )
                if severity == "ok":
                    severity = "medium"

    return {"has_issues": len(issues) > 0, "severity": severity, "issues": issues}


def scan_all_processes(
    context: Context,
    check_blocked: bool = True,
    check_ignored: bool = True,
    user_filter: str | None = None,
) -> list[dict]:
    """Scan all processes for signal disposition issues."""
    results = []

    try:
        proc_entries = context.glob("[0-9]*", root="/proc")
    except (IOError, OSError):
        return results

    for entry in proc_entries:
        try:
            pid = int(entry.split("/")[-1])
        except ValueError:
            continue

        try:
            status_content = context.read_file(f"/proc/{pid}/status")
        except (FileNotFoundError, IOError):
            continue

        proc_info = get_process_signal_info(pid, status_content, context)
        if proc_info is None:
            continue

        # Apply user filter
        if user_filter and proc_info["user"] != user_filter:
            continue

        # Skip kernel threads (ppid 2)
        if proc_info["ppid"] == 2:
            continue
        if proc_info["cmdline"].startswith("[") and proc_info["cmdline"].endswith("]"):
            if proc_info["ppid"] == 2 or proc_info["ppid"] == 0:
                continue

        analysis = analyze_process_signals(proc_info, check_blocked, check_ignored)

        if analysis["has_issues"]:
            proc_info["analysis"] = analysis
            results.append(proc_info)

    return results


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
        description="Monitor process signal dispositions on baremetal systems"
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
        help="Show detailed information and recommendations",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only output if issues are found",
    )
    parser.add_argument("--user", help="Only check processes owned by this user")
    parser.add_argument(
        "--no-blocked",
        action="store_true",
        help="Do not check for blocked signals",
    )
    parser.add_argument(
        "--no-ignored",
        action="store_true",
        help="Do not check for ignored signals",
    )
    parser.add_argument(
        "--high-only",
        action="store_true",
        help="Only show high severity issues (SIGTERM ignored)",
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if opts.no_blocked and opts.no_ignored:
        output.error("Cannot use both --no-blocked and --no-ignored")
        return 2

    # Scan processes
    check_blocked = not opts.no_blocked
    check_ignored = not opts.no_ignored

    try:
        results = scan_all_processes(
            context,
            check_blocked=check_blocked,
            check_ignored=check_ignored,
            user_filter=opts.user,
        )
    except Exception as e:
        output.error(f"Failed to scan processes: {e}")
        return 2

    # Filter to high severity only if requested
    if opts.high_only:
        results = [r for r in results if r["analysis"]["severity"] == "high"]

    # Handle warn-only mode
    if opts.warn_only and not results:
        return 0

    # Output results
    if opts.format == "json":
        _output_json(results)
    elif opts.format == "table":
        _output_table(results, opts.verbose)
    else:
        _output_plain(results, opts.verbose)

    # Set summary
    if results:
        high_count = len([r for r in results if r["analysis"]["severity"] == "high"])
        output.set_summary(
            f"Found {len(results)} process(es) with concerning signal dispositions "
            f"({high_count} high severity)"
        )
    else:
        output.set_summary("No processes with concerning signal dispositions found")

    return 1 if results else 0


def _output_plain(results: list[dict], verbose: bool) -> None:
    """Output in plain text format."""
    if not results:
        print("No processes with concerning signal dispositions found")
        return

    high_severity = [r for r in results if r["analysis"]["severity"] == "high"]
    medium_severity = [r for r in results if r["analysis"]["severity"] == "medium"]

    print(f"Found {len(results)} process(es) with concerning signal dispositions")
    print()

    if high_severity:
        print(f"HIGH SEVERITY ({len(high_severity)} processes - ignoring SIGTERM):")
        print("-" * 70)
        for proc in sorted(high_severity, key=lambda x: x["name"]):
            print(f"  PID {proc['pid']}: {proc['name']} (user: {proc['user']})")
            if verbose:
                print(f"    Command: {proc['cmdline'][:60]}...")
            for issue in proc["analysis"]["issues"]:
                print(f"    - {issue['message']}")
        print()

    if medium_severity:
        print(f"MEDIUM SEVERITY ({len(medium_severity)} processes):")
        print("-" * 70)
        for proc in sorted(medium_severity, key=lambda x: x["name"]):
            print(f"  PID {proc['pid']}: {proc['name']} (user: {proc['user']})")
            if verbose:
                print(f"    Command: {proc['cmdline'][:60]}...")
            for issue in proc["analysis"]["issues"]:
                print(f"    - {issue['message']}")
        print()

    if verbose:
        print("Recommendations:")
        print("- Processes ignoring SIGTERM will not gracefully shut down")
        print("- Review application signal handlers before deployments")
        print("- Consider using SIGKILL as fallback after SIGTERM timeout")
        print("- Some system services legitimately ignore signals (systemd, containerd)")


def _output_json(results: list[dict]) -> None:
    """Output in JSON format."""
    json_results = []
    for proc in results:
        proc_copy = proc.copy()
        proc_copy["blocked"] = list(proc["blocked"])
        proc_copy["ignored"] = list(proc["ignored"])
        proc_copy["caught"] = list(proc["caught"])
        proc_copy["blocked_names"] = [get_signal_name(s) for s in proc["blocked"]]
        proc_copy["ignored_names"] = [get_signal_name(s) for s in proc["ignored"]]
        json_results.append(proc_copy)

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_concerning": len(results),
        "high_severity_count": len(
            [r for r in results if r["analysis"]["severity"] == "high"]
        ),
        "medium_severity_count": len(
            [r for r in results if r["analysis"]["severity"] == "medium"]
        ),
        "processes": json_results,
    }
    print(json.dumps(result, indent=2, default=str))


def _output_table(results: list[dict], verbose: bool) -> None:
    """Output in table format."""
    if not results:
        print("+" + "-" * 60 + "+")
        print("|" + " No concerning signal dispositions found".center(60) + "|")
        print("+" + "-" * 60 + "+")
        return

    print("+" + "-" * 78 + "+")
    print("|" + f" Signal Disposition Report: {len(results)} process(es) ".center(78) + "|")
    print("+" + "-" * 78 + "+")
    print(
        f"| {'PID':<8} {'Name':<16} {'User':<12} {'Severity':<10} {'Issues':<28} |"
    )
    print("+" + "-" * 78 + "+")

    for proc in sorted(
        results, key=lambda x: (x["analysis"]["severity"] != "high", x["name"])
    ):
        severity = proc["analysis"]["severity"].upper()
        issues = ", ".join([i["signal"] for i in proc["analysis"]["issues"]])
        if len(issues) > 28:
            issues = issues[:25] + "..."
        print(
            f"| {proc['pid']:<8} {proc['name'][:16]:<16} {proc['user'][:12]:<12} "
            f"{severity:<10} {issues:<28} |"
        )

    print("+" + "-" * 78 + "+")

    if verbose:
        print()
        print("To inspect a process: cat /proc/<PID>/status | grep Sig")


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
