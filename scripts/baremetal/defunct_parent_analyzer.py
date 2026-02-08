#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [health, process, orphan, reparent]
#   brief: Analyze processes orphaned or reparented to init (PID 1)

"""
Analyze processes with defunct or reparented parent relationships.

This script identifies processes that have been orphaned (reparented to init/systemd)
which may indicate their original parent process crashed or was killed unexpectedly.
This is different from zombie processes - these are live processes whose parent died.

Useful for detecting:
- Service crashes that left child workers running
- Application instability patterns
- Resource leaks from orphaned processes
- Long-running processes that lost supervision

Exit codes:
    0: No orphaned processes with issues detected
    1: Orphaned processes found that may need attention
    2: Usage error or unable to read process information
"""

import argparse
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


# Processes that are expected to be reparented (not concerning)
# These are daemons/services normally started by init
EXPECTED_REPARENTED = {
    # System daemons
    "sshd",
    "cron",
    "crond",
    "rsyslogd",
    "systemd-journal",
    "systemd-logind",
    "systemd-udevd",
    "dbus-daemon",
    "polkitd",
    "NetworkManager",
    "wpa_supplicant",
    "avahi-daemon",
    # Web servers
    "nginx",
    "apache2",
    "httpd",
    "caddy",
    "haproxy",
    # Databases
    "postgres",
    "mysqld",
    "mariadbd",
    "mongod",
    "redis-server",
    # Container runtime
    "dockerd",
    "containerd",
    "kubelet",
    "podman",
    # Session/terminal
    "sshfs",
    "screen",
    "tmux",
    "ssh-agent",
    "gpg-agent",
    # Display managers
    "gdm",
    "lightdm",
    "sddm",
    "login",
    "agetty",
    "getty",
}


def get_boot_time(context: Context) -> int | None:
    """Get system boot time in seconds since epoch from /proc/stat."""
    try:
        content = context.read_file("/proc/stat")
        for line in content.split("\n"):
            if line.startswith("btime"):
                return int(line.split()[1])
    except (IOError, ValueError, IndexError, FileNotFoundError):
        pass
    return None


def parse_proc_stat(stat_line: str) -> dict | None:
    """Parse a /proc/[pid]/stat line."""
    try:
        first_paren = stat_line.index("(")
        last_paren = stat_line.rindex(")")

        comm = stat_line[first_paren + 1 : last_paren]
        rest = stat_line[last_paren + 2 :].split()

        if len(rest) < 20:
            return None

        return {
            "pid": int(stat_line[:first_paren].strip()),
            "comm": comm,
            "state": rest[0],
            "ppid": int(rest[1]),
            "starttime": int(rest[19]),
        }
    except (ValueError, IndexError):
        return None


def parse_proc_status(status_content: str) -> dict:
    """Parse /proc/[pid]/status for additional info."""
    result = {"uid": None, "threads": 1}
    for line in status_content.split("\n"):
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    result["uid"] = int(parts[1])
                except ValueError:
                    pass
        elif line.startswith("Threads:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    result["threads"] = int(parts[1])
                except ValueError:
                    pass
    return result


def is_expected_reparented(comm: str) -> bool:
    """Check if process name is expected to have ppid=1."""
    # Direct match
    if comm in EXPECTED_REPARENTED:
        return True

    # Check base name (before any suffix)
    comm_base = comm.split("/")[0].split("-")[0]
    if comm_base in EXPECTED_REPARENTED:
        return True

    # Common daemon pattern: ends with 'd' and is longer than 3 chars
    if len(comm) > 3 and comm.endswith("d"):
        return True

    return False


def format_age(seconds: float | None) -> str:
    """Format age in human-readable form."""
    if seconds is None:
        return "unknown"
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds / 60)}m"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    else:
        return f"{seconds / 86400:.1f}d"


def analyze_orphans(
    context: Context,
    min_age_seconds: int = 0,
    include_expected: bool = False,
    user_filter: str | None = None,
) -> list[dict]:
    """Find processes that have been reparented to init (PID 1)."""
    orphans = []
    boot_time = get_boot_time(context)
    now = datetime.now(timezone.utc).timestamp()
    clock_ticks = 100  # Standard Linux value

    # Get list of PIDs from /proc
    try:
        proc_entries = context.glob("[0-9]*", root="/proc")
    except (IOError, OSError):
        return orphans

    for entry in proc_entries:
        try:
            pid = int(entry.split("/")[-1])
        except ValueError:
            continue

        if pid == 1:
            continue

        stat_path = f"/proc/{pid}/stat"
        try:
            stat_content = context.read_file(stat_path)
        except (FileNotFoundError, IOError):
            continue

        parsed = parse_proc_stat(stat_content)
        if not parsed:
            continue

        # Check if reparented to init (ppid == 1)
        if parsed["ppid"] != 1:
            continue

        # Skip expected reparented processes unless requested
        if not include_expected and is_expected_reparented(parsed["comm"]):
            continue

        # Calculate age
        age_seconds = None
        start_time_iso = None
        if boot_time:
            start_epoch = boot_time + (parsed["starttime"] / clock_ticks)
            age_seconds = now - start_epoch
            start_time_iso = datetime.fromtimestamp(
                start_epoch, tz=timezone.utc
            ).isoformat()

            # Check age filter
            if age_seconds < min_age_seconds:
                continue

        # Get cmdline
        cmdline = ""
        try:
            cmdline_raw = context.read_file(f"/proc/{pid}/cmdline")
            cmdline = cmdline_raw.replace("\x00", " ").strip()
            if len(cmdline) > 200:
                cmdline = cmdline[:200] + "..."
        except (FileNotFoundError, IOError):
            pass

        # Skip kernel threads (empty cmdline)
        if not cmdline:
            continue

        # Get status info
        status_info = {"uid": None, "threads": 1}
        try:
            status_content = context.read_file(f"/proc/{pid}/status")
            status_info = parse_proc_status(status_content)
        except (FileNotFoundError, IOError):
            pass

        # Determine username (simplified - just use UID as string for testing)
        username = str(status_info["uid"]) if status_info["uid"] is not None else "unknown"

        # Apply user filter
        if user_filter and username != user_filter:
            continue

        # Identify issues
        issues = []
        issues.append(
            {
                "severity": "WARNING",
                "type": "orphaned_process",
                "message": "Process was reparented to init (original parent likely crashed)",
            }
        )

        if age_seconds and age_seconds > 86400:  # > 1 day
            issues.append(
                {
                    "severity": "INFO",
                    "type": "long_running_orphan",
                    "message": f"Orphaned process running for {age_seconds / 86400:.1f} days",
                }
            )

        orphan_info = {
            "pid": pid,
            "comm": parsed["comm"],
            "state": parsed["state"],
            "cmdline": cmdline,
            "uid": status_info["uid"],
            "user": username,
            "age_seconds": int(age_seconds) if age_seconds else None,
            "age_human": format_age(age_seconds),
            "start_time": start_time_iso,
            "issues": issues,
        }

        orphans.append(orphan_info)

    # Sort by age (oldest first)
    orphans.sort(key=lambda x: -(x["age_seconds"] or 0))

    return orphans


def generate_summary(orphans: list[dict]) -> dict:
    """Generate summary statistics."""
    summary = {
        "total_orphans": len(orphans),
        "with_issues": sum(1 for o in orphans if o["issues"]),
        "long_running": sum(1 for o in orphans if (o["age_seconds"] or 0) > 86400),
        "by_user": {},
        "by_process": {},
    }

    for orphan in orphans:
        user = orphan["user"] or "unknown"
        comm = orphan["comm"]

        summary["by_user"][user] = summary["by_user"].get(user, 0) + 1
        summary["by_process"][comm] = summary["by_process"].get(comm, 0) + 1

    return summary


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = orphans with issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze processes orphaned/reparented to init (PID 1)"
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
        help="Show detailed process information including command line",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only produce output if orphaned processes with issues are found",
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Include all orphaned processes, even expected ones",
    )
    parser.add_argument(
        "-u",
        "--user",
        help="Only show processes owned by specified user",
    )
    parser.add_argument(
        "--min-age",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Only show processes orphaned for at least this many seconds",
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if opts.min_age < 0:
        output.error("--min-age must be non-negative")
        return 2

    # Analyze orphaned processes
    try:
        orphans = analyze_orphans(
            context,
            min_age_seconds=opts.min_age,
            include_expected=opts.all,
            user_filter=opts.user,
        )
    except Exception as e:
        output.error(f"Failed to analyze processes: {e}")
        return 2

    # Generate summary
    summary = generate_summary(orphans)
    has_issues = summary["with_issues"] > 0

    # Build result
    result = {"summary": summary, "orphans": orphans}
    output.emit(result)

    # Handle warn-only mode
    if opts.warn_only and not has_issues:
        return 0

    # Output results
    if opts.format == "table":
        _output_table(orphans, summary)
    else:
        output.render(opts.format, "Defunct Parent Analyzer", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    if has_issues:
        output.set_summary(f"Found {summary['with_issues']} orphaned process(es) with issues")
    else:
        output.set_summary("No orphaned processes with issues detected")

    return 1 if has_issues else 0


def _output_table(orphans: list[dict], summary: dict) -> None:
    """Output results in table format."""
    print("=" * 90)
    print("ORPHANED PROCESS REPORT")
    print("=" * 90)
    print()

    # Summary table
    print(f"{'Metric':<40} {'Count':<10}")
    print("-" * 50)
    print(f"{'Total orphaned processes':<40} {summary['total_orphans']:<10}")
    print(f"{'Processes with issues':<40} {summary['with_issues']:<10}")
    print(f"{'Long-running (>1 day)':<40} {summary['long_running']:<10}")
    print()

    if orphans:
        print("=" * 90)
        print(
            f"{'PID':<8} {'Process':<20} {'User':<12} {'Age':<10} "
            f"{'State':<6} {'Issues':<20}"
        )
        print("-" * 90)

        for orphan in orphans:
            issue_count = len(orphan["issues"])
            issue_str = f"{issue_count} issue(s)" if issue_count else "OK"
            user = (orphan["user"] or "N/A")[:12]
            comm = orphan["comm"][:20]

            print(
                f"{orphan['pid']:<8} {comm:<20} {user:<12} "
                f"{orphan['age_human']:<10} {orphan['state']:<6} {issue_str:<20}"
            )


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
