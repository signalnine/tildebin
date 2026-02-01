#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [health, process, age, uptime, maintenance]
#   brief: Monitor process ages to identify long-running processes

"""
Monitor process ages to identify long-running processes that may need attention.

Tracks how long processes have been running and identifies those that exceed
configurable age thresholds. Useful for detecting processes that may need
restart for security patches, identifying memory-leaking services, or finding
stale/orphaned processes.

Use cases:
- Finding services that haven't been restarted after package updates
- Identifying potentially stale or orphaned processes
- Audit of long-running daemon processes
- Pre-maintenance process inventory
- Security patch compliance verification

Exit codes:
    0: No processes exceed warning thresholds
    1: One or more processes exceed warning thresholds
    2: Usage error or unable to read process information
"""

import argparse
import json
import re
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_boot_time(context: Context) -> float | None:
    """Get system boot time from /proc/stat."""
    try:
        content = context.read_file("/proc/stat")
        for line in content.split("\n"):
            if line.startswith("btime "):
                return float(line.split()[1])
    except (IOError, ValueError, IndexError, FileNotFoundError):
        pass
    return None


def parse_proc_stat(stat_content: str) -> dict | None:
    """Parse /proc/[pid]/stat content."""
    try:
        last_paren = stat_content.rfind(")")
        if last_paren == -1:
            return None

        pid_comm = stat_content[:last_paren + 1]
        first_paren = pid_comm.index("(")
        pid = int(pid_comm[:first_paren].strip())
        comm = pid_comm[first_paren + 1 : -1]

        fields = stat_content[last_paren + 2 :].split()
        if len(fields) < 20:
            return None

        return {
            "pid": pid,
            "comm": comm,
            "state": fields[0],
            "ppid": int(fields[1]),
            "starttime": int(fields[19]),
        }
    except (ValueError, IndexError):
        return None


def parse_proc_status(status_content: str) -> dict:
    """Parse /proc/[pid]/status for UID and threads."""
    result = {"uid": None, "ppid": None, "state": None, "threads": 1}
    for line in status_content.split("\n"):
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    result["uid"] = int(parts[1])
                except ValueError:
                    pass
        elif line.startswith("PPid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    result["ppid"] = int(parts[1])
                except ValueError:
                    pass
        elif line.startswith("State:"):
            parts = line.split()
            if len(parts) >= 2:
                result["state"] = parts[1]
        elif line.startswith("Threads:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    result["threads"] = int(parts[1])
                except ValueError:
                    pass
    return result


def get_process_info(pid: int, context: Context, boot_time: float, now: float) -> dict | None:
    """Get detailed information about a process."""
    clock_ticks = 100  # Standard Linux value

    # Read stat file
    try:
        stat_content = context.read_file(f"/proc/{pid}/stat")
    except (FileNotFoundError, IOError):
        return None

    parsed = parse_proc_stat(stat_content)
    if not parsed:
        return None

    # Get command name
    comm = parsed["comm"]

    # Get full command line
    try:
        cmdline_raw = context.read_file(f"/proc/{pid}/cmdline")
        cmdline = cmdline_raw.replace("\x00", " ").strip()
        if len(cmdline) > 100:
            cmdline = cmdline[:97] + "..."
    except (FileNotFoundError, IOError):
        cmdline = comm

    # Get status info
    status_info = {"uid": None, "ppid": None, "state": None, "threads": 1}
    try:
        status_content = context.read_file(f"/proc/{pid}/status")
        status_info = parse_proc_status(status_content)
    except (FileNotFoundError, IOError):
        pass

    # Use status info or fallback to stat
    state = status_info["state"] or parsed["state"]
    ppid = status_info["ppid"] if status_info["ppid"] is not None else parsed["ppid"]

    # Get username (simplified)
    username = str(status_info["uid"]) if status_info["uid"] is not None else "unknown"

    # Calculate start time and age
    start_epoch = boot_time + (parsed["starttime"] / clock_ticks)
    start_datetime = datetime.fromtimestamp(start_epoch, tz=timezone.utc).isoformat()
    age_seconds = now - start_epoch

    return {
        "pid": pid,
        "comm": comm,
        "cmdline": cmdline,
        "user": username,
        "uid": status_info["uid"],
        "ppid": ppid,
        "state": state,
        "threads": status_info["threads"],
        "start_time": start_epoch,
        "start_datetime": start_datetime,
        "age_seconds": age_seconds,
    }


def format_age(seconds: float) -> str:
    """Format age in seconds to human-readable format."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes}m"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"
    else:
        days = int(seconds / 86400)
        hours = int((seconds % 86400) / 3600)
        return f"{days}d {hours}h"


def format_age_long(seconds: float) -> str:
    """Format age in detailed human-readable format."""
    days = int(seconds / 86400)
    hours = int((seconds % 86400) / 3600)
    minutes = int((seconds % 3600) / 60)

    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0 and days == 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

    return ", ".join(parts) if parts else "less than a minute"


def scan_processes(
    context: Context,
    boot_time: float,
    now: float,
    user_filter: str | None = None,
    cmd_filter: str | None = None,
    min_age_hours: float = 0,
) -> list[dict]:
    """Scan all processes and gather age information."""
    processes = []
    min_age_seconds = min_age_hours * 3600

    cmd_pattern = re.compile(cmd_filter, re.IGNORECASE) if cmd_filter else None

    # Get list of PIDs from /proc
    try:
        proc_entries = context.glob("[0-9]*", root="/proc")
    except (IOError, OSError):
        return processes

    for entry in proc_entries:
        try:
            pid = int(entry.split("/")[-1])
        except ValueError:
            continue

        info = get_process_info(pid, context, boot_time, now)
        if not info:
            continue

        # Apply filters
        if user_filter and info["user"] != user_filter:
            continue
        if cmd_pattern and not cmd_pattern.search(info["comm"]):
            continue
        if info["age_seconds"] < min_age_seconds:
            continue

        processes.append(info)

    return processes


def analyze_processes(
    processes: list[dict], warn_age_days: float, crit_age_days: float
) -> tuple[list[dict], list[dict], list[dict]]:
    """Analyze processes and categorize by age thresholds."""
    warn_seconds = warn_age_days * 86400
    crit_seconds = crit_age_days * 86400

    critical = []
    warnings = []
    normal = []

    for proc in processes:
        age = proc["age_seconds"]
        if age >= crit_seconds:
            proc["status"] = "critical"
            critical.append(proc)
        elif age >= warn_seconds:
            proc["status"] = "warning"
            warnings.append(proc)
        else:
            proc["status"] = "ok"
            normal.append(proc)

    return critical, warnings, normal


def group_by_command(processes: list[dict]) -> dict[str, list[dict]]:
    """Group processes by command name."""
    groups: dict[str, list[dict]] = {}
    for proc in processes:
        comm = proc["comm"]
        if comm not in groups:
            groups[comm] = []
        groups[comm].append(proc)
    return groups


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor process ages to identify long-running processes"
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
        help="Show detailed information",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show processes exceeding thresholds",
    )
    parser.add_argument(
        "--min-age",
        type=float,
        default=1.0,
        metavar="HOURS",
        help="Minimum process age in hours to include (default: 1.0)",
    )
    parser.add_argument(
        "--warn-days",
        type=float,
        default=30.0,
        metavar="DAYS",
        help="Age threshold in days for warning (default: 30.0)",
    )
    parser.add_argument(
        "--crit-days",
        type=float,
        default=90.0,
        metavar="DAYS",
        help="Age threshold in days for critical (default: 90.0)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=0,
        metavar="N",
        help="Show only top N oldest processes (default: all)",
    )
    parser.add_argument(
        "--user",
        type=str,
        metavar="USERNAME",
        help="Only monitor processes owned by this user",
    )
    parser.add_argument(
        "--cmd",
        type=str,
        metavar="PATTERN",
        help="Only monitor processes matching command pattern (regex)",
    )
    parser.add_argument(
        "--group",
        action="store_true",
        help="Group output by command name",
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if opts.min_age < 0:
        output.error("--min-age must be non-negative")
        return 2
    if opts.warn_days < 0:
        output.error("--warn-days must be non-negative")
        return 2
    if opts.crit_days < 0:
        output.error("--crit-days must be non-negative")
        return 2
    if opts.crit_days < opts.warn_days:
        output.error("--crit-days must be >= --warn-days")
        return 2
    if opts.top < 0:
        output.error("--top must be non-negative")
        return 2

    # Validate regex pattern
    if opts.cmd:
        try:
            re.compile(opts.cmd)
        except re.error as e:
            output.error(f"Invalid command pattern: {e}")
            return 2

    # Get boot time
    boot_time = get_boot_time(context)
    if boot_time is None:
        output.error("Unable to read boot time from /proc/stat")
        return 2

    now = datetime.now(timezone.utc).timestamp()

    # Scan processes
    try:
        processes = scan_processes(
            context, boot_time, now, opts.user, opts.cmd, opts.min_age
        )
    except Exception as e:
        output.error(f"Failed to scan processes: {e}")
        return 2

    if not processes:
        if opts.format == "json":
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "summary": {
                            "total_processes": 0,
                            "critical_count": 0,
                            "warning_count": 0,
                        },
                        "message": "No matching processes found",
                    },
                    indent=2,
                )
            )
        else:
            print("No matching processes found")

        output.set_summary("No matching processes found")
        return 0

    # Analyze processes
    critical, warnings, normal = analyze_processes(
        processes, opts.warn_days, opts.crit_days
    )

    # Output based on format
    if opts.format == "json":
        _output_json(processes, critical, warnings, boot_time)
    elif opts.format == "table":
        _output_table(processes, critical, warnings, opts.warn_only, opts.top)
    else:
        _output_plain(
            processes, critical, warnings, opts.warn_only, opts.verbose, opts.group
        )

    # Set summary
    status = "critical" if critical else ("warning" if warnings else "ok")
    output.set_summary(
        f"status={status}, critical={len(critical)}, warning={len(warnings)}"
    )

    return 1 if critical or warnings else 0


def _output_plain(
    processes: list[dict],
    critical: list[dict],
    warnings: list[dict],
    warn_only: bool,
    verbose: bool,
    group_by_cmd: bool,
) -> None:
    """Output in plain text format."""
    if critical:
        print("CRITICAL - Processes exceeding critical age threshold:")
        for proc in sorted(critical, key=lambda x: x["age_seconds"], reverse=True):
            print(
                f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                f"age {format_age(proc['age_seconds']):>10} "
                f"user={proc['user']}"
            )
            if verbose:
                print(f"           Started: {proc['start_datetime']}")
                print(f"           Command: {proc['cmdline'][:60]}")
        print()

    if warnings:
        print("WARNING - Processes exceeding warning age threshold:")
        for proc in sorted(warnings, key=lambda x: x["age_seconds"], reverse=True):
            print(
                f"  PID {proc['pid']:>7} ({proc['comm']:<15}): "
                f"age {format_age(proc['age_seconds']):>10} "
                f"user={proc['user']}"
            )
            if verbose:
                print(f"           Started: {proc['start_datetime']}")
        print()

    if not warn_only:
        if not critical and not warnings:
            print("OK - No processes exceed age thresholds")
            print()

        if group_by_cmd and processes:
            groups = group_by_command(processes)
            print(f"Process Summary by Command ({len(processes)} total processes):")
            print(f"{'Command':<20} {'Count':>6} {'Oldest':>12} {'User':<12}")
            print("-" * 54)

            for comm in sorted(groups.keys()):
                procs = groups[comm]
                oldest = max(procs, key=lambda x: x["age_seconds"])
                print(
                    f"{comm:<20} {len(procs):>6} "
                    f"{format_age(oldest['age_seconds']):>12} "
                    f"{oldest['user']:<12}"
                )
            print()


def _output_json(
    processes: list[dict],
    critical: list[dict],
    warnings: list[dict],
    boot_time: float,
) -> None:
    """Output in JSON format."""
    for proc in processes:
        proc["age_formatted"] = format_age_long(proc["age_seconds"])

    status = "critical" if critical else ("warning" if warnings else "ok")

    result = {
        "status": status,
        "summary": {
            "total_processes": len(processes),
            "critical_count": len(critical),
            "warning_count": len(warnings),
            "oldest_age_seconds": max((p["age_seconds"] for p in processes), default=0),
            "boot_time": boot_time,
            "boot_datetime": datetime.fromtimestamp(
                boot_time, tz=timezone.utc
            ).isoformat()
            if boot_time
            else None,
        },
        "critical": critical,
        "warnings": warnings,
        "all_processes": processes,
    }
    print(json.dumps(result, indent=2))


def _output_table(
    processes: list[dict],
    critical: list[dict],
    warnings: list[dict],
    warn_only: bool,
    top_n: int,
) -> None:
    """Output in table format."""
    if warn_only:
        display = critical + warnings
    else:
        display = processes

    display = sorted(display, key=lambda x: x["age_seconds"], reverse=True)
    if top_n > 0:
        display = display[:top_n]

    if not display:
        print("No processes to display")
        return

    # Header
    print(
        f"{'PID':>7} {'Command':<15} {'User':<12} {'Age':>12} "
        f"{'Started':>20} {'Status':<10}"
    )
    print("-" * 82)

    for proc in display:
        status = proc.get("status", "ok").upper()
        started = proc["start_datetime"][:16] if proc.get("start_datetime") else "unknown"
        print(
            f"{proc['pid']:>7} {proc['comm']:<15} {proc['user']:<12} "
            f"{format_age(proc['age_seconds']):>12} {started:>20} {status:<10}"
        )


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
