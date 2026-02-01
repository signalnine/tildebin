#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [health, process, zombie, defunct]
#   brief: Monitor zombie (defunct) processes on baremetal systems

"""
Monitor zombie (defunct) processes on baremetal systems.

Zombie processes are processes that have completed execution but still have
entries in the process table. While individual zombies consume minimal resources,
large numbers indicate parent processes not properly reaping child processes,
which can lead to PID exhaustion and process table bloat.

Exit codes:
    0: No zombie processes detected
    1: Zombie processes found (warning)
    2: Usage error or unable to read process information
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


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
    """
    Parse a /proc/[pid]/stat line.

    Format: pid (comm) state ppid pgrp session tty_nr tpgid flags ...
    Field 22 (0-indexed: 19 after comm fields) is starttime in clock ticks.
    """
    try:
        # Handle process names with spaces/parentheses
        first_paren = stat_line.index("(")
        last_paren = stat_line.rindex(")")

        name = stat_line[first_paren + 1 : last_paren]
        rest = stat_line[last_paren + 2 :].split()

        if len(rest) < 20:
            return None

        return {
            "pid": int(stat_line[:first_paren].strip()),
            "name": name,
            "state": rest[0],
            "ppid": int(rest[1]),
            "starttime": int(rest[19]),  # Clock ticks since boot
        }
    except (ValueError, IndexError):
        return None


def get_process_info(
    pid: int, stat_content: str, boot_time: int | None, clock_ticks: int = 100
) -> dict | None:
    """Parse process info from stat content."""
    parsed = parse_proc_stat(stat_content)
    if not parsed:
        return None

    age_seconds = None
    start_time_iso = None

    if boot_time and clock_ticks:
        start_epoch = boot_time + (parsed["starttime"] / clock_ticks)
        start_datetime = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
        start_time_iso = start_datetime.isoformat()
        age_seconds = int(datetime.now(timezone.utc).timestamp() - start_epoch)

    return {
        "pid": parsed["pid"],
        "name": parsed["name"],
        "state": parsed["state"],
        "ppid": parsed["ppid"],
        "age_seconds": age_seconds,
        "start_time": start_time_iso,
    }


def format_age(seconds: int | None) -> str:
    """Format age in human-readable format."""
    if seconds is None:
        return "unknown"

    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    elif seconds < 86400:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d {hours}h"


def find_zombie_processes(context: Context) -> list[dict]:
    """
    Find all zombie processes in the system.

    Returns list of zombie process info dicts.
    """
    zombies = []
    boot_time = get_boot_time(context)

    # Get list of PIDs from /proc
    try:
        proc_entries = context.glob("[0-9]*", root="/proc")
    except (IOError, OSError):
        return zombies

    for entry in proc_entries:
        try:
            pid = int(entry.split("/")[-1])
        except ValueError:
            continue

        stat_path = f"/proc/{pid}/stat"
        try:
            stat_content = context.read_file(stat_path)
        except (FileNotFoundError, IOError):
            continue

        info = get_process_info(pid, stat_content, boot_time)
        if info and info["state"] == "Z":
            # Try to get parent name
            parent_name = "<unknown>"
            try:
                comm_path = f"/proc/{info['ppid']}/comm"
                parent_name = context.read_file(comm_path).strip()
            except (FileNotFoundError, IOError):
                pass

            info["parent_name"] = parent_name
            zombies.append(info)

    return zombies


def group_by_parent(zombies: list[dict]) -> dict:
    """Group zombie processes by their parent."""
    groups = defaultdict(list)
    for zombie in zombies:
        key = (zombie["ppid"], zombie["parent_name"])
        groups[key].append(zombie)
    return dict(groups)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no zombies, 1 = zombies found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor zombie (defunct) processes on baremetal systems"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-g",
        "--group",
        action="store_true",
        help="Group zombies by parent process",
    )
    parser.add_argument(
        "--min-age",
        type=int,
        default=0,
        help="Only show zombies older than N seconds (default: 0)",
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
        help="Only output if zombies are found",
    )

    opts = parser.parse_args(args)

    # Validate min-age
    if opts.min_age < 0:
        output.error("--min-age must be non-negative")
        return 2

    # Find zombie processes
    try:
        zombies = find_zombie_processes(context)
    except Exception as e:
        output.error(f"Failed to scan processes: {e}")
        return 2

    # Filter by age if specified
    if opts.min_age > 0:
        zombies = [
            z
            for z in zombies
            if z["age_seconds"] is not None and z["age_seconds"] >= opts.min_age
        ]

    # Handle warn-only mode
    if opts.warn_only and not zombies:
        return 0

    # Build result data
    groups = group_by_parent(zombies)
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_zombies": len(zombies),
        "parent_count": len(groups),
        "zombies": zombies,
        "by_parent": {
            f"{ppid}:{parent_name}": {
                "ppid": ppid,
                "parent_name": parent_name,
                "zombie_count": len(children),
                "zombies": children,
            }
            for (ppid, parent_name), children in groups.items()
        },
        "healthy": len(zombies) == 0,
    }

    # Output based on format
    if opts.format == "json":
        print(json.dumps(result, indent=2, default=str))
    elif opts.format == "table":
        _output_table(zombies, groups, opts.verbose, opts.group)
    else:
        _output_plain(zombies, groups, opts.verbose, opts.group)

    # Set summary
    if zombies:
        output.set_summary(f"Found {len(zombies)} zombie process(es)")
    else:
        output.set_summary("No zombie processes detected")

    return 1 if zombies else 0


def _output_plain(
    zombies: list[dict], groups: dict, verbose: bool, group_output: bool
) -> None:
    """Output in plain text format."""
    if not zombies:
        print("No zombie processes detected")
        return

    print(f"Found {len(zombies)} zombie process(es)")
    print()

    if group_output:
        print(f"Grouped by {len(groups)} parent process(es):")
        print()

        for (ppid, parent_name), children in sorted(
            groups.items(), key=lambda x: -len(x[1])
        ):
            print(f"Parent: {parent_name} (PID {ppid}) - {len(children)} zombie(s)")
            for z in children:
                age_str = format_age(z["age_seconds"])
                print(f"  - PID {z['pid']}: {z['name']} (age: {age_str})")
            print()
    else:
        print(f"{'PID':<8} {'Name':<16} {'PPID':<8} {'Parent':<16} {'Age':<10}")
        print("-" * 66)

        for z in sorted(zombies, key=lambda x: x["pid"]):
            age_str = format_age(z["age_seconds"])
            print(
                f"{z['pid']:<8} {z['name']:<16} {z['ppid']:<8} "
                f"{z['parent_name']:<16} {age_str:<10}"
            )

    if verbose:
        print()
        print("Recommendations:")
        print("- Investigate parent processes not reaping children")
        print("- Check for signal handling issues in parent processes")
        print("- Consider restarting problematic parent processes")


def _output_table(
    zombies: list[dict], groups: dict, verbose: bool, group_output: bool
) -> None:
    """Output in table format."""
    if not zombies:
        print("+" + "-" * 50 + "+")
        print("|" + " No zombie processes detected".center(50) + "|")
        print("+" + "-" * 50 + "+")
        return

    print("+" + "-" * 70 + "+")
    print("|" + f" Zombie Process Report: {len(zombies)} zombie(s) ".center(70) + "|")
    print("+" + "-" * 70 + "+")

    if group_output:
        for (ppid, parent_name), children in sorted(
            groups.items(), key=lambda x: -len(x[1])
        ):
            print(f"| Parent: {parent_name} (PID {ppid})".ljust(70) + " |")
            print("|" + "-" * 70 + "|")
            for z in children:
                age_str = format_age(z["age_seconds"])
                line = f"   PID {z['pid']}: {z['name'][:20]} | Age: {age_str}"
                print(f"| {line:<68} |")
            print("+" + "-" * 70 + "+")
    else:
        header = f"{'PID':<7} {'Name':<14} {'PPID':<7} {'Parent':<14} {'Age':<10}"
        print(f"| {header:<68} |")
        print("+" + "-" * 70 + "+")

        for z in sorted(zombies, key=lambda x: x["pid"]):
            age_str = format_age(z["age_seconds"])
            line = (
                f"{z['pid']:<7} {z['name'][:14]:<14} {z['ppid']:<7} "
                f"{z['parent_name'][:14]:<14} {age_str:<10}"
            )
            print(f"| {line:<68} |")

    print("+" + "-" * 70 + "+")


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
