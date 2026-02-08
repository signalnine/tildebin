#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [health, process, dstate, io, blocked]
#   brief: Monitor processes in uninterruptible sleep (D-state)

"""
Monitor processes in uninterruptible sleep (D-state) on baremetal systems.

Processes in uninterruptible sleep (state 'D') are waiting for I/O or holding
kernel locks. While brief D-state is normal, processes stuck in D-state for
extended periods indicate:
- Storage subsystem issues (failing disks, hung NFS mounts)
- Kernel lock contention
- Driver bugs or hardware failures
- Network filesystem hangs

Exit codes:
    0: No D-state processes detected (or all below threshold)
    1: D-state processes found (warning)
    2: Usage error or unable to read process information
"""

import argparse
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
    """Parse a /proc/[pid]/stat line."""
    try:
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
            "starttime": int(rest[19]),
        }
    except (ValueError, IndexError):
        return None


def get_wait_channel(pid: int, context: Context) -> str | None:
    """Get the kernel wait channel for a process."""
    try:
        wchan = context.read_file(f"/proc/{pid}/wchan").strip()
        return wchan if wchan and wchan != "0" else None
    except (FileNotFoundError, IOError):
        return None


def categorize_wait_channel(wchan: str | None) -> tuple[str, str]:
    """
    Categorize wait channel to help identify the type of blocking.

    Returns a tuple of (category, description).
    """
    if wchan is None:
        return ("unknown", "Unknown wait state")

    wchan_lower = wchan.lower()

    # NFS-related waits
    if "nfs" in wchan_lower or "rpc" in wchan_lower:
        return ("nfs", "NFS/RPC operation")

    # Disk I/O waits
    if any(x in wchan_lower for x in ["blk", "bio", "io_schedule", "wait_on_page"]):
        return ("disk_io", "Disk I/O operation")

    # Filesystem waits
    if any(x in wchan_lower for x in ["ext4", "xfs", "btrfs", "jbd2"]):
        return ("filesystem", "Filesystem operation")

    # Lock waits
    if any(x in wchan_lower for x in ["mutex", "semaphore", "rwsem", "lock"]):
        return ("lock", "Kernel lock contention")

    # Memory waits
    if any(x in wchan_lower for x in ["page", "mem", "swap", "reclaim"]):
        return ("memory", "Memory/page operation")

    # Network waits (non-NFS)
    if any(x in wchan_lower for x in ["sock", "tcp", "inet", "net"]):
        return ("network", "Network operation")

    # SCSI/storage driver waits
    if any(x in wchan_lower for x in ["scsi", "ata", "sd_", "nvme"]):
        return ("storage_driver", "Storage driver operation")

    return ("other", f"Kernel function: {wchan}")


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


def get_process_info(
    pid: int, stat_content: str, context: Context, boot_time: int | None
) -> dict | None:
    """Get detailed process info."""
    parsed = parse_proc_stat(stat_content)
    if not parsed:
        return None

    clock_ticks = 100

    age_seconds = None
    start_time_iso = None

    if boot_time:
        start_epoch = boot_time + (parsed["starttime"] / clock_ticks)
        start_datetime = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
        start_time_iso = start_datetime.isoformat()
        age_seconds = int(datetime.now(timezone.utc).timestamp() - start_epoch)

    # Get command line
    cmdline = ""
    try:
        cmdline_raw = context.read_file(f"/proc/{pid}/cmdline")
        cmdline = cmdline_raw.replace("\x00", " ").strip()
    except (FileNotFoundError, IOError):
        pass

    # Get wait channel
    wchan = get_wait_channel(pid, context)

    # Get parent name
    parent_name = "<unknown>"
    try:
        parent_name = context.read_file(f"/proc/{parsed['ppid']}/comm").strip()
    except (FileNotFoundError, IOError):
        pass

    # Categorize wait channel
    category, description = categorize_wait_channel(wchan)

    return {
        "pid": parsed["pid"],
        "name": parsed["name"],
        "state": parsed["state"],
        "ppid": parsed["ppid"],
        "parent_name": parent_name,
        "cmdline": cmdline if cmdline else f"[{parsed['name']}]",
        "age_seconds": age_seconds,
        "start_time": start_time_iso,
        "wait_channel": wchan,
        "wait_category": category,
        "wait_description": description,
    }


def find_dstate_processes(context: Context) -> list[dict]:
    """Find all processes in uninterruptible sleep (D-state)."""
    dstate_procs = []
    boot_time = get_boot_time(context)

    # Get list of PIDs from /proc
    try:
        proc_entries = context.glob("[0-9]*", root="/proc")
    except (IOError, OSError):
        return dstate_procs

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

        info = get_process_info(pid, stat_content, context, boot_time)
        if info and info["state"] == "D":
            dstate_procs.append(info)

    return dstate_procs


def group_by_wait_category(procs: list[dict]) -> dict[str, list[dict]]:
    """Group D-state processes by their wait category."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for proc in procs:
        groups[proc["wait_category"]].append(proc)
    return dict(groups)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no D-state, 1 = D-state found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor processes in uninterruptible sleep (D-state)"
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
        help="Group processes by wait category",
    )
    parser.add_argument(
        "--min-age",
        type=int,
        default=0,
        help="Only show processes in D-state longer than N seconds (default: 0)",
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
        help="Only output if D-state processes are found",
    )

    opts = parser.parse_args(args)

    # Validate min-age
    if opts.min_age < 0:
        output.error("--min-age must be non-negative")
        return 2

    # Find D-state processes
    try:
        dstate_procs = find_dstate_processes(context)
    except Exception as e:
        output.error(f"Failed to scan processes: {e}")
        return 2

    # Filter by age if specified
    if opts.min_age > 0:
        dstate_procs = [
            p
            for p in dstate_procs
            if p["age_seconds"] is not None and p["age_seconds"] >= opts.min_age
        ]

    # Build result
    groups = group_by_wait_category(dstate_procs)
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_dstate": len(dstate_procs),
        "category_count": len(groups),
        "processes": dstate_procs,
        "by_category": {
            category: {
                "count": len(members),
                "description": members[0]["wait_description"] if members else category,
                "processes": members,
            }
            for category, members in groups.items()
        },
        "healthy": len(dstate_procs) == 0,
    }

    output.emit(result)

    # Handle warn-only mode
    if opts.warn_only and not dstate_procs:
        return 0

    # Output based on format
    if opts.format == "table":
        _output_table(dstate_procs, groups, opts.verbose, opts.group)
    else:
        output.render(opts.format, "Uninterruptible Process Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    if dstate_procs:
        output.set_summary(f"Found {len(dstate_procs)} D-state process(es)")
    else:
        output.set_summary("No D-state processes detected")

    return 1 if dstate_procs else 0


def _output_table(
    procs: list[dict], groups: dict, verbose: bool, group_output: bool
) -> None:
    """Output in table format."""
    if not procs:
        print("+" + "-" * 58 + "+")
        print("|" + " No D-state processes detected".center(58) + "|")
        print("+" + "-" * 58 + "+")
        return

    print("+" + "-" * 74 + "+")
    print(
        "|"
        + f" Uninterruptible Sleep (D-state) Report: {len(procs)} process(es) ".center(74)
        + "|"
    )
    print("+" + "-" * 74 + "+")

    if group_output:
        for category, members in sorted(groups.items(), key=lambda x: -len(x[1])):
            desc = members[0]["wait_description"] if members else category
            print(f"| {category.upper()}: {desc}".ljust(74) + " |")
            print("|" + "-" * 74 + "|")
            for p in members:
                age_str = format_age(p["age_seconds"])
                wchan = (p["wait_channel"] or "unknown")[:25]
                line = f"   PID {p['pid']}: {p['name'][:15]} | Age: {age_str} | {wchan}"
                print(f"| {line:<72} |")
            print("+" + "-" * 74 + "+")
    else:
        header = f"{'PID':<7} {'Name':<14} {'Age':<9} {'Wait Channel':<25}"
        print(f"| {header:<72} |")
        print("+" + "-" * 74 + "+")

        for p in sorted(procs, key=lambda x: -(x["age_seconds"] or 0)):
            age_str = format_age(p["age_seconds"])
            wchan = (p["wait_channel"] or "unknown")[:25]
            line = f"{p['pid']:<7} {p['name'][:14]:<14} {age_str:<9} {wchan:<25}"
            print(f"| {line:<72} |")

    print("+" + "-" * 74 + "+")

    if verbose:
        print()
        print("Common wait channels and their meanings:")
        print("  blk_* / io_schedule - Waiting for block device I/O")
        print("  nfs_* / rpc_*       - Waiting for NFS/RPC operations")
        print("  mutex_* / rwsem_*   - Waiting for kernel locks")
        print("  wait_on_page_*      - Waiting for page I/O completion")


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
