#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [monitoring, io, process, performance]
#   brief: Monitor per-process I/O usage to identify I/O bottlenecks

"""
Monitor per-process I/O usage to identify processes causing I/O bottlenecks.

This script reads /proc/[pid]/io to show which processes are responsible for
disk I/O load. Unlike system-wide I/O monitoring (iostat, diskstats), this
identifies the specific processes generating read/write traffic.

Critical for troubleshooting:
- Database servers with unexpected I/O patterns
- Backup jobs consuming excessive bandwidth
- Runaway log writers
- Memory-mapped file thrashing
- Identifying which container/service is causing I/O wait

Metrics tracked per process:
- rchar/wchar: Characters read/written (includes page cache)
- read_bytes/write_bytes: Actual disk I/O (bypasses cache accounting)
- syscr/syscw: Read/write syscall counts
- cancelled_write_bytes: Bytes not written due to truncation

Exit codes:
    0: Successfully collected I/O statistics, no warnings
    1: Warnings detected (high I/O processes found)
    2: Usage error or unable to read process information
"""

import argparse
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_proc_io(content: str) -> dict[str, int] | None:
    """Parse /proc/[pid]/io content into a dict."""
    if not content:
        return None

    result = {}
    for line in content.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            try:
                result[key.strip()] = int(value.strip())
            except ValueError:
                continue

    return result if result else None


def get_process_info(pid: int, io_content: str, context: Context) -> dict | None:
    """Get process information including I/O stats."""
    io_stats = parse_proc_io(io_content)
    if not io_stats:
        return None

    # Get command name
    comm = "unknown"
    try:
        comm = context.read_file(f"/proc/{pid}/comm").strip()
    except (FileNotFoundError, IOError):
        pass

    # Get full command line
    cmdline = comm
    try:
        cmdline_raw = context.read_file(f"/proc/{pid}/cmdline")
        cmdline = cmdline_raw.replace("\x00", " ").strip()
        if len(cmdline) > 80:
            cmdline = cmdline[:77] + "..."
        if not cmdline:
            cmdline = comm
    except (FileNotFoundError, IOError):
        pass

    # Get user info
    username = "unknown"
    uid = None
    try:
        status_content = context.read_file(f"/proc/{pid}/status")
        for line in status_content.split("\n"):
            if line.startswith("Uid:"):
                parts = line.split()
                if len(parts) >= 2:
                    uid = int(parts[1])
                    try:
                        import pwd

                        username = pwd.getpwuid(uid).pw_name
                    except (KeyError, ImportError):
                        username = str(uid)
                break
    except (FileNotFoundError, IOError, ValueError):
        pass

    return {
        "pid": pid,
        "comm": comm,
        "cmdline": cmdline,
        "user": username,
        "uid": uid,
        "rchar": io_stats.get("rchar", 0),
        "wchar": io_stats.get("wchar", 0),
        "syscr": io_stats.get("syscr", 0),
        "syscw": io_stats.get("syscw", 0),
        "read_bytes": io_stats.get("read_bytes", 0),
        "write_bytes": io_stats.get("write_bytes", 0),
        "cancelled_write_bytes": io_stats.get("cancelled_write_bytes", 0),
    }


def scan_processes(context: Context) -> list[dict]:
    """Scan all processes and gather I/O information."""
    processes = []

    try:
        proc_entries = context.glob("[0-9]*", root="/proc")
    except (IOError, OSError):
        return processes

    for entry in proc_entries:
        try:
            pid = int(entry.split("/")[-1])
        except ValueError:
            continue

        try:
            io_content = context.read_file(f"/proc/{pid}/io")
        except (FileNotFoundError, IOError):
            continue

        info = get_process_info(pid, io_content, context)
        if info:
            processes.append(info)

    return processes


def calculate_io_rates(
    before: list[dict], after: list[dict], interval: float
) -> list[dict]:
    """Calculate I/O rates between two samples."""
    before_map = {p["pid"]: p for p in before}
    results = []

    for proc in after:
        pid = proc["pid"]
        if pid not in before_map:
            continue

        prev = before_map[pid]

        # Calculate deltas
        read_bytes_delta = proc["read_bytes"] - prev["read_bytes"]
        write_bytes_delta = proc["write_bytes"] - prev["write_bytes"]
        rchar_delta = proc["rchar"] - prev["rchar"]
        wchar_delta = proc["wchar"] - prev["wchar"]
        syscr_delta = proc["syscr"] - prev["syscr"]
        syscw_delta = proc["syscw"] - prev["syscw"]

        # Handle counter wraparound or process restart
        if read_bytes_delta < 0 or write_bytes_delta < 0:
            continue

        # Calculate rates (bytes per second)
        read_rate = read_bytes_delta / interval if interval > 0 else 0
        write_rate = write_bytes_delta / interval if interval > 0 else 0
        total_rate = read_rate + write_rate

        results.append(
            {
                "pid": pid,
                "comm": proc["comm"],
                "cmdline": proc["cmdline"],
                "user": proc["user"],
                "read_bytes": read_bytes_delta,
                "write_bytes": write_bytes_delta,
                "read_rate": read_rate,
                "write_rate": write_rate,
                "total_rate": total_rate,
                "rchar": rchar_delta,
                "wchar": wchar_delta,
                "syscr": syscr_delta,
                "syscw": syscw_delta,
                "total_io_bytes": proc["read_bytes"] + proc["write_bytes"],
            }
        )

    return results


def format_bytes(num_bytes: float) -> str:
    """Format bytes into human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f}PB"


def format_rate(bytes_per_sec: float) -> str:
    """Format bytes/sec into human-readable string."""
    return format_bytes(bytes_per_sec) + "/s"


def parse_threshold(threshold_str: str) -> float:
    """Parse threshold string with optional K/M/G suffix."""
    threshold_str = threshold_str.upper().strip()
    multiplier = 1
    if threshold_str.endswith("K"):
        multiplier = 1024
        threshold_str = threshold_str[:-1]
    elif threshold_str.endswith("M"):
        multiplier = 1024 * 1024
        threshold_str = threshold_str[:-1]
    elif threshold_str.endswith("G"):
        multiplier = 1024 * 1024 * 1024
        threshold_str = threshold_str[:-1]

    return float(threshold_str) * multiplier


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Note: This script requires two samples with a time interval between them.
    For testing, use the mock_samples parameter to provide pre-computed data.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no warnings, 1 = high I/O detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor per-process I/O usage to identify I/O bottlenecks"
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
        help="Show detailed information including syscall counts",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show processes exceeding I/O threshold",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        metavar="SECS",
        help="Sampling interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Show top N I/O consumers (default: 10)",
    )
    parser.add_argument(
        "--warn-threshold",
        type=str,
        default="10M",
        metavar="RATE",
        help="Warn threshold as bytes/sec with optional K/M/G suffix (default: 10M)",
    )
    parser.add_argument(
        "--snapshot",
        action="store_true",
        help="Show single snapshot of cumulative I/O (no sampling)",
    )

    opts = parser.parse_args(args)

    # Validate interval
    if opts.interval <= 0:
        output.error("Interval must be positive")
        return 2
    if opts.interval > 300:
        output.error("Interval cannot exceed 300 seconds")
        return 2

    # Validate top
    if opts.top < 1:
        output.error("--top must be at least 1")
        return 2

    # Parse warn threshold
    try:
        warn_threshold = parse_threshold(opts.warn_threshold)
    except ValueError:
        output.error(f"Invalid threshold value: {opts.warn_threshold}")
        return 2

    if warn_threshold <= 0:
        output.error("Threshold must be positive")
        return 2

    # Take first sample
    before = scan_processes(context)

    if not before:
        output.error("Unable to read any process I/O information")
        output.error("This may require elevated privileges to read /proc/[pid]/io")
        return 2

    # For snapshot mode, just show cumulative data
    if opts.snapshot:
        processes = [
            {
                "pid": p["pid"],
                "comm": p["comm"],
                "cmdline": p["cmdline"],
                "user": p["user"],
                "read_bytes": p["read_bytes"],
                "write_bytes": p["write_bytes"],
                "total_rate": 0,  # No rate for snapshot
                "read_rate": 0,
                "write_rate": 0,
                "syscr": p["syscr"],
                "syscw": p["syscw"],
                "rchar": p["rchar"],
                "wchar": p["wchar"],
                "total_io_bytes": p["read_bytes"] + p["write_bytes"],
            }
            for p in before
        ]
        warnings: list[dict] = []

        sorted_procs = sorted(processes, key=lambda x: x["total_rate"], reverse=True)
        active_procs = [p for p in sorted_procs if p["total_rate"] > 0 or True]

        snapshot_result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "ok",
            "warn_threshold_bytes_sec": warn_threshold,
            "snapshot_mode": True,
            "summary": {
                "total_processes_sampled": len(processes),
                "processes_with_io": len(active_procs),
                "warning_count": 0,
                "total_read_rate": sum(p["read_rate"] for p in processes),
                "total_write_rate": sum(p["write_rate"] for p in processes),
            },
            "warnings": [],
            "top_consumers": active_procs[:opts.top],
        }

        output.emit(snapshot_result)

        if opts.format == "table":
            _output_table(processes, opts.top, opts.warn_only, warn_threshold, snapshot=True)
        else:
            output.render(opts.format, "Process I/O Monitor", warn_only=getattr(opts, 'warn_only', False))

        output.set_summary(f"Snapshot: {len(processes)} processes sampled")
        return 0

    # Wait for interval
    import time

    time.sleep(opts.interval)

    # Take second sample
    after = scan_processes(context)

    if not after:
        output.error("Unable to read process I/O for second sample")
        return 2

    # Calculate rates
    processes = calculate_io_rates(before, after, opts.interval)

    # Sort by total I/O rate
    sorted_procs = sorted(processes, key=lambda x: x["total_rate"], reverse=True)
    active_procs = [p for p in sorted_procs if p["total_rate"] > 0]
    warnings = [p for p in active_procs if p["total_rate"] >= warn_threshold]

    # Build result for output
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "warning" if warnings else "ok",
        "warn_threshold_bytes_sec": warn_threshold,
        "snapshot_mode": False,
        "summary": {
            "total_processes_sampled": len(processes),
            "processes_with_io": len(active_procs),
            "warning_count": len(warnings),
            "total_read_rate": sum(p["read_rate"] for p in processes),
            "total_write_rate": sum(p["write_rate"] for p in processes),
        },
        "warnings": warnings[:opts.top],
        "top_consumers": active_procs[:opts.top],
    }

    output.emit(result)

    # Output based on format
    if opts.format == "table":
        _output_table(processes, opts.top, opts.warn_only, warn_threshold)
    else:
        output.render(opts.format, "Process I/O Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    if warnings:
        output.set_summary(f"WARNING - {len(warnings)} process(es) exceeding I/O threshold")
    else:
        output.set_summary(f"OK - {len(active_procs)} processes with I/O activity")

    return 1 if warnings else 0



def _output_table(
    processes: list[dict],
    top_n: int,
    warn_only: bool,
    warn_threshold: float,
    snapshot: bool = False,
) -> None:
    """Output in table format."""
    sorted_procs = sorted(processes, key=lambda x: x["total_rate"], reverse=True)
    active_procs = [p for p in sorted_procs if p["total_rate"] > 0 or snapshot]
    warnings = [p for p in active_procs if p["total_rate"] >= warn_threshold]

    if warn_only and not snapshot:
        display_procs = warnings[:top_n]
    else:
        display_procs = active_procs[:top_n] if active_procs else sorted_procs[:top_n]

    if not display_procs:
        print("No processes to display")
        return

    if snapshot:
        print(
            f"{'PID':>7} {'Command':<15} {'User':<10} {'Read':>12} "
            f"{'Write':>12} {'Total':>12}"
        )
        print("-" * 75)

        for proc in display_procs:
            print(
                f"{proc['pid']:>7} {proc['comm']:<15} {proc['user']:<10} "
                f"{format_bytes(proc['read_bytes']):>12} "
                f"{format_bytes(proc['write_bytes']):>12} "
                f"{format_bytes(proc['total_io_bytes']):>12}"
            )
    else:
        print(
            f"{'PID':>7} {'Command':<15} {'User':<10} {'Read/s':>12} "
            f"{'Write/s':>12} {'Total/s':>12} {'Status':<8}"
        )
        print("-" * 85)

        for proc in display_procs:
            status = "WARNING" if proc in warnings else "OK"
            print(
                f"{proc['pid']:>7} {proc['comm']:<15} {proc['user']:<10} "
                f"{format_rate(proc['read_rate']):>12} "
                f"{format_rate(proc['write_rate']):>12} "
                f"{format_rate(proc['total_rate']):>12} {status:<8}"
            )


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
