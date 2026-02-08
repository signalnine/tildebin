#!/usr/bin/env python3
# boxctl:
#   category: baremetal/process
#   tags: [monitoring, memory, leak, process]
#   brief: Monitor processes for memory growth over time to detect potential memory leaks

"""
Monitor processes for memory growth over time to detect potential memory leaks.

Samples process memory usage at intervals and identifies processes showing
significant memory growth. This is critical for detecting memory leaks in
long-running services before they exhaust system resources.

Key features:
- Tracks RSS (resident set size) growth over configurable intervals
- Calculates growth rate per sample period
- Identifies top memory growers
- Filters by minimum growth threshold
- Supports filtering by user or command pattern

Use cases:
- Detecting memory leaks in production services
- Monitoring long-running batch jobs
- Identifying processes that may need restart
- Pre-emptive capacity planning

Exit codes:
    0: No significant memory growth detected
    1: One or more processes showing concerning growth
    2: Usage error or unable to read process information
"""

import argparse
import re
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_status_file(content: str) -> dict:
    """Parse /proc/[pid]/status content into a dict."""
    result = {}
    for line in content.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def get_process_memory_info(pid: int, status_content: str, context: Context) -> dict | None:
    """Get memory information for a process."""
    try:
        status = parse_status_file(status_content)

        # Parse memory values from status
        rss_kb = None
        vsize_kb = None
        uid = None

        vmrss = status.get("VmRSS", "")
        if vmrss:
            parts = vmrss.split()
            if parts:
                rss_kb = int(parts[0])

        vmsize = status.get("VmSize", "")
        if vmsize:
            parts = vmsize.split()
            if parts:
                vsize_kb = int(parts[0])

        uid_line = status.get("Uid", "")
        if uid_line:
            parts = uid_line.split()
            if parts:
                uid = int(parts[0])

        if rss_kb is None:
            return None

        # Get command name
        comm = status.get("Name", "unknown")

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

        # Resolve username
        username = "unknown"
        if uid is not None:
            try:
                import pwd

                username = pwd.getpwuid(uid).pw_name
            except (KeyError, ImportError):
                username = str(uid)

        return {
            "pid": pid,
            "comm": comm,
            "cmdline": cmdline,
            "user": username,
            "rss_kb": rss_kb,
            "vsize_kb": vsize_kb or 0,
        }
    except (ValueError, IndexError, KeyError):
        return None


def scan_processes(
    context: Context, user_filter: str | None = None, cmd_filter: str | None = None
) -> dict[int, dict]:
    """Scan all processes and gather memory information."""
    processes = {}

    cmd_pattern = re.compile(cmd_filter, re.IGNORECASE) if cmd_filter else None

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
            status_content = context.read_file(f"/proc/{pid}/status")
        except (FileNotFoundError, IOError):
            continue

        info = get_process_memory_info(pid, status_content, context)
        if info:
            # Apply filters
            if user_filter and info["user"] != user_filter:
                continue
            if cmd_pattern and not cmd_pattern.search(info["comm"]):
                continue
            processes[pid] = info

    return processes


def calculate_growth(
    samples: list[dict[int, dict]], interval: float
) -> list[dict]:
    """Calculate memory growth for processes that appear in all samples."""
    if len(samples) < 2:
        return []

    first_sample = samples[0]
    last_sample = samples[-1]
    total_time = interval * (len(samples) - 1)

    results = []

    # Find processes that exist in both first and last samples
    common_pids = set(first_sample.keys()) & set(last_sample.keys())

    for pid in common_pids:
        first = first_sample[pid]
        last = last_sample[pid]

        rss_start = first["rss_kb"]
        rss_end = last["rss_kb"]
        growth_kb = rss_end - rss_start

        # Calculate growth rate (KB per minute)
        if total_time > 0:
            growth_rate = (growth_kb / total_time) * 60
        else:
            growth_rate = 0

        # Calculate percentage growth
        if rss_start > 0:
            growth_pct = ((rss_end - rss_start) / rss_start) * 100
        else:
            growth_pct = 0 if rss_end == 0 else 100

        results.append(
            {
                "pid": pid,
                "comm": last["comm"],
                "cmdline": last["cmdline"],
                "user": last["user"],
                "rss_start_kb": rss_start,
                "rss_end_kb": rss_end,
                "growth_kb": growth_kb,
                "growth_pct": round(growth_pct, 1),
                "growth_rate_kb_min": round(growth_rate, 1),
            }
        )

    return results


def analyze_growth(
    results: list[dict], min_growth_kb: int, min_growth_pct: float
) -> tuple[list[dict], list[dict]]:
    """Analyze growth results and identify concerning processes."""
    warnings = []
    critical = []

    for proc in results:
        # Skip processes with negligible absolute growth
        if proc["growth_kb"] < min_growth_kb:
            continue

        # Categorize by growth percentage
        if proc["growth_pct"] >= 50:
            critical.append(proc)
        elif proc["growth_pct"] >= min_growth_pct:
            warnings.append(proc)

    return warnings, critical


def format_size(kb: int) -> str:
    """Format size in KB to human-readable format."""
    if kb < 1024:
        return f"{kb} KB"
    elif kb < 1024 * 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb / (1024 * 1024):.1f} GB"


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no significant growth, 1 = concerning growth, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor processes for memory growth over time"
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
        help="Show detailed information including top growers",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show processes with warnings or critical growth",
    )
    parser.add_argument(
        "-s",
        "--samples",
        type=int,
        default=3,
        metavar="N",
        help="Number of samples to take (default: 3, min: 2)",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=5.0,
        metavar="SEC",
        help="Interval between samples in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--min-growth",
        type=int,
        default=512,
        metavar="KB",
        help="Minimum growth in KB to report (default: 512)",
    )
    parser.add_argument(
        "--min-pct",
        type=float,
        default=10.0,
        metavar="PCT",
        help="Minimum growth percentage for warning (default: 10.0)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=0,
        metavar="N",
        help="Show top N growers (default: 10 with --verbose)",
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
        "--snapshot",
        action="store_true",
        help="Show single snapshot of current memory usage (no sampling)",
    )

    opts = parser.parse_args(args)

    # Validate arguments
    if opts.samples < 2 and not opts.snapshot:
        output.error("Must take at least 2 samples")
        return 2
    if opts.interval <= 0:
        output.error("Interval must be positive")
        return 2
    if opts.min_growth < 0:
        output.error("--min-growth must be non-negative")
        return 2
    if opts.min_pct < 0:
        output.error("--min-pct must be non-negative")
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

    # Snapshot mode - just show current memory
    if opts.snapshot:
        sample = scan_processes(context, opts.user, opts.cmd)
        if not sample:
            output.error("Unable to read any process information")
            return 2

        procs = sorted(sample.values(), key=lambda x: x["rss_kb"], reverse=True)
        top_n = opts.top if opts.top > 0 else 10

        snapshot_result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "ok",
            "snapshot_mode": True,
            "summary": {"total_processes": len(procs)},
            "top_by_memory": procs[:top_n],
        }

        output.emit(snapshot_result)

        if opts.format == "table":
            print(f"{'PID':>7} {'Command':<15} {'User':<10} {'RSS':>12}")
            print("-" * 50)
            for proc in procs[:top_n]:
                print(
                    f"{proc['pid']:>7} {proc['comm']:<15} {proc['user']:<10} "
                    f"{format_size(proc['rss_kb']):>12}"
                )
        else:
            output.render(opts.format, "Process Memory Growth Monitor", warn_only=getattr(opts, 'warn_only', False))

        output.set_summary(f"Snapshot: {len(procs)} processes")
        return 0

    # Collect samples
    samples = []
    total_time = opts.interval * (opts.samples - 1)

    if opts.format == "plain" and not opts.warn_only:
        print(
            f"Monitoring memory growth ({opts.samples} samples, "
            f"{opts.interval}s interval, {total_time}s total)..."
        )
        print()

    import time

    for i in range(opts.samples):
        sample = scan_processes(context, opts.user, opts.cmd)
        samples.append(sample)

        if i < opts.samples - 1:
            time.sleep(opts.interval)

    if not samples or not samples[0]:
        output.error("Unable to read any process information")
        output.error("This may require elevated privileges")
        return 2

    # Calculate growth
    results = calculate_growth(samples, opts.interval)

    if not results:
        no_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "ok",
            "summary": {
                "total_processes_tracked": 0,
                "critical_count": 0,
                "warning_count": 0,
                "total_growth_kb": 0,
                "monitoring_duration_sec": total_time,
            },
            "message": "No processes persisted across all samples",
        }
        output.emit(no_results)
        output.render(opts.format, "Process Memory Growth Monitor", warn_only=getattr(opts, 'warn_only', False))
        return 0

    # Analyze growth
    warnings, critical = analyze_growth(results, opts.min_growth, opts.min_pct)

    # Build result for output
    sorted_results = sorted(results, key=lambda x: x["growth_kb"], reverse=True)
    top_growers = sorted_results[:opts.top] if opts.top > 0 else sorted_results[:10]
    total_growth = sum(r["growth_kb"] for r in results if r["growth_kb"] > 0)

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "critical" if critical else ("warning" if warnings else "ok"),
        "summary": {
            "total_processes_tracked": len(results),
            "critical_count": len(critical),
            "warning_count": len(warnings),
            "total_growth_kb": total_growth,
            "monitoring_duration_sec": round(total_time, 1),
        },
        "critical": critical,
        "warnings": warnings,
        "top_growers": top_growers,
    }

    output.emit(result)

    # Output based on format
    if opts.format == "table":
        _output_table(results, warnings, critical, opts.warn_only, opts.top)
    else:
        output.render(opts.format, "Process Memory Growth Monitor", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    if critical:
        output.set_summary(f"CRITICAL - {len(critical)} process(es) with significant memory growth")
    elif warnings:
        output.set_summary(f"WARNING - {len(warnings)} process(es) with elevated memory growth")
    else:
        output.set_summary("OK - No significant memory growth detected")

    return 1 if (critical or warnings) else 0



def _output_table(
    results: list[dict],
    warnings: list[dict],
    critical: list[dict],
    warn_only: bool,
    top_n: int,
) -> None:
    """Output in table format."""
    if warn_only:
        display = critical + warnings
        display.sort(key=lambda x: x["growth_kb"], reverse=True)
    else:
        display = sorted(results, key=lambda x: x["growth_kb"], reverse=True)
        if top_n > 0:
            display = display[:top_n]

    if not display:
        print("No processes to display")
        return

    # Header
    print(
        f"{'PID':>7} {'Command':<15} {'User':<10} {'Start':>10} {'End':>10} "
        f"{'Growth':>10} {'Pct':>7} {'Status':<10}"
    )
    print("-" * 90)

    for proc in display:
        if proc in critical:
            status = "CRITICAL"
        elif proc in warnings:
            status = "WARNING"
        else:
            status = "OK"

        print(
            f"{proc['pid']:>7} {proc['comm']:<15} {proc['user']:<10} "
            f"{format_size(proc['rss_start_kb']):>10} {format_size(proc['rss_end_kb']):>10} "
            f"{format_size(proc['growth_kb']):>10} {proc['growth_pct']:>6}% {status:<10}"
        )


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
