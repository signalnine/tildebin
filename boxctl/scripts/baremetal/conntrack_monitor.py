#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, conntrack, connections]
#   brief: Monitor Linux connection tracking (conntrack) table saturation

"""
Monitor Linux connection tracking (conntrack) table saturation.

This script monitors the netfilter connection tracking table usage, which
tracks all active network connections for stateful packet inspection. Table
exhaustion causes new connections to be dropped, which is a common failure
mode during:

- DDoS attacks that create many connections
- Traffic spikes (flash crowds, viral events)
- Misconfigured applications opening many connections
- Port scanning or network reconnaissance
- Systems handling many short-lived connections (load balancers, proxies)

The script reads from /proc/sys/net/netfilter/ to check:
- nf_conntrack_count: Current number of tracked connections
- nf_conntrack_max: Maximum table size
- Usage percentage and headroom

Exit codes:
    0: Connection tracking usage is healthy
    1: High usage detected (warning or critical)
    2: Usage error or conntrack not available (module not loaded)
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_conntrack_stats(context: Context) -> dict:
    """Gather connection tracking statistics.

    Args:
        context: Execution context

    Returns:
        dict: Connection tracking statistics

    Raises:
        FileNotFoundError: If conntrack files not found
    """
    # Paths to try for conntrack count
    count_paths = [
        "/proc/sys/net/netfilter/nf_conntrack_count",
        "/proc/sys/net/nf_conntrack_count",
    ]
    max_paths = [
        "/proc/sys/net/netfilter/nf_conntrack_max",
        "/proc/sys/net/nf_conntrack_max",
    ]

    # Find working paths
    count = None
    max_val = None

    for path in count_paths:
        if context.file_exists(path):
            count = int(context.read_file(path).strip())
            break

    for path in max_paths:
        if context.file_exists(path):
            max_val = int(context.read_file(path).strip())
            break

    if count is None:
        raise FileNotFoundError("Could not read conntrack count")

    if max_val is None:
        raise FileNotFoundError("Could not read conntrack max")

    # Calculate stats
    usage_percent = (count / max_val * 100) if max_val > 0 else 0
    available = max_val - count

    stats = {
        "count": count,
        "max": max_val,
        "available": available,
        "usage_percent": round(usage_percent, 2),
    }

    # Try to get bucket info (optional)
    bucket_path = "/proc/sys/net/netfilter/nf_conntrack_buckets"
    if context.file_exists(bucket_path):
        stats["buckets"] = int(context.read_file(bucket_path).strip())

    # Try to get timeout info (optional)
    timeout_paths = {
        "tcp_established": "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established",
        "tcp_time_wait": "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait",
        "udp": "/proc/sys/net/netfilter/nf_conntrack_udp_timeout",
        "generic": "/proc/sys/net/netfilter/nf_conntrack_generic_timeout",
    }

    timeouts = {}
    for name, path in timeout_paths.items():
        if context.file_exists(path):
            try:
                timeouts[name] = int(context.read_file(path).strip())
            except (ValueError, IOError):
                pass

    if timeouts:
        stats["timeouts"] = timeouts

    return stats


def analyze_conntrack(
    stats: dict, warn_threshold: float, crit_threshold: float
) -> list:
    """Analyze connection tracking usage and return issues.

    Args:
        stats: Connection tracking statistics dict
        warn_threshold: Warning threshold (percentage)
        crit_threshold: Critical threshold (percentage)

    Returns:
        list: List of issue dictionaries
    """
    issues = []
    usage = stats["usage_percent"]

    # Check usage thresholds
    if usage >= crit_threshold:
        issues.append(
            {
                "severity": "CRITICAL",
                "metric": "conntrack_usage",
                "value": usage,
                "threshold": crit_threshold,
                "message": f"Connection tracking table nearly full: {usage:.1f}% "
                f"({stats['count']}/{stats['max']})",
            }
        )
    elif usage >= warn_threshold:
        issues.append(
            {
                "severity": "WARNING",
                "metric": "conntrack_usage",
                "value": usage,
                "threshold": warn_threshold,
                "message": f"Connection tracking table usage high: {usage:.1f}% "
                f"({stats['count']}/{stats['max']})",
            }
        )

    # Check if available slots are low (absolute number)
    if stats["available"] < 1000 and stats["max"] >= 10000:
        issues.append(
            {
                "severity": "WARNING",
                "metric": "conntrack_available",
                "value": stats["available"],
                "message": f"Only {stats['available']} connection tracking slots available",
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
        description="Monitor Linux connection tracking (conntrack) table saturation"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed timeout info"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show warnings and errors",
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=75.0,
        metavar="PERCENT",
        help="Warning threshold for usage percentage (default: 75)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=90.0,
        metavar="PERCENT",
        help="Critical threshold for usage percentage (default: 90)",
    )

    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0 or opts.warn > 100:
        output.error("--warn must be between 0 and 100")
        return 2

    if opts.crit < 0 or opts.crit > 100:
        output.error("--crit must be between 0 and 100")
        return 2

    if opts.crit <= opts.warn:
        output.error("--crit must be greater than --warn")
        return 2

    # Gather information
    try:
        stats = get_conntrack_stats(context)
    except FileNotFoundError as e:
        output.error(f"Connection tracking not available: {e}")
        return 2
    except (ValueError, IOError) as e:
        output.error(f"Error reading conntrack stats: {e}")
        return 2

    # Analyze usage
    issues = analyze_conntrack(stats, opts.warn, opts.crit)

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "conntrack": {
            "count": stats["count"],
            "max": stats["max"],
            "available": stats["available"],
            "usage_percent": stats["usage_percent"],
        },
        "issues": issues,
        "healthy": len(issues) == 0,
    }

    if opts.verbose:
        if "buckets" in stats:
            result["conntrack"]["buckets"] = stats["buckets"]
        if "timeouts" in stats:
            result["timeouts"] = stats["timeouts"]

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or issues:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or issues:
            lines = []
            lines.append("Connection Tracking Monitor")
            lines.append("=" * 50)
            lines.append("")
            lines.append(
                f"Conntrack: {stats['count']} / {stats['max']} "
                f"({stats['usage_percent']:.1f}% used)"
            )
            lines.append(f"Available: {stats['available']} slots")

            if opts.verbose:
                if "buckets" in stats:
                    lines.append(f"Hash buckets: {stats['buckets']}")

                if "timeouts" in stats:
                    lines.append("")
                    lines.append("Timeouts:")
                    for name, val in stats["timeouts"].items():
                        lines.append(f"  {name}: {val}s")

            lines.append("")

            if issues:
                for issue in issues:
                    prefix = f"[{issue['severity']}]"
                    lines.append(f"{prefix} {issue['message']}")
            else:
                lines.append("[OK] Connection tracking usage is healthy")

            print("\n".join(lines))

    # Set summary
    output.set_summary(f"usage={stats['usage_percent']:.1f}%, count={stats['count']}")

    # Determine exit code
    has_critical = any(issue["severity"] == "CRITICAL" for issue in issues)
    has_warning = any(issue["severity"] == "WARNING" for issue in issues)

    if has_critical or has_warning:
        return 1
    else:
        return 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
