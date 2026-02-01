#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [health, network, tcp, performance]
#   brief: Monitor TCP retransmission rates to detect network issues

"""
Monitor TCP retransmission rates to detect network issues on baremetal systems.

TCP retransmissions indicate packet loss, network congestion, or connectivity
problems. High retransmission rates can cause application timeouts, reduced
throughput, and connection failures.

This script reads TCP statistics from /proc/net/snmp and /proc/net/netstat
to calculate retransmission rates and detect problematic patterns.

Exit codes:
    0: No issues detected (retransmission rate within thresholds)
    1: Retransmission rate exceeds warning threshold
    2: Missing /proc files or usage error
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_proc_snmp(content: str) -> dict | None:
    """Parse /proc/net/snmp for TCP statistics."""
    stats = {}
    lines = content.strip().split("\n")

    # Lines come in pairs: header line then value line
    i = 0
    while i < len(lines) - 1:
        header_line = lines[i]
        value_line = lines[i + 1]

        if header_line.startswith("Tcp:") and value_line.startswith("Tcp:"):
            headers = header_line.split()[1:]  # Skip "Tcp:" prefix
            values = value_line.split()[1:]

            for h, v in zip(headers, values):
                try:
                    stats[h] = int(v)
                except ValueError:
                    stats[h] = 0

        i += 2

    return stats if stats else None


def parse_proc_netstat(content: str) -> dict | None:
    """Parse /proc/net/netstat for extended TCP statistics."""
    stats = {}
    lines = content.strip().split("\n")

    # Lines come in pairs: header line then value line
    i = 0
    while i < len(lines) - 1:
        header_line = lines[i]
        value_line = lines[i + 1]

        if header_line.startswith("TcpExt:") and value_line.startswith("TcpExt:"):
            headers = header_line.split()[1:]  # Skip "TcpExt:" prefix
            values = value_line.split()[1:]

            for h, v in zip(headers, values):
                try:
                    stats[h] = int(v)
                except ValueError:
                    stats[h] = 0

        i += 2

    return stats if stats else None


def analyze_retransmissions(stats: dict, warn_pct: float, crit_pct: float) -> dict:
    """Analyze retransmission rates and generate warnings."""
    issues = []
    warnings = []

    out_segs = stats.get("OutSegs", 0)
    retrans_segs = stats.get("RetransSegs", 0)

    # Calculate retransmission percentage
    retrans_pct = 0.0
    if out_segs > 0:
        retrans_pct = (retrans_segs / out_segs) * 100

    # Determine status based on retransmission percentage
    status = "healthy"
    if retrans_pct >= crit_pct:
        status = "critical"
        issues.append(
            f"TCP retransmission rate {retrans_pct:.2f}% exceeds critical threshold ({crit_pct}%)"
        )
    elif retrans_pct >= warn_pct:
        status = "warning"
        warnings.append(
            f"TCP retransmission rate {retrans_pct:.2f}% exceeds warning threshold ({warn_pct}%)"
        )

    # Check for high timeout count
    timeouts = stats.get("TCPTimeouts", 0)
    if timeouts > 1000:  # High timeout count
        warnings.append(f"High TCP timeout count: {timeouts}")

    # Check for high RST count
    out_rsts = stats.get("OutRsts", 0)
    if out_rsts > 1000:
        warnings.append(f"High RST count: {out_rsts} (may indicate connection issues)")

    return {
        "status": status,
        "retransmission_pct": round(retrans_pct, 4),
        "out_segs": out_segs,
        "retrans_segs": retrans_segs,
        "in_segs": stats.get("InSegs", 0),
        "timeouts": stats.get("TCPTimeouts", 0),
        "fast_retrans": stats.get("TCPFastRetrans", 0),
        "slow_start_retrans": stats.get("TCPSlowStartRetrans", 0),
        "out_rsts": stats.get("OutRsts", 0),
        "in_errs": stats.get("InErrs", 0),
        "spurious_rtos": stats.get("TCPSpuriousRTOs", 0),
        "issues": issues,
        "warnings": warnings,
    }


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
        description="Monitor TCP retransmission rates to detect network issues"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed information"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only output if issues are detected",
    )
    parser.add_argument(
        "--warn",
        type=float,
        default=1.0,
        metavar="PCT",
        help="Warning threshold percentage (default: 1.0)",
    )
    parser.add_argument(
        "--crit",
        type=float,
        default=5.0,
        metavar="PCT",
        help="Critical threshold percentage (default: 5.0)",
    )

    opts = parser.parse_args(args)

    if opts.warn >= opts.crit:
        output.error("Warning threshold must be less than critical threshold")
        return 2

    if opts.warn < 0 or opts.crit < 0:
        output.error("Thresholds must be non-negative")
        return 2

    # Read /proc/net/snmp
    try:
        snmp_content = context.read_file("/proc/net/snmp")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/net/snmp: {e}")
        return 2

    # Parse SNMP stats
    snmp_stats = parse_proc_snmp(snmp_content)
    if snmp_stats is None:
        output.error("Failed to parse /proc/net/snmp")
        return 2

    # Read /proc/net/netstat (optional, for extended stats)
    netstat_stats = {}
    try:
        netstat_content = context.read_file("/proc/net/netstat")
        netstat_stats = parse_proc_netstat(netstat_content) or {}
    except (FileNotFoundError, IOError):
        pass  # netstat is optional

    # Combine stats
    stats = snmp_stats.copy()
    stats.update(netstat_stats)

    # Analyze retransmissions
    analysis = analyze_retransmissions(stats, opts.warn, opts.crit)

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": analysis["status"],
        "retransmission_pct": analysis["retransmission_pct"],
        "metrics": {
            "out_segs": analysis["out_segs"],
            "retrans_segs": analysis["retrans_segs"],
            "in_segs": analysis["in_segs"],
            "timeouts": analysis["timeouts"],
            "fast_retrans": analysis["fast_retrans"],
            "slow_start_retrans": analysis["slow_start_retrans"],
            "out_rsts": analysis["out_rsts"],
            "in_errs": analysis["in_errs"],
            "spurious_rtos": analysis["spurious_rtos"],
        },
        "issues": analysis["issues"],
        "warnings": analysis["warnings"],
        "healthy": len(analysis["issues"]) == 0,
    }

    # Output handling
    if opts.format == "json":
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            print(json.dumps(result, indent=2))
    else:
        if not opts.warn_only or analysis["issues"] or analysis["warnings"]:
            lines = []
            lines.append("TCP Retransmission Monitor")
            lines.append("=" * 40)
            lines.append("")

            status_symbol = (
                "OK" if analysis["status"] == "healthy" else analysis["status"].upper()
            )
            lines.append(f"Status: [{status_symbol}]")
            lines.append("")

            lines.append("Retransmission Metrics:")
            lines.append(f"  Retransmission rate: {analysis['retransmission_pct']:.4f}%")
            lines.append(f"  Segments out:        {analysis['out_segs']:,}")
            lines.append(f"  Retransmits:         {analysis['retrans_segs']:,}")
            lines.append(f"  Segments in:         {analysis['in_segs']:,}")

            if opts.verbose:
                lines.append("")
                lines.append("Detailed Metrics:")
                lines.append(f"  TCP timeouts:        {analysis['timeouts']:,}")
                lines.append(f"  Fast retransmits:    {analysis['fast_retrans']:,}")
                lines.append(
                    f"  Slow start retrans:  {analysis['slow_start_retrans']:,}"
                )
                lines.append(f"  RST segments out:    {analysis['out_rsts']:,}")
                lines.append(f"  Errors in:           {analysis['in_errs']:,}")
                lines.append(f"  Spurious RTOs:       {analysis['spurious_rtos']:,}")

            if analysis["issues"]:
                lines.append("")
                lines.append("ISSUES:")
                for issue in analysis["issues"]:
                    lines.append(f"  [!] {issue}")

            if analysis["warnings"]:
                lines.append("")
                lines.append("WARNINGS:")
                for warning in analysis["warnings"]:
                    lines.append(f"  [*] {warning}")

            if not analysis["issues"] and not analysis["warnings"]:
                lines.append("")
                lines.append("[OK] TCP retransmission rate within thresholds")

            print("\n".join(lines))

    # Set summary
    output.set_summary(
        f"status={analysis['status']}, retrans={analysis['retransmission_pct']:.2f}%"
    )

    return 1 if analysis["issues"] else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
