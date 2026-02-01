#!/usr/bin/env python3
# boxctl:
#   category: baremetal/system
#   tags: [health, entropy, crypto, security, random]
#   brief: Monitor system entropy pool levels

"""
Monitor system entropy pool levels for cryptographic operations.

Monitors the available entropy in the kernel's random number generator pool.
Low entropy can cause blocking in applications that use /dev/random and
performance degradation for TLS/SSL operations.

Critical for:
- High-traffic TLS/SSL servers that consume entropy rapidly
- Virtualized environments where entropy sources are limited
- Headless servers without keyboard/mouse input
- Systems generating many cryptographic keys or certificates

The script reads from /proc/sys/kernel/random/ to check:
- entropy_avail: Current entropy pool size (bits)
- poolsize: Maximum entropy pool capacity
- read/write wakeup thresholds

Exit codes:
    0 - Entropy levels are healthy
    1 - Low entropy detected (warning or critical)
    2 - Usage error or /proc filesystem not available
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


RANDOM_BASE = "/proc/sys/kernel/random"


def get_entropy_stats(context: Context) -> dict[str, Any] | None:
    """
    Gather all entropy statistics.

    Returns dict with entropy stats or None if unavailable.
    """
    try:
        entropy_avail = int(context.read_file(f"{RANDOM_BASE}/entropy_avail").strip())
        poolsize = int(context.read_file(f"{RANDOM_BASE}/poolsize").strip())
    except (FileNotFoundError, ValueError, PermissionError):
        return None

    # read/write_wakeup_threshold may not exist on newer kernels (5.6+)
    try:
        read_wakeup = int(context.read_file(f"{RANDOM_BASE}/read_wakeup_threshold").strip())
    except (FileNotFoundError, ValueError, PermissionError):
        read_wakeup = 64  # Default

    try:
        write_wakeup = int(context.read_file(f"{RANDOM_BASE}/write_wakeup_threshold").strip())
    except (FileNotFoundError, ValueError, PermissionError):
        write_wakeup = 896  # Default

    # Calculate percentage
    entropy_percent = (entropy_avail / poolsize * 100) if poolsize > 0 else 0

    return {
        "entropy_avail": entropy_avail,
        "poolsize": poolsize,
        "entropy_percent": round(entropy_percent, 2),
        "read_wakeup_threshold": read_wakeup,
        "write_wakeup_threshold": write_wakeup
    }


def check_rng_sources(context: Context) -> dict[str, Any]:
    """Check if hardware RNG and entropy daemons are available."""
    rng_info = {
        "hw_rng_available": False,
        "hw_rng_name": None,
        "rngd_running": False,
        "haveged_running": False
    }

    # Check for hardware RNG device
    if context.file_exists("/dev/hwrng"):
        rng_info["hw_rng_available"] = True
        try:
            rng_info["hw_rng_name"] = context.read_file(
                "/sys/class/misc/hw_random/rng_current"
            ).strip()
        except (FileNotFoundError, PermissionError):
            pass

    # Check for rngd or haveged processes
    proc_dirs = context.glob("[0-9]*", root="/proc")
    for proc_dir in proc_dirs:
        try:
            comm = context.read_file(f"{proc_dir}/comm").strip()
            if comm == "rngd":
                rng_info["rngd_running"] = True
            elif comm == "haveged":
                rng_info["haveged_running"] = True
        except (FileNotFoundError, PermissionError):
            continue

    return rng_info


def analyze_entropy(stats: dict[str, Any], warn_threshold: int,
                    crit_threshold: int) -> list[dict[str, Any]]:
    """Analyze entropy levels and return issues."""
    issues = []
    entropy = stats["entropy_avail"]

    if entropy <= crit_threshold:
        issues.append({
            "severity": "CRITICAL",
            "metric": "entropy_avail",
            "value": entropy,
            "threshold": crit_threshold,
            "message": f"Entropy critically low: {entropy} bits - "
                      f"/dev/random may block, crypto operations affected"
        })
    elif entropy <= warn_threshold:
        issues.append({
            "severity": "WARNING",
            "metric": "entropy_avail",
            "value": entropy,
            "threshold": warn_threshold,
            "message": f"Entropy low: {entropy} bits - "
                      f"consider installing rng-tools or haveged"
        })

    # Check if entropy is below read wakeup threshold
    if entropy < stats["read_wakeup_threshold"]:
        issues.append({
            "severity": "WARNING",
            "metric": "read_wakeup",
            "value": entropy,
            "threshold": stats["read_wakeup_threshold"],
            "message": f"Entropy below read wakeup threshold: {entropy} < "
                      f"{stats['read_wakeup_threshold']} bits - "
                      f"processes reading /dev/random will block"
        })

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = low entropy, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor system entropy pool levels"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show RNG sources and daemon status")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show warnings and errors")
    parser.add_argument("--warn", type=int, default=256, metavar="BITS",
                        help="Warning threshold (default: 256)")
    parser.add_argument("--crit", type=int, default=100, metavar="BITS",
                        help="Critical threshold (default: 100)")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0:
        output.error("--warn must be positive")
        return 2
    if opts.crit < 0:
        output.error("--crit must be positive")
        return 2
    if opts.crit >= opts.warn:
        output.error("--crit must be less than --warn")
        return 2

    # Check if /proc filesystem available
    if not context.file_exists(RANDOM_BASE):
        output.error(f"{RANDOM_BASE} not found (non-Linux system?)")
        return 2

    # Get entropy stats
    stats = get_entropy_stats(context)
    if stats is None:
        output.error("Could not read entropy information")
        return 2

    # Get RNG info if verbose
    rng_info = None
    if opts.verbose:
        rng_info = check_rng_sources(context)

    # Analyze entropy
    issues = analyze_entropy(stats, opts.warn, opts.crit)

    # Emit data
    data = {
        "entropy": {
            "available": stats["entropy_avail"],
            "pool_size": stats["poolsize"],
            "percent": stats["entropy_percent"],
            "read_wakeup_threshold": stats["read_wakeup_threshold"],
            "write_wakeup_threshold": stats["write_wakeup_threshold"]
        },
        "issues": issues
    }

    if rng_info:
        data["rng"] = rng_info

    output.emit(data)

    # Set summary
    entropy = stats["entropy_avail"]
    if any(i["severity"] == "CRITICAL" for i in issues):
        output.set_summary(f"CRITICAL: Entropy at {entropy} bits")
    elif any(i["severity"] == "WARNING" for i in issues):
        output.set_summary(f"WARNING: Entropy at {entropy} bits")
    else:
        output.set_summary(f"Entropy OK: {entropy}/{stats['poolsize']} bits "
                          f"({stats['entropy_percent']}%)")

    # Return code
    has_critical = any(i["severity"] == "CRITICAL" for i in issues)
    has_warning = any(i["severity"] == "WARNING" for i in issues)

    if has_critical or has_warning:
        return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
