#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [kernel, sysctl, config, security, performance, audit]
#   requires: []
#   privilege: user
#   related: [kernel_security, kernel_cmdline_audit, sysctl_security_audit]
#   brief: Audit kernel runtime configuration against baselines

"""
Audit kernel runtime configuration against security and performance baselines.

Checks /proc/sys kernel parameters against recommended values for production
server environments. Useful for ensuring consistent configuration across
large baremetal fleets.

Checks include:
- Network security settings (syn cookies, rp_filter, etc.)
- Memory management (swappiness, overcommit, OOM behavior)
- Performance tuning (TCP buffers, file limits, vm settings)
- Security hardening (ASLR, ptrace, dmesg restrictions)

Profiles available:
- security: Focus on security hardening
- performance: Focus on high-performance computing
- balanced: Combined security and performance (default)

Exit codes:
    0: All checked parameters meet recommendations
    1: One or more parameters don't match recommendations
    2: Error (missing /proc/sys or usage error)
"""

import argparse
import json
import os
from pathlib import Path
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Baseline configurations organized by profile
# Format: {sysctl_path: (recommended_value, comparison, description)}
# comparison: 'eq' (equal), 'ge' (>=), 'le' (<=), 'ne' (not equal)

SECURITY_BASELINE = {
    # Network security
    "net.ipv4.tcp_syncookies": ("1", "eq", "Enable SYN flood protection"),
    "net.ipv4.conf.all.rp_filter": ("1", "ge", "Enable reverse path filtering"),
    "net.ipv4.conf.default.rp_filter": ("1", "ge", "Enable reverse path filtering"),
    "net.ipv4.conf.all.accept_redirects": ("0", "eq", "Disable ICMP redirects"),
    "net.ipv4.conf.default.accept_redirects": ("0", "eq", "Disable ICMP redirects"),
    "net.ipv4.conf.all.send_redirects": ("0", "eq", "Disable sending ICMP redirects"),
    "net.ipv4.conf.default.send_redirects": ("0", "eq", "Disable sending ICMP redirects"),
    "net.ipv4.conf.all.accept_source_route": ("0", "eq", "Disable source routing"),
    "net.ipv4.conf.default.accept_source_route": ("0", "eq", "Disable source routing"),
    "net.ipv4.conf.all.log_martians": ("1", "eq", "Log spoofed packets"),
    "net.ipv4.icmp_echo_ignore_broadcasts": ("1", "eq", "Ignore broadcast ICMP"),
    "net.ipv4.icmp_ignore_bogus_error_responses": ("1", "eq", "Ignore bogus ICMP errors"),
    "net.ipv6.conf.all.accept_redirects": ("0", "eq", "Disable IPv6 ICMP redirects"),
    "net.ipv6.conf.default.accept_redirects": ("0", "eq", "Disable IPv6 ICMP redirects"),
    "net.ipv6.conf.all.accept_source_route": ("0", "eq", "Disable IPv6 source routing"),
    "net.ipv6.conf.default.accept_source_route": ("0", "eq", "Disable IPv6 source routing"),
    # Kernel security
    "kernel.randomize_va_space": ("2", "eq", "Full ASLR enabled"),
    "kernel.dmesg_restrict": ("1", "eq", "Restrict dmesg access"),
    "kernel.kptr_restrict": ("1", "ge", "Restrict kernel pointer exposure"),
    "kernel.yama.ptrace_scope": ("1", "ge", "Restrict ptrace to parent process"),
    "kernel.sysrq": ("0", "le", "Disable/restrict SysRq"),
    "kernel.core_uses_pid": ("1", "eq", "Core dumps include PID"),
    # Filesystem security
    "fs.protected_hardlinks": ("1", "eq", "Protect against hardlink attacks"),
    "fs.protected_symlinks": ("1", "eq", "Protect against symlink attacks"),
    "fs.suid_dumpable": ("0", "eq", "Disable core dumps for setuid programs"),
}

PERFORMANCE_BASELINE = {
    # TCP/Network performance
    "net.core.somaxconn": ("4096", "ge", "Socket listen backlog"),
    "net.core.netdev_max_backlog": ("5000", "ge", "Network device backlog queue"),
    "net.core.rmem_max": ("16777216", "ge", "Max receive socket buffer"),
    "net.core.wmem_max": ("16777216", "ge", "Max send socket buffer"),
    "net.ipv4.tcp_max_syn_backlog": ("4096", "ge", "SYN backlog queue size"),
    "net.ipv4.tcp_fin_timeout": ("15", "le", "TCP FIN timeout"),
    "net.ipv4.tcp_tw_reuse": ("1", "eq", "Allow TIME_WAIT socket reuse"),
    "net.ipv4.tcp_keepalive_time": ("600", "le", "TCP keepalive time"),
    "net.ipv4.tcp_keepalive_intvl": ("60", "le", "TCP keepalive interval"),
    "net.ipv4.tcp_keepalive_probes": ("5", "le", "TCP keepalive probes"),
    # Memory/VM performance
    "vm.swappiness": ("10", "le", "Reduce swap usage preference"),
    "vm.dirty_ratio": ("40", "le", "Max dirty pages percentage"),
    "vm.dirty_background_ratio": ("10", "le", "Background dirty pages flush threshold"),
    "vm.vfs_cache_pressure": ("50", "le", "Reduce inode/dentry cache reclaim pressure"),
    "vm.min_free_kbytes": ("65536", "ge", "Minimum free memory reserved for kernel"),
    # File descriptor limits
    "fs.file-max": ("2097152", "ge", "Maximum open files system-wide"),
    "fs.nr_open": ("1048576", "ge", "Maximum file descriptors per process"),
    "fs.inotify.max_user_watches": ("524288", "ge", "Inotify watches per user"),
    "fs.inotify.max_user_instances": ("1024", "ge", "Inotify instances per user"),
    # Kernel performance
    "kernel.pid_max": ("4194304", "ge", "Maximum PID value"),
    "kernel.threads-max": ("256000", "ge", "Maximum threads system-wide"),
}

BALANCED_BASELINE = {**SECURITY_BASELINE, **PERFORMANCE_BASELINE}


def sysctl_path_to_file(sysctl_path: str) -> str:
    """Convert sysctl path (net.ipv4.tcp_syncookies) to file path."""
    return "/proc/sys/" + sysctl_path.replace(".", "/")


def read_sysctl(sysctl_path: str, context: Context | None = None) -> str | None:
    """Read current value of a sysctl parameter."""
    file_path = sysctl_path_to_file(sysctl_path)
    try:
        if context is not None:
            value = context.read_file(file_path).strip()
        else:
            with open(file_path, "r") as f:
                value = f.read().strip()
        # Normalize whitespace for multi-value params like tcp_rmem
        value = " ".join(value.split())
        return value
    except FileNotFoundError:
        return None
    except PermissionError:
        return "[permission denied]"
    except IOError as e:
        return f"[error: {e}]"


def compare_values(current: str | None, expected: str, comparison: str) -> tuple[bool, str]:
    """Compare values based on comparison type."""
    if current is None or current.startswith("["):
        return False, "unreadable"

    try:
        # Handle multi-value parameters (like tcp_rmem "4096 87380 16777216")
        if " " in expected:
            # For multi-value, use string comparison
            return current == expected, "eq"

        # Try numeric comparison
        current_num = int(current)
        expected_num = int(expected)

        if comparison == "eq":
            return current_num == expected_num, comparison
        elif comparison == "ge":
            return current_num >= expected_num, comparison
        elif comparison == "le":
            return current_num <= expected_num, comparison
        elif comparison == "ne":
            return current_num != expected_num, comparison
        else:
            return current == expected, "eq"

    except ValueError:
        # Fall back to string comparison
        if comparison == "eq":
            return current == expected, comparison
        elif comparison == "ne":
            return current != expected, comparison
        else:
            return current == expected, "eq"


def audit_baseline(
    baseline: dict, verbose: bool = False, context: Context | None = None
) -> dict[str, Any]:
    """Audit current settings against baseline."""
    results = []
    passed = 0
    failed = 0
    skipped = 0

    for sysctl_path, (expected, comparison, description) in baseline.items():
        current = read_sysctl(sysctl_path, context)

        if current is None:
            status = "skipped"
            skipped += 1
            match = None
        elif current.startswith("["):
            status = "error"
            skipped += 1
            match = False
        else:
            match, _ = compare_values(current, expected, comparison)
            if match:
                status = "pass"
                passed += 1
            else:
                status = "fail"
                failed += 1

        results.append(
            {
                "param": sysctl_path,
                "current": current,
                "expected": expected,
                "comparison": comparison,
                "description": description,
                "status": status,
                "match": match,
            }
        )

    return {
        "results": results,
        "summary": {
            "total": len(baseline),
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
        },
    }


def get_fix_commands(audit_result: dict) -> list[str]:
    """Generate sysctl commands to fix failed parameters."""
    commands = []
    for r in audit_result["results"]:
        if r["status"] == "fail":
            commands.append(f"sysctl -w {r['param']}={r['expected']}")
    return commands


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all pass, 1 = failures found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit kernel runtime configuration against baselines"
    )
    parser.add_argument(
        "--profile",
        choices=["security", "performance", "balanced"],
        default="balanced",
        help="Configuration profile to audit against (default: balanced)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all parameters including passed and skipped",
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show failed parameters"
    )
    parser.add_argument(
        "--show-fixes",
        action="store_true",
        help="Show sysctl commands to fix failed parameters",
    )
    parser.add_argument(
        "--param",
        action="append",
        help="Check only specific parameter(s). Can be specified multiple times.",
    )
    opts = parser.parse_args(args)

    # Check for Linux
    if not os.path.exists("/proc/sys"):
        output.error("/proc/sys not found - requires Linux")
        return 2

    # Select baseline
    if opts.profile == "security":
        baseline = SECURITY_BASELINE
    elif opts.profile == "performance":
        baseline = PERFORMANCE_BASELINE
    else:  # balanced
        baseline = BALANCED_BASELINE

    # Filter to specific params if requested
    if opts.param:
        filtered = {}
        for p in opts.param:
            if p in baseline:
                filtered[p] = baseline[p]
        if filtered:
            baseline = filtered
        else:
            output.error("No valid parameters to check")
            return 2

    # Run audit
    audit_result = audit_baseline(baseline, verbose=opts.verbose, context=context)

    output.emit(audit_result)

    # Output results
    summary = audit_result["summary"]
    results = audit_result["results"]

    if opts.format == "json":
        print(json.dumps(audit_result, indent=2))
    else:
        if not opts.warn_only:
            print("Kernel Configuration Audit")
            print("=" * 70)
            print(
                f"Total: {summary['total']} | "
                f"Passed: {summary['passed']} | "
                f"Failed: {summary['failed']} | "
                f"Skipped: {summary['skipped']}"
            )
            print()

        # Group by status
        failures = [r for r in results if r["status"] == "fail"]
        passes = [r for r in results if r["status"] == "pass"]
        skipped_list = [r for r in results if r["status"] in ("skipped", "error")]

        if failures:
            print("FAILED CHECKS:")
            print("-" * 70)
            for r in failures:
                comp_symbol = {"eq": "=", "ge": ">=", "le": "<=", "ne": "!="}
                expected_str = f"{comp_symbol.get(r['comparison'], '=')} {r['expected']}"
                print(f"[FAIL] {r['param']}")
                print(f"       Current: {r['current']} | Expected: {expected_str}")
                if opts.verbose and r["description"]:
                    print(f"       {r['description']}")
            print()

        if opts.verbose and not opts.warn_only:
            if passes:
                print("PASSED CHECKS:")
                print("-" * 70)
                for r in passes:
                    print(f"[PASS] {r['param']} = {r['current']}")
                print()

            if skipped_list:
                print("SKIPPED (parameter not found or unreadable):")
                print("-" * 70)
                for r in skipped_list:
                    reason = r["current"] if r["current"] else "not found"
                    print(f"[SKIP] {r['param']} ({reason})")
                print()

        if not opts.warn_only:
            if summary["failed"] == 0:
                print("Status: OK - All checked parameters meet recommendations")
            else:
                print(f"Status: FAIL - {summary['failed']} parameter(s) need attention")

    # Show fix commands if requested
    if opts.show_fixes and summary["failed"] > 0:
        print()
        print("Commands to fix failed parameters:")
        print("-" * 50)
        for cmd in get_fix_commands(audit_result):
            print(f"  sudo {cmd}")
        print()
        print("To persist changes, add to /etc/sysctl.d/99-custom.conf")

    output.set_summary(f"passed={summary['passed']}, failed={summary['failed']}")

    # Exit based on failures
    return 1 if summary["failed"] > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
