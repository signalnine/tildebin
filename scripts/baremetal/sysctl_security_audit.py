#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, sysctl, hardening, compliance, audit]
#   related: [kernel_hardening_audit, sysctl_drift_detector]
#   brief: Audit kernel sysctl parameters against security best practices

"""
Audit kernel sysctl parameters against security hardening best practices.

Unlike sysctl_drift_detector which compares against a user-provided baseline,
this script has built-in security recommendations based on CIS benchmarks,
STIG guidelines, and Linux kernel security best practices.

Checks cover:
- Network security (IP forwarding, ICMP, SYN flood protection)
- Kernel memory protections (ASLR, exec-shield, ptrace scope)
- Filesystem security (protected symlinks, hardlinks, core dumps)
- User namespace and privilege controls

Exit codes:
    0 - All checks pass (no security issues found)
    1 - Security issues found (one or more checks failed)
    2 - Usage error or unable to read kernel parameters
"""

import argparse
from boxctl.core.context import Context
from boxctl.core.output import Output


# Security recommendations organized by category
# Format: (parameter, recommended_value, severity, description)
# severity: 'critical', 'high', 'medium', 'low'
SECURITY_CHECKS = {
    "network_ipv4": [
        (
            "net.ipv4.ip_forward",
            "0",
            "high",
            "Disable IPv4 forwarding unless acting as router",
        ),
        (
            "net.ipv4.conf.all.send_redirects",
            "0",
            "medium",
            "Disable sending ICMP redirects",
        ),
        (
            "net.ipv4.conf.default.send_redirects",
            "0",
            "medium",
            "Disable sending ICMP redirects (default)",
        ),
        ("net.ipv4.conf.all.accept_redirects", "0", "medium", "Ignore ICMP redirects"),
        (
            "net.ipv4.conf.default.accept_redirects",
            "0",
            "medium",
            "Ignore ICMP redirects (default)",
        ),
        (
            "net.ipv4.conf.all.secure_redirects",
            "0",
            "medium",
            "Ignore secure ICMP redirects",
        ),
        (
            "net.ipv4.conf.default.secure_redirects",
            "0",
            "medium",
            "Ignore secure ICMP redirects (default)",
        ),
        (
            "net.ipv4.conf.all.accept_source_route",
            "0",
            "high",
            "Disable source routing",
        ),
        (
            "net.ipv4.conf.default.accept_source_route",
            "0",
            "high",
            "Disable source routing (default)",
        ),
        (
            "net.ipv4.conf.all.log_martians",
            "1",
            "low",
            "Log packets with impossible addresses",
        ),
        (
            "net.ipv4.conf.default.log_martians",
            "1",
            "low",
            "Log martian packets (default)",
        ),
        (
            "net.ipv4.icmp_echo_ignore_broadcasts",
            "1",
            "medium",
            "Ignore broadcast ICMP echo requests (smurf attack mitigation)",
        ),
        (
            "net.ipv4.icmp_ignore_bogus_error_responses",
            "1",
            "low",
            "Ignore bogus ICMP error responses",
        ),
        (
            "net.ipv4.conf.all.rp_filter",
            "1",
            "high",
            "Enable reverse path filtering (spoofing protection)",
        ),
        (
            "net.ipv4.conf.default.rp_filter",
            "1",
            "high",
            "Enable reverse path filtering (default)",
        ),
        ("net.ipv4.tcp_syncookies", "1", "high", "Enable SYN flood protection"),
        (
            "net.ipv4.tcp_timestamps",
            "1",
            "low",
            "Enable TCP timestamps (PAWS protection)",
        ),
    ],
    "network_ipv6": [
        (
            "net.ipv6.conf.all.forwarding",
            "0",
            "high",
            "Disable IPv6 forwarding unless acting as router",
        ),
        (
            "net.ipv6.conf.all.accept_redirects",
            "0",
            "medium",
            "Ignore IPv6 ICMP redirects",
        ),
        (
            "net.ipv6.conf.default.accept_redirects",
            "0",
            "medium",
            "Ignore IPv6 ICMP redirects (default)",
        ),
        (
            "net.ipv6.conf.all.accept_source_route",
            "0",
            "high",
            "Disable IPv6 source routing",
        ),
        (
            "net.ipv6.conf.default.accept_source_route",
            "0",
            "high",
            "Disable IPv6 source routing (default)",
        ),
        (
            "net.ipv6.conf.all.accept_ra",
            "0",
            "medium",
            "Ignore IPv6 router advertisements",
        ),
        (
            "net.ipv6.conf.default.accept_ra",
            "0",
            "medium",
            "Ignore IPv6 router advertisements (default)",
        ),
    ],
    "kernel_memory": [
        (
            "kernel.randomize_va_space",
            "2",
            "critical",
            "Enable full ASLR (Address Space Layout Randomization)",
        ),
        ("kernel.kptr_restrict", "1", "high", "Restrict kernel pointer exposure"),
        ("kernel.dmesg_restrict", "1", "medium", "Restrict access to kernel logs"),
        (
            "kernel.perf_event_paranoid",
            "2",
            "medium",
            "Restrict unprivileged access to perf events",
        ),
        (
            "kernel.yama.ptrace_scope",
            "1",
            "high",
            "Restrict ptrace to child processes only",
        ),
        (
            "vm.mmap_min_addr",
            "65536",
            "high",
            "Prevent mapping at low addresses (NULL deref protection)",
        ),
    ],
    "kernel_modules": [
        (
            "kernel.modules_disabled",
            "0",
            "low",
            "Module loading (1=disabled after boot, 0=allowed)",
        ),
        ("kernel.kexec_load_disabled", "1", "medium", "Disable kexec system call"),
    ],
    "filesystem": [
        (
            "fs.protected_symlinks",
            "1",
            "high",
            "Protect against symlink attacks in world-writable directories",
        ),
        ("fs.protected_hardlinks", "1", "high", "Protect against hardlink attacks"),
        (
            "fs.protected_fifos",
            "1",
            "medium",
            "Protect against FIFO attacks in world-writable directories",
        ),
        (
            "fs.protected_regular",
            "2",
            "medium",
            "Protect against regular file overwrites",
        ),
        ("fs.suid_dumpable", "0", "high", "Disable core dumps for setuid programs"),
    ],
    "user_namespaces": [
        (
            "kernel.unprivileged_userns_clone",
            "0",
            "medium",
            "Restrict unprivileged user namespace creation",
        ),
        (
            "kernel.unprivileged_bpf_disabled",
            "1",
            "high",
            "Disable unprivileged BPF",
        ),
        ("net.core.bpf_jit_harden", "2", "medium", "Harden BPF JIT compiler"),
    ],
}

# Category display names
CATEGORY_NAMES = {
    "network_ipv4": "Network Security (IPv4)",
    "network_ipv6": "Network Security (IPv6)",
    "kernel_memory": "Kernel Memory Protections",
    "kernel_modules": "Kernel Module Controls",
    "filesystem": "Filesystem Security",
    "user_namespaces": "User Namespace & BPF Controls",
}


def sysctl_to_path(param: str) -> str:
    """Convert sysctl parameter name to /proc/sys path."""
    return "/proc/sys/" + param.replace(".", "/")


def get_sysctl_value(context: Context, param: str) -> str | None:
    """Get the current value of a sysctl parameter."""
    path = sysctl_to_path(param)
    try:
        return context.read_file(path).strip()
    except (FileNotFoundError, IOError, PermissionError):
        return None


def audit_category(
    context: Context,
    category_name: str,
    checks: list[tuple[str, str, str, str]],
    verbose: bool = False,
) -> list[dict]:
    """Audit a category of sysctl parameters."""
    results = []

    for param, expected, severity, description in checks:
        actual = get_sysctl_value(context, param)

        if actual is None:
            status = "unavailable"
            passed = True  # Not a failure if parameter doesn't exist
        elif actual == expected:
            status = "pass"
            passed = True
        else:
            status = "fail"
            passed = False

        result = {
            "parameter": param,
            "expected": expected,
            "actual": actual,
            "severity": severity,
            "description": description,
            "status": status,
            "passed": passed,
            "category": category_name,
        }

        # In non-verbose mode, only include failures and unavailable
        if verbose or status in ("fail", "unavailable"):
            results.append(result)

    return results


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point for sysctl security audit.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all checks pass, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit kernel sysctl parameters against security best practices"
    )

    parser.add_argument(
        "-c",
        "--category",
        choices=["network", "kernel", "filesystem", "all"],
        default="all",
        help="Category to audit (default: all)",
    )

    parser.add_argument(
        "-s",
        "--severity",
        choices=["critical", "high", "medium", "low", "all"],
        default="all",
        help="Minimum severity to check (default: all)",
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show all checks including passed"
    )

    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show failed checks"
    )

    parser.add_argument(
        "-l",
        "--list-checks",
        action="store_true",
        help="List all checks without running them",
    )

    opts = parser.parse_args(args)

    # List checks mode
    if opts.list_checks:
        total = 0
        for cat_name, checks in sorted(SECURITY_CHECKS.items()):
            print(f"{cat_name}:")
            for param, expected, severity, desc in checks:
                print(f"  {param} [{severity}] = {expected} ({desc})")
                total += 1
            print()
        print(f"Total: {total} checks")
        return 0

    # Check if we can read /proc/sys
    if not context.file_exists("/proc/sys/kernel"):
        output.error("/proc/sys not available")
        return 2

    # Determine which categories to check
    categories_to_check = []
    if opts.category == "all":
        categories_to_check = list(SECURITY_CHECKS.keys())
    elif opts.category == "network":
        categories_to_check = ["network_ipv4", "network_ipv6"]
    elif opts.category == "kernel":
        categories_to_check = ["kernel_memory", "kernel_modules", "user_namespaces"]
    elif opts.category == "filesystem":
        categories_to_check = ["filesystem"]

    # Filter by severity
    severity_levels = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    min_severity = severity_levels.get(opts.severity, 3)

    # Run checks
    all_results = []
    for cat_name in categories_to_check:
        checks = SECURITY_CHECKS.get(cat_name, [])

        # Filter by severity
        if opts.severity != "all":
            checks = [
                c for c in checks if severity_levels.get(c[2], 3) <= min_severity
            ]

        results = audit_category(context, cat_name, checks, verbose=opts.verbose)
        all_results.extend(results)

    # Count results
    failures = [r for r in all_results if r["status"] == "fail"]
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    for r in failures:
        by_severity[r["severity"]].append(r)

    # Build output data
    summary = {
        "total_checks": len(all_results),
        "passed": len([r for r in all_results if r["status"] == "pass"]),
        "failed": len(failures),
        "unavailable": len([r for r in all_results if r["status"] == "unavailable"]),
        "by_severity": {
            sev: len(items) for sev, items in by_severity.items()
        },
    }
    json_output = {"summary": summary, "results": all_results}

    output.emit(json_output)

    # Output results
    if opts.format == "table":
        if opts.warn_only:
            display_results = failures
        else:
            display_results = all_results

        if not display_results:
            print("All security checks passed!")
        else:
            print(
                f"{'Status':<6} {'Severity':<10} {'Parameter':<45} {'Current':<8} {'Expected':<8}"
            )
            print("-" * 80)

            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_results = sorted(
                display_results,
                key=lambda x: (severity_order.get(x["severity"], 4), x["parameter"]),
            )

            for r in sorted_results:
                status = (
                    "PASS"
                    if r["status"] == "pass"
                    else ("N/A" if r["status"] == "unavailable" else "FAIL")
                )
                actual = r["actual"] if r["actual"] else "N/A"
                print(
                    f"{status:<6} {r['severity'].upper():<10} "
                    f"{r['parameter'][:45]:<45} {str(actual)[:8]:<8} {r['expected'][:8]:<8}"
                )
    else:
        output.render(opts.format, "Sysctl Security Audit", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    status = "issues" if failures else "secure"
    output.set_summary(f"failed={len(failures)}, status={status}")

    # Exit code based on failures
    return 1 if failures else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
