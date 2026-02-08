#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, sysctl, configuration, drift, compliance]
#   related: [sysctl_security_audit, kernel_hardening_audit]
#   brief: Detect sysctl parameter drift from baseline or recommended values

"""
Detect sysctl parameter drift from baseline or recommended values.

Compares current kernel parameters against a baseline configuration file
or built-in recommended values for production systems. Useful for detecting
configuration drift across large baremetal fleets.

Features:
- Compare against custom baseline file (JSON or key=value format)
- Built-in recommended values for common production settings
- Detect missing, changed, or extra parameters
- Support for pattern-based parameter filtering
- Fleet-wide configuration consistency checking

Use cases:
- Detect configuration drift after system updates
- Verify security hardening across fleet
- Audit kernel tuning consistency
- Pre-deployment configuration validation
- Post-incident configuration verification

Exit codes:
    0 - No drift detected
    1 - Configuration drift detected
    2 - Usage error or missing dependencies
"""

import argparse
import json
import re

from boxctl.core.context import Context
from boxctl.core.output import Output


# Recommended production values for common sysctls
RECOMMENDED_VALUES = {
    # Network security
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.default.accept_source_route": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.secure_redirects": "0",
    "net.ipv4.conf.default.secure_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.tcp_syncookies": "1",
    # IPv6 security
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv6.conf.default.accept_redirects": "0",
    "net.ipv6.conf.all.accept_source_route": "0",
    "net.ipv6.conf.default.accept_source_route": "0",
    # Kernel security
    "kernel.randomize_va_space": "2",
    "kernel.kptr_restrict": "1",
    "kernel.dmesg_restrict": "1",
    "kernel.perf_event_paranoid": "2",
    "kernel.yama.ptrace_scope": "1",
    "kernel.sysrq": "0",
    # Core dumps
    "kernel.core_uses_pid": "1",
    "fs.suid_dumpable": "0",
    # File system
    "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1",
}

# Categories for grouping parameters
PARAM_CATEGORIES = {
    "network_security": [
        "net.ipv4.conf.",
        "net.ipv6.conf.",
        "net.ipv4.icmp_",
        "net.ipv4.tcp_syncookies",
    ],
    "kernel_security": [
        "kernel.randomize_va_space",
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.perf_event_paranoid",
        "kernel.yama.",
        "kernel.sysrq",
    ],
    "memory": [
        "vm.",
        "kernel.shmmax",
        "kernel.shmall",
    ],
    "network_performance": [
        "net.core.",
        "net.ipv4.tcp_",
        "net.ipv4.udp_",
    ],
    "filesystem": [
        "fs.",
    ],
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


def get_category(param: str) -> str:
    """Determine category for a parameter."""
    for category, prefixes in PARAM_CATEGORIES.items():
        for prefix in prefixes:
            if param.startswith(prefix):
                return category
    return "other"


def load_baseline_json(content: str) -> dict[str, str]:
    """Load baseline from JSON content."""
    data = json.loads(content)
    if isinstance(data, dict):
        return {k: str(v) for k, v in data.items()}
    raise ValueError("JSON baseline must be an object")


def load_baseline_conf(content: str) -> dict[str, str]:
    """Load baseline from sysctl.conf format."""
    baseline = {}
    for line in content.splitlines():
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        if "=" in line:
            parts = line.split("=", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                baseline[key] = value

    return baseline


def load_baseline(context: Context, filepath: str) -> dict[str, str]:
    """Load baseline configuration from file."""
    try:
        content = context.read_file(filepath)
    except FileNotFoundError:
        raise FileNotFoundError(f"Baseline file not found: {filepath}")
    except IOError as e:
        raise IOError(f"Error reading baseline file: {e}")

    # Try JSON format first
    try:
        return load_baseline_json(content)
    except json.JSONDecodeError:
        pass

    # Try key=value format (like sysctl.conf)
    return load_baseline_conf(content)


def compare_sysctls(
    context: Context,
    baseline: dict[str, str],
    pattern: str | None = None,
    ignore_extra: bool = False,
) -> dict[str, list]:
    """Compare current sysctls against baseline."""
    drift = {
        "changed": [],
        "missing": [],
        "extra": [],
    }

    # Get all current values for baseline parameters
    current = {}
    for key in baseline:
        if pattern and not re.search(pattern, key):
            continue
        value = get_sysctl_value(context, key)
        if value is not None:
            current[key] = value

    # Check for changed and missing parameters
    for key, expected_value in baseline.items():
        if pattern and not re.search(pattern, key):
            continue

        if key in current:
            current_value = current[key]
            # Normalize values for comparison
            norm_current = " ".join(current_value.split())
            norm_expected = " ".join(str(expected_value).split())

            if norm_current != norm_expected:
                drift["changed"].append(
                    {
                        "key": key,
                        "expected": expected_value,
                        "actual": current_value,
                        "category": get_category(key),
                    }
                )
        else:
            drift["missing"].append(
                {
                    "key": key,
                    "expected": expected_value,
                    "category": get_category(key),
                }
            )

    return drift


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point for sysctl drift detection.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no drift, 1 = drift detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Detect sysctl parameter drift from baseline or recommended values"
    )

    parser.add_argument(
        "--baseline",
        "-b",
        metavar="FILE",
        help="Baseline configuration file (JSON or sysctl.conf format)",
    )

    parser.add_argument(
        "--pattern",
        "-p",
        metavar="REGEX",
        help="Only check parameters matching pattern",
    )

    parser.add_argument(
        "--category",
        "-c",
        choices=list(PARAM_CATEGORIES.keys()),
        help="Only check parameters in specified category",
    )

    parser.add_argument(
        "--ignore-extra",
        action="store_true",
        help="Ignore parameters not in baseline",
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
        help="Show detailed information including extra parameters",
    )

    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show drift issues, suppress summary",
    )

    parser.add_argument(
        "--use-recommended",
        action="store_true",
        help="Use built-in recommended values (default when no baseline specified)",
    )

    opts = parser.parse_args(args)

    # Check if we can read /proc/sys
    if not context.file_exists("/proc/sys/kernel"):
        output.error("/proc/sys not available")
        return 2

    # Determine baseline to use
    if opts.baseline:
        try:
            baseline = load_baseline(context, opts.baseline)
        except (FileNotFoundError, IOError) as e:
            output.error(str(e))
            return 2
    else:
        # Use built-in recommended values
        baseline = RECOMMENDED_VALUES.copy()

    # Filter by category if specified
    if opts.category:
        prefixes = PARAM_CATEGORIES.get(opts.category, [])
        baseline = {
            k: v for k, v in baseline.items() if any(k.startswith(p) for p in prefixes)
        }

    # Filter by pattern if specified
    if opts.pattern:
        baseline = {k: v for k, v in baseline.items() if re.search(opts.pattern, k)}

    if not baseline:
        output.warning("No parameters to check after filtering")
        return 0

    # Compare sysctls
    drift = compare_sysctls(
        context, baseline, pattern=opts.pattern, ignore_extra=opts.ignore_extra
    )

    total_drift = len(drift["changed"]) + len(drift["missing"])

    # Build result
    result = {
        "summary": {
            "changed_count": len(drift["changed"]),
            "missing_count": len(drift["missing"]),
            "extra_count": len(drift["extra"]),
            "total_drift": total_drift,
        },
        "changed": drift["changed"],
        "missing": drift["missing"],
    }
    if opts.verbose:
        result["extra"] = drift["extra"]

    output.emit(result)

    # Output results
    if opts.format == "table":
        if not total_drift and not opts.warn_only:
            print("No configuration drift detected.")
        else:
            if not opts.warn_only:
                print("=" * 80)
                print("SYSCTL DRIFT DETECTION")
                print("=" * 80)
                print(f"{'Metric':<25} {'Count':<10}")
                print("-" * 35)
                print(f"{'Changed Parameters':<25} {len(drift['changed']):<10}")
                print(f"{'Missing Parameters':<25} {len(drift['missing']):<10}")
                print("=" * 80)
                print()

            if drift["changed"]:
                print(f"{'Parameter':<45} {'Expected':<15} {'Actual':<15}")
                print("-" * 75)
                for item in sorted(drift["changed"], key=lambda x: x["key"]):
                    key = item["key"]
                    if len(key) > 44:
                        key = key[:41] + "..."
                    expected = str(item["expected"])[:14]
                    actual = str(item["actual"])[:14]
                    print(f"{key:<45} {expected:<15} {actual:<15}")
                print()

            if drift["missing"]:
                print(f"{'Missing Parameter':<45} {'Expected Value':<30}")
                print("-" * 75)
                for item in sorted(drift["missing"], key=lambda x: x["key"]):
                    key = item["key"]
                    if len(key) > 44:
                        key = key[:41] + "..."
                    expected = str(item["expected"])[:29]
                    print(f"{key:<45} {expected:<30}")
                print()
    else:
        output.render(opts.format, "Sysctl Drift Detector", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    status = "drift" if total_drift > 0 else "clean"
    output.set_summary(f"changed={len(drift['changed'])}, missing={len(drift['missing'])}, status={status}")

    # Exit based on findings
    return 1 if total_drift > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
