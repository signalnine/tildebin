#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [kernel, version, audit, compliance, fleet]
#   requires: [uname]
#   privilege: user
#   related: [kernel_config, kernel_cmdline_audit, boot_issues_analyzer]
#   brief: Audit kernel version and detect configuration inconsistencies

"""
Audit kernel version and detect configuration inconsistencies.

Audits the running kernel version, build information, and command-line
parameters to help identify version drift across server fleets.

Useful for:
- Detecting kernel version inconsistencies across baremetal hosts
- Identifying systems needing kernel updates
- Verifying kernel command-line parameters are consistent
- Checking for outdated or EOL kernel versions
- Auditing kernel configuration for security and performance

The script analyzes /proc/version, /proc/cmdline, and uname to gather
comprehensive kernel information.

Exit codes:
    0: Kernel information retrieved successfully, no issues detected
    1: Issues detected (warnings about kernel configuration)
    2: Error (/proc filesystem not available or usage error)
"""

import argparse
import json
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_kernel_version(context: Context) -> dict[str, Any]:
    """Get kernel version information from /proc/version and uname."""
    kernel_info = {}

    try:
        # Read /proc/version for detailed version info
        with open("/proc/version", "r") as f:
            kernel_info["proc_version"] = f.read().strip()

        # Use uname for structured information
        result = context.run(["uname", "-a"])
        kernel_info["uname_full"] = result.stdout.strip()

        # Get individual components
        result = context.run(["uname", "-r"])
        kernel_info["release"] = result.stdout.strip()

        result = context.run(["uname", "-v"])
        kernel_info["version"] = result.stdout.strip()

        result = context.run(["uname", "-m"])
        kernel_info["architecture"] = result.stdout.strip()

        result = context.run(["uname", "-s"])
        kernel_info["kernel_name"] = result.stdout.strip()

    except FileNotFoundError:
        raise ValueError("/proc/version not found (non-Linux system?)")
    except Exception as e:
        raise ValueError(f"Error getting kernel version: {e}")

    return kernel_info


def get_kernel_cmdline() -> str:
    """Get kernel command-line parameters from /proc/cmdline."""
    try:
        with open("/proc/cmdline", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""
    except Exception:
        return ""


def analyze_kernel_info(kernel_info: dict, cmdline: str) -> list[dict]:
    """Analyze kernel information and return issues."""
    issues = []

    # Check for very old kernels (< 3.x)
    release = kernel_info.get("release", "")
    if release:
        try:
            major_version = int(release.split(".")[0])
            if major_version < 3:
                issues.append(
                    {
                        "severity": "WARNING",
                        "message": f"Running very old kernel version {release} (< 3.x)",
                        "recommendation": "Consider upgrading to a modern kernel version",
                    }
                )
            elif major_version < 4:
                issues.append(
                    {
                        "severity": "INFO",
                        "message": f"Running kernel version {release} (3.x series)",
                        "recommendation": "Consider upgrading to 4.x or newer for better features",
                    }
                )
        except (ValueError, IndexError):
            pass

    # Check for missing security features in cmdline
    security_params = [
        "selinux",
        "apparmor",
        "security",
    ]

    has_security = any(param in cmdline for param in security_params)
    if not has_security and cmdline:
        issues.append(
            {
                "severity": "INFO",
                "message": "No security module detected in kernel parameters",
                "recommendation": "Consider enabling SELinux or AppArmor for enhanced security",
            }
        )

    # Check for debug/development options
    debug_options = ["debug", "nokaslr", "nosmp"]
    for opt in debug_options:
        if opt in cmdline.split():
            issues.append(
                {
                    "severity": "WARNING",
                    "message": f"Debug/development option '{opt}' found in kernel cmdline",
                    "recommendation": f"Remove '{opt}' for production systems",
                }
            )

    # Check for recommended security options
    recommended_options = {
        "mitigations=auto": "CPU vulnerability mitigations",
        "page_poison=1": "Page poisoning for debugging",
        "slab_nomerge": "SLAB hardening",
    }

    # These are informational, not warnings
    for opt, description in recommended_options.items():
        opt_key = opt.split("=")[0]
        if opt_key not in cmdline:
            issues.append(
                {
                    "severity": "INFO",
                    "message": f"Recommended option '{opt}' not in kernel cmdline",
                    "recommendation": f"Consider adding for {description}",
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
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit kernel version and configuration"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed kernel information and recommendations",
    )
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show warnings and issues (suppress normal output)",
    )
    opts = parser.parse_args(args)

    # Check for uname
    if not context.check_tool("uname"):
        output.error("uname command not found")
        return 2

    # Get kernel information
    try:
        kernel_info = get_kernel_version(context)
    except ValueError as e:
        output.error(str(e))
        return 2

    cmdline = get_kernel_cmdline()

    # Analyze for issues
    issues = analyze_kernel_info(kernel_info, cmdline)

    # Build result
    data = {
        "kernel": {
            "release": kernel_info.get("release", ""),
            "version": kernel_info.get("version", ""),
            "architecture": kernel_info.get("architecture", ""),
            "kernel_name": kernel_info.get("kernel_name", ""),
            "uname_full": kernel_info.get("uname_full", ""),
            "proc_version": kernel_info.get("proc_version", ""),
            "cmdline": cmdline,
        },
        "issues": issues,
        "issue_count": len(issues),
    }

    output.emit(data)

    # Count issues by severity
    warning_count = sum(1 for i in issues if i["severity"] == "WARNING")
    info_count = sum(1 for i in issues if i["severity"] == "INFO")

    # Output based on format
    if opts.format == "json":
        print(json.dumps(data, indent=2))
    else:
        if not opts.warn_only:
            print(f"Kernel version: {kernel_info.get('release', 'Unknown')}")
            print(f"Kernel name: {kernel_info.get('kernel_name', 'Unknown')}")

            if opts.verbose:
                print(f"Architecture: {kernel_info.get('architecture', 'Unknown')}")
                print(f"Build version: {kernel_info.get('version', 'Unknown')}")
                print(f"\nKernel parameters: {cmdline if cmdline else 'N/A'}")
                print(f"\nFull uname: {kernel_info.get('uname_full', 'Unknown')}")

        if issues:
            if not opts.warn_only:
                print(f"\n{'='*60}")
                print("ISSUES DETECTED")
                print("=" * 60)

            for issue in issues:
                # In warn-only mode, only show warnings (not INFO)
                if opts.warn_only and issue["severity"] == "INFO":
                    continue
                print(f"[{issue['severity']}] {issue['message']}")
                if opts.verbose:
                    print(f"  Recommendation: {issue['recommendation']}")

        if not issues and not opts.warn_only:
            print("\nNo issues detected.")

    output.set_summary(
        f"release={kernel_info.get('release', 'unknown')}, warnings={warning_count}, info={info_count}"
    )

    # Exit with appropriate code (only warnings count, not INFO)
    return 1 if warning_count > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
