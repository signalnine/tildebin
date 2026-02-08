#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, landlock, io_uring, lsm, sandbox, kernel]
#   requires: []
#   privilege: user
#   related: [security_modules, kernel_hardening_audit, seccomp_audit]
#   brief: Audit Landlock LSM and io_uring restriction configuration

"""
Audit Landlock LSM and io_uring restriction configuration.

Checks:
- /sys/kernel/security/lsm for active Linux Security Modules
- Whether Landlock is present in the active LSM list
- /proc/sys/kernel/io_uring_disabled restriction level
- /proc/sys/kernel/io_uring_group GID setting

Exit codes:
    0 - All checks pass (Landlock enabled, io_uring restricted)
    1 - Warnings found (Landlock missing or io_uring unrestricted)
    2 - Unable to read LSM configuration
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_lsm_list(lsm_content: str) -> list[str]:
    """Parse the comma-separated LSM list from /sys/kernel/security/lsm."""
    return [module.strip() for module in lsm_content.strip().split(",") if module.strip()]


def check_io_uring(context: Context) -> dict[str, Any] | None:
    """Check io_uring restriction configuration.

    Returns None if io_uring files don't exist (older kernel).
    """
    io_uring_disabled_path = "/proc/sys/kernel/io_uring_disabled"

    if not context.file_exists(io_uring_disabled_path):
        return None

    result: dict[str, Any] = {
        "disabled": None,
        "group": None,
        "status": "unknown",
        "details": [],
    }

    try:
        value = context.read_file(io_uring_disabled_path).strip()
        level = int(value)
        result["disabled"] = level

        if level == 0:
            result["status"] = "unrestricted"
            result["details"].append("io_uring allowed for all users")
        elif level == 1:
            result["status"] = "unprivileged_disabled"
            result["details"].append("io_uring disabled for unprivileged users")
            group_path = "/proc/sys/kernel/io_uring_group"
            if context.file_exists(group_path):
                try:
                    gid = context.read_file(group_path).strip()
                    result["group"] = int(gid)
                    result["details"].append(f"Allowed GID: {gid}")
                except (ValueError, FileNotFoundError, IOError):
                    pass
        elif level == 2:
            result["status"] = "fully_disabled"
            result["details"].append("io_uring disabled for all users")
    except (ValueError, FileNotFoundError, IOError):
        result["details"].append("Unable to read io_uring_disabled")

    return result


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point for LSM restriction audit.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all checks pass, 1 = warnings found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit Landlock LSM and io_uring restriction configuration"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed information"
    )

    opts = parser.parse_args(args)

    # Check if LSM file exists
    lsm_path = "/sys/kernel/security/lsm"
    if not context.file_exists(lsm_path):
        output.error("/sys/kernel/security/lsm not available")
        return 2

    # Read and parse LSM list
    try:
        lsm_content = context.read_file(lsm_path)
    except (FileNotFoundError, IOError, PermissionError):
        output.error("Unable to read /sys/kernel/security/lsm")
        return 2

    lsm_list = parse_lsm_list(lsm_content)
    landlock_enabled = "landlock" in lsm_list

    warnings = []
    if not landlock_enabled:
        warnings.append("Landlock LSM is not active")

    # Check io_uring restrictions
    io_uring = check_io_uring(context)

    if io_uring is not None and io_uring["status"] == "unrestricted":
        warnings.append("io_uring is unrestricted (allowed for all users)")

    # Build output data
    data: dict[str, Any] = {
        "lsm_list": lsm_list,
        "landlock_enabled": landlock_enabled,
        "io_uring": io_uring,
        "warnings": warnings,
    }

    output.emit(data)

    # Generate summary
    if warnings:
        output.set_summary(f"{len(warnings)} warnings found")
    else:
        output.set_summary("Landlock active, io_uring restricted")

    output.render(opts.format, "Landlock LSM and io_uring Restriction Audit")

    return 1 if warnings else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
