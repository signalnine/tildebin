#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [packages, security, updates, vulnerabilities, patching]
#   requires: []
#   privilege: user
#   related: [file_integrity, security_policy]
#   brief: Audit system packages for pending security updates

"""
Audit system packages for pending security updates.

Checks for available security updates on Debian/Ubuntu (apt) and
RHEL/CentOS/Fedora (dnf/yum) systems. Identifies packages with
known security vulnerabilities that need patching.

Returns:
    0 - No security updates pending
    1 - Security updates available or issues detected
    2 - Error (unsupported package manager)
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def detect_package_manager(context: Context) -> str | None:
    """Detect the system's package manager."""
    if context.file_exists("/usr/bin/apt") or context.file_exists("/usr/bin/apt-get"):
        return "apt"
    if context.file_exists("/usr/bin/dnf"):
        return "dnf"
    if context.file_exists("/usr/bin/yum"):
        return "yum"
    return None


def get_apt_security_updates(context: Context) -> tuple[list[dict[str, Any]], list[str]]:
    """Get security updates for apt-based systems."""
    updates = []
    errors = []

    # Get list of upgradable packages
    result = context.run(["apt", "list", "--upgradable"], check=False)

    if result.returncode != 0:
        errors.append(f"Failed to list upgradable packages: {result.stderr}")
        return updates, errors

    # Parse output
    for line in result.stdout.strip().split("\n"):
        if not line or line.startswith("Listing"):
            continue

        # Format: package/source version [arch]
        match = re.match(r"^([^/]+)/(\S+)\s+(\S+)\s+(\S+)", line)
        if match:
            package = match.group(1)
            source = match.group(2)
            new_version = match.group(3)
            arch = match.group(4)

            # Check if it's a security update
            is_security = "-security" in source or "security" in source.lower()

            if is_security:
                updates.append({
                    "package": package,
                    "new_version": new_version,
                    "source": source,
                    "arch": arch,
                    "severity": "security",
                })

    return updates, errors


def get_dnf_security_updates(context: Context) -> tuple[list[dict[str, Any]], list[str]]:
    """Get security updates for dnf-based systems."""
    updates = []
    errors = []

    # Check for security updates
    result = context.run(["dnf", "updateinfo", "list", "security", "--available", "-q"], check=False)

    if result.returncode != 0:
        errors.append(f"Failed to check security updates: {result.stderr}")
        return updates, errors

    # Parse dnf updateinfo output
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 3:
            # Format: ADVISORY-ID SEVERITY PACKAGE
            if parts[0].startswith(("RHSA", "RHBA", "RHEA", "CESA", "FEDORA")):
                advisory = parts[0]
                severity = parts[1] if len(parts) > 2 else "unknown"
                package = parts[2] if len(parts) > 2 else parts[1]
            else:
                package = parts[0]
                advisory = ""
                severity = "security"

            updates.append({
                "package": package,
                "advisory": advisory,
                "severity": severity.lower(),
                "new_version": parts[1] if len(parts) > 1 else "unknown",
            })

    return updates, errors


def get_yum_security_updates(context: Context) -> tuple[list[dict[str, Any]], list[str]]:
    """Get security updates for yum-based systems."""
    updates = []
    errors = []

    result = context.run(["yum", "updateinfo", "list", "security", "--available", "-q"], check=False)

    if result.returncode != 0:
        errors.append(f"Failed to check security updates: {result.stderr}")
        return updates, errors

    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 2:
            package = parts[0]
            version = parts[1] if len(parts) > 1 else "unknown"

            updates.append({
                "package": package,
                "new_version": version,
                "severity": "security",
            })

    return updates, errors


def categorize_severity(updates: list[dict[str, Any]]) -> dict[str, int]:
    """Categorize updates by severity."""
    categories = {
        "critical": 0,
        "important": 0,
        "moderate": 0,
        "low": 0,
        "security": 0,
    }

    for update in updates:
        severity = update.get("severity", "security").lower()
        if severity in categories:
            categories[severity] += 1
        elif "critical" in severity or "crit" in severity:
            categories["critical"] += 1
        elif "important" in severity or "high" in severity:
            categories["important"] += 1
        elif "moderate" in severity or "medium" in severity:
            categories["moderate"] += 1
        elif "low" in severity:
            categories["low"] += 1
        else:
            categories["security"] += 1

    return categories


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no updates, 1 = updates found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Audit packages for security updates")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show output if updates pending")
    parser.add_argument("--critical-only", action="store_true", help="Only alert for critical/important updates")
    parser.add_argument("--package-manager", choices=["apt", "dnf", "yum", "auto"], default="auto")
    opts = parser.parse_args(args)

    # Detect or use specified package manager
    if opts.package_manager == "auto":
        pkg_mgr = detect_package_manager(context)
        if pkg_mgr is None:
            output.error("Could not detect package manager")
            output.error("Supported: apt (Debian/Ubuntu), dnf/yum (RHEL/Fedora)")
            return 2
    else:
        pkg_mgr = opts.package_manager

    # Check for required tools
    if not context.check_tool(pkg_mgr):
        output.error(f"{pkg_mgr} not found in PATH")
        return 2

    # Get security updates
    if pkg_mgr == "apt":
        updates, errors = get_apt_security_updates(context)
    elif pkg_mgr == "dnf":
        updates, errors = get_dnf_security_updates(context)
    elif pkg_mgr == "yum":
        updates, errors = get_yum_security_updates(context)
    else:
        output.error(f"Unsupported package manager: {pkg_mgr}")
        return 2

    # Categorize by severity
    categories = categorize_severity(updates)

    # Build output
    output.emit({
        "package_manager": pkg_mgr,
        "total_updates": len(updates),
        "categories": categories,
        "updates": updates if opts.verbose else [],
        "errors": errors,
        "has_critical": categories.get("critical", 0) > 0 or categories.get("important", 0) > 0,
    })

    if not updates:
        output.set_summary("No security updates pending")
    else:
        output.set_summary(f"{len(updates)} security updates pending")

    # Determine exit code
    if errors:
        return 1

    if not updates:
        return 0

    if opts.critical_only:
        if categories["critical"] > 0 or categories["important"] > 0:
            return 1
        return 0

    return 1


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
