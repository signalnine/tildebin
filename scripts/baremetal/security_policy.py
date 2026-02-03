#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [selinux, apparmor, mac, security, compliance]
#   requires: []
#   privilege: user
#   related: [file_integrity, ssl_cert_scanner]
#   brief: Monitor Linux Security Module (LSM) status

"""
Monitor Linux Security Module (LSM) status for baremetal systems.

Checks SELinux and AppArmor security policy status, detecting:
- LSM disabled or permissive modes (security risk)
- Policy violations and denials
- Missing or corrupted policy files
- Configuration drift from expected state

Returns:
    0 - Security policy is enforcing and healthy
    1 - Security issues detected (disabled, permissive, denials)
    2 - Error
"""

import argparse
import json
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def detect_active_lsm(context: Context) -> dict[str, Any]:
    """Detect which LSM is active on the system."""
    lsms = []

    # Check /sys/kernel/security/lsm for active LSMs
    if context.file_exists("/sys/kernel/security/lsm"):
        try:
            lsm_list = context.read_file("/sys/kernel/security/lsm").strip()
            lsms = [lsm.strip() for lsm in lsm_list.split(",") if lsm.strip()]
        except (IOError, OSError):
            pass

    selinux_active = context.file_exists("/sys/fs/selinux") or context.file_exists("/selinux")
    apparmor_active = context.file_exists("/sys/kernel/security/apparmor")

    return {
        "lsm_list": lsms,
        "selinux_present": selinux_active or "selinux" in lsms,
        "apparmor_present": apparmor_active or "apparmor" in lsms,
    }


def get_selinux_status(context: Context) -> dict[str, Any]:
    """Get detailed SELinux status."""
    status: dict[str, Any] = {
        "available": False,
        "enabled": False,
        "mode": "unknown",
        "policy": "unknown",
        "issues": [],
        "denials_recent": 0,
    }

    # Check if SELinux filesystem exists
    if not context.file_exists("/sys/fs/selinux") and not context.file_exists("/selinux"):
        return status

    status["available"] = True

    # Try getenforce command
    if context.check_tool("getenforce"):
        result = context.run(["getenforce"], check=False)
        if result.returncode == 0:
            mode = result.stdout.strip().lower()
            status["mode"] = mode
            status["enabled"] = mode in ["enforcing", "permissive"]
            if mode == "permissive":
                status["issues"].append({
                    "severity": "warning",
                    "message": "SELinux is in permissive mode (not enforcing)",
                })
            elif mode == "disabled":
                status["issues"].append({
                    "severity": "critical",
                    "message": "SELinux is disabled",
                })

    # Get policy type from sestatus if available
    if context.check_tool("sestatus"):
        result = context.run(["sestatus"], check=False)
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "loaded policy name" in line.lower():
                    status["policy"] = line.split(":")[-1].strip()

    # Check for recent denials using ausearch
    if context.check_tool("ausearch"):
        result = context.run(["ausearch", "-m", "AVC", "-ts", "recent"], check=False)
        if result.returncode == 0 and "denied" in result.stdout.lower():
            denial_count = result.stdout.lower().count("denied")
            status["denials_recent"] = denial_count
            if denial_count > 0:
                status["issues"].append({
                    "severity": "warning",
                    "message": f"{denial_count} AVC denial(s) in recent audit log",
                })

    return status


def get_apparmor_status(context: Context) -> dict[str, Any]:
    """Get detailed AppArmor status."""
    status: dict[str, Any] = {
        "available": False,
        "enabled": False,
        "mode": "unknown",
        "profiles_enforcing": 0,
        "profiles_complain": 0,
        "issues": [],
        "denials_recent": 0,
    }

    if not context.file_exists("/sys/kernel/security/apparmor"):
        return status

    status["available"] = True

    # Try aa-status --json
    if context.check_tool("aa-status"):
        result = context.run(["aa-status", "--json"], check=False)
        if result.returncode == 0:
            try:
                aa_data = json.loads(result.stdout)
                status["enabled"] = True

                profiles = aa_data.get("profiles", {})
                for profile, mode in profiles.items():
                    if mode == "enforce":
                        status["profiles_enforcing"] += 1
                    elif mode == "complain":
                        status["profiles_complain"] += 1
                        status["issues"].append({
                            "severity": "info",
                            "message": f"Profile in complain mode: {profile}",
                        })

                if status["profiles_enforcing"] > 0:
                    status["mode"] = "enforcing"
                elif status["profiles_complain"] > 0:
                    status["mode"] = "complain"
                else:
                    status["mode"] = "disabled"
                    status["issues"].append({
                        "severity": "critical",
                        "message": "No enforcing AppArmor profiles",
                    })

            except json.JSONDecodeError:
                # Fall back to text parsing
                result = context.run(["aa-status"], check=False)
                if result.returncode == 0:
                    status["enabled"] = True
                    for line in result.stdout.split("\n"):
                        if "profiles are in enforce mode" in line:
                            try:
                                status["profiles_enforcing"] = int(line.split()[0])
                            except (ValueError, IndexError):
                                pass
                        elif "profiles are in complain mode" in line:
                            try:
                                status["profiles_complain"] = int(line.split()[0])
                            except (ValueError, IndexError):
                                pass

                    if status["profiles_enforcing"] > 0:
                        status["mode"] = "enforcing"
                    elif status["profiles_complain"] > 0:
                        status["mode"] = "complain"
                        status["issues"].append({
                            "severity": "warning",
                            "message": "AppArmor profiles in complain mode only",
                        })

    return status


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
    parser = argparse.ArgumentParser(description="Monitor security policy status")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show warnings")
    parser.add_argument("--expected", choices=["enforcing", "permissive", "complain", "disabled"],
                        help="Expected security mode")
    parser.add_argument("--require-lsm", action="store_true", help="Require LSM to be active")
    opts = parser.parse_args(args)

    # Detect active LSM
    lsm_info = detect_active_lsm(context)
    selinux = get_selinux_status(context)
    apparmor = get_apparmor_status(context)

    # Determine primary LSM
    primary_lsm = "none"
    if selinux["enabled"]:
        primary_lsm = "selinux"
    elif apparmor["enabled"]:
        primary_lsm = "apparmor"

    # Collect all issues
    all_issues: list[dict[str, str]] = []
    overall_status = "healthy"

    if primary_lsm == "none":
        overall_status = "critical"
        all_issues.append({
            "severity": "critical",
            "message": "No MAC security policy is active",
        })
    else:
        if primary_lsm == "selinux":
            all_issues.extend(selinux["issues"])
            if selinux["mode"] == "permissive":
                overall_status = "warning"
            elif selinux["mode"] == "disabled":
                overall_status = "critical"
            elif selinux["denials_recent"] > 0:
                overall_status = "warning"
        elif primary_lsm == "apparmor":
            all_issues.extend(apparmor["issues"])
            if apparmor["mode"] == "complain":
                overall_status = "warning"
            elif apparmor["profiles_enforcing"] == 0:
                overall_status = "critical"
            elif apparmor["denials_recent"] > 0:
                overall_status = "warning"

    # Check against expected mode
    if opts.expected:
        current_mode = selinux["mode"] if primary_lsm == "selinux" else apparmor["mode"]
        if current_mode != opts.expected:
            all_issues.append({
                "severity": "warning",
                "message": f"Mode mismatch: expected {opts.expected}, got {current_mode}",
            })
            if overall_status == "healthy":
                overall_status = "warning"

    # Build output data
    data: dict[str, Any] = {
        "primary_lsm": primary_lsm,
        "lsm_list": lsm_info["lsm_list"],
        "overall_status": overall_status,
        "issues": all_issues,
        "selinux": {
            "available": selinux["available"],
            "enabled": selinux["enabled"],
            "mode": selinux["mode"],
            "policy": selinux["policy"],
            "denials_recent": selinux["denials_recent"],
        },
        "apparmor": {
            "available": apparmor["available"],
            "enabled": apparmor["enabled"],
            "mode": apparmor["mode"],
            "profiles_enforcing": apparmor["profiles_enforcing"],
            "profiles_complain": apparmor["profiles_complain"],
            "denials_recent": apparmor["denials_recent"],
        },
    }

    output.emit(data)

    # Set summary
    if primary_lsm == "none":
        output.set_summary("No security policy active")
    elif overall_status == "healthy":
        mode = selinux["mode"] if primary_lsm == "selinux" else apparmor["mode"]
        output.set_summary(f"{primary_lsm.upper()} {mode}")
    else:
        output.set_summary(f"{len(all_issues)} issue(s) detected")

    # Determine exit code
    if opts.require_lsm and primary_lsm == "none":

        output.render(opts.format, "Monitor Linux Security Module (LSM) status")
        return 1

    if overall_status == "healthy":

        output.render(opts.format, "Monitor Linux Security Module (LSM) status")
        return 0
    elif overall_status in ["warning", "critical"]:

        output.render(opts.format, "Monitor Linux Security Module (LSM) status")
        return 1
    else:

        output.render(opts.format, "Monitor Linux Security Module (LSM) status")
        return 2


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
