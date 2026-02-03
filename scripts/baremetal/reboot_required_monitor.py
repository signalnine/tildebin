#!/usr/bin/env python3
# boxctl:
#   category: baremetal/boot
#   tags: [health, boot, reboot, maintenance]
#   requires: []
#   privilege: optional
#   related: [boot_issues_analyzer, grub_config_audit, firmware_inventory]
#   brief: Monitor system reboot requirements

"""
Monitor system reboot requirements for large-scale baremetal environments.

Checks if a system requires a reboot due to:
- Kernel version mismatch (running vs installed)
- /var/run/reboot-required (Debian/Ubuntu)
- needs-restarting (RHEL/CentOS/Fedora)
- Libraries requiring restart (deleted files in use)
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_running_kernel(context: Context) -> str | None:
    """Get the currently running kernel version."""
    try:
        result = context.run(["uname", "-r"], check=False)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def get_installed_kernels(context: Context) -> list[str]:
    """Get list of installed kernel versions."""
    kernels = []

    try:
        vmlinuz_files = context.glob("vmlinuz-*", "/boot")
        for vmlinuz in vmlinuz_files:
            # Extract version from vmlinuz-<version>
            filename = vmlinuz.split("/")[-1]
            version = filename.replace("vmlinuz-", "")
            if version and not version.endswith(".old"):
                kernels.append(version)

        # Sort by version (roughly)
        kernels.sort(reverse=True)
    except Exception:
        pass

    return kernels


def check_debian_reboot_required(context: Context) -> dict[str, Any]:
    """Check Debian/Ubuntu reboot-required flag."""
    result = {
        "required": False,
        "packages": [],
    }

    reboot_required_path = "/var/run/reboot-required"
    pkgs_path = "/var/run/reboot-required.pkgs"

    if context.file_exists(reboot_required_path):
        result["required"] = True

    if context.file_exists(pkgs_path):
        try:
            content = context.read_file(pkgs_path)
            result["packages"] = [line.strip() for line in content.split("\n") if line.strip()]
        except Exception:
            pass

    return result


def check_rhel_needs_restarting(context: Context) -> dict[str, Any]:
    """Check RHEL/CentOS/Fedora needs-restarting."""
    result = {
        "available": False,
        "reboot_required": False,
        "services": [],
    }

    if not context.check_tool("needs-restarting"):
        return result

    try:
        # Check for reboot requirement
        proc = context.run(["needs-restarting", "-r"], check=False)
        result["available"] = True

        # Exit code 1 means reboot required
        if proc.returncode == 1:
            result["reboot_required"] = True

        # Get services needing restart
        proc_services = context.run(["needs-restarting", "-s"], check=False)
        if proc_services.returncode == 0:
            result["services"] = [
                s.strip() for s in proc_services.stdout.strip().split("\n")
                if s.strip()
            ]
    except Exception:
        pass

    return result


def check_kernel_mismatch(
    running_kernel: str | None,
    installed_kernels: list[str],
) -> dict[str, Any]:
    """Check if running kernel differs from newest installed."""
    result = {
        "mismatch": False,
        "running": running_kernel,
        "newest_installed": None,
        "available_kernels": installed_kernels[:5],
    }

    if not running_kernel or not installed_kernels:
        return result

    result["newest_installed"] = installed_kernels[0] if installed_kernels else None

    if installed_kernels and running_kernel != installed_kernels[0]:
        result["mismatch"] = True

    return result


def check_deleted_libraries(context: Context) -> dict[str, Any]:
    """Check for processes using deleted libraries."""
    result = {
        "processes": [],
        "count": 0,
    }

    if not context.check_tool("lsof"):
        return result

    try:
        proc = context.run(["lsof", "+L1"], check=False)

        if proc.returncode == 0:
            lines = proc.stdout.strip().split("\n")[1:]  # Skip header
            deleted_procs = set()

            for line in lines:
                parts = line.split()
                if len(parts) >= 9:
                    proc_name = parts[0]
                    pid = parts[1]
                    filename = parts[-1] if len(parts) > 8 else ""

                    # Look for deleted .so files
                    if ".so" in filename or "(deleted)" in line:
                        deleted_procs.add(f"{proc_name}({pid})")

            result["processes"] = list(deleted_procs)[:20]
            result["count"] = len(deleted_procs)

    except Exception:
        pass

    return result


def analyze_reboot_status(
    kernel_info: dict,
    debian_info: dict,
    rhel_info: dict,
    deleted_libs: dict,
) -> dict[str, Any]:
    """Analyze all checks and determine reboot status."""
    issues = []
    reboot_required = False
    reboot_recommended = False

    # Check kernel mismatch
    if kernel_info["mismatch"]:
        reboot_required = True
        issues.append({
            "severity": "WARNING",
            "category": "kernel",
            "message": f"Kernel update pending: running {kernel_info['running']}, "
                      f"newest installed {kernel_info['newest_installed']}",
            "recommendation": "Schedule a reboot to apply kernel update",
        })

    # Check Debian reboot-required
    if debian_info["required"]:
        reboot_required = True
        pkg_list = ", ".join(debian_info["packages"][:5]) if debian_info["packages"] else "unknown"
        issues.append({
            "severity": "WARNING",
            "category": "packages",
            "message": f"System reboot required (packages: {pkg_list})",
            "recommendation": "Schedule a reboot to complete package updates",
        })

    # Check RHEL needs-restarting
    if rhel_info["available"] and rhel_info["reboot_required"]:
        reboot_required = True
        issues.append({
            "severity": "WARNING",
            "category": "packages",
            "message": "System reboot required (needs-restarting)",
            "recommendation": "Schedule a reboot to complete package updates",
        })

    if rhel_info["available"] and rhel_info["services"]:
        reboot_recommended = True
        svc_list = ", ".join(rhel_info["services"][:5])
        issues.append({
            "severity": "INFO",
            "category": "services",
            "message": f"Services need restart: {svc_list}",
            "recommendation": "Restart affected services or schedule a reboot",
        })

    # Check deleted libraries
    if deleted_libs["count"] > 0:
        reboot_recommended = True
        proc_list = ", ".join(deleted_libs["processes"][:5])
        issues.append({
            "severity": "INFO",
            "category": "libraries",
            "message": f"{deleted_libs['count']} process(es) using deleted libraries: {proc_list}",
            "recommendation": "Restart affected services or schedule a reboot",
        })

    # Determine overall status
    if reboot_required:
        status = "REBOOT_REQUIRED"
    elif reboot_recommended:
        status = "REBOOT_RECOMMENDED"
    else:
        status = "OK"

    return {
        "status": status,
        "reboot_required": reboot_required,
        "reboot_recommended": reboot_recommended,
        "issues": issues,
    }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no reboot needed, 1 = reboot required/recommended, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor system reboot requirements")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for uname (basic requirement)
    if not context.check_tool("uname"):
        output.error("uname not found - basic Linux tools required")

        output.render(opts.format, "Monitor system reboot requirements")
        return 2

    # Gather system information
    running_kernel = get_running_kernel(context)
    if not running_kernel:
        output.error("Could not determine running kernel version")

        output.render(opts.format, "Monitor system reboot requirements")
        return 2

    installed_kernels = get_installed_kernels(context)

    # Run all checks
    kernel_info = check_kernel_mismatch(running_kernel, installed_kernels)
    debian_info = check_debian_reboot_required(context)
    rhel_info = check_rhel_needs_restarting(context)
    deleted_libs = check_deleted_libraries(context)

    # Analyze results
    analysis = analyze_reboot_status(
        kernel_info, debian_info, rhel_info, deleted_libs
    )

    # Build output
    output.emit({
        "status": analysis["status"],
        "reboot_required": analysis["reboot_required"],
        "reboot_recommended": analysis["reboot_recommended"],
        "kernel": kernel_info,
        "debian_reboot_required": debian_info,
        "rhel_needs_restarting": rhel_info,
        "deleted_libraries": deleted_libs,
        "issues": analysis["issues"],
    })

    # Set summary
    if analysis["status"] == "REBOOT_REQUIRED":
        output.set_summary("Reboot required")
    elif analysis["status"] == "REBOOT_RECOMMENDED":
        output.set_summary("Reboot recommended")
    else:
        output.set_summary("No reboot needed")

    # Exit code based on status
    if analysis["reboot_required"] or analysis["reboot_recommended"]:

        output.render(opts.format, "Monitor system reboot requirements")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
