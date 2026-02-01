#!/usr/bin/env python3
# boxctl:
#   category: baremetal/boot
#   tags: [health, boot, security, grub]
#   requires: []
#   privilege: optional
#   related: [efi_boot_audit, boot_issues_analyzer, reboot_required_monitor]
#   brief: Audit GRUB bootloader configuration for security

"""
Audit GRUB bootloader configuration for security and consistency.

Checks performed:
- GRUB configuration file presence and permissions
- Bootloader password protection status
- Kernel command line parameters audit
- Timeout and default boot entry settings
- Security-related boot parameters (IOMMU, KASLR, mitigations)
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Paths to check
GRUB_DIRS = ["/boot/grub2", "/boot/grub"]
GRUB_DEFAULT_PATHS = ["/etc/default/grub", "/etc/sysconfig/grub"]
GRUB_PASSWORD_PATHS = [
    "{grub_dir}/user.cfg",
    "/etc/grub.d/01_users",
    "/etc/grub.d/40_custom",
]


def find_grub_paths(context: Context) -> dict[str, Any]:
    """Find GRUB configuration files."""
    paths = {
        "main_config": None,
        "default_config": None,
        "grub_dir": None,
    }

    # Find main grub.cfg
    for grub_dir in GRUB_DIRS:
        cfg_path = f"{grub_dir}/grub.cfg"
        if context.file_exists(cfg_path):
            paths["main_config"] = cfg_path
            paths["grub_dir"] = grub_dir
            break

    # Find defaults file
    for default_path in GRUB_DEFAULT_PATHS:
        if context.file_exists(default_path):
            paths["default_config"] = default_path
            break

    return paths


def parse_grub_defaults(context: Context, filepath: str | None) -> dict[str, Any]:
    """Parse GRUB defaults configuration file."""
    config = {
        "path": filepath,
        "settings": {},
        "cmdline": "",
        "timeout": None,
        "default": None,
    }

    if not filepath or not context.file_exists(filepath):
        return config

    try:
        content = context.read_file(filepath)
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = re.match(r"^([A-Z_]+)=(.*)$", line)
            if match:
                key = match.group(1)
                value = match.group(2).strip("\"'")
                config["settings"][key] = value

                if key == "GRUB_CMDLINE_LINUX":
                    if config["cmdline"]:
                        config["cmdline"] = value + " " + config["cmdline"]
                    else:
                        config["cmdline"] = value
                elif key == "GRUB_CMDLINE_LINUX_DEFAULT":
                    if config["cmdline"]:
                        config["cmdline"] = config["cmdline"] + " " + value
                    else:
                        config["cmdline"] = value
                elif key == "GRUB_TIMEOUT":
                    try:
                        config["timeout"] = int(value)
                    except ValueError:
                        config["timeout"] = value
                elif key == "GRUB_DEFAULT":
                    config["default"] = value

    except Exception:
        pass

    return config


def check_password_protection(context: Context, grub_dir: str | None) -> dict[str, Any]:
    """Check if GRUB password protection is enabled."""
    info = {
        "enabled": False,
        "superusers": [],
        "password_file": None,
    }

    if not grub_dir:
        return info

    for pwd_template in GRUB_PASSWORD_PATHS:
        pwd_file = pwd_template.format(grub_dir=grub_dir)
        if context.file_exists(pwd_file):
            try:
                content = context.read_file(pwd_file)

                # Look for superusers definition
                su_match = re.search(r"set superusers\s*=\s*[\"']?([^\"']+)", content)
                if su_match:
                    info["enabled"] = True
                    info["superusers"] = su_match.group(1).split(",")
                    info["password_file"] = pwd_file

                # Look for password entries
                if "password_pbkdf2" in content or re.search(r"\bpassword\s+", content):
                    info["enabled"] = True
                    info["password_file"] = pwd_file

            except Exception:
                continue

    return info


def analyze_kernel_cmdline(cmdline: str) -> dict[str, Any]:
    """Analyze kernel command line parameters for security issues."""
    analysis = {
        "raw": cmdline,
        "parameters": {},
        "security": {
            "iommu_enabled": False,
            "selinux_status": "unknown",
            "kaslr_disabled": False,
            "smep_disabled": False,
            "smap_disabled": False,
            "mitigations_off": False,
        },
        "issues": [],
    }

    if not cmdline:
        return analysis

    # Parse parameters
    params = cmdline.split()
    for param in params:
        if "=" in param:
            key, value = param.split("=", 1)
            analysis["parameters"][key] = value
        else:
            analysis["parameters"][param] = True

    params_lower = {k.lower(): v for k, v in analysis["parameters"].items()}

    # IOMMU
    if "intel_iommu" in params_lower or "amd_iommu" in params_lower:
        iommu_val = params_lower.get("intel_iommu") or params_lower.get("amd_iommu")
        analysis["security"]["iommu_enabled"] = iommu_val == "on"

    # SELinux
    if "selinux" in params_lower:
        val = params_lower["selinux"]
        if val == "0":
            analysis["security"]["selinux_status"] = "disabled"
            analysis["issues"].append("selinux=0 (security disabled)")
        elif val == "1":
            analysis["security"]["selinux_status"] = "enabled"

    if "enforcing" in params_lower:
        val = params_lower["enforcing"]
        if val == "0":
            analysis["security"]["selinux_status"] = "permissive"

    # KASLR
    if "nokaslr" in analysis["parameters"]:
        analysis["security"]["kaslr_disabled"] = True
        analysis["issues"].append("nokaslr (security risk)")

    # SMEP/SMAP
    if "nosmep" in analysis["parameters"]:
        analysis["security"]["smep_disabled"] = True
        analysis["issues"].append("nosmep (security risk)")
    if "nosmap" in analysis["parameters"]:
        analysis["security"]["smap_disabled"] = True
        analysis["issues"].append("nosmap (security risk)")

    # Mitigations
    if "mitigations" in params_lower:
        if params_lower["mitigations"] == "off":
            analysis["security"]["mitigations_off"] = True
            analysis["issues"].append("mitigations=off (security risk)")

    return analysis


def analyze_configuration(
    paths: dict,
    defaults: dict,
    password: dict,
    cmdline_analysis: dict,
) -> list[dict[str, str]]:
    """Analyze configuration and return issues."""
    issues = []

    # Check if GRUB config exists
    if not paths["main_config"]:
        issues.append({
            "severity": "CRITICAL",
            "category": "installation",
            "message": "GRUB configuration file not found",
        })

    # Check defaults file
    if not paths["default_config"]:
        issues.append({
            "severity": "WARNING",
            "category": "configuration",
            "message": "GRUB defaults file not found (/etc/default/grub)",
        })

    # Check password protection
    if not password["enabled"]:
        issues.append({
            "severity": "WARNING",
            "category": "security",
            "message": "GRUB password protection is not enabled",
        })

    # Check timeout
    timeout = defaults.get("timeout")
    if timeout is not None:
        if timeout == 0:
            issues.append({
                "severity": "INFO",
                "category": "usability",
                "message": "GRUB timeout is 0 - cannot interrupt boot",
            })
        elif isinstance(timeout, int) and timeout > 30:
            issues.append({
                "severity": "INFO",
                "category": "performance",
                "message": f"GRUB timeout is high ({timeout}s) - consider reducing",
            })

    # Security parameter issues
    security = cmdline_analysis.get("security", {})

    if security.get("mitigations_off"):
        issues.append({
            "severity": "CRITICAL",
            "category": "security",
            "message": "CPU mitigations are disabled (mitigations=off)",
        })

    if security.get("kaslr_disabled"):
        issues.append({
            "severity": "WARNING",
            "category": "security",
            "message": "KASLR is disabled (nokaslr) - reduced security",
        })

    if security.get("smep_disabled"):
        issues.append({
            "severity": "WARNING",
            "category": "security",
            "message": "SMEP is disabled (nosmep) - reduced security",
        })

    if security.get("smap_disabled"):
        issues.append({
            "severity": "WARNING",
            "category": "security",
            "message": "SMAP is disabled (nosmap) - reduced security",
        })

    if security.get("selinux_status") == "disabled":
        issues.append({
            "severity": "WARNING",
            "category": "security",
            "message": "SELinux is disabled via boot parameters",
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
        0 = secure, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Audit GRUB bootloader configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for /boot (basic Linux check)
    if not context.file_exists("/boot"):
        output.error("/boot not found - requires Linux")
        return 2

    # Gather information
    paths = find_grub_paths(context)
    defaults = parse_grub_defaults(context, paths["default_config"])
    password = check_password_protection(context, paths["grub_dir"])
    cmdline_analysis = analyze_kernel_cmdline(defaults["cmdline"])

    # Analyze configuration
    issues = analyze_configuration(paths, defaults, password, cmdline_analysis)

    # Build result
    result = {
        "paths": paths,
        "defaults": {
            "timeout": defaults["timeout"],
            "default_entry": defaults["default"],
        },
        "password_protected": password["enabled"],
        "security": cmdline_analysis["security"],
        "issues": issues,
    }

    output.emit(result)

    # Categorize issues
    critical_count = sum(1 for i in issues if i["severity"] == "CRITICAL")
    warning_count = sum(1 for i in issues if i["severity"] == "WARNING")
    info_count = sum(1 for i in issues if i["severity"] == "INFO")

    if critical_count > 0:
        output.set_summary(f"{critical_count} critical, {warning_count} warning, {info_count} info issues")
    elif warning_count > 0:
        output.set_summary(f"{warning_count} warning, {info_count} info issues")
    elif info_count > 0:
        output.set_summary(f"{info_count} info issues")
    else:
        output.set_summary("GRUB configuration is secure")

    # Exit code based on findings
    has_critical = critical_count > 0
    has_warning = warning_count > 0

    return 1 if (has_critical or has_warning) else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
