#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, kernel, hardening, compliance, audit]
#   related: [sysctl_security_audit, sysctl_drift_detector]
#   brief: Audit kernel security hardening settings for baremetal systems

"""
Audit kernel security hardening settings for baremetal systems.

Checks critical kernel security features including:
- ASLR (Address Space Layout Randomization)
- KASLR (Kernel ASLR)
- NX/DEP (No-Execute/Data Execution Prevention)
- SMEP/SMAP (Supervisor Mode Execution/Access Prevention)
- PTI (Page Table Isolation / Meltdown mitigation)
- Spectre/Meltdown mitigations
- Kernel pointer hiding (kptr_restrict)
- dmesg restrictions
- Unprivileged BPF restrictions
- Yama LSM ptrace scope

Essential for security compliance auditing in datacenters, detecting
systems with weakened security settings, and ensuring fleet consistency.

Exit codes:
    0 - All security features properly configured
    1 - Security warnings or issues detected
    2 - Missing dependencies or usage error
"""

import argparse
import os

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_sysctl(context: Context, param: str) -> str | None:
    """Read a sysctl value from /proc/sys."""
    path = "/proc/sys/" + param.replace(".", "/")
    try:
        return context.read_file(path).strip()
    except (FileNotFoundError, IOError, PermissionError):
        return None


def check_aslr(context: Context) -> dict:
    """Check ASLR (Address Space Layout Randomization) status."""
    result = {
        "enabled": False,
        "level": 0,
        "status": "disabled",
        "details": [],
    }

    value = read_sysctl(context, "kernel.randomize_va_space")
    if value is not None:
        try:
            level = int(value)
            result["level"] = level
            if level == 2:
                result["enabled"] = True
                result["status"] = "full"
                result["details"].append("Full ASLR enabled (stack, VDSO, mmap, heap)")
            elif level == 1:
                result["enabled"] = True
                result["status"] = "partial"
                result["details"].append("Partial ASLR (stack, VDSO, mmap only)")
            else:
                result["status"] = "disabled"
                result["details"].append("ASLR is disabled")
        except ValueError:
            result["details"].append(f"Unexpected value: {value}")
    else:
        result["details"].append("Unable to read ASLR status")

    return result


def check_kaslr(context: Context) -> dict:
    """Check KASLR (Kernel ASLR) status."""
    result = {
        "enabled": None,
        "status": "unknown",
        "details": [],
    }

    # Check kernel cmdline for nokaslr
    try:
        cmdline = context.read_file("/proc/cmdline")
    except (FileNotFoundError, IOError):
        cmdline = ""

    if "nokaslr" in cmdline:
        result["enabled"] = False
        result["status"] = "disabled"
        result["details"].append("KASLR disabled via kernel cmdline (nokaslr)")
        return result

    result["enabled"] = True
    result["status"] = "enabled"
    result["details"].append("KASLR not disabled in kernel cmdline")

    return result


def check_nx_dep(context: Context) -> dict:
    """Check NX/DEP (No-Execute) bit support."""
    result = {
        "supported": False,
        "enabled": False,
        "status": "unknown",
        "details": [],
    }

    # Check CPU flags for NX support
    try:
        cpuinfo = context.read_file("/proc/cpuinfo")
    except (FileNotFoundError, IOError):
        cpuinfo = ""

    if " nx " in cpuinfo or " nx" in cpuinfo:
        result["supported"] = True
        result["details"].append("CPU supports NX (No-Execute) bit")

    if " pae " in cpuinfo or " pae" in cpuinfo:
        result["details"].append("PAE mode enabled")

    # Check kernel cmdline for noexec
    try:
        cmdline = context.read_file("/proc/cmdline")
    except (FileNotFoundError, IOError):
        cmdline = ""

    if "noexec=off" in cmdline:
        result["enabled"] = False
        result["status"] = "disabled"
        result["details"].append("NX disabled via kernel cmdline")
    elif result["supported"]:
        result["enabled"] = True
        result["status"] = "enabled"
        result["details"].insert(0, "NX/DEP protection enabled")
    else:
        result["status"] = "not_supported"
        result["details"].insert(0, "NX bit not supported by CPU")

    return result


def check_smep_smap(context: Context) -> dict:
    """Check SMEP and SMAP CPU security features."""
    result = {
        "smep": {"supported": False, "enabled": False},
        "smap": {"supported": False, "enabled": False},
        "status": "unknown",
        "details": [],
    }

    try:
        cpuinfo = context.read_file("/proc/cpuinfo")
    except (FileNotFoundError, IOError):
        cpuinfo = ""

    try:
        cmdline = context.read_file("/proc/cmdline")
    except (FileNotFoundError, IOError):
        cmdline = ""

    # Check SMEP
    if " smep " in cpuinfo or " smep" in cpuinfo:
        result["smep"]["supported"] = True
        if "nosmep" not in cmdline:
            result["smep"]["enabled"] = True
            result["details"].append("SMEP enabled (Supervisor Mode Execution Prevention)")
        else:
            result["details"].append("SMEP disabled via kernel cmdline")
    else:
        result["details"].append("SMEP not supported by CPU")

    # Check SMAP
    if " smap " in cpuinfo or " smap" in cpuinfo:
        result["smap"]["supported"] = True
        if "nosmap" not in cmdline:
            result["smap"]["enabled"] = True
            result["details"].append("SMAP enabled (Supervisor Mode Access Prevention)")
        else:
            result["details"].append("SMAP disabled via kernel cmdline")
    else:
        result["details"].append("SMAP not supported by CPU")

    # Determine overall status
    if result["smep"]["enabled"] and result["smap"]["enabled"]:
        result["status"] = "full"
    elif result["smep"]["enabled"] or result["smap"]["enabled"]:
        result["status"] = "partial"
    elif result["smep"]["supported"] or result["smap"]["supported"]:
        result["status"] = "disabled"
    else:
        result["status"] = "not_supported"

    return result


def check_pti(context: Context) -> dict:
    """Check PTI/KPTI (Page Table Isolation) status."""
    result = {
        "enabled": None,
        "status": "unknown",
        "details": [],
    }

    # Check kernel cmdline
    try:
        cmdline = context.read_file("/proc/cmdline")
    except (FileNotFoundError, IOError):
        cmdline = ""

    if "nopti" in cmdline or "pti=off" in cmdline:
        result["enabled"] = False
        result["status"] = "disabled"
        result["details"].append("PTI disabled via kernel cmdline")
    elif "pti=on" in cmdline:
        result["enabled"] = True
        result["status"] = "enabled"
        result["details"].append("PTI enabled via kernel cmdline")
    else:
        # Assume enabled by default on modern kernels
        result["enabled"] = True
        result["status"] = "enabled"
        result["details"].append("PTI enabled (default)")

    return result


def check_spectre_meltdown(context: Context) -> dict:
    """Check Spectre/Meltdown mitigation status."""
    result = {
        "vulnerabilities": {},
        "mitigated": True,
        "status": "unknown",
        "details": [],
    }

    # Check vulnerability files
    vuln_files = [
        "meltdown",
        "spectre_v1",
        "spectre_v2",
        "spec_store_bypass",
        "l1tf",
        "mds",
        "itlb_multihit",
    ]

    for vuln in vuln_files:
        path = f"/sys/devices/system/cpu/vulnerabilities/{vuln}"
        try:
            status = context.read_file(path).strip()
            result["vulnerabilities"][vuln] = status
            if "Vulnerable" in status and "Mitigation" not in status:
                result["mitigated"] = False
        except (FileNotFoundError, IOError):
            pass

    if result["vulnerabilities"]:
        vulnerable_count = sum(
            1
            for v in result["vulnerabilities"].values()
            if "Vulnerable" in v and "Mitigation" not in v
        )
        mitigated_count = sum(
            1
            for v in result["vulnerabilities"].values()
            if "Mitigation" in v or "Not affected" in v
        )

        if vulnerable_count == 0:
            result["status"] = "mitigated"
            result["details"].append(f"All {mitigated_count} CPU vulnerabilities mitigated")
        else:
            result["status"] = "vulnerable"
            result["details"].append(f"{vulnerable_count} vulnerabilities not mitigated")
    else:
        result["details"].append("Vulnerability status not available (older kernel)")

    return result


def check_kptr_restrict(context: Context) -> dict:
    """Check kernel pointer restriction level."""
    result = {
        "level": None,
        "status": "unknown",
        "details": [],
    }

    value = read_sysctl(context, "kernel.kptr_restrict")
    if value is not None:
        try:
            level = int(value)
            result["level"] = level
            if level == 2:
                result["status"] = "strict"
                result["details"].append("Kernel pointers hidden from all users")
            elif level == 1:
                result["status"] = "restricted"
                result["details"].append("Kernel pointers hidden from unprivileged users")
            else:
                result["status"] = "exposed"
                result["details"].append("Kernel pointers visible (security risk)")
        except ValueError:
            result["details"].append(f"Unexpected value: {value}")
    else:
        result["details"].append("Unable to read kptr_restrict")

    return result


def check_dmesg_restrict(context: Context) -> dict:
    """Check dmesg restriction setting."""
    result = {
        "restricted": False,
        "status": "unrestricted",
        "details": [],
    }

    value = read_sysctl(context, "kernel.dmesg_restrict")
    if value is not None:
        try:
            restricted = int(value)
            if restricted == 1:
                result["restricted"] = True
                result["status"] = "restricted"
                result["details"].append("dmesg restricted to privileged users")
            else:
                result["status"] = "unrestricted"
                result["details"].append("dmesg readable by unprivileged users")
        except ValueError:
            result["details"].append(f"Unexpected value: {value}")
    else:
        result["details"].append("Unable to read dmesg_restrict")

    return result


def check_unprivileged_bpf(context: Context) -> dict:
    """Check unprivileged BPF restrictions."""
    result = {
        "disabled": False,
        "status": "unknown",
        "details": [],
    }

    value = read_sysctl(context, "kernel.unprivileged_bpf_disabled")
    if value is not None:
        try:
            disabled = int(value)
            if disabled >= 1:
                result["disabled"] = True
                result["status"] = "restricted"
                result["details"].append("Unprivileged BPF disabled")
            else:
                result["status"] = "allowed"
                result["details"].append("Unprivileged BPF allowed (security risk)")
        except ValueError:
            result["details"].append(f"Unexpected value: {value}")
    else:
        result["details"].append("BPF restriction sysctl not available")

    return result


def check_yama_ptrace(context: Context) -> dict:
    """Check Yama LSM ptrace scope."""
    result = {
        "scope": None,
        "status": "unknown",
        "details": [],
    }

    value = read_sysctl(context, "kernel.yama.ptrace_scope")
    if value is not None:
        try:
            scope = int(value)
            result["scope"] = scope
            scopes = {
                0: ("permissive", "Classic ptrace permissions (any process)"),
                1: ("restricted", "Restricted ptrace to child processes"),
                2: ("admin_only", "Ptrace restricted to CAP_SYS_PTRACE"),
                3: ("disabled", "Ptrace completely disabled"),
            }
            if scope in scopes:
                result["status"], desc = scopes[scope]
                result["details"].append(desc)
            else:
                result["details"].append(f"Unknown scope: {scope}")
        except ValueError:
            result["details"].append(f"Unexpected value: {value}")
    else:
        result["details"].append("Yama LSM not available or not enabled")

    return result


def analyze_security(checks: dict, strict: bool = False) -> tuple[list, list]:
    """Analyze security status and return issues/warnings."""
    issues = []
    warnings = []

    # Critical checks - always issues
    if checks["aslr"]["status"] == "disabled":
        issues.append("ASLR is disabled")
    elif checks["aslr"]["status"] == "partial":
        warnings.append("ASLR is only partially enabled")

    if checks["kaslr"]["status"] == "disabled":
        issues.append("KASLR is disabled")

    if checks["nx_dep"]["status"] == "disabled":
        issues.append("NX/DEP is disabled")

    if checks["spectre_meltdown"]["status"] == "vulnerable":
        issues.append("CPU vulnerabilities not fully mitigated")

    # Important checks
    if checks["kptr_restrict"]["status"] == "exposed":
        if strict:
            issues.append("Kernel pointers exposed")
        else:
            warnings.append("Kernel pointers exposed")

    if checks["dmesg_restrict"]["status"] == "unrestricted":
        warnings.append("dmesg readable by unprivileged users")

    if checks["unprivileged_bpf"]["status"] == "allowed":
        warnings.append("Unprivileged BPF allowed")

    if checks["yama_ptrace"]["status"] == "permissive":
        warnings.append("Yama ptrace scope is permissive")

    if checks["smep_smap"]["status"] == "disabled":
        warnings.append("SMEP/SMAP disabled despite CPU support")

    if checks["pti"]["status"] == "disabled":
        warnings.append("PTI/KPTI disabled")

    return issues, warnings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point for kernel hardening audit.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = secure, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit kernel security hardening settings"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information for each check",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show checks with warnings or issues",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat exposed kernel pointers as error (not warning)",
    )

    opts = parser.parse_args(args)

    # Check if we can read /proc
    if not context.file_exists("/proc/cmdline"):
        output.error("/proc not available")
        return 2

    # Run all checks
    checks = {
        "aslr": check_aslr(context),
        "kaslr": check_kaslr(context),
        "nx_dep": check_nx_dep(context),
        "smep_smap": check_smep_smap(context),
        "pti": check_pti(context),
        "spectre_meltdown": check_spectre_meltdown(context),
        "kptr_restrict": check_kptr_restrict(context),
        "dmesg_restrict": check_dmesg_restrict(context),
        "unprivileged_bpf": check_unprivileged_bpf(context),
        "yama_ptrace": check_yama_ptrace(context),
    }

    # Analyze results
    issues, warnings = analyze_security(checks, strict=opts.strict)

    # Output results
    json_output = {
        "checks": checks,
        "issues": issues,
        "warnings": warnings,
        "summary": {
            "aslr": checks["aslr"]["status"],
            "kaslr": checks["kaslr"]["status"],
            "nx_dep": checks["nx_dep"]["status"],
            "smep_smap": checks["smep_smap"]["status"],
            "pti": checks["pti"]["status"],
            "spectre_meltdown": checks["spectre_meltdown"]["status"],
            "kptr_restrict": checks["kptr_restrict"]["status"],
            "dmesg_restrict": checks["dmesg_restrict"]["status"],
        },
    }
    output.emit(json_output)

    if opts.format == "table":
        print("=" * 75)
        print("KERNEL SECURITY HARDENING AUDIT")
        print("=" * 75)
        print(f"{'CHECK':<25} {'STATUS':<15} {'DETAILS':<35}")
        print("-" * 75)

        check_order = [
            ("ASLR", "aslr"),
            ("KASLR", "kaslr"),
            ("NX/DEP", "nx_dep"),
            ("SMEP/SMAP", "smep_smap"),
            ("PTI/KPTI", "pti"),
            ("Spectre/Meltdown", "spectre_meltdown"),
            ("kptr_restrict", "kptr_restrict"),
            ("dmesg_restrict", "dmesg_restrict"),
            ("Unprivileged BPF", "unprivileged_bpf"),
            ("Yama ptrace", "yama_ptrace"),
        ]

        good_statuses = [
            "full",
            "enabled",
            "mitigated",
            "strict",
            "restricted",
            "admin_only",
        ]

        for name, key in check_order:
            check = checks[key]
            status = check.get("status", "unknown")
            details = check["details"][0][:35] if check.get("details") else ""

            is_good = status in good_statuses
            if opts.warn_only and is_good:
                continue

            print(f"{name:<25} {status.upper():<15} {details:<35}")

        print("=" * 75)

        if issues or warnings:
            print()
            if issues:
                print("ISSUES:")
                for issue in issues:
                    print(f"  ! {issue}")
            if warnings:
                print("WARNINGS:")
                for warning in warnings:
                    print(f"  * {warning}")
    else:
        output.render(opts.format, "Kernel Security Hardening Audit", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    status = "issues" if (issues or warnings) else "secure"
    output.set_summary(f"issues={len(issues)}, warnings={len(warnings)}, status={status}")

    # Exit code
    return 1 if (issues or warnings) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
