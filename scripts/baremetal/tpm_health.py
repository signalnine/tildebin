#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [tpm, security, hardware, encryption, attestation]
#   requires: []
#   privilege: user
#   related: [file_integrity, security_policy]
#   brief: Monitor TPM health and status

"""
Monitor TPM (Trusted Platform Module) health and status for baremetal systems.

Checks TPM presence, version, and operational status. Useful for:
- Verifying TPM is present and functional for disk encryption
- Checking TPM version (1.2 vs 2.0) for compliance
- Monitoring TPM state for remote attestation workflows
- Auditing security posture

Returns:
    0 - TPM healthy, no issues
    1 - Issues detected (TPM missing, disabled, or errors)
    2 - Error
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_tpm_sysfs(context: Context) -> dict[str, bool]:
    """Check for TPM device via sysfs."""
    tpm_paths = [
        "/sys/class/tpm/tpm0",
        "/sys/class/misc/tpm0",
        "/dev/tpm0",
        "/dev/tpmrm0",
    ]

    found = {}
    for path in tpm_paths:
        found[path] = context.file_exists(path)

    return found


def get_tpm_version_sysfs(context: Context) -> dict[str, Any]:
    """Get TPM version from sysfs."""
    version_info: dict[str, Any] = {
        "version": None,
        "manufacturer": None,
        "description": None,
    }

    # Try tpm_version_major/minor
    major_path = "/sys/class/tpm/tpm0/tpm_version_major"
    minor_path = "/sys/class/tpm/tpm0/tpm_version_minor"

    if context.file_exists(major_path):
        try:
            major = context.read_file(major_path).strip()
            minor = "0"
            if context.file_exists(minor_path):
                minor = context.read_file(minor_path).strip()
            version_info["version"] = f"{major}.{minor}"
        except (IOError, OSError):
            pass

    return version_info


def get_tpm2_properties(context: Context) -> dict[str, Any] | None:
    """Get TPM 2.0 properties using tpm2-tools."""
    if not context.check_tool("tpm2_getcap"):
        return None

    properties: dict[str, Any] = {
        "manufacturer": None,
        "vendor_string": None,
        "firmware_version": None,
        "family": None,
        "revision": None,
        "lockout_counter": None,
    }

    # Get fixed properties
    result = context.run(["tpm2_getcap", "properties-fixed"], check=False)
    if result.returncode == 0:
        lines = result.stdout.strip().split("\n")
        current_prop = None
        for line in lines:
            # Check for property name line
            if "TPM2_PT_MANUFACTURER" in line:
                current_prop = "manufacturer"
            elif "TPM2_PT_VENDOR_STRING" in line:
                current_prop = "vendor_string"
            elif "TPM2_PT_FIRMWARE_VERSION" in line:
                current_prop = "firmware_version"
            elif "TPM2_PT_FAMILY_INDICATOR" in line:
                current_prop = "family"
            elif "TPM2_PT_REVISION" in line:
                current_prop = "revision"
            elif "value:" in line and current_prop:
                # Extract value from the value line
                match = re.search(r'value:\s*"?([^"]+)"?\s*$', line)
                if match:
                    properties[current_prop] = match.group(1).strip()
                current_prop = None

    # Get variable properties (lockout status)
    result = context.run(["tpm2_getcap", "properties-variable"], check=False)
    if result.returncode == 0:
        lines = result.stdout.strip().split("\n")
        current_prop = None
        for line in lines:
            if "TPM2_PT_LOCKOUT_COUNTER" in line:
                current_prop = "lockout_counter"
            elif "value:" in line and current_prop == "lockout_counter":
                match = re.search(r"value:\s*(\d+)", line)
                if match:
                    properties["lockout_counter"] = int(match.group(1))
                current_prop = None

    return properties


def run_tpm2_selftest(context: Context) -> tuple[bool | None, str]:
    """Run TPM 2.0 self-test."""
    if not context.check_tool("tpm2_selftest"):
        return None, "tpm2_selftest not available"

    result = context.run(["tpm2_selftest", "--fulltest"], check=False)
    if result.returncode == 0:
        return True, ""
    else:
        return False, result.stderr


def get_pcr_banks(context: Context) -> list[str]:
    """Get available PCR banks."""
    if not context.check_tool("tpm2_getcap"):
        return []

    banks = []
    result = context.run(["tpm2_getcap", "pcrs"], check=False)
    if result.returncode == 0:
        for line in result.stdout.strip().split("\n"):
            # Match "sha1:", "sha256:", etc or "- sha1:" format
            bank_match = re.search(r"(sha\d+):", line)
            if bank_match:
                banks.append(bank_match.group(1))

    return list(set(banks))  # Remove duplicates


def analyze_tpm_status(
    sysfs_status: dict[str, bool],
    version_info: dict[str, Any],
    tpm2_props: dict[str, Any] | None,
    selftest_ok: bool | None,
    pcr_banks: list[str],
) -> list[dict[str, str]]:
    """Analyze TPM status and return issues."""
    issues = []

    # Check if TPM device exists
    has_tpm = any(sysfs_status.values())
    if not has_tpm:
        issues.append({
            "severity": "critical",
            "message": "No TPM device detected",
            "recommendation": "Check BIOS/UEFI settings to enable TPM",
        })
        return issues

    # Check TPM version
    version = version_info.get("version")
    if version:
        try:
            major = int(version.split(".")[0])
            if major < 2:
                issues.append({
                    "severity": "info",
                    "message": f"TPM version {version} detected (TPM 1.2)",
                    "recommendation": "Consider upgrading to TPM 2.0 for better security",
                })
        except (ValueError, IndexError):
            pass

    # Check self-test result
    if selftest_ok is False:
        issues.append({
            "severity": "critical",
            "message": "TPM self-test failed",
            "recommendation": "TPM may be malfunctioning; check firmware or hardware",
        })
    elif selftest_ok is None:
        issues.append({
            "severity": "info",
            "message": "Could not run TPM self-test (tpm2_selftest not available)",
            "recommendation": "Install tpm2-tools for full TPM health checking",
        })

    # Check lockout counter
    if tpm2_props and tpm2_props.get("lockout_counter") is not None:
        lockout_count = tpm2_props["lockout_counter"]
        if lockout_count > 0:
            issues.append({
                "severity": "warning",
                "message": f"TPM lockout counter is {lockout_count} (failed auth attempts)",
                "recommendation": "Investigate failed authentication attempts",
            })

    # Check PCR banks
    if pcr_banks:
        if "sha1" in pcr_banks and "sha256" not in pcr_banks:
            issues.append({
                "severity": "warning",
                "message": "Only SHA-1 PCR bank available",
                "recommendation": "Enable SHA-256 PCR bank for stronger security",
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
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor TPM health and status")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show warnings")
    parser.add_argument("--skip-selftest", action="store_true", help="Skip TPM self-test")
    opts = parser.parse_args(args)

    # Check TPM via sysfs
    sysfs_status = check_tpm_sysfs(context)
    tpm_present = any(sysfs_status.values())

    # Get version info
    version_info = get_tpm_version_sysfs(context)

    # TPM 2.0 specific checks
    tpm2_props = None
    selftest_ok = None
    pcr_banks: list[str] = []

    if tpm_present:
        tpm2_props = get_tpm2_properties(context)
        if not opts.skip_selftest:
            selftest_ok, _ = run_tpm2_selftest(context)
        pcr_banks = get_pcr_banks(context)

    # Analyze status
    issues = analyze_tpm_status(sysfs_status, version_info, tpm2_props, selftest_ok, pcr_banks)

    # Build output data
    data: dict[str, Any] = {
        "tpm_present": tpm_present,
        "device_paths": sysfs_status,
        "version": version_info.get("version"),
        "selftest_passed": selftest_ok,
        "pcr_banks": pcr_banks,
        "issues": issues,
    }

    if tpm2_props:
        data["tpm2_properties"] = tpm2_props

    output.emit(data)

    # Set summary
    if not tpm_present:
        output.set_summary("TPM not detected")
    elif not issues:
        output.set_summary("TPM healthy")
    else:
        critical_count = sum(1 for i in issues if i["severity"] == "critical")
        warning_count = sum(1 for i in issues if i["severity"] == "warning")
        output.set_summary(f"{critical_count} critical, {warning_count} warnings")

    # Exit with appropriate code
    has_critical = any(i["severity"] == "critical" for i in issues)
    has_warning = any(i["severity"] == "warning" for i in issues)

    if has_critical or has_warning:

        output.render(opts.format, "Monitor TPM health and status")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
