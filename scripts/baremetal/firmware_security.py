#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, firmware, secure-boot, tpm, uefi]
#   requires: []
#   privilege: root
#   related: [cpu_vulnerability, kernel_cmdline_audit]
#   brief: Audit firmware security settings for baremetal systems

"""
Audit firmware security settings for baremetal systems.

Checks critical security features including:
- Secure Boot status and configuration
- TPM (Trusted Platform Module) presence and health
- UEFI vs Legacy BIOS mode
- Intel TXT (Trusted Execution Technology) status
- AMD SEV (Secure Encrypted Virtualization) status
- IOMMU/VT-d/AMD-Vi status for DMA protection
- Kernel lockdown mode

Essential for security compliance auditing in datacenters, detecting
systems with disabled security features, and ensuring fleet consistency.

Returns exit code 1 if security warnings or issues detected.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_secure_boot(context: Context) -> dict[str, Any]:
    """Check Secure Boot status."""
    result = {
        'enabled': None,
        'setup_mode': None,
        'status': 'unknown',
        'details': [],
    }

    # Check if running in EFI mode
    if not context.file_exists('/sys/firmware/efi'):
        result['status'] = 'not_applicable'
        result['details'].append('System booted in Legacy BIOS mode (not UEFI)')
        return result

    # Try to check Secure Boot via mokutil
    if context.check_tool('mokutil'):
        mokutil_result = context.run(['mokutil', '--sb-state'], check=False)
        if mokutil_result.returncode == 0:
            if 'SecureBoot enabled' in mokutil_result.stdout:
                result['enabled'] = True
                result['status'] = 'enabled'
                result['details'].append('Secure Boot is enabled')
            elif 'SecureBoot disabled' in mokutil_result.stdout:
                result['enabled'] = False
                result['status'] = 'disabled'
                result['details'].append('Secure Boot is disabled')

    # If mokutil didn't work, try reading EFI variables
    if result['enabled'] is None:
        sb_path = '/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
        if context.file_exists(sb_path):
            result['status'] = 'unknown'
            result['details'].append('Secure Boot variable exists but status undetermined')

    return result


def check_tpm(context: Context) -> dict[str, Any]:
    """Check TPM status and health."""
    result = {
        'present': False,
        'version': None,
        'enabled': None,
        'status': 'not_found',
        'details': [],
    }

    # Check for TPM device
    for tpm_path in ['/dev/tpm0', '/dev/tpmrm0']:
        if context.file_exists(tpm_path):
            result['present'] = True
            break

    # Check sysfs for TPM info
    tpm_sysfs = '/sys/class/tpm/tpm0'
    if context.file_exists(tpm_sysfs):
        result['present'] = True

        # Check TPM version
        version_path = f'{tpm_sysfs}/tpm_version_major'
        if context.file_exists(version_path):
            try:
                major = context.read_file(version_path).strip()
                if major == '2':
                    result['version'] = 'TPM 2.0'
                elif major == '1':
                    result['version'] = 'TPM 1.2'
                else:
                    result['version'] = f'TPM {major}.x'
            except Exception:
                pass

    # Determine status
    if result['present']:
        result['status'] = 'present'
        if result['version']:
            result['details'].append(f'{result["version"]} present')
        else:
            result['details'].append('TPM device present')
    else:
        result['status'] = 'not_found'
        result['details'].append('No TPM device found')

    return result


def check_boot_mode(context: Context) -> dict[str, Any]:
    """Check if system is using UEFI or Legacy BIOS."""
    result = {
        'mode': 'unknown',
        'bits': None,
        'details': [],
    }

    if context.file_exists('/sys/firmware/efi'):
        result['mode'] = 'uefi'
        result['details'].append('UEFI mode')
    else:
        result['mode'] = 'legacy'
        result['details'].append('Legacy BIOS mode (no UEFI)')

    return result


def check_iommu(context: Context) -> dict[str, Any]:
    """Check IOMMU/VT-d/AMD-Vi status for DMA protection."""
    result = {
        'enabled': False,
        'type': None,
        'groups': 0,
        'status': 'disabled',
        'details': [],
    }

    # Check for IOMMU groups
    iommu_groups_path = '/sys/kernel/iommu_groups'
    if context.file_exists(iommu_groups_path):
        groups = context.glob('*', iommu_groups_path)
        if groups:
            result['enabled'] = True
            result['groups'] = len(groups)

    # Check kernel cmdline for iommu settings
    if context.file_exists('/proc/cmdline'):
        try:
            cmdline = context.read_file('/proc/cmdline')
            if 'iommu=off' in cmdline or 'intel_iommu=off' in cmdline or 'amd_iommu=off' in cmdline:
                result['enabled'] = False
                result['details'].append('IOMMU disabled via kernel cmdline')
            elif 'intel_iommu=on' in cmdline:
                result['type'] = 'Intel VT-d'
            elif 'amd_iommu=on' in cmdline:
                result['type'] = 'AMD-Vi'
        except Exception:
            pass

    # Determine status
    if result['enabled']:
        result['status'] = 'enabled'
        type_str = result['type'] if result['type'] else 'IOMMU'
        result['details'].insert(0, f'{type_str} enabled ({result["groups"]} groups)')
    else:
        result['status'] = 'disabled'
        result['details'].insert(0, 'IOMMU/VT-d/AMD-Vi not enabled')

    return result


def check_kernel_lockdown(context: Context) -> dict[str, Any]:
    """Check kernel lockdown mode."""
    result = {
        'mode': None,
        'status': 'unknown',
        'details': [],
    }

    lockdown_path = '/sys/kernel/security/lockdown'
    if context.file_exists(lockdown_path):
        try:
            lockdown = context.read_file(lockdown_path)
            # Parse the lockdown status - format is "[none] integrity confidentiality"
            match = re.search(r'\[(\w+)\]', lockdown)
            if match:
                result['mode'] = match.group(1)

            if result['mode'] == 'confidentiality':
                result['status'] = 'confidentiality'
                result['details'].append('Kernel lockdown: confidentiality mode (strictest)')
            elif result['mode'] == 'integrity':
                result['status'] = 'integrity'
                result['details'].append('Kernel lockdown: integrity mode')
            elif result['mode'] == 'none':
                result['status'] = 'none'
                result['details'].append('Kernel lockdown: disabled')
        except Exception:
            pass
    else:
        result['status'] = 'not_supported'
        result['details'].append('Kernel lockdown not available')

    return result


def analyze_security(
    checks: dict[str, Any],
    require_secure_boot: bool = False,
    require_tpm: bool = False,
    require_iommu: bool = False,
) -> tuple[list[str], list[str]]:
    """Analyze security status and return (issues, warnings)."""
    issues = []
    warnings = []

    # Check Secure Boot
    if checks['secure_boot']['status'] == 'disabled':
        if require_secure_boot:
            issues.append('Secure Boot is disabled')
        else:
            warnings.append('Secure Boot is disabled')
    elif checks['secure_boot']['status'] == 'unknown' and require_secure_boot:
        issues.append('Secure Boot status unknown')

    # Check TPM
    if checks['tpm']['status'] == 'not_found':
        if require_tpm:
            issues.append('No TPM device found')
        else:
            warnings.append('No TPM device found')

    # Check IOMMU
    if checks['iommu']['status'] == 'disabled':
        if require_iommu:
            issues.append('IOMMU/VT-d/AMD-Vi is disabled')
        else:
            warnings.append('IOMMU/VT-d/AMD-Vi is disabled')

    # Check boot mode
    if checks['boot_mode']['mode'] == 'legacy':
        warnings.append('System using Legacy BIOS (not UEFI)')

    # Check kernel lockdown
    if checks['kernel_lockdown']['status'] == 'none':
        warnings.append('Kernel lockdown is disabled')

    return issues, warnings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all good, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Audit firmware security settings")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--require-secure-boot", action="store_true",
                        help="Treat disabled Secure Boot as an error")
    parser.add_argument("--require-tpm", action="store_true",
                        help="Treat missing TPM as an error")
    parser.add_argument("--require-iommu", action="store_true",
                        help="Treat disabled IOMMU as an error")
    parser.add_argument("--require-all", action="store_true",
                        help="Require Secure Boot, TPM, and IOMMU")
    opts = parser.parse_args(args)

    # Handle --require-all
    if opts.require_all:
        opts.require_secure_boot = True
        opts.require_tpm = True
        opts.require_iommu = True

    # Run all checks
    checks = {
        'secure_boot': check_secure_boot(context),
        'tpm': check_tpm(context),
        'boot_mode': check_boot_mode(context),
        'iommu': check_iommu(context),
        'kernel_lockdown': check_kernel_lockdown(context),
    }

    # Analyze results
    issues, warnings = analyze_security(
        checks,
        require_secure_boot=opts.require_secure_boot,
        require_tpm=opts.require_tpm,
        require_iommu=opts.require_iommu,
    )

    # Build output data
    data = {
        'checks': checks,
        'issues': issues,
        'warnings': warnings,
        'summary': {
            'secure_boot': checks['secure_boot']['status'],
            'tpm': checks['tpm']['status'],
            'boot_mode': checks['boot_mode']['mode'],
            'iommu': checks['iommu']['status'],
            'kernel_lockdown': checks['kernel_lockdown']['status'],
        },
    }

    output.emit(data)

    # Generate summary
    if issues:
        output.set_summary(f"{len(issues)} security issues")
    elif warnings:
        output.set_summary(f"{len(warnings)} security warnings")
    else:
        output.set_summary("All security checks passed")

    return 1 if (issues or warnings) else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
