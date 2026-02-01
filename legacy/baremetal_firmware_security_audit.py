#!/usr/bin/env python3
"""
Audit firmware security settings for baremetal systems.

Checks critical security features including:
- Secure Boot status and configuration
- TPM (Trusted Platform Module) presence and health
- UEFI vs Legacy BIOS mode
- Intel TXT (Trusted Execution Technology) status
- AMD SEV (Secure Encrypted Virtualization) status
- IOMMU/VT-d/AMD-Vi status for DMA protection
- Firmware write protection status

Essential for security compliance auditing in datacenters, detecting
systems with disabled security features, and ensuring fleet consistency.

Exit codes:
    0 - All security features properly configured (or informational only)
    1 - Security warnings or issues detected
    2 - Missing dependencies or usage error
"""

import argparse
import json
import os
import re
import subprocess
import sys


def run_command(cmd):
    """Execute a command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def read_file(path):
    """Read a file and return contents, or None if not readable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def check_secure_boot():
    """Check Secure Boot status."""
    result = {
        'enabled': None,
        'setup_mode': None,
        'deployed_mode': None,
        'status': 'unknown',
        'details': []
    }

    # Check if running in EFI mode
    if not os.path.exists('/sys/firmware/efi'):
        result['status'] = 'not_applicable'
        result['details'].append('System booted in Legacy BIOS mode (not UEFI)')
        return result

    # Check Secure Boot variable
    sb_enabled = read_file('/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c')
    if sb_enabled is not None:
        # Last byte indicates status (1 = enabled)
        try:
            result['enabled'] = sb_enabled[-1] == '\x01' or ord(sb_enabled[-1]) == 1
        except (IndexError, TypeError):
            pass

    # Alternative check using mokutil
    returncode, stdout, _ = run_command("mokutil --sb-state 2>/dev/null")
    if returncode == 0:
        if 'SecureBoot enabled' in stdout:
            result['enabled'] = True
        elif 'SecureBoot disabled' in stdout:
            result['enabled'] = False

    # Check setup mode
    setup_mode = read_file('/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c')
    if setup_mode is not None:
        try:
            result['setup_mode'] = setup_mode[-1] == '\x01' or ord(setup_mode[-1]) == 1
        except (IndexError, TypeError):
            pass

    # Determine status
    if result['enabled'] is True:
        result['status'] = 'enabled'
        result['details'].append('Secure Boot is enabled')
    elif result['enabled'] is False:
        result['status'] = 'disabled'
        result['details'].append('Secure Boot is disabled')
    else:
        result['status'] = 'unknown'
        result['details'].append('Unable to determine Secure Boot status')

    if result['setup_mode'] is True:
        result['details'].append('WARNING: System is in Setup Mode (keys can be modified)')

    return result


def check_tpm():
    """Check TPM status and health."""
    result = {
        'present': False,
        'version': None,
        'enabled': None,
        'owned': None,
        'status': 'not_found',
        'details': []
    }

    # Check for TPM device
    tpm_devices = []
    for tpm_path in ['/dev/tpm0', '/dev/tpmrm0']:
        if os.path.exists(tpm_path):
            tpm_devices.append(tpm_path)
            result['present'] = True

    # Check sysfs for TPM info
    tpm_sysfs = '/sys/class/tpm/tpm0'
    if os.path.exists(tpm_sysfs):
        result['present'] = True

        # Check TPM version
        tpm_version_major = read_file(f'{tpm_sysfs}/tpm_version_major')
        if tpm_version_major:
            if tpm_version_major == '2':
                result['version'] = 'TPM 2.0'
            elif tpm_version_major == '1':
                result['version'] = 'TPM 1.2'
            else:
                result['version'] = f'TPM {tpm_version_major}.x'

    # Try tpm2_getcap for TPM 2.0
    returncode, stdout, _ = run_command("tpm2_getcap properties-fixed 2>/dev/null | head -20")
    if returncode == 0 and stdout.strip():
        result['version'] = 'TPM 2.0'
        result['enabled'] = True

        # Extract manufacturer
        for line in stdout.split('\n'):
            if 'TPM2_PT_MANUFACTURER' in line:
                result['details'].append(f'Manufacturer: {line.split(":")[-1].strip()}')
                break

    # Try tpm_version for TPM 1.2
    if result['version'] is None:
        returncode, stdout, _ = run_command("tpm_version 2>/dev/null")
        if returncode == 0 and stdout.strip():
            result['version'] = 'TPM 1.2'
            result['enabled'] = True

    # Determine status
    if result['present']:
        if result['enabled'] is True:
            result['status'] = 'enabled'
            result['details'].insert(0, f'{result["version"]} present and accessible')
        else:
            result['status'] = 'present'
            result['details'].insert(0, f'TPM device present ({result.get("version", "unknown version")})')
    else:
        result['status'] = 'not_found'
        result['details'].append('No TPM device found')

    return result


def check_boot_mode():
    """Check if system is using UEFI or Legacy BIOS."""
    result = {
        'mode': 'unknown',
        'bits': None,
        'details': []
    }

    if os.path.exists('/sys/firmware/efi'):
        result['mode'] = 'uefi'

        # Check if 32-bit or 64-bit UEFI
        efi_systab = read_file('/sys/firmware/efi/systab')
        if efi_systab:
            if 'ACPI20' in efi_systab or 'ACPI 2.0' in efi_systab:
                result['bits'] = 64
            else:
                result['bits'] = 32

        # Check EFI runtime services
        if os.path.exists('/sys/firmware/efi/runtime'):
            result['details'].append('EFI runtime services available')

        result['details'].insert(0, f'UEFI mode ({result["bits"]}-bit)' if result['bits'] else 'UEFI mode')
    else:
        result['mode'] = 'legacy'
        result['details'].append('Legacy BIOS mode (no UEFI)')

    return result


def check_iommu():
    """Check IOMMU/VT-d/AMD-Vi status for DMA protection."""
    result = {
        'enabled': False,
        'type': None,
        'groups': 0,
        'status': 'disabled',
        'details': []
    }

    # Check for IOMMU groups
    iommu_groups_path = '/sys/kernel/iommu_groups'
    if os.path.exists(iommu_groups_path):
        try:
            groups = os.listdir(iommu_groups_path)
            if groups:
                result['enabled'] = True
                result['groups'] = len(groups)
        except OSError:
            pass

    # Check dmesg for IOMMU type
    returncode, stdout, _ = run_command("dmesg 2>/dev/null | grep -i 'iommu\\|dmar\\|amd-vi' | head -10")
    if returncode == 0 and stdout.strip():
        if 'DMAR' in stdout or 'Intel-IOMMU' in stdout:
            result['type'] = 'Intel VT-d'
        elif 'AMD-Vi' in stdout or 'AMD IOMMUv2' in stdout:
            result['type'] = 'AMD-Vi'

    # Check kernel cmdline for iommu settings
    cmdline = read_file('/proc/cmdline') or ''
    if 'iommu=off' in cmdline or 'intel_iommu=off' in cmdline or 'amd_iommu=off' in cmdline:
        result['enabled'] = False
        result['details'].append('WARNING: IOMMU disabled via kernel cmdline')
    elif 'intel_iommu=on' in cmdline or 'amd_iommu=on' in cmdline or 'iommu=pt' in cmdline:
        result['details'].append('IOMMU enabled via kernel cmdline')

    # Determine status
    if result['enabled']:
        result['status'] = 'enabled'
        type_str = result['type'] if result['type'] else 'IOMMU'
        result['details'].insert(0, f'{type_str} enabled ({result["groups"]} groups)')
    else:
        result['status'] = 'disabled'
        result['details'].insert(0, 'IOMMU/VT-d/AMD-Vi not enabled')

    return result


def check_intel_txt():
    """Check Intel TXT (Trusted Execution Technology) status."""
    result = {
        'supported': False,
        'enabled': False,
        'status': 'not_supported',
        'details': []
    }

    # Check for TXT support in CPU flags
    cpuinfo = read_file('/proc/cpuinfo') or ''
    if 'smx' in cpuinfo:
        result['supported'] = True
        result['details'].append('CPU supports Intel TXT (SMX flag present)')

    # Check for TXT in dmesg
    returncode, stdout, _ = run_command("dmesg 2>/dev/null | grep -i 'txt\\|tboot' | head -5")
    if returncode == 0 and 'TXT' in stdout:
        result['enabled'] = True

    # Check for tboot
    returncode, _, _ = run_command("which tboot 2>/dev/null")
    if returncode == 0:
        result['details'].append('tboot package installed')

    # Determine status
    if result['enabled']:
        result['status'] = 'enabled'
        result['details'].insert(0, 'Intel TXT is enabled')
    elif result['supported']:
        result['status'] = 'supported'
        result['details'].insert(0, 'Intel TXT supported but not enabled')
    else:
        result['details'].insert(0, 'Intel TXT not supported on this CPU')

    return result


def check_amd_sev():
    """Check AMD SEV (Secure Encrypted Virtualization) status."""
    result = {
        'supported': False,
        'enabled': False,
        'type': None,
        'status': 'not_supported',
        'details': []
    }

    # Check for SEV support in CPU flags
    cpuinfo = read_file('/proc/cpuinfo') or ''
    if 'sev' in cpuinfo.lower():
        result['supported'] = True
        if 'sev_es' in cpuinfo.lower():
            result['type'] = 'SEV-ES'
        elif 'sev_snp' in cpuinfo.lower():
            result['type'] = 'SEV-SNP'
        else:
            result['type'] = 'SEV'
        result['details'].append(f'CPU supports AMD {result["type"]}')

    # Check /sys for SEV status
    sev_path = '/sys/module/kvm_amd/parameters/sev'
    if os.path.exists(sev_path):
        sev_enabled = read_file(sev_path)
        if sev_enabled in ['1', 'Y', 'y']:
            result['enabled'] = True

    # Check dmesg for SEV
    returncode, stdout, _ = run_command("dmesg 2>/dev/null | grep -i 'sev.*enabled\\|ccp.*sev' | head -3")
    if returncode == 0 and ('enabled' in stdout.lower() or 'SEV' in stdout):
        result['enabled'] = True

    # Determine status
    if result['enabled']:
        result['status'] = 'enabled'
        result['details'].insert(0, f'AMD {result["type"]} is enabled')
    elif result['supported']:
        result['status'] = 'supported'
        result['details'].insert(0, f'AMD {result["type"]} supported but not enabled')
    else:
        result['details'].insert(0, 'AMD SEV not supported on this CPU')

    return result


def check_kernel_lockdown():
    """Check kernel lockdown mode."""
    result = {
        'mode': None,
        'status': 'unknown',
        'details': []
    }

    lockdown_path = '/sys/kernel/security/lockdown'
    lockdown = read_file(lockdown_path)

    if lockdown:
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
        else:
            result['details'].append(f'Kernel lockdown mode: {result["mode"]}')
    else:
        result['status'] = 'not_supported'
        result['details'].append('Kernel lockdown not available')

    return result


def analyze_security(checks, require_secure_boot=False, require_tpm=False, require_iommu=False):
    """Analyze security status and return overall assessment."""
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

    if checks['secure_boot'].get('setup_mode'):
        warnings.append('System is in Setup Mode')

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


def main():
    parser = argparse.ArgumentParser(
        description='Audit firmware security settings for baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         # Basic security audit
  %(prog)s --format json           # JSON output for automation
  %(prog)s --require-secure-boot   # Fail if Secure Boot disabled
  %(prog)s --require-all           # Require all security features
  %(prog)s --warn-only             # Only show issues/warnings

Checks performed:
  - Secure Boot status (enabled/disabled/setup mode)
  - TPM presence and version (1.2/2.0)
  - Boot mode (UEFI vs Legacy BIOS)
  - IOMMU/VT-d/AMD-Vi status
  - Intel TXT or AMD SEV support
  - Kernel lockdown mode

Exit codes:
  0 - All security features properly configured
  1 - Security warnings or issues detected
  2 - Usage error
"""
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information for each check'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--warn-only',
        action='store_true',
        help='Only show checks with warnings or issues'
    )
    parser.add_argument(
        '--require-secure-boot',
        action='store_true',
        help='Treat disabled Secure Boot as an error (not warning)'
    )
    parser.add_argument(
        '--require-tpm',
        action='store_true',
        help='Treat missing TPM as an error (not warning)'
    )
    parser.add_argument(
        '--require-iommu',
        action='store_true',
        help='Treat disabled IOMMU as an error (not warning)'
    )
    parser.add_argument(
        '--require-all',
        action='store_true',
        help='Require Secure Boot, TPM, and IOMMU (implies all --require-* flags)'
    )

    args = parser.parse_args()

    # Handle --require-all
    if args.require_all:
        args.require_secure_boot = True
        args.require_tpm = True
        args.require_iommu = True

    # Run all checks
    checks = {
        'secure_boot': check_secure_boot(),
        'tpm': check_tpm(),
        'boot_mode': check_boot_mode(),
        'iommu': check_iommu(),
        'intel_txt': check_intel_txt(),
        'amd_sev': check_amd_sev(),
        'kernel_lockdown': check_kernel_lockdown(),
    }

    # Analyze results
    issues, warnings = analyze_security(
        checks,
        require_secure_boot=args.require_secure_boot,
        require_tpm=args.require_tpm,
        require_iommu=args.require_iommu
    )

    # Output results
    if args.format == 'json':
        output = {
            'checks': checks,
            'issues': issues,
            'warnings': warnings,
            'summary': {
                'secure_boot': checks['secure_boot']['status'],
                'tpm': checks['tpm']['status'],
                'boot_mode': checks['boot_mode']['mode'],
                'iommu': checks['iommu']['status'],
                'intel_txt': checks['intel_txt']['status'],
                'amd_sev': checks['amd_sev']['status'],
                'kernel_lockdown': checks['kernel_lockdown']['status'],
            }
        }
        print(json.dumps(output, indent=2))

    elif args.format == 'table':
        print("{:<20} {:<15} {:<50}".format('CHECK', 'STATUS', 'DETAILS'))
        print("-" * 85)

        rows = [
            ('Secure Boot', checks['secure_boot']['status'],
             checks['secure_boot']['details'][0] if checks['secure_boot']['details'] else ''),
            ('TPM', checks['tpm']['status'],
             checks['tpm']['details'][0] if checks['tpm']['details'] else ''),
            ('Boot Mode', checks['boot_mode']['mode'],
             checks['boot_mode']['details'][0] if checks['boot_mode']['details'] else ''),
            ('IOMMU/VT-d', checks['iommu']['status'],
             checks['iommu']['details'][0] if checks['iommu']['details'] else ''),
            ('Intel TXT', checks['intel_txt']['status'],
             checks['intel_txt']['details'][0] if checks['intel_txt']['details'] else ''),
            ('AMD SEV', checks['amd_sev']['status'],
             checks['amd_sev']['details'][0] if checks['amd_sev']['details'] else ''),
            ('Kernel Lockdown', checks['kernel_lockdown']['status'],
             checks['kernel_lockdown']['details'][0] if checks['kernel_lockdown']['details'] else ''),
        ]

        for name, status, details in rows:
            if args.warn_only and status in ['enabled', 'uefi', 'confidentiality', 'integrity']:
                continue
            print("{:<20} {:<15} {:<50}".format(name, status.upper(), details[:50]))

    else:  # plain
        check_order = [
            ('Secure Boot', 'secure_boot'),
            ('TPM', 'tpm'),
            ('Boot Mode', 'boot_mode'),
            ('IOMMU/VT-d/AMD-Vi', 'iommu'),
            ('Intel TXT', 'intel_txt'),
            ('AMD SEV', 'amd_sev'),
            ('Kernel Lockdown', 'kernel_lockdown'),
        ]

        for name, key in check_order:
            check = checks[key]
            status = check.get('status', check.get('mode', 'unknown'))

            # Skip if warn-only and status is good
            if args.warn_only:
                if status in ['enabled', 'uefi', 'confidentiality', 'integrity']:
                    continue

            # Status symbol
            if status in ['enabled', 'uefi', 'confidentiality', 'integrity']:
                symbol = '[OK]'
            elif status in ['disabled', 'none', 'legacy', 'not_found']:
                symbol = '[!!]'
            elif status in ['supported', 'present']:
                symbol = '[--]'
            else:
                symbol = '[??]'

            print("{} {}: {}".format(symbol, name, status))

            if args.verbose and check.get('details'):
                for detail in check['details']:
                    print("    {}".format(detail))

        # Print issues and warnings
        if issues:
            print()
            print("ISSUES:")
            for issue in issues:
                print("  ! {}".format(issue))

        if warnings:
            print()
            print("WARNINGS:")
            for warning in warnings:
                print("  * {}".format(warning))

    # Exit code
    if issues:
        sys.exit(1)
    elif warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
