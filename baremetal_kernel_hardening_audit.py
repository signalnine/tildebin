#!/usr/bin/env python3
"""
Audit kernel security hardening settings for baremetal systems.

Checks critical kernel security features including:
- ASLR (Address Space Layout Randomization)
- KASLR (Kernel ASLR)
- NX/DEP (No-Execute/Data Execution Prevention)
- Stack Protector (stack canaries)
- SMEP/SMAP (Supervisor Mode Execution/Access Prevention)
- PTI (Page Table Isolation / Meltdown mitigation)
- KPTI (Kernel Page Table Isolation)
- Spectre/Meltdown mitigations
- Kernel module signing
- Kernel pointer hiding (kptr_restrict)
- dmesg restrictions
- Unprivileged BPF restrictions
- Unprivileged userfaultfd restrictions
- Yama LSM ptrace scope

Essential for security compliance auditing in datacenters, detecting
systems with weakened security settings, and ensuring fleet consistency.

Exit codes:
    0 - All security features properly configured
    1 - Security warnings or issues detected
    2 - Missing dependencies or usage error
"""

import argparse
import json
import os
import re
import subprocess
import sys


def read_file(path):
    """Read a file and return contents, or None if not readable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError, PermissionError):
        return None


def read_sysctl(key):
    """Read a sysctl value from /proc/sys."""
    path = '/proc/sys/' + key.replace('.', '/')
    return read_file(path)


def run_command(cmd):
    """Execute a command and return output."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 127, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def check_aslr():
    """Check ASLR (Address Space Layout Randomization) status."""
    result = {
        'enabled': False,
        'level': 0,
        'status': 'disabled',
        'details': []
    }

    value = read_sysctl('kernel.randomize_va_space')
    if value is not None:
        try:
            level = int(value)
            result['level'] = level
            if level == 2:
                result['enabled'] = True
                result['status'] = 'full'
                result['details'].append('Full ASLR enabled (stack, VDSO, mmap, heap)')
            elif level == 1:
                result['enabled'] = True
                result['status'] = 'partial'
                result['details'].append('Partial ASLR (stack, VDSO, mmap only)')
            else:
                result['status'] = 'disabled'
                result['details'].append('ASLR is disabled')
        except ValueError:
            result['details'].append(f'Unexpected value: {value}')
    else:
        result['details'].append('Unable to read ASLR status')

    return result


def check_kaslr():
    """Check KASLR (Kernel ASLR) status."""
    result = {
        'enabled': None,
        'status': 'unknown',
        'details': []
    }

    # Check kernel cmdline for nokaslr
    cmdline = read_file('/proc/cmdline') or ''
    if 'nokaslr' in cmdline:
        result['enabled'] = False
        result['status'] = 'disabled'
        result['details'].append('KASLR disabled via kernel cmdline (nokaslr)')
        return result

    # Check /proc/kallsyms - if all addresses are 0, kptr_restrict is hiding them
    # but we can't determine KASLR status directly without comparing boots
    # Best we can do is check if it wasn't explicitly disabled
    result['enabled'] = True
    result['status'] = 'enabled'
    result['details'].append('KASLR not disabled in kernel cmdline')

    return result


def check_nx_dep():
    """Check NX/DEP (No-Execute) bit support."""
    result = {
        'supported': False,
        'enabled': False,
        'status': 'unknown',
        'details': []
    }

    # Check CPU flags for NX support
    cpuinfo = read_file('/proc/cpuinfo') or ''
    if ' nx ' in cpuinfo or ' nx' in cpuinfo:
        result['supported'] = True
        result['details'].append('CPU supports NX (No-Execute) bit')

    # Check if PAE is enabled (required for NX on 32-bit)
    if ' pae ' in cpuinfo or ' pae' in cpuinfo:
        result['details'].append('PAE mode enabled')

    # Check kernel cmdline for noexec
    cmdline = read_file('/proc/cmdline') or ''
    if 'noexec=off' in cmdline:
        result['enabled'] = False
        result['status'] = 'disabled'
        result['details'].append('NX disabled via kernel cmdline')
    elif result['supported']:
        result['enabled'] = True
        result['status'] = 'enabled'
        result['details'].insert(0, 'NX/DEP protection enabled')
    else:
        result['status'] = 'not_supported'
        result['details'].insert(0, 'NX bit not supported by CPU')

    return result


def check_smep_smap():
    """Check SMEP and SMAP CPU security features."""
    result = {
        'smep': {'supported': False, 'enabled': False},
        'smap': {'supported': False, 'enabled': False},
        'status': 'unknown',
        'details': []
    }

    cpuinfo = read_file('/proc/cpuinfo') or ''
    cmdline = read_file('/proc/cmdline') or ''

    # Check SMEP
    if ' smep ' in cpuinfo or ' smep' in cpuinfo:
        result['smep']['supported'] = True
        if 'nosmep' not in cmdline:
            result['smep']['enabled'] = True
            result['details'].append('SMEP enabled (Supervisor Mode Execution Prevention)')
        else:
            result['details'].append('SMEP disabled via kernel cmdline')
    else:
        result['details'].append('SMEP not supported by CPU')

    # Check SMAP
    if ' smap ' in cpuinfo or ' smap' in cpuinfo:
        result['smap']['supported'] = True
        if 'nosmap' not in cmdline:
            result['smap']['enabled'] = True
            result['details'].append('SMAP enabled (Supervisor Mode Access Prevention)')
        else:
            result['details'].append('SMAP disabled via kernel cmdline')
    else:
        result['details'].append('SMAP not supported by CPU')

    # Determine overall status
    if result['smep']['enabled'] and result['smap']['enabled']:
        result['status'] = 'full'
    elif result['smep']['enabled'] or result['smap']['enabled']:
        result['status'] = 'partial'
    elif result['smep']['supported'] or result['smap']['supported']:
        result['status'] = 'disabled'
    else:
        result['status'] = 'not_supported'

    return result


def check_pti():
    """Check PTI/KPTI (Page Table Isolation) status."""
    result = {
        'enabled': None,
        'status': 'unknown',
        'details': []
    }

    # Check /sys/kernel/debug/x86/pti_enabled if available
    pti_path = '/sys/kernel/debug/x86/pti_enabled'
    if os.path.exists(pti_path):
        value = read_file(pti_path)
        if value == '1':
            result['enabled'] = True
            result['status'] = 'enabled'
            result['details'].append('PTI/KPTI enabled (Meltdown mitigation)')
        elif value == '0':
            result['enabled'] = False
            result['status'] = 'disabled'
            result['details'].append('PTI/KPTI disabled')

    # Check kernel cmdline
    cmdline = read_file('/proc/cmdline') or ''
    if 'nopti' in cmdline or 'pti=off' in cmdline:
        result['enabled'] = False
        result['status'] = 'disabled'
        result['details'].append('PTI disabled via kernel cmdline')
    elif 'pti=on' in cmdline:
        result['enabled'] = True
        result['status'] = 'enabled'
        result['details'].append('PTI enabled via kernel cmdline')

    # Check dmesg for PTI status
    if result['status'] == 'unknown':
        rc, stdout, _ = run_command(['dmesg'])
        if rc == 0:
            if 'page tables isolation: enabled' in stdout.lower():
                result['enabled'] = True
                result['status'] = 'enabled'
                result['details'].append('PTI enabled (from dmesg)')
            elif 'page tables isolation: disabled' in stdout.lower():
                result['enabled'] = False
                result['status'] = 'disabled'
                result['details'].append('PTI disabled (from dmesg)')

    if result['status'] == 'unknown':
        result['details'].append('Unable to determine PTI status')

    return result


def check_spectre_meltdown():
    """Check Spectre/Meltdown mitigation status."""
    result = {
        'vulnerabilities': {},
        'mitigated': True,
        'status': 'unknown',
        'details': []
    }

    vuln_path = '/sys/devices/system/cpu/vulnerabilities'
    if not os.path.exists(vuln_path):
        result['status'] = 'unknown'
        result['details'].append('Vulnerability status not available (older kernel)')
        return result

    try:
        for vuln in os.listdir(vuln_path):
            status = read_file(os.path.join(vuln_path, vuln))
            if status:
                result['vulnerabilities'][vuln] = status
                if 'Vulnerable' in status and 'Mitigation' not in status:
                    result['mitigated'] = False
    except OSError:
        pass

    if result['vulnerabilities']:
        vulnerable_count = sum(
            1 for v in result['vulnerabilities'].values()
            if 'Vulnerable' in v and 'Mitigation' not in v
        )
        mitigated_count = sum(
            1 for v in result['vulnerabilities'].values()
            if 'Mitigation' in v or 'Not affected' in v
        )

        if vulnerable_count == 0:
            result['status'] = 'mitigated'
            result['details'].append(f'All {mitigated_count} CPU vulnerabilities mitigated')
        else:
            result['status'] = 'vulnerable'
            result['details'].append(f'{vulnerable_count} vulnerabilities not mitigated')
    else:
        result['details'].append('No vulnerability information found')

    return result


def check_kptr_restrict():
    """Check kernel pointer restriction level."""
    result = {
        'level': None,
        'status': 'unknown',
        'details': []
    }

    value = read_sysctl('kernel.kptr_restrict')
    if value is not None:
        try:
            level = int(value)
            result['level'] = level
            if level == 2:
                result['status'] = 'strict'
                result['details'].append('Kernel pointers hidden from all users')
            elif level == 1:
                result['status'] = 'restricted'
                result['details'].append('Kernel pointers hidden from unprivileged users')
            else:
                result['status'] = 'exposed'
                result['details'].append('Kernel pointers visible (security risk)')
        except ValueError:
            result['details'].append(f'Unexpected value: {value}')
    else:
        result['details'].append('Unable to read kptr_restrict')

    return result


def check_dmesg_restrict():
    """Check dmesg restriction setting."""
    result = {
        'restricted': False,
        'status': 'unrestricted',
        'details': []
    }

    value = read_sysctl('kernel.dmesg_restrict')
    if value is not None:
        try:
            restricted = int(value)
            if restricted == 1:
                result['restricted'] = True
                result['status'] = 'restricted'
                result['details'].append('dmesg restricted to privileged users')
            else:
                result['status'] = 'unrestricted'
                result['details'].append('dmesg readable by unprivileged users')
        except ValueError:
            result['details'].append(f'Unexpected value: {value}')
    else:
        result['details'].append('Unable to read dmesg_restrict')

    return result


def check_unprivileged_bpf():
    """Check unprivileged BPF restrictions."""
    result = {
        'disabled': False,
        'status': 'unknown',
        'details': []
    }

    value = read_sysctl('kernel.unprivileged_bpf_disabled')
    if value is not None:
        try:
            disabled = int(value)
            if disabled >= 1:
                result['disabled'] = True
                result['status'] = 'restricted'
                result['details'].append('Unprivileged BPF disabled')
            else:
                result['status'] = 'allowed'
                result['details'].append('Unprivileged BPF allowed (security risk)')
        except ValueError:
            result['details'].append(f'Unexpected value: {value}')
    else:
        result['details'].append('BPF restriction sysctl not available')

    return result


def check_userfaultfd():
    """Check unprivileged userfaultfd restrictions."""
    result = {
        'unprivileged': True,
        'status': 'unknown',
        'details': []
    }

    value = read_sysctl('vm.unprivileged_userfaultfd')
    if value is not None:
        try:
            allowed = int(value)
            if allowed == 0:
                result['unprivileged'] = False
                result['status'] = 'restricted'
                result['details'].append('Unprivileged userfaultfd disabled')
            else:
                result['status'] = 'allowed'
                result['details'].append('Unprivileged userfaultfd allowed')
        except ValueError:
            result['details'].append(f'Unexpected value: {value}')
    else:
        result['details'].append('userfaultfd sysctl not available (likely restricted)')
        result['status'] = 'not_available'

    return result


def check_yama_ptrace():
    """Check Yama LSM ptrace scope."""
    result = {
        'scope': None,
        'status': 'unknown',
        'details': []
    }

    value = read_sysctl('kernel.yama.ptrace_scope')
    if value is not None:
        try:
            scope = int(value)
            result['scope'] = scope
            scopes = {
                0: ('permissive', 'Classic ptrace permissions (any process)'),
                1: ('restricted', 'Restricted ptrace to child processes'),
                2: ('admin_only', 'Ptrace restricted to CAP_SYS_PTRACE'),
                3: ('disabled', 'Ptrace completely disabled')
            }
            if scope in scopes:
                result['status'], desc = scopes[scope]
                result['details'].append(desc)
            else:
                result['details'].append(f'Unknown scope: {scope}')
        except ValueError:
            result['details'].append(f'Unexpected value: {value}')
    else:
        result['details'].append('Yama LSM not available or not enabled')

    return result


def check_module_signing():
    """Check kernel module signing enforcement."""
    result = {
        'required': False,
        'status': 'unknown',
        'details': []
    }

    # Check kernel config for module signing
    rc, stdout, _ = run_command(['cat', '/proc/config.gz'])
    if rc != 0:
        # Try reading from /boot
        import glob
        config_files = glob.glob('/boot/config-*')
        if config_files:
            rc, stdout, _ = run_command(['cat', config_files[0]])

    if rc == 0:
        if 'CONFIG_MODULE_SIG_FORCE=y' in stdout:
            result['required'] = True
            result['status'] = 'enforced'
            result['details'].append('Module signature verification enforced')
        elif 'CONFIG_MODULE_SIG=y' in stdout:
            result['status'] = 'enabled'
            result['details'].append('Module signing enabled but not enforced')
        else:
            result['status'] = 'disabled'
            result['details'].append('Module signing not enabled')
    else:
        # Check lockdown as alternative
        lockdown = read_file('/sys/kernel/security/lockdown')
        if lockdown and 'integrity' in lockdown:
            result['status'] = 'lockdown'
            result['details'].append('Kernel lockdown provides module protection')
        else:
            result['details'].append('Unable to determine module signing status')

    return result


def check_stack_protector():
    """Check if kernel was built with stack protector."""
    result = {
        'enabled': False,
        'strong': False,
        'status': 'unknown',
        'details': []
    }

    # Check kernel config
    rc, stdout, _ = run_command(['cat', '/proc/config.gz'])
    if rc != 0:
        import glob
        config_files = glob.glob('/boot/config-*')
        if config_files:
            rc, stdout, _ = run_command(['cat', config_files[0]])

    if rc == 0:
        if 'CONFIG_STACKPROTECTOR_STRONG=y' in stdout or 'CONFIG_CC_STACKPROTECTOR_STRONG=y' in stdout:
            result['enabled'] = True
            result['strong'] = True
            result['status'] = 'strong'
            result['details'].append('Strong stack protector enabled')
        elif 'CONFIG_STACKPROTECTOR=y' in stdout or 'CONFIG_CC_STACKPROTECTOR=y' in stdout:
            result['enabled'] = True
            result['status'] = 'enabled'
            result['details'].append('Stack protector enabled')
        else:
            result['status'] = 'disabled'
            result['details'].append('Stack protector not enabled')
    else:
        result['details'].append('Unable to read kernel config')

    return result


def analyze_security(checks, strict=False):
    """Analyze security status and return issues/warnings."""
    issues = []
    warnings = []

    # Critical checks - always issues
    if checks['aslr']['status'] == 'disabled':
        issues.append('ASLR is disabled')
    elif checks['aslr']['status'] == 'partial':
        warnings.append('ASLR is only partially enabled')

    if checks['kaslr']['status'] == 'disabled':
        issues.append('KASLR is disabled')

    if checks['nx_dep']['status'] == 'disabled':
        issues.append('NX/DEP is disabled')

    if checks['spectre_meltdown']['status'] == 'vulnerable':
        issues.append('CPU vulnerabilities not fully mitigated')

    # Important checks
    if checks['kptr_restrict']['status'] == 'exposed':
        if strict:
            issues.append('Kernel pointers exposed')
        else:
            warnings.append('Kernel pointers exposed')

    if checks['dmesg_restrict']['status'] == 'unrestricted':
        warnings.append('dmesg readable by unprivileged users')

    if checks['unprivileged_bpf']['status'] == 'allowed':
        warnings.append('Unprivileged BPF allowed')

    if checks['yama_ptrace']['status'] == 'permissive':
        warnings.append('Yama ptrace scope is permissive')

    if checks['smep_smap']['status'] == 'disabled':
        warnings.append('SMEP/SMAP disabled despite CPU support')

    if checks['pti']['status'] == 'disabled':
        warnings.append('PTI/KPTI disabled')

    return issues, warnings


def output_plain(checks, issues, warnings, verbose, warn_only):
    """Output results in plain text format."""
    check_order = [
        ('ASLR', 'aslr'),
        ('KASLR', 'kaslr'),
        ('NX/DEP', 'nx_dep'),
        ('SMEP/SMAP', 'smep_smap'),
        ('PTI/KPTI', 'pti'),
        ('Spectre/Meltdown', 'spectre_meltdown'),
        ('Stack Protector', 'stack_protector'),
        ('Module Signing', 'module_signing'),
        ('kptr_restrict', 'kptr_restrict'),
        ('dmesg_restrict', 'dmesg_restrict'),
        ('Unprivileged BPF', 'unprivileged_bpf'),
        ('userfaultfd', 'userfaultfd'),
        ('Yama ptrace', 'yama_ptrace'),
    ]

    good_statuses = ['full', 'enabled', 'mitigated', 'strict', 'restricted',
                     'enforced', 'strong', 'disabled', 'admin_only']

    for name, key in check_order:
        check = checks[key]
        status = check.get('status', 'unknown')

        # For unprivileged_bpf, 'disabled' means the restriction is enabled (good)
        if key == 'unprivileged_bpf' and status == 'restricted':
            is_good = True
        elif key == 'userfaultfd' and status == 'restricted':
            is_good = True
        else:
            is_good = status in good_statuses

        # Skip good items in warn-only mode
        if warn_only and is_good:
            continue

        # Status symbol
        if is_good:
            symbol = '[OK]'
        elif status in ['partial', 'allowed', 'permissive', 'unrestricted']:
            symbol = '[--]'
        elif status in ['disabled', 'exposed', 'vulnerable']:
            symbol = '[!!]'
        else:
            symbol = '[??]'

        print(f"{symbol} {name}: {status}")

        if verbose and check.get('details'):
            for detail in check['details']:
                print(f"    {detail}")

    # Print vulnerabilities in verbose mode
    if verbose and checks['spectre_meltdown'].get('vulnerabilities'):
        print()
        print("CPU Vulnerabilities:")
        for vuln, status in sorted(checks['spectre_meltdown']['vulnerabilities'].items()):
            print(f"  {vuln}: {status}")

    # Print issues and warnings
    if issues:
        print()
        print("ISSUES:")
        for issue in issues:
            print(f"  ! {issue}")

    if warnings and not warn_only:
        print()
        print("WARNINGS:")
        for warning in warnings:
            print(f"  * {warning}")


def output_json(checks, issues, warnings):
    """Output results in JSON format."""
    output = {
        'checks': checks,
        'issues': issues,
        'warnings': warnings,
        'summary': {
            'aslr': checks['aslr']['status'],
            'kaslr': checks['kaslr']['status'],
            'nx_dep': checks['nx_dep']['status'],
            'smep_smap': checks['smep_smap']['status'],
            'pti': checks['pti']['status'],
            'spectre_meltdown': checks['spectre_meltdown']['status'],
            'kptr_restrict': checks['kptr_restrict']['status'],
            'dmesg_restrict': checks['dmesg_restrict']['status'],
        }
    }
    print(json.dumps(output, indent=2))


def output_table(checks, issues, warnings, verbose, warn_only):
    """Output results in table format."""
    print("=" * 75)
    print("KERNEL SECURITY HARDENING AUDIT")
    print("=" * 75)
    print(f"{'CHECK':<25} {'STATUS':<15} {'DETAILS':<35}")
    print("-" * 75)

    check_order = [
        ('ASLR', 'aslr'),
        ('KASLR', 'kaslr'),
        ('NX/DEP', 'nx_dep'),
        ('SMEP/SMAP', 'smep_smap'),
        ('PTI/KPTI', 'pti'),
        ('Spectre/Meltdown', 'spectre_meltdown'),
        ('Stack Protector', 'stack_protector'),
        ('Module Signing', 'module_signing'),
        ('kptr_restrict', 'kptr_restrict'),
        ('dmesg_restrict', 'dmesg_restrict'),
        ('Unprivileged BPF', 'unprivileged_bpf'),
        ('userfaultfd', 'userfaultfd'),
        ('Yama ptrace', 'yama_ptrace'),
    ]

    good_statuses = ['full', 'enabled', 'mitigated', 'strict', 'restricted',
                     'enforced', 'strong', 'admin_only']

    for name, key in check_order:
        check = checks[key]
        status = check.get('status', 'unknown')
        details = check['details'][0][:35] if check.get('details') else ''

        # Skip good items in warn-only mode
        is_good = status in good_statuses
        if warn_only and is_good:
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


def main():
    parser = argparse.ArgumentParser(
        description='Audit kernel security hardening settings',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Basic security audit
  %(prog)s --format json       # JSON output for automation
  %(prog)s --verbose           # Show detailed information
  %(prog)s --warn-only         # Only show issues/warnings
  %(prog)s --strict            # Treat more findings as errors

Checks performed:
  - ASLR/KASLR randomization
  - NX/DEP execution prevention
  - SMEP/SMAP CPU protections
  - PTI/KPTI page table isolation
  - Spectre/Meltdown mitigations
  - Stack protector status
  - Kernel pointer hiding
  - dmesg restrictions
  - Unprivileged BPF/userfaultfd
  - Yama LSM ptrace scope
  - Module signing enforcement

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
        '-w', '--warn-only',
        action='store_true',
        help='Only show checks with warnings or issues'
    )
    parser.add_argument(
        '--strict',
        action='store_true',
        help='Treat exposed kernel pointers as error (not warning)'
    )

    args = parser.parse_args()

    # Run all checks
    checks = {
        'aslr': check_aslr(),
        'kaslr': check_kaslr(),
        'nx_dep': check_nx_dep(),
        'smep_smap': check_smep_smap(),
        'pti': check_pti(),
        'spectre_meltdown': check_spectre_meltdown(),
        'kptr_restrict': check_kptr_restrict(),
        'dmesg_restrict': check_dmesg_restrict(),
        'unprivileged_bpf': check_unprivileged_bpf(),
        'userfaultfd': check_userfaultfd(),
        'yama_ptrace': check_yama_ptrace(),
        'module_signing': check_module_signing(),
        'stack_protector': check_stack_protector(),
    }

    # Analyze results
    issues, warnings = analyze_security(checks, strict=args.strict)

    # Output results
    if args.format == 'json':
        output_json(checks, issues, warnings)
    elif args.format == 'table':
        output_table(checks, issues, warnings, args.verbose, args.warn_only)
    else:
        output_plain(checks, issues, warnings, args.verbose, args.warn_only)

    # Exit code
    if issues:
        sys.exit(1)
    elif warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
