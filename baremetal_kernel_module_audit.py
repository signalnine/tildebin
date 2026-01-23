#!/usr/bin/env python3
"""
Audit loaded kernel modules for security and compliance.

Identifies unsigned modules, out-of-tree modules, modules that taint the kernel,
and potentially problematic drivers. Useful for security compliance auditing,
debugging kernel issues, and maintaining fleet consistency.

Key features:
- Lists all loaded kernel modules with metadata
- Identifies unsigned/unsigned modules (kernel tainting)
- Detects out-of-tree modules (not part of mainline kernel)
- Flags staging drivers and deprecated modules
- Shows module dependencies and reference counts
- Outputs in plain, JSON, or table format

Exit codes:
    0 - All modules are signed and in-tree (healthy)
    1 - Warnings detected (unsigned or out-of-tree modules found)
    2 - Usage error or missing dependency
"""

import argparse
import subprocess
import sys
import json
import os
import re


def run_command(cmd, shell=False):
    """Execute a command and return output"""
    try:
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def get_kernel_taint():
    """Get kernel taint flags and their meanings"""
    taint_flags = {
        'G': ('proprietary', 'Proprietary module loaded'),
        'P': ('proprietary', 'Proprietary module loaded (older flag)'),
        'F': ('forced', 'Module force loaded'),
        'S': ('smp_unsafe', 'SMP unsafe module'),
        'R': ('forced_unload', 'Module force unloaded'),
        'M': ('machine_check', 'Machine check exception occurred'),
        'B': ('bad_page', 'Bad page reference'),
        'U': ('userspace', 'Userspace wrote to /dev/mem'),
        'D': ('oops', 'Kernel oops has occurred'),
        'A': ('acpi', 'ACPI table overridden'),
        'W': ('warning', 'Kernel warning has occurred'),
        'C': ('staging', 'Staging driver loaded'),
        'I': ('firmware', 'Firmware bug workaround applied'),
        'O': ('out_of_tree', 'Out-of-tree module loaded'),
        'E': ('unsigned', 'Unsigned module loaded'),
        'L': ('softlockup', 'Soft lockup occurred'),
        'K': ('live_patch', 'Kernel live patch applied'),
        'X': ('auxiliary', 'Auxiliary taint'),
        'T': ('randstruct', 'Randstruct randomization'),
        'N': ('test', 'Test taint (for testing)'),
    }

    try:
        with open('/proc/sys/kernel/tainted', 'r') as f:
            taint_value = int(f.read().strip())
    except (IOError, ValueError):
        return 0, []

    active_taints = []
    if taint_value == 0:
        return 0, []

    # The taint value is a bitmask
    taint_bits = {
        0: 'P',   # Proprietary module
        1: 'F',   # Module force loaded
        2: 'S',   # SMP unsafe
        3: 'R',   # Module force unloaded
        4: 'M',   # Machine check
        5: 'B',   # Bad page
        6: 'U',   # User wrote to /dev/mem
        7: 'D',   # Oops occurred
        8: 'A',   # ACPI override
        9: 'W',   # Warning occurred
        10: 'C',  # Staging driver
        11: 'I',  # Firmware workaround
        12: 'O',  # Out-of-tree module
        13: 'E',  # Unsigned module
        14: 'L',  # Soft lockup
        15: 'K',  # Live patch
        16: 'X',  # Auxiliary
        17: 'T',  # Randstruct
        18: 'N',  # Test
    }

    for bit, flag in taint_bits.items():
        if taint_value & (1 << bit):
            if flag in taint_flags:
                category, description = taint_flags[flag]
                active_taints.append({
                    'flag': flag,
                    'category': category,
                    'description': description
                })

    return taint_value, active_taints


def get_loaded_modules():
    """Get list of loaded kernel modules"""
    modules = []

    returncode, stdout, _ = run_command(['lsmod'])
    if returncode != 0:
        return modules

    lines = stdout.strip().split('\n')
    if len(lines) < 2:
        return modules

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            module = {
                'name': parts[0],
                'size': int(parts[1]),
                'used_by_count': int(parts[2]),
                'used_by': parts[3].split(',') if len(parts) > 3 and parts[3] != '-' else [],
                'flags': [],
                'issues': []
            }
            modules.append(module)

    return modules


def get_module_info(module_name):
    """Get detailed info about a module using modinfo"""
    info = {}

    returncode, stdout, stderr = run_command(['modinfo', module_name])
    if returncode != 0:
        return info

    for line in stdout.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()

            if key == 'filename':
                info['filename'] = value
            elif key == 'version':
                info['version'] = value
            elif key == 'license':
                info['license'] = value
            elif key == 'description':
                info['description'] = value
            elif key == 'author':
                info['author'] = value
            elif key == 'srcversion':
                info['srcversion'] = value
            elif key == 'vermagic':
                info['vermagic'] = value
            elif key == 'sig_id':
                info['signed'] = True
            elif key == 'signer':
                info['signer'] = value
            elif key == 'sig_key':
                info['sig_key'] = value
            elif key == 'intree':
                info['intree'] = value.lower() == 'y'
            elif key == 'retpoline':
                info['retpoline'] = value.lower() == 'y'

    # Check for signature
    if 'signer' in info or 'sig_key' in info:
        info['signed'] = True
    elif 'signed' not in info:
        info['signed'] = False

    # Determine if module is in-tree (built into kernel source)
    if 'intree' not in info:
        filename = info.get('filename', '')
        if '/kernel/' in filename or '/updates/' in filename:
            info['intree'] = True
        elif '/extra/' in filename or '/weak-updates/' in filename:
            info['intree'] = False
        else:
            info['intree'] = None  # Unknown

    return info


def analyze_module(module, module_info):
    """Analyze a module for potential issues"""
    issues = []
    flags = []

    license_val = module_info.get('license', '').upper()
    filename = module_info.get('filename', '')

    # Check for proprietary license
    proprietary_licenses = ['PROPRIETARY', 'NVIDIA', 'CLOSED']
    if any(p in license_val for p in proprietary_licenses):
        flags.append('proprietary')
        issues.append('Proprietary license may taint kernel')

    # Check for unsigned module
    if not module_info.get('signed', False):
        flags.append('unsigned')
        issues.append('Module is not signed')

    # Check for out-of-tree module
    if module_info.get('intree') is False:
        flags.append('out-of-tree')
        issues.append('Module is out-of-tree (not from kernel source)')

    # Check for staging drivers
    if '/staging/' in filename:
        flags.append('staging')
        issues.append('Staging driver (experimental, may be unstable)')

    # Check for deprecated modules
    deprecated_modules = [
        'floppy',  # Floppy disk driver
        'parport', 'parport_pc',  # Parallel port
        'lp',  # Line printer
        'pcspkr',  # PC speaker
    ]
    if module['name'] in deprecated_modules:
        flags.append('deprecated')
        issues.append('Deprecated/legacy module')

    # Check for known problematic modules
    problematic_modules = {
        'nouveau': 'Open-source NVIDIA driver (consider nvidia for production)',
        'r8169': 'Realtek driver (known issues with certain NICs)',
    }
    if module['name'] in problematic_modules:
        flags.append('problematic')
        issues.append(problematic_modules[module['name']])

    # Check for virtualization detection
    virt_modules = ['kvm', 'kvm_intel', 'kvm_amd', 'vhost_net', 'vhost_scsi']
    if module['name'] in virt_modules:
        flags.append('virtualization')

    # Check for security modules
    security_modules = ['apparmor', 'selinux', 'tomoyo', 'smack']
    if module['name'] in security_modules:
        flags.append('security')

    # Check for filesystem modules
    fs_modules = ['ext4', 'xfs', 'btrfs', 'zfs', 'nfs', 'cifs', 'fuse']
    if module['name'] in fs_modules:
        flags.append('filesystem')

    module['flags'] = flags
    module['issues'] = issues
    module['info'] = module_info

    return module


def collect_module_data(include_all=False, check_signatures=True):
    """Collect and analyze all module data"""
    data = {
        'kernel_version': '',
        'taint_value': 0,
        'taints': [],
        'modules': [],
        'summary': {
            'total': 0,
            'unsigned': 0,
            'out_of_tree': 0,
            'proprietary': 0,
            'staging': 0,
            'with_issues': 0
        }
    }

    # Get kernel version
    returncode, stdout, _ = run_command(['uname', '-r'])
    data['kernel_version'] = stdout.strip() if returncode == 0 else 'unknown'

    # Get taint status
    data['taint_value'], data['taints'] = get_kernel_taint()

    # Get modules
    modules = get_loaded_modules()

    for module in modules:
        if check_signatures:
            module_info = get_module_info(module['name'])
            module = analyze_module(module, module_info)
        else:
            module['flags'] = []
            module['issues'] = []
            module['info'] = {}

        # Update summary
        data['summary']['total'] += 1
        if 'unsigned' in module['flags']:
            data['summary']['unsigned'] += 1
        if 'out-of-tree' in module['flags']:
            data['summary']['out_of_tree'] += 1
        if 'proprietary' in module['flags']:
            data['summary']['proprietary'] += 1
        if 'staging' in module['flags']:
            data['summary']['staging'] += 1
        if module['issues']:
            data['summary']['with_issues'] += 1

        # Include module based on filter
        if include_all or module['issues']:
            data['modules'].append(module)

    # Sort by issue count (modules with issues first)
    data['modules'].sort(key=lambda m: len(m['issues']), reverse=True)

    return data


def format_output_plain(data, verbose=False):
    """Format output as plain text"""
    lines = []

    lines.append("Kernel Module Audit Report")
    lines.append("=" * 60)
    lines.append("Kernel Version: {}".format(data['kernel_version']))
    lines.append("")

    # Taint status
    if data['taint_value'] == 0:
        lines.append("Kernel Taint: None (clean)")
    else:
        lines.append("Kernel Taint: {} (tainted)".format(data['taint_value']))
        for taint in data['taints']:
            lines.append("  [{}] {}".format(taint['flag'], taint['description']))
    lines.append("")

    # Summary
    lines.append("Summary:")
    lines.append("  Total modules loaded: {}".format(data['summary']['total']))
    lines.append("  Unsigned modules: {}".format(data['summary']['unsigned']))
    lines.append("  Out-of-tree modules: {}".format(data['summary']['out_of_tree']))
    lines.append("  Proprietary modules: {}".format(data['summary']['proprietary']))
    lines.append("  Staging drivers: {}".format(data['summary']['staging']))
    lines.append("  Modules with issues: {}".format(data['summary']['with_issues']))
    lines.append("")

    # Module details
    if data['modules']:
        lines.append("Module Details:")
        lines.append("-" * 60)

        for module in data['modules']:
            flags_str = ','.join(module['flags']) if module['flags'] else 'ok'
            lines.append("{} ({})".format(module['name'], flags_str))

            if verbose:
                info = module.get('info', {})
                if info.get('license'):
                    lines.append("  License: {}".format(info['license']))
                if info.get('version'):
                    lines.append("  Version: {}".format(info['version']))
                if info.get('description'):
                    lines.append("  Description: {}".format(info['description'][:60]))
                lines.append("  Size: {} bytes, Used by: {}".format(
                    module['size'],
                    ','.join(module['used_by']) if module['used_by'] else 'none'
                ))

            for issue in module['issues']:
                lines.append("  [!] {}".format(issue))

            lines.append("")

    return '\n'.join(lines)


def format_output_table(data):
    """Format output as table"""
    lines = []

    lines.append("{:<25} {:<12} {:<10} {:<20} {}".format(
        "Module", "Size", "Used By", "Flags", "Issues"
    ))
    lines.append("-" * 90)

    for module in data['modules']:
        flags_str = ','.join(module['flags'][:3]) if module['flags'] else '-'
        issues_count = len(module['issues'])
        issues_str = "{} issue(s)".format(issues_count) if issues_count else 'ok'
        used_count = module['used_by_count']

        lines.append("{:<25} {:<12} {:<10} {:<20} {}".format(
            module['name'][:25],
            module['size'],
            used_count,
            flags_str[:20],
            issues_str
        ))

    return '\n'.join(lines)


def format_output_json(data):
    """Format output as JSON"""
    return json.dumps(data, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(
        description="Audit loaded kernel modules for security and compliance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Module Flags:
  proprietary  - Module has proprietary license
  unsigned     - Module is not cryptographically signed
  out-of-tree  - Module not from mainline kernel source
  staging      - Experimental staging driver
  deprecated   - Legacy/deprecated module

Examples:
  %(prog)s                      # Show only modules with issues
  %(prog)s --all                # Show all loaded modules
  %(prog)s --format json        # JSON output for automation
  %(prog)s --warn-only          # Only show warnings (non-zero exit if issues)
"""
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed module information"
    )

    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Show all modules, not just those with issues"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show modules with warnings/issues"
    )

    parser.add_argument(
        "--no-signature-check",
        action="store_true",
        help="Skip signature verification (faster but less thorough)"
    )

    args = parser.parse_args()

    # Collect module data
    data = collect_module_data(
        include_all=args.all and not args.warn_only,
        check_signatures=not args.no_signature_check
    )

    # Filter if warn-only
    if args.warn_only:
        data['modules'] = [m for m in data['modules'] if m['issues']]

    # Format output
    if args.format == "json":
        output = format_output_json(data)
    elif args.format == "table":
        output = format_output_table(data)
    else:
        output = format_output_plain(data, args.verbose)

    print(output)

    # Determine exit code
    has_issues = data['summary']['with_issues'] > 0
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
