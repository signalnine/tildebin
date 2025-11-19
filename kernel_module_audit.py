#!/usr/bin/env python3
"""
Audit loaded kernel modules for security and compliance.

Identifies potentially suspicious or unknown kernel modules, checks for
unsigned modules (when kernel lockdown is enabled), and reports module
parameters. Useful for baremetal security auditing in large-scale environments.

Exit codes:
    0 - No issues detected
    1 - Warnings or issues found
    2 - Usage error or missing dependencies
"""

import argparse
import json
import os
import re
import sys


# Well-known kernel modules that are generally safe
KNOWN_SAFE_MODULES = {
    # Core system
    'ext4', 'xfs', 'btrfs', 'nfs', 'nfsd', 'cifs', 'overlay', 'fuse',
    'dm_mod', 'dm_crypt', 'dm_mirror', 'dm_snapshot', 'dm_thin_pool',
    'raid0', 'raid1', 'raid10', 'raid456', 'md_mod',
    'loop', 'nbd', 'scsi_mod', 'sd_mod', 'sr_mod', 'sg',

    # Networking
    'ip_tables', 'ip6_tables', 'iptable_filter', 'iptable_nat', 'iptable_mangle',
    'nf_conntrack', 'nf_nat', 'nf_defrag_ipv4', 'nf_defrag_ipv6',
    'bridge', 'br_netfilter', 'vxlan', 'bonding', 'tun', 'tap', 'veth',
    'ipvlan', 'macvlan', 'wireguard', 'openvswitch',
    'tcp_bbr', 'tcp_cubic', 'tcp_vegas',

    # Hardware drivers
    'e1000', 'e1000e', 'igb', 'ixgbe', 'i40e', 'ice', 'mlx4_core', 'mlx5_core',
    'bnxt_en', 'r8169', 'virtio_net', 'virtio_blk', 'virtio_pci',
    'nvme', 'ahci', 'libahci', 'megaraid_sas', 'mpt3sas', 'hpsa',
    'i915', 'amdgpu', 'nouveau', 'nvidia', 'nvidia_modeset', 'nvidia_uvm',
    'snd', 'snd_hda_intel', 'snd_hda_codec', 'usbcore', 'usb_storage',

    # Virtualization
    'kvm', 'kvm_intel', 'kvm_amd', 'vhost', 'vhost_net', 'vhost_scsi',
    'irqbypass', 'virtio', 'virtio_ring', 'virtio_mmio',
    'xen_blkfront', 'xen_netfront', 'vmw_balloon', 'vmw_vmci',

    # Container/Security
    'nf_tables', 'nft_chain_nat', 'nft_compat', 'xt_conntrack',
    'xt_MASQUERADE', 'xt_addrtype', 'xt_comment', 'xt_mark', 'xt_nat',
    'cls_cgroup', 'sch_fq', 'sch_fq_codel',
    'bpf', 'bpfilter',

    # Misc system
    'acpi', 'acpi_cpufreq', 'cpufreq_ondemand', 'cpufreq_conservative',
    'coretemp', 'k10temp', 'nct6775', 'it87', 'hwmon',
    'lp', 'parport', 'pps_core', 'ptp',
    'efi', 'efivars', 'tpm', 'tpm_tis', 'tpm_crb',
    'ipmi_si', 'ipmi_devintf', 'ipmi_msghandler',
    'edac_core', 'edac_mce_amd', 'ie31200_edac',
    'pcspkr', 'serio_raw', 'i2c_core', 'crc32c_intel',
}


def read_proc_modules():
    """
    Read /proc/modules to get list of loaded kernel modules.

    Returns list of dicts with module name, size, refcount, and dependencies.
    """
    modules = []

    try:
        with open('/proc/modules', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    module = {
                        'name': parts[0],
                        'size': int(parts[1]),
                        'refcount': int(parts[2]),
                        'used_by': parts[3].rstrip(',').split(',') if parts[3] != '-' else [],
                        'state': parts[4] if len(parts) > 4 else 'Live',
                        'address': parts[5] if len(parts) > 5 else None,
                    }
                    modules.append(module)
    except (IOError, OSError) as e:
        print(f"Error: Cannot read /proc/modules: {e}", file=sys.stderr)
        sys.exit(2)

    return modules


def get_module_info(module_name):
    """
    Get detailed module information from /sys/module/.

    Returns dict with parameters, version, srcversion, etc.
    """
    info = {
        'parameters': {},
        'version': None,
        'srcversion': None,
        'taint': None,
    }

    module_path = f'/sys/module/{module_name}'

    if not os.path.isdir(module_path):
        return info

    # Read version
    version_path = f'{module_path}/version'
    if os.path.exists(version_path):
        try:
            with open(version_path, 'r') as f:
                info['version'] = f.read().strip()
        except (IOError, OSError):
            pass

    # Read srcversion
    srcversion_path = f'{module_path}/srcversion'
    if os.path.exists(srcversion_path):
        try:
            with open(srcversion_path, 'r') as f:
                info['srcversion'] = f.read().strip()
        except (IOError, OSError):
            pass

    # Read taint flags
    taint_path = f'{module_path}/taint'
    if os.path.exists(taint_path):
        try:
            with open(taint_path, 'r') as f:
                taint = f.read().strip()
                if taint:
                    info['taint'] = taint
        except (IOError, OSError):
            pass

    # Read parameters
    params_path = f'{module_path}/parameters'
    if os.path.isdir(params_path):
        try:
            for param_name in os.listdir(params_path):
                param_file = f'{params_path}/{param_name}'
                try:
                    with open(param_file, 'r') as f:
                        info['parameters'][param_name] = f.read().strip()
                except (IOError, OSError):
                    info['parameters'][param_name] = '<unreadable>'
        except (IOError, OSError):
            pass

    return info


def check_kernel_lockdown():
    """Check if kernel lockdown is enabled."""
    lockdown_path = '/sys/kernel/security/lockdown'

    if not os.path.exists(lockdown_path):
        return None

    try:
        with open(lockdown_path, 'r') as f:
            content = f.read().strip()
            # Parse format like "[none] integrity confidentiality"
            match = re.search(r'\[(\w+)\]', content)
            if match:
                return match.group(1)
            return content
    except (IOError, OSError):
        return None


def get_kernel_taint():
    """Get kernel taint flags from /proc/sys/kernel/tainted."""
    try:
        with open('/proc/sys/kernel/tainted', 'r') as f:
            return int(f.read().strip())
    except (IOError, OSError, ValueError):
        return None


def decode_taint_flags(taint_value):
    """Decode kernel taint bitmask into human-readable flags."""
    flags = []

    taint_meanings = {
        0: 'proprietary module loaded',
        1: 'module force loaded',
        2: 'kernel running on out-of-spec system',
        3: 'module force unloaded',
        4: 'processor reported MCE',
        5: 'bad page referenced',
        6: 'user requested taint',
        7: 'kernel died recently (OOPS or BUG)',
        8: 'ACPI table overridden',
        9: 'kernel issued warning',
        10: 'staging driver loaded',
        11: 'applied workaround for platform firmware bug',
        12: 'externally-built (out-of-tree) module loaded',
        13: 'unsigned module loaded',
        14: 'soft lockup occurred',
        15: 'kernel live patched',
        16: 'auxiliary taint for distros',
        17: 'kernel built with struct randomization',
        18: 'in-kernel test module loaded',
    }

    for bit, meaning in taint_meanings.items():
        if taint_value & (1 << bit):
            flags.append(meaning)

    return flags


def analyze_modules(modules, check_unknown=True):
    """
    Analyze modules for potential issues.

    Returns dict with categorized modules and issues.
    """
    result = {
        'total_count': len(modules),
        'known_count': 0,
        'unknown_count': 0,
        'tainted_count': 0,
        'issues': [],
        'modules': {
            'known': [],
            'unknown': [],
            'tainted': [],
        }
    }

    for module in modules:
        name = module['name']
        info = get_module_info(name)

        module_entry = {
            **module,
            **info,
        }

        # Check for taint
        if info.get('taint'):
            result['tainted_count'] += 1
            result['modules']['tainted'].append(module_entry)
            result['issues'].append({
                'type': 'TAINTED',
                'module': name,
                'message': f"Module '{name}' has taint flag: {info['taint']}"
            })

        # Check if module is known/unknown
        if check_unknown:
            # Strip version suffix (e.g., nf_nat_ipv4 -> nf_nat)
            base_name = name.split('_ipv')[0].split('_ipv6')[0]

            if name in KNOWN_SAFE_MODULES or base_name in KNOWN_SAFE_MODULES:
                result['known_count'] += 1
                result['modules']['known'].append(module_entry)
            else:
                result['unknown_count'] += 1
                result['modules']['unknown'].append(module_entry)

                # Only flag as issue if it's not in known and has suspicious characteristics
                if info.get('taint') or not info.get('srcversion'):
                    result['issues'].append({
                        'type': 'UNKNOWN',
                        'module': name,
                        'message': f"Unknown module '{name}' loaded (size: {module['size']} bytes)"
                    })

    return result


def format_size(size_bytes):
    """Format bytes to human readable."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / 1024 / 1024:.1f} MB"


def output_plain(analysis, kernel_taint, lockdown, warn_only=False, verbose=False):
    """Output results in plain text format."""
    lines = []

    # Summary
    if not warn_only:
        lines.append("=== Kernel Module Audit ===")
        lines.append(f"Total modules: {analysis['total_count']}")
        lines.append(f"Known modules: {analysis['known_count']}")
        lines.append(f"Unknown modules: {analysis['unknown_count']}")
        lines.append(f"Tainted modules: {analysis['tainted_count']}")

        if kernel_taint is not None:
            if kernel_taint == 0:
                lines.append("Kernel taint: None (clean)")
            else:
                flags = decode_taint_flags(kernel_taint)
                lines.append(f"Kernel taint: {kernel_taint} ({', '.join(flags)})")

        if lockdown:
            lines.append(f"Kernel lockdown: {lockdown}")

        lines.append("")

    # Issues
    if analysis['issues']:
        lines.append("=== Issues Found ===")
        for issue in analysis['issues']:
            lines.append(f"[{issue['type']}] {issue['message']}")
        lines.append("")
    elif not warn_only:
        lines.append("No security issues detected.")
        lines.append("")

    # Verbose output - show all modules
    if verbose and not warn_only:
        if analysis['modules']['unknown']:
            lines.append("=== Unknown Modules ===")
            for mod in analysis['modules']['unknown']:
                lines.append(f"  {mod['name']}: {format_size(mod['size'])}")
                if mod.get('version'):
                    lines.append(f"    Version: {mod['version']}")
                if mod.get('parameters'):
                    for param, value in mod['parameters'].items():
                        lines.append(f"    {param} = {value}")
            lines.append("")

        if analysis['modules']['tainted']:
            lines.append("=== Tainted Modules ===")
            for mod in analysis['modules']['tainted']:
                lines.append(f"  {mod['name']}: taint={mod.get('taint', 'unknown')}")
            lines.append("")

    if not lines:
        return "No issues found."

    return '\n'.join(lines)


def output_json(analysis, kernel_taint, lockdown, warn_only=False):
    """Output results in JSON format."""
    result = {
        'summary': {
            'total_modules': analysis['total_count'],
            'known_modules': analysis['known_count'],
            'unknown_modules': analysis['unknown_count'],
            'tainted_modules': analysis['tainted_count'],
            'kernel_taint': kernel_taint,
            'kernel_taint_flags': decode_taint_flags(kernel_taint) if kernel_taint else [],
            'kernel_lockdown': lockdown,
        },
        'issues': analysis['issues'],
    }

    if not warn_only:
        result['modules'] = {
            'unknown': analysis['modules']['unknown'],
            'tainted': analysis['modules']['tainted'],
        }

    return json.dumps(result, indent=2)


def output_table(analysis, kernel_taint, lockdown, warn_only=False):
    """Output results in table format."""
    lines = []

    if not warn_only:
        lines.append("KERNEL MODULE AUDIT SUMMARY")
        lines.append("-" * 60)
        lines.append(f"{'Metric':<30} {'Value':<30}")
        lines.append("-" * 60)
        lines.append(f"{'Total Modules':<30} {analysis['total_count']:<30}")
        lines.append(f"{'Known Modules':<30} {analysis['known_count']:<30}")
        lines.append(f"{'Unknown Modules':<30} {analysis['unknown_count']:<30}")
        lines.append(f"{'Tainted Modules':<30} {analysis['tainted_count']:<30}")

        if kernel_taint is not None:
            taint_str = 'Clean' if kernel_taint == 0 else str(kernel_taint)
            lines.append(f"{'Kernel Taint':<30} {taint_str:<30}")

        if lockdown:
            lines.append(f"{'Kernel Lockdown':<30} {lockdown:<30}")

        lines.append("")

    if analysis['issues']:
        lines.append("ISSUES")
        lines.append("-" * 60)
        lines.append(f"{'Type':<12} {'Module':<20} {'Message':<26}")
        lines.append("-" * 60)
        for issue in analysis['issues']:
            msg = issue['message'][:26] + '...' if len(issue['message']) > 26 else issue['message']
            lines.append(f"{issue['type']:<12} {issue['module']:<20} {msg:<26}")
    elif warn_only:
        lines.append("No issues found.")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Audit loaded kernel modules for security and compliance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic audit of loaded modules
  %(prog)s

  # Show only issues/warnings
  %(prog)s --warn-only

  # JSON output for monitoring systems
  %(prog)s --format json

  # Verbose output with module details
  %(prog)s --verbose

  # Skip unknown module checking
  %(prog)s --no-unknown-check

Exit codes:
  0 - No issues detected
  1 - Issues detected (tainted/suspicious modules)
  2 - Usage error or missing dependencies

Notes:
  - Tainted modules indicate non-mainline or unsigned modules
  - Unknown modules are not in the built-in safe list
  - Kernel lockdown restricts module loading when enabled
        """
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
        help='Only show issues and warnings'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed module information'
    )
    parser.add_argument(
        '--no-unknown-check',
        action='store_true',
        help='Skip checking for unknown modules'
    )

    args = parser.parse_args()

    # Read module information
    modules = read_proc_modules()

    # Get kernel security state
    kernel_taint = get_kernel_taint()
    lockdown = check_kernel_lockdown()

    # Analyze modules
    analysis = analyze_modules(
        modules,
        check_unknown=not args.no_unknown_check
    )

    # Output results
    if args.format == 'json':
        output = output_json(analysis, kernel_taint, lockdown, args.warn_only)
    elif args.format == 'table':
        output = output_table(analysis, kernel_taint, lockdown, args.warn_only)
    else:
        output = output_plain(analysis, kernel_taint, lockdown, args.warn_only, args.verbose)

    print(output)

    # Determine exit code
    has_issues = bool(analysis['issues']) or (kernel_taint and kernel_taint != 0)

    return 1 if has_issues else 0


if __name__ == '__main__':
    sys.exit(main())
