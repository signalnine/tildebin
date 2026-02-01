#!/usr/bin/env python3
"""
Audit GRUB bootloader configuration for security and consistency.

This script analyzes GRUB configuration files to detect security issues,
misconfigurations, and ensure boot parameters are properly set. Critical
for large-scale baremetal environments where consistent boot configuration
is essential for fleet management.

Checks performed:
- GRUB configuration file presence and permissions
- Bootloader password protection status
- Kernel command line parameters audit
- Timeout and default boot entry settings
- Recovery mode availability
- IOMMU and security-related boot parameters
- Deprecated or problematic kernel parameters

Exit codes:
    0 - Configuration is secure and properly configured
    1 - Configuration issues or warnings detected
    2 - Usage error or GRUB not found
"""

import argparse
import sys
import os
import json
import re
import glob
import subprocess


def find_grub_config():
    """Find GRUB configuration files.

    Returns:
        dict: Paths to GRUB configuration files
    """
    paths = {
        'main_config': None,
        'default_config': None,
        'custom_configs': [],
        'grub_dir': None
    }

    # Check for GRUB2 locations (most common)
    grub_dirs = [
        '/boot/grub2',      # RHEL/CentOS/Fedora
        '/boot/grub',       # Debian/Ubuntu
        '/boot/efi/EFI/*/grub.cfg',  # EFI systems
    ]

    for grub_dir in grub_dirs:
        if '*' in grub_dir:
            # Handle glob pattern for EFI
            matches = glob.glob(grub_dir)
            if matches:
                paths['main_config'] = matches[0]
                paths['grub_dir'] = os.path.dirname(matches[0])
                break
        else:
            cfg_path = os.path.join(grub_dir, 'grub.cfg')
            if os.path.exists(cfg_path):
                paths['main_config'] = cfg_path
                paths['grub_dir'] = grub_dir
                break

    # Check for defaults file
    default_locations = [
        '/etc/default/grub',
        '/etc/sysconfig/grub'
    ]

    for default_loc in default_locations:
        if os.path.exists(default_loc):
            paths['default_config'] = default_loc
            break

    # Find custom configuration files
    custom_dirs = [
        '/etc/grub.d',
        '/etc/default/grub.d'
    ]

    for custom_dir in custom_dirs:
        if os.path.isdir(custom_dir):
            for f in os.listdir(custom_dir):
                full_path = os.path.join(custom_dir, f)
                if os.path.isfile(full_path):
                    paths['custom_configs'].append(full_path)

    return paths


def check_file_permissions(filepath):
    """Check file permissions for security issues.

    Args:
        filepath: Path to check

    Returns:
        dict: Permission information
    """
    info = {
        'path': filepath,
        'exists': False,
        'readable': False,
        'mode': None,
        'mode_octal': None,
        'owner_uid': None,
        'owner_gid': None,
        'world_readable': False,
        'world_writable': False
    }

    if not os.path.exists(filepath):
        return info

    info['exists'] = True
    info['readable'] = os.access(filepath, os.R_OK)

    try:
        stat_info = os.stat(filepath)
        info['mode'] = stat_info.st_mode
        info['mode_octal'] = oct(stat_info.st_mode)[-3:]
        info['owner_uid'] = stat_info.st_uid
        info['owner_gid'] = stat_info.st_gid

        # Check world permissions
        info['world_readable'] = bool(stat_info.st_mode & 0o004)
        info['world_writable'] = bool(stat_info.st_mode & 0o002)

    except Exception as e:
        info['error'] = str(e)

    return info


def parse_grub_defaults(filepath):
    """Parse GRUB defaults configuration file.

    Args:
        filepath: Path to defaults file

    Returns:
        dict: Parsed configuration
    """
    config = {
        'path': filepath,
        'settings': {},
        'cmdline': '',
        'timeout': None,
        'default': None
    }

    if not filepath or not os.path.exists(filepath):
        return config

    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Parse KEY=VALUE or KEY="VALUE"
                match = re.match(r'^([A-Z_]+)=(.*)$', line)
                if match:
                    key = match.group(1)
                    value = match.group(2).strip('"\'')
                    config['settings'][key] = value

                    if key == 'GRUB_CMDLINE_LINUX':
                        config['cmdline'] = value
                    elif key == 'GRUB_CMDLINE_LINUX_DEFAULT':
                        config['cmdline'] += ' ' + value
                    elif key == 'GRUB_TIMEOUT':
                        try:
                            config['timeout'] = int(value)
                        except ValueError:
                            config['timeout'] = value
                    elif key == 'GRUB_DEFAULT':
                        config['default'] = value

    except Exception as e:
        config['error'] = str(e)

    return config


def check_password_protection(grub_dir):
    """Check if GRUB password protection is enabled.

    Args:
        grub_dir: Path to GRUB directory

    Returns:
        dict: Password protection status
    """
    info = {
        'enabled': False,
        'superusers': [],
        'password_file': None
    }

    if not grub_dir:
        return info

    # Check for password configuration in various locations
    password_files = [
        os.path.join(grub_dir, 'user.cfg'),
        '/etc/grub.d/01_users',
        '/etc/grub.d/40_custom'
    ]

    for pwd_file in password_files:
        if os.path.exists(pwd_file):
            try:
                with open(pwd_file, 'r') as f:
                    content = f.read()

                    # Look for superusers definition
                    su_match = re.search(r'set superusers\s*=\s*["\']?([^"\']+)', content)
                    if su_match:
                        info['enabled'] = True
                        info['superusers'] = su_match.group(1).split(',')
                        info['password_file'] = pwd_file

                    # Look for password_pbkdf2 or password entries
                    if 'password_pbkdf2' in content or re.search(r'\bpassword\s+', content):
                        info['enabled'] = True
                        info['password_file'] = pwd_file

            except (IOError, PermissionError):
                continue

    return info


def analyze_kernel_cmdline(cmdline):
    """Analyze kernel command line parameters.

    Args:
        cmdline: Kernel command line string

    Returns:
        dict: Analysis results with security and configuration checks
    """
    analysis = {
        'raw': cmdline,
        'parameters': {},
        'security': {
            'iommu_enabled': False,
            'selinux_status': 'unknown',
            'apparmor_status': 'unknown',
            'kaslr_disabled': False,
            'smep_disabled': False,
            'smap_disabled': False,
            'mitigations_off': False
        },
        'performance': {
            'transparent_hugepages': 'unknown',
            'numa_balancing': 'unknown'
        },
        'deprecated': [],
        'problematic': []
    }

    if not cmdline:
        return analysis

    # Parse parameters
    params = cmdline.split()
    for param in params:
        if '=' in param:
            key, value = param.split('=', 1)
            analysis['parameters'][key] = value
        else:
            analysis['parameters'][param] = True

    # Security checks
    params_lower = {k.lower(): v for k, v in analysis['parameters'].items()}

    # IOMMU
    if 'intel_iommu' in params_lower or 'amd_iommu' in params_lower:
        iommu_val = params_lower.get('intel_iommu') or params_lower.get('amd_iommu')
        analysis['security']['iommu_enabled'] = iommu_val == 'on'

    # SELinux
    if 'selinux' in params_lower:
        val = params_lower['selinux']
        if val == '0':
            analysis['security']['selinux_status'] = 'disabled'
        elif val == '1':
            analysis['security']['selinux_status'] = 'enabled'

    if 'enforcing' in params_lower:
        val = params_lower['enforcing']
        if val == '0':
            analysis['security']['selinux_status'] = 'permissive'

    # AppArmor
    if 'apparmor' in params_lower:
        val = params_lower['apparmor']
        if val == '0':
            analysis['security']['apparmor_status'] = 'disabled'
        elif val == '1':
            analysis['security']['apparmor_status'] = 'enabled'

    # KASLR (Kernel Address Space Layout Randomization)
    if 'nokaslr' in analysis['parameters']:
        analysis['security']['kaslr_disabled'] = True

    # SMEP/SMAP
    if 'nosmep' in analysis['parameters']:
        analysis['security']['smep_disabled'] = True
    if 'nosmap' in analysis['parameters']:
        analysis['security']['smap_disabled'] = True

    # Mitigations
    if 'mitigations' in params_lower:
        if params_lower['mitigations'] == 'off':
            analysis['security']['mitigations_off'] = True

    # Performance settings
    if 'transparent_hugepage' in params_lower:
        analysis['performance']['transparent_hugepages'] = params_lower['transparent_hugepage']
    if 'numa_balancing' in params_lower:
        analysis['performance']['numa_balancing'] = params_lower['numa_balancing']

    # Deprecated parameters
    deprecated_params = [
        'noapic',  # Usually indicates hardware workaround
        'acpi=off',  # Disabling ACPI entirely is rarely correct
        'nox2apic',  # Legacy workaround
    ]

    for dep in deprecated_params:
        if dep in cmdline:
            analysis['deprecated'].append(dep)

    # Problematic parameters
    if analysis['security']['mitigations_off']:
        analysis['problematic'].append('mitigations=off (security risk)')
    if analysis['security']['kaslr_disabled']:
        analysis['problematic'].append('nokaslr (security risk)')
    if analysis['security']['selinux_status'] == 'disabled':
        analysis['problematic'].append('selinux=0 (security disabled)')

    return analysis


def check_recovery_mode(config):
    """Check if recovery mode is available and configured.

    Args:
        config: Parsed GRUB defaults config

    Returns:
        dict: Recovery mode status
    """
    info = {
        'disabled': False,
        'single_user_protected': 'unknown'
    }

    settings = config.get('settings', {})

    if settings.get('GRUB_DISABLE_RECOVERY') == 'true':
        info['disabled'] = True

    return info


def get_installed_kernels():
    """Get list of installed kernels.

    Returns:
        list: List of kernel versions
    """
    kernels = []

    # Check /boot for vmlinuz files
    vmlinuz_pattern = '/boot/vmlinuz-*'
    for vmlinuz in glob.glob(vmlinuz_pattern):
        version = os.path.basename(vmlinuz).replace('vmlinuz-', '')
        kernels.append({
            'version': version,
            'path': vmlinuz,
            'size': os.path.getsize(vmlinuz) if os.path.exists(vmlinuz) else 0
        })

    # Sort by version (newest first)
    kernels.sort(key=lambda x: x['version'], reverse=True)

    return kernels


def check_grub_install():
    """Check GRUB installation status.

    Returns:
        dict: Installation information
    """
    info = {
        'version': None,
        'installed': False,
        'efi_mode': False
    }

    # Try to get GRUB version
    try:
        result = subprocess.run(
            ['grub2-install', '--version'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            info['version'] = result.stdout.strip()
            info['installed'] = True
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ['grub-install', '--version'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                info['version'] = result.stdout.strip()
                info['installed'] = True
        except FileNotFoundError:
            pass

    # Check for EFI
    if os.path.isdir('/sys/firmware/efi'):
        info['efi_mode'] = True

    return info


def analyze_configuration(paths, defaults, password, cmdline_analysis,
                          recovery, grub_install, kernels):
    """Analyze configuration and return issues.

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    # Check if GRUB config exists
    if not paths['main_config']:
        issues.append({
            'severity': 'CRITICAL',
            'category': 'installation',
            'message': 'GRUB configuration file not found'
        })

    # Check defaults file
    if not paths['default_config']:
        issues.append({
            'severity': 'WARNING',
            'category': 'configuration',
            'message': 'GRUB defaults file not found (/etc/default/grub)'
        })

    # Check file permissions
    if paths['main_config']:
        perms = check_file_permissions(paths['main_config'])
        if perms['world_writable']:
            issues.append({
                'severity': 'CRITICAL',
                'category': 'security',
                'message': f"GRUB config is world-writable: {paths['main_config']}"
            })

    # Check password protection
    if not password['enabled']:
        issues.append({
            'severity': 'WARNING',
            'category': 'security',
            'message': 'GRUB password protection is not enabled'
        })

    # Check timeout (0 or very short may prevent recovery)
    timeout = defaults.get('timeout')
    if timeout is not None:
        if timeout == 0:
            issues.append({
                'severity': 'INFO',
                'category': 'usability',
                'message': 'GRUB timeout is 0 - cannot interrupt boot'
            })
        elif isinstance(timeout, int) and timeout > 30:
            issues.append({
                'severity': 'INFO',
                'category': 'performance',
                'message': f'GRUB timeout is high ({timeout}s) - consider reducing'
            })

    # Security parameter issues
    security = cmdline_analysis.get('security', {})

    if security.get('mitigations_off'):
        issues.append({
            'severity': 'CRITICAL',
            'category': 'security',
            'message': 'CPU mitigations are disabled (mitigations=off)'
        })

    if security.get('kaslr_disabled'):
        issues.append({
            'severity': 'WARNING',
            'category': 'security',
            'message': 'KASLR is disabled (nokaslr) - reduced security'
        })

    if security.get('smep_disabled'):
        issues.append({
            'severity': 'WARNING',
            'category': 'security',
            'message': 'SMEP is disabled (nosmep) - reduced security'
        })

    if security.get('smap_disabled'):
        issues.append({
            'severity': 'WARNING',
            'category': 'security',
            'message': 'SMAP is disabled (nosmap) - reduced security'
        })

    if security.get('selinux_status') == 'disabled':
        issues.append({
            'severity': 'WARNING',
            'category': 'security',
            'message': 'SELinux is disabled via boot parameters'
        })

    # EFI without secure boot consideration
    if grub_install.get('efi_mode'):
        issues.append({
            'severity': 'INFO',
            'category': 'security',
            'message': 'EFI mode detected - verify Secure Boot status'
        })

    # Deprecated parameters
    for dep in cmdline_analysis.get('deprecated', []):
        issues.append({
            'severity': 'INFO',
            'category': 'configuration',
            'message': f'Deprecated kernel parameter: {dep}'
        })

    # Check number of installed kernels
    if len(kernels) > 5:
        issues.append({
            'severity': 'INFO',
            'category': 'maintenance',
            'message': f'{len(kernels)} kernels installed - consider cleanup'
        })

    return issues


def output_plain(data, args):
    """Output results in plain text format."""
    if not args.warn_only:
        print("GRUB Configuration Audit")
        print("=" * 60)

        # Installation status
        grub = data['grub_install']
        print(f"GRUB Version: {grub['version'] or 'unknown'}")
        print(f"EFI Mode: {'Yes' if grub['efi_mode'] else 'No'}")

        # Configuration files
        paths = data['paths']
        print(f"\nMain Config: {paths['main_config'] or 'not found'}")
        print(f"Defaults File: {paths['default_config'] or 'not found'}")

        # Password protection
        password = data['password']
        print(f"\nPassword Protection: {'Enabled' if password['enabled'] else 'Disabled'}")
        if password['superusers']:
            print(f"Superusers: {', '.join(password['superusers'])}")

        # Timeout and default
        defaults = data['defaults']
        if defaults['timeout'] is not None:
            print(f"Timeout: {defaults['timeout']}s")
        if defaults['default']:
            print(f"Default Entry: {defaults['default']}")

        # Kernel command line highlights
        cmdline = data['cmdline_analysis']
        security = cmdline.get('security', {})
        print(f"\nKernel Command Line Security:")
        print(f"  IOMMU: {'Enabled' if security.get('iommu_enabled') else 'Not configured'}")
        print(f"  SELinux: {security.get('selinux_status', 'unknown')}")
        print(f"  KASLR: {'Disabled' if security.get('kaslr_disabled') else 'Enabled'}")
        print(f"  Mitigations: {'Off' if security.get('mitigations_off') else 'On'}")

        # Installed kernels
        kernels = data['kernels']
        if kernels:
            print(f"\nInstalled Kernels: {len(kernels)}")
            for k in kernels[:3]:
                print(f"  - {k['version']}")
            if len(kernels) > 3:
                print(f"  ... and {len(kernels) - 3} more")

        print()

    # Print issues
    if data['issues']:
        for issue in data['issues']:
            if args.warn_only and issue['severity'] == 'INFO':
                continue
            print(f"[{issue['severity']}] {issue['message']}")
    elif not args.warn_only:
        print("No GRUB configuration issues detected.")


def output_json(data, args):
    """Output results in JSON format."""
    print(json.dumps(data, indent=2, default=str))


def output_table(data, args):
    """Output results in table format."""
    if not args.warn_only:
        print("=" * 70)
        print("GRUB CONFIGURATION AUDIT")
        print("=" * 70)
        print()

        print(f"{'Setting':<35} {'Value':<35}")
        print("-" * 70)

        grub = data['grub_install']
        print(f"{'GRUB Version':<35} {grub['version'] or 'unknown'}")
        print(f"{'EFI Mode':<35} {'Yes' if grub['efi_mode'] else 'No'}")
        print(f"{'Password Protected':<35} {'Yes' if data['password']['enabled'] else 'No'}")

        defaults = data['defaults']
        print(f"{'Timeout':<35} {defaults['timeout']}s" if defaults['timeout'] is not None else "")
        print(f"{'Default Entry':<35} {defaults['default'] or 'default'}")

        security = data['cmdline_analysis'].get('security', {})
        print(f"{'IOMMU Enabled':<35} {'Yes' if security.get('iommu_enabled') else 'No'}")
        print(f"{'KASLR Enabled':<35} {'No' if security.get('kaslr_disabled') else 'Yes'}")
        print(f"{'Mitigations Active':<35} {'No' if security.get('mitigations_off') else 'Yes'}")
        print(f"{'Installed Kernels':<35} {len(data['kernels'])}")

        print()

    if data['issues']:
        filtered = [i for i in data['issues']
                    if not (args.warn_only and i['severity'] == 'INFO')]
        if filtered:
            print("ISSUES DETECTED")
            print("=" * 70)
            for issue in filtered:
                print(f"[{issue['severity']}] {issue['message']}")
            print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Audit GRUB bootloader configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check GRUB configuration
  %(prog)s --format json        # JSON output for monitoring
  %(prog)s --verbose            # Show additional details
  %(prog)s --warn-only          # Only show warnings/errors

Security recommendations:
  1. Enable GRUB password protection for superuser operations
  2. Keep CPU mitigations enabled unless specific need
  3. Enable IOMMU for better device isolation
  4. Verify Secure Boot on EFI systems
  5. Regularly update and maintain kernel list

Exit codes:
  0 - GRUB is properly configured
  1 - Configuration issues detected
  2 - Usage error or GRUB not accessible
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show additional details'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors'
    )

    args = parser.parse_args()

    # Check for Linux
    if not os.path.exists('/boot'):
        print("Error: /boot not found - requires Linux", file=sys.stderr)
        sys.exit(2)

    # Gather information
    paths = find_grub_config()
    defaults = parse_grub_defaults(paths['default_config'])
    password = check_password_protection(paths['grub_dir'])
    cmdline_analysis = analyze_kernel_cmdline(defaults['cmdline'])
    recovery = check_recovery_mode(defaults)
    grub_install = check_grub_install()
    kernels = get_installed_kernels()

    # Analyze configuration
    issues = analyze_configuration(
        paths, defaults, password, cmdline_analysis,
        recovery, grub_install, kernels
    )

    # Build result data
    data = {
        'paths': paths,
        'defaults': defaults,
        'password': password,
        'cmdline_analysis': cmdline_analysis,
        'recovery': recovery,
        'grub_install': grub_install,
        'kernels': kernels,
        'issues': issues
    }

    # Output results
    if args.format == 'json':
        output_json(data, args)
    elif args.format == 'table':
        output_table(data, args)
    else:
        output_plain(data, args)

    # Determine exit code
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
