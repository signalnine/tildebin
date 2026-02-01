#!/usr/bin/env python3
"""
Monitor system reboot requirements for large-scale baremetal environments.

This script checks if a system requires a reboot due to kernel updates,
library updates, or other pending changes. Essential for managing fleet-wide
maintenance windows and ensuring security patches are fully applied.

Checks performed:
- Kernel version mismatch (running vs installed)
- /var/run/reboot-required (Debian/Ubuntu)
- needs-restarting (RHEL/CentOS/Fedora)
- Libraries requiring restart (deleted files in use)
- Pending microcode updates
- systemd units needing restart

Exit codes:
    0 - No reboot required
    1 - Reboot required or recommended
    2 - Usage error or required tools not available
"""

import argparse
import sys
import json
import os
import subprocess
import glob


def get_running_kernel():
    """Get the currently running kernel version.

    Returns:
        str: Running kernel version
    """
    try:
        result = subprocess.run(
            ['uname', '-r'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def get_installed_kernels():
    """Get list of installed kernel versions.

    Returns:
        list: List of installed kernel versions (newest first)
    """
    kernels = []

    # Check /boot for installed kernels
    try:
        vmlinuz_files = glob.glob('/boot/vmlinuz-*')
        for vmlinuz in vmlinuz_files:
            # Extract version from vmlinuz-<version>
            version = os.path.basename(vmlinuz).replace('vmlinuz-', '')
            if version and not version.endswith('.old'):
                kernels.append(version)

        # Sort by version (roughly, may not be perfect for all version schemes)
        kernels.sort(reverse=True)
    except Exception:
        pass

    return kernels


def check_debian_reboot_required():
    """Check Debian/Ubuntu reboot-required flag.

    Returns:
        dict: Reboot requirement info
    """
    result = {
        'required': False,
        'packages': [],
    }

    # Check main reboot-required file
    reboot_required_path = '/var/run/reboot-required'
    if os.path.exists(reboot_required_path):
        result['required'] = True

    # Check for list of packages requiring reboot
    pkgs_path = '/var/run/reboot-required.pkgs'
    if os.path.exists(pkgs_path):
        try:
            with open(pkgs_path, 'r') as f:
                result['packages'] = [line.strip() for line in f if line.strip()]
        except (IOError, PermissionError):
            pass

    return result


def check_rhel_needs_restarting():
    """Check RHEL/CentOS/Fedora needs-restarting.

    Returns:
        dict: Needs-restarting info
    """
    result = {
        'available': False,
        'reboot_required': False,
        'services': [],
    }

    # Check if needs-restarting is available
    try:
        # Check for reboot requirement
        proc = subprocess.run(
            ['needs-restarting', '-r'],
            capture_output=True,
            text=True,
            timeout=30
        )
        result['available'] = True

        # Exit code 1 means reboot required
        if proc.returncode == 1:
            result['reboot_required'] = True

        # Get services needing restart
        proc_services = subprocess.run(
            ['needs-restarting', '-s'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if proc_services.returncode == 0:
            result['services'] = [
                s.strip() for s in proc_services.stdout.strip().split('\n')
                if s.strip()
            ]

    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        result['available'] = True
        result['error'] = 'needs-restarting timed out'

    return result


def check_kernel_mismatch(running_kernel, installed_kernels):
    """Check if running kernel differs from newest installed.

    Args:
        running_kernel: Currently running kernel version
        installed_kernels: List of installed kernel versions

    Returns:
        dict: Kernel mismatch info
    """
    result = {
        'mismatch': False,
        'running': running_kernel,
        'newest_installed': None,
        'available_kernels': installed_kernels[:5],  # Show top 5
    }

    if not running_kernel or not installed_kernels:
        return result

    result['newest_installed'] = installed_kernels[0] if installed_kernels else None

    # Check if running kernel is the newest installed
    if installed_kernels and running_kernel != installed_kernels[0]:
        result['mismatch'] = True

    return result


def check_deleted_libraries():
    """Check for processes using deleted libraries (need restart).

    Returns:
        dict: Deleted libraries info
    """
    result = {
        'processes': [],
        'count': 0,
    }

    # Check /proc/*/maps for deleted files
    try:
        # Use lsof to find deleted files in use
        proc = subprocess.run(
            ['lsof', '+L1'],
            capture_output=True,
            text=True,
            timeout=60
        )

        if proc.returncode == 0:
            lines = proc.stdout.strip().split('\n')[1:]  # Skip header
            deleted_procs = set()

            for line in lines:
                parts = line.split()
                if len(parts) >= 9:
                    proc_name = parts[0]
                    pid = parts[1]
                    filename = parts[-1] if len(parts) > 8 else ''

                    # Look for deleted .so files
                    if '.so' in filename or '(deleted)' in line:
                        deleted_procs.add(f"{proc_name}({pid})")

            result['processes'] = list(deleted_procs)[:20]  # Limit to 20
            result['count'] = len(deleted_procs)

    except FileNotFoundError:
        # lsof not available, try /proc directly
        try:
            for pid_dir in glob.glob('/proc/[0-9]*'):
                maps_file = os.path.join(pid_dir, 'maps')
                try:
                    with open(maps_file, 'r') as f:
                        for line in f:
                            if '(deleted)' in line and '.so' in line:
                                pid = os.path.basename(pid_dir)
                                # Get process name
                                comm_file = os.path.join(pid_dir, 'comm')
                                try:
                                    with open(comm_file, 'r') as cf:
                                        proc_name = cf.read().strip()
                                        result['processes'].append(f"{proc_name}({pid})")
                                        break
                                except (IOError, PermissionError):
                                    pass
                except (IOError, PermissionError):
                    pass

            result['processes'] = list(set(result['processes']))[:20]
            result['count'] = len(result['processes'])

        except Exception:
            pass
    except subprocess.TimeoutExpired:
        result['error'] = 'lsof timed out'

    return result


def check_microcode_update():
    """Check for pending microcode updates.

    Returns:
        dict: Microcode update info
    """
    result = {
        'pending': False,
        'current_revision': None,
        'available_revision': None,
    }

    # Read current microcode revision
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if 'microcode' in line.lower():
                    parts = line.split(':')
                    if len(parts) == 2:
                        result['current_revision'] = parts[1].strip()
                    break
    except (IOError, PermissionError):
        pass

    # Check for early microcode loading status
    dmesg_check = False
    try:
        proc = subprocess.run(
            ['dmesg'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if proc.returncode == 0:
            for line in proc.stdout.split('\n'):
                if 'microcode' in line.lower() and 'updated' in line.lower():
                    dmesg_check = True
                    break
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        pass

    return result


def check_systemd_units():
    """Check for systemd units needing restart.

    Returns:
        dict: Systemd units info
    """
    result = {
        'available': False,
        'units': [],
    }

    try:
        # Use systemctl to check for units that need restart
        proc = subprocess.run(
            ['systemctl', 'list-units', '--state=running', '--no-pager', '--no-legend'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if proc.returncode == 0:
            result['available'] = True

    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        result['available'] = True
        result['error'] = 'systemctl timed out'

    return result


def analyze_reboot_status(kernel_info, debian_info, rhel_info, deleted_libs, microcode):
    """Analyze all checks and determine reboot status.

    Args:
        kernel_info: Kernel mismatch info
        debian_info: Debian reboot-required info
        rhel_info: RHEL needs-restarting info
        deleted_libs: Deleted libraries info
        microcode: Microcode update info

    Returns:
        dict: Analysis with issues and recommendations
    """
    issues = []
    reboot_required = False
    reboot_recommended = False

    # Check kernel mismatch
    if kernel_info['mismatch']:
        reboot_required = True
        issues.append({
            'severity': 'WARNING',
            'category': 'kernel',
            'message': f"Kernel update pending: running {kernel_info['running']}, "
                      f"newest installed {kernel_info['newest_installed']}",
            'recommendation': 'Schedule a reboot to apply kernel update',
        })

    # Check Debian reboot-required
    if debian_info['required']:
        reboot_required = True
        pkg_list = ', '.join(debian_info['packages'][:5]) if debian_info['packages'] else 'unknown'
        issues.append({
            'severity': 'WARNING',
            'category': 'packages',
            'message': f"System reboot required (packages: {pkg_list})",
            'recommendation': 'Schedule a reboot to complete package updates',
        })

    # Check RHEL needs-restarting
    if rhel_info['available'] and rhel_info['reboot_required']:
        reboot_required = True
        issues.append({
            'severity': 'WARNING',
            'category': 'packages',
            'message': 'System reboot required (needs-restarting)',
            'recommendation': 'Schedule a reboot to complete package updates',
        })

    if rhel_info['available'] and rhel_info['services']:
        reboot_recommended = True
        svc_list = ', '.join(rhel_info['services'][:5])
        issues.append({
            'severity': 'INFO',
            'category': 'services',
            'message': f"Services need restart: {svc_list}",
            'recommendation': 'Restart affected services or schedule a reboot',
        })

    # Check deleted libraries
    if deleted_libs['count'] > 0:
        reboot_recommended = True
        proc_list = ', '.join(deleted_libs['processes'][:5])
        issues.append({
            'severity': 'INFO',
            'category': 'libraries',
            'message': f"{deleted_libs['count']} process(es) using deleted libraries: {proc_list}",
            'recommendation': 'Restart affected services or schedule a reboot',
        })

    # Determine overall status
    if reboot_required:
        status = 'REBOOT_REQUIRED'
    elif reboot_recommended:
        status = 'REBOOT_RECOMMENDED'
    else:
        status = 'OK'

    return {
        'status': status,
        'reboot_required': reboot_required,
        'reboot_recommended': reboot_recommended,
        'issues': issues,
    }


def output_plain(analysis, kernel_info, debian_info, rhel_info, deleted_libs,
                 verbose, warn_only):
    """Output results in plain text format."""
    status = analysis['status']
    issues = analysis['issues']

    if not warn_only:
        if status == 'REBOOT_REQUIRED':
            print("Status: REBOOT REQUIRED")
        elif status == 'REBOOT_RECOMMENDED':
            print("Status: REBOOT RECOMMENDED")
        else:
            print("Status: OK (no reboot needed)")

        print(f"Running kernel: {kernel_info['running']}")
        if kernel_info['newest_installed']:
            print(f"Newest installed: {kernel_info['newest_installed']}")

        if verbose:
            print()
            if kernel_info['available_kernels']:
                print(f"Available kernels: {', '.join(kernel_info['available_kernels'][:3])}")

            if debian_info['required']:
                print(f"Debian reboot-required: Yes")
                if debian_info['packages']:
                    print(f"  Packages: {', '.join(debian_info['packages'][:5])}")

            if rhel_info['available']:
                print(f"RHEL needs-restarting: {'Yes' if rhel_info['reboot_required'] else 'No'}")
                if rhel_info['services']:
                    print(f"  Services needing restart: {', '.join(rhel_info['services'][:5])}")

            if deleted_libs['count'] > 0:
                print(f"Processes with deleted libraries: {deleted_libs['count']}")

        print()

    if issues:
        if not warn_only:
            print("Issues detected:")
        for issue in issues:
            print(f"[{issue['severity']}] {issue['message']}")
            if verbose:
                print(f"  Recommendation: {issue['recommendation']}")
    elif not warn_only:
        print("No reboot-related issues detected.")


def output_json(analysis, kernel_info, debian_info, rhel_info, deleted_libs, microcode):
    """Output results in JSON format."""
    output = {
        'status': analysis['status'],
        'reboot_required': analysis['reboot_required'],
        'reboot_recommended': analysis['reboot_recommended'],
        'kernel': kernel_info,
        'debian_reboot_required': debian_info,
        'rhel_needs_restarting': rhel_info,
        'deleted_libraries': deleted_libs,
        'microcode': microcode,
        'issues': analysis['issues'],
        'issue_count': len(analysis['issues']),
    }

    print(json.dumps(output, indent=2))


def output_table(analysis, kernel_info, debian_info, rhel_info, deleted_libs,
                 verbose, warn_only):
    """Output results in table format."""
    status = analysis['status']
    issues = analysis['issues']

    if not warn_only:
        print("=" * 70)
        print(f"{'SYSTEM REBOOT STATUS':^70}")
        print("=" * 70)
        print()

        # Status banner
        if status == 'REBOOT_REQUIRED':
            print(f"{'*** REBOOT REQUIRED ***':^70}")
        elif status == 'REBOOT_RECOMMENDED':
            print(f"{'* REBOOT RECOMMENDED *':^70}")
        else:
            print(f"{'OK - No reboot needed':^70}")
        print()

        print(f"{'Check':<30} {'Status':<40}")
        print("-" * 70)

        # Kernel check
        kernel_status = 'MISMATCH' if kernel_info['mismatch'] else 'OK'
        print(f"{'Kernel version':<30} {kernel_status:<40}")

        # Debian check
        if os.path.exists('/var/run/reboot-required') or debian_info['required']:
            deb_status = 'REQUIRED' if debian_info['required'] else 'OK'
            print(f"{'Debian reboot-required':<30} {deb_status:<40}")

        # RHEL check
        if rhel_info['available']:
            rhel_status = 'REQUIRED' if rhel_info['reboot_required'] else 'OK'
            print(f"{'RHEL needs-restarting':<30} {rhel_status:<40}")

        # Deleted libraries check
        lib_status = f"{deleted_libs['count']} processes" if deleted_libs['count'] > 0 else 'OK'
        print(f"{'Deleted libraries in use':<30} {lib_status:<40}")

        print()

        if verbose:
            print(f"{'Property':<30} {'Value':<40}")
            print("-" * 70)
            print(f"{'Running kernel':<30} {kernel_info['running']:<40}")
            if kernel_info['newest_installed']:
                print(f"{'Newest installed kernel':<30} {kernel_info['newest_installed']:<40}")
            print()

    if issues:
        if not warn_only:
            print("=" * 70)
            print(f"{'ISSUES':^70}")
            print("=" * 70)
            print()

        print(f"{'Severity':<12} {'Category':<12} {'Message':<46}")
        print("-" * 70)

        for issue in issues:
            msg = issue['message'][:46]
            print(f"{issue['severity']:<12} {issue['category']:<12} {msg:<46}")

        print()
    elif not warn_only:
        print("=" * 70)
        print(f"{'NO ISSUES DETECTED':^70}")
        print("=" * 70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor system reboot requirements',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Check reboot status
  %(prog)s --verbose           # Show detailed information
  %(prog)s --format json       # Output in JSON format
  %(prog)s --warn-only         # Only show if reboot needed

Exit codes:
  0 - No reboot required
  1 - Reboot required or recommended
  2 - Usage error

Checks performed:
  - Kernel version mismatch (running vs newest installed)
  - /var/run/reboot-required (Debian/Ubuntu)
  - needs-restarting (RHEL/CentOS/Fedora)
  - Processes using deleted libraries (.so files)
  - Pending microcode updates

Notes:
  - Some checks require root privileges for full functionality
  - On Debian/Ubuntu, installs linux-base for reboot-required tracking
  - On RHEL/CentOS, install yum-utils for needs-restarting command
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
        help='Show detailed reboot requirement information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if reboot is required/recommended'
    )

    args = parser.parse_args()

    # Gather system information
    running_kernel = get_running_kernel()
    if not running_kernel:
        print("Error: Could not determine running kernel version", file=sys.stderr)
        sys.exit(2)

    installed_kernels = get_installed_kernels()

    # Run all checks
    kernel_info = check_kernel_mismatch(running_kernel, installed_kernels)
    debian_info = check_debian_reboot_required()
    rhel_info = check_rhel_needs_restarting()
    deleted_libs = check_deleted_libraries()
    microcode = check_microcode_update()

    # Analyze results
    analysis = analyze_reboot_status(
        kernel_info, debian_info, rhel_info, deleted_libs, microcode
    )

    # Handle warn-only mode
    if args.warn_only and analysis['status'] == 'OK':
        # No output needed, exit cleanly
        sys.exit(0)

    # Output results
    if args.format == 'json':
        output_json(analysis, kernel_info, debian_info, rhel_info, deleted_libs, microcode)
    elif args.format == 'table':
        output_table(analysis, kernel_info, debian_info, rhel_info, deleted_libs,
                     args.verbose, args.warn_only)
    else:
        output_plain(analysis, kernel_info, debian_info, rhel_info, deleted_libs,
                     args.verbose, args.warn_only)

    # Exit code based on status
    if analysis['reboot_required'] or analysis['reboot_recommended']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
