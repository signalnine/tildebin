#!/usr/bin/env python3
"""
Audit kernel version and detect configuration inconsistencies.

This script audits the running kernel version, build information, and
command-line parameters to help identify version drift across server fleets.
Useful for:

- Detecting kernel version inconsistencies across baremetal hosts
- Identifying systems needing kernel updates
- Verifying kernel command-line parameters are consistent
- Checking for outdated or EOL kernel versions
- Auditing kernel configuration for security and performance

The script analyzes /proc/version, /proc/cmdline, and uname to gather
comprehensive kernel information. Supports multiple output formats for
integration with configuration management systems.

Exit codes:
    0 - Kernel information retrieved successfully, no issues detected
    1 - Issues detected (warnings about kernel configuration)
    2 - Usage error or /proc filesystem not available
"""

import argparse
import sys
import json
import os
import subprocess


def get_kernel_version():
    """Get kernel version information from /proc/version and uname.

    Returns:
        dict: Kernel version information
    """
    kernel_info = {}

    try:
        # Read /proc/version for detailed version info
        with open('/proc/version', 'r') as f:
            kernel_info['proc_version'] = f.read().strip()

        # Use uname for structured information
        result = subprocess.run(
            ['uname', '-a'],
            capture_output=True,
            text=True,
            check=True
        )
        kernel_info['uname_full'] = result.stdout.strip()

        # Get individual components
        result = subprocess.run(
            ['uname', '-r'],
            capture_output=True,
            text=True,
            check=True
        )
        kernel_info['release'] = result.stdout.strip()

        result = subprocess.run(
            ['uname', '-v'],
            capture_output=True,
            text=True,
            check=True
        )
        kernel_info['version'] = result.stdout.strip()

        result = subprocess.run(
            ['uname', '-m'],
            capture_output=True,
            text=True,
            check=True
        )
        kernel_info['architecture'] = result.stdout.strip()

        result = subprocess.run(
            ['uname', '-s'],
            capture_output=True,
            text=True,
            check=True
        )
        kernel_info['kernel_name'] = result.stdout.strip()

    except FileNotFoundError:
        print("Error: /proc/version not found (non-Linux system?)", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running uname: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error getting kernel version: {e}", file=sys.stderr)
        sys.exit(2)

    return kernel_info


def get_kernel_cmdline():
    """Get kernel command-line parameters from /proc/cmdline.

    Returns:
        str: Kernel command-line parameters
    """
    try:
        with open('/proc/cmdline', 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""
    except Exception as e:
        print(f"Warning: Could not read /proc/cmdline: {e}", file=sys.stderr)
        return ""


def analyze_kernel_info(kernel_info, cmdline):
    """Analyze kernel information and return issues.

    Args:
        kernel_info: Dictionary of kernel information
        cmdline: Kernel command-line parameters

    Returns:
        list: List of issues detected
    """
    issues = []

    # Check for very old kernels (< 3.x)
    release = kernel_info.get('release', '')
    if release:
        try:
            major_version = int(release.split('.')[0])
            if major_version < 3:
                issues.append({
                    'severity': 'WARNING',
                    'message': f'Running very old kernel version {release} (< 3.x)',
                    'recommendation': 'Consider upgrading to a modern kernel version'
                })
        except (ValueError, IndexError):
            pass

    # Check for missing security features in cmdline
    security_params = [
        'selinux',
        'apparmor',
        'security',
    ]

    has_security = any(param in cmdline for param in security_params)
    if not has_security and cmdline:
        issues.append({
            'severity': 'INFO',
            'message': 'No security module detected in kernel parameters',
            'recommendation': 'Consider enabling SELinux or AppArmor for enhanced security'
        })

    return issues


def output_plain(kernel_info, cmdline, issues, verbose, warn_only):
    """Output kernel information in plain text format.

    Args:
        kernel_info: Dictionary of kernel information
        cmdline: Kernel command-line parameters
        issues: List of detected issues
        verbose: Show verbose information
        warn_only: Only show warnings
    """
    if not warn_only:
        print(f"Kernel version: {kernel_info.get('release', 'Unknown')}")
        print(f"Kernel name: {kernel_info.get('kernel_name', 'Unknown')}")

        if verbose:
            print(f"Architecture: {kernel_info.get('architecture', 'Unknown')}")
            print(f"Build version: {kernel_info.get('version', 'Unknown')}")
            print(f"\nKernel parameters: {cmdline if cmdline else 'N/A'}")
            print(f"\nFull uname: {kernel_info.get('uname_full', 'Unknown')}")

    if issues:
        if not warn_only:
            print(f"\n{'='*60}")
            print("ISSUES DETECTED")
            print('='*60)

        for issue in issues:
            print(f"[{issue['severity']}] {issue['message']}")
            if verbose:
                print(f"  Recommendation: {issue['recommendation']}")

    if not issues and not warn_only:
        print("\nNo issues detected.")


def output_json(kernel_info, cmdline, issues):
    """Output kernel information in JSON format.

    Args:
        kernel_info: Dictionary of kernel information
        cmdline: Kernel command-line parameters
        issues: List of detected issues
    """
    output = {
        'kernel': {
            'release': kernel_info.get('release', ''),
            'version': kernel_info.get('version', ''),
            'architecture': kernel_info.get('architecture', ''),
            'kernel_name': kernel_info.get('kernel_name', ''),
            'uname_full': kernel_info.get('uname_full', ''),
            'proc_version': kernel_info.get('proc_version', ''),
            'cmdline': cmdline,
        },
        'issues': issues,
        'issue_count': len(issues)
    }

    print(json.dumps(output, indent=2))


def output_table(kernel_info, cmdline, issues, verbose, warn_only):
    """Output kernel information in table format.

    Args:
        kernel_info: Dictionary of kernel information
        cmdline: Kernel command-line parameters
        issues: List of detected issues
        verbose: Show verbose information
        warn_only: Only show warnings
    """
    if not warn_only:
        print("="*70)
        print(f"{'KERNEL VERSION AUDIT':^70}")
        print("="*70)
        print()

        print(f"{'Property':<25} {'Value':<45}")
        print("-"*70)
        print(f"{'Kernel Release':<25} {kernel_info.get('release', 'Unknown'):<45}")
        print(f"{'Kernel Name':<25} {kernel_info.get('kernel_name', 'Unknown'):<45}")
        print(f"{'Architecture':<25} {kernel_info.get('architecture', 'Unknown'):<45}")

        if verbose:
            build_version = kernel_info.get('version', 'Unknown')
            if len(build_version) > 45:
                build_version = build_version[:42] + "..."
            print(f"{'Build Version':<25} {build_version:<45}")

            cmdline_display = cmdline if cmdline else 'N/A'
            if len(cmdline_display) > 45:
                # Print cmdline on its own line if too long
                print(f"{'Command Line':<25}")
                print(f"  {cmdline_display}")
            else:
                print(f"{'Command Line':<25} {cmdline_display:<45}")

        print()

    if issues:
        if not warn_only:
            print("="*70)
            print(f"{'ISSUES DETECTED':^70}")
            print("="*70)
            print()

        print(f"{'Severity':<12} {'Message':<58}")
        print("-"*70)

        for issue in issues:
            message = issue['message']
            if len(message) > 58:
                # Wrap long messages
                print(f"{issue['severity']:<12} {message[:58]}")
                remaining = message[58:]
                while remaining:
                    print(f"{'':<12} {remaining[:58]}")
                    remaining = remaining[58:]
            else:
                print(f"{issue['severity']:<12} {message:<58}")

            if verbose:
                rec = issue['recommendation']
                print(f"{'Recommendation':<12} {rec}")
                print()

        print()

    if not issues and not warn_only:
        print("="*70)
        print(f"{'NO ISSUES DETECTED':^70}")
        print("="*70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Audit kernel version and configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter
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
        help='Show detailed kernel information and recommendations'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues (suppress normal output)'
    )

    args = parser.parse_args()

    # Get kernel information
    kernel_info = get_kernel_version()
    cmdline = get_kernel_cmdline()

    # Analyze for issues
    issues = analyze_kernel_info(kernel_info, cmdline)

    # Output based on format
    if args.format == 'json':
        output_json(kernel_info, cmdline, issues)
    elif args.format == 'table':
        output_table(kernel_info, cmdline, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(kernel_info, cmdline, issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    if issues:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
