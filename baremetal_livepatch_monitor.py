#!/usr/bin/env python3
"""
Monitor kernel live patching status for security and compliance.

This script checks the status of kernel live patches (kpatch, livepatch, ksplice)
to help verify security patches are applied without requiring reboots. Useful for:

- Verifying live patches are active and properly applied
- Detecting systems missing required security patches
- Fleet-wide live patch inventory and compliance checking
- Identifying stale patches that require a reboot
- Monitoring for failed or disabled patches

The script checks multiple live patching systems:
- Canonical Livepatch (livepatch)
- Red Hat kpatch
- Oracle ksplice

Exit codes:
    0 - Live patching healthy or not in use (no issues detected)
    1 - Issues detected (failed patches, disabled patches, etc.)
    2 - Usage error or required files not available
"""

import argparse
import sys
import json
import os
import subprocess
import glob


def check_livepatch_support():
    """Check if the kernel supports live patching.

    Returns:
        dict: Live patch support information
    """
    support = {
        'kernel_support': False,
        'livepatch_enabled': False,
        'kpatch_available': False,
        'ksplice_available': False,
        'canonical_livepatch': False,
    }

    # Check kernel config for livepatch support
    try:
        with open('/proc/config.gz', 'rb') as f:
            import gzip
            config = gzip.decompress(f.read()).decode('utf-8', errors='ignore')
            if 'CONFIG_LIVEPATCH=y' in config:
                support['kernel_support'] = True
    except (FileNotFoundError, ImportError):
        # Try /boot/config-* as fallback
        try:
            result = subprocess.run(
                ['uname', '-r'],
                capture_output=True,
                text=True,
                check=True
            )
            kernel_release = result.stdout.strip()
            config_path = f'/boot/config-{kernel_release}'

            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = f.read()
                    if 'CONFIG_LIVEPATCH=y' in config:
                        support['kernel_support'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    # Check /sys/kernel/livepatch
    if os.path.isdir('/sys/kernel/livepatch'):
        support['livepatch_enabled'] = True
        support['kernel_support'] = True

    # Check for kpatch command
    try:
        result = subprocess.run(
            ['which', 'kpatch'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            support['kpatch_available'] = True
    except FileNotFoundError:
        pass

    # Check for ksplice command
    try:
        result = subprocess.run(
            ['which', 'ksplice'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            support['ksplice_available'] = True
    except FileNotFoundError:
        pass

    # Check for canonical-livepatch
    try:
        result = subprocess.run(
            ['which', 'canonical-livepatch'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            support['canonical_livepatch'] = True
    except FileNotFoundError:
        pass

    return support


def get_sysfs_livepatches():
    """Get live patch status from /sys/kernel/livepatch.

    Returns:
        list: List of active live patches
    """
    patches = []
    livepatch_dir = '/sys/kernel/livepatch'

    if not os.path.isdir(livepatch_dir):
        return patches

    try:
        for patch_name in os.listdir(livepatch_dir):
            patch_path = os.path.join(livepatch_dir, patch_name)
            if not os.path.isdir(patch_path):
                continue

            patch_info = {
                'name': patch_name,
                'source': 'sysfs',
                'enabled': False,
                'transition': False,
            }

            # Read enabled status
            enabled_path = os.path.join(patch_path, 'enabled')
            if os.path.exists(enabled_path):
                with open(enabled_path, 'r') as f:
                    patch_info['enabled'] = f.read().strip() == '1'

            # Read transition status (patch being applied/removed)
            transition_path = os.path.join(patch_path, 'transition')
            if os.path.exists(transition_path):
                with open(transition_path, 'r') as f:
                    patch_info['transition'] = f.read().strip() == '1'

            patches.append(patch_info)

    except PermissionError:
        pass
    except Exception:
        pass

    return patches


def get_kpatch_status():
    """Get kpatch status if available.

    Returns:
        dict: kpatch status information
    """
    status = {
        'available': False,
        'loaded_patches': [],
        'installed_patches': [],
    }

    try:
        # Check kpatch list (loaded patches)
        result = subprocess.run(
            ['kpatch', 'list'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            status['available'] = True

            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('Loaded') or line.startswith('Installed'):
                    continue

                # Parse kpatch list output
                # Format: "kpatch_name [enabled/disabled]"
                parts = line.split()
                if parts:
                    patch = {
                        'name': parts[0],
                        'enabled': '[enabled]' in line.lower(),
                    }
                    if 'Loaded' in result.stdout[:result.stdout.find(line)] or \
                       line.startswith('kpatch'):
                        status['loaded_patches'].append(patch)
                    else:
                        status['installed_patches'].append(patch)

    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        status['available'] = True
        status['error'] = 'kpatch command timed out'
    except subprocess.CalledProcessError:
        pass

    return status


def get_canonical_livepatch_status():
    """Get Canonical Livepatch status if available.

    Returns:
        dict: Canonical Livepatch status
    """
    status = {
        'available': False,
        'enabled': False,
        'running': False,
        'patches': [],
        'last_check': None,
        'machine_token': False,
    }

    try:
        result = subprocess.run(
            ['canonical-livepatch', 'status', '--format', 'json'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            status['available'] = True
            try:
                data = json.loads(result.stdout)
                status['enabled'] = data.get('Status', '') == 'enabled'
                status['running'] = data.get('Running', False)
                status['machine_token'] = bool(data.get('MachineToken', ''))

                # Get patch info
                if 'Livepatch' in data:
                    lp = data['Livepatch']
                    status['last_check'] = lp.get('CheckState', {}).get('LastCheck')

                    if 'Fixes' in lp:
                        for fix in lp['Fixes']:
                            status['patches'].append({
                                'name': fix.get('Name', 'Unknown'),
                                'description': fix.get('Description', ''),
                                'bug': fix.get('Bug', ''),
                                'patched': fix.get('Patched', False),
                            })

            except json.JSONDecodeError:
                # Fallback to text parsing
                status['enabled'] = 'enabled' in result.stdout.lower()

    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        status['available'] = True
        status['error'] = 'canonical-livepatch command timed out'

    return status


def get_ksplice_status():
    """Get Oracle Ksplice status if available.

    Returns:
        dict: Ksplice status
    """
    status = {
        'available': False,
        'patches': [],
    }

    try:
        result = subprocess.run(
            ['ksplice', 'all'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            status['available'] = True

            # Parse ksplice output
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line or 'No updates' in line:
                    continue

                # Ksplice output varies; extract patch names
                if line and not line.startswith('Checking'):
                    status['patches'].append({
                        'name': line,
                        'source': 'ksplice',
                    })

    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        status['available'] = True
        status['error'] = 'ksplice command timed out'
    except subprocess.CalledProcessError:
        pass

    return status


def get_kernel_info():
    """Get current kernel version info.

    Returns:
        dict: Kernel version information
    """
    info = {}

    try:
        result = subprocess.run(
            ['uname', '-r'],
            capture_output=True,
            text=True,
            check=True
        )
        info['release'] = result.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        info['release'] = 'Unknown'

    try:
        result = subprocess.run(
            ['uname', '-v'],
            capture_output=True,
            text=True,
            check=True
        )
        info['version'] = result.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        info['version'] = 'Unknown'

    return info


def analyze_livepatch_status(support, sysfs_patches, kpatch, canonical, ksplice):
    """Analyze live patch status and identify issues.

    Args:
        support: Live patch support info
        sysfs_patches: Patches from /sys/kernel/livepatch
        kpatch: kpatch status
        canonical: Canonical Livepatch status
        ksplice: Ksplice status

    Returns:
        dict: Analysis with issues
    """
    issues = []
    summary = {
        'livepatch_in_use': False,
        'total_patches': 0,
        'enabled_patches': 0,
        'disabled_patches': 0,
        'transitioning_patches': 0,
        'systems': [],
    }

    # Check sysfs patches
    for patch in sysfs_patches:
        summary['total_patches'] += 1
        summary['livepatch_in_use'] = True

        if patch['enabled']:
            summary['enabled_patches'] += 1
        else:
            summary['disabled_patches'] += 1
            issues.append({
                'severity': 'WARNING',
                'message': f"Live patch '{patch['name']}' is disabled",
                'recommendation': 'Check patch status and enable if needed',
            })

        if patch.get('transition'):
            summary['transitioning_patches'] += 1
            issues.append({
                'severity': 'INFO',
                'message': f"Live patch '{patch['name']}' is transitioning",
                'recommendation': 'Patch is being applied/removed, may need wait',
            })

    # Check kpatch
    if kpatch['available']:
        summary['systems'].append('kpatch')
        if kpatch.get('error'):
            issues.append({
                'severity': 'WARNING',
                'message': f"kpatch error: {kpatch['error']}",
                'recommendation': 'Check kpatch service status',
            })

        for patch in kpatch.get('loaded_patches', []):
            summary['livepatch_in_use'] = True
            if not patch.get('enabled'):
                issues.append({
                    'severity': 'WARNING',
                    'message': f"kpatch '{patch['name']}' is loaded but disabled",
                    'recommendation': 'Enable the patch with: kpatch enable',
                })

    # Check Canonical Livepatch
    if canonical['available']:
        summary['systems'].append('canonical-livepatch')
        summary['livepatch_in_use'] = True

        if canonical.get('error'):
            issues.append({
                'severity': 'WARNING',
                'message': f"Canonical Livepatch error: {canonical['error']}",
                'recommendation': 'Check livepatch service: canonical-livepatch status',
            })

        if not canonical.get('machine_token'):
            issues.append({
                'severity': 'WARNING',
                'message': 'Canonical Livepatch not registered (no machine token)',
                'recommendation': 'Register with: canonical-livepatch enable <token>',
            })

        if not canonical.get('enabled'):
            issues.append({
                'severity': 'WARNING',
                'message': 'Canonical Livepatch is disabled',
                'recommendation': 'Enable with: canonical-livepatch enable',
            })

        summary['total_patches'] += len(canonical.get('patches', []))
        for patch in canonical.get('patches', []):
            if patch.get('patched'):
                summary['enabled_patches'] += 1
            else:
                summary['disabled_patches'] += 1

    # Check Ksplice
    if ksplice['available']:
        summary['systems'].append('ksplice')
        summary['livepatch_in_use'] = True

        if ksplice.get('error'):
            issues.append({
                'severity': 'WARNING',
                'message': f"Ksplice error: {ksplice['error']}",
                'recommendation': 'Check ksplice service status',
            })

        summary['total_patches'] += len(ksplice.get('patches', []))

    # Check kernel support
    if not support['kernel_support'] and not summary['livepatch_in_use']:
        issues.append({
            'severity': 'INFO',
            'message': 'Kernel live patching not enabled',
            'recommendation': 'Consider enabling CONFIG_LIVEPATCH for security patches without reboots',
        })

    return {
        'summary': summary,
        'issues': issues,
    }


def output_plain(kernel_info, support, analysis, sysfs_patches, kpatch, canonical, ksplice, verbose, warn_only):
    """Output results in plain text format."""
    summary = analysis['summary']
    issues = analysis['issues']

    if not warn_only:
        print(f"Kernel: {kernel_info['release']}")
        print(f"Live patching support: {'Yes' if support['kernel_support'] else 'No'}")
        print(f"Live patching in use: {'Yes' if summary['livepatch_in_use'] else 'No'}")

        if summary['systems']:
            print(f"Systems: {', '.join(summary['systems'])}")

        if summary['total_patches'] > 0:
            print(f"Total patches: {summary['total_patches']} "
                  f"({summary['enabled_patches']} enabled, "
                  f"{summary['disabled_patches']} disabled)")

        if verbose:
            print()
            # Show sysfs patches
            if sysfs_patches:
                print("Kernel live patches (sysfs):")
                for patch in sysfs_patches:
                    status = 'enabled' if patch['enabled'] else 'disabled'
                    trans = ' (transitioning)' if patch.get('transition') else ''
                    print(f"  - {patch['name']}: {status}{trans}")

            # Show kpatch details
            if kpatch['available'] and kpatch.get('loaded_patches'):
                print("\nkpatch loaded:")
                for patch in kpatch['loaded_patches']:
                    status = 'enabled' if patch.get('enabled') else 'disabled'
                    print(f"  - {patch['name']}: {status}")

            # Show Canonical Livepatch details
            if canonical['available']:
                print(f"\nCanonical Livepatch:")
                print(f"  Enabled: {canonical.get('enabled', False)}")
                print(f"  Registered: {canonical.get('machine_token', False)}")
                if canonical.get('last_check'):
                    print(f"  Last check: {canonical['last_check']}")
                if canonical.get('patches'):
                    print("  Patches:")
                    for patch in canonical['patches']:
                        status = 'patched' if patch.get('patched') else 'not patched'
                        print(f"    - {patch['name']}: {status}")

            # Show Ksplice details
            if ksplice['available'] and ksplice.get('patches'):
                print("\nKsplice patches:")
                for patch in ksplice['patches']:
                    print(f"  - {patch['name']}")

        print()

    if issues:
        if not warn_only:
            print("Issues detected:")
        for issue in issues:
            print(f"[{issue['severity']}] {issue['message']}")
            if verbose:
                print(f"  Recommendation: {issue['recommendation']}")
    elif not warn_only:
        print("No live patch issues detected.")


def output_json(kernel_info, support, analysis, sysfs_patches, kpatch, canonical, ksplice):
    """Output results in JSON format."""
    output = {
        'kernel': kernel_info,
        'support': support,
        'summary': analysis['summary'],
        'sysfs_patches': sysfs_patches,
        'kpatch': kpatch,
        'canonical_livepatch': canonical,
        'ksplice': ksplice,
        'issues': analysis['issues'],
        'issue_count': len(analysis['issues']),
    }

    print(json.dumps(output, indent=2))


def output_table(kernel_info, support, analysis, sysfs_patches, kpatch, canonical, ksplice, verbose, warn_only):
    """Output results in table format."""
    summary = analysis['summary']
    issues = analysis['issues']

    if not warn_only:
        print("=" * 70)
        print(f"{'KERNEL LIVE PATCH STATUS':^70}")
        print("=" * 70)
        print()

        print(f"{'Property':<30} {'Value':<40}")
        print("-" * 70)
        print(f"{'Kernel Release':<30} {kernel_info['release']:<40}")
        print(f"{'Live Patch Support':<30} {'Yes' if support['kernel_support'] else 'No':<40}")
        print(f"{'Live Patching In Use':<30} {'Yes' if summary['livepatch_in_use'] else 'No':<40}")

        if summary['systems']:
            print(f"{'Active Systems':<30} {', '.join(summary['systems']):<40}")

        print(f"{'Total Patches':<30} {summary['total_patches']:<40}")
        print(f"{'Enabled Patches':<30} {summary['enabled_patches']:<40}")
        print(f"{'Disabled Patches':<30} {summary['disabled_patches']:<40}")
        print()

        if verbose and sysfs_patches:
            print("=" * 70)
            print(f"{'SYSFS PATCHES':^70}")
            print("=" * 70)
            print()

            print(f"{'Name':<35} {'Enabled':<12} {'Transition':<15}")
            print("-" * 70)

            for patch in sysfs_patches:
                enabled = 'Yes' if patch['enabled'] else 'No'
                trans = 'Yes' if patch.get('transition') else 'No'
                print(f"{patch['name']:<35} {enabled:<12} {trans:<15}")

            print()

    if issues:
        if not warn_only:
            print("=" * 70)
            print(f"{'ISSUES DETECTED':^70}")
            print("=" * 70)
            print()

        print(f"{'Severity':<12} {'Message':<58}")
        print("-" * 70)

        for issue in issues:
            msg = issue['message'][:58]
            print(f"{issue['severity']:<12} {msg:<58}")

        print()
    elif not warn_only:
        print("=" * 70)
        print(f"{'NO LIVE PATCH ISSUES DETECTED':^70}")
        print("=" * 70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor kernel live patching status for security and compliance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Check live patch status
  %(prog)s --verbose           # Show detailed patch information
  %(prog)s --format json       # Output in JSON format
  %(prog)s --warn-only         # Only show warnings/issues

Exit codes:
  0 - Live patching healthy or not in use
  1 - Issues detected (disabled/failed patches)
  2 - Usage error or system check failed

Supported live patch systems:
  - Kernel livepatch (sysfs)
  - Red Hat kpatch
  - Canonical Livepatch (Ubuntu)
  - Oracle Ksplice

Notes:
  - Requires Linux /sys/kernel/livepatch or live patch tools
  - Some operations may require root privileges
  - Live patches allow security updates without reboots
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
        help='Show detailed patch information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    args = parser.parse_args()

    # Get kernel info
    kernel_info = get_kernel_info()

    # Check live patch support
    support = check_livepatch_support()

    # Get status from all sources
    sysfs_patches = get_sysfs_livepatches()
    kpatch = get_kpatch_status()
    canonical = get_canonical_livepatch_status()
    ksplice = get_ksplice_status()

    # Analyze status
    analysis = analyze_livepatch_status(
        support, sysfs_patches, kpatch, canonical, ksplice
    )

    # Output results
    if args.format == 'json':
        output_json(kernel_info, support, analysis, sysfs_patches, kpatch, canonical, ksplice)
    elif args.format == 'table':
        output_table(kernel_info, support, analysis, sysfs_patches, kpatch, canonical, ksplice, args.verbose, args.warn_only)
    else:
        output_plain(kernel_info, support, analysis, sysfs_patches, kpatch, canonical, ksplice, args.verbose, args.warn_only)

    # Exit code based on issues
    has_warnings = any(i['severity'] in ['WARNING', 'CRITICAL', 'ERROR']
                       for i in analysis['issues'])

    if has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
