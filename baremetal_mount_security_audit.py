#!/usr/bin/env python3
"""
Audit filesystem mount options for security compliance.

This script checks mounted filesystems against security best practices and
CIS benchmark recommendations. It verifies that security-critical mount options
(noexec, nosuid, nodev) are applied to appropriate mount points.

In large-scale baremetal environments, inconsistent mount options across hosts
can lead to privilege escalation vulnerabilities or allow execution of malicious
binaries from user-writable locations.

Checks include:
- /tmp, /var/tmp, /dev/shm: Should have noexec, nosuid, nodev
- /home: Should have nosuid, nodev
- /var: Should have nosuid (optionally noexec)
- /var/log: Should have noexec, nosuid, nodev
- /boot: Should have noexec, nosuid, nodev
- Removable media mounts: Should have noexec, nosuid, nodev

Exit codes:
    0 - All mount points comply with security recommendations
    1 - One or more mount points have missing security options
    2 - Usage error or missing dependencies

Examples:
    # Basic security audit
    baremetal_mount_security_audit.py

    # JSON output for automation
    baremetal_mount_security_audit.py --format json

    # Strict mode (more mount points checked)
    baremetal_mount_security_audit.py --strict

    # Show remediation commands
    baremetal_mount_security_audit.py --show-fixes
"""

import argparse
import json
import sys
from datetime import datetime

# Security requirements for specific mount points
# Format: (required_options, recommended_options, description)
# CIS Benchmark references included

SECURITY_REQUIREMENTS = {
    '/tmp': {
        'required': ['noexec', 'nosuid', 'nodev'],
        'recommended': [],
        'description': 'Temporary files - prevent execution of malicious binaries',
        'cis_ref': 'CIS 1.1.2-1.1.5'
    },
    '/var/tmp': {
        'required': ['noexec', 'nosuid', 'nodev'],
        'recommended': [],
        'description': 'Persistent temporary files - prevent code execution',
        'cis_ref': 'CIS 1.1.6-1.1.9'
    },
    '/dev/shm': {
        'required': ['noexec', 'nosuid', 'nodev'],
        'recommended': [],
        'description': 'Shared memory - prevent exploitation via shared memory',
        'cis_ref': 'CIS 1.1.15-1.1.18'
    },
    '/home': {
        'required': ['nosuid', 'nodev'],
        'recommended': [],
        'description': 'User home directories - prevent setuid/device file exploits',
        'cis_ref': 'CIS 1.1.13-1.1.14'
    },
    '/var': {
        'required': ['nosuid'],
        'recommended': ['nodev'],
        'description': 'Variable data - restrict setuid binaries',
        'cis_ref': 'CIS 1.1.10'
    },
    '/var/log': {
        'required': ['noexec', 'nosuid', 'nodev'],
        'recommended': [],
        'description': 'Log files - prevent log-based attacks',
        'cis_ref': 'CIS 1.1.11'
    },
    '/var/log/audit': {
        'required': ['noexec', 'nosuid', 'nodev'],
        'recommended': [],
        'description': 'Audit logs - protect audit trail integrity',
        'cis_ref': 'CIS 1.1.12'
    },
    '/boot': {
        'required': ['nosuid', 'nodev'],
        'recommended': ['noexec'],
        'description': 'Boot partition - protect bootloader and kernel',
        'cis_ref': 'CIS 1.1.19'
    },
    '/boot/efi': {
        'required': ['nosuid', 'nodev'],
        'recommended': ['noexec'],
        'description': 'EFI partition - protect UEFI binaries',
        'cis_ref': 'CIS 1.1.19'
    },
}

# Strict mode adds more mount points
STRICT_REQUIREMENTS = {
    '/opt': {
        'required': ['nosuid'],
        'recommended': ['nodev'],
        'description': 'Optional software - restrict setuid binaries',
        'cis_ref': 'Custom'
    },
    '/usr': {
        'required': [],
        'recommended': ['nodev'],
        'description': 'System binaries - prevent device file exploits',
        'cis_ref': 'Custom'
    },
    '/srv': {
        'required': ['nosuid', 'nodev'],
        'recommended': ['noexec'],
        'description': 'Service data - restrict execution',
        'cis_ref': 'Custom'
    },
}

# Removable/external media patterns
REMOVABLE_PATTERNS = [
    '/media/',
    '/mnt/',
    '/run/media/',
]


def parse_proc_mounts():
    """Parse /proc/mounts to get current mount information.

    Returns:
        list: List of mount dictionaries with device, mountpoint, fstype, options
    """
    mounts = []
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    device = parts[0]
                    mountpoint = parts[1]
                    fstype = parts[2]
                    options = set(parts[3].split(','))

                    mounts.append({
                        'device': device,
                        'mountpoint': mountpoint,
                        'fstype': fstype,
                        'options': options
                    })
        return mounts
    except FileNotFoundError:
        print("Error: /proc/mounts not found - requires Linux", file=sys.stderr)
        sys.exit(2)
    except IOError as e:
        print(f"Error reading /proc/mounts: {e}", file=sys.stderr)
        sys.exit(2)


def is_removable_mount(mountpoint):
    """Check if mountpoint is for removable/external media."""
    for pattern in REMOVABLE_PATTERNS:
        if mountpoint.startswith(pattern):
            return True
    return False


def check_mount_security(mount, requirements):
    """Check a single mount against security requirements.

    Args:
        mount: Mount dictionary with options
        requirements: Dict of required and recommended options

    Returns:
        dict: Audit result with missing options and status
    """
    options = mount['options']
    required = set(requirements.get('required', []))
    recommended = set(requirements.get('recommended', []))

    missing_required = required - options
    missing_recommended = recommended - options

    # Check for 'rw' when mount should be read-only
    # (not enforcing this as it's often intentional)

    return {
        'mountpoint': mount['mountpoint'],
        'device': mount['device'],
        'fstype': mount['fstype'],
        'current_options': sorted(options),
        'missing_required': sorted(missing_required),
        'missing_recommended': sorted(missing_recommended),
        'has_noexec': 'noexec' in options,
        'has_nosuid': 'nosuid' in options,
        'has_nodev': 'nodev' in options,
        'description': requirements.get('description', ''),
        'cis_ref': requirements.get('cis_ref', ''),
        'compliant': len(missing_required) == 0,
        'fully_hardened': len(missing_required) == 0 and len(missing_recommended) == 0
    }


def audit_mounts(mounts, strict=False, check_removable=True):
    """Audit all mounts against security requirements.

    Args:
        mounts: List of mount dictionaries
        strict: Include additional mount points
        check_removable: Check removable media mounts

    Returns:
        dict: Audit results with summary and details
    """
    results = {
        'timestamp': datetime.now().isoformat(),
        'total_mounts': len(mounts),
        'checked': 0,
        'compliant': 0,
        'non_compliant': 0,
        'fully_hardened': 0,
        'findings': [],
        'removable_findings': [],
        'summary': {}
    }

    # Build requirements map
    requirements = dict(SECURITY_REQUIREMENTS)
    if strict:
        requirements.update(STRICT_REQUIREMENTS)

    # Create mount lookup by mountpoint
    mount_lookup = {m['mountpoint']: m for m in mounts}

    # Check known mount points
    for mountpoint, reqs in requirements.items():
        if mountpoint in mount_lookup:
            mount = mount_lookup[mountpoint]
            result = check_mount_security(mount, reqs)
            results['checked'] += 1
            results['findings'].append(result)

            if result['compliant']:
                results['compliant'] += 1
                if result['fully_hardened']:
                    results['fully_hardened'] += 1
            else:
                results['non_compliant'] += 1
        else:
            # Mount point doesn't exist as separate partition
            # This is informational - some systems don't have separate partitions
            pass

    # Check removable media mounts
    if check_removable:
        removable_reqs = {
            'required': ['noexec', 'nosuid', 'nodev'],
            'recommended': [],
            'description': 'Removable media - prevent execution of untrusted code',
            'cis_ref': 'CIS 1.1.20-1.1.23'
        }

        for mount in mounts:
            if is_removable_mount(mount['mountpoint']):
                result = check_mount_security(mount, removable_reqs)
                results['removable_findings'].append(result)
                results['checked'] += 1

                if result['compliant']:
                    results['compliant'] += 1
                else:
                    results['non_compliant'] += 1

    # Generate summary
    results['summary'] = {
        'total_checked': results['checked'],
        'compliant': results['compliant'],
        'non_compliant': results['non_compliant'],
        'fully_hardened': results['fully_hardened'],
        'compliance_percentage': (
            round(results['compliant'] / results['checked'] * 100, 1)
            if results['checked'] > 0 else 100.0
        )
    }

    return results


def get_remount_command(finding):
    """Generate remount command to fix missing options.

    Args:
        finding: Audit finding dict

    Returns:
        str: Shell command to fix the issue
    """
    all_missing = finding['missing_required'] + finding['missing_recommended']
    if not all_missing:
        return None

    options = ','.join(all_missing)
    return f"mount -o remount,{options} {finding['mountpoint']}"


def get_fstab_entry(finding):
    """Generate fstab entry with security options.

    Args:
        finding: Audit finding dict

    Returns:
        str: Suggested fstab line
    """
    all_required = finding['missing_required'] + finding['missing_recommended']
    current = set(finding['current_options'])
    new_opts = sorted(current | set(all_required))
    opts_str = ','.join(new_opts)

    return f"{finding['device']} {finding['mountpoint']} {finding['fstype']} {opts_str} 0 0"


def output_plain(results, verbose=False, warn_only=False, show_fixes=False):
    """Output results in plain text format."""
    summary = results['summary']

    if not warn_only:
        print("Mount Security Audit")
        print("=" * 70)
        print(f"Mounts checked:    {summary['total_checked']}")
        print(f"Compliant:         {summary['compliant']}")
        print(f"Non-compliant:     {summary['non_compliant']}")
        print(f"Fully hardened:    {summary['fully_hardened']}")
        print(f"Compliance:        {summary['compliance_percentage']}%")
        print()

    # Show non-compliant findings
    non_compliant = [f for f in results['findings'] if not f['compliant']]
    non_compliant += [f for f in results['removable_findings'] if not f['compliant']]

    if non_compliant:
        print("NON-COMPLIANT MOUNT POINTS:")
        print("-" * 70)
        for finding in non_compliant:
            print(f"[FAIL] {finding['mountpoint']}")
            print(f"       Missing required: {', '.join(finding['missing_required'])}")
            if finding['missing_recommended']:
                print(f"       Missing recommended: {', '.join(finding['missing_recommended'])}")
            if verbose:
                print(f"       Current options: {', '.join(finding['current_options'])}")
                print(f"       Reference: {finding['cis_ref']}")
                print(f"       {finding['description']}")

            if show_fixes:
                cmd = get_remount_command(finding)
                if cmd:
                    print(f"       Fix (temporary): sudo {cmd}")
            print()

    # Show compliant findings if verbose
    if verbose and not warn_only:
        compliant = [f for f in results['findings'] if f['compliant']]
        if compliant:
            print("COMPLIANT MOUNT POINTS:")
            print("-" * 70)
            for finding in compliant:
                status = "[HARDENED]" if finding['fully_hardened'] else "[OK]"
                print(f"{status} {finding['mountpoint']}")
                if finding['missing_recommended']:
                    print(f"         Consider adding: {', '.join(finding['missing_recommended'])}")
            print()

    # Show fstab suggestions if requested
    if show_fixes and non_compliant:
        print("SUGGESTED /etc/fstab ENTRIES:")
        print("-" * 70)
        print("# Add or modify these entries in /etc/fstab for persistent changes:")
        for finding in non_compliant:
            print(f"# {finding['mountpoint']} - {finding['description']}")
            print(get_fstab_entry(finding))
            print()

    # Final status
    if not warn_only:
        if summary['non_compliant'] == 0:
            print("[OK] All checked mount points are compliant")
        else:
            print(f"[FAIL] {summary['non_compliant']} mount point(s) need attention")


def output_json(results):
    """Output results in JSON format."""
    print(json.dumps(results, indent=2, default=list))


def output_table(results, verbose=False, warn_only=False):
    """Output results in table format."""
    all_findings = results['findings'] + results['removable_findings']

    if warn_only:
        all_findings = [f for f in all_findings if not f['compliant']]

    if not all_findings:
        print("No findings to display")
        return

    # Print header
    print(f"{'Status':<10} {'Mount Point':<25} {'noexec':<8} {'nosuid':<8} {'nodev':<8} {'Missing':<20}")
    print("=" * 85)

    for finding in sorted(all_findings, key=lambda x: (x['compliant'], x['mountpoint'])):
        status = "OK" if finding['compliant'] else "FAIL"
        if finding['fully_hardened']:
            status = "HARDENED"

        noexec = "Yes" if finding['has_noexec'] else "No"
        nosuid = "Yes" if finding['has_nosuid'] else "No"
        nodev = "Yes" if finding['has_nodev'] else "No"
        missing = ', '.join(finding['missing_required'][:3])  # Truncate if long
        if len(finding['missing_required']) > 3:
            missing += '...'

        mp = finding['mountpoint'][:24]
        print(f"{status:<10} {mp:<25} {noexec:<8} {nosuid:<8} {nodev:<8} {missing:<20}")

    print()
    summary = results['summary']
    print(f"Compliance: {summary['compliant']}/{summary['total_checked']} ({summary['compliance_percentage']}%)")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Audit filesystem mount options for security compliance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Basic security audit
  %(prog)s --format json      # JSON output for automation
  %(prog)s --strict           # Include additional mount points
  %(prog)s --show-fixes       # Show remediation commands
  %(prog)s -v                 # Verbose output with CIS references

Security Options Explained:
  noexec  - Prevent execution of binaries from this filesystem
  nosuid  - Ignore setuid/setgid bits (prevent privilege escalation)
  nodev   - Prevent interpretation of device files (prevent device exploits)

Exit codes:
  0 - All mount points comply with security recommendations
  1 - One or more mount points have missing security options
  2 - Usage error or missing dependencies
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
        help='Show detailed information including CIS references'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show non-compliant mount points'
    )

    parser.add_argument(
        '--strict',
        action='store_true',
        help='Check additional mount points (/opt, /usr, /srv)'
    )

    parser.add_argument(
        '--no-removable',
        action='store_true',
        help='Skip checking removable media mount points'
    )

    parser.add_argument(
        '--show-fixes',
        action='store_true',
        help='Show commands to fix non-compliant mounts'
    )

    args = parser.parse_args()

    # Parse current mounts
    mounts = parse_proc_mounts()

    # Run audit
    results = audit_mounts(
        mounts,
        strict=args.strict,
        check_removable=not args.no_removable
    )

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.verbose, args.warn_only)
    else:  # plain
        output_plain(results, args.verbose, args.warn_only, args.show_fixes)

    # Exit based on compliance
    sys.exit(1 if results['summary']['non_compliant'] > 0 else 0)


if __name__ == '__main__':
    main()
