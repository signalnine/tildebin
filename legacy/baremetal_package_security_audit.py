#!/usr/bin/env python3
"""
Audit system packages for pending security updates.

Checks for available security updates on Debian/Ubuntu (apt) and
RHEL/CentOS/Fedora (dnf/yum) systems. Identifies packages with
known security vulnerabilities that need patching.

Critical for:
- Security compliance auditing
- Vulnerability management
- Patch management workflows
- Fleet-wide security posture assessment

Exit codes:
    0 - No security updates pending
    1 - Security updates available or issues detected
    2 - Usage error or unsupported package manager
"""

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple


def detect_package_manager() -> Optional[str]:
    """Detect the system's package manager."""
    # Check for apt (Debian/Ubuntu)
    if os.path.exists('/usr/bin/apt') or os.path.exists('/usr/bin/apt-get'):
        return 'apt'

    # Check for dnf (Fedora/RHEL 8+)
    if os.path.exists('/usr/bin/dnf'):
        return 'dnf'

    # Check for yum (RHEL 7/CentOS 7)
    if os.path.exists('/usr/bin/yum'):
        return 'yum'

    return None


def run_command(cmd: List[str], timeout: int = 120) -> Tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, '', 'Command timed out'
    except FileNotFoundError:
        return -1, '', f'Command not found: {cmd[0]}'


def get_apt_security_updates() -> Tuple[List[Dict], List[str]]:
    """Get security updates for apt-based systems."""
    updates = []
    errors = []

    # Update package lists first (non-fatal if fails)
    returncode, _, stderr = run_command(
        ['apt-get', 'update', '-qq'],
        timeout=300
    )
    if returncode != 0 and 'permission denied' in stderr.lower():
        # Try without update if we don't have permissions
        pass

    # Get list of upgradable packages
    returncode, stdout, stderr = run_command(
        ['apt', 'list', '--upgradable'],
        timeout=60
    )

    if returncode != 0:
        errors.append(f'Failed to list upgradable packages: {stderr}')
        return updates, errors

    # Parse output
    for line in stdout.strip().split('\n'):
        if not line or line.startswith('Listing'):
            continue

        # Format: package/source version [arch]
        match = re.match(r'^([^/]+)/(\S+)\s+(\S+)\s+(\S+)', line)
        if match:
            package = match.group(1)
            source = match.group(2)
            new_version = match.group(3)
            arch = match.group(4)

            # Check if it's a security update
            is_security = '-security' in source or 'security' in source.lower()

            if is_security:
                updates.append({
                    'package': package,
                    'new_version': new_version,
                    'source': source,
                    'arch': arch,
                    'severity': 'security',
                })

    # Alternative: use apt-check if available (Ubuntu)
    if not updates:
        returncode, stdout, stderr = run_command(
            ['/usr/lib/update-notifier/apt-check', '--human-readable'],
            timeout=60
        )
        if returncode == 0 and 'security' in stdout.lower():
            # Parse the human-readable output
            match = re.search(r'(\d+)\s+.*security', stdout)
            if match:
                count = int(match.group(1))
                if count > 0:
                    # We know there are security updates but can't list them
                    errors.append(
                        f'apt-check reports {count} security updates but '
                        f'detailed list unavailable'
                    )

    return updates, errors


def get_dnf_security_updates() -> Tuple[List[Dict], List[str]]:
    """Get security updates for dnf-based systems."""
    updates = []
    errors = []

    # Check for security updates
    returncode, stdout, stderr = run_command(
        ['dnf', 'updateinfo', 'list', 'security', '--available', '-q'],
        timeout=120
    )

    if returncode != 0:
        # Try alternative command
        returncode, stdout, stderr = run_command(
            ['dnf', 'check-update', '--security', '-q'],
            timeout=120
        )
        if returncode not in [0, 100]:  # 100 = updates available
            errors.append(f'Failed to check security updates: {stderr}')
            return updates, errors

    # Parse dnf updateinfo output
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 3:
            # Format varies: ADVISORY-ID SEVERITY PACKAGE
            # or: PACKAGE VERSION REPO
            if parts[0].startswith(('RHSA', 'RHBA', 'RHEA', 'CESA', 'FEDORA')):
                advisory = parts[0]
                severity = parts[1] if len(parts) > 2 else 'unknown'
                package = parts[2] if len(parts) > 2 else parts[1]
            else:
                package = parts[0]
                advisory = ''
                severity = 'security'

            updates.append({
                'package': package,
                'advisory': advisory,
                'severity': severity.lower(),
                'new_version': parts[1] if len(parts) > 1 else 'unknown',
            })

    return updates, errors


def get_yum_security_updates() -> Tuple[List[Dict], List[str]]:
    """Get security updates for yum-based systems."""
    updates = []
    errors = []

    # Check for security updates
    returncode, stdout, stderr = run_command(
        ['yum', 'updateinfo', 'list', 'security', '--available', '-q'],
        timeout=120
    )

    if returncode != 0:
        # Try alternative: yum check-update
        returncode, stdout, stderr = run_command(
            ['yum', 'check-update', '--security', '-q'],
            timeout=120
        )
        if returncode not in [0, 100]:  # 100 = updates available
            errors.append(f'Failed to check security updates: {stderr}')
            return updates, errors

    # Parse yum output (similar to dnf)
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 2:
            package = parts[0]
            version = parts[1] if len(parts) > 1 else 'unknown'

            updates.append({
                'package': package,
                'new_version': version,
                'severity': 'security',
            })

    return updates, errors


def categorize_severity(updates: List[Dict]) -> Dict[str, int]:
    """Categorize updates by severity."""
    categories = {
        'critical': 0,
        'important': 0,
        'moderate': 0,
        'low': 0,
        'security': 0,  # generic security
        'unknown': 0,
    }

    for update in updates:
        severity = update.get('severity', 'unknown').lower()
        if severity in categories:
            categories[severity] += 1
        elif 'critical' in severity or 'crit' in severity:
            categories['critical'] += 1
        elif 'important' in severity or 'high' in severity:
            categories['important'] += 1
        elif 'moderate' in severity or 'medium' in severity:
            categories['moderate'] += 1
        elif 'low' in severity:
            categories['low'] += 1
        else:
            categories['security'] += 1

    return categories


def output_plain(updates: List[Dict], errors: List[str],
                 package_manager: str, verbose: bool, warn_only: bool):
    """Plain text output."""
    if not updates and not errors:
        print(f"No security updates pending ({package_manager})")
        return

    print(f"Security Updates Audit ({package_manager})")
    print("=" * 50)

    if updates:
        categories = categorize_severity(updates)
        print(f"\nPending security updates: {len(updates)}")
        if categories['critical'] > 0:
            print(f"  Critical: {categories['critical']}")
        if categories['important'] > 0:
            print(f"  Important: {categories['important']}")
        if categories['moderate'] > 0:
            print(f"  Moderate: {categories['moderate']}")
        if categories['low'] > 0:
            print(f"  Low: {categories['low']}")
        if categories['security'] > 0:
            print(f"  Security (unclassified): {categories['security']}")

        if verbose:
            print("\nPackages:")
            for update in sorted(updates, key=lambda x: x['package']):
                pkg = update['package']
                ver = update.get('new_version', 'N/A')
                sev = update.get('severity', 'security')
                advisory = update.get('advisory', '')
                if advisory:
                    print(f"  [{sev.upper()}] {pkg} -> {ver} ({advisory})")
                else:
                    print(f"  [{sev.upper()}] {pkg} -> {ver}")

    if errors:
        print("\nErrors:")
        for error in errors:
            print(f"  ! {error}")


def output_json(updates: List[Dict], errors: List[str],
                package_manager: str, warn_only: bool):
    """JSON output."""
    categories = categorize_severity(updates)

    output = {
        'package_manager': package_manager,
        'total_updates': len(updates),
        'categories': categories,
        'updates': updates,
        'errors': errors,
        'has_critical': categories.get('critical', 0) > 0,
        'has_updates': len(updates) > 0,
    }

    print(json.dumps(output, indent=2))


def output_table(updates: List[Dict], errors: List[str],
                 package_manager: str, warn_only: bool):
    """Table output."""
    print(f"{'SEVERITY':<12} {'PACKAGE':<40} {'NEW VERSION':<20} {'ADVISORY':<15}")
    print("-" * 90)

    for update in sorted(updates, key=lambda x: (
        0 if 'critical' in x.get('severity', '').lower() else
        1 if 'important' in x.get('severity', '').lower() else
        2 if 'moderate' in x.get('severity', '').lower() else
        3 if 'low' in x.get('severity', '').lower() else 4,
        x['package']
    )):
        sev = update.get('severity', 'security')[:11]
        pkg = update['package'][:39]
        ver = update.get('new_version', 'N/A')[:19]
        adv = update.get('advisory', '')[:14]

        print(f"{sev.upper():<12} {pkg:<40} {ver:<20} {adv:<15}")

    print()
    categories = categorize_severity(updates)
    print(f"Total: {len(updates)} security updates "
          f"(Critical: {categories['critical']}, "
          f"Important: {categories['important']}, "
          f"Moderate: {categories['moderate']}, "
          f"Low: {categories['low']})")

    if errors:
        print(f"\nErrors: {len(errors)}")
        for error in errors:
            print(f"  ! {error}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Audit system packages for pending security updates',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check for security updates
  %(prog)s

  # Verbose output with package details
  %(prog)s --verbose

  # JSON output for automation
  %(prog)s --format json

  # Table format for review
  %(prog)s --format table

  # Only exit with error if critical updates pending
  %(prog)s --critical-only

Supported package managers:
  - apt (Debian, Ubuntu)
  - dnf (Fedora, RHEL 8+, CentOS Stream)
  - yum (RHEL 7, CentOS 7)

Exit codes:
  0 - No security updates pending (or only non-critical with --critical-only)
  1 - Security updates available or errors encountered
  2 - Usage error or unsupported package manager

Notes:
  - May require root/sudo for accurate results on some systems
  - Package list refresh may take time on first run
  - Severity classification depends on distribution's metadata
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
        help='Show detailed package information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if updates are pending'
    )

    parser.add_argument(
        '--critical-only',
        action='store_true',
        help='Only return exit code 1 for critical/important updates'
    )

    parser.add_argument(
        '--package-manager',
        choices=['apt', 'dnf', 'yum', 'auto'],
        default='auto',
        help='Package manager to use (default: auto-detect)'
    )

    args = parser.parse_args()

    # Detect or use specified package manager
    if args.package_manager == 'auto':
        pkg_mgr = detect_package_manager()
        if pkg_mgr is None:
            print("Error: Could not detect package manager", file=sys.stderr)
            print("Supported: apt (Debian/Ubuntu), dnf/yum (RHEL/Fedora)",
                  file=sys.stderr)
            sys.exit(2)
    else:
        pkg_mgr = args.package_manager

    # Get security updates
    if pkg_mgr == 'apt':
        updates, errors = get_apt_security_updates()
    elif pkg_mgr == 'dnf':
        updates, errors = get_dnf_security_updates()
    elif pkg_mgr == 'yum':
        updates, errors = get_yum_security_updates()
    else:
        print(f"Error: Unsupported package manager: {pkg_mgr}", file=sys.stderr)
        sys.exit(2)

    # Output results
    if args.warn_only and not updates and not errors:
        pass  # No output
    elif args.format == 'json':
        output_json(updates, errors, pkg_mgr, args.warn_only)
    elif args.format == 'table':
        output_table(updates, errors, pkg_mgr, args.warn_only)
    else:
        output_plain(updates, errors, pkg_mgr, args.verbose, args.warn_only)

    # Determine exit code
    if errors:
        sys.exit(1)

    if not updates:
        sys.exit(0)

    if args.critical_only:
        categories = categorize_severity(updates)
        if categories['critical'] > 0 or categories['important'] > 0:
            sys.exit(1)
        sys.exit(0)

    sys.exit(1)


if __name__ == '__main__':
    main()
