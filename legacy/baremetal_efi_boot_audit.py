#!/usr/bin/env python3
"""
Audit EFI/UEFI boot configuration for baremetal systems.

This script analyzes UEFI boot entries, boot order, and Secure Boot status
to help ensure consistent boot configurations across server fleets. Useful for:

- Detecting stale or duplicate boot entries
- Verifying boot order is correct
- Checking Secure Boot status
- Identifying systems with misconfigured UEFI settings
- Auditing boot configuration before firmware updates
- Ensuring PXE/network boot entries are properly configured

The script uses efibootmgr to gather UEFI boot information and analyzes
the results for common misconfigurations.

Exit codes:
    0 - Boot configuration retrieved, no issues detected
    1 - Issues detected (warnings about boot configuration)
    2 - Usage error or efibootmgr not available (non-UEFI system)
"""

import argparse
import json
import os
import re
import subprocess
import sys


def check_efibootmgr_available():
    """Check if efibootmgr is available."""
    try:
        result = subprocess.run(
            ['which', 'efibootmgr'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def check_efi_system():
    """Check if system is booted in EFI mode."""
    return os.path.exists('/sys/firmware/efi')


def run_efibootmgr():
    """Run efibootmgr and return output."""
    try:
        result = subprocess.run(
            ['efibootmgr', '-v'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running efibootmgr: {e.stderr}", file=sys.stderr)
        sys.exit(2)
    except FileNotFoundError:
        print("Error: efibootmgr not found", file=sys.stderr)
        print("Install with: sudo apt-get install efibootmgr", file=sys.stderr)
        sys.exit(2)


def parse_efibootmgr_output(output):
    """Parse efibootmgr output into structured data."""
    data = {
        'boot_current': None,
        'boot_next': None,
        'boot_order': [],
        'timeout': None,
        'secure_boot': None,
        'entries': {}
    }

    for line in output.strip().split('\n'):
        line = line.strip()

        # Parse BootCurrent
        if line.startswith('BootCurrent:'):
            data['boot_current'] = line.split(':')[1].strip()

        # Parse BootNext
        elif line.startswith('BootNext:'):
            data['boot_next'] = line.split(':')[1].strip()

        # Parse BootOrder
        elif line.startswith('BootOrder:'):
            order_str = line.split(':')[1].strip()
            data['boot_order'] = [x.strip() for x in order_str.split(',')]

        # Parse Timeout
        elif line.startswith('Timeout:'):
            timeout_str = line.split(':')[1].strip()
            try:
                data['timeout'] = int(timeout_str.split()[0])
            except (ValueError, IndexError):
                data['timeout'] = timeout_str

        # Parse SecureBoot
        elif 'SecureBoot' in line:
            if 'enabled' in line.lower():
                data['secure_boot'] = True
            elif 'disabled' in line.lower():
                data['secure_boot'] = False

        # Parse Boot entries (Boot0000, Boot0001, etc.)
        elif line.startswith('Boot'):
            match = re.match(r'^Boot([0-9A-Fa-f]{4})(\*)?\s+(.*)$', line)
            if match:
                entry_num = match.group(1)
                is_active = match.group(2) == '*'
                description = match.group(3)

                # Try to extract device path
                device_path = None
                if '\t' in description:
                    parts = description.split('\t')
                    label = parts[0]
                    device_path = parts[1] if len(parts) > 1 else None
                else:
                    label = description

                data['entries'][entry_num] = {
                    'label': label.strip(),
                    'active': is_active,
                    'device_path': device_path.strip() if device_path else None
                }

    return data


def get_secure_boot_status():
    """Get Secure Boot status from sysfs."""
    secure_boot_path = '/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
    setup_mode_path = '/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c'

    result = {
        'secure_boot': None,
        'setup_mode': None
    }

    try:
        if os.path.exists(secure_boot_path):
            with open(secure_boot_path, 'rb') as f:
                # Skip first 4 bytes (attributes)
                f.read(4)
                value = f.read(1)
                result['secure_boot'] = value == b'\x01'
    except (PermissionError, IOError):
        pass

    try:
        if os.path.exists(setup_mode_path):
            with open(setup_mode_path, 'rb') as f:
                f.read(4)
                value = f.read(1)
                result['setup_mode'] = value == b'\x01'
    except (PermissionError, IOError):
        pass

    return result


def analyze_boot_config(data):
    """Analyze boot configuration and return issues."""
    issues = []
    secure_status = get_secure_boot_status()

    # Update secure boot status if we got it from sysfs
    if secure_status['secure_boot'] is not None:
        data['secure_boot'] = secure_status['secure_boot']
    data['setup_mode'] = secure_status.get('setup_mode')

    # Check for no boot entries
    if not data['entries']:
        issues.append({
            'severity': 'CRITICAL',
            'message': 'No EFI boot entries found',
            'recommendation': 'System may not boot correctly; verify EFI configuration'
        })
        return issues

    # Check if current boot entry exists
    if data['boot_current'] and data['boot_current'] not in data['entries']:
        issues.append({
            'severity': 'WARNING',
            'message': f"Current boot entry {data['boot_current']} not in entries list",
            'recommendation': 'Boot configuration may be corrupted'
        })

    # Check for entries in boot order that don't exist
    for entry_num in data['boot_order']:
        if entry_num not in data['entries']:
            issues.append({
                'severity': 'WARNING',
                'message': f"Boot order references non-existent entry {entry_num}",
                'recommendation': 'Clean up boot order with efibootmgr'
            })

    # Check for active entries not in boot order
    for entry_num, entry in data['entries'].items():
        if entry['active'] and entry_num not in data['boot_order']:
            issues.append({
                'severity': 'WARNING',
                'message': f"Active entry {entry_num} ({entry['label']}) not in boot order",
                'recommendation': 'Add entry to boot order or deactivate it'
            })

    # Check for inactive entries in boot order
    for entry_num in data['boot_order']:
        if entry_num in data['entries'] and not data['entries'][entry_num]['active']:
            issues.append({
                'severity': 'INFO',
                'message': f"Inactive entry {entry_num} ({data['entries'][entry_num]['label']}) in boot order",
                'recommendation': 'Entry will be skipped during boot'
            })

    # Check for duplicate labels (common misconfiguration)
    labels = {}
    for entry_num, entry in data['entries'].items():
        label = entry['label']
        if label in labels:
            issues.append({
                'severity': 'WARNING',
                'message': f"Duplicate boot entry label '{label}' (entries {labels[label]} and {entry_num})",
                'recommendation': 'Remove duplicate entries with efibootmgr -b <num> -B'
            })
        else:
            labels[label] = entry_num

    # Check for common stale entry patterns
    stale_patterns = ['UEFI OS', 'Windows Boot Manager', 'Network Boot']
    for entry_num, entry in data['entries'].items():
        for pattern in stale_patterns:
            if pattern in entry['label']:
                # Only warn if there are multiple entries with similar names
                similar = [e for e in data['entries'].values() if pattern in e['label']]
                if len(similar) > 1:
                    issues.append({
                        'severity': 'INFO',
                        'message': f"Multiple '{pattern}' entries detected ({len(similar)} entries)",
                        'recommendation': 'Review and remove stale entries'
                    })
                    break

    # Check Secure Boot status
    if data['secure_boot'] is False:
        issues.append({
            'severity': 'INFO',
            'message': 'Secure Boot is disabled',
            'recommendation': 'Consider enabling Secure Boot for enhanced security'
        })

    # Check if in Setup Mode (Secure Boot not properly configured)
    if data.get('setup_mode') is True:
        issues.append({
            'severity': 'WARNING',
            'message': 'System is in Setup Mode (Secure Boot not fully configured)',
            'recommendation': 'Configure Secure Boot keys or disable Setup Mode'
        })

    # Check for very short timeout
    if data['timeout'] is not None and isinstance(data['timeout'], int):
        if data['timeout'] == 0:
            issues.append({
                'severity': 'INFO',
                'message': 'Boot timeout is 0 (no delay)',
                'recommendation': 'May want timeout for maintenance access'
            })

    # Check for excessive boot entries
    if len(data['entries']) > 10:
        issues.append({
            'severity': 'INFO',
            'message': f"Large number of boot entries ({len(data['entries'])})",
            'recommendation': 'Consider cleaning up unused entries'
        })

    return issues


def output_plain(data, issues, verbose, warn_only):
    """Output boot configuration in plain text format."""
    if not warn_only:
        print(f"Boot Current: {data['boot_current'] or 'N/A'}")
        print(f"Boot Order: {','.join(data['boot_order']) if data['boot_order'] else 'N/A'}")

        if data['timeout'] is not None:
            print(f"Timeout: {data['timeout']} seconds")

        secure_str = 'Enabled' if data['secure_boot'] else ('Disabled' if data['secure_boot'] is False else 'Unknown')
        print(f"Secure Boot: {secure_str}")

        if verbose and data['entries']:
            print(f"\nBoot Entries ({len(data['entries'])}):")
            for entry_num in data['boot_order']:
                if entry_num in data['entries']:
                    entry = data['entries'][entry_num]
                    active = '*' if entry['active'] else ' '
                    current = '<-' if entry_num == data['boot_current'] else ''
                    print(f"  Boot{entry_num}{active} {entry['label']} {current}")
                    if entry['device_path'] and verbose:
                        print(f"           {entry['device_path'][:70]}")

            # Show entries not in boot order
            orphaned = [e for e in data['entries'] if e not in data['boot_order']]
            if orphaned:
                print(f"\n  Not in boot order:")
                for entry_num in orphaned:
                    entry = data['entries'][entry_num]
                    active = '*' if entry['active'] else ' '
                    print(f"  Boot{entry_num}{active} {entry['label']}")

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


def output_json(data, issues):
    """Output boot configuration in JSON format."""
    output = {
        'boot_config': {
            'boot_current': data['boot_current'],
            'boot_next': data['boot_next'],
            'boot_order': data['boot_order'],
            'timeout': data['timeout'],
            'secure_boot': data['secure_boot'],
            'setup_mode': data.get('setup_mode'),
            'entry_count': len(data['entries']),
            'entries': data['entries']
        },
        'issues': issues,
        'issue_count': len(issues)
    }

    print(json.dumps(output, indent=2))


def output_table(data, issues, verbose, warn_only):
    """Output boot configuration in table format."""
    if not warn_only:
        print("="*70)
        print(f"{'EFI BOOT CONFIGURATION AUDIT':^70}")
        print("="*70)
        print()

        print(f"{'Property':<20} {'Value':<50}")
        print("-"*70)
        print(f"{'Boot Current':<20} {data['boot_current'] or 'N/A':<50}")
        print(f"{'Boot Order':<20} {','.join(data['boot_order'][:8]) or 'N/A':<50}")
        if len(data['boot_order']) > 8:
            print(f"{'':<20} {'...' + ','.join(data['boot_order'][8:]):<50}")
        print(f"{'Timeout':<20} {str(data['timeout']) + ' seconds' if data['timeout'] is not None else 'N/A':<50}")

        secure_str = 'Enabled' if data['secure_boot'] else ('Disabled' if data['secure_boot'] is False else 'Unknown')
        print(f"{'Secure Boot':<20} {secure_str:<50}")

        setup_str = 'Yes' if data.get('setup_mode') else ('No' if data.get('setup_mode') is False else 'Unknown')
        print(f"{'Setup Mode':<20} {setup_str:<50}")
        print(f"{'Total Entries':<20} {len(data['entries']):<50}")
        print()

        if verbose and data['entries']:
            print("-"*70)
            print(f"{'Entry':<10} {'Active':<8} {'Label':<52}")
            print("-"*70)

            for entry_num in data['boot_order']:
                if entry_num in data['entries']:
                    entry = data['entries'][entry_num]
                    active = 'Yes' if entry['active'] else 'No'
                    label = entry['label'][:50] + '..' if len(entry['label']) > 50 else entry['label']
                    current = ' *' if entry_num == data['boot_current'] else ''
                    print(f"Boot{entry_num:<6} {active:<8} {label}{current}")

            orphaned = [e for e in data['entries'] if e not in data['boot_order']]
            if orphaned:
                print(f"\n{'Not in boot order:'}")
                for entry_num in orphaned:
                    entry = data['entries'][entry_num]
                    active = 'Yes' if entry['active'] else 'No'
                    label = entry['label'][:50] + '..' if len(entry['label']) > 50 else entry['label']
                    print(f"Boot{entry_num:<6} {active:<8} {label}")

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
                print(f"{issue['severity']:<12} {message[:58]}")
                remaining = message[58:]
                while remaining:
                    print(f"{'':<12} {remaining[:58]}")
                    remaining = remaining[58:]
            else:
                print(f"{issue['severity']:<12} {message:<58}")

            if verbose:
                rec = issue['recommendation']
                print(f"{'  -> Fix':<12} {rec}")
                print()

        print()

    if not issues and not warn_only:
        print("="*70)
        print(f"{'NO ISSUES DETECTED':^70}")
        print("="*70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Audit EFI/UEFI boot configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Basic boot configuration audit
  %(prog)s --verbose           # Show detailed boot entries
  %(prog)s --format json       # JSON output for automation
  %(prog)s --warn-only         # Only show issues

Exit codes:
  0 - No issues detected
  1 - Issues detected (warnings about boot configuration)
  2 - Usage error or not an EFI system
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
        help='Show detailed boot entry information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    args = parser.parse_args()

    # Check if this is an EFI system
    if not check_efi_system():
        print("Error: System is not booted in EFI mode", file=sys.stderr)
        print("This script requires UEFI firmware", file=sys.stderr)
        sys.exit(2)

    # Check for efibootmgr
    if not check_efibootmgr_available():
        print("Error: efibootmgr not found", file=sys.stderr)
        print("Install with: sudo apt-get install efibootmgr", file=sys.stderr)
        sys.exit(2)

    # Get and parse boot configuration
    output = run_efibootmgr()
    data = parse_efibootmgr_output(output)

    # Analyze for issues
    issues = analyze_boot_config(data)

    # Output based on format
    if args.format == 'json':
        output_json(data, issues)
    elif args.format == 'table':
        output_table(data, issues, args.verbose, args.warn_only)
    else:
        output_plain(data, issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    has_warnings = any(i['severity'] in ['WARNING', 'CRITICAL'] for i in issues)
    sys.exit(1 if has_warnings else 0)


if __name__ == "__main__":
    main()
