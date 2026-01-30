#!/usr/bin/env python3
"""
Monitor SELinux and AppArmor security policy status and violations.

This script checks the status of Linux Security Modules (LSM) on baremetal
systems, focusing on SELinux and AppArmor - the two most common mandatory
access control (MAC) systems:

- SELinux mode (enforcing/permissive/disabled)
- AppArmor status (enabled/profiles loaded)
- Recent policy denials from audit logs
- Profile/policy statistics
- Boolean settings (SELinux)
- Complain vs enforce mode profiles (AppArmor)

In security-hardened environments (NIST 800-53, PCI-DSS, CIS benchmarks),
MAC enforcement is required. This tool helps verify compliance and detect
policy violations that may indicate:
- Misconfigured applications
- Potential security incidents
- Policy drift from baseline

Exit codes:
    0 - Security module active and no recent denials
    1 - Warnings found (permissive mode, denials, or issues)
    2 - Usage error or no security module available
"""

import argparse
import sys
import json
import subprocess
import os
import re
from datetime import datetime, timedelta


def run_command(cmd):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}"
    except Exception as e:
        return -1, "", str(e)


def check_selinux_available():
    """Check if SELinux is available on the system."""
    # Check for getenforce command
    rc, _, _ = run_command(['which', 'getenforce'])
    if rc == 0:
        return True
    # Also check /sys/fs/selinux
    return os.path.exists('/sys/fs/selinux')


def check_apparmor_available():
    """Check if AppArmor is available on the system."""
    # Check for aa-status command
    rc, _, _ = run_command(['which', 'aa-status'])
    if rc == 0:
        return True
    # Also check /sys/module/apparmor
    return os.path.exists('/sys/module/apparmor')


def get_selinux_status():
    """Get SELinux status and configuration."""
    status = {
        'available': False,
        'mode': 'unknown',
        'policy': 'unknown',
        'mls_enabled': False,
        'booleans': [],
        'issues': []
    }

    # Get enforcement mode
    rc, stdout, _ = run_command(['getenforce'])
    if rc != 0:
        return status

    status['available'] = True
    status['mode'] = stdout.strip().lower()

    if status['mode'] == 'disabled':
        status['issues'].append({
            'severity': 'WARNING',
            'type': 'selinux_disabled',
            'message': 'SELinux is disabled - system is not protected by MAC'
        })
    elif status['mode'] == 'permissive':
        status['issues'].append({
            'severity': 'WARNING',
            'type': 'selinux_permissive',
            'message': 'SELinux is in permissive mode - violations logged but not enforced'
        })

    # Get policy type from /etc/selinux/config
    if os.path.exists('/etc/selinux/config'):
        try:
            with open('/etc/selinux/config', 'r') as f:
                for line in f:
                    if line.startswith('SELINUXTYPE='):
                        status['policy'] = line.split('=')[1].strip()
                        break
        except (IOError, PermissionError):
            pass

    # Check sestatus for more details
    rc, stdout, _ = run_command(['sestatus'])
    if rc == 0:
        for line in stdout.split('\n'):
            if 'Policy MLS status:' in line:
                status['mls_enabled'] = 'enabled' in line.lower()
            elif 'Loaded policy name:' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    status['policy'] = parts[1].strip()

    # Get important security booleans
    rc, stdout, _ = run_command(['getsebool', '-a'])
    if rc == 0:
        important_bools = [
            'httpd_can_network_connect',
            'httpd_enable_homedirs',
            'allow_execstack',
            'allow_execmem',
            'allow_execheap',
            'selinuxuser_execmod',
            'ssh_sysadm_login',
        ]
        for line in stdout.split('\n'):
            for bool_name in important_bools:
                if line.startswith(bool_name):
                    parts = line.split('-->')
                    if len(parts) == 2:
                        value = parts[1].strip()
                        status['booleans'].append({
                            'name': bool_name,
                            'value': value
                        })
                        # Flag dangerous booleans
                        if bool_name.startswith('allow_exec') and value == 'on':
                            status['issues'].append({
                                'severity': 'WARNING',
                                'type': 'dangerous_boolean',
                                'message': f"SELinux boolean '{bool_name}' is ON - allows executable memory"
                            })

    return status


def get_apparmor_status():
    """Get AppArmor status and profile information."""
    status = {
        'available': False,
        'enabled': False,
        'profiles': {
            'total': 0,
            'enforce': 0,
            'complain': 0,
            'unconfined': 0
        },
        'processes': {
            'total': 0,
            'confined': 0,
            'unconfined': 0
        },
        'issues': []
    }

    # Check if AppArmor module is loaded
    if os.path.exists('/sys/module/apparmor'):
        status['available'] = True

    # Get status from aa-status (requires root for full info)
    rc, stdout, stderr = run_command(['aa-status', '--json'])
    if rc == 0:
        try:
            data = json.loads(stdout)
            status['enabled'] = True

            # Parse profile counts
            if 'profiles' in data:
                profiles = data['profiles']
                status['profiles']['total'] = len(profiles)
                for name, mode in profiles.items():
                    if mode == 'enforce':
                        status['profiles']['enforce'] += 1
                    elif mode == 'complain':
                        status['profiles']['complain'] += 1
                    else:
                        status['profiles']['unconfined'] += 1

            # Parse process counts
            if 'processes' in data:
                for mode, procs in data['processes'].items():
                    count = len(procs) if isinstance(procs, dict) else 0
                    if mode == 'unconfined':
                        status['processes']['unconfined'] = count
                    else:
                        status['processes']['confined'] += count
                status['processes']['total'] = (
                    status['processes']['confined'] +
                    status['processes']['unconfined']
                )

        except json.JSONDecodeError:
            # Fall back to text parsing
            pass

    # Fallback: parse text output if JSON failed
    if not status['enabled']:
        rc, stdout, stderr = run_command(['aa-status'])
        if rc == 0 or 'profiles are loaded' in stdout:
            status['enabled'] = True
            for line in stdout.split('\n'):
                if 'profiles are loaded' in line:
                    match = re.search(r'(\d+) profiles are loaded', line)
                    if match:
                        status['profiles']['total'] = int(match.group(1))
                elif 'profiles are in enforce mode' in line:
                    match = re.search(r'(\d+) profiles are in enforce', line)
                    if match:
                        status['profiles']['enforce'] = int(match.group(1))
                elif 'profiles are in complain mode' in line:
                    match = re.search(r'(\d+) profiles are in complain', line)
                    if match:
                        status['profiles']['complain'] = int(match.group(1))
                elif 'processes are unconfined' in line:
                    match = re.search(r'(\d+) processes are unconfined', line)
                    if match:
                        status['processes']['unconfined'] = int(match.group(1))

    # Check for issues
    if status['available'] and not status['enabled']:
        status['issues'].append({
            'severity': 'WARNING',
            'type': 'apparmor_not_running',
            'message': 'AppArmor module loaded but not running'
        })

    if status['profiles']['complain'] > 0:
        status['issues'].append({
            'severity': 'INFO',
            'type': 'profiles_in_complain',
            'message': f"{status['profiles']['complain']} profiles in complain mode (not enforcing)"
        })

    if status['processes']['unconfined'] > 10:
        status['issues'].append({
            'severity': 'INFO',
            'type': 'many_unconfined',
            'message': f"{status['processes']['unconfined']} processes running unconfined"
        })

    return status


def get_recent_denials(hours=24, limit=20):
    """Get recent SELinux/AppArmor denials from audit log."""
    denials = []
    cutoff = datetime.now() - timedelta(hours=hours)

    # Try to read audit log
    audit_log = '/var/log/audit/audit.log'
    if os.path.exists(audit_log):
        try:
            rc, stdout, _ = run_command(['tail', '-n', '1000', audit_log])
            if rc == 0:
                for line in stdout.split('\n'):
                    if 'avc:  denied' in line or 'AVC' in line:
                        # Parse SELinux denial
                        denial = parse_selinux_denial(line)
                        if denial:
                            denials.append(denial)
                    elif 'apparmor="DENIED"' in line or 'apparmor="ALLOWED"' in line:
                        # Parse AppArmor denial
                        denial = parse_apparmor_denial(line)
                        if denial:
                            denials.append(denial)
        except (IOError, PermissionError):
            pass

    # Also check dmesg for recent denials
    rc, stdout, _ = run_command(['dmesg', '--time-format=iso'])
    if rc == 0:
        for line in stdout.split('\n'):
            if 'avc:  denied' in line:
                denial = parse_selinux_denial(line)
                if denial:
                    denials.append(denial)
            elif 'apparmor="DENIED"' in line:
                denial = parse_apparmor_denial(line)
                if denial:
                    denials.append(denial)

    # Deduplicate and limit
    seen = set()
    unique_denials = []
    for d in denials:
        key = (d.get('type'), d.get('source'), d.get('target'), d.get('permission'))
        if key not in seen:
            seen.add(key)
            unique_denials.append(d)

    return unique_denials[:limit]


def parse_selinux_denial(line):
    """Parse a SELinux AVC denial message."""
    denial = {'type': 'selinux', 'raw': line[:200]}

    # Extract permission
    perm_match = re.search(r'\{ ([^}]+) \}', line)
    if perm_match:
        denial['permission'] = perm_match.group(1)

    # Extract source context
    scontext_match = re.search(r'scontext=(\S+)', line)
    if scontext_match:
        denial['source'] = scontext_match.group(1)

    # Extract target context
    tcontext_match = re.search(r'tcontext=(\S+)', line)
    if tcontext_match:
        denial['target'] = tcontext_match.group(1)

    # Extract class
    class_match = re.search(r'tclass=(\S+)', line)
    if class_match:
        denial['class'] = class_match.group(1)

    # Extract command
    comm_match = re.search(r'comm="([^"]+)"', line)
    if comm_match:
        denial['command'] = comm_match.group(1)

    return denial if 'permission' in denial else None


def parse_apparmor_denial(line):
    """Parse an AppArmor denial message."""
    denial = {'type': 'apparmor', 'raw': line[:200]}

    # Extract profile
    profile_match = re.search(r'profile="([^"]+)"', line)
    if profile_match:
        denial['profile'] = profile_match.group(1)

    # Extract operation
    op_match = re.search(r'operation="([^"]+)"', line)
    if op_match:
        denial['permission'] = op_match.group(1)

    # Extract name (file/resource)
    name_match = re.search(r'name="([^"]+)"', line)
    if name_match:
        denial['target'] = name_match.group(1)

    # Extract command
    comm_match = re.search(r'comm="([^"]+)"', line)
    if comm_match:
        denial['command'] = comm_match.group(1)

    return denial if 'profile' in denial or 'permission' in denial else None


def output_plain(selinux, apparmor, denials, verbose, warn_only):
    """Output results in plain text format."""
    issues = []

    if selinux['available']:
        if not warn_only:
            print(f"SELinux: {selinux['mode']}")
            print(f"  Policy: {selinux['policy']}")
            print(f"  MLS: {'enabled' if selinux['mls_enabled'] else 'disabled'}")
            if verbose and selinux['booleans']:
                print("  Key booleans:")
                for b in selinux['booleans']:
                    print(f"    {b['name']}: {b['value']}")
        issues.extend(selinux['issues'])
    elif apparmor['available']:
        if not warn_only:
            status_str = 'enabled' if apparmor['enabled'] else 'disabled'
            print(f"AppArmor: {status_str}")
            print(f"  Profiles: {apparmor['profiles']['total']} loaded")
            print(f"    Enforce: {apparmor['profiles']['enforce']}")
            print(f"    Complain: {apparmor['profiles']['complain']}")
            if verbose:
                print(f"  Processes:")
                print(f"    Confined: {apparmor['processes']['confined']}")
                print(f"    Unconfined: {apparmor['processes']['unconfined']}")
        issues.extend(apparmor['issues'])
    else:
        if not warn_only:
            print("No LSM: Neither SELinux nor AppArmor detected")

    if denials:
        if not warn_only:
            print(f"\nRecent denials: {len(denials)}")
        for d in denials:
            if d['type'] == 'selinux':
                msg = f"SELinux: {d.get('command', 'unknown')} denied {d.get('permission', '?')} on {d.get('class', '?')}"
            else:
                msg = f"AppArmor: {d.get('profile', 'unknown')} denied {d.get('permission', '?')} to {d.get('target', '?')}"
            issues.append({
                'severity': 'WARNING',
                'type': 'denial',
                'message': msg
            })

    if not warn_only:
        print()

    if issues:
        for issue in issues:
            if warn_only and issue['severity'] == 'INFO':
                continue
            print(f"[{issue['severity']}] {issue['message']}")
    elif not warn_only:
        print("No issues detected.")


def output_json(selinux, apparmor, denials, verbose):
    """Output results in JSON format."""
    result = {
        'selinux': selinux if selinux['available'] else None,
        'apparmor': apparmor if apparmor['available'] else None,
        'denials': denials,
        'issues': selinux.get('issues', []) + apparmor.get('issues', [])
    }
    if denials:
        for d in denials:
            result['issues'].append({
                'severity': 'WARNING',
                'type': 'denial',
                'details': d
            })
    print(json.dumps(result, indent=2))


def output_table(selinux, apparmor, denials, verbose, warn_only):
    """Output results in table format."""
    print("=" * 70)
    print("LINUX SECURITY MODULE STATUS")
    print("=" * 70)

    if selinux['available']:
        print(f"{'System':<20} {'SELinux':<50}")
        print("-" * 70)
        print(f"{'Mode':<20} {selinux['mode']:<50}")
        print(f"{'Policy':<20} {selinux['policy']:<50}")
        print(f"{'MLS':<20} {'enabled' if selinux['mls_enabled'] else 'disabled':<50}")
        if verbose and selinux['booleans']:
            print("-" * 70)
            print("Key Security Booleans:")
            for b in selinux['booleans']:
                print(f"  {b['name']:<35} {b['value']:<20}")
    elif apparmor['available']:
        print(f"{'System':<20} {'AppArmor':<50}")
        print("-" * 70)
        print(f"{'Status':<20} {'enabled' if apparmor['enabled'] else 'disabled':<50}")
        print(f"{'Profiles Loaded':<20} {apparmor['profiles']['total']:<50}")
        print(f"{'  Enforcing':<20} {apparmor['profiles']['enforce']:<50}")
        print(f"{'  Complain':<20} {apparmor['profiles']['complain']:<50}")
        if verbose:
            print(f"{'Confined Procs':<20} {apparmor['processes']['confined']:<50}")
            print(f"{'Unconfined Procs':<20} {apparmor['processes']['unconfined']:<50}")
    else:
        print("No Linux Security Module (SELinux/AppArmor) detected")

    print("=" * 70)

    if denials:
        print()
        print("RECENT DENIALS")
        print("=" * 70)
        for d in denials[:10]:
            if d['type'] == 'selinux':
                print(f"SELinux: {d.get('command', '?')} - {d.get('permission', '?')} ({d.get('class', '?')})")
            else:
                print(f"AppArmor: {d.get('profile', '?')} - {d.get('permission', '?')}")
        if len(denials) > 10:
            print(f"... and {len(denials) - 10} more")
        print("=" * 70)

    # Print issues
    all_issues = selinux.get('issues', []) + apparmor.get('issues', [])
    if all_issues or denials:
        print()
        print("ISSUES")
        print("-" * 70)
        for issue in all_issues:
            if warn_only and issue['severity'] == 'INFO':
                continue
            print(f"[{issue['severity']}] {issue['message']}")
        if denials:
            print(f"[WARNING] {len(denials)} policy denial(s) detected in logs")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor SELinux and AppArmor security policy status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check LSM status
  %(prog)s --verbose            # Include boolean and profile details
  %(prog)s --format json        # JSON output for monitoring tools
  %(prog)s --hours 1            # Check denials from last hour only
  %(prog)s --warn-only          # Only show warnings and errors

Security modules detected:
  - SELinux (RHEL, CentOS, Fedora)
  - AppArmor (Ubuntu, Debian, SUSE)

Exit codes:
  0 - Security module active, no warnings
  1 - Warnings found (permissive mode, denials, disabled)
  2 - Usage error or no security module available
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
        help='Show detailed information (booleans, profiles)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress info'
    )

    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        metavar='N',
        help='Look back N hours for denials (default: 24)'
    )

    parser.add_argument(
        '--limit',
        type=int,
        default=20,
        metavar='N',
        help='Maximum number of denials to show (default: 20)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.hours < 1:
        print("Error: --hours must be at least 1", file=sys.stderr)
        sys.exit(2)

    if args.limit < 1:
        print("Error: --limit must be at least 1", file=sys.stderr)
        sys.exit(2)

    # Check for LSM availability
    selinux_avail = check_selinux_available()
    apparmor_avail = check_apparmor_available()

    if not selinux_avail and not apparmor_avail:
        print("Error: Neither SELinux nor AppArmor detected on this system", file=sys.stderr)
        print("This system may not have mandatory access control enabled", file=sys.stderr)
        sys.exit(2)

    # Get status
    selinux = get_selinux_status() if selinux_avail else {'available': False, 'issues': []}
    apparmor = get_apparmor_status() if apparmor_avail else {'available': False, 'issues': []}

    # Get recent denials
    denials = get_recent_denials(hours=args.hours, limit=args.limit)

    # Output
    if args.format == 'json':
        output_json(selinux, apparmor, denials, args.verbose)
    elif args.format == 'table':
        output_table(selinux, apparmor, denials, args.verbose, args.warn_only)
    else:
        output_plain(selinux, apparmor, denials, args.verbose, args.warn_only)

    # Determine exit code
    all_issues = selinux.get('issues', []) + apparmor.get('issues', [])
    has_warning = (
        any(i['severity'] == 'WARNING' for i in all_issues) or
        len(denials) > 0
    )

    sys.exit(1 if has_warning else 0)


if __name__ == '__main__':
    main()
