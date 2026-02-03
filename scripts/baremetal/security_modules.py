#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, selinux, apparmor, mac, compliance]
#   requires: []
#   privilege: user
#   related: [smt_status]
#   brief: Monitor SELinux and AppArmor security policy status

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
policy violations.
"""

import argparse
import os
import re
from datetime import datetime, timedelta
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def check_selinux_available(context: Context) -> bool:
    """Check if SELinux is available on the system."""
    result = context.run(['which', 'getenforce'], check=False)
    if result.returncode == 0:
        return True
    return os.path.exists('/sys/fs/selinux')


def check_apparmor_available(context: Context) -> bool:
    """Check if AppArmor is available on the system."""
    result = context.run(['which', 'aa-status'], check=False)
    if result.returncode == 0:
        return True
    return os.path.exists('/sys/module/apparmor')


def get_selinux_status(context: Context) -> dict[str, Any]:
    """Get SELinux status and configuration."""
    status = {
        'available': False,
        'mode': 'unknown',
        'policy': 'unknown',
        'mls_enabled': False,
        'booleans': [],
        'issues': []
    }

    result = context.run(['getenforce'], check=False)
    if result.returncode != 0:
        return status

    status['available'] = True
    status['mode'] = result.stdout.strip().lower()

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

    # Get policy type
    if os.path.exists('/etc/selinux/config'):
        try:
            with open('/etc/selinux/config', 'r') as f:
                for line in f:
                    if line.startswith('SELINUXTYPE='):
                        status['policy'] = line.split('=')[1].strip()
                        break
        except (IOError, PermissionError):
            pass

    # Check sestatus
    result = context.run(['sestatus'], check=False)
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            if 'Policy MLS status:' in line:
                status['mls_enabled'] = 'enabled' in line.lower()
            elif 'Loaded policy name:' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    status['policy'] = parts[1].strip()

    # Get important security booleans
    result = context.run(['getsebool', '-a'], check=False)
    if result.returncode == 0:
        important_bools = [
            'httpd_can_network_connect',
            'allow_execstack',
            'allow_execmem',
            'allow_execheap',
        ]
        for line in result.stdout.split('\n'):
            for bool_name in important_bools:
                if line.startswith(bool_name):
                    parts = line.split('-->')
                    if len(parts) == 2:
                        value = parts[1].strip()
                        status['booleans'].append({
                            'name': bool_name,
                            'value': value
                        })
                        if bool_name.startswith('allow_exec') and value == 'on':
                            status['issues'].append({
                                'severity': 'WARNING',
                                'type': 'dangerous_boolean',
                                'message': f"SELinux boolean '{bool_name}' is ON"
                            })

    return status


def get_apparmor_status(context: Context) -> dict[str, Any]:
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

    if os.path.exists('/sys/module/apparmor'):
        status['available'] = True

    # Try JSON output first
    result = context.run(['aa-status', '--json'], check=False)
    if result.returncode == 0:
        try:
            import json
            data = json.loads(result.stdout)
            status['enabled'] = True

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
        except (json.JSONDecodeError, ImportError):
            pass

    # Fallback to text parsing
    if not status['enabled']:
        result = context.run(['aa-status'], check=False)
        if result.returncode == 0 or 'profiles are loaded' in result.stdout:
            status['enabled'] = True
            for line in result.stdout.split('\n'):
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
            'message': f"{status['profiles']['complain']} profiles in complain mode"
        })

    return status


def get_recent_denials(context: Context, hours: int = 24, limit: int = 20) -> list[dict]:
    """Get recent SELinux/AppArmor denials from audit log."""
    denials = []

    # Try audit log
    audit_log = '/var/log/audit/audit.log'
    if os.path.exists(audit_log):
        result = context.run(['tail', '-n', '1000', audit_log], check=False)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'avc:  denied' in line or 'AVC' in line:
                    denial = parse_selinux_denial(line)
                    if denial:
                        denials.append(denial)
                elif 'apparmor="DENIED"' in line:
                    denial = parse_apparmor_denial(line)
                    if denial:
                        denials.append(denial)

    # Also check dmesg
    result = context.run(['dmesg', '--time-format=iso'], check=False)
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            if 'avc:  denied' in line:
                denial = parse_selinux_denial(line)
                if denial:
                    denials.append(denial)
            elif 'apparmor="DENIED"' in line:
                denial = parse_apparmor_denial(line)
                if denial:
                    denials.append(denial)

    # Deduplicate
    seen = set()
    unique = []
    for d in denials:
        key = (d.get('type'), d.get('source'), d.get('target'), d.get('permission'))
        if key not in seen:
            seen.add(key)
            unique.append(d)

    return unique[:limit]


def parse_selinux_denial(line: str) -> dict | None:
    """Parse a SELinux AVC denial message."""
    denial = {'type': 'selinux', 'raw': line[:200]}

    perm_match = re.search(r'\{ ([^}]+) \}', line)
    if perm_match:
        denial['permission'] = perm_match.group(1)

    scontext_match = re.search(r'scontext=(\S+)', line)
    if scontext_match:
        denial['source'] = scontext_match.group(1)

    tcontext_match = re.search(r'tcontext=(\S+)', line)
    if tcontext_match:
        denial['target'] = tcontext_match.group(1)

    class_match = re.search(r'tclass=(\S+)', line)
    if class_match:
        denial['class'] = class_match.group(1)

    comm_match = re.search(r'comm="([^"]+)"', line)
    if comm_match:
        denial['command'] = comm_match.group(1)

    return denial if 'permission' in denial else None


def parse_apparmor_denial(line: str) -> dict | None:
    """Parse an AppArmor denial message."""
    denial = {'type': 'apparmor', 'raw': line[:200]}

    profile_match = re.search(r'profile="([^"]+)"', line)
    if profile_match:
        denial['profile'] = profile_match.group(1)

    op_match = re.search(r'operation="([^"]+)"', line)
    if op_match:
        denial['permission'] = op_match.group(1)

    name_match = re.search(r'name="([^"]+)"', line)
    if name_match:
        denial['target'] = name_match.group(1)

    comm_match = re.search(r'comm="([^"]+)"', line)
    if comm_match:
        denial['command'] = comm_match.group(1)

    return denial if 'profile' in denial or 'permission' in denial else None


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = warnings found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor SELinux and AppArmor security policy status"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed information (booleans, profiles)")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--hours", type=int, default=24, metavar="N",
                        help="Look back N hours for denials (default: 24)")
    parser.add_argument("--limit", type=int, default=20, metavar="N",
                        help="Maximum number of denials to show (default: 20)")
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.hours < 1:
        output.error("--hours must be at least 1")

        output.render(opts.format, "Monitor SELinux and AppArmor security policy status")
        return 2

    if opts.limit < 1:
        output.error("--limit must be at least 1")

        output.render(opts.format, "Monitor SELinux and AppArmor security policy status")
        return 2

    # Check for LSM availability
    selinux_avail = check_selinux_available(context)
    apparmor_avail = check_apparmor_available(context)

    if not selinux_avail and not apparmor_avail:
        output.error("Neither SELinux nor AppArmor detected on this system")

        output.render(opts.format, "Monitor SELinux and AppArmor security policy status")
        return 2

    # Get status
    selinux = get_selinux_status(context) if selinux_avail else {'available': False, 'issues': []}
    apparmor = get_apparmor_status(context) if apparmor_avail else {'available': False, 'issues': []}

    # Get recent denials
    denials = get_recent_denials(context, hours=opts.hours, limit=opts.limit)

    # Build output
    result = {
        'selinux_available': selinux['available'],
        'apparmor_available': apparmor['available'],
        'denial_count': len(denials),
        'issues': selinux.get('issues', []) + apparmor.get('issues', []),
    }

    if selinux['available']:
        result['selinux'] = {
            'mode': selinux['mode'],
            'policy': selinux['policy'],
            'mls_enabled': selinux['mls_enabled'],
        }
        if opts.verbose:
            result['selinux']['booleans'] = selinux['booleans']

    if apparmor['available']:
        result['apparmor'] = {
            'enabled': apparmor['enabled'],
            'profiles': apparmor['profiles'],
        }
        if opts.verbose:
            result['apparmor']['processes'] = apparmor['processes']

    if denials:
        result['denials'] = denials
        for d in denials:
            result['issues'].append({
                'severity': 'WARNING',
                'type': 'denial',
                'message': f"{d['type']}: {d.get('command', 'unknown')} - {d.get('permission', '?')}"
            })

    output.emit(result)

    # Set summary
    all_issues = result['issues']
    has_warning = any(i['severity'] == 'WARNING' for i in all_issues) or len(denials) > 0

    if selinux['available']:
        output.set_summary(f"SELinux: {selinux['mode']}, {len(denials)} denials")
    elif apparmor['available']:
        status = 'enabled' if apparmor['enabled'] else 'disabled'
        output.set_summary(f"AppArmor: {status}, {len(denials)} denials")

    output.render(opts.format, "Monitor SELinux and AppArmor security policy status")

    return 1 if has_warning else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
