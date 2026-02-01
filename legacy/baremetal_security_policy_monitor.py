#!/usr/bin/env python3
"""
Monitor Linux Security Module (LSM) status for baremetal systems.

Checks SELinux and AppArmor security policy status, detecting:
- LSM disabled or permissive modes (security risk)
- Policy violations and denials in audit logs
- Missing or corrupted policy files
- Configuration drift from expected state

This is critical for enterprise baremetal environments where security
compliance requires mandatory access control (MAC) to be active and enforcing.

Exit codes:
    0 - Security policy is enforcing and healthy
    1 - Security issues detected (disabled, permissive, denials)
    2 - Usage error or unable to determine LSM status
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime


def run_command(cmd, check=False):
    """Execute a shell command and return output"""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True,
            timeout=30
        )
        if check and result.returncode != 0:
            return None, result.stderr
        return result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}"
    except subprocess.TimeoutExpired:
        return None, "Command timed out"
    except Exception as e:
        return None, str(e)


def detect_active_lsm():
    """Detect which LSM is active on the system"""
    lsms = []

    # Check /sys/kernel/security/lsm for active LSMs
    try:
        with open('/sys/kernel/security/lsm', 'r') as f:
            lsm_list = f.read().strip()
            lsms = [lsm.strip() for lsm in lsm_list.split(',') if lsm.strip()]
    except (FileNotFoundError, PermissionError):
        pass

    # Check for SELinux
    selinux_active = os.path.exists('/sys/fs/selinux') or os.path.exists('/selinux')

    # Check for AppArmor
    apparmor_active = os.path.exists('/sys/kernel/security/apparmor')

    return {
        'lsm_list': lsms,
        'selinux_present': selinux_active or 'selinux' in lsms,
        'apparmor_present': apparmor_active or 'apparmor' in lsms,
    }


def get_selinux_status():
    """Get detailed SELinux status"""
    status = {
        'available': False,
        'enabled': False,
        'mode': 'unknown',
        'policy': 'unknown',
        'mls_enabled': False,
        'issues': [],
        'denials_recent': 0,
    }

    # Check if SELinux filesystem exists
    if not os.path.exists('/sys/fs/selinux') and not os.path.exists('/selinux'):
        status['issues'].append('SELinux filesystem not mounted')
        return status

    status['available'] = True

    # Try getenforce command
    output, err = run_command(['getenforce'])
    if output:
        mode = output.lower()
        status['mode'] = mode
        status['enabled'] = mode in ['enforcing', 'permissive']
        if mode == 'permissive':
            status['issues'].append('SELinux is in permissive mode (not enforcing)')
        elif mode == 'disabled':
            status['issues'].append('SELinux is disabled')
    else:
        # Try reading from /sys/fs/selinux/enforce
        try:
            with open('/sys/fs/selinux/enforce', 'r') as f:
                enforce_val = f.read().strip()
                if enforce_val == '1':
                    status['mode'] = 'enforcing'
                    status['enabled'] = True
                elif enforce_val == '0':
                    status['mode'] = 'permissive'
                    status['enabled'] = True
                    status['issues'].append('SELinux is in permissive mode')
        except (FileNotFoundError, PermissionError):
            pass

    # Get policy type from sestatus if available
    output, err = run_command(['sestatus'])
    if output:
        for line in output.split('\n'):
            if 'loaded policy name' in line.lower():
                status['policy'] = line.split(':')[-1].strip()
            if 'mls' in line.lower() and 'enabled' in line.lower():
                status['mls_enabled'] = True

    # Check for recent denials in audit log (last 100 lines)
    output, err = run_command(['ausearch', '-m', 'AVC', '-ts', 'recent'])
    if output and 'denied' in output.lower():
        denial_count = output.lower().count('denied')
        status['denials_recent'] = denial_count
        if denial_count > 0:
            status['issues'].append(f'{denial_count} AVC denial(s) in recent audit log')

    # Alternative: check dmesg for denials if ausearch not available
    if status['denials_recent'] == 0:
        output, err = run_command(['dmesg'])
        if output:
            denial_lines = [l for l in output.split('\n') if 'avc:' in l.lower() and 'denied' in l.lower()]
            if denial_lines:
                status['denials_recent'] = len(denial_lines[-10:])  # Last 10 denials
                if status['denials_recent'] > 0:
                    status['issues'].append(f'{status["denials_recent"]} AVC denial(s) in dmesg')

    return status


def get_apparmor_status():
    """Get detailed AppArmor status"""
    status = {
        'available': False,
        'enabled': False,
        'mode': 'unknown',
        'profiles_enforcing': 0,
        'profiles_complain': 0,
        'profiles_unconfined': 0,
        'issues': [],
        'denials_recent': 0,
    }

    # Check if AppArmor is available
    if not os.path.exists('/sys/kernel/security/apparmor'):
        return status

    status['available'] = True

    # Check AppArmor status
    output, err = run_command(['aa-status', '--json'])
    if output:
        try:
            aa_data = json.loads(output)
            status['enabled'] = True

            # Count profiles by mode
            profiles = aa_data.get('profiles', {})
            for profile, mode in profiles.items():
                if mode == 'enforce':
                    status['profiles_enforcing'] += 1
                elif mode == 'complain':
                    status['profiles_complain'] += 1
                    status['issues'].append(f'Profile in complain mode: {profile}')
                elif mode == 'unconfined':
                    status['profiles_unconfined'] += 1

            if status['profiles_enforcing'] > 0:
                status['mode'] = 'enforcing'
            elif status['profiles_complain'] > 0:
                status['mode'] = 'complain'
            else:
                status['mode'] = 'disabled'
                status['issues'].append('No enforcing AppArmor profiles')

        except json.JSONDecodeError:
            # Fall back to text parsing
            pass

    # Try text-based aa-status if JSON failed
    if not status['enabled']:
        output, err = run_command(['aa-status'])
        if output:
            status['enabled'] = True
            for line in output.split('\n'):
                if 'profiles are in enforce mode' in line:
                    try:
                        status['profiles_enforcing'] = int(line.split()[0])
                    except (ValueError, IndexError):
                        pass
                elif 'profiles are in complain mode' in line:
                    try:
                        status['profiles_complain'] = int(line.split()[0])
                    except (ValueError, IndexError):
                        pass
                elif 'processes are unconfined' in line:
                    try:
                        status['profiles_unconfined'] = int(line.split()[0])
                    except (ValueError, IndexError):
                        pass

            if status['profiles_enforcing'] > 0:
                status['mode'] = 'enforcing'
            elif status['profiles_complain'] > 0:
                status['mode'] = 'complain'
                status['issues'].append('AppArmor profiles in complain mode only')

    # Check for recent denials in syslog/journal
    output, err = run_command(['journalctl', '-k', '-g', 'apparmor.*DENIED', '-n', '100', '--no-pager'])
    if output:
        denial_count = output.count('DENIED')
        if denial_count > 0:
            status['denials_recent'] = denial_count
            status['issues'].append(f'{denial_count} AppArmor denial(s) in recent journal')

    return status


def collect_data(expected_mode=None):
    """Collect all LSM security data"""
    lsm_info = detect_active_lsm()
    selinux = get_selinux_status()
    apparmor = get_apparmor_status()

    # Determine primary LSM
    primary_lsm = 'none'
    if selinux['enabled']:
        primary_lsm = 'selinux'
    elif apparmor['enabled']:
        primary_lsm = 'apparmor'

    # Determine overall status
    overall_status = 'healthy'
    all_issues = []

    if primary_lsm == 'none':
        overall_status = 'critical'
        all_issues.append('No MAC security policy is active')
    else:
        if primary_lsm == 'selinux':
            all_issues.extend(selinux['issues'])
            if selinux['mode'] == 'permissive':
                overall_status = 'warning'
            elif selinux['mode'] == 'disabled':
                overall_status = 'critical'
            elif selinux['denials_recent'] > 0:
                overall_status = 'warning'
        elif primary_lsm == 'apparmor':
            all_issues.extend(apparmor['issues'])
            if apparmor['mode'] == 'complain':
                overall_status = 'warning'
            elif apparmor['profiles_enforcing'] == 0:
                overall_status = 'critical'
            elif apparmor['denials_recent'] > 0:
                overall_status = 'warning'

    # Check against expected mode
    if expected_mode:
        current_mode = selinux['mode'] if primary_lsm == 'selinux' else apparmor['mode']
        if current_mode != expected_mode:
            all_issues.append(f'Mode mismatch: expected {expected_mode}, got {current_mode}')
            overall_status = 'warning' if overall_status == 'healthy' else overall_status

    data = {
        'timestamp': datetime.now().isoformat(),
        'primary_lsm': primary_lsm,
        'lsm_list': lsm_info['lsm_list'],
        'overall_status': overall_status,
        'issues': all_issues,
        'selinux': selinux,
        'apparmor': apparmor,
        'summary': {
            'total_issues': len(all_issues),
            'selinux_available': selinux['available'],
            'selinux_enforcing': selinux['mode'] == 'enforcing',
            'apparmor_available': apparmor['available'],
            'apparmor_enforcing': apparmor['mode'] == 'enforcing',
        }
    }

    return data


def output_plain(data, verbose=False, warn_only=False):
    """Output in plain text format"""
    if data['overall_status'] == 'healthy' and warn_only:
        return

    # Header
    status_display = {
        'healthy': 'HEALTHY',
        'warning': 'WARNING',
        'critical': 'CRITICAL'
    }

    print(f"Security Policy Status: {status_display.get(data['overall_status'], 'UNKNOWN')}")
    print(f"Primary LSM: {data['primary_lsm'].upper() if data['primary_lsm'] != 'none' else 'NONE'}")

    if data['lsm_list']:
        print(f"Active LSMs: {', '.join(data['lsm_list'])}")
    print()

    # SELinux details
    se = data['selinux']
    if se['available']:
        print("SELinux:")
        print(f"  Mode: {se['mode']}")
        if se['policy'] != 'unknown':
            print(f"  Policy: {se['policy']}")
        if se['denials_recent'] > 0:
            print(f"  Recent denials: {se['denials_recent']}")
        if verbose and se['mls_enabled']:
            print(f"  MLS: enabled")
        print()

    # AppArmor details
    aa = data['apparmor']
    if aa['available']:
        print("AppArmor:")
        print(f"  Mode: {aa['mode']}")
        print(f"  Profiles enforcing: {aa['profiles_enforcing']}")
        if aa['profiles_complain'] > 0:
            print(f"  Profiles complain: {aa['profiles_complain']}")
        if aa['denials_recent'] > 0:
            print(f"  Recent denials: {aa['denials_recent']}")
        print()

    # Issues
    if data['issues']:
        print("Issues detected:")
        for issue in data['issues']:
            print(f"  - {issue}")


def output_json(data):
    """Output in JSON format"""
    print(json.dumps(data, indent=2))


def output_table(data, warn_only=False):
    """Output in table format"""
    if data['overall_status'] == 'healthy' and warn_only:
        return

    print(f"{'Component':<15} {'Status':<12} {'Mode':<12} {'Issues':<10}")
    print("=" * 49)

    # SELinux row
    if data['selinux']['available']:
        se = data['selinux']
        status = 'Active' if se['enabled'] else 'Inactive'
        issue_count = len(se['issues'])
        print(f"{'SELinux':<15} {status:<12} {se['mode']:<12} {issue_count:<10}")

    # AppArmor row
    if data['apparmor']['available']:
        aa = data['apparmor']
        status = 'Active' if aa['enabled'] else 'Inactive'
        issue_count = len(aa['issues'])
        print(f"{'AppArmor':<15} {status:<12} {aa['mode']:<12} {issue_count:<10}")

    # No LSM row
    if not data['selinux']['available'] and not data['apparmor']['available']:
        print(f"{'None':<15} {'N/A':<12} {'N/A':<12} {'1':<10}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Monitor Linux Security Module (LSM) status for baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported LSMs:
  SELinux  - Security-Enhanced Linux (RHEL, CentOS, Fedora)
  AppArmor - Application Armor (Ubuntu, Debian, SUSE)

Status Levels:
  HEALTHY  - Security policy is enforcing, no recent denials
  WARNING  - Policy is permissive/complain mode, or recent denials
  CRITICAL - No MAC policy active, or policy is disabled

Examples:
  %(prog)s                           # Check security policy status
  %(prog)s --format json             # JSON output for automation
  %(prog)s --expected enforcing      # Alert if not in enforcing mode
  %(prog)s -w                        # Only output if issues found

Exit codes:
  0 - Security policy is healthy and enforcing
  1 - Security issues detected (disabled, permissive, denials)
  2 - Error determining LSM status
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
        help='Show detailed information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues are found'
    )

    parser.add_argument(
        '--expected',
        metavar='MODE',
        choices=['enforcing', 'permissive', 'complain', 'disabled'],
        help='Expected security mode (alert if different)'
    )

    parser.add_argument(
        '--require-lsm',
        action='store_true',
        help='Exit with error if no LSM is active'
    )

    args = parser.parse_args()

    # Collect data
    try:
        data = collect_data(expected_mode=args.expected)
    except Exception as e:
        print(f"Error collecting LSM status: {e}", file=sys.stderr)
        sys.exit(2)

    # Output
    if args.format == 'json':
        output_json(data)
    elif args.format == 'table':
        output_table(data, warn_only=args.warn_only)
    else:
        output_plain(data, verbose=args.verbose, warn_only=args.warn_only)

    # Determine exit code
    if args.require_lsm and data['primary_lsm'] == 'none':
        sys.exit(1)

    if data['overall_status'] == 'healthy':
        sys.exit(0)
    elif data['overall_status'] in ['warning', 'critical']:
        sys.exit(1)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
