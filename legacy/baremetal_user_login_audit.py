#!/usr/bin/env python3
"""
Audit user accounts and login history to identify dormant accounts.

Analyzes user accounts from /etc/passwd and login history from lastlog
to identify accounts that haven't logged in recently. Useful for security
compliance and identifying stale accounts that should be disabled.

Key features:
- Reports last login time for each user account
- Identifies accounts that have never logged in
- Detects dormant accounts exceeding configurable thresholds
- Supports filtering by UID range (system vs human users)
- Checks for accounts with no password expiration
- Identifies accounts with expired passwords

Use cases:
- Security compliance audits (SOC2, PCI-DSS, HIPAA)
- Identifying accounts to disable during offboarding reviews
- Detecting service accounts that may be abandoned
- Pre-audit preparation for access reviews

Exit codes:
    0 - No dormant or problematic accounts found
    1 - Dormant or suspicious accounts detected
    2 - Usage error or required tools not available
"""

import argparse
import subprocess
import sys
import json
import os
import pwd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

# spwd module may not be available on all systems
try:
    import spwd
    SPWD_AVAILABLE = True
except ImportError:
    SPWD_AVAILABLE = False


def run_command(cmd: List[str], timeout: int = 30) -> tuple:
    """Execute shell command and return result."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def get_lastlog_entries() -> Dict[str, Optional[datetime]]:
    """Parse lastlog output to get last login times per user."""
    lastlog_data = {}

    # Try to use lastlog command
    returncode, stdout, stderr = run_command(['lastlog'])

    if returncode != 0:
        return lastlog_data

    lines = stdout.strip().split('\n')
    if len(lines) < 2:
        return lastlog_data

    # Skip header line
    for line in lines[1:]:
        if not line.strip():
            continue

        # Parse lastlog output format:
        # Username         Port     From             Latest
        parts = line.split()
        if len(parts) < 1:
            continue

        username = parts[0]

        # Check if user has never logged in
        if '**Never logged in**' in line:
            lastlog_data[username] = None
            continue

        # Try to parse the date (last 4 or 5 fields typically form the date)
        # Format: "Mon Jan  1 12:00:00 +0000 2024" or similar
        try:
            # Find where the date starts (after "From" field or "Port" if no From)
            date_str = None
            if len(parts) >= 5:
                # Try to find date pattern in the line
                # Look for month abbreviation
                months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                          'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                for i, part in enumerate(parts):
                    if part in months and i + 3 < len(parts):
                        # Found month, try to construct date
                        # Format varies: "Mon Jan  1 12:00:00 2024"
                        date_parts = parts[i-1:i+4] if i > 0 else parts[i:i+4]
                        date_str = ' '.join(date_parts)
                        break

            if date_str:
                # Try multiple date formats
                for fmt in ['%a %b %d %H:%M:%S %Y',
                            '%a %b %d %H:%M:%S %z %Y',
                            '%b %d %H:%M:%S %Y']:
                    try:
                        lastlog_data[username] = datetime.strptime(
                            date_str.strip(), fmt)
                        break
                    except ValueError:
                        continue

            # If we couldn't parse the date, check if there's any login record
            if username not in lastlog_data:
                # User has logged in but we couldn't parse the date
                lastlog_data[username] = datetime.now()  # Mark as recently active

        except (ValueError, IndexError):
            continue

    return lastlog_data


def get_users(min_uid: int = 1000, max_uid: int = 65533,
              include_system: bool = False) -> List[Dict[str, Any]]:
    """Get user accounts from /etc/passwd."""
    users = []

    try:
        for pw in pwd.getpwall():
            # Filter by UID range unless including system accounts
            if not include_system:
                if pw.pw_uid < min_uid or pw.pw_uid > max_uid:
                    continue
            else:
                # Even with system accounts, skip truly special UIDs
                if pw.pw_uid > max_uid:
                    continue

            user_info = {
                'username': pw.pw_name,
                'uid': pw.pw_uid,
                'gid': pw.pw_gid,
                'gecos': pw.pw_gecos,
                'home': pw.pw_dir,
                'shell': pw.pw_shell,
                'is_system': pw.pw_uid < min_uid,
            }

            # Check if shell is a nologin shell
            nologin_shells = ['/sbin/nologin', '/usr/sbin/nologin',
                              '/bin/false', '/usr/bin/false']
            user_info['has_login_shell'] = pw.pw_shell not in nologin_shells

            users.append(user_info)

    except Exception as e:
        print(f"Error reading passwd: {e}", file=sys.stderr)
        return []

    return users


def get_shadow_info() -> Dict[str, Dict[str, Any]]:
    """Get password aging information from shadow file (requires root)."""
    shadow_info = {}

    # spwd module may not be available on all systems
    if not SPWD_AVAILABLE:
        return shadow_info

    try:
        for sp in spwd.getspall():
            info = {
                'has_password': sp.sp_pwdp not in ['*', '!', '!!', ''],
                'password_locked': sp.sp_pwdp.startswith('!') or sp.sp_pwdp.startswith('*'),
                'last_change': None,
                'max_days': sp.sp_max,
                'warn_days': sp.sp_warn,
                'inactive_days': sp.sp_inact,
                'expire_date': None,
            }

            # Convert last password change (days since epoch)
            if sp.sp_lstchg and sp.sp_lstchg > 0:
                info['last_change'] = datetime(1970, 1, 1) + timedelta(days=sp.sp_lstchg)

            # Convert expiration date (days since epoch)
            if sp.sp_expire and sp.sp_expire > 0:
                info['expire_date'] = datetime(1970, 1, 1) + timedelta(days=sp.sp_expire)

            shadow_info[sp.sp_nnam] = info

    except PermissionError:
        # Not running as root, shadow info unavailable
        pass
    except Exception:
        pass

    return shadow_info


def analyze_user(user: Dict[str, Any], lastlog: Dict[str, Optional[datetime]],
                 shadow: Dict[str, Dict[str, Any]], dormant_days: int) -> Dict[str, Any]:
    """Analyze a single user account for issues."""
    username = user['username']
    now = datetime.now()

    analysis = {
        **user,
        'last_login': None,
        'days_since_login': None,
        'never_logged_in': False,
        'is_dormant': False,
        'issues': [],
    }

    # Get last login info
    if username in lastlog:
        last_login = lastlog[username]
        if last_login is None:
            analysis['never_logged_in'] = True
            if user['has_login_shell']:
                analysis['issues'].append('Has login shell but never logged in')
        else:
            analysis['last_login'] = last_login.isoformat()
            days_since = (now - last_login).days
            analysis['days_since_login'] = days_since

            if days_since > dormant_days:
                analysis['is_dormant'] = True
                analysis['issues'].append(f'Dormant for {days_since} days')

    # Get shadow info if available
    if username in shadow:
        sh = shadow[username]
        analysis['password_locked'] = sh['password_locked']
        analysis['has_password'] = sh['has_password']

        if sh['expire_date']:
            analysis['account_expires'] = sh['expire_date'].isoformat()
            if sh['expire_date'] < now:
                analysis['issues'].append('Account expired')

        if sh['last_change']:
            analysis['password_last_changed'] = sh['last_change'].isoformat()

        # Check for accounts with no password aging
        if sh['max_days'] and sh['max_days'] > 99999:
            if not sh['password_locked'] and sh['has_password']:
                analysis['issues'].append('No password expiration set')

    return analysis


def output_plain(results: List[Dict], summary: Dict, warn_only: bool, verbose: bool):
    """Output results in plain text format."""
    if not warn_only:
        print("User Account Login Audit")
        print("=" * 60)
        print(f"Total accounts analyzed: {summary['total_users']}")
        print(f"Dormant accounts: {summary['dormant_count']}")
        print(f"Never logged in: {summary['never_logged_in']}")
        print(f"Accounts with issues: {summary['issues_count']}")
        print()

    # Filter if warn_only
    if warn_only:
        results = [r for r in results if r['issues']]

    if not results:
        if not warn_only:
            print("No issues detected.")
        return

    # Print results
    for user in sorted(results, key=lambda x: (not x['issues'], x['username'])):
        if warn_only and not user['issues']:
            continue

        status = "!" if user['issues'] else " "
        login_str = user.get('last_login', 'Never')
        if login_str and login_str != 'Never':
            login_str = login_str[:10]  # Just the date

        print(f"[{status}] {user['username']:<20} UID:{user['uid']:<6} "
              f"Last Login: {login_str}")

        if user['issues']:
            for issue in user['issues']:
                print(f"    - {issue}")

        if verbose:
            print(f"    Shell: {user['shell']}")
            print(f"    Home: {user['home']}")
            if user.get('gecos'):
                print(f"    GECOS: {user['gecos']}")

    print()


def output_json(results: List[Dict], summary: Dict, warn_only: bool):
    """Output results in JSON format."""
    if warn_only:
        results = [r for r in results if r['issues']]

    output = {
        'summary': summary,
        'users': results,
    }
    print(json.dumps(output, indent=2, default=str))


def output_table(results: List[Dict], summary: Dict, warn_only: bool, verbose: bool):
    """Output results in table format."""
    if warn_only:
        results = [r for r in results if r['issues']]

    print(f"{'Username':<20} {'UID':<8} {'Last Login':<12} {'Days':<8} {'Issues'}")
    print("-" * 80)

    for user in sorted(results, key=lambda x: (x['days_since_login'] or 99999, x['username']),
                       reverse=True):
        login_str = user.get('last_login', 'Never')
        if login_str and login_str != 'Never':
            login_str = login_str[:10]

        days = user.get('days_since_login', 'N/A')
        if days == 'N/A' or days is None:
            days = 'Never'

        issues = ', '.join(user['issues']) if user['issues'] else '-'
        if len(issues) > 30:
            issues = issues[:27] + '...'

        print(f"{user['username']:<20} {user['uid']:<8} {login_str:<12} "
              f"{str(days):<8} {issues}")

    print()
    print(f"Total: {summary['total_users']} | Dormant: {summary['dormant_count']} | "
          f"Never logged in: {summary['never_logged_in']} | With issues: {summary['issues_count']}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Audit user accounts and login history',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Audit human user accounts (UID >= 1000)
  %(prog)s --dormant-days 90         # Flag accounts inactive for 90+ days
  %(prog)s --include-system          # Include system accounts
  %(prog)s --format json             # JSON output for automation
  %(prog)s --warn-only               # Only show accounts with issues
  %(prog)s --min-uid 500             # Include UIDs starting from 500

Exit codes:
  0 - No dormant or problematic accounts
  1 - Issues detected (dormant accounts, never logged in, etc.)
  2 - Usage error or required tools unavailable
        """
    )

    parser.add_argument(
        '--dormant-days', '-d',
        type=int,
        default=90,
        metavar='DAYS',
        help='Days since login to consider account dormant (default: %(default)s)'
    )

    parser.add_argument(
        '--min-uid',
        type=int,
        default=1000,
        metavar='UID',
        help='Minimum UID to check (default: %(default)s)'
    )

    parser.add_argument(
        '--max-uid',
        type=int,
        default=65533,
        metavar='UID',
        help='Maximum UID to check (default: %(default)s)'
    )

    parser.add_argument(
        '--include-system', '-s',
        action='store_true',
        help='Include system accounts (UID < min-uid)'
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
        help='Show detailed user information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show accounts with issues'
    )

    args = parser.parse_args()

    # Check if lastlog is available
    returncode, _, _ = run_command(['which', 'lastlog'])
    if returncode != 0:
        print("Error: 'lastlog' command not found", file=sys.stderr)
        print("Install with: sudo apt-get install login", file=sys.stderr)
        sys.exit(2)

    # Get user accounts
    users = get_users(
        min_uid=args.min_uid,
        max_uid=args.max_uid,
        include_system=args.include_system
    )

    if not users:
        print("No user accounts found matching criteria", file=sys.stderr)
        sys.exit(0)

    # Get lastlog data
    lastlog = get_lastlog_entries()

    # Get shadow info (may be empty if not root)
    shadow = get_shadow_info()

    # Analyze each user
    results = []
    for user in users:
        analysis = analyze_user(user, lastlog, shadow, args.dormant_days)
        results.append(analysis)

    # Calculate summary
    summary = {
        'total_users': len(results),
        'dormant_count': sum(1 for r in results if r['is_dormant']),
        'never_logged_in': sum(1 for r in results if r['never_logged_in']),
        'issues_count': sum(1 for r in results if r['issues']),
        'dormant_threshold_days': args.dormant_days,
    }

    # Output results
    if args.format == 'json':
        output_json(results, summary, args.warn_only)
    elif args.format == 'table':
        output_table(results, summary, args.warn_only, args.verbose)
    else:
        output_plain(results, summary, args.warn_only, args.verbose)

    # Exit based on findings
    if summary['issues_count'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
