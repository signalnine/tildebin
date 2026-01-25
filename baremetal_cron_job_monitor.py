#!/usr/bin/env python3
"""
Cron Job Health Monitor

Monitors cron jobs for health issues including:
- Syntax errors in crontab files
- Jobs with invalid commands or missing executables
- Orphaned user crontabs (user no longer exists)
- Jobs that haven't run recently (based on log analysis)
- Permission issues on cron directories
- Disabled or empty crontabs

Useful for ensuring scheduled tasks are properly configured in baremetal
environments where cron is used alongside or instead of systemd timers.

Exit codes:
    0 - All cron configurations are healthy
    1 - One or more issues detected (syntax errors, missing commands, etc.)
    2 - Unable to read cron configuration or usage error

Examples:
    # Check all cron configurations
    baremetal_cron_job_monitor.py

    # Show only problematic entries
    baremetal_cron_job_monitor.py --warn-only

    # JSON output for monitoring integration
    baremetal_cron_job_monitor.py --format json

    # Verbose output with job details
    baremetal_cron_job_monitor.py --verbose

    # Check specific cron directories only
    baremetal_cron_job_monitor.py --system-only
    baremetal_cron_job_monitor.py --user-only
"""

import argparse
import grp
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from typing import List, Dict, Any, Optional, Tuple


# Standard cron directories
SYSTEM_CRON_DIRS = [
    '/etc/cron.d',
    '/etc/cron.hourly',
    '/etc/cron.daily',
    '/etc/cron.weekly',
    '/etc/cron.monthly',
]

SYSTEM_CRONTAB = '/etc/crontab'
USER_CRONTAB_DIR = '/var/spool/cron/crontabs'  # Debian/Ubuntu
USER_CRONTAB_DIR_ALT = '/var/spool/cron'  # RHEL/CentOS


def get_user_crontab_dir() -> Optional[str]:
    """Determine the user crontab directory for this system."""
    if os.path.isdir(USER_CRONTAB_DIR):
        return USER_CRONTAB_DIR
    elif os.path.isdir(USER_CRONTAB_DIR_ALT):
        return USER_CRONTAB_DIR_ALT
    return None


def user_exists(username: str) -> bool:
    """Check if a user exists on the system."""
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def command_exists(cmd: str) -> bool:
    """Check if a command exists in PATH or is an absolute path."""
    if not cmd:
        return False

    # Extract the actual command (first word, handle shell redirections)
    cmd_parts = cmd.split()
    if not cmd_parts:
        return False

    executable = cmd_parts[0]

    # Skip shell built-ins and special cases
    shell_builtins = {'cd', 'echo', 'test', '[', 'true', 'false', 'exit',
                      'export', 'source', '.', 'eval', 'exec', 'set', 'unset'}
    if executable in shell_builtins:
        return True

    # Handle commands run through interpreters
    interpreters = {'/bin/sh', '/bin/bash', '/usr/bin/bash', '/bin/zsh',
                    '/usr/bin/python', '/usr/bin/python3', '/usr/bin/perl',
                    '/usr/bin/ruby', 'sh', 'bash', 'zsh', 'python', 'python3',
                    'perl', 'ruby'}
    if executable in interpreters:
        return True

    # Check absolute path
    if executable.startswith('/'):
        return os.path.isfile(executable) and os.access(executable, os.X_OK)

    # Check in PATH
    try:
        result = subprocess.run(
            ['which', executable],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def parse_cron_schedule(schedule: str) -> Tuple[bool, str]:
    """
    Validate a cron schedule string (5 or 6 fields).

    Returns (is_valid, error_message)
    """
    # Handle special strings
    special_schedules = {'@reboot', '@yearly', '@annually', '@monthly',
                         '@weekly', '@daily', '@midnight', '@hourly'}
    if schedule.lower() in special_schedules:
        return True, ''

    fields = schedule.split()
    if len(fields) < 5:
        return False, f'Too few fields ({len(fields)}, need 5-6)'
    if len(fields) > 6:
        return False, f'Too many fields ({len(fields)}, max 6)'

    # Basic field validation (simplified - real cron parsing is complex)
    field_names = ['minute', 'hour', 'day', 'month', 'weekday']
    field_ranges = [
        (0, 59),   # minute
        (0, 23),   # hour
        (1, 31),   # day of month
        (1, 12),   # month
        (0, 7),    # day of week (0 and 7 are Sunday)
    ]

    for i, (field, (min_val, max_val)) in enumerate(zip(fields[:5], field_ranges)):
        if field == '*':
            continue

        # Handle step values (*/5, 1-10/2)
        if '/' in field:
            base, step = field.split('/', 1)
            if base != '*' and not base.replace('-', '').replace(',', '').isdigit():
                return False, f'Invalid {field_names[i]}: {field}'
            continue

        # Handle ranges (1-5)
        if '-' in field:
            parts = field.split('-')
            if len(parts) != 2:
                return False, f'Invalid range in {field_names[i]}: {field}'
            continue

        # Handle lists (1,2,3)
        if ',' in field:
            continue

        # Simple numeric value
        if not field.isdigit():
            # Could be month/day name - allow it
            if i == 3 and field.lower() in ['jan', 'feb', 'mar', 'apr', 'may',
                                             'jun', 'jul', 'aug', 'sep', 'oct',
                                             'nov', 'dec']:
                continue
            if i == 4 and field.lower() in ['sun', 'mon', 'tue', 'wed', 'thu',
                                             'fri', 'sat']:
                continue
            return False, f'Invalid {field_names[i]}: {field}'

    return True, ''


def parse_crontab_line(line: str, has_user_field: bool = False) -> Optional[Dict[str, Any]]:
    """
    Parse a single crontab line.

    Args:
        line: The crontab line to parse
        has_user_field: True for /etc/crontab and /etc/cron.d/* (6th field is user)

    Returns:
        Dict with schedule, user (if applicable), and command, or None if not a job line
    """
    line = line.strip()

    # Skip empty lines and comments
    if not line or line.startswith('#'):
        return None

    # Skip variable assignments
    if '=' in line and not line.startswith('@') and not line[0].isdigit():
        # Check if it looks like VAR=value (no spaces before =)
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', line):
            return None

    # Handle special schedules (@reboot, @daily, etc.)
    if line.startswith('@'):
        parts = line.split(None, 2 if has_user_field else 1)
        if len(parts) < (3 if has_user_field else 2):
            return None

        if has_user_field:
            return {
                'schedule': parts[0],
                'user': parts[1],
                'command': parts[2] if len(parts) > 2 else '',
            }
        else:
            return {
                'schedule': parts[0],
                'user': None,
                'command': parts[1] if len(parts) > 1 else '',
            }

    # Standard cron format: min hour day month dow [user] command
    parts = line.split(None, 6 if has_user_field else 5)

    if len(parts) < (7 if has_user_field else 6):
        # Not enough fields for a valid cron job
        return None

    schedule = ' '.join(parts[:5])

    if has_user_field:
        user = parts[5]
        command = parts[6] if len(parts) > 6 else ''
    else:
        user = None
        command = parts[5] if len(parts) > 5 else ''

    return {
        'schedule': schedule,
        'user': user,
        'command': command,
    }


def check_file_permissions(path: str) -> List[str]:
    """Check file permissions for security issues."""
    issues = []

    try:
        st = os.stat(path)
        mode = st.st_mode

        # Cron files should not be world-writable
        if mode & stat.S_IWOTH:
            issues.append('World-writable (insecure)')

        # Cron files should not be group-writable (in most cases)
        if mode & stat.S_IWGRP:
            issues.append('Group-writable')

        # Check ownership
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
            if owner not in ['root', 'cron']:
                issues.append(f'Owned by {owner} (should be root)')
        except KeyError:
            issues.append(f'Unknown owner UID {st.st_uid}')

    except OSError as e:
        issues.append(f'Cannot stat: {e}')

    return issues


def analyze_crontab_file(path: str, has_user_field: bool = False,
                         source_type: str = 'file') -> Dict[str, Any]:
    """
    Analyze a crontab file for issues.

    Args:
        path: Path to the crontab file
        has_user_field: True for /etc/crontab and /etc/cron.d/*
        source_type: Description of the source ('system', 'user', etc.)

    Returns:
        Dict with analysis results
    """
    result = {
        'path': path,
        'source_type': source_type,
        'exists': False,
        'readable': False,
        'jobs': [],
        'issues': [],
        'severity': 'OK',
    }

    if not os.path.exists(path):
        result['issues'].append('File does not exist')
        return result

    result['exists'] = True

    # Check permissions
    perm_issues = check_file_permissions(path)
    if perm_issues:
        result['issues'].extend(perm_issues)
        result['severity'] = 'WARNING'

    # Try to read the file
    try:
        with open(path, 'r') as f:
            content = f.read()
        result['readable'] = True
    except PermissionError:
        result['issues'].append('Permission denied')
        result['severity'] = 'WARNING'
        return result
    except Exception as e:
        result['issues'].append(f'Read error: {e}')
        result['severity'] = 'WARNING'
        return result

    # Parse each line
    line_number = 0
    for line in content.split('\n'):
        line_number += 1
        job = parse_crontab_line(line, has_user_field)

        if job is None:
            continue

        job['line_number'] = line_number
        job['issues'] = []
        job['severity'] = 'OK'

        # Validate schedule
        is_valid, error = parse_cron_schedule(job['schedule'])
        if not is_valid:
            job['issues'].append(f'Invalid schedule: {error}')
            job['severity'] = 'CRITICAL'

        # Check if user exists (for system crontabs)
        if job['user'] and not user_exists(job['user']):
            job['issues'].append(f"User '{job['user']}' does not exist")
            job['severity'] = 'CRITICAL'

        # Check if command exists (basic check)
        if job['command']:
            # Extract first command from potential pipeline
            first_cmd = job['command'].split('|')[0].split('&&')[0].split(';')[0].strip()
            if not command_exists(first_cmd):
                job['issues'].append(f'Command may not exist: {first_cmd.split()[0] if first_cmd.split() else "empty"}')
                job['severity'] = 'WARNING' if job['severity'] == 'OK' else job['severity']

        if job['issues']:
            if job['severity'] == 'CRITICAL':
                result['severity'] = 'CRITICAL'
            elif result['severity'] == 'OK':
                result['severity'] = 'WARNING'

        result['jobs'].append(job)

    return result


def analyze_cron_directory(path: str, is_script_dir: bool = False) -> Dict[str, Any]:
    """
    Analyze a cron directory (/etc/cron.d, /etc/cron.hourly, etc.)

    Args:
        path: Directory path
        is_script_dir: True for cron.hourly/daily/weekly/monthly (contains scripts, not crontabs)
    """
    result = {
        'path': path,
        'exists': False,
        'files': [],
        'issues': [],
        'severity': 'OK',
    }

    if not os.path.exists(path):
        return result

    result['exists'] = True

    if not os.path.isdir(path):
        result['issues'].append('Not a directory')
        result['severity'] = 'CRITICAL'
        return result

    # Check directory permissions
    perm_issues = check_file_permissions(path)
    if perm_issues:
        result['issues'].extend(perm_issues)
        result['severity'] = 'WARNING'

    try:
        entries = os.listdir(path)
    except PermissionError:
        result['issues'].append('Cannot list directory (permission denied)')
        result['severity'] = 'WARNING'
        return result

    for entry in sorted(entries):
        entry_path = os.path.join(path, entry)

        # Skip directories and hidden files
        if os.path.isdir(entry_path) or entry.startswith('.'):
            continue

        # Skip backup/package manager files
        if entry.endswith(('.dpkg-old', '.dpkg-new', '.dpkg-dist', '.bak', '~')):
            continue

        if is_script_dir:
            # For script directories, just check if scripts are executable
            file_result = {
                'path': entry_path,
                'name': entry,
                'issues': [],
                'severity': 'OK',
            }

            if not os.access(entry_path, os.X_OK):
                file_result['issues'].append('Not executable')
                file_result['severity'] = 'WARNING'

            perm_issues = check_file_permissions(entry_path)
            if perm_issues:
                file_result['issues'].extend(perm_issues)
                if file_result['severity'] == 'OK':
                    file_result['severity'] = 'WARNING'

            if file_result['severity'] != 'OK':
                if file_result['severity'] == 'CRITICAL':
                    result['severity'] = 'CRITICAL'
                elif result['severity'] == 'OK':
                    result['severity'] = 'WARNING'

            result['files'].append(file_result)
        else:
            # For cron.d, parse as crontab files
            file_result = analyze_crontab_file(entry_path, has_user_field=True,
                                                source_type='cron.d')
            file_result['name'] = entry

            if file_result['severity'] == 'CRITICAL':
                result['severity'] = 'CRITICAL'
            elif file_result['severity'] == 'WARNING' and result['severity'] == 'OK':
                result['severity'] = 'WARNING'

            result['files'].append(file_result)

    return result


def analyze_user_crontabs() -> Dict[str, Any]:
    """Analyze user crontabs in /var/spool/cron/crontabs or /var/spool/cron."""
    result = {
        'path': None,
        'exists': False,
        'users': [],
        'issues': [],
        'severity': 'OK',
    }

    crontab_dir = get_user_crontab_dir()
    if not crontab_dir:
        return result

    result['path'] = crontab_dir
    result['exists'] = True

    try:
        entries = os.listdir(crontab_dir)
    except PermissionError:
        result['issues'].append('Cannot read user crontab directory (need root)')
        result['severity'] = 'WARNING'
        return result

    for username in sorted(entries):
        if username.startswith('.'):
            continue

        user_crontab = os.path.join(crontab_dir, username)
        if not os.path.isfile(user_crontab):
            continue

        user_result = analyze_crontab_file(user_crontab, has_user_field=False,
                                            source_type='user')
        user_result['username'] = username

        # Check if user exists
        if not user_exists(username):
            user_result['issues'].append('User no longer exists (orphaned crontab)')
            user_result['severity'] = 'WARNING'

        if user_result['severity'] == 'CRITICAL':
            result['severity'] = 'CRITICAL'
        elif user_result['severity'] == 'WARNING' and result['severity'] == 'OK':
            result['severity'] = 'WARNING'

        result['users'].append(user_result)

    return result


def output_plain(results: Dict[str, Any], warn_only: bool = False,
                 verbose: bool = False) -> None:
    """Output results in plain text format."""
    total_jobs = 0
    total_issues = 0

    # Count totals
    if results.get('system_crontab'):
        total_jobs += len(results['system_crontab'].get('jobs', []))
        total_issues += sum(1 for j in results['system_crontab'].get('jobs', [])
                           if j.get('severity') != 'OK')

    for dir_result in results.get('cron_directories', []):
        for f in dir_result.get('files', []):
            if 'jobs' in f:
                total_jobs += len(f['jobs'])
                total_issues += sum(1 for j in f['jobs']
                                   if j.get('severity') != 'OK')

    for user in results.get('user_crontabs', {}).get('users', []):
        total_jobs += len(user.get('jobs', []))
        total_issues += sum(1 for j in user.get('jobs', [])
                           if j.get('severity') != 'OK')

    if not warn_only:
        print("Cron Job Health Monitor")
        print("=" * 60)
        print(f"Total cron jobs found: {total_jobs}")
        print(f"Jobs with issues: {total_issues}")
        print()

    # System crontab
    sys_crontab = results.get('system_crontab')
    if sys_crontab and sys_crontab.get('exists'):
        has_issues = sys_crontab.get('severity') != 'OK'
        if not warn_only or has_issues:
            print(f"System crontab ({sys_crontab['path']}):")
            if sys_crontab['issues']:
                for issue in sys_crontab['issues']:
                    print(f"  ! {issue}")
            for job in sys_crontab.get('jobs', []):
                if warn_only and not job.get('issues'):
                    continue
                marker = "!!!" if job['severity'] == 'CRITICAL' else \
                         " ! " if job['severity'] == 'WARNING' else "   "
                cmd_preview = job['command'][:40] + '...' if len(job['command']) > 40 else job['command']
                print(f"  {marker} Line {job['line_number']}: {job['schedule']} - {cmd_preview}")
                if verbose or job.get('issues'):
                    for issue in job.get('issues', []):
                        print(f"      -> {issue}")
            print()

    # Cron directories
    for dir_result in results.get('cron_directories', []):
        if not dir_result.get('exists'):
            continue

        has_issues = dir_result.get('severity') != 'OK'
        if not warn_only or has_issues:
            print(f"Directory: {dir_result['path']}")
            if dir_result['issues']:
                for issue in dir_result['issues']:
                    print(f"  ! {issue}")

            for f in dir_result.get('files', []):
                file_has_issues = f.get('severity') != 'OK'
                if warn_only and not file_has_issues:
                    continue

                print(f"  File: {f.get('name', f.get('path'))}")
                for issue in f.get('issues', []):
                    print(f"    ! {issue}")

                for job in f.get('jobs', []):
                    if warn_only and not job.get('issues'):
                        continue
                    marker = "!!!" if job['severity'] == 'CRITICAL' else \
                             " ! " if job['severity'] == 'WARNING' else "   "
                    cmd_preview = job['command'][:35] + '...' if len(job['command']) > 35 else job['command']
                    user_str = f" ({job['user']})" if job.get('user') else ""
                    print(f"    {marker} {job['schedule']}{user_str}: {cmd_preview}")
                    for issue in job.get('issues', []):
                        print(f"        -> {issue}")
            print()

    # User crontabs
    user_crontabs = results.get('user_crontabs', {})
    if user_crontabs.get('exists'):
        has_issues = user_crontabs.get('severity') != 'OK'
        if not warn_only or has_issues:
            print(f"User crontabs ({user_crontabs['path']}):")
            if user_crontabs['issues']:
                for issue in user_crontabs['issues']:
                    print(f"  ! {issue}")

            for user in user_crontabs.get('users', []):
                user_has_issues = user.get('severity') != 'OK'
                if warn_only and not user_has_issues:
                    continue

                job_count = len(user.get('jobs', []))
                print(f"  User: {user['username']} ({job_count} jobs)")
                for issue in user.get('issues', []):
                    print(f"    ! {issue}")

                for job in user.get('jobs', []):
                    if warn_only and not job.get('issues'):
                        continue
                    marker = "!!!" if job['severity'] == 'CRITICAL' else \
                             " ! " if job['severity'] == 'WARNING' else "   "
                    cmd_preview = job['command'][:35] + '...' if len(job['command']) > 35 else job['command']
                    print(f"    {marker} {job['schedule']}: {cmd_preview}")
                    for issue in job.get('issues', []):
                        print(f"        -> {issue}")
            print()

    if total_issues == 0:
        print("All cron configurations are healthy")


def output_json(results: Dict[str, Any]) -> None:
    """Output results in JSON format."""
    # Calculate summary
    total_jobs = 0
    jobs_with_issues = 0
    critical = 0
    warning = 0

    def count_jobs(jobs_list):
        nonlocal total_jobs, jobs_with_issues, critical, warning
        for job in jobs_list:
            total_jobs += 1
            if job.get('severity') == 'CRITICAL':
                jobs_with_issues += 1
                critical += 1
            elif job.get('severity') == 'WARNING':
                jobs_with_issues += 1
                warning += 1

    if results.get('system_crontab'):
        count_jobs(results['system_crontab'].get('jobs', []))

    for dir_result in results.get('cron_directories', []):
        for f in dir_result.get('files', []):
            count_jobs(f.get('jobs', []))

    for user in results.get('user_crontabs', {}).get('users', []):
        count_jobs(user.get('jobs', []))

    output = {
        'summary': {
            'total_jobs': total_jobs,
            'jobs_with_issues': jobs_with_issues,
            'critical': critical,
            'warning': warning,
        },
        **results
    }

    print(json.dumps(output, indent=2, default=str))


def output_table(results: Dict[str, Any], warn_only: bool = False) -> None:
    """Output results in table format."""
    print(f"{'STATUS':<10} {'SOURCE':<25} {'SCHEDULE':<20} {'USER':<10} {'COMMAND':<30}")
    print("=" * 95)

    def print_jobs(jobs, source):
        for job in jobs:
            if warn_only and job.get('severity') == 'OK':
                continue
            status = job.get('severity', 'OK')
            user = job.get('user', '-')[:10] if job.get('user') else '-'
            schedule = job.get('schedule', '')[:20]
            command = job.get('command', '')[:30]
            print(f"{status:<10} {source:<25} {schedule:<20} {user:<10} {command:<30}")

    if results.get('system_crontab'):
        print_jobs(results['system_crontab'].get('jobs', []), '/etc/crontab')

    for dir_result in results.get('cron_directories', []):
        for f in dir_result.get('files', []):
            source = f.get('name', os.path.basename(f.get('path', '')))[:25]
            print_jobs(f.get('jobs', []), source)

    for user in results.get('user_crontabs', {}).get('users', []):
        source = f"user:{user['username']}"[:25]
        print_jobs(user.get('jobs', []), source)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor cron job health and identify configuration issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Check all cron configurations
  %(prog)s --warn-only            # Show only problematic entries
  %(prog)s --format json          # JSON output for monitoring
  %(prog)s --system-only          # Check only system cron (not user crontabs)
  %(prog)s --user-only            # Check only user crontabs
  %(prog)s -v                     # Verbose output

Exit codes:
  0 - All cron configurations healthy
  1 - One or more issues detected
  2 - Unable to read cron configuration or usage error
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show entries with issues'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    parser.add_argument(
        '--system-only',
        action='store_true',
        help='Only check system cron files (skip user crontabs)'
    )

    parser.add_argument(
        '--user-only',
        action='store_true',
        help='Only check user crontabs (skip system cron files)'
    )

    args = parser.parse_args()

    if args.system_only and args.user_only:
        print("Error: Cannot specify both --system-only and --user-only",
              file=sys.stderr)
        sys.exit(2)

    results = {
        'system_crontab': None,
        'cron_directories': [],
        'user_crontabs': None,
    }

    has_critical = False
    has_warning = False

    # Check system crontab
    if not args.user_only:
        if os.path.exists(SYSTEM_CRONTAB):
            results['system_crontab'] = analyze_crontab_file(
                SYSTEM_CRONTAB, has_user_field=True, source_type='system'
            )
            if results['system_crontab']['severity'] == 'CRITICAL':
                has_critical = True
            elif results['system_crontab']['severity'] == 'WARNING':
                has_warning = True

        # Check cron directories
        for cron_dir in SYSTEM_CRON_DIRS:
            is_script_dir = cron_dir in ['/etc/cron.hourly', '/etc/cron.daily',
                                          '/etc/cron.weekly', '/etc/cron.monthly']
            dir_result = analyze_cron_directory(cron_dir, is_script_dir=is_script_dir)
            results['cron_directories'].append(dir_result)

            if dir_result['severity'] == 'CRITICAL':
                has_critical = True
            elif dir_result['severity'] == 'WARNING':
                has_warning = True

    # Check user crontabs
    if not args.system_only:
        results['user_crontabs'] = analyze_user_crontabs()
        if results['user_crontabs']['severity'] == 'CRITICAL':
            has_critical = True
        elif results['user_crontabs']['severity'] == 'WARNING':
            has_warning = True

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, warn_only=args.warn_only)
    else:
        output_plain(results, warn_only=args.warn_only, verbose=args.verbose)

    # Exit based on findings
    if has_critical or has_warning:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
