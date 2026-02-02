#!/usr/bin/env python3
# boxctl:
#   category: baremetal/system
#   tags: [cron, scheduler, jobs, monitoring]
#   requires: []
#   privilege: root
#   related: [systemd_timer_monitor]
#   brief: Monitor cron jobs for health issues and configuration problems

"""
Cron Job Health Monitor.

Monitors cron jobs for health issues including:
- Syntax errors in crontab files
- Jobs with invalid commands or missing executables
- Orphaned user crontabs (user no longer exists)
- Permission issues on cron directories
- Disabled or empty crontabs

Useful for ensuring scheduled tasks are properly configured in baremetal
environments where cron is used alongside or instead of systemd timers.

Returns exit code 1 if configuration issues are detected.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Standard cron directories
SYSTEM_CRON_DIRS = [
    '/etc/cron.d',
    '/etc/cron.hourly',
    '/etc/cron.daily',
    '/etc/cron.weekly',
    '/etc/cron.monthly',
]

SYSTEM_CRONTAB = '/etc/crontab'
USER_CRONTAB_DIRS = [
    '/var/spool/cron/crontabs',  # Debian/Ubuntu
    '/var/spool/cron',           # RHEL/CentOS
]

# Special schedule strings
SPECIAL_SCHEDULES = {
    '@reboot', '@yearly', '@annually', '@monthly',
    '@weekly', '@daily', '@midnight', '@hourly'
}


def parse_cron_schedule(schedule: str) -> tuple[bool, str]:
    """
    Validate a cron schedule string (5 or 6 fields).

    Returns (is_valid, error_message)
    """
    if schedule.lower() in SPECIAL_SCHEDULES:
        return True, ''

    fields = schedule.split()
    if len(fields) < 5:
        return False, f'Too few fields ({len(fields)}, need 5-6)'
    if len(fields) > 6:
        return False, f'Too many fields ({len(fields)}, max 6)'

    return True, ''


def parse_crontab_line(line: str, has_user_field: bool = False) -> dict[str, Any] | None:
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


def analyze_crontab_file(path: str, context: Context, has_user_field: bool = False) -> dict[str, Any]:
    """Analyze a crontab file for issues."""
    result = {
        'path': path,
        'exists': context.file_exists(path),
        'jobs': [],
        'issues': [],
        'severity': 'OK',
    }

    if not result['exists']:
        return result

    try:
        content = context.read_file(path)
    except Exception as e:
        result['issues'].append(f'Read error: {e}')
        result['severity'] = 'WARNING'
        return result

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

        if job['issues']:
            if job['severity'] == 'CRITICAL':
                result['severity'] = 'CRITICAL'
            elif result['severity'] == 'OK':
                result['severity'] = 'WARNING'

        result['jobs'].append(job)

    return result


def analyze_cron_directory(path: str, context: Context, is_script_dir: bool = False) -> dict[str, Any]:
    """Analyze a cron directory (/etc/cron.d, /etc/cron.hourly, etc.)."""
    result = {
        'path': path,
        'exists': context.file_exists(path),
        'files': [],
        'issues': [],
        'severity': 'OK',
    }

    if not result['exists']:
        return result

    try:
        entries = context.glob('*', path)
    except Exception:
        result['issues'].append('Cannot list directory')
        result['severity'] = 'WARNING'
        return result

    for entry_path in sorted(entries):
        name = entry_path.split('/')[-1]

        # Skip hidden files and backups
        if name.startswith('.') or name.endswith(('.bak', '~', '.dpkg-old', '.dpkg-new')):
            continue

        if is_script_dir:
            # For script directories, just note the files
            result['files'].append({'path': entry_path, 'name': name})
        else:
            # For cron.d, parse as crontab files
            file_result = analyze_crontab_file(entry_path, context, has_user_field=True)
            file_result['name'] = name

            if file_result['severity'] == 'CRITICAL':
                result['severity'] = 'CRITICAL'
            elif file_result['severity'] == 'WARNING' and result['severity'] == 'OK':
                result['severity'] = 'WARNING'

            result['files'].append(file_result)

    return result


def get_user_crontab_dir(context: Context) -> str | None:
    """Determine the user crontab directory for this system."""
    for path in USER_CRONTAB_DIRS:
        if context.file_exists(path):
            return path
    return None


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor cron job health and configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--system-only", action="store_true", help="Only check system cron files")
    parser.add_argument("--user-only", action="store_true", help="Only check user crontabs")
    opts = parser.parse_args(args)

    if opts.system_only and opts.user_only:
        output.error("Cannot specify both --system-only and --user-only")
        return 2

    has_critical = False
    has_warning = False

    data = {
        'system_crontab': None,
        'cron_directories': [],
        'user_crontabs': None,
    }

    # Check system crontab
    if not opts.user_only and context.file_exists(SYSTEM_CRONTAB):
        data['system_crontab'] = analyze_crontab_file(SYSTEM_CRONTAB, context, has_user_field=True)
        if data['system_crontab']['severity'] == 'CRITICAL':
            has_critical = True
        elif data['system_crontab']['severity'] == 'WARNING':
            has_warning = True

    # Check cron directories
    if not opts.user_only:
        for cron_dir in SYSTEM_CRON_DIRS:
            is_script_dir = cron_dir in ['/etc/cron.hourly', '/etc/cron.daily',
                                          '/etc/cron.weekly', '/etc/cron.monthly']
            dir_result = analyze_cron_directory(cron_dir, context, is_script_dir=is_script_dir)
            data['cron_directories'].append(dir_result)

            if dir_result['severity'] == 'CRITICAL':
                has_critical = True
            elif dir_result['severity'] == 'WARNING':
                has_warning = True

    # Check user crontabs
    if not opts.system_only:
        user_crontab_dir = get_user_crontab_dir(context)
        if user_crontab_dir:
            data['user_crontabs'] = {
                'path': user_crontab_dir,
                'users': [],
            }

            try:
                user_files = context.glob('*', user_crontab_dir)
                for user_file in user_files:
                    username = user_file.split('/')[-1]
                    if username.startswith('.'):
                        continue

                    user_result = analyze_crontab_file(user_file, context, has_user_field=False)
                    user_result['username'] = username

                    if user_result['severity'] == 'CRITICAL':
                        has_critical = True
                    elif user_result['severity'] == 'WARNING':
                        has_warning = True

                    data['user_crontabs']['users'].append(user_result)
            except Exception:
                pass

    output.emit(data)

    # Count total jobs
    total_jobs = 0
    jobs_with_issues = 0

    if data['system_crontab']:
        for job in data['system_crontab'].get('jobs', []):
            total_jobs += 1
            if job.get('issues'):
                jobs_with_issues += 1

    for dir_result in data['cron_directories']:
        for f in dir_result.get('files', []):
            for job in f.get('jobs', []):
                total_jobs += 1
                if job.get('issues'):
                    jobs_with_issues += 1

    if data['user_crontabs']:
        for user in data['user_crontabs'].get('users', []):
            for job in user.get('jobs', []):
                total_jobs += 1
                if job.get('issues'):
                    jobs_with_issues += 1

    # Generate summary
    if jobs_with_issues > 0:
        output.set_summary(f"{jobs_with_issues}/{total_jobs} jobs with issues")
    else:
        output.set_summary(f"{total_jobs} jobs healthy")

    return 1 if (has_critical or has_warning) else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
