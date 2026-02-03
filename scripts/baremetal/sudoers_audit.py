#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, audit, sudo, sudoers, privilege]
#   privilege: root
#   brief: Audit sudoers configuration for security issues

"""
Audit sudoers configuration for security issues and best practices.

Checks both /etc/sudoers and files in /etc/sudoers.d/ directory for:
- NOPASSWD rules (passwordless sudo access)
- ALL permissions (overly broad command access)
- Missing security defaults (env_reset, secure_path)
- Insecure timestamp_timeout settings
- SETENV usage (environment override risk)

Returns exit code 1 if security issues are found.
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Security-relevant patterns
NOPASSWD_PATTERN = re.compile(r'\bNOPASSWD\s*:', re.IGNORECASE)
# Match NOPASSWD: ALL specifically (critical) - more specific pattern
NOPASSWD_ALL_PATTERN = re.compile(r'NOPASSWD\s*:\s*ALL\b', re.IGNORECASE)
SETENV_PATTERN = re.compile(r'\bSETENV\b', re.IGNORECASE)
ENV_RESET_PATTERN = re.compile(r'Defaults\s+env_reset', re.IGNORECASE)
SECURE_PATH_PATTERN = re.compile(r'Defaults\s+secure_path', re.IGNORECASE)
TIMESTAMP_TIMEOUT_PATTERN = re.compile(r'Defaults\s+timestamp_timeout\s*=\s*(-?\d+)', re.IGNORECASE)
NO_REQUIRETTY_PATTERN = re.compile(r'Defaults\s+!requiretty', re.IGNORECASE)


def parse_sudoers_content(content: str, filepath: str) -> tuple[list[dict[str, Any]], dict[str, bool]]:
    """Parse sudoers content and identify security issues."""
    issues = []
    lines = content.split('\n')

    # Only check active (non-comment) lines for defaults
    active_content = '\n'.join(
        line for line in lines
        if line.strip() and not line.strip().startswith('#')
    )
    has_env_reset = bool(ENV_RESET_PATTERN.search(active_content))
    has_secure_path = bool(SECURE_PATH_PATTERN.search(active_content))
    has_no_requiretty = bool(NO_REQUIRETTY_PATTERN.search(active_content))

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        # Check for NOPASSWD
        if NOPASSWD_PATTERN.search(line):
            # NOPASSWD: ALL is critical, specific commands is just warning
            severity = 'critical' if NOPASSWD_ALL_PATTERN.search(line) else 'warning'
            issues.append({
                'type': 'nopasswd',
                'severity': severity,
                'file': filepath,
                'line': lineno,
                'message': 'NOPASSWD allows passwordless sudo execution',
            })

        # Check for SETENV
        if SETENV_PATTERN.search(line):
            issues.append({
                'type': 'setenv',
                'severity': 'info',
                'file': filepath,
                'line': lineno,
                'message': 'SETENV allows user to override environment variables',
            })

        # Check timestamp_timeout
        timeout_match = TIMESTAMP_TIMEOUT_PATTERN.search(line)
        if timeout_match:
            timeout = int(timeout_match.group(1))
            if timeout < 0:
                issues.append({
                    'type': 'timestamp_timeout',
                    'severity': 'warning',
                    'file': filepath,
                    'line': lineno,
                    'message': f'Negative timestamp_timeout ({timeout}) means credentials never expire',
                })

    defaults = {
        'has_env_reset': has_env_reset,
        'has_secure_path': has_secure_path,
        'has_no_requiretty': has_no_requiretty,
    }

    return issues, defaults


def check_defaults(defaults: dict[str, bool], filepath: str) -> list[dict[str, Any]]:
    """Check for missing security-relevant Defaults."""
    issues = []

    if not defaults['has_env_reset']:
        issues.append({
            'type': 'missing_default',
            'severity': 'warning',
            'file': filepath,
            'message': 'Missing "Defaults env_reset" - environment not sanitized',
        })

    if not defaults['has_secure_path']:
        issues.append({
            'type': 'missing_default',
            'severity': 'info',
            'file': filepath,
            'message': 'Missing "Defaults secure_path" - PATH not restricted',
        })

    if defaults['has_no_requiretty']:
        issues.append({
            'type': 'insecure_default',
            'severity': 'info',
            'file': filepath,
            'message': '"Defaults !requiretty" allows sudo without TTY',
        })

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit sudoers configuration for security issues"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true",
                        help="Only show warnings and critical issues")
    opts = parser.parse_args(args)

    # Check for main sudoers file
    main_sudoers = '/etc/sudoers'
    if not context.file_exists(main_sudoers):
        output.error("No sudoers file found at /etc/sudoers")

        output.render(opts.format, "Audit sudoers configuration for security issues")
        return 2

    all_issues = []
    files_checked = []
    combined_defaults = {
        'has_env_reset': False,
        'has_secure_path': False,
        'has_no_requiretty': False,
    }

    # Check main sudoers file
    try:
        content = context.read_file(main_sudoers)
        files_checked.append(main_sudoers)

        issues, defaults = parse_sudoers_content(content, main_sudoers)
        all_issues.extend(issues)

        for key in combined_defaults:
            combined_defaults[key] = combined_defaults[key] or defaults[key]

    except PermissionError:
        output.error(f"Permission denied reading {main_sudoers}")

        output.render(opts.format, "Audit sudoers configuration for security issues")
        return 2
    except Exception as e:
        output.error(f"Error reading {main_sudoers}: {e}")

        output.render(opts.format, "Audit sudoers configuration for security issues")
        return 2

    # Check sudoers.d files
    sudoers_d = '/etc/sudoers.d'
    if context.file_exists(sudoers_d):
        try:
            for filepath in context.glob('*', root=sudoers_d):
                if filepath.endswith('~') or filepath.startswith('.'):
                    continue
                if filepath.lower().endswith('readme'):
                    continue

                try:
                    content = context.read_file(filepath)
                    files_checked.append(filepath)

                    issues, defaults = parse_sudoers_content(content, filepath)
                    all_issues.extend(issues)

                    for key in combined_defaults:
                        combined_defaults[key] = combined_defaults[key] or defaults[key]
                except (PermissionError, FileNotFoundError):
                    continue
        except Exception:
            pass

    # Check for missing defaults (only on main sudoers)
    defaults_issues = check_defaults(combined_defaults, main_sudoers)
    all_issues.extend(defaults_issues)

    # Count by severity
    critical_count = sum(1 for i in all_issues if i['severity'] == 'critical')
    warning_count = sum(1 for i in all_issues if i['severity'] == 'warning')
    info_count = sum(1 for i in all_issues if i['severity'] == 'info')

    # Filter if warn-only
    if opts.warn_only:
        all_issues = [i for i in all_issues if i['severity'] in ('critical', 'warning')]

    output.emit({
        'files_checked': files_checked,
        'issues': all_issues,
        'critical_count': critical_count,
        'warning_count': warning_count,
        'info_count': info_count,
        'defaults': combined_defaults,
    })

    # Set summary
    if critical_count > 0:
        output.set_summary(f"{critical_count} critical, {warning_count} warnings")
    elif warning_count > 0:
        output.set_summary(f"{warning_count} warnings found")
    else:
        output.set_summary("Sudoers configuration passes security checks")

    # Return 1 if critical or warning issues
    if critical_count > 0 or warning_count > 0:

        output.render(opts.format, "Audit sudoers configuration for security issues")
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
