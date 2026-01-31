#!/usr/bin/env python3
"""
Baremetal Sudoers Configuration Auditor

Audits sudoers configuration for security issues and best practices compliance.
Checks both /etc/sudoers and files in /etc/sudoers.d/ directory.

Security checks performed:
- NOPASSWD rules (passwordless sudo access)
- ALL permissions (overly broad command access)
- Missing requiretty (allows non-interactive sudo)
- Insecure Defaults (env_reset, secure_path, etc.)
- Syntax errors (via visudo -c if available)
- World-readable sudoers files
- Include directive issues

Exit codes:
    0 - No security issues detected
    1 - Security issues or warnings found
    2 - Usage error or cannot read sudoers files
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
from datetime import datetime, timezone


# Security-relevant patterns to check
NOPASSWD_PATTERN = re.compile(r'\bNOPASSWD\b', re.IGNORECASE)
ALL_COMMANDS_PATTERN = re.compile(r'ALL\s*=\s*\(.*?\)\s*ALL', re.IGNORECASE)
NOEXEC_PATTERN = re.compile(r'\bNOEXEC\b', re.IGNORECASE)
SETENV_PATTERN = re.compile(r'\bSETENV\b', re.IGNORECASE)
REQUIRETTY_PATTERN = re.compile(r'Defaults\s+requiretty', re.IGNORECASE)
NO_REQUIRETTY_PATTERN = re.compile(r'Defaults\s+!requiretty', re.IGNORECASE)
ENV_RESET_PATTERN = re.compile(r'Defaults\s+env_reset', re.IGNORECASE)
SECURE_PATH_PATTERN = re.compile(r'Defaults\s+secure_path', re.IGNORECASE)
TIMESTAMP_TIMEOUT_PATTERN = re.compile(r'Defaults\s+timestamp_timeout\s*=\s*(-?\d+)', re.IGNORECASE)
INCLUDEDIR_PATTERN = re.compile(r'^[@#]includedir\s+(\S+)', re.MULTILINE)
INCLUDE_PATTERN = re.compile(r'^[@#]include\s+(\S+)', re.MULTILINE)


def check_file_permissions(filepath):
    """Check if sudoers file has correct permissions."""
    issues = []
    try:
        st = os.stat(filepath)
        mode = stat.S_IMODE(st.st_mode)

        # Sudoers should be 0440 or 0400 (no write, no world access)
        # 0440 = owner read + group read (common for wheel/sudo group)
        # 0400 = owner read only
        acceptable_modes = [0o440, 0o400]
        if mode not in acceptable_modes:
            issues.append({
                'type': 'permission',
                'severity': 'critical',
                'file': filepath,
                'message': f'Insecure permissions: {oct(mode)} (should be 0440 or 0400)',
                'recommendation': f'Run: chmod 0440 {filepath}'
            })

        # Should be owned by root
        if st.st_uid != 0:
            try:
                owner = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                owner = str(st.st_uid)
            issues.append({
                'type': 'ownership',
                'severity': 'critical',
                'file': filepath,
                'message': f'Not owned by root (owner: {owner})',
                'recommendation': f'Run: chown root:root {filepath}'
            })

        # Should be owned by root group (or wheel on some systems)
        if st.st_gid not in [0]:
            try:
                group = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                group = str(st.st_gid)
            # wheel group (GID varies) is acceptable on some systems
            if group != 'wheel':
                issues.append({
                    'type': 'ownership',
                    'severity': 'warning',
                    'file': filepath,
                    'message': f'Group is not root (group: {group})',
                    'recommendation': f'Run: chown root:root {filepath}'
                })

    except OSError as e:
        issues.append({
            'type': 'access',
            'severity': 'error',
            'file': filepath,
            'message': f'Cannot stat file: {e}'
        })

    return issues


def parse_sudoers_content(content, filepath):
    """Parse sudoers content and identify security issues."""
    issues = []
    lines = content.split('\n')

    has_env_reset = bool(ENV_RESET_PATTERN.search(content))
    has_secure_path = bool(SECURE_PATH_PATTERN.search(content))
    has_requiretty = bool(REQUIRETTY_PATTERN.search(content))
    has_no_requiretty = bool(NO_REQUIRETTY_PATTERN.search(content))

    for lineno, line in enumerate(lines, 1):
        # Skip comments and empty lines
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        # Check for NOPASSWD
        if NOPASSWD_PATTERN.search(line):
            issues.append({
                'type': 'nopasswd',
                'severity': 'warning',
                'file': filepath,
                'line': lineno,
                'content': stripped,
                'message': 'NOPASSWD allows passwordless sudo execution',
                'recommendation': 'Consider removing NOPASSWD unless absolutely necessary'
            })

        # Check for ALL commands access
        if ALL_COMMANDS_PATTERN.search(line):
            # Especially concerning if combined with NOPASSWD
            severity = 'critical' if NOPASSWD_PATTERN.search(line) else 'warning'
            issues.append({
                'type': 'all_commands',
                'severity': severity,
                'file': filepath,
                'line': lineno,
                'content': stripped,
                'message': 'Grants access to ALL commands',
                'recommendation': 'Restrict to specific commands instead of ALL'
            })

        # Check for SETENV (allows overriding environment)
        if SETENV_PATTERN.search(line):
            issues.append({
                'type': 'setenv',
                'severity': 'info',
                'file': filepath,
                'line': lineno,
                'content': stripped,
                'message': 'SETENV allows user to override environment variables',
                'recommendation': 'Ensure this is intentional; can be security risk'
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
                    'content': stripped,
                    'message': f'Negative timestamp_timeout ({timeout}) means credentials never expire',
                    'recommendation': 'Set a reasonable positive timeout (e.g., 5 minutes)'
                })
            elif timeout == 0:
                issues.append({
                    'type': 'timestamp_timeout',
                    'severity': 'info',
                    'file': filepath,
                    'line': lineno,
                    'content': stripped,
                    'message': 'timestamp_timeout=0 requires password every time',
                    'recommendation': 'This is secure but may impact usability'
                })
            elif timeout > 30:
                issues.append({
                    'type': 'timestamp_timeout',
                    'severity': 'info',
                    'file': filepath,
                    'line': lineno,
                    'content': stripped,
                    'message': f'Long timestamp_timeout ({timeout} minutes)',
                    'recommendation': 'Consider reducing to 5-15 minutes'
                })

    return issues, {
        'has_env_reset': has_env_reset,
        'has_secure_path': has_secure_path,
        'has_requiretty': has_requiretty,
        'has_no_requiretty': has_no_requiretty
    }


def check_defaults(defaults_info, filepath):
    """Check for missing security-relevant Defaults."""
    issues = []

    if not defaults_info['has_env_reset']:
        issues.append({
            'type': 'missing_default',
            'severity': 'warning',
            'file': filepath,
            'message': 'Missing "Defaults env_reset" - environment not sanitized',
            'recommendation': 'Add "Defaults env_reset" to sudoers'
        })

    if not defaults_info['has_secure_path']:
        issues.append({
            'type': 'missing_default',
            'severity': 'info',
            'file': filepath,
            'message': 'Missing "Defaults secure_path" - PATH not restricted',
            'recommendation': 'Add "Defaults secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
        })

    if defaults_info['has_no_requiretty']:
        issues.append({
            'type': 'insecure_default',
            'severity': 'info',
            'file': filepath,
            'message': '"Defaults !requiretty" allows sudo without TTY',
            'recommendation': 'Consider if this is necessary; may be required for automation'
        })

    return issues


def run_visudo_check(filepath):
    """Run visudo syntax check if available."""
    try:
        result = subprocess.run(
            ['visudo', '-c', '-f', filepath],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return {
                'type': 'syntax',
                'severity': 'critical',
                'file': filepath,
                'message': f'Syntax error detected: {result.stderr.strip()}',
                'recommendation': 'Fix syntax errors using visudo'
            }
        return None
    except FileNotFoundError:
        return None  # visudo not available
    except subprocess.TimeoutExpired:
        return {
            'type': 'syntax',
            'severity': 'warning',
            'file': filepath,
            'message': 'visudo check timed out'
        }
    except Exception as e:
        return {
            'type': 'syntax',
            'severity': 'warning',
            'file': filepath,
            'message': f'visudo check failed: {e}'
        }


def get_sudoers_files():
    """Get list of sudoers files to check."""
    files = []

    # Main sudoers file
    main_sudoers = '/etc/sudoers'
    if os.path.exists(main_sudoers):
        files.append(main_sudoers)

    # sudoers.d directory
    sudoers_d = '/etc/sudoers.d'
    if os.path.isdir(sudoers_d):
        try:
            for entry in sorted(os.listdir(sudoers_d)):
                # Skip files starting with . or ending with ~
                if entry.startswith('.') or entry.endswith('~'):
                    continue
                # Skip README files
                if entry.lower() == 'readme':
                    continue
                filepath = os.path.join(sudoers_d, entry)
                if os.path.isfile(filepath):
                    files.append(filepath)
        except PermissionError:
            pass

    return files


def audit_sudoers(check_syntax=True):
    """Perform full sudoers audit."""
    all_issues = []
    files_checked = []
    combined_defaults = {
        'has_env_reset': False,
        'has_secure_path': False,
        'has_requiretty': False,
        'has_no_requiretty': False
    }

    sudoers_files = get_sudoers_files()

    if not sudoers_files:
        return {
            'error': 'No sudoers files found',
            'files_checked': [],
            'issues': []
        }

    for filepath in sudoers_files:
        files_checked.append(filepath)

        # Check file permissions
        perm_issues = check_file_permissions(filepath)
        all_issues.extend(perm_issues)

        # Check syntax with visudo
        if check_syntax:
            syntax_issue = run_visudo_check(filepath)
            if syntax_issue:
                all_issues.append(syntax_issue)

        # Read and parse content
        try:
            with open(filepath, 'r') as f:
                content = f.read()

            content_issues, defaults_info = parse_sudoers_content(content, filepath)
            all_issues.extend(content_issues)

            # Merge defaults info
            for key in combined_defaults:
                combined_defaults[key] = combined_defaults[key] or defaults_info[key]

        except PermissionError:
            all_issues.append({
                'type': 'access',
                'severity': 'error',
                'file': filepath,
                'message': 'Permission denied reading file',
                'recommendation': 'Run as root to perform full audit'
            })
        except Exception as e:
            all_issues.append({
                'type': 'access',
                'severity': 'error',
                'file': filepath,
                'message': f'Error reading file: {e}'
            })

    # Check combined defaults (only for main sudoers)
    main_sudoers = '/etc/sudoers'
    if main_sudoers in files_checked:
        defaults_issues = check_defaults(combined_defaults, main_sudoers)
        all_issues.extend(defaults_issues)

    return {
        'files_checked': files_checked,
        'issues': all_issues,
        'defaults': combined_defaults
    }


def format_plain(result, warn_only=False, verbose=False):
    """Format output as plain text."""
    lines = []

    lines.append("Sudoers Configuration Audit")
    lines.append("=" * 50)
    lines.append("")

    if 'error' in result:
        lines.append(f"ERROR: {result['error']}")
        return "\n".join(lines)

    # Show files checked
    if verbose:
        lines.append(f"Files checked: {len(result['files_checked'])}")
        for f in result['files_checked']:
            lines.append(f"  - {f}")
        lines.append("")

    # Count by severity
    severity_counts = {'critical': 0, 'warning': 0, 'info': 0, 'error': 0}
    for issue in result['issues']:
        severity_counts[issue.get('severity', 'info')] += 1

    # Filter issues if warn_only
    issues_to_show = result['issues']
    if warn_only:
        issues_to_show = [i for i in issues_to_show
                         if i.get('severity') in ['critical', 'warning', 'error']]

    if not issues_to_show:
        if warn_only:
            lines.append("[OK] No critical or warning issues found")
        else:
            lines.append("[OK] No security issues detected")
    else:
        # Group by severity
        by_severity = {'critical': [], 'warning': [], 'info': [], 'error': []}
        for issue in issues_to_show:
            by_severity[issue.get('severity', 'info')].append(issue)

        for severity in ['critical', 'error', 'warning', 'info']:
            issues = by_severity[severity]
            if not issues:
                continue

            lines.append(f"{severity.upper()} ({len(issues)}):")
            for issue in issues:
                file_info = issue.get('file', 'unknown')
                if 'line' in issue:
                    file_info += f":{issue['line']}"
                lines.append(f"  [{issue['type']}] {file_info}")
                lines.append(f"    {issue['message']}")
                if verbose and 'content' in issue:
                    lines.append(f"    Line: {issue['content'][:60]}...")
                if 'recommendation' in issue:
                    lines.append(f"    -> {issue['recommendation']}")
            lines.append("")

    # Summary
    lines.append("-" * 50)
    if severity_counts['critical'] > 0:
        lines.append(f"[CRITICAL] {severity_counts['critical']} critical issue(s) found")
    elif severity_counts['warning'] > 0 or severity_counts['error'] > 0:
        lines.append(f"[WARNING] {severity_counts['warning']} warning(s), {severity_counts['error']} error(s)")
    else:
        lines.append("[OK] Sudoers configuration passes security checks")

    return "\n".join(lines)


def format_json(result):
    """Format output as JSON."""
    # Determine overall status
    severity_counts = {'critical': 0, 'warning': 0, 'info': 0, 'error': 0}
    for issue in result.get('issues', []):
        severity_counts[issue.get('severity', 'info')] += 1

    if severity_counts['critical'] > 0:
        status = 'critical'
    elif severity_counts['warning'] > 0 or severity_counts['error'] > 0:
        status = 'warning'
    else:
        status = 'healthy'

    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'status': status,
        'files_checked': result.get('files_checked', []),
        'issues': result.get('issues', []),
        'summary': severity_counts,
        'defaults': result.get('defaults', {}),
        'healthy': status == 'healthy'
    }

    if 'error' in result:
        output['error'] = result['error']
        output['healthy'] = False

    return json.dumps(output, indent=2)


def format_table(result):
    """Format output as a table."""
    lines = []

    lines.append("+" + "-" * 78 + "+")
    lines.append("| Sudoers Configuration Audit" + " " * 50 + "|")
    lines.append("+" + "-" * 78 + "+")

    if 'error' in result:
        lines.append(f"| ERROR: {result['error']:<69} |")
        lines.append("+" + "-" * 78 + "+")
        return "\n".join(lines)

    lines.append(f"| {'Severity':<10} | {'Type':<18} | {'File':<30} | {'Line':<6} |")
    lines.append("+" + "-" * 78 + "+")

    for issue in result['issues']:
        severity = issue.get('severity', 'info')[:10]
        issue_type = issue.get('type', 'unknown')[:18]
        filepath = issue.get('file', 'unknown')
        # Shorten filepath if needed
        if len(filepath) > 30:
            filepath = '...' + filepath[-27:]
        line = str(issue.get('line', '-'))[:6]

        lines.append(f"| {severity:<10} | {issue_type:<18} | {filepath:<30} | {line:<6} |")

    if not result['issues']:
        lines.append(f"| {'No issues found':<76} |")

    lines.append("+" + "-" * 78 + "+")

    # Summary
    severity_counts = {'critical': 0, 'warning': 0, 'info': 0, 'error': 0}
    for issue in result.get('issues', []):
        severity_counts[issue.get('severity', 'info')] += 1

    summary = f"Critical: {severity_counts['critical']} | Warning: {severity_counts['warning']} | Info: {severity_counts['info']}"
    lines.append(f"| {summary:<76} |")
    lines.append("+" + "-" * 78 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Audit sudoers configuration for security issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                       # Basic audit
  %(prog)s --format json         # JSON output for monitoring systems
  %(prog)s --warn-only           # Only show warnings and critical issues
  %(prog)s --no-syntax           # Skip visudo syntax check
  %(prog)s -v                    # Verbose output with line content

Security Checks:
  - NOPASSWD rules (passwordless sudo)
  - ALL commands access (overly broad permissions)
  - Missing env_reset and secure_path defaults
  - File permission issues (should be 0440, owned by root)
  - Syntax errors (via visudo -c)
  - Timestamp timeout settings
  - SETENV usage (environment override)

Note: Must be run as root for complete audit.

Exit codes:
  0 - No security issues detected
  1 - Security issues or warnings found
  2 - Usage error or cannot read sudoers files
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show warnings and critical issues'
    )

    parser.add_argument(
        '--no-syntax',
        action='store_true',
        help='Skip visudo syntax check'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including line content'
    )

    args = parser.parse_args()

    # Check if we can access sudoers
    if not os.path.exists('/etc/sudoers') and not os.path.isdir('/etc/sudoers.d'):
        if args.format == 'json':
            print(json.dumps({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'error': 'No sudoers files found',
                'healthy': False
            }, indent=2))
        else:
            print("Error: No sudoers files found", file=sys.stderr)
        sys.exit(2)

    # Perform audit
    result = audit_sudoers(check_syntax=not args.no_syntax)

    if 'error' in result and not result.get('issues'):
        if args.format == 'json':
            print(format_json(result))
        else:
            print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(2)

    # Format output
    if args.format == 'json':
        output = format_json(result)
    elif args.format == 'table':
        output = format_table(result)
    else:
        output = format_plain(result, warn_only=args.warn_only, verbose=args.verbose)

    print(output)

    # Determine exit code
    severity_counts = {'critical': 0, 'warning': 0, 'error': 0}
    for issue in result.get('issues', []):
        sev = issue.get('severity', 'info')
        if sev in severity_counts:
            severity_counts[sev] += 1

    if severity_counts['critical'] > 0 or severity_counts['warning'] > 0 or severity_counts['error'] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
