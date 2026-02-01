#!/usr/bin/env python3
"""
Analyze systemd journal for service failures, restart loops, and error patterns.

This script parses systemd journal logs to detect application-level issues including:
- Service failures and crashes
- Restart loops (services cycling repeatedly)
- Services stuck in activating/deactivating state
- OOM kills at the service level
- Failed unit starts across reboots
- Segfaults and core dumps
- Authentication failures

Complements kernel-level monitoring (dmesg) with application-level insights.
Useful for detecting service health issues before they cascade to system failures.

Exit codes:
    0 - No critical errors or warnings found
    1 - Errors or warnings found in journal
    2 - Usage error or journalctl not available
"""

import argparse
import sys
import subprocess
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta


# Patterns for detecting issues in journal entries
ISSUE_PATTERNS = {
    'service_failure': [
        (r'(\S+\.service): (Failed|failed) with result', 'CRITICAL'),
        (r'(\S+\.service): Main process exited, code=(exited|killed|dumped)', 'CRITICAL'),
        (r'Failed to start (.+)\.', 'CRITICAL'),
        (r'(\S+\.service): Start request repeated too quickly', 'WARNING'),
    ],
    'restart_loop': [
        (r'(\S+\.service): Scheduled restart job', 'WARNING'),
        (r'(\S+\.service): Service RestartSec=.*configured', 'WARNING'),
        (r'(\S+\.service): Triggering OnFailure=', 'WARNING'),
    ],
    'oom_kill': [
        (r'Out of memory: Killed process \d+ \((.+)\)', 'CRITICAL'),
        (r'oom-kill:.*task=(\S+)', 'CRITICAL'),
        (r'Memory cgroup out of memory: Killed process', 'CRITICAL'),
    ],
    'segfault': [
        (r'(\S+)\[\d+\]: segfault at', 'CRITICAL'),
        (r'(\S+)\[\d+\] (trap|general protection)', 'CRITICAL'),
        (r'Process \d+ \((.+)\) dumped core', 'CRITICAL'),
    ],
    'auth_failure': [
        (r'pam_unix.*authentication failure', 'WARNING'),
        (r'Failed password for .* from', 'WARNING'),
        (r'Connection closed by .* \[preauth\]', 'WARNING'),
    ],
    'disk_space': [
        (r'No space left on device', 'CRITICAL'),
        (r'Disk quota exceeded', 'WARNING'),
        (r'Journal file .* is truncated, ignoring', 'WARNING'),
    ],
    'timeout': [
        (r'(\S+\.service): State .* timed out', 'CRITICAL'),
        (r'(\S+\.service): Job .* timed out', 'CRITICAL'),
        (r'A stop job is running for', 'WARNING'),
    ],
    'dependency': [
        (r'Dependency failed for (.+)\.', 'WARNING'),
        (r'(\S+\.service): Bound to unit .* that isn.*t active', 'WARNING'),
        (r'Job .* failed with result .dependency.', 'WARNING'),
    ],
}

# Priority levels from journalctl
PRIORITY_MAP = {
    '0': 'EMERG',
    '1': 'ALERT',
    '2': 'CRIT',
    '3': 'ERR',
    '4': 'WARNING',
    '5': 'NOTICE',
    '6': 'INFO',
    '7': 'DEBUG',
}


def check_journalctl_available():
    """Check if journalctl is available"""
    try:
        result = subprocess.run(
            ['which', 'journalctl'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def run_journalctl(args_list, timeout=30):
    """Execute journalctl command and return output"""
    cmd = ['journalctl'] + args_list

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr

    except FileNotFoundError:
        print("Error: 'journalctl' command not found", file=sys.stderr)
        print("This script requires systemd. Install systemd or run on a systemd-based system.", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print(f"Error: journalctl command timed out after {timeout}s", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error running journalctl: {e}", file=sys.stderr)
        sys.exit(1)


def get_failed_units():
    """Get list of currently failed systemd units"""
    cmd = ['systemctl', 'list-units', '--state=failed', '--no-legend', '--plain']
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            units = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if parts:
                        units.append(parts[0])
            return units
        return []
    except Exception:
        return []


def get_restart_counts(since='24h'):
    """Count service restarts in the given time period"""
    # Get service start events
    cmd = ['-p', '6', '--since', f'-{since}', '--no-pager', '-o', 'short']
    returncode, stdout, stderr = run_journalctl(cmd)

    restart_counts = defaultdict(int)
    for line in stdout.split('\n'):
        if 'Started ' in line or 'Starting ' in line:
            # Extract service name
            match = re.search(r'Started (.+)\.?$|Starting (.+)\.\.\.', line)
            if match:
                service = match.group(1) or match.group(2)
                if service:
                    restart_counts[service.strip('.')] += 1

    return restart_counts


def analyze_journal_entries(since='24h', priority='warning', unit=None):
    """Analyze journal entries for issues"""
    findings = defaultdict(list)

    # Build journalctl command
    cmd = ['--no-pager', '-o', 'short-iso', '--since', f'-{since}']

    if priority:
        priority_num = {'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
                       'warning': 4, 'notice': 5, 'info': 6, 'debug': 7}.get(priority.lower(), 4)
        cmd.extend(['-p', str(priority_num)])

    if unit:
        cmd.extend(['-u', unit])

    returncode, stdout, stderr = run_journalctl(cmd)

    if returncode != 0 and stderr:
        print(f"Warning: journalctl returned errors: {stderr}", file=sys.stderr)

    # Analyze each line
    for line in stdout.split('\n'):
        if not line.strip():
            continue

        # Check against each pattern category
        for category, patterns in ISSUE_PATTERNS.items():
            for pattern, severity in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    findings[category].append({
                        'severity': severity,
                        'message': line.strip(),
                        'match': match.group(0),
                        'captured': match.groups() if match.groups() else None,
                    })
                    break  # Only match first pattern per line per category

    return findings


def get_journal_disk_usage():
    """Get journal disk usage statistics"""
    cmd = ['--disk-usage']
    returncode, stdout, stderr = run_journalctl(cmd)

    if returncode == 0:
        # Parse output like "Archived and active journals take up 512.0M in the file system."
        match = re.search(r'take up ([\d.]+\s*[KMGT]?)i?B?', stdout)
        if match:
            return match.group(1)
    return None


def output_plain(findings, failed_units, restart_counts, warn_only=False, verbose=False):
    """Output findings in plain text format"""
    has_output = False

    # Show currently failed units
    if failed_units:
        has_output = True
        print(f"\nCURRENTLY FAILED UNITS: {len(failed_units)}")
        print("-" * 60)
        for unit in failed_units:
            print(f"  !!! {unit}")

    # Show services with high restart counts (potential restart loops)
    high_restart = {k: v for k, v in restart_counts.items() if v >= 3}
    if high_restart:
        has_output = True
        print(f"\nSERVICES WITH MULTIPLE RESTARTS:")
        print("-" * 60)
        for service, count in sorted(high_restart.items(), key=lambda x: -x[1])[:10]:
            marker = "!!!" if count >= 10 else "   "
            print(f"  {marker} {service}: {count} restarts")

    # Show journal findings
    if findings:
        has_output = True
        categories_sorted = sorted(
            findings.items(),
            key=lambda x: (
                min((f['severity'] for f in x[1]), default='WARNING') != 'CRITICAL',
                x[0]
            )
        )

        for category, issues in categories_sorted:
            if not issues:
                continue

            critical_count = sum(1 for i in issues if i['severity'] == 'CRITICAL')
            warning_count = sum(1 for i in issues if i['severity'] == 'WARNING')

            print(f"\n{category.upper().replace('_', ' ')}: {len(issues)} issue(s) "
                  f"({critical_count} critical, {warning_count} warnings)")
            print("-" * 60)

            # Deduplicate similar messages
            seen = set()
            for issue in issues:
                key = issue.get('match', issue['message'][:50])
                if key in seen and not verbose:
                    continue
                seen.add(key)

                severity_marker = "!!!" if issue['severity'] == 'CRITICAL' else "   "
                if verbose:
                    print(f"{severity_marker} [{issue['severity']}] {issue['message']}")
                else:
                    msg = issue['message']
                    if len(msg) > 100:
                        msg = msg[:97] + "..."
                    print(f"{severity_marker} {msg}")

    if not has_output and not warn_only:
        print("No journal errors or warnings detected")


def output_json(findings, failed_units, restart_counts):
    """Output findings in JSON format"""
    output = {
        'summary': {
            'failed_units_count': len(failed_units),
            'total_categories': len(findings),
            'total_issues': sum(len(issues) for issues in findings.values()),
            'critical_count': sum(
                1 for issues in findings.values()
                for i in issues if i['severity'] == 'CRITICAL'
            ),
            'warning_count': sum(
                1 for issues in findings.values()
                for i in issues if i['severity'] == 'WARNING'
            ),
        },
        'failed_units': failed_units,
        'high_restart_services': {k: v for k, v in restart_counts.items() if v >= 3},
        'findings': {}
    }

    for category, issues in findings.items():
        output['findings'][category] = [
            {
                'severity': i['severity'],
                'message': i['message'],
            }
            for i in issues
        ]

    print(json.dumps(output, indent=2))


def output_table(findings, failed_units, restart_counts, warn_only=False, verbose=False):
    """Output findings in table format"""
    has_output = False

    if failed_units:
        has_output = True
        print(f"{'Unit':<50} {'Status':<15}")
        print("=" * 65)
        for unit in failed_units:
            print(f"{unit:<50} {'FAILED':<15}")
        print()

    if findings:
        has_output = True
        print(f"{'Category':<20} {'Severity':<10} {'Count':<8} {'Sample':<50}")
        print("=" * 88)

        for category, issues in sorted(findings.items()):
            if not issues:
                continue

            severity_groups = defaultdict(list)
            for issue in issues:
                severity_groups[issue['severity']].append(issue)

            for severity, severity_issues in sorted(severity_groups.items(), reverse=True):
                msg = severity_issues[0].get('match', severity_issues[0]['message'][:50])
                if len(msg) > 50:
                    msg = msg[:47] + "..."

                cat_display = category.replace('_', ' ')
                print(f"{cat_display:<20} {severity:<10} {len(severity_issues):<8} {msg:<50}")

    if not has_output and not warn_only:
        print("No journal errors or warnings detected")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Analyze systemd journal for service failures, restart loops, and error patterns',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Analyze last 24 hours
  %(prog)s --since 1h               # Only last hour
  %(prog)s --since 7d               # Last 7 days
  %(prog)s --format json            # JSON output
  %(prog)s -u nginx.service         # Specific unit only
  %(prog)s --priority err           # Only errors and above
  %(prog)s --warn-only              # Only show issues

Categories checked:
  - Service failures and crashes
  - Restart loops (repeated restarts)
  - OOM kills at service level
  - Segfaults and core dumps
  - Authentication failures
  - Disk space issues
  - Service timeouts
  - Dependency failures
        """
    )

    parser.add_argument(
        '--since',
        default='24h',
        help='Time period to analyze (e.g., "1h", "24h", "7d") (default: %(default)s)'
    )

    parser.add_argument(
        '-u', '--unit',
        help='Only analyze specific systemd unit (e.g., nginx.service)'
    )

    parser.add_argument(
        '-p', '--priority',
        choices=['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'],
        default='warning',
        help='Minimum priority level to include (default: %(default)s)'
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
        help='Show full messages and all duplicates'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show issues, suppress "no errors" message'
    )

    args = parser.parse_args()

    # Check for journalctl
    if not check_journalctl_available():
        print("Error: journalctl not found in PATH", file=sys.stderr)
        print("This script requires systemd. Install systemd or run on a systemd-based system.", file=sys.stderr)
        sys.exit(2)

    # Gather data
    failed_units = get_failed_units()
    restart_counts = get_restart_counts(args.since)
    findings = analyze_journal_entries(
        since=args.since,
        priority=args.priority,
        unit=args.unit
    )

    # Output results
    if args.format == 'json':
        output_json(findings, failed_units, restart_counts)
    elif args.format == 'table':
        output_table(findings, failed_units, restart_counts,
                    warn_only=args.warn_only, verbose=args.verbose)
    else:  # plain
        output_plain(findings, failed_units, restart_counts,
                    warn_only=args.warn_only, verbose=args.verbose)

    # Exit based on findings
    has_critical = (
        len(failed_units) > 0 or
        any(i['severity'] == 'CRITICAL' for issues in findings.values() for i in issues)
    )
    has_warnings = (
        any(v >= 10 for v in restart_counts.values()) or
        any(i['severity'] == 'WARNING' for issues in findings.values() for i in issues)
    )

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
