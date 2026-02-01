#!/usr/bin/env python3
"""
Analyze boot issues from journald logs across recent system boots.

This script examines journald logs to identify boot-related problems including:
- Kernel panics and oopses
- Emergency/rescue mode entries
- OOM kills during boot
- Failed systemd units during boot
- Critical/alert level messages during boot
- Hardware errors detected during boot

Useful for large-scale baremetal environments to identify machines that
experienced problematic boots or recurring boot issues.

Exit codes:
    0 - No boot issues detected
    1 - Boot issues found
    2 - Missing dependencies or usage error
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime


def run_command(cmd):
    """Execute a command and return output."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def check_journalctl_available():
    """Check if journalctl is available."""
    returncode, _, _ = run_command(['which', 'journalctl'])
    return returncode == 0


def get_boot_list(num_boots=5):
    """Get list of recent boots with their boot IDs."""
    returncode, stdout, _ = run_command(
        ['journalctl', '--list-boots', '--no-pager']
    )

    if returncode != 0:
        return []

    boots = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 4:
            # Format: offset boot_id first_entry last_entry
            # Example: -1 abc123def... Thu 2024-01-01 10:00:00 Thu 2024-01-01 12:00:00
            try:
                offset = int(parts[0])
                boot_id = parts[1]
                # Reconstruct timestamp (varies by locale)
                timestamp_parts = parts[2:]
                timestamp_str = ' '.join(timestamp_parts[:4]) if len(timestamp_parts) >= 4 else ''

                boots.append({
                    'offset': offset,
                    'boot_id': boot_id,
                    'timestamp': timestamp_str
                })
            except (ValueError, IndexError):
                continue

    # Return most recent boots (limited to num_boots)
    return boots[:num_boots]


def get_boot_logs(boot_id, priority=None, grep_pattern=None):
    """Get logs for a specific boot."""
    cmd = ['journalctl', '-b', boot_id, '--no-pager', '-o', 'short-iso']

    if priority:
        cmd.extend(['-p', priority])

    returncode, stdout, _ = run_command(cmd)

    if returncode != 0:
        return []

    logs = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue

        if grep_pattern and grep_pattern.lower() not in line.lower():
            continue

        logs.append(line)

    return logs


def check_kernel_issues(boot_id):
    """Check for kernel panics, oopses, and critical kernel errors."""
    issues = []

    # Check for kernel panics
    panic_patterns = [
        'Kernel panic',
        'kernel BUG',
        'Oops:',
        'general protection fault',
        'unable to handle kernel',
        'BUG: unable to handle',
        'Call Trace:',
        'RIP:',
        'kernel stack',
    ]

    logs = get_boot_logs(boot_id)

    for line in logs:
        line_lower = line.lower()
        for pattern in panic_patterns:
            if pattern.lower() in line_lower:
                issues.append({
                    'type': 'kernel_error',
                    'severity': 'critical',
                    'message': line.strip()[:200]
                })
                break

    return issues


def check_oom_kills(boot_id):
    """Check for OOM (Out of Memory) kills during boot."""
    issues = []

    oom_patterns = [
        'Out of memory:',
        'oom-kill:',
        'Killed process',
        'Memory cgroup out of memory',
        'invoked oom-killer',
    ]

    logs = get_boot_logs(boot_id)

    for line in logs:
        line_lower = line.lower()
        for pattern in oom_patterns:
            if pattern.lower() in line_lower:
                issues.append({
                    'type': 'oom_kill',
                    'severity': 'warning',
                    'message': line.strip()[:200]
                })
                break

    return issues


def check_emergency_mode(boot_id):
    """Check if system entered emergency or rescue mode."""
    issues = []

    emergency_patterns = [
        'Entering emergency mode',
        'Emergency mode',
        'rescue.target',
        'emergency.target',
        'You are in emergency mode',
        'Give root password for maintenance',
        'Entering rescue mode',
    ]

    logs = get_boot_logs(boot_id)

    for line in logs:
        line_lower = line.lower()
        for pattern in emergency_patterns:
            if pattern.lower() in line_lower:
                issues.append({
                    'type': 'emergency_mode',
                    'severity': 'critical',
                    'message': line.strip()[:200]
                })
                break

    return issues


def check_failed_units(boot_id):
    """Check for failed systemd units during boot."""
    issues = []

    failed_patterns = [
        'Failed to start',
        'failed with result',
        'entered failed state',
        'Service unit .* failed',
        'Job .* failed',
    ]

    logs = get_boot_logs(boot_id)

    for line in logs:
        line_lower = line.lower()
        for pattern in failed_patterns:
            # Simple string matching (not full regex for performance)
            if 'failed' in line_lower and ('start' in line_lower or 'unit' in line_lower or 'service' in line_lower or 'job' in line_lower):
                issues.append({
                    'type': 'failed_unit',
                    'severity': 'warning',
                    'message': line.strip()[:200]
                })
                break

    return issues


def check_hardware_errors(boot_id):
    """Check for hardware-related errors during boot."""
    issues = []

    hw_patterns = [
        'Hardware Error',
        'Machine check exception',
        'MCE:',
        'ACPI Error',
        'ACPI BIOS Error',
        'DMAR:',
        'IOMMU:',
        'ECC error',
        'EDAC',
        'pcie error',
        'AER:',
        'link down',
        'I/O error',
        'Medium Error',
        'ata[0-9].*error',
        'SMART error',
        'Uncorrected error',
    ]

    logs = get_boot_logs(boot_id)

    for line in logs:
        line_lower = line.lower()
        for pattern in hw_patterns:
            if pattern.lower() in line_lower:
                issues.append({
                    'type': 'hardware_error',
                    'severity': 'warning',
                    'message': line.strip()[:200]
                })
                break

    return issues


def check_critical_logs(boot_id):
    """Check for critical/alert/emergency level logs."""
    issues = []

    # Get only critical and above (priority 0-2: emerg, alert, crit)
    logs = get_boot_logs(boot_id, priority='2')

    for line in logs:
        if line.strip():
            issues.append({
                'type': 'critical_log',
                'severity': 'critical',
                'message': line.strip()[:200]
            })

    return issues


def check_filesystem_errors(boot_id):
    """Check for filesystem errors during boot."""
    issues = []

    fs_patterns = [
        'EXT4-fs error',
        'XFS error',
        'BTRFS error',
        'filesystem error',
        'fsck',
        'journal recovery',
        'Remounting filesystem read-only',
        'I/O error',
        'Superblock needs',
        'inconsistent',
    ]

    logs = get_boot_logs(boot_id)

    for line in logs:
        line_lower = line.lower()
        for pattern in fs_patterns:
            if pattern.lower() in line_lower and 'error' in line_lower:
                issues.append({
                    'type': 'filesystem_error',
                    'severity': 'warning',
                    'message': line.strip()[:200]
                })
                break

    return issues


def analyze_boot(boot_info, checks):
    """Analyze a single boot for issues."""
    boot_id = boot_info['boot_id']
    all_issues = []

    if 'kernel' in checks:
        all_issues.extend(check_kernel_issues(boot_id))
    if 'oom' in checks:
        all_issues.extend(check_oom_kills(boot_id))
    if 'emergency' in checks:
        all_issues.extend(check_emergency_mode(boot_id))
    if 'units' in checks:
        all_issues.extend(check_failed_units(boot_id))
    if 'hardware' in checks:
        all_issues.extend(check_hardware_errors(boot_id))
    if 'critical' in checks:
        all_issues.extend(check_critical_logs(boot_id))
    if 'filesystem' in checks:
        all_issues.extend(check_filesystem_errors(boot_id))

    # Deduplicate issues based on message
    seen = set()
    unique_issues = []
    for issue in all_issues:
        msg_key = issue['message'][:100]
        if msg_key not in seen:
            seen.add(msg_key)
            unique_issues.append(issue)

    return {
        'boot_id': boot_id,
        'offset': boot_info['offset'],
        'timestamp': boot_info['timestamp'],
        'issues': unique_issues,
        'critical_count': sum(1 for i in unique_issues if i['severity'] == 'critical'),
        'warning_count': sum(1 for i in unique_issues if i['severity'] == 'warning')
    }


def output_plain(results, verbose=False, warn_only=False):
    """Output results in plain text format."""
    total_issues = sum(len(r['issues']) for r in results)
    total_critical = sum(r['critical_count'] for r in results)

    if warn_only and total_issues == 0:
        return

    print("Boot Issues Analysis")
    print("=" * 60)
    print(f"Boots analyzed: {len(results)}")
    print(f"Total issues found: {total_issues}")
    print(f"Critical issues: {total_critical}")
    print()

    for result in results:
        if warn_only and len(result['issues']) == 0:
            continue

        boot_label = "current" if result['offset'] == 0 else f"{result['offset']}"
        print(f"Boot {boot_label} ({result['boot_id'][:12]}...)")
        print(f"  Timestamp: {result['timestamp']}")
        print(f"  Issues: {len(result['issues'])} ({result['critical_count']} critical, {result['warning_count']} warnings)")

        if verbose and result['issues']:
            print("  Details:")
            for issue in result['issues'][:10]:  # Limit to first 10
                severity_marker = "[CRIT]" if issue['severity'] == 'critical' else "[WARN]"
                print(f"    {severity_marker} [{issue['type']}] {issue['message'][:80]}")
            if len(result['issues']) > 10:
                print(f"    ... and {len(result['issues']) - 10} more issues")
        print()


def output_json(results):
    """Output results in JSON format."""
    output = {
        'summary': {
            'boots_analyzed': len(results),
            'total_issues': sum(len(r['issues']) for r in results),
            'total_critical': sum(r['critical_count'] for r in results),
            'total_warnings': sum(r['warning_count'] for r in results)
        },
        'boots': results,
        'timestamp': datetime.now().isoformat()
    }
    print(json.dumps(output, indent=2))


def output_table(results, verbose=False, warn_only=False):
    """Output results in table format."""
    total_issues = sum(len(r['issues']) for r in results)

    if warn_only and total_issues == 0:
        return

    print(f"{'BOOT':<10} {'BOOT ID':<15} {'ISSUES':<10} {'CRITICAL':<10} {'WARNINGS':<10}")
    print("-" * 60)

    for result in results:
        if warn_only and len(result['issues']) == 0:
            continue

        boot_label = "current" if result['offset'] == 0 else str(result['offset'])
        boot_id_short = result['boot_id'][:12] + "..."
        print(f"{boot_label:<10} {boot_id_short:<15} {len(result['issues']):<10} {result['critical_count']:<10} {result['warning_count']:<10}")

    print("-" * 60)
    print(f"{'TOTAL':<10} {'':<15} {sum(len(r['issues']) for r in results):<10} {sum(r['critical_count'] for r in results):<10} {sum(r['warning_count'] for r in results):<10}")

    if verbose:
        print("\nIssue Types by Boot:")
        for result in results:
            if result['issues']:
                boot_label = "current" if result['offset'] == 0 else str(result['offset'])
                types = {}
                for issue in result['issues']:
                    types[issue['type']] = types.get(issue['type'], 0) + 1
                type_str = ', '.join(f"{k}:{v}" for k, v in types.items())
                print(f"  Boot {boot_label}: {type_str}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze boot issues from journald logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Analyze last 5 boots
  %(prog)s --boots 10                # Analyze last 10 boots
  %(prog)s --current-only            # Analyze only current boot
  %(prog)s --checks kernel,oom       # Only check for kernel issues and OOM
  %(prog)s --format json             # JSON output for monitoring systems
  %(prog)s --verbose                 # Show detailed issue messages

Available checks:
  kernel     - Kernel panics, oopses, BUGs
  oom        - Out of memory kills
  emergency  - Emergency/rescue mode entries
  units      - Failed systemd units
  hardware   - Hardware errors (MCE, ACPI, PCIe, etc.)
  critical   - Critical/alert/emergency level logs
  filesystem - Filesystem errors

Exit codes:
  0 - No issues detected
  1 - Boot issues found
  2 - Missing dependencies or usage error
"""
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed issue messages'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only',
        action='store_true',
        help='Only show boots with issues'
    )

    parser.add_argument(
        '--boots',
        type=int,
        default=5,
        metavar='N',
        help='Number of recent boots to analyze (default: 5)'
    )

    parser.add_argument(
        '--current-only',
        action='store_true',
        help='Only analyze current boot'
    )

    parser.add_argument(
        '--checks',
        metavar='CHECKS',
        default='kernel,oom,emergency,units,hardware,filesystem',
        help='Comma-separated list of checks to run (default: all except critical)'
    )

    args = parser.parse_args()

    # Check for journalctl
    if not check_journalctl_available():
        print("Error: journalctl not found. This script requires systemd journald.",
              file=sys.stderr)
        sys.exit(2)

    # Parse checks
    available_checks = {'kernel', 'oom', 'emergency', 'units', 'hardware', 'critical', 'filesystem'}
    requested_checks = set(c.strip() for c in args.checks.split(','))
    invalid_checks = requested_checks - available_checks
    if invalid_checks:
        print(f"Error: Invalid checks: {', '.join(invalid_checks)}", file=sys.stderr)
        print(f"Available checks: {', '.join(sorted(available_checks))}", file=sys.stderr)
        sys.exit(2)

    # Get boot list
    if args.current_only:
        boots = [{'offset': 0, 'boot_id': '0', 'timestamp': 'current'}]
        # Get actual current boot ID
        returncode, stdout, _ = run_command(['journalctl', '--list-boots', '-n', '1', '--no-pager'])
        if returncode == 0 and stdout.strip():
            parts = stdout.strip().split()
            if len(parts) >= 2:
                boots[0]['boot_id'] = parts[1]
    else:
        boots = get_boot_list(args.boots)

    if not boots:
        print("Error: No boots found in journal", file=sys.stderr)
        sys.exit(2)

    # Analyze each boot
    results = []
    for boot in boots:
        result = analyze_boot(boot, requested_checks)
        results.append(result)

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.verbose, args.warn_only)
    else:  # plain
        output_plain(results, args.verbose, args.warn_only)

    # Exit code based on findings
    total_issues = sum(len(r['issues']) for r in results)
    sys.exit(1 if total_issues > 0 else 0)


if __name__ == "__main__":
    main()
