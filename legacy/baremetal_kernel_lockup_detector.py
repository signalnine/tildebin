#!/usr/bin/env python3
"""
Detect kernel lockups, RCU stalls, and hung tasks on Linux systems.

Monitors kernel messages for indicators of system instability:
- Soft lockups (CPU stuck in kernel mode with interrupts enabled)
- Hard lockups (CPU stuck with interrupts disabled)
- RCU stalls (Read-Copy-Update mechanism blocked)
- Hung tasks (processes stuck in uninterruptible sleep)
- Kernel panics and oops messages

These issues often indicate hardware problems, driver bugs, or resource
exhaustion that can lead to system hangs or crashes.

Useful for:
- Proactive detection of system instability
- Hardware problem diagnosis
- Driver debugging
- Monitoring high-load production systems
- Detecting silent failures in baremetal infrastructure

Exit codes:
    0 - No lockup indicators detected
    1 - Lockup warnings or issues detected
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import subprocess
import re
from datetime import datetime, timedelta


def read_file(path):
    """Read a file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read()
    except (IOError, OSError):
        return None


def run_command(cmd):
    """Execute shell command and return result."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def get_kernel_config():
    """Get kernel lockup detection configuration."""
    config = {
        'softlockup_panic': None,
        'softlockup_all_cpu_backtrace': None,
        'hardlockup_panic': None,
        'hung_task_panic': None,
        'hung_task_timeout_secs': None,
        'watchdog_thresh': None,
        'nmi_watchdog': None,
    }

    # Read sysctl values
    sysctl_paths = {
        'softlockup_panic': '/proc/sys/kernel/softlockup_panic',
        'softlockup_all_cpu_backtrace': '/proc/sys/kernel/softlockup_all_cpu_backtrace',
        'hardlockup_panic': '/proc/sys/kernel/hardlockup_panic',
        'hung_task_panic': '/proc/sys/kernel/hung_task_panic',
        'hung_task_timeout_secs': '/proc/sys/kernel/hung_task_timeout_secs',
        'watchdog_thresh': '/proc/sys/kernel/watchdog_thresh',
        'nmi_watchdog': '/proc/sys/kernel/nmi_watchdog',
    }

    for key, path in sysctl_paths.items():
        content = read_file(path)
        if content is not None:
            try:
                config[key] = int(content.strip())
            except ValueError:
                config[key] = content.strip()

    return config


def get_dmesg_lockups(hours=24):
    """Parse dmesg for lockup-related messages."""
    lockups = []

    # Patterns to detect various kernel issues
    patterns = {
        'soft_lockup': re.compile(
            r'(\w+\s+\d+\s+[\d:]+|\[\s*[\d.]+\])\s.*?(soft lockup|softlockup)',
            re.IGNORECASE
        ),
        'hard_lockup': re.compile(
            r'(\w+\s+\d+\s+[\d:]+|\[\s*[\d.]+\])\s.*?(hard lockup|hardlockup|NMI watchdog.*hard LOCKUP)',
            re.IGNORECASE
        ),
        'rcu_stall': re.compile(
            r'(\w+\s+\d+\s+[\d:]+|\[\s*[\d.]+\])\s.*?(rcu.*stall|RCU.*detected stall)',
            re.IGNORECASE
        ),
        'hung_task': re.compile(
            r'(\w+\s+\d+\s+[\d:]+|\[\s*[\d.]+\])\s.*?(hung_task|blocked for more than \d+ seconds)',
            re.IGNORECASE
        ),
        'kernel_panic': re.compile(
            r'(\w+\s+\d+\s+[\d:]+|\[\s*[\d.]+\])\s.*?(Kernel panic|kernel BUG)',
            re.IGNORECASE
        ),
        'oops': re.compile(
            r'(\w+\s+\d+\s+[\d:]+|\[\s*[\d.]+\])\s.*?(Oops:|general protection fault)',
            re.IGNORECASE
        ),
        'mce': re.compile(
            r'(\w+\s+\d+\s+[\d:]+|\[\s*[\d.]+\])\s.*?(Machine check|mce:.*Hardware Error)',
            re.IGNORECASE
        ),
        'watchdog': re.compile(
            r'(\w+\s+\d+\s+[\d:]+|\[\s*[\d.]+\])\s.*?(watchdog.*timeout|watchdog.*didn\'t)',
            re.IGNORECASE
        ),
    }

    # Try journalctl first (more reliable timestamps)
    since = f"-{hours}h" if hours else None
    cmd = ['journalctl', '-k', '--no-pager', '-q']
    if since:
        cmd.extend(['--since', f'{hours} hours ago'])

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        # Fall back to dmesg
        cmd = ['dmesg', '-T']
        returncode, stdout, stderr = run_command(cmd)
        if returncode != 0:
            # Try dmesg without timestamps
            cmd = ['dmesg']
            returncode, stdout, stderr = run_command(cmd)
            if returncode != 0:
                return lockups

    # Parse output for lockup patterns
    for line in stdout.splitlines():
        for lockup_type, pattern in patterns.items():
            if pattern.search(line):
                lockups.append({
                    'type': lockup_type,
                    'message': line.strip()[:500],  # Truncate long lines
                    'severity': get_severity(lockup_type)
                })
                break  # Only match once per line

    return lockups


def get_severity(lockup_type):
    """Return severity level for lockup type."""
    critical_types = ['hard_lockup', 'kernel_panic', 'mce']
    warning_types = ['soft_lockup', 'rcu_stall', 'hung_task', 'oops', 'watchdog']

    if lockup_type in critical_types:
        return 'CRITICAL'
    elif lockup_type in warning_types:
        return 'WARNING'
    return 'INFO'


def get_current_hung_tasks():
    """Check for currently hung tasks by examining process states."""
    hung_tasks = []

    # Look for processes in D (uninterruptible sleep) state
    returncode, stdout, stderr = run_command(['ps', '-eo', 'pid,stat,wchan:32,comm', '--no-headers'])

    if returncode != 0:
        return hung_tasks

    for line in stdout.splitlines():
        parts = line.split(None, 3)
        if len(parts) >= 4:
            pid, stat, wchan, comm = parts
            # D state indicates uninterruptible sleep (potential hung task)
            if 'D' in stat:
                hung_tasks.append({
                    'pid': pid,
                    'state': stat,
                    'wchan': wchan,
                    'command': comm
                })

    return hung_tasks


def get_cpu_softlockup_times():
    """Get per-CPU softlockup watchdog status if available."""
    cpu_status = []

    # Check watchdog status via /proc/sys/kernel
    watchdog_enabled = read_file('/proc/sys/kernel/watchdog')
    if watchdog_enabled and watchdog_enabled.strip() == '0':
        return cpu_status  # Watchdog disabled

    # Try to get CPU-specific information from /sys
    cpu_pattern = '/sys/devices/system/cpu/cpu[0-9]*'
    try:
        import glob
        for cpu_path in sorted(glob.glob(cpu_pattern)):
            cpu_id = os.path.basename(cpu_path).replace('cpu', '')
            cpu_status.append({
                'cpu': int(cpu_id),
                'online': os.path.exists(os.path.join(cpu_path, 'online'))
            })
    except Exception:
        pass

    return cpu_status


def analyze_lockups(lockups, hung_tasks, config, thresholds):
    """Analyze lockup data and return issues."""
    issues = []

    # Report kernel lockup events
    for lockup in lockups:
        issues.append({
            'severity': lockup['severity'],
            'type': lockup['type'],
            'message': lockup['message']
        })

    # Report currently hung tasks
    if len(hung_tasks) >= thresholds['hung_task_count']:
        issues.append({
            'severity': 'WARNING',
            'type': 'current_hung_tasks',
            'count': len(hung_tasks),
            'message': f"Found {len(hung_tasks)} processes in uninterruptible sleep (D state)"
        })

    # Check kernel configuration warnings
    if config.get('softlockup_panic') == 0:
        issues.append({
            'severity': 'INFO',
            'type': 'config',
            'message': "softlockup_panic disabled - soft lockups won't trigger panic"
        })

    if config.get('nmi_watchdog') == 0:
        issues.append({
            'severity': 'INFO',
            'type': 'config',
            'message': "NMI watchdog disabled - hard lockups may not be detected"
        })

    if config.get('hung_task_timeout_secs') == 0:
        issues.append({
            'severity': 'INFO',
            'type': 'config',
            'message': "hung_task detection disabled (timeout=0)"
        })

    return issues


def output_plain(lockups, hung_tasks, config, issues, verbose, warn_only):
    """Output results in plain text format."""
    lines = []

    if not warn_only:
        # Summary
        critical_count = sum(1 for l in lockups if get_severity(l['type']) == 'CRITICAL')
        warning_count = sum(1 for l in lockups if get_severity(l['type']) == 'WARNING')

        lines.append(f"Kernel Lockup Detection Summary")
        lines.append(f"Critical events: {critical_count}")
        lines.append(f"Warning events: {warning_count}")
        lines.append(f"Processes in D state: {len(hung_tasks)}")
        lines.append("")

        if verbose:
            # Show kernel configuration
            lines.append("Kernel Configuration:")
            if config.get('watchdog_thresh'):
                lines.append(f"  Watchdog threshold: {config['watchdog_thresh']}s")
            if config.get('hung_task_timeout_secs'):
                lines.append(f"  Hung task timeout: {config['hung_task_timeout_secs']}s")
            if config.get('nmi_watchdog') is not None:
                lines.append(f"  NMI watchdog: {'enabled' if config['nmi_watchdog'] else 'disabled'}")
            lines.append("")

            # Show hung tasks
            if hung_tasks:
                lines.append("Processes in D state (uninterruptible sleep):")
                for task in hung_tasks[:10]:  # Limit to 10
                    lines.append(f"  PID {task['pid']}: {task['command']} (wchan: {task['wchan']})")
                if len(hung_tasks) > 10:
                    lines.append(f"  ... and {len(hung_tasks) - 10} more")
                lines.append("")

    # Issues
    for issue in issues:
        if warn_only and issue['severity'] == 'INFO':
            continue
        prefix = f"[{issue['severity']}]"
        if issue['type'] in ['soft_lockup', 'hard_lockup', 'rcu_stall', 'hung_task',
                             'kernel_panic', 'oops', 'mce', 'watchdog']:
            lines.append(f"{prefix} {issue['type']}: {issue['message'][:100]}")
        else:
            lines.append(f"{prefix} {issue['message']}")

    if not issues and not warn_only:
        lines.append("No kernel lockup issues detected.")

    print('\n'.join(lines))


def output_json(lockups, hung_tasks, config, issues, verbose):
    """Output results in JSON format."""
    result = {
        'summary': {
            'total_events': len(lockups),
            'critical_count': sum(1 for l in lockups if get_severity(l['type']) == 'CRITICAL'),
            'warning_count': sum(1 for l in lockups if get_severity(l['type']) == 'WARNING'),
            'hung_task_count': len(hung_tasks)
        },
        'issues': issues
    }

    if verbose:
        result['lockup_events'] = lockups
        result['hung_tasks'] = hung_tasks
        result['kernel_config'] = config

    print(json.dumps(result, indent=2))


def output_table(lockups, hung_tasks, config, issues, verbose, warn_only):
    """Output results in table format."""
    lines = []

    if not warn_only:
        lines.append("=" * 70)
        lines.append("KERNEL LOCKUP DETECTION")
        lines.append("=" * 70)
        lines.append(f"{'Metric':<30} {'Value':<40}")
        lines.append("-" * 70)

        critical_count = sum(1 for l in lockups if get_severity(l['type']) == 'CRITICAL')
        warning_count = sum(1 for l in lockups if get_severity(l['type']) == 'WARNING')

        lines.append(f"{'Critical Events':<30} {critical_count:<40}")
        lines.append(f"{'Warning Events':<30} {warning_count:<40}")
        lines.append(f"{'Processes in D State':<30} {len(hung_tasks):<40}")

        if config.get('watchdog_thresh'):
            lines.append(f"{'Watchdog Threshold':<30} {str(config['watchdog_thresh']) + 's':<40}")
        if config.get('nmi_watchdog') is not None:
            status = 'enabled' if config['nmi_watchdog'] else 'disabled'
            lines.append(f"{'NMI Watchdog':<30} {status:<40}")

        lines.append("=" * 70)
        lines.append("")

    if issues:
        filtered_issues = [i for i in issues if not (warn_only and i['severity'] == 'INFO')]
        if filtered_issues:
            lines.append("ISSUES DETECTED")
            lines.append("-" * 70)
            for issue in filtered_issues:
                msg = issue.get('message', '')[:60]
                lines.append(f"[{issue['severity']}] {issue['type']}: {msg}")
            lines.append("")

    print('\n'.join(lines))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Detect kernel lockups, RCU stalls, and hung tasks on Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check for lockup events
  %(prog)s --format json        # JSON output for monitoring
  %(prog)s --hours 48           # Check last 48 hours
  %(prog)s --verbose            # Show detailed information
  %(prog)s --warn-only          # Only show warnings/errors

Monitored Events:
  - Soft lockups: CPU stuck in kernel mode (interrupts enabled)
  - Hard lockups: CPU stuck with interrupts disabled
  - RCU stalls: Read-Copy-Update mechanism blocked
  - Hung tasks: Processes stuck in uninterruptible sleep
  - Kernel panics and oops messages
  - Machine check exceptions (MCE)

Exit codes:
  0 - No issues detected
  1 - Lockup events or warnings detected
  2 - Usage error or missing dependencies

Notes:
  - Requires read access to dmesg/journalctl
  - Some events require root access to view
  - Configure kernel.softlockup_panic to crash on soft lockup
  - Configure kernel.hung_task_panic to crash on hung tasks
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
        help='Show detailed information including config and hung tasks'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors'
    )

    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        metavar='N',
        help='Hours of history to check (default: 24)'
    )

    parser.add_argument(
        '--hung-task-threshold',
        type=int,
        default=5,
        metavar='N',
        help='Number of D-state processes to trigger warning (default: 5)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.hours < 0:
        print("Error: --hours must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.hung_task_threshold < 0:
        print("Error: --hung-task-threshold must be non-negative", file=sys.stderr)
        sys.exit(2)

    thresholds = {
        'hung_task_count': args.hung_task_threshold
    }

    # Gather information
    config = get_kernel_config()
    lockups = get_dmesg_lockups(args.hours)
    hung_tasks = get_current_hung_tasks()

    # Analyze
    issues = analyze_lockups(lockups, hung_tasks, config, thresholds)

    # Output
    if args.format == 'json':
        output_json(lockups, hung_tasks, config, issues, args.verbose)
    elif args.format == 'table':
        output_table(lockups, hung_tasks, config, issues, args.verbose, args.warn_only)
    else:
        output_plain(lockups, hung_tasks, config, issues, args.verbose, args.warn_only)

    # Exit based on findings
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
