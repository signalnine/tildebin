#!/usr/bin/env python3
"""
Monitor process signal dispositions on baremetal systems.

Detects processes with potentially problematic signal handling configurations:
- Processes ignoring SIGTERM (won't gracefully shut down)
- Processes blocking critical signals (may not respond to shutdown requests)
- Long-running processes with unusual signal masks

This is useful for:
- Pre-deployment checks to ensure services will gracefully terminate
- Detecting misbehaving applications that won't respond to signals
- Identifying potential issues before node drains or rolling restarts
- Security auditing (processes ignoring termination signals)

Signal information is read from /proc/<pid>/status (SigBlk, SigIgn, SigCgt).

Exit codes:
    0 - No processes with concerning signal dispositions found
    1 - Processes with concerning signal dispositions detected
    2 - Usage error or missing dependencies
"""

import argparse
import json
import os
import pwd
import sys
from collections import defaultdict


# Signal number to name mapping (Linux x86_64)
SIGNAL_NAMES = {
    1: 'SIGHUP',
    2: 'SIGINT',
    3: 'SIGQUIT',
    4: 'SIGILL',
    5: 'SIGTRAP',
    6: 'SIGABRT',
    7: 'SIGBUS',
    8: 'SIGFPE',
    9: 'SIGKILL',
    10: 'SIGUSR1',
    11: 'SIGSEGV',
    12: 'SIGUSR2',
    13: 'SIGPIPE',
    14: 'SIGALRM',
    15: 'SIGTERM',
    16: 'SIGSTKFLT',
    17: 'SIGCHLD',
    18: 'SIGCONT',
    19: 'SIGSTOP',
    20: 'SIGTSTP',
    21: 'SIGTTIN',
    22: 'SIGTTOU',
    23: 'SIGURG',
    24: 'SIGXCPU',
    25: 'SIGXFSZ',
    26: 'SIGVTALRM',
    27: 'SIGPROF',
    28: 'SIGWINCH',
    29: 'SIGIO',
    30: 'SIGPWR',
    31: 'SIGSYS',
}

# Signals that are concerning if ignored (can't be caught/ignored: SIGKILL, SIGSTOP)
# SIGTERM is the most important - used for graceful shutdown
CONCERNING_IGNORED_SIGNALS = {
    15: 'SIGTERM',   # Graceful termination - critical for deployments
    1: 'SIGHUP',     # Hangup - often used for config reload
    2: 'SIGINT',     # Interrupt (Ctrl+C)
    3: 'SIGQUIT',    # Quit with core dump
}

# Signals that are concerning if blocked for long periods
CONCERNING_BLOCKED_SIGNALS = {
    15: 'SIGTERM',   # Graceful termination
    1: 'SIGHUP',     # Hangup
    2: 'SIGINT',     # Interrupt
}

# Process names that commonly and legitimately ignore signals
EXPECTED_SIGNAL_IGNORERS = {
    'systemd', 'init', 'dockerd', 'containerd', 'runc',
    'kubelet', 'kube-proxy', 'crio', 'podman',
}


def parse_signal_mask(hex_mask):
    """
    Parse a signal mask from hex string to set of signal numbers.

    Args:
        hex_mask: Hexadecimal string from /proc/<pid>/status

    Returns:
        set: Signal numbers that are set in the mask
    """
    try:
        mask = int(hex_mask, 16)
        signals = set()
        for signum in range(1, 65):  # Linux supports up to 64 signals
            if mask & (1 << (signum - 1)):
                signals.add(signum)
        return signals
    except (ValueError, TypeError):
        return set()


def get_signal_name(signum):
    """Get human-readable signal name."""
    return SIGNAL_NAMES.get(signum, f'SIG{signum}')


def get_process_signal_info(pid):
    """
    Get signal disposition information for a process.

    Args:
        pid: Process ID

    Returns:
        dict: Signal info or None if unavailable
    """
    try:
        # Read status file
        status = {}
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if ':' in line:
                    key, value = line.split(':', 1)
                    status[key.strip()] = value.strip()

        # Parse signal masks
        sig_blk = parse_signal_mask(status.get('SigBlk', '0'))
        sig_ign = parse_signal_mask(status.get('SigIgn', '0'))
        sig_cgt = parse_signal_mask(status.get('SigCgt', '0'))

        # Get process name
        name = status.get('Name', '<unknown>')

        # Get command line
        try:
            with open(f'/proc/{pid}/cmdline', 'r') as f:
                cmdline = f.read().replace('\x00', ' ').strip()
        except IOError:
            cmdline = ''

        # Get process owner
        try:
            stat_info = os.stat(f'/proc/{pid}')
            try:
                username = pwd.getpwuid(stat_info.st_uid).pw_name
            except KeyError:
                username = str(stat_info.st_uid)
        except OSError:
            username = '<unknown>'

        # Get PPID
        ppid = int(status.get('PPid', 0))

        return {
            'pid': pid,
            'name': name,
            'cmdline': cmdline if cmdline else f'[{name}]',
            'user': username,
            'ppid': ppid,
            'blocked': sig_blk,
            'ignored': sig_ign,
            'caught': sig_cgt,
        }

    except (IOError, OSError, ValueError, KeyError):
        return None


def analyze_process_signals(proc_info, check_blocked=True, check_ignored=True):
    """
    Analyze signal dispositions for concerning patterns.

    Args:
        proc_info: Process info dict from get_process_signal_info
        check_blocked: Whether to check for blocked signals
        check_ignored: Whether to check for ignored signals

    Returns:
        dict: Analysis results with issues found
    """
    issues = []
    severity = 'ok'

    name = proc_info['name']

    # Check ignored signals
    if check_ignored:
        concerning_ignored = proc_info['ignored'] & set(CONCERNING_IGNORED_SIGNALS.keys())
        for signum in concerning_ignored:
            signame = CONCERNING_IGNORED_SIGNALS[signum]
            # SIGTERM ignored is most severe
            if signum == 15:
                if name not in EXPECTED_SIGNAL_IGNORERS:
                    issues.append({
                        'type': 'ignored',
                        'signal': signame,
                        'signum': signum,
                        'severity': 'high',
                        'message': f'Process ignores {signame} - will not gracefully terminate'
                    })
                    severity = 'high'
            else:
                if name not in EXPECTED_SIGNAL_IGNORERS:
                    issues.append({
                        'type': 'ignored',
                        'signal': signame,
                        'signum': signum,
                        'severity': 'medium',
                        'message': f'Process ignores {signame}'
                    })
                    if severity != 'high':
                        severity = 'medium'

    # Check blocked signals
    if check_blocked:
        concerning_blocked = proc_info['blocked'] & set(CONCERNING_BLOCKED_SIGNALS.keys())
        for signum in concerning_blocked:
            signame = CONCERNING_BLOCKED_SIGNALS[signum]
            # Blocking SIGTERM is concerning
            if signum == 15:
                issues.append({
                    'type': 'blocked',
                    'signal': signame,
                    'signum': signum,
                    'severity': 'medium',
                    'message': f'Process blocks {signame} - may delay graceful termination'
                })
                if severity == 'ok':
                    severity = 'medium'

    return {
        'has_issues': len(issues) > 0,
        'severity': severity,
        'issues': issues
    }


def scan_all_processes(check_blocked=True, check_ignored=True, user_filter=None):
    """
    Scan all processes for signal disposition issues.

    Args:
        check_blocked: Whether to check for blocked signals
        check_ignored: Whether to check for ignored signals
        user_filter: Only check processes owned by this user

    Returns:
        list: Processes with concerning signal dispositions
    """
    results = []

    try:
        pids = [int(d) for d in os.listdir('/proc') if d.isdigit()]
    except OSError as e:
        print(f"Error: Could not list /proc: {e}", file=sys.stderr)
        return results

    for pid in pids:
        proc_info = get_process_signal_info(pid)
        if proc_info is None:
            continue

        # Apply user filter
        if user_filter and proc_info['user'] != user_filter:
            continue

        # Skip kernel threads (ppid 2 or name in brackets from cmdline)
        if proc_info['ppid'] == 2:
            continue
        if proc_info['cmdline'].startswith('[') and proc_info['cmdline'].endswith(']'):
            # Could be kernel thread or just unknown cmdline
            if proc_info['ppid'] == 2 or proc_info['ppid'] == 0:
                continue

        analysis = analyze_process_signals(proc_info, check_blocked, check_ignored)

        if analysis['has_issues']:
            proc_info['analysis'] = analysis
            results.append(proc_info)

    return results


def format_signals_list(signals):
    """Format a set of signal numbers as readable names."""
    return ', '.join(sorted([get_signal_name(s) for s in signals]))


def output_plain(results, verbose=False):
    """Output in plain text format."""
    if not results:
        print("No processes with concerning signal dispositions found")
        return

    # Group by severity
    high_severity = [r for r in results if r['analysis']['severity'] == 'high']
    medium_severity = [r for r in results if r['analysis']['severity'] == 'medium']

    print(f"Found {len(results)} process(es) with concerning signal dispositions")
    print()

    if high_severity:
        print(f"HIGH SEVERITY ({len(high_severity)} processes - ignoring SIGTERM):")
        print("-" * 70)
        for proc in sorted(high_severity, key=lambda x: x['name']):
            print(f"  PID {proc['pid']}: {proc['name']} (user: {proc['user']})")
            if verbose:
                print(f"    Command: {proc['cmdline'][:60]}...")
            for issue in proc['analysis']['issues']:
                print(f"    - {issue['message']}")
        print()

    if medium_severity:
        print(f"MEDIUM SEVERITY ({len(medium_severity)} processes):")
        print("-" * 70)
        for proc in sorted(medium_severity, key=lambda x: x['name']):
            print(f"  PID {proc['pid']}: {proc['name']} (user: {proc['user']})")
            if verbose:
                print(f"    Command: {proc['cmdline'][:60]}...")
            for issue in proc['analysis']['issues']:
                print(f"    - {issue['message']}")
        print()

    if verbose:
        print("Recommendations:")
        print("- Processes ignoring SIGTERM will not gracefully shut down")
        print("- Review application signal handlers before deployments")
        print("- Consider using SIGKILL as fallback after SIGTERM timeout")
        print("- Some system services legitimately ignore signals (systemd, containerd)")


def output_json(results):
    """Output in JSON format."""
    # Convert signal sets to lists for JSON serialization
    json_results = []
    for proc in results:
        proc_copy = proc.copy()
        proc_copy['blocked'] = list(proc['blocked'])
        proc_copy['ignored'] = list(proc['ignored'])
        proc_copy['caught'] = list(proc['caught'])
        proc_copy['blocked_names'] = [get_signal_name(s) for s in proc['blocked']]
        proc_copy['ignored_names'] = [get_signal_name(s) for s in proc['ignored']]
        json_results.append(proc_copy)

    output = {
        'total_concerning': len(results),
        'high_severity_count': len([r for r in results if r['analysis']['severity'] == 'high']),
        'medium_severity_count': len([r for r in results if r['analysis']['severity'] == 'medium']),
        'processes': json_results
    }
    print(json.dumps(output, indent=2, default=str))


def output_table(results, verbose=False):
    """Output in table format."""
    if not results:
        print("+" + "-" * 60 + "+")
        print("|" + " No concerning signal dispositions found".center(60) + "|")
        print("+" + "-" * 60 + "+")
        return

    print("+" + "-" * 78 + "+")
    print("|" + f" Signal Disposition Report: {len(results)} process(es) ".center(78) + "|")
    print("+" + "-" * 78 + "+")
    print(f"| {'PID':<8} {'Name':<16} {'User':<12} {'Severity':<10} {'Issues':<28} |")
    print("+" + "-" * 78 + "+")

    for proc in sorted(results, key=lambda x: (x['analysis']['severity'] != 'high', x['name'])):
        severity = proc['analysis']['severity'].upper()
        issues = ', '.join([i['signal'] for i in proc['analysis']['issues']])
        if len(issues) > 28:
            issues = issues[:25] + '...'
        print(f"| {proc['pid']:<8} {proc['name'][:16]:<16} {proc['user'][:12]:<12} "
              f"{severity:<10} {issues:<28} |")

    print("+" + "-" * 78 + "+")

    if verbose:
        print()
        print("To inspect a process: cat /proc/<PID>/status | grep Sig")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor process signal dispositions on baremetal systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all processes for signal issues
  baremetal_signal_disposition_monitor.py

  # JSON output for scripting
  baremetal_signal_disposition_monitor.py --format json

  # Only check for ignored signals (not blocked)
  baremetal_signal_disposition_monitor.py --no-blocked

  # Only check processes owned by a specific user
  baremetal_signal_disposition_monitor.py --user appuser

  # Verbose output with recommendations
  baremetal_signal_disposition_monitor.py --verbose

Signal masks from /proc/<pid>/status:
  SigBlk - Signals currently blocked by the process
  SigIgn - Signals the process is ignoring
  SigCgt - Signals the process has handlers for

Exit codes:
  0 - No processes with concerning signal dispositions
  1 - Processes with concerning dispositions found
  2 - Usage error or missing dependencies
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
        help='Show detailed information and recommendations'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if issues are found'
    )

    parser.add_argument(
        '--user',
        help='Only check processes owned by this user'
    )

    parser.add_argument(
        '--no-blocked',
        action='store_true',
        help='Do not check for blocked signals'
    )

    parser.add_argument(
        '--no-ignored',
        action='store_true',
        help='Do not check for ignored signals'
    )

    parser.add_argument(
        '--high-only',
        action='store_true',
        help='Only show high severity issues (SIGTERM ignored)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.no_blocked and args.no_ignored:
        print("Error: Cannot use both --no-blocked and --no-ignored", file=sys.stderr)
        sys.exit(2)

    # Scan processes
    check_blocked = not args.no_blocked
    check_ignored = not args.no_ignored

    results = scan_all_processes(
        check_blocked=check_blocked,
        check_ignored=check_ignored,
        user_filter=args.user
    )

    # Filter to high severity only if requested
    if args.high_only:
        results = [r for r in results if r['analysis']['severity'] == 'high']

    # Handle warn-only mode
    if args.warn_only and not results:
        sys.exit(0)

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.verbose)
    else:
        output_plain(results, args.verbose)

    # Exit code based on findings
    sys.exit(1 if results else 0)


if __name__ == '__main__':
    main()
