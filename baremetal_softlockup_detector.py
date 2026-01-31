#!/usr/bin/env python3
"""
Detect kernel softlockups, hung tasks, and RCU stalls from dmesg and sysctl.

Softlockups occur when the kernel detects that a CPU has been spinning in
kernel code for longer than the watchdog threshold (default 20 seconds)
without yielding. These indicate serious problems:
- Infinite loops in kernel code
- Interrupt storms preventing scheduling
- Severe lock contention
- Hardware problems (bad CPU, memory, etc.)

Hung tasks occur when a process is stuck in uninterruptible sleep (D state)
for longer than the hung_task_timeout threshold (default 120 seconds).

RCU (Read-Copy-Update) stalls indicate that RCU grace periods are not
completing, often due to a CPU being stuck in an RCU read-side critical
section.

This script:
- Parses dmesg for softlockup, hung_task, and RCU stall messages
- Checks current kernel watchdog configuration via sysctl
- Reports recent events with severity and timestamps
- Useful for post-mortem analysis and proactive monitoring

Exit codes:
    0 - No softlockups or hung tasks detected
    1 - Softlockups, hung tasks, or RCU stalls detected
    2 - Usage error or missing permissions
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone


def run_command(cmd):
    """Execute a command and return stdout, stderr, returncode."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -1
    except Exception as e:
        return "", str(e), -1


def get_dmesg_output():
    """Get dmesg output, trying different methods."""
    # Try dmesg command first
    stdout, stderr, rc = run_command(['dmesg', '-T', '--nopager'])
    if rc == 0 and stdout:
        return stdout, True  # Has timestamps

    # Try without timestamps
    stdout, stderr, rc = run_command(['dmesg', '--nopager'])
    if rc == 0 and stdout:
        return stdout, False  # No timestamps

    # Try reading from /dev/kmsg (requires root)
    stdout, stderr, rc = run_command(['dmesg'])
    if rc == 0 and stdout:
        return stdout, False

    # Last resort: try /var/log/kern.log
    try:
        with open('/var/log/kern.log', 'r') as f:
            return f.read(), True
    except (FileNotFoundError, PermissionError):
        pass

    return "", False


def get_sysctl_value(key):
    """Get a sysctl value."""
    try:
        with open(f'/proc/sys/{key.replace(".", "/")}', 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return None


def get_watchdog_config():
    """Get kernel watchdog configuration."""
    config = {}

    # Softlockup detector settings
    config['soft_watchdog'] = get_sysctl_value('kernel.soft_watchdog')
    config['softlockup_panic'] = get_sysctl_value('kernel.softlockup_panic')
    config['softlockup_all_cpu_backtrace'] = get_sysctl_value(
        'kernel.softlockup_all_cpu_backtrace'
    )

    # Hung task detector settings
    config['hung_task_timeout_secs'] = get_sysctl_value(
        'kernel.hung_task_timeout_secs'
    )
    config['hung_task_panic'] = get_sysctl_value('kernel.hung_task_panic')
    config['hung_task_check_count'] = get_sysctl_value(
        'kernel.hung_task_check_count'
    )
    config['hung_task_warnings'] = get_sysctl_value(
        'kernel.hung_task_warnings'
    )

    # Hardlockup detector
    config['hard_watchdog'] = get_sysctl_value('kernel.nmi_watchdog')
    config['hardlockup_panic'] = get_sysctl_value('kernel.hardlockup_panic')

    # Watchdog threshold
    config['watchdog_thresh'] = get_sysctl_value('kernel.watchdog_thresh')

    return {k: v for k, v in config.items() if v is not None}


def parse_softlockup_events(dmesg_output):
    """Parse softlockup events from dmesg."""
    events = []

    # Patterns for softlockup detection
    # Example: [12345.678901] watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [process:1234]
    softlockup_pattern = re.compile(
        r'\[?\s*(\d+\.\d+)\]?\s*'  # timestamp
        r'(?:watchdog:\s*)?'
        r'BUG:\s*soft\s+lockup\s*-?\s*'
        r'CPU#?(\d+)\s+stuck\s+for\s+(\d+)s[!]?\s*'
        r'\[([^\]]+):(\d+)\]',
        re.IGNORECASE
    )

    # Alternative pattern with human-readable timestamps
    softlockup_pattern_ts = re.compile(
        r'\[([A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+\d+\]\s*'
        r'(?:watchdog:\s*)?'
        r'BUG:\s*soft\s+lockup\s*-?\s*'
        r'CPU#?(\d+)\s+stuck\s+for\s+(\d+)s[!]?\s*'
        r'\[([^\]]+):(\d+)\]',
        re.IGNORECASE
    )

    for line in dmesg_output.split('\n'):
        # Try pattern with kernel timestamp
        match = softlockup_pattern.search(line)
        if match:
            events.append({
                'type': 'softlockup',
                'severity': 'CRITICAL',
                'timestamp_kernel': float(match.group(1)),
                'cpu': int(match.group(2)),
                'duration_secs': int(match.group(3)),
                'process': match.group(4),
                'pid': int(match.group(5)),
                'raw': line.strip()
            })
            continue

        # Try pattern with human-readable timestamp
        match = softlockup_pattern_ts.search(line)
        if match:
            events.append({
                'type': 'softlockup',
                'severity': 'CRITICAL',
                'timestamp_human': match.group(1),
                'cpu': int(match.group(2)),
                'duration_secs': int(match.group(3)),
                'process': match.group(4),
                'pid': int(match.group(5)),
                'raw': line.strip()
            })
            continue

        # Simpler pattern for partial matches
        if 'soft lockup' in line.lower() and 'CPU' in line:
            events.append({
                'type': 'softlockup',
                'severity': 'CRITICAL',
                'raw': line.strip()
            })

    return events


def parse_hung_task_events(dmesg_output):
    """Parse hung task events from dmesg."""
    events = []

    # Pattern for hung task detection
    # Example: [12345.678901] INFO: task kworker/0:0:1234 blocked for more than 120 seconds.
    hung_task_pattern = re.compile(
        r'\[?\s*(\d+\.\d+)\]?\s*'
        r'INFO:\s*task\s+(\S+):(\d+)\s+'
        r'blocked\s+for\s+more\s+than\s+(\d+)\s+seconds',
        re.IGNORECASE
    )

    # Pattern with human-readable timestamp
    hung_task_pattern_ts = re.compile(
        r'\[([A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+\d+\]\s*'
        r'INFO:\s*task\s+(\S+):(\d+)\s+'
        r'blocked\s+for\s+more\s+than\s+(\d+)\s+seconds',
        re.IGNORECASE
    )

    for line in dmesg_output.split('\n'):
        match = hung_task_pattern.search(line)
        if match:
            events.append({
                'type': 'hung_task',
                'severity': 'WARNING',
                'timestamp_kernel': float(match.group(1)),
                'process': match.group(2),
                'pid': int(match.group(3)),
                'duration_secs': int(match.group(4)),
                'raw': line.strip()
            })
            continue

        match = hung_task_pattern_ts.search(line)
        if match:
            events.append({
                'type': 'hung_task',
                'severity': 'WARNING',
                'timestamp_human': match.group(1),
                'process': match.group(2),
                'pid': int(match.group(3)),
                'duration_secs': int(match.group(4)),
                'raw': line.strip()
            })
            continue

        # Simpler pattern
        if 'blocked for more than' in line.lower() and 'task' in line.lower():
            events.append({
                'type': 'hung_task',
                'severity': 'WARNING',
                'raw': line.strip()
            })

    return events


def parse_rcu_stall_events(dmesg_output):
    """Parse RCU stall events from dmesg."""
    events = []

    # Pattern for RCU stalls
    # Example: [12345.678901] rcu: INFO: rcu_sched self-detected stall on CPU
    rcu_stall_pattern = re.compile(
        r'\[?\s*(\d+\.\d+)\]?\s*'
        r'(?:rcu:\s*)?'
        r'INFO:\s*(\w+)\s+'
        r'(?:self-)?detected\s+stall\s+on\s+CPU',
        re.IGNORECASE
    )

    # Pattern for RCU callback stalls
    rcu_callback_pattern = re.compile(
        r'\[?\s*(\d+\.\d+)\]?\s*'
        r'(?:rcu:\s*)?'
        r'(?:INFO:\s*)?'
        r'rcu.*stall',
        re.IGNORECASE
    )

    for line in dmesg_output.split('\n'):
        if 'rcu' in line.lower() and 'stall' in line.lower():
            match = rcu_stall_pattern.search(line)
            if match:
                events.append({
                    'type': 'rcu_stall',
                    'severity': 'CRITICAL',
                    'timestamp_kernel': float(match.group(1)),
                    'rcu_type': match.group(2),
                    'raw': line.strip()
                })
            else:
                events.append({
                    'type': 'rcu_stall',
                    'severity': 'CRITICAL',
                    'raw': line.strip()
                })

    return events


def parse_hardlockup_events(dmesg_output):
    """Parse hardlockup events from dmesg."""
    events = []

    # Pattern for hardlockup detection
    # Example: [12345.678901] NMI watchdog: Watchdog detected hard LOCKUP on cpu 0
    hardlockup_pattern = re.compile(
        r'\[?\s*(\d+\.\d+)\]?\s*'
        r'(?:NMI\s+)?watchdog:\s*'
        r'(?:Watchdog\s+)?detected\s+hard\s+LOCKUP\s+on\s+cpu\s+(\d+)',
        re.IGNORECASE
    )

    for line in dmesg_output.split('\n'):
        if 'hard' in line.lower() and 'lockup' in line.lower():
            match = hardlockup_pattern.search(line)
            if match:
                events.append({
                    'type': 'hardlockup',
                    'severity': 'CRITICAL',
                    'timestamp_kernel': float(match.group(1)),
                    'cpu': int(match.group(2)),
                    'raw': line.strip()
                })
            else:
                events.append({
                    'type': 'hardlockup',
                    'severity': 'CRITICAL',
                    'raw': line.strip()
                })

    return events


def get_current_stuck_processes():
    """Find processes currently in D (uninterruptible sleep) state."""
    stuck = []

    try:
        # Use ps to find D state processes
        stdout, stderr, rc = run_command([
            'ps', 'axo', 'pid,state,wchan:32,comm', '--no-headers'
        ])
        if rc != 0:
            return stuck

        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4 and parts[1] == 'D':
                stuck.append({
                    'pid': int(parts[0]),
                    'state': parts[1],
                    'wchan': parts[2],
                    'comm': ' '.join(parts[3:])
                })
    except Exception:
        pass

    return stuck


def output_plain(events, config, stuck_procs, verbose=False, warn_only=False):
    """Output in plain text format."""
    if warn_only and not events and not stuck_procs:
        return

    total_events = len(events)
    has_issues = total_events > 0 or len(stuck_procs) > 0

    if not warn_only:
        print("Kernel Softlockup / Hung Task Detector")
        print("=" * 55)
        print()

        # Show watchdog configuration
        print("Watchdog Configuration:")
        print("-" * 55)
        if config:
            wd_enabled = config.get('soft_watchdog', '?')
            wd_thresh = config.get('watchdog_thresh', '?')
            hung_timeout = config.get('hung_task_timeout_secs', '?')
            nmi_wd = config.get('hard_watchdog', '?')

            print(f"  Soft watchdog:        {'enabled' if wd_enabled == '1' else 'disabled' if wd_enabled == '0' else wd_enabled}")
            print(f"  NMI watchdog:         {'enabled' if nmi_wd == '1' else 'disabled' if nmi_wd == '0' else nmi_wd}")
            print(f"  Watchdog threshold:   {wd_thresh}s")
            print(f"  Hung task timeout:    {hung_timeout}s")

            if config.get('softlockup_panic') == '1':
                print("  [!] System will PANIC on softlockup")
            if config.get('hung_task_panic') == '1':
                print("  [!] System will PANIC on hung task")
        else:
            print("  Unable to read watchdog configuration")
        print()

    # Show current D-state processes
    if stuck_procs:
        print("Processes in Uninterruptible Sleep (D state):")
        print("-" * 55)
        print(f"  {'PID':<8} {'WCHAN':<32} {'COMMAND'}")
        for proc in stuck_procs[:10]:  # Limit to 10
            print(f"  {proc['pid']:<8} {proc['wchan']:<32} {proc['comm']}")
        if len(stuck_procs) > 10:
            print(f"  ... and {len(stuck_procs) - 10} more")
        print()

    # Show detected events
    if events:
        # Group by type
        by_type = {}
        for event in events:
            t = event['type']
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(event)

        print("Detected Events:")
        print("-" * 55)

        type_names = {
            'softlockup': 'Soft Lockups',
            'hardlockup': 'Hard Lockups',
            'hung_task': 'Hung Tasks',
            'rcu_stall': 'RCU Stalls'
        }

        for event_type, type_events in by_type.items():
            print(f"\n  {type_names.get(event_type, event_type)}: {len(type_events)} event(s)")
            if verbose:
                for event in type_events[-5:]:  # Show last 5
                    if 'cpu' in event:
                        print(f"    CPU {event['cpu']}: {event.get('process', 'unknown')} "
                              f"(stuck {event.get('duration_secs', '?')}s)")
                    elif 'process' in event:
                        print(f"    {event['process']} (PID {event.get('pid', '?')}, "
                              f"blocked {event.get('duration_secs', '?')}s)")
                    else:
                        print(f"    {event.get('raw', 'Unknown event')[:60]}")
        print()

    # Summary
    if not warn_only:
        if has_issues:
            print("Summary:")
            print("-" * 55)
            print(f"  Total dmesg events:   {total_events}")
            print(f"  Current D-state:      {len(stuck_procs)}")
            print()
            print("[!] Issues detected - investigate system stability")
        else:
            print("[OK] No softlockups, hung tasks, or RCU stalls detected")


def output_json(events, config, stuck_procs):
    """Output in JSON format."""
    # Count by type
    by_type = {}
    for event in events:
        t = event['type']
        by_type[t] = by_type.get(t, 0) + 1

    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'summary': {
            'total_events': len(events),
            'softlockups': by_type.get('softlockup', 0),
            'hardlockups': by_type.get('hardlockup', 0),
            'hung_tasks': by_type.get('hung_task', 0),
            'rcu_stalls': by_type.get('rcu_stall', 0),
            'current_d_state_procs': len(stuck_procs),
            'has_issues': len(events) > 0 or len(stuck_procs) > 0
        },
        'config': config,
        'stuck_processes': stuck_procs[:20],  # Limit
        'events': events[-50],  # Last 50 events
        'healthy': len(events) == 0
    }
    print(json.dumps(output, indent=2, default=str))


def output_table(events, config, stuck_procs, warn_only=False):
    """Output in table format."""
    if warn_only and not events and not stuck_procs:
        return

    # Summary table
    by_type = {}
    for event in events:
        t = event['type']
        by_type[t] = by_type.get(t, 0) + 1

    print(f"{'Event Type':<20} {'Count':>10} {'Severity':<10}")
    print("=" * 42)
    print(f"{'Soft Lockups':<20} {by_type.get('softlockup', 0):>10} {'CRITICAL':<10}")
    print(f"{'Hard Lockups':<20} {by_type.get('hardlockup', 0):>10} {'CRITICAL':<10}")
    print(f"{'Hung Tasks':<20} {by_type.get('hung_task', 0):>10} {'WARNING':<10}")
    print(f"{'RCU Stalls':<20} {by_type.get('rcu_stall', 0):>10} {'CRITICAL':<10}")
    print(f"{'D-State Processes':<20} {len(stuck_procs):>10} {'INFO':<10}")
    print("=" * 42)
    print(f"{'TOTAL':<20} {len(events):>10}")


def main():
    parser = argparse.ArgumentParser(
        description='Detect kernel softlockups, hung tasks, and RCU stalls',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Basic check for lockup events
  %(prog)s -v                 # Show detailed event information
  %(prog)s --format json      # JSON output for monitoring
  %(prog)s --warn-only        # Only output if issues found

What these events mean:
  Softlockup: CPU stuck in kernel code without yielding for >20s
              Indicates infinite loop, severe lock contention, or HW issue

  Hardlockup: CPU not responding to NMI (Non-Maskable Interrupt)
              More severe than softlockup, often hardware-related

  Hung Task:  Process stuck in uninterruptible sleep (D state) for >120s
              Often caused by I/O issues, NFS hangs, or driver problems

  RCU Stall:  Read-Copy-Update mechanism stuck, delays grace periods
              Can cascade to other CPU stalls

Remediation:
  1. Check hardware: memory, CPU, disk controller
  2. Review recent kernel/driver updates
  3. Check for I/O issues (NFS mounts, disk errors)
  4. Look for kernel bugs in your version

Exit codes:
  0 - No issues detected
  1 - Softlockups, hung tasks, or other issues detected
  2 - Unable to read dmesg or permission denied
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed event information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues detected'
    )

    args = parser.parse_args()

    # Get dmesg output
    dmesg_output, has_timestamps = get_dmesg_output()
    if not dmesg_output:
        print("Error: Unable to read dmesg", file=sys.stderr)
        print("Try running with sudo or check permissions", file=sys.stderr)
        sys.exit(2)

    # Get watchdog configuration
    config = get_watchdog_config()

    # Parse events
    events = []
    events.extend(parse_softlockup_events(dmesg_output))
    events.extend(parse_hardlockup_events(dmesg_output))
    events.extend(parse_hung_task_events(dmesg_output))
    events.extend(parse_rcu_stall_events(dmesg_output))

    # Get current D-state processes
    stuck_procs = get_current_stuck_processes()

    # Output
    if args.format == 'json':
        output_json(events, config, stuck_procs)
    elif args.format == 'table':
        output_table(events, config, stuck_procs, warn_only=args.warn_only)
    else:
        output_plain(events, config, stuck_procs,
                    verbose=args.verbose, warn_only=args.warn_only)

    # Exit code
    if events or len(stuck_procs) > 5:  # 5+ D-state procs is concerning
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    sys.exit(main())
