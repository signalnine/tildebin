#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [kernel, softlockup, hung, rcu, watchdog, stability]
#   requires: [dmesg, ps]
#   privilege: root
#   related: [kernel_lockup_detector, dmesg_analyzer, kernel_taint]
#   brief: Detect kernel softlockups, hung tasks, and RCU stalls

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
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


SYSCTL_PATHS = {
    'soft_watchdog': '/proc/sys/kernel/soft_watchdog',
    'softlockup_panic': '/proc/sys/kernel/softlockup_panic',
    'softlockup_all_cpu_backtrace': '/proc/sys/kernel/softlockup_all_cpu_backtrace',
    'hung_task_timeout_secs': '/proc/sys/kernel/hung_task_timeout_secs',
    'hung_task_panic': '/proc/sys/kernel/hung_task_panic',
    'hung_task_check_count': '/proc/sys/kernel/hung_task_check_count',
    'hung_task_warnings': '/proc/sys/kernel/hung_task_warnings',
    'hard_watchdog': '/proc/sys/kernel/nmi_watchdog',
    'hardlockup_panic': '/proc/sys/kernel/hardlockup_panic',
    'watchdog_thresh': '/proc/sys/kernel/watchdog_thresh',
}


def get_sysctl_value(context: Context, key: str) -> str | None:
    """Get a sysctl value."""
    path = SYSCTL_PATHS.get(key) or f'/proc/sys/{key.replace(".", "/")}'
    try:
        return context.read_file(path).strip()
    except (FileNotFoundError, PermissionError):
        return None


def get_watchdog_config(context: Context) -> dict[str, str | None]:
    """Get kernel watchdog configuration."""
    config = {}
    for key in SYSCTL_PATHS:
        config[key] = get_sysctl_value(context, key)
    return {k: v for k, v in config.items() if v is not None}


def parse_softlockup_events(dmesg_output: str) -> list[dict[str, Any]]:
    """Parse softlockup events from dmesg."""
    events = []

    softlockup_pattern = re.compile(
        r'\[?\s*(\d+\.\d+)\]?\s*'
        r'(?:watchdog:\s*)?'
        r'BUG:\s*soft\s+lockup\s*-?\s*'
        r'CPU#?(\d+)\s+stuck\s+for\s+(\d+)s[!]?\s*'
        r'\[([^\]]+):(\d+)\]',
        re.IGNORECASE
    )

    for line in dmesg_output.split('\n'):
        match = softlockup_pattern.search(line)
        if match:
            events.append({
                'type': 'softlockup',
                'severity': 'critical',
                'timestamp_kernel': float(match.group(1)),
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
                'severity': 'critical',
                'raw': line.strip()
            })

    return events


def parse_hung_task_events(dmesg_output: str) -> list[dict[str, Any]]:
    """Parse hung task events from dmesg."""
    events = []

    hung_task_pattern = re.compile(
        r'\[?\s*(\d+\.\d+)\]?\s*'
        r'INFO:\s*task\s+(\S+):(\d+)\s+'
        r'blocked\s+for\s+more\s+than\s+(\d+)\s+seconds',
        re.IGNORECASE
    )

    for line in dmesg_output.split('\n'):
        match = hung_task_pattern.search(line)
        if match:
            events.append({
                'type': 'hung_task',
                'severity': 'warning',
                'timestamp_kernel': float(match.group(1)),
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
                'severity': 'warning',
                'raw': line.strip()
            })

    return events


def parse_rcu_stall_events(dmesg_output: str) -> list[dict[str, Any]]:
    """Parse RCU stall events from dmesg."""
    events = []

    rcu_stall_pattern = re.compile(
        r'\[?\s*(\d+\.\d+)\]?\s*'
        r'(?:rcu:\s*)?'
        r'INFO:\s*(\w+)\s+'
        r'(?:self-)?detected\s+stall\s+on\s+CPU',
        re.IGNORECASE
    )

    for line in dmesg_output.split('\n'):
        if 'rcu' in line.lower() and 'stall' in line.lower():
            match = rcu_stall_pattern.search(line)
            if match:
                events.append({
                    'type': 'rcu_stall',
                    'severity': 'critical',
                    'timestamp_kernel': float(match.group(1)),
                    'rcu_type': match.group(2),
                    'raw': line.strip()
                })
            else:
                events.append({
                    'type': 'rcu_stall',
                    'severity': 'critical',
                    'raw': line.strip()
                })

    return events


def parse_hardlockup_events(dmesg_output: str) -> list[dict[str, Any]]:
    """Parse hardlockup events from dmesg."""
    events = []

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
                    'severity': 'critical',
                    'timestamp_kernel': float(match.group(1)),
                    'cpu': int(match.group(2)),
                    'raw': line.strip()
                })
            else:
                events.append({
                    'type': 'hardlockup',
                    'severity': 'critical',
                    'raw': line.strip()
                })

    return events


def get_current_stuck_processes(context: Context) -> list[dict[str, Any]]:
    """Find processes currently in D (uninterruptible sleep) state."""
    stuck = []

    try:
        result = context.run(
            ['ps', 'axo', 'pid,state,wchan:32,comm', '--no-headers'],
            check=False
        )
        if result.returncode != 0:
            return stuck

        for line in result.stdout.strip().split('\n'):
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
    parser = argparse.ArgumentParser(
        description="Detect kernel softlockups, hung tasks, and RCU stalls"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed event information")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for dmesg command
    if not context.check_tool("dmesg"):
        output.error("dmesg command not found")

        output.render(opts.format, "Detect kernel softlockups, hung tasks, and RCU stalls")
        return 2

    # Get dmesg output
    try:
        result = context.run(['dmesg', '-T', '--nopager'], check=False)
        if result.returncode != 0:
            # Try without timestamps
            result = context.run(['dmesg', '--nopager'], check=False)
        if result.returncode != 0:
            result = context.run(['dmesg'], check=False)

        dmesg_output = result.stdout
    except Exception as e:
        output.error(f"Unable to read dmesg: {e}")

        output.render(opts.format, "Detect kernel softlockups, hung tasks, and RCU stalls")
        return 2

    if not dmesg_output:
        output.error("Unable to read dmesg - try running with sudo")

        output.render(opts.format, "Detect kernel softlockups, hung tasks, and RCU stalls")
        return 2

    # Get watchdog configuration
    config = get_watchdog_config(context)

    # Parse events
    events = []
    events.extend(parse_softlockup_events(dmesg_output))
    events.extend(parse_hardlockup_events(dmesg_output))
    events.extend(parse_hung_task_events(dmesg_output))
    events.extend(parse_rcu_stall_events(dmesg_output))

    # Get current D-state processes
    stuck_procs = []
    if context.check_tool("ps"):
        stuck_procs = get_current_stuck_processes(context)

    # Count by type
    by_type: dict[str, int] = {}
    for event in events:
        t = event['type']
        by_type[t] = by_type.get(t, 0) + 1

    has_issues = len(events) > 0 or len(stuck_procs) > 5

    # Build result
    result_data = {
        'status': 'critical' if has_issues else 'ok',
        'summary': {
            'total_events': len(events),
            'softlockups': by_type.get('softlockup', 0),
            'hardlockups': by_type.get('hardlockup', 0),
            'hung_tasks': by_type.get('hung_task', 0),
            'rcu_stalls': by_type.get('rcu_stall', 0),
            'current_d_state_procs': len(stuck_procs),
            'has_issues': has_issues
        },
        'config': config,
        'stuck_processes': stuck_procs[:20] if opts.verbose else [],
        'events': events[-50:] if events else [],
    }

    output.emit(result_data)

    # Set summary
    if has_issues:
        parts = []
        if by_type.get('softlockup', 0):
            parts.append(f"{by_type['softlockup']} softlockups")
        if by_type.get('hardlockup', 0):
            parts.append(f"{by_type['hardlockup']} hardlockups")
        if by_type.get('hung_task', 0):
            parts.append(f"{by_type['hung_task']} hung tasks")
        if by_type.get('rcu_stall', 0):
            parts.append(f"{by_type['rcu_stall']} RCU stalls")
        if stuck_procs:
            parts.append(f"{len(stuck_procs)} D-state procs")
        output.set_summary(", ".join(parts) if parts else "Issues detected")
    else:
        output.set_summary("No softlockups, hung tasks, or RCU stalls detected")

    output.render(opts.format, "Detect kernel softlockups, hung tasks, and RCU stalls")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
