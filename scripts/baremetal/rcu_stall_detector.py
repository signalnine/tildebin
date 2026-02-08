#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [kernel, rcu, stall, stability, latency]
#   requires: []
#   privilege: root
#   related: [kernel_lockup_detector, softlockup, dmesg_analyzer]
#   brief: Detect RCU stall warnings indicating kernel scheduling issues

"""
Detect RCU stall warnings indicating kernel scheduling issues.

RCU (Read-Copy-Update) stalls occur when a CPU is stuck in an RCU read-side
critical section or when the RCU grace period machinery is unable to make
progress. These indicate serious kernel scheduling problems that can lead
to system hangs.

Checks:
- dmesg output for RCU stall patterns (self-detected stalls, kthread starvation)
- /proc/sys/kernel/rcu_expedited for expedited grace period mode

Exit codes:
    0 - No RCU stalls detected
    1 - RCU stalls or starvation detected
    2 - Error (dmesg unavailable)
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Patterns indicating RCU stalls in dmesg
STALL_PATTERNS = [
    (re.compile(r'rcu_sched self-detected stall', re.IGNORECASE), 'CRITICAL', 'rcu_sched_stall'),
    (re.compile(r'rcu_preempt self-detected stall', re.IGNORECASE), 'CRITICAL', 'rcu_preempt_stall'),
    (re.compile(r'rcu: INFO: rcu_\w+ detected stall', re.IGNORECASE), 'CRITICAL', 'rcu_detected_stall'),
    (re.compile(r'rcu_sched kthread starved', re.IGNORECASE), 'WARNING', 'rcu_sched_starved'),
    (re.compile(r'rcu_preempt kthread starved', re.IGNORECASE), 'WARNING', 'rcu_preempt_starved'),
]


def parse_dmesg_for_rcu(dmesg_output: str) -> list[dict[str, Any]]:
    """Parse dmesg output for RCU stall patterns.

    Returns list of matches with severity, type, and the matching line.
    """
    matches = []
    seen_types: set[str] = set()

    for line in dmesg_output.split('\n'):
        line = line.strip()
        if not line:
            continue

        for pattern, severity, stall_type in STALL_PATTERNS:
            if pattern.search(line):
                matches.append({
                    'severity': severity,
                    'type': stall_type,
                    'line': line,
                })
                seen_types.add(stall_type)
                break  # Only match first pattern per line

    return matches


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no stalls, 1 = stalls detected, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Detect RCU stall warnings indicating kernel scheduling issues"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all matched lines")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Run dmesg
    try:
        result = context.run(['dmesg'], check=True)
    except Exception as e:
        output.error(f"Failed to run dmesg: {e}")
        output.render(opts.format, "RCU Stall Detection")
        return 2

    dmesg_output = result.stdout

    # Parse for RCU stall patterns
    matches = parse_dmesg_for_rcu(dmesg_output)

    # Check rcu_expedited
    rcu_expedited = None
    try:
        content = context.read_file('/proc/sys/kernel/rcu_expedited')
        rcu_expedited = content.strip()
    except (FileNotFoundError, Exception):
        pass

    # Build issues
    issues: list[dict[str, Any]] = []

    # Deduplicate by type for issue reporting
    seen_types: dict[str, str] = {}
    for match in matches:
        if match['type'] not in seen_types:
            seen_types[match['type']] = match['severity']
            issues.append({
                'severity': match['severity'],
                'type': match['type'],
                'message': f"RCU issue detected: {match['line'][:200]}",
            })

    if rcu_expedited == '1':
        issues.append({
            'severity': 'INFO',
            'type': 'rcu_expedited',
            'message': 'RCU expedited grace periods enabled (higher CPU overhead)',
        })

    # Emit data
    data: dict[str, Any] = {
        'stall_count': len(matches),
        'unique_types': list(seen_types.keys()),
        'issues': issues,
        'rcu_expedited': rcu_expedited,
    }

    if opts.verbose:
        data['matches'] = matches

    output.emit(data)

    # Summary
    critical = sum(1 for i in issues if i['severity'] == 'CRITICAL')
    warning = sum(1 for i in issues if i['severity'] == 'WARNING')
    if critical > 0:
        output.set_summary(f"{critical} critical RCU stalls, {warning} warnings")
    elif warning > 0:
        output.set_summary(f"{warning} RCU warnings")
    else:
        output.set_summary("no RCU stalls detected")

    output.render(opts.format, "RCU Stall Detection")

    has_issues = any(i['severity'] in ('CRITICAL', 'WARNING') for i in issues)
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
