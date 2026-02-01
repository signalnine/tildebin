#!/usr/bin/env python3
# boxctl:
#   category: baremetal/kernel
#   tags: [health, kernel, stability, lockup, hung, rcu]
#   requires: [dmesg]
#   brief: Detect kernel lockups, RCU stalls, and hung tasks

"""
Detect kernel lockups, RCU stalls, and hung tasks on Linux systems.

Monitors kernel messages for indicators of system instability:
- Soft lockups (CPU stuck in kernel mode with interrupts enabled)
- Hard lockups (CPU stuck with interrupts disabled)
- RCU stalls (Read-Copy-Update mechanism blocked)
- Hung tasks (processes stuck in uninterruptible sleep)
- Kernel panics and oops messages

Exit codes:
    0: No lockup indicators detected
    1: Lockup warnings or issues detected
    2: Usage error or missing dependencies
"""

import argparse
import json
import re
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Patterns to detect various kernel issues
LOCKUP_PATTERNS = {
    "soft_lockup": (
        re.compile(r"(soft lockup|softlockup)", re.IGNORECASE),
        "WARNING",
        "CPU stuck in kernel mode with interrupts enabled",
    ),
    "hard_lockup": (
        re.compile(r"(hard lockup|hardlockup|NMI watchdog.*hard LOCKUP)", re.IGNORECASE),
        "CRITICAL",
        "CPU stuck with interrupts disabled",
    ),
    "rcu_stall": (
        re.compile(r"(rcu.*stall|RCU.*detected stall)", re.IGNORECASE),
        "WARNING",
        "RCU mechanism blocked",
    ),
    "hung_task": (
        re.compile(r"(hung_task|blocked for more than \d+ seconds)", re.IGNORECASE),
        "WARNING",
        "Process stuck in uninterruptible sleep",
    ),
    "kernel_panic": (
        re.compile(r"(Kernel panic|kernel BUG)", re.IGNORECASE),
        "CRITICAL",
        "Kernel panic or BUG",
    ),
    "oops": (
        re.compile(r"(Oops:|general protection fault)", re.IGNORECASE),
        "WARNING",
        "Kernel oops or protection fault",
    ),
    "mce": (
        re.compile(r"(Machine check|mce:.*Hardware Error)", re.IGNORECASE),
        "CRITICAL",
        "Machine check exception (hardware error)",
    ),
    "watchdog": (
        re.compile(r"(watchdog.*timeout|watchdog.*didn't)", re.IGNORECASE),
        "WARNING",
        "Watchdog timeout",
    ),
}


def parse_dmesg_for_lockups(dmesg_output: str) -> list[dict[str, Any]]:
    """Parse dmesg output for lockup-related messages."""
    lockups = []

    for line in dmesg_output.splitlines():
        line = line.strip()
        if not line:
            continue

        for lockup_type, (pattern, severity, description) in LOCKUP_PATTERNS.items():
            if pattern.search(line):
                lockups.append(
                    {
                        "type": lockup_type,
                        "severity": severity,
                        "description": description,
                        "message": line[:500],  # Truncate long lines
                    }
                )
                break  # Only match once per line

    return lockups


def get_kernel_config(context: Context) -> dict[str, Any]:
    """Get kernel lockup detection configuration."""
    config: dict[str, Any] = {
        "softlockup_panic": None,
        "hardlockup_panic": None,
        "hung_task_panic": None,
        "hung_task_timeout_secs": None,
        "watchdog_thresh": None,
        "nmi_watchdog": None,
    }

    sysctl_paths = {
        "softlockup_panic": "/proc/sys/kernel/softlockup_panic",
        "hardlockup_panic": "/proc/sys/kernel/hardlockup_panic",
        "hung_task_panic": "/proc/sys/kernel/hung_task_panic",
        "hung_task_timeout_secs": "/proc/sys/kernel/hung_task_timeout_secs",
        "watchdog_thresh": "/proc/sys/kernel/watchdog_thresh",
        "nmi_watchdog": "/proc/sys/kernel/nmi_watchdog",
    }

    for key, path in sysctl_paths.items():
        try:
            content = context.read_file(path)
            config[key] = int(content.strip())
        except (FileNotFoundError, ValueError, IOError):
            pass

    return config


def get_hung_tasks(context: Context) -> list[dict[str, str]]:
    """Check for currently hung tasks (processes in D state)."""
    hung_tasks = []

    try:
        result = context.run(["ps", "-eo", "pid,stat,wchan:32,comm", "--no-headers"])
        for line in result.stdout.splitlines():
            parts = line.split(None, 3)
            if len(parts) >= 4:
                pid, stat, wchan, comm = parts
                if "D" in stat:
                    hung_tasks.append(
                        {
                            "pid": pid,
                            "state": stat,
                            "wchan": wchan,
                            "command": comm,
                        }
                    )
    except Exception:
        pass

    return hung_tasks


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
        description="Detect kernel lockups, RCU stalls, and hung tasks"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--format", choices=["plain", "json"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show warnings and errors"
    )
    parser.add_argument(
        "--hung-task-threshold",
        type=int,
        default=5,
        metavar="N",
        help="Number of D-state processes to trigger warning (default: 5)",
    )
    opts = parser.parse_args(args)

    # Check for dmesg
    if not context.check_tool("dmesg"):
        output.error("dmesg not found")
        return 2

    # Get dmesg output
    try:
        dmesg_result = context.run(["dmesg", "-T"], check=False)
        if dmesg_result.returncode != 0:
            # Try without -T flag
            dmesg_result = context.run(["dmesg"], check=False)
        dmesg_output = dmesg_result.stdout
    except Exception as e:
        output.error(f"Failed to run dmesg: {e}")
        return 2

    # Parse for lockups
    lockups = parse_dmesg_for_lockups(dmesg_output)

    # Get kernel config
    config = get_kernel_config(context)

    # Get currently hung tasks
    hung_tasks = get_hung_tasks(context)

    # Build issues list
    issues: list[dict[str, Any]] = []

    for lockup in lockups:
        issues.append(
            {
                "severity": lockup["severity"],
                "type": lockup["type"],
                "message": lockup["message"],
                "description": lockup["description"],
            }
        )

    # Check hung task count
    if len(hung_tasks) >= opts.hung_task_threshold:
        issues.append(
            {
                "severity": "WARNING",
                "type": "current_hung_tasks",
                "message": f"Found {len(hung_tasks)} processes in uninterruptible sleep (D state)",
                "description": "Possible hung tasks",
            }
        )

    # Check kernel configuration warnings
    if config.get("nmi_watchdog") == 0:
        issues.append(
            {
                "severity": "INFO",
                "type": "config",
                "message": "NMI watchdog disabled - hard lockups may not be detected",
                "description": "Configuration warning",
            }
        )

    if config.get("hung_task_timeout_secs") == 0:
        issues.append(
            {
                "severity": "INFO",
                "type": "config",
                "message": "hung_task detection disabled (timeout=0)",
                "description": "Configuration warning",
            }
        )

    # Count by severity
    critical_count = sum(1 for i in issues if i["severity"] == "CRITICAL")
    warning_count = sum(1 for i in issues if i["severity"] == "WARNING")
    info_count = sum(1 for i in issues if i["severity"] == "INFO")

    # Build result
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_events": len(lockups),
            "critical_count": critical_count,
            "warning_count": warning_count,
            "info_count": info_count,
            "hung_task_count": len(hung_tasks),
        },
        "issues": issues,
        "kernel_config": config,
        "hung_tasks": hung_tasks if opts.verbose else [],
    }

    # Output handling
    if opts.format == "json":
        print(json.dumps(result, indent=2))
    else:
        lines = []

        if not opts.warn_only:
            lines.append("Kernel Lockup Detection Summary")
            lines.append(f"Critical events: {critical_count}")
            lines.append(f"Warning events: {warning_count}")
            lines.append(f"Processes in D state: {len(hung_tasks)}")
            lines.append("")

            if opts.verbose:
                lines.append("Kernel Configuration:")
                if config.get("watchdog_thresh"):
                    lines.append(f"  Watchdog threshold: {config['watchdog_thresh']}s")
                if config.get("hung_task_timeout_secs"):
                    lines.append(f"  Hung task timeout: {config['hung_task_timeout_secs']}s")
                if config.get("nmi_watchdog") is not None:
                    status = "enabled" if config["nmi_watchdog"] else "disabled"
                    lines.append(f"  NMI watchdog: {status}")
                lines.append("")

                if hung_tasks:
                    lines.append("Processes in D state (uninterruptible sleep):")
                    for task in hung_tasks[:10]:
                        lines.append(
                            f"  PID {task['pid']}: {task['command']} (wchan: {task['wchan']})"
                        )
                    if len(hung_tasks) > 10:
                        lines.append(f"  ... and {len(hung_tasks) - 10} more")
                    lines.append("")

        # Issues
        for issue in issues:
            if opts.warn_only and issue["severity"] == "INFO":
                continue
            prefix = f"[{issue['severity']}]"
            msg = issue["message"][:100]
            lines.append(f"{prefix} {issue['type']}: {msg}")

        if not issues and not opts.warn_only:
            lines.append("No kernel lockup issues detected.")

        print("\n".join(lines))

    # Store data for output helper
    output.emit(result)
    output.set_summary(f"critical={critical_count}, warnings={warning_count}")

    # Exit based on findings
    return 1 if critical_count > 0 or warning_count > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
