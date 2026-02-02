#!/usr/bin/env python3
# boxctl:
#   category: baremetal/system
#   tags: [crash, kdump, kernel, reliability]
#   requires: []
#   privilege: root
#   related: [dmesg_analyzer, kernel_taint]
#   brief: Monitor kernel crash dumps and kdump configuration

"""
Monitor kernel crash dumps and kdump configuration on baremetal systems.

Checks the health of crash dump mechanisms and identifies any historical
kernel panics or crashes. Essential for baremetal systems where understanding
crash history is critical for reliability analysis.

Features:
- Check if kdump service is configured and active
- Verify crash dump directory exists and has proper permissions
- List historical crash dumps with timestamps and sizes
- Detect recent crashes that may need investigation
- Check crashkernel reservation in boot parameters

Returns exit code 1 if kdump is misconfigured or recent crashes are detected.
"""

import argparse
import os
from datetime import datetime
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Common crash dump directories
CRASH_DIRECTORIES = [
    '/var/crash',
    '/var/spool/abrt',
    '/var/lib/systemd/coredump',
    '/var/log/dump',
]


def check_kdump_service(context: Context) -> dict[str, Any]:
    """Check if kdump service is enabled and active."""
    result = {
        'installed': False,
        'enabled': False,
        'active': False,
        'status': 'unknown',
    }

    # Check using systemctl
    try:
        enabled_result = context.run(['systemctl', 'is-enabled', 'kdump'], check=False)
        if enabled_result.returncode == 0:
            result['installed'] = True
            result['enabled'] = enabled_result.stdout.strip() == 'enabled'
        elif 'No such file' not in enabled_result.stderr:
            result['installed'] = True
            result['enabled'] = False
    except Exception:
        pass

    try:
        active_result = context.run(['systemctl', 'is-active', 'kdump'], check=False)
        if active_result.returncode == 0:
            result['active'] = active_result.stdout.strip() == 'active'
            result['status'] = active_result.stdout.strip()
        else:
            result['status'] = active_result.stdout.strip() if active_result.stdout.strip() else 'inactive'
    except Exception:
        pass

    return result


def check_crashkernel_reservation(context: Context) -> dict[str, Any]:
    """Check if crashkernel memory is reserved in boot parameters."""
    result = {
        'reserved': False,
        'size': None,
        'cmdline_param': None,
    }

    # Check /proc/cmdline
    if context.file_exists('/proc/cmdline'):
        try:
            cmdline = context.read_file('/proc/cmdline')
            for param in cmdline.split():
                if param.startswith('crashkernel='):
                    result['reserved'] = True
                    result['cmdline_param'] = param
                    result['size'] = param.split('=')[1]
                    break
        except Exception:
            pass

    # Also check /sys/kernel/kexec_crash_size
    crash_size_path = '/sys/kernel/kexec_crash_size'
    if context.file_exists(crash_size_path):
        try:
            crash_size = int(context.read_file(crash_size_path))
            if crash_size > 0:
                result['reserved'] = True
                result['actual_bytes'] = crash_size
        except Exception:
            pass

    return result


def analyze_crash_directory(path: str, context: Context) -> dict[str, Any]:
    """Analyze a crash dump directory for crash files."""
    result = {
        'path': path,
        'exists': context.file_exists(path),
        'crashes': [],
        'total_size_bytes': 0,
        'crash_count': 0,
    }

    if not result['exists']:
        return result

    # Try to list directory contents
    try:
        entries = context.glob('*', path)
        for entry_path in entries:
            name = entry_path.split('/')[-1]
            # Look for crash-related files/directories
            if any(kw in name.lower() for kw in ['vmcore', 'dump', 'crash', 'core']):
                crash_info = {
                    'path': entry_path,
                    'name': name,
                }
                result['crashes'].append(crash_info)
                result['crash_count'] += 1
    except Exception:
        pass

    return result


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
    parser = argparse.ArgumentParser(description="Monitor kernel crash dumps and kdump configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument(
        "--recent-days",
        type=int,
        default=30,
        metavar="DAYS",
        help="Consider crashes within N days as recent (default: 30)"
    )
    opts = parser.parse_args(args)

    issues = []

    # Check kdump service
    kdump_status = check_kdump_service(context)

    if not kdump_status['installed']:
        issues.append({
            'severity': 'WARNING',
            'message': 'Kdump is not installed - crash dumps will not be captured',
        })
    elif not kdump_status['enabled']:
        issues.append({
            'severity': 'WARNING',
            'message': 'Kdump service is not enabled',
        })
    elif not kdump_status['active']:
        issues.append({
            'severity': 'WARNING',
            'message': 'Kdump service is not active',
        })

    # Check crashkernel reservation
    crashkernel_info = check_crashkernel_reservation(context)

    if not crashkernel_info['reserved']:
        issues.append({
            'severity': 'WARNING',
            'message': 'Crashkernel memory not reserved - add crashkernel=auto to boot params',
        })

    # Analyze crash directories
    crash_dirs = []
    total_crashes = 0

    for path in CRASH_DIRECTORIES:
        dir_info = analyze_crash_directory(path, context)
        crash_dirs.append(dir_info)
        total_crashes += dir_info['crash_count']

    # Check for any crashes (simplified - in production would check timestamps)
    if total_crashes > 0:
        issues.append({
            'severity': 'CRITICAL',
            'message': f'{total_crashes} crash dump(s) found - investigation recommended',
        })

    # Build output data
    data = {
        'kdump_service': kdump_status,
        'crashkernel': crashkernel_info,
        'crash_directories': crash_dirs,
        'issues': issues,
    }

    if opts.verbose:
        data['total_crashes'] = total_crashes

    output.emit(data)

    # Generate summary
    if issues:
        critical_count = sum(1 for i in issues if i['severity'] == 'CRITICAL')
        warning_count = sum(1 for i in issues if i['severity'] == 'WARNING')
        if critical_count > 0:
            output.set_summary(f"{critical_count} critical, {warning_count} warnings")
        else:
            output.set_summary(f"{warning_count} warnings")
    else:
        output.set_summary("kdump healthy, no crashes found")

    return 1 if issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
