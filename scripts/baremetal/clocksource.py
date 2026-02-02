#!/usr/bin/env python3
# boxctl:
#   category: baremetal/performance
#   tags: [time, clock, tsc, performance]
#   requires: []
#   privilege: none
#   related: [cpu_microcode, cpu_time]
#   brief: Monitor kernel clock source configuration and stability

"""
Monitor kernel clock source configuration and stability.

Checks the kernel's time-keeping clock source to ensure optimal configuration
for accurate timing and performance. Important for high-frequency trading,
distributed systems, database consistency, and virtualization workloads.

Key checks:
- Current vs available clock sources
- TSC (Time Stamp Counter) stability and reliability
- Clock source consistency across system
- Detection of clock source fallbacks (may indicate hardware issues)

Clock source priority (best to worst for most workloads):
1. tsc - CPU timestamp counter (fastest, most accurate when stable)
2. hpet - High Precision Event Timer (good fallback)
3. acpi_pm - ACPI Power Management timer (slower but reliable)
4. jiffies - Software-only (last resort, poor accuracy)
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_clocksource_info(context: Context) -> tuple[dict[str, Any] | None, str | None]:
    """Get current and available clock sources from sysfs."""
    base_path = '/sys/devices/system/clocksource/clocksource0'

    try:
        current = context.read_file(f'{base_path}/current_clocksource').strip()
    except (FileNotFoundError, OSError):
        return None, "Cannot read clock source from sysfs"

    try:
        available_str = context.read_file(f'{base_path}/available_clocksource').strip()
        available_list = available_str.split()
    except (FileNotFoundError, OSError):
        available_list = [current]

    return {
        'current': current,
        'available': available_list,
    }, None


def get_tsc_info(context: Context) -> dict[str, Any]:
    """Get TSC-related information from kernel."""
    info = {
        'reliable': None,
        'unstable': None,
        'constant': None,
        'nonstop': None,
    }

    # Check /proc/cpuinfo for TSC flags
    try:
        cpuinfo = context.read_file('/proc/cpuinfo')
        flags_line = None
        for line in cpuinfo.split('\n'):
            if line.startswith('flags'):
                flags_line = line
                break

        if flags_line and ':' in flags_line:
            flags = flags_line.split(':')[1].strip().split()
            info['constant'] = 'constant_tsc' in flags
            info['nonstop'] = 'nonstop_tsc' in flags
            info['reliable'] = 'tsc_reliable' in flags or (info['constant'] and info['nonstop'])
    except (FileNotFoundError, OSError):
        pass

    # Check dmesg for TSC messages (may require root)
    try:
        dmesg_content = context.read_file('/var/log/dmesg')
        info['unstable'] = ('tsc unstable' in dmesg_content.lower() or
                           'tsc: marking unstable' in dmesg_content.lower())
    except (FileNotFoundError, OSError):
        info['unstable'] = None

    return info


def get_kernel_cmdline_clock_params(context: Context) -> dict[str, Any]:
    """Get clock-related kernel command line parameters."""
    try:
        cmdline = context.read_file('/proc/cmdline')
    except (FileNotFoundError, OSError):
        return {}

    params = {}
    clock_params = [
        'clocksource=',
        'tsc=',
        'hpet=',
        'nohpet',
        'notsc',
        'lpj=',
    ]

    for word in cmdline.split():
        for param in clock_params:
            if word.startswith(param) or word == param.rstrip('='):
                key = param.rstrip('=')
                if '=' in word:
                    params[key] = word.split('=', 1)[1]
                else:
                    params[key] = True

    return params


def get_cpu_freq_info(context: Context) -> dict[str, Any]:
    """Get CPU frequency info relevant to TSC stability."""
    info = {
        'scaling_driver': None,
        'scaling_governor': None,
        'constant_freq': None,
    }

    cpu0_path = '/sys/devices/system/cpu/cpu0/cpufreq'

    try:
        info['scaling_driver'] = context.read_file(f'{cpu0_path}/scaling_driver').strip()
    except (FileNotFoundError, OSError):
        pass

    try:
        info['scaling_governor'] = context.read_file(f'{cpu0_path}/scaling_governor').strip()
    except (FileNotFoundError, OSError):
        pass

    try:
        min_freq = int(context.read_file(f'{cpu0_path}/scaling_min_freq').strip())
        max_freq = int(context.read_file(f'{cpu0_path}/scaling_max_freq').strip())
        info['constant_freq'] = min_freq == max_freq
    except (FileNotFoundError, OSError, ValueError):
        pass

    return info


def analyze_clocksource(clocksource_info: dict, tsc_info: dict,
                        cmdline_params: dict, cpu_freq_info: dict) -> dict[str, Any]:
    """Analyze clock source configuration and return findings."""
    issues = []
    warnings = []
    info_msgs = []

    current = clocksource_info['current']
    available = clocksource_info['available']

    # Check if using optimal clock source
    if current == 'tsc':
        # TSC is best - verify it's stable
        if tsc_info.get('unstable'):
            issues.append("TSC marked as unstable - time accuracy may be affected")
        elif not tsc_info.get('constant'):
            warnings.append("TSC lacks constant_tsc flag - may vary with CPU frequency")
        elif not tsc_info.get('nonstop'):
            warnings.append("TSC lacks nonstop_tsc flag - may stop in deep sleep states")
        else:
            info_msgs.append("TSC is stable and reliable (constant_tsc + nonstop_tsc)")

    elif current == 'hpet':
        if 'tsc' in available:
            warnings.append("Using HPET instead of TSC - TSC may be unstable or disabled")
        else:
            info_msgs.append("Using HPET (TSC not available)")

    elif current == 'acpi_pm':
        warnings.append("Using ACPI PM timer - slower than TSC/HPET")
        if 'tsc' in available:
            warnings.append("TSC available but not in use - check for stability issues")
        if 'hpet' in available:
            warnings.append("HPET available but not in use - consider enabling")

    elif current == 'jiffies':
        issues.append("Using jiffies clock source - poor timing accuracy")
        issues.append("No hardware clock source available - check system configuration")

    else:
        info_msgs.append(f"Using clock source: {current}")

    # Check for forced clock source via kernel command line
    if 'clocksource' in cmdline_params:
        forced = cmdline_params['clocksource']
        info_msgs.append(f"Clock source forced via kernel cmdline: {forced}")
        if forced != current:
            warnings.append(f"Forced clock source '{forced}' differs from current '{current}'")

    if 'notsc' in cmdline_params or cmdline_params.get('tsc') == 'unstable':
        info_msgs.append("TSC explicitly disabled via kernel command line")

    if 'nohpet' in cmdline_params:
        info_msgs.append("HPET explicitly disabled via kernel command line")

    # CPU frequency scaling can affect TSC on older CPUs
    if current == 'tsc' and not tsc_info.get('constant'):
        if cpu_freq_info.get('scaling_governor') not in [None, 'performance']:
            warnings.append(
                f"CPU frequency scaling active (governor: {cpu_freq_info.get('scaling_governor')}) "
                "with non-constant TSC - may affect timing accuracy"
            )

    # Determine overall status
    if issues:
        status = 'critical'
    elif warnings:
        status = 'warning'
    else:
        status = 'healthy'

    return {
        'status': status,
        'issues': issues,
        'warnings': warnings,
        'info': info_msgs,
    }


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
    parser = argparse.ArgumentParser(description="Monitor kernel clock source configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Gather information
    clocksource_info, error = get_clocksource_info(context)
    if clocksource_info is None:
        output.error(error)
        return 2

    tsc_info = get_tsc_info(context)
    cmdline_params = get_kernel_cmdline_clock_params(context)
    cpu_freq_info = get_cpu_freq_info(context)

    # Analyze
    analysis = analyze_clocksource(clocksource_info, tsc_info, cmdline_params, cpu_freq_info)

    # Build result
    result = {
        'clocksource': {
            'current': clocksource_info['current'],
            'available': clocksource_info['available'],
        },
        'tsc': {
            'constant': tsc_info.get('constant'),
            'nonstop': tsc_info.get('nonstop'),
            'reliable': tsc_info.get('reliable'),
        },
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
    }

    if opts.verbose:
        result['kernel_cmdline_params'] = cmdline_params
        result['cpu_frequency'] = cpu_freq_info
        result['info'] = analysis['info']

    output.emit(result)

    # Set summary
    if analysis['issues']:
        output.set_summary(f"clock source issues: {clocksource_info['current']}")
    elif analysis['warnings']:
        output.set_summary(f"clock source warnings: {clocksource_info['current']}")
    else:
        output.set_summary(f"clock source optimal: {clocksource_info['current']}")

    # Exit code
    if analysis['issues'] or analysis['warnings']:
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
