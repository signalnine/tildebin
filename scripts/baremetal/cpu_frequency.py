#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [health, cpu, frequency, performance, governor]
#   requires: []
#   privilege: user
#   related: [cpu_usage, thermal_zone, thermal_throttle]
#   brief: Monitor CPU frequency scaling and governor settings

"""
Monitor CPU frequency scaling and governor settings on baremetal systems.

Checks CPU frequency settings, governors, and identifies CPUs running at
unexpected frequencies. Critical for detecting performance issues in
large-scale baremetal environments where CPU throttling or incorrect
governor settings can impact workload performance.

Returns exit code 1 if any CPU has issues (wrong governor, throttling).
"""

import argparse
import glob
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_cpu_count(context: Context) -> int:
    """Get the number of CPUs in the system."""
    try:
        cpu_dirs = glob.glob('/sys/devices/system/cpu/cpu[0-9]*')
        return len(cpu_dirs)
    except Exception:
        return 0


def read_sysfs_file(path: str) -> str | None:
    """Read a sysfs file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def get_cpu_info(cpu_num: int) -> dict[str, Any] | None:
    """
    Get frequency and governor information for a specific CPU.

    Returns dict with current freq, min freq, max freq, governor,
    available governors, and driver.
    """
    base_path = f'/sys/devices/system/cpu/cpu{cpu_num}/cpufreq'

    if not os.path.exists(base_path):
        return None

    info = {
        'cpu': cpu_num,
        'current_freq': None,
        'min_freq': None,
        'max_freq': None,
        'scaling_min_freq': None,
        'scaling_max_freq': None,
        'governor': None,
        'available_governors': [],
        'driver': None,
        'status': 'healthy'
    }

    # Read current frequency (in kHz)
    current_freq = read_sysfs_file(f'{base_path}/scaling_cur_freq')
    if current_freq:
        info['current_freq'] = int(current_freq)

    # Read hardware limits
    min_freq = read_sysfs_file(f'{base_path}/cpuinfo_min_freq')
    if min_freq:
        info['min_freq'] = int(min_freq)

    max_freq = read_sysfs_file(f'{base_path}/cpuinfo_max_freq')
    if max_freq:
        info['max_freq'] = int(max_freq)

    # Read scaling limits
    scaling_min = read_sysfs_file(f'{base_path}/scaling_min_freq')
    if scaling_min:
        info['scaling_min_freq'] = int(scaling_min)

    scaling_max = read_sysfs_file(f'{base_path}/scaling_max_freq')
    if scaling_max:
        info['scaling_max_freq'] = int(scaling_max)

    # Read governor
    governor = read_sysfs_file(f'{base_path}/scaling_governor')
    if governor:
        info['governor'] = governor

    # Read available governors
    available_gov = read_sysfs_file(f'{base_path}/scaling_available_governors')
    if available_gov:
        info['available_governors'] = available_gov.split()

    # Read driver
    driver = read_sysfs_file(f'{base_path}/scaling_driver')
    if driver:
        info['driver'] = driver

    return info


def analyze_cpu_status(
    cpu_info: dict[str, Any],
    expected_governor: str | None = None,
    check_throttling: bool = True
) -> dict[str, Any]:
    """
    Analyze CPU info and determine status.

    Sets status to 'warning' based on:
    - Governor mismatch with expected
    - CPU running below maximum frequency (potential throttling)
    - Scaling limits set below hardware maximum
    """
    if not cpu_info:
        return cpu_info

    issues = []

    # Check governor
    if expected_governor and cpu_info['governor'] != expected_governor:
        issues.append(
            f"Governor is '{cpu_info['governor']}', expected '{expected_governor}'"
        )
        cpu_info['status'] = 'warning'

    # Check for throttling (current freq significantly below max)
    if check_throttling and cpu_info['current_freq'] and cpu_info['max_freq']:
        freq_percent = (cpu_info['current_freq'] / cpu_info['max_freq']) * 100
        # Only flag if CPU is stuck at low frequency (below 50% of max)
        # This avoids false positives from normal frequency scaling
        if freq_percent < 50:
            issues.append(
                f"Running at {freq_percent:.1f}% of max frequency (possible throttling)"
            )
            if cpu_info['status'] == 'healthy':
                cpu_info['status'] = 'warning'

    # Check if scaling limits are artificially constrained
    if cpu_info['scaling_max_freq'] and cpu_info['max_freq']:
        if cpu_info['scaling_max_freq'] < cpu_info['max_freq']:
            diff_mhz = (cpu_info['max_freq'] - cpu_info['scaling_max_freq']) / 1000
            issues.append(
                f"Scaling max limited to {cpu_info['scaling_max_freq']/1000:.0f} MHz "
                f"(hardware max: {cpu_info['max_freq']/1000:.0f} MHz, -{diff_mhz:.0f} MHz)"
            )
            if cpu_info['status'] == 'healthy':
                cpu_info['status'] = 'warning'

    cpu_info['issues'] = issues
    return cpu_info


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor CPU frequency scaling and governor settings"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain"
    )
    parser.add_argument(
        "--expected-governor",
        help="Expected governor (e.g., performance, powersave, ondemand)"
    )
    parser.add_argument(
        "--no-throttle-check",
        action="store_true",
        help="Disable throttling detection (avoid false positives)"
    )
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="Only show CPUs with warnings or issues"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information for all CPUs"
    )

    opts = parser.parse_args(args)

    # Check if cpufreq is available
    if not context.file_exists('/sys/devices/system/cpu/cpu0/cpufreq'):
        output.error("CPU frequency scaling interface not available")
        return 2

    # Get CPU count
    cpu_count = get_cpu_count(context)
    if cpu_count == 0:
        output.error("Could not determine CPU count")
        return 2

    # Gather CPU information
    cpu_data = []
    for cpu_num in range(cpu_count):
        cpu_info = get_cpu_info(cpu_num)
        if cpu_info:
            cpu_info = analyze_cpu_status(
                cpu_info,
                expected_governor=opts.expected_governor,
                check_throttling=not opts.no_throttle_check
            )
            cpu_data.append(cpu_info)

    if not cpu_data:
        output.error("Could not read CPU frequency information")
        return 2

    # Count status
    total_cpus = len(cpu_data)
    ok_cpus = sum(1 for c in cpu_data if c['status'] == 'healthy')
    warn_cpus = total_cpus - ok_cpus

    # Get governor distribution
    governors = {}
    for cpu in cpu_data:
        gov = cpu['governor']
        if gov not in governors:
            governors[gov] = 0
        governors[gov] += 1

    # Get driver info
    driver = cpu_data[0]['driver'] if cpu_data else None

    # Filter if warn-only
    filtered_data = cpu_data
    if opts.warn_only:
        filtered_data = [c for c in cpu_data if c['status'] != 'healthy']

    # Remove verbose fields if not requested
    if not opts.verbose:
        for cpu in filtered_data:
            cpu.pop('available_governors', None)
            cpu.pop('issues', None)
            cpu.pop('scaling_min_freq', None)
            cpu.pop('min_freq', None)

    # Emit data
    output.emit({
        "cpus": filtered_data,
        "driver": driver,
        "governors": governors,
        "summary": {
            "total": total_cpus,
            "healthy": ok_cpus,
            "warnings": warn_cpus
        }
    })

    output.set_summary(f"{ok_cpus}/{total_cpus} CPUs healthy, driver: {driver}")

    # Exit with code 1 if any warnings
    return 1 if warn_cpus > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
