#!/usr/bin/env python3
"""
Monitor kernel clock source configuration and stability on baremetal systems.

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

Useful for:
- Ensuring consistent clock configuration across baremetal fleet
- Detecting TSC instability that could affect time-sensitive workloads
- Validating virtualization readiness (VMs need stable TSC)
- Troubleshooting time drift and synchronization issues
- Pre-deployment validation for latency-sensitive applications

Exit codes:
    0 - Clock source configuration is optimal
    1 - Warnings or suboptimal configuration detected
    2 - Usage error or clock source info unavailable
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def read_file(path):
    """Read a file and return its contents, or None if unavailable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError, PermissionError):
        return None


def get_clocksource_info():
    """Get current and available clock sources from sysfs."""
    base_path = '/sys/devices/system/clocksource/clocksource0'

    current = read_file(os.path.join(base_path, 'current_clocksource'))
    available = read_file(os.path.join(base_path, 'available_clocksource'))

    if current is None:
        return None, "Cannot read clock source from sysfs"

    available_list = available.split() if available else [current]

    return {
        'current': current,
        'available': available_list,
    }, None


def get_tsc_info():
    """Get TSC-related information from kernel."""
    info = {
        'reliable': None,
        'unstable': None,
        'constant': None,
        'nonstop': None,
    }

    # Check /proc/cpuinfo for TSC flags
    cpuinfo = read_file('/proc/cpuinfo')
    if cpuinfo:
        flags_line = None
        for line in cpuinfo.split('\n'):
            if line.startswith('flags'):
                flags_line = line
                break

        if flags_line:
            flags = flags_line.split(':')[1].strip().split() if ':' in flags_line else []
            info['constant'] = 'constant_tsc' in flags
            info['nonstop'] = 'nonstop_tsc' in flags
            info['reliable'] = 'tsc_reliable' in flags or (info['constant'] and info['nonstop'])

    # Check dmesg for TSC messages (may require root)
    dmesg_content = read_file('/var/log/dmesg')
    if dmesg_content:
        info['unstable'] = 'tsc unstable' in dmesg_content.lower() or \
                          'tsc: marking unstable' in dmesg_content.lower()

    # Alternative: check /sys/devices/system/clocksource for tsc status
    # This varies by kernel version

    return info


def get_kernel_cmdline_clock_params():
    """Get clock-related kernel command line parameters."""
    cmdline = read_file('/proc/cmdline')
    if not cmdline:
        return {}

    params = {}
    clock_params = [
        'clocksource=',
        'tsc=',
        'hpet=',
        'nohpet',
        'notsc',
        'lpj=',  # loops_per_jiffy - affects timing
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


def get_cpu_freq_info():
    """Get CPU frequency info relevant to TSC stability."""
    info = {
        'scaling_driver': None,
        'scaling_governor': None,
        'constant_freq': None,
    }

    cpu0_path = '/sys/devices/system/cpu/cpu0/cpufreq'

    info['scaling_driver'] = read_file(os.path.join(cpu0_path, 'scaling_driver'))
    info['scaling_governor'] = read_file(os.path.join(cpu0_path, 'scaling_governor'))

    # Check if CPU frequency is constant (affects TSC on older systems)
    min_freq = read_file(os.path.join(cpu0_path, 'scaling_min_freq'))
    max_freq = read_file(os.path.join(cpu0_path, 'scaling_max_freq'))

    if min_freq and max_freq:
        try:
            info['constant_freq'] = int(min_freq) == int(max_freq)
        except ValueError:
            pass

    return info


def analyze_clocksource(clocksource_info, tsc_info, cmdline_params, cpu_freq_info):
    """Analyze clock source configuration and return findings."""
    issues = []
    warnings = []
    info_msgs = []

    current = clocksource_info['current']
    available = clocksource_info['available']

    # Priority order for clock sources
    priority = ['tsc', 'hpet', 'acpi_pm', 'jiffies']

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


def format_plain(clocksource_info, tsc_info, cmdline_params, cpu_freq_info,
                 analysis, verbose=False):
    """Format output as plain text."""
    lines = []

    lines.append("Kernel Clock Source Monitor")
    lines.append("=" * 40)
    lines.append("")

    # Current configuration
    lines.append(f"Current clock source: {clocksource_info['current']}")
    lines.append(f"Available: {', '.join(clocksource_info['available'])}")
    lines.append("")

    # TSC information
    if clocksource_info['current'] == 'tsc' or 'tsc' in clocksource_info['available']:
        lines.append("TSC Status:")
        if tsc_info.get('constant'):
            lines.append("  [+] constant_tsc: yes")
        else:
            lines.append("  [-] constant_tsc: no")
        if tsc_info.get('nonstop'):
            lines.append("  [+] nonstop_tsc: yes")
        else:
            lines.append("  [-] nonstop_tsc: no")
        if tsc_info.get('unstable'):
            lines.append("  [!] TSC marked unstable")
        lines.append("")

    # Verbose information
    if verbose:
        if cmdline_params:
            lines.append("Kernel cmdline clock parameters:")
            for key, value in cmdline_params.items():
                lines.append(f"  {key}={value}")
            lines.append("")

        if cpu_freq_info.get('scaling_governor'):
            lines.append(f"CPU frequency governor: {cpu_freq_info['scaling_governor']}")
            lines.append("")

    # Analysis results
    if analysis['issues']:
        lines.append("ISSUES:")
        for issue in analysis['issues']:
            lines.append(f"  [!] {issue}")
        lines.append("")

    if analysis['warnings']:
        lines.append("WARNINGS:")
        for warning in analysis['warnings']:
            lines.append(f"  [*] {warning}")
        lines.append("")

    if verbose and analysis['info']:
        lines.append("INFO:")
        for info in analysis['info']:
            lines.append(f"  [i] {info}")
        lines.append("")

    # Summary
    if not analysis['issues'] and not analysis['warnings']:
        lines.append("[OK] Clock source configuration is optimal")

    return "\n".join(lines)


def format_json(clocksource_info, tsc_info, cmdline_params, cpu_freq_info, analysis):
    """Format output as JSON."""
    return json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'clocksource': clocksource_info,
        'tsc': tsc_info,
        'kernel_cmdline_params': cmdline_params,
        'cpu_frequency': cpu_freq_info,
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'info': analysis['info'],
        'healthy': analysis['status'] == 'healthy',
    }, indent=2)


def format_table(clocksource_info, tsc_info, analysis):
    """Format output as table."""
    lines = []

    lines.append("+" + "-" * 58 + "+")
    lines.append("| Kernel Clock Source Monitor" + " " * 30 + "|")
    lines.append("+" + "-" * 58 + "+")

    lines.append(f"| {'Metric':<28} | {'Value':<25} |")
    lines.append("+" + "-" * 58 + "+")

    lines.append(f"| {'Current Clock Source':<28} | {clocksource_info['current']:<25} |")
    lines.append(f"| {'Available Sources':<28} | {len(clocksource_info['available']):<25} |")

    if 'tsc' in clocksource_info['available'] or clocksource_info['current'] == 'tsc':
        tsc_status = 'stable' if tsc_info.get('reliable') else 'check flags'
        lines.append(f"| {'TSC Status':<28} | {tsc_status:<25} |")
        const = 'yes' if tsc_info.get('constant') else 'no'
        lines.append(f"| {'TSC constant_tsc':<28} | {const:<25} |")
        nonstop = 'yes' if tsc_info.get('nonstop') else 'no'
        lines.append(f"| {'TSC nonstop_tsc':<28} | {nonstop:<25} |")

    lines.append("+" + "-" * 58 + "+")

    status_str = analysis['status'].upper()
    issue_count = len(analysis['issues']) + len(analysis['warnings'])
    if issue_count > 0:
        status_line = f"Status: {status_str} ({issue_count} finding(s))"
    else:
        status_line = f"Status: {status_str}"
    lines.append(f"| {status_line:<56} |")
    lines.append("+" + "-" * 58 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor kernel clock source configuration and stability',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check clock source configuration
  %(prog)s --format json        # JSON output for monitoring systems
  %(prog)s --verbose            # Show detailed TSC and cmdline info
  %(prog)s --warn-only          # Only show warnings and errors

Clock Sources (typical priority):
  tsc      - Time Stamp Counter (fastest, preferred when stable)
  hpet     - High Precision Event Timer (good fallback)
  acpi_pm  - ACPI Power Management timer (reliable but slower)
  jiffies  - Software timer (poor accuracy, last resort)

TSC Flags:
  constant_tsc - TSC runs at constant rate regardless of CPU frequency
  nonstop_tsc  - TSC continues during deep sleep (C-states)
  tsc_reliable - Kernel considers TSC fully reliable

Exit codes:
  0 - Clock source configuration is optimal
  1 - Warnings or suboptimal configuration detected
  2 - Usage error or clock source info unavailable
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
        help='Show detailed information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if warnings or issues detected'
    )

    args = parser.parse_args()

    # Gather information
    clocksource_info, error = get_clocksource_info()
    if clocksource_info is None:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    tsc_info = get_tsc_info()
    cmdline_params = get_kernel_cmdline_clock_params()
    cpu_freq_info = get_cpu_freq_info()

    # Analyze
    analysis = analyze_clocksource(clocksource_info, tsc_info, cmdline_params, cpu_freq_info)

    # Check if we should output (respecting --warn-only)
    has_findings = analysis['issues'] or analysis['warnings']
    if args.warn_only and not has_findings:
        sys.exit(0)

    # Format and output
    if args.format == 'json':
        output = format_json(clocksource_info, tsc_info, cmdline_params,
                            cpu_freq_info, analysis)
    elif args.format == 'table':
        output = format_table(clocksource_info, tsc_info, analysis)
    else:
        output = format_plain(clocksource_info, tsc_info, cmdline_params,
                             cpu_freq_info, analysis, args.verbose)

    print(output)

    # Exit code based on findings
    if analysis['issues']:
        sys.exit(1)
    elif analysis['warnings']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
