#!/usr/bin/env python3
"""
Monitor cgroup v2 PSI (Pressure Stall Information) for resource contention.

This script analyzes Pressure Stall Information from cgroup v2 to detect
resource contention issues on container hosts. PSI provides visibility into
how much time processes are stalled waiting for CPU, memory, or I/O resources.

PSI metrics:
- some: Percentage of time at least one task is stalled
- full: Percentage of time ALL tasks are stalled (more severe)

Useful for:
- Detecting container resource contention on Kubernetes nodes
- Identifying memory pressure before OOM kills occur
- Finding I/O bottlenecks affecting container performance
- Capacity planning on shared container hosts

Exit codes:
    0 - No pressure issues detected
    1 - Pressure warnings or critical issues found
    2 - Usage error or cgroup v2/PSI not available
"""

import argparse
import sys
import os
import json
import glob
from collections import defaultdict


def check_cgroup_v2_available():
    """Check if cgroup v2 is mounted and PSI is available"""
    # Check for cgroup v2 unified hierarchy
    if not os.path.exists('/sys/fs/cgroup/cgroup.controllers'):
        return False, "cgroup v2 not mounted"

    # Check if PSI is available (cpu.pressure, memory.pressure, io.pressure)
    if not os.path.exists('/proc/pressure'):
        return False, "PSI not available (kernel may need CONFIG_PSI=y)"

    return True, None


def read_pressure_file(path):
    """
    Read a PSI pressure file and return parsed values.

    Format example:
    some avg10=0.00 avg60=0.00 avg300=0.00 total=0
    full avg10=0.00 avg60=0.00 avg300=0.00 total=0
    """
    result = {}
    try:
        with open(path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if not parts:
                    continue

                level = parts[0]  # 'some' or 'full'
                metrics = {}

                for part in parts[1:]:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        try:
                            metrics[key] = float(value)
                        except ValueError:
                            metrics[key] = value

                result[level] = metrics

    except (IOError, OSError):
        return None

    return result


def get_system_pressure():
    """Get system-wide PSI metrics from /proc/pressure"""
    pressure = {}

    for resource in ['cpu', 'memory', 'io']:
        path = f'/proc/pressure/{resource}'
        if os.path.exists(path):
            data = read_pressure_file(path)
            if data:
                pressure[resource] = data

    return pressure


def find_cgroup_paths():
    """Find cgroup v2 paths with pressure files"""
    cgroups = []

    # Walk cgroup hierarchy
    cgroup_root = '/sys/fs/cgroup'

    for root, dirs, files in os.walk(cgroup_root):
        # Check if this cgroup has pressure files
        has_pressure = any(
            f in files for f in ['cpu.pressure', 'memory.pressure', 'io.pressure']
        )

        if has_pressure:
            # Get relative path from cgroup root
            rel_path = os.path.relpath(root, cgroup_root)
            if rel_path == '.':
                rel_path = '/'

            cgroups.append({
                'path': root,
                'name': rel_path
            })

    return cgroups


def get_cgroup_pressure(cgroup_path):
    """Get PSI metrics for a specific cgroup"""
    pressure = {}

    for resource in ['cpu', 'memory', 'io']:
        path = f'{cgroup_path}/{resource}.pressure'
        if os.path.exists(path):
            data = read_pressure_file(path)
            if data:
                pressure[resource] = data

    return pressure


def analyze_pressure(pressure, warn_threshold=10.0, crit_threshold=25.0):
    """
    Analyze pressure metrics and return issues.

    Args:
        pressure: Dict of resource -> {some/full -> {avg10, avg60, avg300, total}}
        warn_threshold: Percentage above which to warn
        crit_threshold: Percentage above which to mark critical

    Returns:
        List of issues with severity
    """
    issues = []

    for resource, levels in pressure.items():
        for level, metrics in levels.items():
            # Check avg10 (10-second average) for immediate pressure
            avg10 = metrics.get('avg10', 0.0)

            if avg10 >= crit_threshold:
                issues.append({
                    'severity': 'CRITICAL',
                    'resource': resource,
                    'level': level,
                    'avg10': avg10,
                    'avg60': metrics.get('avg60', 0.0),
                    'message': f"{resource.upper()} pressure ({level}): {avg10:.1f}% avg10"
                })
            elif avg10 >= warn_threshold:
                issues.append({
                    'severity': 'WARNING',
                    'resource': resource,
                    'level': level,
                    'avg10': avg10,
                    'avg60': metrics.get('avg60', 0.0),
                    'message': f"{resource.upper()} pressure ({level}): {avg10:.1f}% avg10"
                })

    return issues


def format_pressure_summary(pressure):
    """Format pressure data as a one-line summary"""
    parts = []
    for resource in ['cpu', 'memory', 'io']:
        if resource in pressure:
            some = pressure[resource].get('some', {}).get('avg10', 0.0)
            full = pressure[resource].get('full', {}).get('avg10', 0.0)
            parts.append(f"{resource}={some:.1f}/{full:.1f}")
    return ' '.join(parts)


def output_plain(system_pressure, cgroup_data, issues, warn_only=False, verbose=False):
    """Output results in plain text format"""
    lines = []

    if not warn_only:
        lines.append("System-wide Pressure (some/full avg10):")
        lines.append(f"  {format_pressure_summary(system_pressure)}")
        lines.append("")

    if issues:
        critical = [i for i in issues if i['severity'] == 'CRITICAL']
        warnings = [i for i in issues if i['severity'] == 'WARNING']

        if critical:
            lines.append(f"CRITICAL Issues ({len(critical)}):")
            for issue in critical:
                lines.append(f"  !!! {issue['message']}")
            lines.append("")

        if warnings:
            lines.append(f"Warnings ({len(warnings)}):")
            for issue in warnings:
                lines.append(f"  {issue['message']}")
            lines.append("")
    elif not warn_only:
        lines.append("No pressure issues detected.")
        lines.append("")

    if verbose and cgroup_data and not warn_only:
        lines.append("Per-Cgroup Pressure:")
        for cg in cgroup_data:
            if cg['pressure']:
                lines.append(f"  {cg['name']}:")
                lines.append(f"    {format_pressure_summary(cg['pressure'])}")

    return '\n'.join(lines)


def output_json(system_pressure, cgroup_data, issues, include_cgroups=False):
    """Output results in JSON format"""
    result = {
        'system_pressure': system_pressure,
        'issues': issues,
        'summary': {
            'total_issues': len(issues),
            'critical_count': len([i for i in issues if i['severity'] == 'CRITICAL']),
            'warning_count': len([i for i in issues if i['severity'] == 'WARNING'])
        }
    }

    if include_cgroups and cgroup_data:
        result['cgroups'] = [
            {'name': cg['name'], 'pressure': cg['pressure']}
            for cg in cgroup_data if cg['pressure']
        ]

    return json.dumps(result, indent=2)


def output_table(system_pressure, cgroup_data, issues, warn_only=False):
    """Output results in table format"""
    lines = []

    if not warn_only:
        lines.append(f"{'Resource':<10} {'Level':<8} {'avg10':<10} {'avg60':<10} {'avg300':<10}")
        lines.append("-" * 50)

        for resource in ['cpu', 'memory', 'io']:
            if resource in system_pressure:
                for level in ['some', 'full']:
                    if level in system_pressure[resource]:
                        metrics = system_pressure[resource][level]
                        lines.append(
                            f"{resource:<10} {level:<8} "
                            f"{metrics.get('avg10', 0.0):<10.2f} "
                            f"{metrics.get('avg60', 0.0):<10.2f} "
                            f"{metrics.get('avg300', 0.0):<10.2f}"
                        )
        lines.append("")

    if issues:
        lines.append(f"{'Severity':<10} {'Resource':<10} {'Level':<8} {'avg10':<10} {'Message':<40}")
        lines.append("-" * 80)
        for issue in issues:
            lines.append(
                f"{issue['severity']:<10} {issue['resource']:<10} "
                f"{issue['level']:<8} {issue['avg10']:<10.2f} "
                f"{issue['message']:<40}"
            )

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor cgroup v2 PSI (Pressure Stall Information) for resource contention",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check system-wide pressure
  %(prog)s --verbose                # Include per-cgroup breakdown
  %(prog)s --format json            # JSON output
  %(prog)s --warn 5 --crit 15       # Lower thresholds for sensitive systems
  %(prog)s --warn-only              # Only show issues

PSI Metrics:
  some  - Percentage of time at least one task was stalled
  full  - Percentage of time ALL tasks were stalled (more severe)
  avg10/60/300 - 10/60/300 second running averages

Resources monitored:
  cpu    - Tasks waiting for CPU time
  memory - Tasks waiting for memory (reclaim, allocation)
  io     - Tasks waiting for I/O completion

Exit codes:
  0 - No pressure issues detected
  1 - Pressure warnings or critical issues found
  2 - Usage error or cgroup v2/PSI not available

Notes:
  - Requires Linux kernel 4.20+ with CONFIG_PSI=y
  - Requires cgroup v2 unified hierarchy
  - Memory pressure > 10%% often precedes OOM kills
  - CPU pressure > 25%% indicates significant contention
        """
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show per-cgroup pressure breakdown"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )

    parser.add_argument(
        "--warn",
        type=float,
        default=10.0,
        help="Warning threshold percentage (default: %(default)s%%)"
    )

    parser.add_argument(
        "--crit",
        type=float,
        default=25.0,
        help="Critical threshold percentage (default: %(default)s%%)"
    )

    parser.add_argument(
        "--cgroup",
        help="Monitor specific cgroup path instead of system-wide"
    )

    args = parser.parse_args()

    # Validate thresholds
    if not 0.0 <= args.warn <= 100.0:
        print("Error: Warning threshold must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if not 0.0 <= args.crit <= 100.0:
        print("Error: Critical threshold must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.warn >= args.crit:
        print("Error: Warning threshold must be less than critical threshold",
              file=sys.stderr)
        sys.exit(2)

    # Check for cgroup v2 and PSI availability
    available, error = check_cgroup_v2_available()
    if not available:
        print(f"Error: {error}", file=sys.stderr)
        print("Ensure kernel has CONFIG_PSI=y and cgroup v2 is mounted", file=sys.stderr)
        sys.exit(2)

    # Get system-wide pressure
    system_pressure = get_system_pressure()

    if not system_pressure:
        print("Error: Could not read pressure metrics from /proc/pressure",
              file=sys.stderr)
        sys.exit(2)

    # Analyze system pressure
    issues = analyze_pressure(system_pressure, args.warn, args.crit)

    # Get per-cgroup pressure if requested
    cgroup_data = []
    if args.verbose or args.cgroup:
        if args.cgroup:
            # Monitor specific cgroup
            cgroup_path = args.cgroup
            if not cgroup_path.startswith('/'):
                cgroup_path = f'/sys/fs/cgroup/{cgroup_path}'

            if os.path.exists(cgroup_path):
                pressure = get_cgroup_pressure(cgroup_path)
                cgroup_data.append({
                    'name': args.cgroup,
                    'path': cgroup_path,
                    'pressure': pressure
                })
                # Also analyze cgroup-specific issues
                cgroup_issues = analyze_pressure(pressure, args.warn, args.crit)
                for issue in cgroup_issues:
                    issue['cgroup'] = args.cgroup
                issues.extend(cgroup_issues)
            else:
                print(f"Warning: Cgroup path not found: {cgroup_path}",
                      file=sys.stderr)
        else:
            # Get all cgroups with pressure files
            cgroups = find_cgroup_paths()
            for cg in cgroups[:20]:  # Limit to first 20 to avoid huge output
                pressure = get_cgroup_pressure(cg['path'])
                cgroup_data.append({
                    'name': cg['name'],
                    'path': cg['path'],
                    'pressure': pressure
                })

    # Output results
    if args.format == "json":
        output = output_json(system_pressure, cgroup_data, issues,
                           include_cgroups=args.verbose)
    elif args.format == "table":
        output = output_table(system_pressure, cgroup_data, issues,
                            warn_only=args.warn_only)
    else:  # plain
        output = output_plain(system_pressure, cgroup_data, issues,
                            warn_only=args.warn_only, verbose=args.verbose)

    print(output)

    # Exit based on findings
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
