#!/usr/bin/env python3
"""
Baremetal Pressure Stall Information (PSI) Monitor

Monitors Linux PSI metrics to detect resource contention for CPU, memory, and I/O.
PSI provides early warning of resource pressure before it causes visible performance
degradation, making it valuable for large-scale baremetal fleet monitoring.

PSI tracks three resources:
- CPU: Tasks waiting for CPU time
- Memory: Tasks stalled on memory operations (reclaim, swap)
- I/O: Tasks waiting for I/O completion

Each resource reports:
- some: Percentage of time at least one task was stalled
- full: Percentage of time ALL tasks were stalled (not for CPU)

Metrics are reported over 10s, 60s, and 300s windows with total microseconds stalled.

Requirements:
- Linux kernel 4.20+ with CONFIG_PSI=y
- /proc/pressure/{cpu,memory,io} readable

Exit codes:
    0 - All pressure metrics within acceptable thresholds
    1 - Pressure thresholds exceeded (resource contention detected)
    2 - Usage error or PSI not available
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def check_psi_available():
    """Check if PSI is available on this system."""
    return os.path.exists('/proc/pressure/cpu')


def parse_psi_line(line):
    """Parse a single PSI line into a dictionary.

    Example line: some avg10=0.00 avg60=0.00 avg300=0.00 total=0
    Returns: {'avg10': 0.0, 'avg60': 0.0, 'avg300': 0.0, 'total': 0}
    """
    parts = line.strip().split()
    if len(parts) < 2:
        return None

    metric_type = parts[0]  # 'some' or 'full'
    values = {}

    for part in parts[1:]:
        if '=' in part:
            key, val = part.split('=', 1)
            try:
                if key == 'total':
                    values[key] = int(val)
                else:
                    values[key] = float(val)
            except ValueError:
                values[key] = val

    return metric_type, values


def read_psi_file(resource):
    """Read PSI metrics for a specific resource (cpu, memory, io)."""
    path = f'/proc/pressure/{resource}'
    try:
        with open(path, 'r') as f:
            lines = f.readlines()

        result = {}
        for line in lines:
            parsed = parse_psi_line(line)
            if parsed:
                metric_type, values = parsed
                result[metric_type] = values

        return result
    except FileNotFoundError:
        return None
    except PermissionError:
        return {'error': 'permission denied'}
    except IOError as e:
        return {'error': str(e)}


def get_all_psi_metrics():
    """Get PSI metrics for all resources."""
    resources = ['cpu', 'memory', 'io']
    metrics = {}

    for resource in resources:
        data = read_psi_file(resource)
        if data is not None:
            metrics[resource] = data

    return metrics


def analyze_pressure(metrics, thresholds):
    """Analyze PSI metrics against thresholds and identify issues."""
    issues = []
    warnings = []

    # Default thresholds if not specified
    warn_some = thresholds.get('warn_some', 10.0)
    crit_some = thresholds.get('crit_some', 25.0)
    warn_full = thresholds.get('warn_full', 5.0)
    crit_full = thresholds.get('crit_full', 10.0)

    for resource, data in metrics.items():
        if 'error' in data:
            warnings.append(f"{resource}: {data['error']}")
            continue

        # Check 'some' pressure (at least one task stalled)
        if 'some' in data:
            for window in ['avg10', 'avg60', 'avg300']:
                if window in data['some']:
                    val = data['some'][window]
                    if val >= crit_some:
                        issues.append(
                            f"{resource} {window} some={val:.2f}% (critical >= {crit_some}%)"
                        )
                    elif val >= warn_some:
                        warnings.append(
                            f"{resource} {window} some={val:.2f}% (warning >= {warn_some}%)"
                        )

        # Check 'full' pressure (all tasks stalled) - not applicable to CPU
        if 'full' in data:
            for window in ['avg10', 'avg60', 'avg300']:
                if window in data['full']:
                    val = data['full'][window]
                    if val >= crit_full:
                        issues.append(
                            f"{resource} {window} full={val:.2f}% (critical >= {crit_full}%)"
                        )
                    elif val >= warn_full:
                        warnings.append(
                            f"{resource} {window} full={val:.2f}% (warning >= {warn_full}%)"
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
        'warnings': warnings
    }


def format_plain(metrics, analysis, verbose=False):
    """Format output as plain text."""
    lines = []

    lines.append("Pressure Stall Information (PSI) Monitor")
    lines.append("=" * 50)
    lines.append("")

    for resource in ['cpu', 'memory', 'io']:
        if resource not in metrics:
            lines.append(f"{resource.upper()}: not available")
            continue

        data = metrics[resource]
        if 'error' in data:
            lines.append(f"{resource.upper()}: {data['error']}")
            continue

        lines.append(f"{resource.upper()}:")

        if 'some' in data:
            some = data['some']
            lines.append(f"  some: {some.get('avg10', 0):.2f}% (10s) "
                        f"{some.get('avg60', 0):.2f}% (60s) "
                        f"{some.get('avg300', 0):.2f}% (300s)")
            if verbose and 'total' in some:
                lines.append(f"        total: {some['total']:,} µs")

        if 'full' in data:
            full = data['full']
            lines.append(f"  full: {full.get('avg10', 0):.2f}% (10s) "
                        f"{full.get('avg60', 0):.2f}% (60s) "
                        f"{full.get('avg300', 0):.2f}% (300s)")
            if verbose and 'total' in full:
                lines.append(f"        total: {full['total']:,} µs")

        lines.append("")

    # Show issues and warnings
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

    # Summary
    if analysis['status'] == 'healthy':
        lines.append("[OK] All pressure metrics within acceptable thresholds")
    elif analysis['status'] == 'warning':
        lines.append(f"[WARN] {len(analysis['warnings'])} warning(s) detected")
    else:
        lines.append(f"[CRITICAL] {len(analysis['issues'])} issue(s) detected")

    return "\n".join(lines)


def format_json(metrics, analysis):
    """Format output as JSON."""
    return json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'psi_available': True,
        'metrics': metrics,
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'healthy': analysis['status'] == 'healthy'
    }, indent=2)


def format_table(metrics, analysis):
    """Format output as a table."""
    lines = []

    # Header
    lines.append("+" + "-" * 72 + "+")
    lines.append("| Pressure Stall Information (PSI)" + " " * 39 + "|")
    lines.append("+" + "-" * 72 + "+")
    lines.append(f"| {'Resource':<10} | {'Type':<6} | {'10s':<8} | {'60s':<8} | "
                f"{'300s':<8} | {'Status':<10} |")
    lines.append("+" + "-" * 72 + "+")

    status_map = {
        'cpu': 'healthy',
        'memory': 'healthy',
        'io': 'healthy'
    }

    # Check for issues/warnings to determine status
    for item in analysis['issues'] + analysis['warnings']:
        for resource in ['cpu', 'memory', 'io']:
            if item.startswith(resource):
                if item in [i for i in analysis['issues']]:
                    status_map[resource] = 'CRITICAL'
                elif status_map[resource] != 'CRITICAL':
                    status_map[resource] = 'WARNING'

    for resource in ['cpu', 'memory', 'io']:
        if resource not in metrics:
            lines.append(f"| {resource.upper():<10} | {'N/A':<6} | {'-':<8} | {'-':<8} | "
                        f"{'-':<8} | {'N/A':<10} |")
            continue

        data = metrics[resource]
        if 'error' in data:
            lines.append(f"| {resource.upper():<10} | {'ERR':<6} | {'-':<8} | {'-':<8} | "
                        f"{'-':<8} | {'ERROR':<10} |")
            continue

        status = status_map.get(resource, 'healthy')

        if 'some' in data:
            some = data['some']
            lines.append(f"| {resource.upper():<10} | {'some':<6} | "
                        f"{some.get('avg10', 0):>7.2f}% | "
                        f"{some.get('avg60', 0):>7.2f}% | "
                        f"{some.get('avg300', 0):>7.2f}% | {status:<10} |")

        if 'full' in data:
            full = data['full']
            lines.append(f"| {'':<10} | {'full':<6} | "
                        f"{full.get('avg10', 0):>7.2f}% | "
                        f"{full.get('avg60', 0):>7.2f}% | "
                        f"{full.get('avg300', 0):>7.2f}% | {'':<10} |")

    lines.append("+" + "-" * 72 + "+")

    # Overall status
    overall = analysis['status'].upper()
    lines.append(f"| Overall Status: {overall:<54} |")
    lines.append("+" + "-" * 72 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Linux Pressure Stall Information (PSI) metrics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                       # Basic PSI check
  %(prog)s --format json         # JSON output for monitoring systems
  %(prog)s --warn-some 5         # Lower warning threshold
  %(prog)s --resource memory     # Check only memory pressure
  %(prog)s -w                    # Only show output if issues detected

PSI Metrics:
  'some' - Percentage of time at least one task was stalled
  'full' - Percentage of time ALL runnable tasks were stalled
           (Note: 'full' is not reported for CPU)

  Windows: avg10 (10 seconds), avg60 (60 seconds), avg300 (5 minutes)

Interpreting Values:
  - 0%%:     No pressure, healthy system
  - 1-10%%:  Light pressure, generally acceptable
  - 10-25%%: Moderate pressure, may indicate contention
  - 25%%+:   High pressure, likely performance impact

Exit codes:
  0 - All pressure metrics within acceptable thresholds
  1 - Pressure thresholds exceeded
  2 - Usage error or PSI not available
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-some',
        type=float,
        default=10.0,
        help='Warning threshold for "some" pressure %% (default: 10.0)'
    )

    parser.add_argument(
        '--crit-some',
        type=float,
        default=25.0,
        help='Critical threshold for "some" pressure %% (default: 25.0)'
    )

    parser.add_argument(
        '--warn-full',
        type=float,
        default=5.0,
        help='Warning threshold for "full" pressure %% (default: 5.0)'
    )

    parser.add_argument(
        '--crit-full',
        type=float,
        default=10.0,
        help='Critical threshold for "full" pressure %% (default: 10.0)'
    )

    parser.add_argument(
        '--resource', '-r',
        choices=['cpu', 'memory', 'io', 'all'],
        default='all',
        help='Resource to monitor (default: all)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including total stall time'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn_some >= args.crit_some:
        print("Error: --warn-some must be less than --crit-some", file=sys.stderr)
        sys.exit(2)

    if args.warn_full >= args.crit_full:
        print("Error: --warn-full must be less than --crit-full", file=sys.stderr)
        sys.exit(2)

    # Check if PSI is available
    if not check_psi_available():
        if args.format == 'json':
            print(json.dumps({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'psi_available': False,
                'error': 'PSI not available (requires Linux 4.20+ with CONFIG_PSI=y)',
                'healthy': False
            }, indent=2))
        else:
            print("Error: PSI not available on this system", file=sys.stderr)
            print("Requires Linux kernel 4.20+ with CONFIG_PSI=y", file=sys.stderr)
        sys.exit(2)

    # Get metrics
    metrics = get_all_psi_metrics()

    # Filter to requested resource
    if args.resource != 'all':
        if args.resource in metrics:
            metrics = {args.resource: metrics[args.resource]}
        else:
            print(f"Error: Resource '{args.resource}' not available", file=sys.stderr)
            sys.exit(2)

    # Analyze
    thresholds = {
        'warn_some': args.warn_some,
        'crit_some': args.crit_some,
        'warn_full': args.warn_full,
        'crit_full': args.crit_full
    }
    analysis = analyze_pressure(metrics, thresholds)

    # Format output
    if args.format == 'json':
        output = format_json(metrics, analysis)
    elif args.format == 'table':
        output = format_table(metrics, analysis)
    else:
        output = format_plain(metrics, analysis, verbose=args.verbose)

    # Print output (respecting --warn-only)
    if not args.warn_only or analysis['issues'] or analysis['warnings']:
        print(output)

    # Return appropriate exit code
    return 1 if analysis['issues'] else 0


if __name__ == '__main__':
    sys.exit(main())
