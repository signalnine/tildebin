#!/usr/bin/env python3
"""Baremetal Load Average Monitor

Monitors system load averages and compares them to CPU count to identify
overloaded or underutilized systems. Provides normalized load metrics
that account for the number of available CPUs.

Key metrics:
- 1, 5, and 15 minute load averages
- Load per CPU (normalized load)
- CPU count and online status
- Historical trend analysis (increasing/decreasing/stable)

Useful for capacity planning, detecting runaway processes, and identifying
systems that may need workload rebalancing in large-scale deployments.

Exit codes:
    0: Load averages within acceptable thresholds
    1: Load averages indicate overload or issues detected
    2: Usage error or unable to read system metrics
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def get_cpu_count():
    """Get the number of CPUs available."""
    try:
        # Try to get online CPUs first
        online_cpus = os.sysconf('SC_NPROCESSORS_ONLN')
        configured_cpus = os.sysconf('SC_NPROCESSORS_CONF')
        return {
            'online': online_cpus,
            'configured': configured_cpus,
            'offline': configured_cpus - online_cpus
        }
    except (ValueError, OSError):
        # Fallback to cpu_count
        count = os.cpu_count() or 1
        return {
            'online': count,
            'configured': count,
            'offline': 0
        }


def get_load_averages():
    """Get system load averages."""
    try:
        load1, load5, load15 = os.getloadavg()
        return {
            '1min': round(load1, 2),
            '5min': round(load5, 2),
            '15min': round(load15, 2)
        }
    except OSError as e:
        print(f"Error: Unable to read load averages: {e}", file=sys.stderr)
        sys.exit(2)


def get_running_processes():
    """Get count of running and total processes from /proc/loadavg."""
    try:
        with open('/proc/loadavg', 'r') as f:
            parts = f.read().strip().split()
            if len(parts) >= 4:
                running_total = parts[3].split('/')
                if len(running_total) == 2:
                    return {
                        'running': int(running_total[0]),
                        'total': int(running_total[1])
                    }
    except (IOError, ValueError, IndexError):
        pass
    return {'running': 0, 'total': 0}


def analyze_load(load_averages, cpu_info, thresholds):
    """Analyze load averages and return status."""
    online_cpus = cpu_info['online']
    issues = []
    warnings = []

    # Calculate normalized load (load per CPU)
    normalized = {
        '1min': round(load_averages['1min'] / online_cpus, 2),
        '5min': round(load_averages['5min'] / online_cpus, 2),
        '15min': round(load_averages['15min'] / online_cpus, 2)
    }

    # Determine trend (comparing 1min to 15min)
    if load_averages['1min'] > load_averages['15min'] * 1.5:
        trend = 'increasing'
    elif load_averages['1min'] < load_averages['15min'] * 0.5:
        trend = 'decreasing'
    else:
        trend = 'stable'

    # Check thresholds (normalized load)
    critical_threshold = thresholds['critical']
    warning_threshold = thresholds['warning']

    # Check 1-minute load (most recent)
    if normalized['1min'] >= critical_threshold:
        issues.append(f"1-min load critical: {normalized['1min']:.2f} per CPU "
                     f"(threshold: {critical_threshold})")
    elif normalized['1min'] >= warning_threshold:
        warnings.append(f"1-min load elevated: {normalized['1min']:.2f} per CPU "
                       f"(threshold: {warning_threshold})")

    # Check 5-minute load (sustained)
    if normalized['5min'] >= critical_threshold:
        issues.append(f"5-min load critical: {normalized['5min']:.2f} per CPU "
                     f"(sustained overload)")
    elif normalized['5min'] >= warning_threshold:
        warnings.append(f"5-min load elevated: {normalized['5min']:.2f} per CPU")

    # Check 15-minute load (long-term)
    if normalized['15min'] >= critical_threshold:
        issues.append(f"15-min load critical: {normalized['15min']:.2f} per CPU "
                     f"(chronic overload)")

    # Check for offline CPUs
    if cpu_info['offline'] > 0:
        warnings.append(f"{cpu_info['offline']} CPU(s) offline of {cpu_info['configured']} configured")

    # Check for rapidly increasing load
    if trend == 'increasing' and normalized['1min'] >= warning_threshold:
        warnings.append("Load is rapidly increasing - potential runaway process")

    return {
        'normalized': normalized,
        'trend': trend,
        'issues': issues,
        'warnings': warnings,
        'status': 'critical' if issues else ('warning' if warnings else 'healthy')
    }


def format_plain(load_averages, cpu_info, processes, analysis, verbose=False):
    """Format output as plain text."""
    lines = []

    # Header
    lines.append("System Load Average Monitor")
    lines.append("=" * 40)
    lines.append("")

    # CPU info
    lines.append(f"CPUs: {cpu_info['online']} online / {cpu_info['configured']} configured")
    if cpu_info['offline'] > 0:
        lines.append(f"  [!] {cpu_info['offline']} CPU(s) offline")
    lines.append("")

    # Load averages
    lines.append("Load Averages:")
    lines.append(f"  1-min:  {load_averages['1min']:>6.2f}  "
                f"({analysis['normalized']['1min']:.2f} per CPU)")
    lines.append(f"  5-min:  {load_averages['5min']:>6.2f}  "
                f"({analysis['normalized']['5min']:.2f} per CPU)")
    lines.append(f"  15-min: {load_averages['15min']:>6.2f}  "
                f"({analysis['normalized']['15min']:.2f} per CPU)")
    lines.append("")

    # Trend
    trend_symbol = {'increasing': '↑', 'decreasing': '↓', 'stable': '→'}
    lines.append(f"Trend: {trend_symbol.get(analysis['trend'], '?')} {analysis['trend']}")
    lines.append("")

    # Process info
    if verbose and processes['total'] > 0:
        lines.append(f"Processes: {processes['running']} running / {processes['total']} total")
        lines.append("")

    # Issues and warnings
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
    if not analysis['issues'] and not analysis['warnings']:
        lines.append("[OK] Load averages within acceptable thresholds")

    return "\n".join(lines)


def format_json(load_averages, cpu_info, processes, analysis):
    """Format output as JSON."""
    return json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'cpu': cpu_info,
        'load_averages': load_averages,
        'normalized_load': analysis['normalized'],
        'processes': processes,
        'trend': analysis['trend'],
        'status': analysis['status'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'healthy': len(analysis['issues']) == 0
    }, indent=2)


def format_table(load_averages, cpu_info, processes, analysis):
    """Format output as a table."""
    lines = []

    # Header
    lines.append("+" + "-" * 58 + "+")
    lines.append("| System Load Average Monitor" + " " * 30 + "|")
    lines.append("+" + "-" * 58 + "+")

    # Table header
    lines.append(f"| {'Metric':<20} | {'Value':<15} | {'Per CPU':<15} |")
    lines.append("+" + "-" * 58 + "+")

    # Load averages
    lines.append(f"| {'1-min load':<20} | {load_averages['1min']:<15.2f} | "
                f"{analysis['normalized']['1min']:<15.2f} |")
    lines.append(f"| {'5-min load':<20} | {load_averages['5min']:<15.2f} | "
                f"{analysis['normalized']['5min']:<15.2f} |")
    lines.append(f"| {'15-min load':<20} | {load_averages['15min']:<15.2f} | "
                f"{analysis['normalized']['15min']:<15.2f} |")
    lines.append("+" + "-" * 58 + "+")

    # CPU and trend info
    cpu_str = f"{cpu_info['online']}/{cpu_info['configured']}"
    trend_str = f"Trend: {analysis['trend']}"
    lines.append(f"| {'CPUs (online/total)':<20} | {cpu_str:<15} | {trend_str:<15} |")
    lines.append("+" + "-" * 58 + "+")

    # Status
    status_text = analysis['status'].upper()
    if analysis['issues']:
        status_line = f"Status: {status_text} - {len(analysis['issues'])} issue(s)"
    elif analysis['warnings']:
        status_line = f"Status: {status_text} - {len(analysis['warnings'])} warning(s)"
    else:
        status_line = f"Status: {status_text}"
    lines.append(f"| {status_line:<56} |")
    lines.append("+" + "-" * 58 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor system load averages relative to CPU count',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic load check
  %(prog)s

  # JSON output for monitoring systems
  %(prog)s --format json

  # Custom thresholds (normalized load per CPU)
  %(prog)s --warning 0.8 --critical 1.5

  # Only show output if issues detected
  %(prog)s --warn-only

Thresholds:
  Load is normalized per CPU. A normalized load of 1.0 means each CPU
  has one process waiting on average. Values above 1.0 indicate the
  system is oversubscribed.

  Default warning: 0.7 (70%% utilized)
  Default critical: 1.0 (fully saturated)

Exit codes:
  0 - Load averages within acceptable thresholds
  1 - Load issues detected (overload or warnings)
  2 - Usage error or unable to read system metrics
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '--warning', '-W',
        type=float,
        default=0.7,
        help='Warning threshold for normalized load per CPU (default: 0.7)'
    )
    parser.add_argument(
        '--critical', '-C',
        type=float,
        default=1.0,
        help='Critical threshold for normalized load per CPU (default: 1.0)'
    )
    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including process counts'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warning >= args.critical:
        print("Error: Warning threshold must be less than critical threshold",
              file=sys.stderr)
        sys.exit(2)

    if args.warning < 0 or args.critical < 0:
        print("Error: Thresholds must be non-negative", file=sys.stderr)
        sys.exit(2)

    # Gather metrics
    cpu_info = get_cpu_count()
    load_averages = get_load_averages()
    processes = get_running_processes()

    # Analyze
    thresholds = {
        'warning': args.warning,
        'critical': args.critical
    }
    analysis = analyze_load(load_averages, cpu_info, thresholds)

    # Format output
    if args.format == 'json':
        output = format_json(load_averages, cpu_info, processes, analysis)
    elif args.format == 'table':
        output = format_table(load_averages, cpu_info, processes, analysis)
    else:
        output = format_plain(load_averages, cpu_info, processes, analysis, args.verbose)

    # Print output (respecting --warn-only)
    if not args.warn_only or analysis['issues'] or analysis['warnings']:
        print(output)

    # Return appropriate exit code
    return 1 if analysis['issues'] else 0


if __name__ == '__main__':
    sys.exit(main())
