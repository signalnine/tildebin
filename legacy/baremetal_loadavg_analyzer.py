#!/usr/bin/env python3
"""
Analyze system load average and correlate with CPU count for scheduling pressure.

Monitors /proc/loadavg and compares against CPU core count to detect CPU
saturation. Provides normalized load metrics and identifies when the system
is under pressure.

Key features:
- Reports 1, 5, and 15 minute load averages
- Calculates per-CPU normalized load
- Detects CPU saturation conditions
- Tracks running and total processes
- Warns when load exceeds configurable thresholds

Use cases:
- Detecting CPU oversubscription
- Capacity planning for compute-heavy workloads
- Pre-incident visibility into CPU scheduling pressure
- Identifying sustained vs transient load spikes

Exit codes:
    0 - Load within acceptable limits
    1 - Load exceeds warning/critical thresholds
    2 - Usage error or unable to read load information
"""

import argparse
import json
import os
import sys
from typing import Dict, Optional


def get_cpu_count() -> int:
    """Get the number of CPU cores."""
    # Try /proc/cpuinfo first
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpu_count = sum(1 for line in f if line.startswith('processor'))
            if cpu_count > 0:
                return cpu_count
    except (OSError, IOError):
        pass

    # Fallback to sysconf
    try:
        import os
        return os.sysconf('SC_NPROCESSORS_ONLN')
    except (AttributeError, ValueError):
        pass

    # Last resort: assume 1
    return 1


def get_loadavg() -> Optional[Dict]:
    """Read load average from /proc/loadavg."""
    try:
        with open('/proc/loadavg', 'r') as f:
            content = f.read().strip()
    except (OSError, IOError) as e:
        return None

    # Format: "0.37 0.48 0.52 1/742 12345"
    # 1-min 5-min 15-min running/total last_pid
    parts = content.split()
    if len(parts) < 4:
        return None

    try:
        running_total = parts[3].split('/')
        return {
            'load_1min': float(parts[0]),
            'load_5min': float(parts[1]),
            'load_15min': float(parts[2]),
            'running_processes': int(running_total[0]),
            'total_processes': int(running_total[1]),
            'last_pid': int(parts[4]) if len(parts) > 4 else None,
        }
    except (ValueError, IndexError):
        return None


def get_uptime() -> Optional[float]:
    """Get system uptime in seconds."""
    try:
        with open('/proc/uptime', 'r') as f:
            content = f.read().strip()
            return float(content.split()[0])
    except (OSError, IOError, ValueError, IndexError):
        return None


def format_uptime(seconds: float) -> str:
    """Format uptime in human-readable form."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)

    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"


def analyze_load(loadavg: Dict, cpu_count: int,
                 warn_threshold: float, crit_threshold: float) -> Dict:
    """Analyze load averages and generate assessment."""
    # Calculate per-CPU (normalized) load
    load_1min_norm = loadavg['load_1min'] / cpu_count
    load_5min_norm = loadavg['load_5min'] / cpu_count
    load_15min_norm = loadavg['load_15min'] / cpu_count

    issues = []

    # Check 1-minute load (most sensitive)
    if load_1min_norm >= crit_threshold:
        issues.append({
            'type': 'LOAD_1MIN_CRITICAL',
            'severity': 'critical',
            'load': loadavg['load_1min'],
            'normalized': round(load_1min_norm, 2),
            'threshold': crit_threshold,
            'message': (f"1-min load {loadavg['load_1min']:.2f} "
                        f"({load_1min_norm:.2f} per CPU) exceeds critical "
                        f"threshold {crit_threshold}")
        })
    elif load_1min_norm >= warn_threshold:
        issues.append({
            'type': 'LOAD_1MIN_WARNING',
            'severity': 'warning',
            'load': loadavg['load_1min'],
            'normalized': round(load_1min_norm, 2),
            'threshold': warn_threshold,
            'message': (f"1-min load {loadavg['load_1min']:.2f} "
                        f"({load_1min_norm:.2f} per CPU) exceeds warning "
                        f"threshold {warn_threshold}")
        })

    # Check 5-minute load (sustained pressure)
    if load_5min_norm >= crit_threshold:
        issues.append({
            'type': 'LOAD_5MIN_CRITICAL',
            'severity': 'critical',
            'load': loadavg['load_5min'],
            'normalized': round(load_5min_norm, 2),
            'threshold': crit_threshold,
            'message': (f"5-min load {loadavg['load_5min']:.2f} "
                        f"({load_5min_norm:.2f} per CPU) indicates sustained "
                        f"critical pressure")
        })
    elif load_5min_norm >= warn_threshold:
        issues.append({
            'type': 'LOAD_5MIN_WARNING',
            'severity': 'warning',
            'load': loadavg['load_5min'],
            'normalized': round(load_5min_norm, 2),
            'threshold': warn_threshold,
            'message': (f"5-min load {loadavg['load_5min']:.2f} "
                        f"({load_5min_norm:.2f} per CPU) indicates sustained "
                        f"warning pressure")
        })

    # Determine overall status
    overall_status = 'ok'
    if any(i['severity'] == 'critical' for i in issues):
        overall_status = 'critical'
    elif any(i['severity'] == 'warning' for i in issues):
        overall_status = 'warning'

    # Trend analysis
    trend = 'stable'
    if loadavg['load_1min'] > loadavg['load_5min'] * 1.5:
        trend = 'increasing'
    elif loadavg['load_1min'] < loadavg['load_5min'] * 0.5:
        trend = 'decreasing'

    return {
        'status': overall_status,
        'cpu_count': cpu_count,
        'loadavg': loadavg,
        'normalized': {
            'load_1min': round(load_1min_norm, 2),
            'load_5min': round(load_5min_norm, 2),
            'load_15min': round(load_15min_norm, 2),
        },
        'trend': trend,
        'issues': issues,
    }


def output_plain(analysis: Dict, uptime: Optional[float],
                 warn_only: bool, verbose: bool) -> None:
    """Output in plain text format."""
    issues = analysis['issues']
    loadavg = analysis['loadavg']
    norm = analysis['normalized']
    cpu_count = analysis['cpu_count']

    # Print issues first
    if issues:
        print("ISSUES DETECTED:")
        for issue in issues:
            severity = issue['severity'].upper()
            print(f"  [{severity}] {issue['message']}")
        print()

    if warn_only and not issues:
        print("OK - Load average within acceptable limits")
        return

    # System info
    print(f"System Load Analysis ({cpu_count} CPUs)")
    print("=" * 50)

    if uptime is not None:
        print(f"Uptime: {format_uptime(uptime)}")
    print()

    # Load average display
    print("Load Averages:")
    print(f"  {'Period':<12} {'Raw':>8} {'Per-CPU':>10}")
    print("  " + "-" * 32)
    print(f"  {'1 minute':<12} {loadavg['load_1min']:>8.2f} {norm['load_1min']:>10.2f}")
    print(f"  {'5 minutes':<12} {loadavg['load_5min']:>8.2f} {norm['load_5min']:>10.2f}")
    print(f"  {'15 minutes':<12} {loadavg['load_15min']:>8.2f} {norm['load_15min']:>10.2f}")
    print()

    # Process info
    print("Processes:")
    print(f"  Running: {loadavg['running_processes']}")
    print(f"  Total:   {loadavg['total_processes']}")
    print()

    # Trend
    print(f"Trend: {analysis['trend'].capitalize()}")
    if analysis['trend'] == 'increasing':
        print("  Load is spiking - monitor closely")
    elif analysis['trend'] == 'decreasing':
        print("  Load is recovering")

    if verbose:
        print()
        print("Interpretation:")
        if norm['load_1min'] < 0.5:
            print("  System is lightly loaded")
        elif norm['load_1min'] < 1.0:
            print("  System is moderately loaded (optimal range)")
        elif norm['load_1min'] < 2.0:
            print("  System is heavily loaded (may experience delays)")
        else:
            print("  System is overloaded (significant scheduling delays)")


def output_json(analysis: Dict, uptime: Optional[float]) -> None:
    """Output in JSON format."""
    result = {
        'status': analysis['status'],
        'cpu_count': analysis['cpu_count'],
        'uptime_seconds': uptime,
        'load': {
            'raw': {
                '1min': analysis['loadavg']['load_1min'],
                '5min': analysis['loadavg']['load_5min'],
                '15min': analysis['loadavg']['load_15min'],
            },
            'normalized': analysis['normalized'],
        },
        'processes': {
            'running': analysis['loadavg']['running_processes'],
            'total': analysis['loadavg']['total_processes'],
        },
        'trend': analysis['trend'],
        'issues': analysis['issues'],
    }
    print(json.dumps(result, indent=2))


def output_table(analysis: Dict, warn_only: bool) -> None:
    """Output in table format."""
    issues = analysis['issues']

    if warn_only:
        if not issues:
            print("No load issues detected")
            return
        print(f"{'Type':<22} {'Severity':<10} {'Load':>8} {'Per-CPU':>10}")
        print("-" * 54)
        for issue in issues:
            print(f"{issue['type']:<22} {issue['severity']:<10} "
                  f"{issue['load']:>8.2f} {issue['normalized']:>10.2f}")
        return

    loadavg = analysis['loadavg']
    norm = analysis['normalized']

    print(f"{'Metric':<20} {'Value':>12}")
    print("-" * 34)
    print(f"{'CPU Cores':<20} {analysis['cpu_count']:>12}")
    print(f"{'Load 1-min':<20} {loadavg['load_1min']:>12.2f}")
    print(f"{'Load 5-min':<20} {loadavg['load_5min']:>12.2f}")
    print(f"{'Load 15-min':<20} {loadavg['load_15min']:>12.2f}")
    print(f"{'Per-CPU 1-min':<20} {norm['load_1min']:>12.2f}")
    print(f"{'Per-CPU 5-min':<20} {norm['load_5min']:>12.2f}")
    print(f"{'Per-CPU 15-min':<20} {norm['load_15min']:>12.2f}")
    print(f"{'Running Procs':<20} {loadavg['running_processes']:>12}")
    print(f"{'Total Procs':<20} {loadavg['total_processes']:>12}")
    print(f"{'Trend':<20} {analysis['trend']:>12}")
    print(f"{'Status':<20} {analysis['status']:>12}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze system load average and CPU scheduling pressure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         Show load average analysis
  %(prog)s --warn-only             Only show if there are issues
  %(prog)s --format json           JSON output for monitoring systems
  %(prog)s --warn 0.8 --crit 1.5   Custom thresholds (per-CPU)

Thresholds (per-CPU normalized):
  < 0.7  - Low load (underutilized)
  0.7-1.0 - Optimal load
  1.0-2.0 - High load (acceptable for bursts)
  > 2.0  - Overloaded (scheduling delays likely)

Exit codes:
  0 - Load within acceptable limits
  1 - Load exceeds warning/critical thresholds
  2 - Usage error or unable to read load information
"""
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed interpretation'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show if there are issues'
    )

    parser.add_argument(
        '--warn',
        type=float,
        default=1.0,
        metavar='THRESHOLD',
        help='Warning threshold (per-CPU load, default: 1.0)'
    )

    parser.add_argument(
        '--crit',
        type=float,
        default=2.0,
        metavar='THRESHOLD',
        help='Critical threshold (per-CPU load, default: 2.0)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.warn < 0:
        print("Error: --warn must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.crit < 0:
        print("Error: --crit must be non-negative", file=sys.stderr)
        sys.exit(2)
    if args.crit < args.warn:
        print("Error: --crit must be >= --warn", file=sys.stderr)
        sys.exit(2)

    # Check if we can read /proc
    if not os.path.isfile('/proc/loadavg'):
        print("Error: /proc/loadavg not available", file=sys.stderr)
        print("This script requires the procfs filesystem", file=sys.stderr)
        sys.exit(2)

    # Get load average
    loadavg = get_loadavg()
    if loadavg is None:
        print("Error: Unable to read load average", file=sys.stderr)
        sys.exit(2)

    # Get CPU count
    cpu_count = get_cpu_count()

    # Get uptime
    uptime = get_uptime()

    # Analyze
    analysis = analyze_load(
        loadavg,
        cpu_count,
        warn_threshold=args.warn,
        crit_threshold=args.crit
    )

    # Output
    if args.format == 'json':
        output_json(analysis, uptime)
    elif args.format == 'table':
        output_table(analysis, args.warn_only)
    else:
        output_plain(analysis, uptime, args.warn_only, args.verbose)

    # Exit code
    if analysis['status'] in ['critical', 'warning']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
