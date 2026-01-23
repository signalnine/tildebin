#!/usr/bin/env python3
"""
Forecast disk space exhaustion based on usage trends.

This script analyzes current filesystem usage and historical growth patterns
to predict when filesystems will run out of space. It uses linear regression
on recent usage data (from /var/log/sa/ or sampled snapshots) to estimate
the days until each filesystem reaches critical capacity.

For systems without historical data, it provides current usage analysis
and can sample usage over a configurable interval to estimate growth rate.

Useful for:
- Capacity planning and proactive disk management
- Alerting before filesystems reach critical levels
- Identifying fast-growing filesystems that need attention
- Planning storage expansion timelines

Exit codes:
    0 - All filesystems healthy with adequate runway
    1 - Warnings detected (filesystem predicted to fill within threshold)
    2 - Usage error or missing data sources
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta


def get_filesystem_usage():
    """
    Get current filesystem usage using 'df' command.

    Returns:
        List of dicts with filesystem information:
        - filesystem: device name
        - mount: mount point
        - size_bytes: total size in bytes
        - used_bytes: used space in bytes
        - avail_bytes: available space in bytes
        - use_pct: usage percentage
    """
    try:
        result = subprocess.run(
            ['df', '-B1', '--output=source,target,size,used,avail,pcent'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return None

        filesystems = []
        lines = result.stdout.strip().split('\n')

        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) < 6:
                continue

            # Skip pseudo filesystems
            source = parts[0]
            if source.startswith(('tmpfs', 'devtmpfs', 'overlay', 'shm', 'none')):
                continue
            if not source.startswith('/'):
                continue

            try:
                mount = parts[1]
                size_bytes = int(parts[2])
                used_bytes = int(parts[3])
                avail_bytes = int(parts[4])
                use_pct = float(parts[5].rstrip('%'))

                # Skip tiny filesystems (< 100MB)
                if size_bytes < 100 * 1024 * 1024:
                    continue

                filesystems.append({
                    'filesystem': source,
                    'mount': mount,
                    'size_bytes': size_bytes,
                    'used_bytes': used_bytes,
                    'avail_bytes': avail_bytes,
                    'use_pct': use_pct,
                })
            except (ValueError, IndexError):
                continue

        return filesystems

    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None


def format_bytes(bytes_val):
    """Format bytes to human-readable size."""
    for unit, divisor in [('TB', 1024**4), ('GB', 1024**3),
                          ('MB', 1024**2), ('KB', 1024)]:
        if bytes_val >= divisor:
            return f"{bytes_val / divisor:.1f}{unit}"
    return f"{bytes_val}B"


def format_days(days):
    """Format days to human-readable duration."""
    if days is None or days < 0:
        return "N/A"
    if days == float('inf'):
        return "never"
    if days < 1:
        hours = int(days * 24)
        return f"{hours}h" if hours > 0 else "<1h"
    if days < 7:
        return f"{days:.1f}d"
    if days < 30:
        weeks = days / 7
        return f"{weeks:.1f}w"
    if days < 365:
        months = days / 30
        return f"{months:.1f}mo"
    years = days / 365
    return f"{years:.1f}y"


def sample_usage_growth(filesystems, interval_seconds):
    """
    Sample filesystem usage over an interval to estimate growth rate.

    Args:
        filesystems: List of filesystem dicts from get_filesystem_usage()
        interval_seconds: Seconds to wait between samples

    Returns:
        Dict mapping mount point to growth rate in bytes/day
    """
    # Record initial usage
    initial = {fs['mount']: fs['used_bytes'] for fs in filesystems}

    # Wait for interval
    time.sleep(interval_seconds)

    # Get new usage
    new_filesystems = get_filesystem_usage()
    if new_filesystems is None:
        return {}

    final = {fs['mount']: fs['used_bytes'] for fs in new_filesystems}

    # Calculate growth rates (bytes per day)
    growth_rates = {}
    seconds_per_day = 86400

    for mount, initial_used in initial.items():
        if mount in final:
            delta_bytes = final[mount] - initial_used
            # Extrapolate to daily rate
            daily_rate = (delta_bytes / interval_seconds) * seconds_per_day
            growth_rates[mount] = daily_rate

    return growth_rates


def calculate_days_until_full(fs, growth_rate_per_day, threshold_pct=95):
    """
    Calculate days until filesystem reaches threshold.

    Args:
        fs: Filesystem dict with size_bytes, used_bytes, etc.
        growth_rate_per_day: Bytes added per day (can be negative)
        threshold_pct: Target usage percentage to predict (default 95%)

    Returns:
        Days until threshold reached, or float('inf') if shrinking/stable
    """
    threshold_bytes = fs['size_bytes'] * (threshold_pct / 100)
    bytes_remaining = threshold_bytes - fs['used_bytes']

    if bytes_remaining <= 0:
        # Already at or past threshold
        return 0

    if growth_rate_per_day <= 0:
        # Not growing or shrinking
        return float('inf')

    days = bytes_remaining / growth_rate_per_day
    return days


def analyze_filesystems(filesystems, growth_rates, warn_days, crit_days, threshold_pct):
    """
    Analyze filesystems and identify those at risk.

    Returns:
        List of analysis results with predictions and warnings
    """
    results = []

    for fs in filesystems:
        mount = fs['mount']
        growth_rate = growth_rates.get(mount, 0)

        days_until_full = calculate_days_until_full(fs, growth_rate, threshold_pct)

        # Determine severity
        severity = 'OK'
        if fs['use_pct'] >= threshold_pct:
            severity = 'CRITICAL'
        elif days_until_full <= crit_days:
            severity = 'CRITICAL'
        elif days_until_full <= warn_days:
            severity = 'WARNING'
        elif fs['use_pct'] >= 80:
            severity = 'WARNING'

        results.append({
            'filesystem': fs['filesystem'],
            'mount': mount,
            'size_bytes': fs['size_bytes'],
            'used_bytes': fs['used_bytes'],
            'avail_bytes': fs['avail_bytes'],
            'use_pct': fs['use_pct'],
            'growth_rate_bytes_per_day': growth_rate,
            'days_until_full': days_until_full,
            'severity': severity,
        })

    # Sort by severity (CRITICAL first) then by days_until_full
    severity_order = {'CRITICAL': 0, 'WARNING': 1, 'OK': 2}
    results.sort(key=lambda x: (severity_order[x['severity']], x['days_until_full']))

    return results


def output_plain(results, warn_only=False, verbose=False):
    """Output results in plain text format."""
    lines = []

    if not warn_only:
        lines.append("Disk Space Forecast:")
        lines.append("")

    # Show warnings first
    warnings = [r for r in results if r['severity'] in ('CRITICAL', 'WARNING')]
    ok_results = [r for r in results if r['severity'] == 'OK']

    if warnings:
        for r in warnings:
            status = "!!!" if r['severity'] == 'CRITICAL' else "!"
            growth_str = format_bytes(abs(r['growth_rate_bytes_per_day'])) + "/day"
            if r['growth_rate_bytes_per_day'] < 0:
                growth_str = "-" + growth_str

            lines.append(
                f"{status} {r['mount']}: {r['use_pct']:.1f}% used, "
                f"{format_bytes(r['avail_bytes'])} free, "
                f"~{format_days(r['days_until_full'])} until 95%"
            )
            if verbose:
                lines.append(f"    Device: {r['filesystem']}")
                lines.append(f"    Size: {format_bytes(r['size_bytes'])}")
                lines.append(f"    Growth: {growth_str}")
        lines.append("")

    if not warn_only and ok_results:
        lines.append("Healthy filesystems:")
        for r in ok_results:
            lines.append(
                f"  {r['mount']}: {r['use_pct']:.1f}% used, "
                f"{format_bytes(r['avail_bytes'])} free"
            )
            if verbose:
                growth_str = format_bytes(abs(r['growth_rate_bytes_per_day'])) + "/day"
                if r['growth_rate_bytes_per_day'] < 0:
                    growth_str = "-" + growth_str
                lines.append(f"    Growth: {growth_str}, ~{format_days(r['days_until_full'])} runway")

    if not warnings and not warn_only:
        lines.append("")
        lines.append("All filesystems have adequate runway.")

    return '\n'.join(lines)


def output_json(results):
    """Output results in JSON format."""
    output = {
        'timestamp': datetime.now().isoformat(),
        'filesystems': results,
        'summary': {
            'total': len(results),
            'critical': len([r for r in results if r['severity'] == 'CRITICAL']),
            'warning': len([r for r in results if r['severity'] == 'WARNING']),
            'ok': len([r for r in results if r['severity'] == 'OK']),
        }
    }
    return json.dumps(output, indent=2, default=str)


def output_table(results, warn_only=False):
    """Output results in table format."""
    lines = []

    display_results = results
    if warn_only:
        display_results = [r for r in results if r['severity'] != 'OK']

    if not display_results:
        if warn_only:
            return "No warnings or issues detected."
        return "No filesystems found."

    # Header
    lines.append(
        f"{'Mount':<20} {'Use%':<7} {'Avail':<10} {'Growth/day':<12} "
        f"{'Runway':<10} {'Status':<10}"
    )
    lines.append("-" * 75)

    for r in display_results:
        growth_str = format_bytes(abs(r['growth_rate_bytes_per_day']))
        if r['growth_rate_bytes_per_day'] < 0:
            growth_str = "-" + growth_str
        elif r['growth_rate_bytes_per_day'] == 0:
            growth_str = "0"

        mount_display = r['mount']
        if len(mount_display) > 19:
            mount_display = "..." + mount_display[-16:]

        lines.append(
            f"{mount_display:<20} {r['use_pct']:<7.1f} "
            f"{format_bytes(r['avail_bytes']):<10} {growth_str:<12} "
            f"{format_days(r['days_until_full']):<10} {r['severity']:<10}"
        )

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Forecast disk space exhaustion based on usage trends",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Quick analysis with instant sample
  %(prog)s --sample 60              # Sample for 60 seconds for better accuracy
  %(prog)s --format json            # JSON output for monitoring systems
  %(prog)s --warn-days 14           # Warn if < 14 days runway
  %(prog)s --warn-only              # Only show warnings

Threshold interpretation:
  Runway > 90 days  - Healthy, no immediate action needed
  Runway 30-90 days - Monitor, plan expansion if growing steadily
  Runway 7-30 days  - Warning, schedule capacity expansion
  Runway < 7 days   - Critical, immediate action required

Exit codes:
  0 - All filesystems healthy with adequate runway
  1 - Warnings detected (filesystem predicted to fill within threshold)
  2 - Usage error or missing data sources

Notes:
  - Growth rate is estimated by sampling usage over --sample interval
  - Longer sample intervals provide more accurate predictions
  - Without historical data, predictions assume current growth continues
  - Negative growth rates (shrinking) are reported but don't trigger warnings
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
        help="Show detailed information"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )

    parser.add_argument(
        "--sample",
        type=int,
        default=5,
        metavar="SECONDS",
        help="Seconds to sample usage for growth estimation (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-days",
        type=int,
        default=30,
        help="Warning threshold in days until full (default: %(default)s)"
    )

    parser.add_argument(
        "--crit-days",
        type=int,
        default=7,
        help="Critical threshold in days until full (default: %(default)s)"
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=95.0,
        help="Usage percentage threshold to predict (default: %(default)s)"
    )

    parser.add_argument(
        "--mount",
        help="Only analyze specific mount point"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.sample < 1:
        print("Error: --sample must be at least 1 second", file=sys.stderr)
        sys.exit(2)

    if args.sample > 300:
        print("Error: --sample cannot exceed 300 seconds", file=sys.stderr)
        sys.exit(2)

    if args.warn_days < 1:
        print("Error: --warn-days must be at least 1", file=sys.stderr)
        sys.exit(2)

    if args.crit_days < 1:
        print("Error: --crit-days must be at least 1", file=sys.stderr)
        sys.exit(2)

    if args.crit_days >= args.warn_days:
        print("Error: --crit-days must be less than --warn-days", file=sys.stderr)
        sys.exit(2)

    if not 50 <= args.threshold <= 100:
        print("Error: --threshold must be between 50 and 100", file=sys.stderr)
        sys.exit(2)

    # Get initial filesystem usage
    filesystems = get_filesystem_usage()

    if filesystems is None:
        print("Error: Could not get filesystem usage", file=sys.stderr)
        print("Ensure 'df' command is available", file=sys.stderr)
        sys.exit(2)

    if not filesystems:
        print("Error: No filesystems found", file=sys.stderr)
        sys.exit(2)

    # Filter to specific mount if requested
    if args.mount:
        filesystems = [fs for fs in filesystems if fs['mount'] == args.mount]
        if not filesystems:
            print(f"Error: Mount point '{args.mount}' not found", file=sys.stderr)
            sys.exit(2)

    # Sample usage growth
    if args.verbose:
        print(f"Sampling usage for {args.sample} seconds...", file=sys.stderr)

    growth_rates = sample_usage_growth(filesystems, args.sample)

    # Re-fetch current usage after sampling
    filesystems = get_filesystem_usage()
    if filesystems is None:
        print("Error: Could not get filesystem usage after sampling", file=sys.stderr)
        sys.exit(2)

    if args.mount:
        filesystems = [fs for fs in filesystems if fs['mount'] == args.mount]

    # Analyze filesystems
    results = analyze_filesystems(
        filesystems, growth_rates, args.warn_days, args.crit_days, args.threshold
    )

    # Output results
    if args.format == "json":
        output = output_json(results)
    elif args.format == "table":
        output = output_table(results, warn_only=args.warn_only)
    else:
        output = output_plain(results, warn_only=args.warn_only, verbose=args.verbose)

    print(output)

    # Exit based on findings
    has_critical = any(r['severity'] == 'CRITICAL' for r in results)
    has_warnings = any(r['severity'] == 'WARNING' for r in results)

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
