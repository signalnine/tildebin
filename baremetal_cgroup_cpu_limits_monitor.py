#!/usr/bin/env python3
"""
Monitor cgroup CPU resource limits and utilization.

This script analyzes CPU resource allocation for cgroups (containers, systemd
services, etc.) to identify misconfigured or over-constrained workloads.
Works with cgroup v2 unified hierarchy.

CPU resources tracked:
- cpu.max: CPU bandwidth limit (quota/period microseconds)
- cpu.weight: Proportional CPU share (1-10000, default 100)
- cpu.stat: Actual CPU usage statistics
- cpuset.cpus: Pinned CPU cores (if cpuset controller enabled)

Useful for:
- Detecting containers with overly restrictive CPU limits
- Finding services with unfair CPU weight allocation
- Identifying CPU throttling before it impacts latency
- Kubernetes pod CPU quota auditing
- Container host capacity planning

Exit codes:
    0 - No issues detected, all cgroups have reasonable limits
    1 - Warnings or critical issues found (throttling, misconfig)
    2 - Usage error or cgroup v2 not available
"""

import argparse
import sys
import os
import json


def check_cgroup_v2_available():
    """Check if cgroup v2 is mounted"""
    if not os.path.exists('/sys/fs/cgroup/cgroup.controllers'):
        return False, "cgroup v2 not mounted (unified hierarchy required)"
    return True, None


def read_file_value(path):
    """Read a single value from a file, return None if not readable"""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def parse_cpu_max(value):
    """
    Parse cpu.max value.

    Format: "$MAX $PERIOD" where:
    - MAX is quota in microseconds or "max" for unlimited
    - PERIOD is the period in microseconds (default 100000)

    Returns tuple: (quota_us, period_us) or (None, period_us) if unlimited
    """
    if value is None:
        return None, None

    parts = value.split()
    if len(parts) != 2:
        return None, None

    quota_str, period_str = parts

    try:
        period = int(period_str)
    except ValueError:
        period = 100000  # Default

    if quota_str == "max":
        return None, period  # Unlimited

    try:
        quota = int(quota_str)
        return quota, period
    except ValueError:
        return None, period


def parse_cpu_stat(value):
    """
    Parse cpu.stat file.

    Format:
    usage_usec 123456
    user_usec 100000
    system_usec 23456
    nr_periods 1000
    nr_throttled 50
    throttled_usec 5000000
    ...
    """
    stats = {}
    if value is None:
        return stats

    for line in value.strip().split('\n'):
        parts = line.split()
        if len(parts) >= 2:
            key = parts[0]
            try:
                stats[key] = int(parts[1])
            except ValueError:
                stats[key] = parts[1]

    return stats


def get_cgroup_name(path):
    """Extract a readable cgroup name from path"""
    rel_path = os.path.relpath(path, '/sys/fs/cgroup')
    if rel_path == '.':
        return '/'
    return rel_path


def find_cpu_cgroups():
    """Find all cgroups with CPU controller"""
    cgroups = []
    cgroup_root = '/sys/fs/cgroup'

    for root, dirs, files in os.walk(cgroup_root):
        # Check if this cgroup has CPU controls
        if 'cpu.max' in files or 'cpu.weight' in files:
            cgroups.append(root)

    return cgroups


def get_cgroup_cpu_stats(cgroup_path):
    """Get CPU statistics for a cgroup"""
    stats = {
        'path': cgroup_path,
        'name': get_cgroup_name(cgroup_path),
    }

    # Read cpu.max (bandwidth limit)
    cpu_max = read_file_value(os.path.join(cgroup_path, 'cpu.max'))
    quota, period = parse_cpu_max(cpu_max)
    stats['quota_us'] = quota
    stats['period_us'] = period
    stats['cpu_max_raw'] = cpu_max

    # Calculate CPU limit as a percentage of one CPU
    if quota is not None and period is not None and period > 0:
        stats['cpu_limit_pct'] = (quota / period) * 100
    else:
        stats['cpu_limit_pct'] = None  # Unlimited

    # Read cpu.weight (proportional share)
    weight = read_file_value(os.path.join(cgroup_path, 'cpu.weight'))
    if weight is not None:
        try:
            stats['weight'] = int(weight)
        except ValueError:
            stats['weight'] = None
    else:
        stats['weight'] = None

    # Read cpu.stat (usage and throttling)
    cpu_stat = read_file_value(os.path.join(cgroup_path, 'cpu.stat'))
    stat_data = parse_cpu_stat(cpu_stat)
    stats['usage_usec'] = stat_data.get('usage_usec', 0)
    stats['nr_periods'] = stat_data.get('nr_periods', 0)
    stats['nr_throttled'] = stat_data.get('nr_throttled', 0)
    stats['throttled_usec'] = stat_data.get('throttled_usec', 0)

    # Calculate throttle percentage
    if stats['nr_periods'] > 0:
        stats['throttle_pct'] = (stats['nr_throttled'] / stats['nr_periods']) * 100
    else:
        stats['throttle_pct'] = 0.0

    # Read cpuset.cpus if available
    cpuset = read_file_value(os.path.join(cgroup_path, 'cpuset.cpus'))
    stats['cpuset'] = cpuset

    # Read cpuset.cpus.effective (actual available CPUs)
    cpuset_effective = read_file_value(os.path.join(cgroup_path, 'cpuset.cpus.effective'))
    stats['cpuset_effective'] = cpuset_effective

    return stats


def count_cpus_from_cpuset(cpuset_str):
    """Count number of CPUs from cpuset string like '0-3,5,7-9'"""
    if not cpuset_str:
        return None

    count = 0
    for part in cpuset_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                count += int(end) - int(start) + 1
            except ValueError:
                continue
        elif part:
            try:
                int(part)  # Validate it's a number
                count += 1
            except ValueError:
                continue

    return count if count > 0 else None


def analyze_cgroup(stats, throttle_warn, throttle_crit, low_weight_threshold):
    """Analyze a cgroup and return any issues"""
    issues = []
    name = stats['name']

    # Check for CPU throttling
    throttle_pct = stats.get('throttle_pct', 0)
    if throttle_pct >= throttle_crit:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'throttling',
            'cgroup': name,
            'throttle_pct': round(throttle_pct, 1),
            'nr_throttled': stats.get('nr_throttled', 0),
            'message': f"CPU throttled {throttle_pct:.1f}% of periods ({stats.get('nr_throttled', 0)} throttled)"
        })
    elif throttle_pct >= throttle_warn:
        issues.append({
            'severity': 'WARNING',
            'type': 'throttling',
            'cgroup': name,
            'throttle_pct': round(throttle_pct, 1),
            'nr_throttled': stats.get('nr_throttled', 0),
            'message': f"CPU throttled {throttle_pct:.1f}% of periods ({stats.get('nr_throttled', 0)} throttled)"
        })

    # Check for very low CPU weight (unfair scheduling)
    weight = stats.get('weight')
    if weight is not None and weight < low_weight_threshold:
        issues.append({
            'severity': 'WARNING',
            'type': 'low_weight',
            'cgroup': name,
            'weight': weight,
            'message': f"Very low CPU weight ({weight}), may be starved for CPU"
        })

    # Check for very restrictive CPU limits (< 10% of one CPU)
    cpu_limit = stats.get('cpu_limit_pct')
    if cpu_limit is not None and cpu_limit < 10:
        issues.append({
            'severity': 'WARNING',
            'type': 'low_limit',
            'cgroup': name,
            'cpu_limit_pct': round(cpu_limit, 1),
            'message': f"Very restrictive CPU limit ({cpu_limit:.1f}% of one core)"
        })

    return issues


def format_cpu_limit(stats):
    """Format CPU limit as a human-readable string"""
    if stats.get('cpu_limit_pct') is None:
        return "unlimited"

    limit = stats['cpu_limit_pct']
    if limit >= 100:
        cores = limit / 100
        return f"{cores:.1f} cores"
    else:
        return f"{limit:.0f}%"


def format_usec(usec):
    """Format microseconds as human-readable duration"""
    if usec is None or usec == 0:
        return "0"
    if usec < 1000:
        return f"{usec}µs"
    elif usec < 1000000:
        return f"{usec / 1000:.1f}ms"
    elif usec < 60000000:
        return f"{usec / 1000000:.1f}s"
    else:
        return f"{usec / 60000000:.1f}min"


def output_plain(results, issues, warn_only, verbose, top_n):
    """Output results in plain text format"""
    lines = []

    # Sort by throttle percentage (highest first), then by CPU usage
    sorted_results = sorted(
        results,
        key=lambda x: (x.get('throttle_pct', 0), x.get('usage_usec', 0)),
        reverse=True
    )

    if not warn_only:
        lines.append("Cgroup CPU Limits Monitor")
        lines.append("=" * 70)
        lines.append("")

        # Show top N by throttling
        throttled = [r for r in sorted_results if r.get('throttle_pct', 0) > 0]
        if throttled:
            lines.append(f"Top Throttled Cgroups:")
            lines.append(f"{'Cgroup':<45} {'Limit':<12} {'Throttle%':>10}")
            lines.append("-" * 70)

            for stats in throttled[:top_n]:
                name = stats['name']
                if len(name) > 43:
                    name = "..." + name[-40:]

                limit = format_cpu_limit(stats)
                throttle = stats.get('throttle_pct', 0)

                lines.append(f"{name:<45} {limit:<12} {throttle:>9.1f}%")

            lines.append("")

        # Show cgroups with limits
        limited = [r for r in results if r.get('cpu_limit_pct') is not None]
        if limited and verbose:
            lines.append(f"Cgroups with CPU Limits ({len(limited)}):")
            lines.append(f"{'Cgroup':<45} {'Limit':<12} {'Weight':>8}")
            lines.append("-" * 70)

            for stats in sorted(limited, key=lambda x: x.get('cpu_limit_pct', 0)):
                name = stats['name']
                if len(name) > 43:
                    name = "..." + name[-40:]

                limit = format_cpu_limit(stats)
                weight = stats.get('weight', '-')

                lines.append(f"{name:<45} {limit:<12} {weight:>8}")

            lines.append("")

    # Show issues
    if issues:
        critical = [i for i in issues if i['severity'] == 'CRITICAL']
        warnings = [i for i in issues if i['severity'] == 'WARNING']

        if critical:
            lines.append(f"CRITICAL Issues ({len(critical)}):")
            for issue in critical:
                lines.append(f"  !!! {issue['cgroup']}: {issue['message']}")
            lines.append("")

        if warnings:
            lines.append(f"Warnings ({len(warnings)}):")
            for issue in warnings:
                lines.append(f"  {issue['cgroup']}: {issue['message']}")
            lines.append("")
    elif not warn_only:
        lines.append("No CPU limit issues detected.")
        lines.append("")

    # Summary
    if verbose and not warn_only:
        total = len(results)
        limited = len([r for r in results if r.get('cpu_limit_pct') is not None])
        throttled = len([r for r in results if r.get('throttle_pct', 0) > 0])
        lines.append(f"Summary: {total} cgroups, {limited} with limits, {throttled} experiencing throttling")

    return '\n'.join(lines)


def output_json(results, issues):
    """Output results in JSON format"""
    # Filter to meaningful cgroups
    meaningful = [
        r for r in results
        if r.get('cpu_limit_pct') is not None or r.get('usage_usec', 0) > 0
    ]

    output = {
        'cgroups': meaningful,
        'issues': issues,
        'summary': {
            'total_cgroups': len(results),
            'with_limits': len([r for r in results if r.get('cpu_limit_pct') is not None]),
            'throttled': len([r for r in results if r.get('throttle_pct', 0) > 0]),
            'critical_count': len([i for i in issues if i['severity'] == 'CRITICAL']),
            'warning_count': len([i for i in issues if i['severity'] == 'WARNING'])
        }
    }

    return json.dumps(output, indent=2)


def output_table(results, issues, warn_only, top_n):
    """Output results in table format"""
    lines = []

    # Sort by throttle percentage
    sorted_results = sorted(
        results,
        key=lambda x: (x.get('throttle_pct', 0), x.get('usage_usec', 0)),
        reverse=True
    )

    if warn_only:
        # Only show cgroups with issues
        issue_cgroups = set(i['cgroup'] for i in issues)
        sorted_results = [r for r in sorted_results if r['name'] in issue_cgroups]

    lines.append(f"{'Cgroup':<40} {'Limit':<10} {'Weight':>6} {'Throttle':>9} {'Status':<10}")
    lines.append("-" * 80)

    for stats in sorted_results[:top_n]:
        name = stats['name']
        if len(name) > 38:
            name = "..." + name[-35:]

        limit = format_cpu_limit(stats)
        weight = stats.get('weight', '-')
        if weight == '-':
            weight_str = '-'
        else:
            weight_str = str(weight)

        throttle = stats.get('throttle_pct', 0)

        # Determine status
        status = "OK"
        cgroup_issues = [i for i in issues if i['cgroup'] == stats['name']]
        if any(i['severity'] == 'CRITICAL' for i in cgroup_issues):
            status = "CRITICAL"
        elif any(i['severity'] == 'WARNING' for i in cgroup_issues):
            status = "WARNING"

        lines.append(f"{name:<40} {limit:<10} {weight_str:>6} {throttle:>8.1f}% {status:<10}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor cgroup CPU resource limits and utilization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                            # Check all cgroups
  %(prog)s --format json              # JSON output for monitoring
  %(prog)s --throttle-warn 5          # Warn at 5%% throttling
  %(prog)s --verbose                  # Show all cgroups with limits
  %(prog)s --warn-only                # Only show issues
  %(prog)s --cgroup /system.slice    # Check specific cgroup

CPU Files (cgroup v2):
  cpu.max     - Bandwidth limit: "QUOTA PERIOD" or "max PERIOD"
  cpu.weight  - Proportional share (1-10000, default 100)
  cpu.stat    - Usage stats including throttling counts
  cpuset.cpus - Pinned CPU cores

Exit codes:
  0 - No issues detected
  1 - Warnings or critical issues found
  2 - Usage error or cgroup v2 not available

Notes:
  - CPU throttling indicates quota exhaustion
  - Low weight (<50) may cause starvation under contention
  - Works with Docker, containerd, Kubernetes pods
  - Throttling is expected under load; high rates indicate limit issues
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
        help="Show additional details"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show cgroups with issues"
    )

    parser.add_argument(
        "--throttle-warn",
        type=float,
        default=10.0,
        help="Throttle warning threshold percentage (default: %(default)s%%)"
    )

    parser.add_argument(
        "--throttle-crit",
        type=float,
        default=25.0,
        help="Throttle critical threshold percentage (default: %(default)s%%)"
    )

    parser.add_argument(
        "--low-weight",
        type=int,
        default=50,
        help="Warn if CPU weight below this value (default: %(default)s)"
    )

    parser.add_argument(
        "--top",
        type=int,
        default=15,
        help="Show top N cgroups (default: %(default)s)"
    )

    parser.add_argument(
        "--cgroup",
        help="Monitor specific cgroup path (relative to /sys/fs/cgroup)"
    )

    args = parser.parse_args()

    # Validate thresholds
    if not 0.0 <= args.throttle_warn <= 100.0:
        print("Error: Throttle warning threshold must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if not 0.0 <= args.throttle_crit <= 100.0:
        print("Error: Throttle critical threshold must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.throttle_warn >= args.throttle_crit:
        print("Error: Warning threshold must be less than critical threshold",
              file=sys.stderr)
        sys.exit(2)

    if not 1 <= args.low_weight <= 10000:
        print("Error: Low weight threshold must be between 1 and 10000", file=sys.stderr)
        sys.exit(2)

    # Check for cgroup v2
    available, error = check_cgroup_v2_available()
    if not available:
        print(f"Error: {error}", file=sys.stderr)
        print("Ensure cgroup v2 unified hierarchy is mounted", file=sys.stderr)
        sys.exit(2)

    # Find cgroups to analyze
    if args.cgroup:
        cgroup_path = args.cgroup
        if not cgroup_path.startswith('/'):
            cgroup_path = f'/sys/fs/cgroup/{cgroup_path}'

        if not os.path.exists(cgroup_path):
            print(f"Error: Cgroup not found: {cgroup_path}", file=sys.stderr)
            sys.exit(2)

        cgroup_paths = [cgroup_path]
    else:
        cgroup_paths = find_cpu_cgroups()

    if not cgroup_paths:
        print("Error: No cgroups with CPU controller found", file=sys.stderr)
        sys.exit(2)

    # Gather stats for all cgroups
    results = []
    all_issues = []

    for path in cgroup_paths:
        stats = get_cgroup_cpu_stats(path)
        results.append(stats)

        # Analyze for issues
        issues = analyze_cgroup(
            stats,
            args.throttle_warn,
            args.throttle_crit,
            args.low_weight
        )
        all_issues.extend(issues)

    # Output results
    if args.format == "json":
        output = output_json(results, all_issues)
    elif args.format == "table":
        output = output_table(results, all_issues, args.warn_only, args.top)
    else:  # plain
        output = output_plain(results, all_issues, args.warn_only, args.verbose, args.top)

    print(output)

    # Exit based on findings
    has_critical = any(i['severity'] == 'CRITICAL' for i in all_issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in all_issues)

    if has_critical or has_warnings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
