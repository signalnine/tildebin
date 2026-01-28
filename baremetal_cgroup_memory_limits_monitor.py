#!/usr/bin/env python3
"""
Monitor cgroup memory usage against configured limits.

This script analyzes container/cgroup memory usage relative to their configured
limits (memory.max) to identify containers at risk of OOM kills. It works with
cgroup v2 and provides early warning before memory exhaustion.

Metrics tracked:
- memory.current: Current memory usage
- memory.max: Configured limit (or "max" for unlimited)
- memory.swap.current: Swap usage (if enabled)
- memory.swap.max: Swap limit

Useful for:
- Container host capacity monitoring
- Predicting OOM kills before they happen
- Identifying memory-hungry containers
- Kubernetes node memory pressure analysis
- Docker/containerd host health checks

Exit codes:
    0 - No issues detected, all cgroups within safe limits
    1 - Warnings or critical issues found (high memory usage)
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


def parse_memory_value(value_str):
    """
    Parse memory value string.
    Returns bytes as int, or None for 'max'/unlimited.
    """
    if value_str is None:
        return None
    if value_str == 'max':
        return None  # Unlimited
    try:
        return int(value_str)
    except ValueError:
        return None


def format_bytes(bytes_val):
    """Format bytes as human-readable string"""
    if bytes_val is None:
        return "unlimited"
    if bytes_val < 1024:
        return f"{bytes_val}B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f}Ki"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.1f}Mi"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f}Gi"


def get_cgroup_name(path):
    """Extract a readable cgroup name from path"""
    rel_path = os.path.relpath(path, '/sys/fs/cgroup')
    if rel_path == '.':
        return '/'
    return rel_path


def find_memory_cgroups():
    """Find all cgroups with memory controller"""
    cgroups = []
    cgroup_root = '/sys/fs/cgroup'

    for root, dirs, files in os.walk(cgroup_root):
        # Check if this cgroup has memory controls
        if 'memory.current' in files:
            cgroups.append(root)

    return cgroups


def get_cgroup_memory_stats(cgroup_path):
    """Get memory statistics for a cgroup"""
    stats = {
        'path': cgroup_path,
        'name': get_cgroup_name(cgroup_path),
    }

    # Read memory.current (usage)
    current = read_file_value(os.path.join(cgroup_path, 'memory.current'))
    stats['current'] = parse_memory_value(current)
    stats['current_raw'] = current

    # Read memory.max (limit)
    max_val = read_file_value(os.path.join(cgroup_path, 'memory.max'))
    stats['max'] = parse_memory_value(max_val)
    stats['max_raw'] = max_val

    # Read memory.swap.current (if available)
    swap_current = read_file_value(os.path.join(cgroup_path, 'memory.swap.current'))
    stats['swap_current'] = parse_memory_value(swap_current)

    # Read memory.swap.max (if available)
    swap_max = read_file_value(os.path.join(cgroup_path, 'memory.swap.max'))
    stats['swap_max'] = parse_memory_value(swap_max)

    # Read memory.high (soft limit, if available)
    high = read_file_value(os.path.join(cgroup_path, 'memory.high'))
    stats['high'] = parse_memory_value(high)

    # Calculate utilization
    if stats['current'] is not None and stats['max'] is not None:
        stats['utilization'] = (stats['current'] / stats['max']) * 100
    else:
        stats['utilization'] = None

    # Calculate swap utilization
    if stats['swap_current'] is not None and stats['swap_max'] is not None:
        stats['swap_utilization'] = (stats['swap_current'] / stats['swap_max']) * 100
    else:
        stats['swap_utilization'] = None

    return stats


def analyze_cgroup(stats, warn_threshold, crit_threshold):
    """Analyze a cgroup and return any issues"""
    issues = []

    name = stats['name']
    utilization = stats['utilization']

    # Skip cgroups with no limit (unlimited)
    if stats['max'] is None:
        return issues

    # Skip cgroups with no usage data
    if stats['current'] is None:
        return issues

    # Check memory utilization
    if utilization is not None:
        if utilization >= crit_threshold:
            issues.append({
                'severity': 'CRITICAL',
                'type': 'high_memory',
                'cgroup': name,
                'utilization': round(utilization, 1),
                'current': stats['current'],
                'max': stats['max'],
                'message': f"Memory at {utilization:.1f}% ({format_bytes(stats['current'])}/{format_bytes(stats['max'])})"
            })
        elif utilization >= warn_threshold:
            issues.append({
                'severity': 'WARNING',
                'type': 'high_memory',
                'cgroup': name,
                'utilization': round(utilization, 1),
                'current': stats['current'],
                'max': stats['max'],
                'message': f"Memory at {utilization:.1f}% ({format_bytes(stats['current'])}/{format_bytes(stats['max'])})"
            })

    # Check swap utilization (if swap is limited)
    swap_util = stats.get('swap_utilization')
    if swap_util is not None and swap_util >= warn_threshold:
        severity = 'CRITICAL' if swap_util >= crit_threshold else 'WARNING'
        issues.append({
            'severity': severity,
            'type': 'high_swap',
            'cgroup': name,
            'utilization': round(swap_util, 1),
            'message': f"Swap at {swap_util:.1f}%"
        })

    return issues


def output_plain(results, issues, warn_only, verbose, top_n):
    """Output results in plain text format"""
    lines = []

    # Sort by utilization (highest first)
    sorted_results = sorted(
        [r for r in results if r['utilization'] is not None],
        key=lambda x: x['utilization'],
        reverse=True
    )

    if not warn_only:
        lines.append("Cgroup Memory Limits Monitor")
        lines.append("=" * 60)
        lines.append("")

        # Show top N consumers
        lines.append(f"Top {top_n} Memory Consumers (by utilization):")
        lines.append(f"{'Cgroup':<40} {'Usage':<12} {'Limit':<12} {'%':>6}")
        lines.append("-" * 72)

        for stats in sorted_results[:top_n]:
            name = stats['name']
            if len(name) > 38:
                name = "..." + name[-35:]

            current = format_bytes(stats['current'])
            max_val = format_bytes(stats['max'])
            util = stats['utilization']

            lines.append(f"{name:<40} {current:<12} {max_val:<12} {util:>5.1f}%")

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
        lines.append("No memory limit issues detected.")
        lines.append("")

    # Verbose: show all cgroups with limits
    if verbose and not warn_only:
        limited = [r for r in results if r['max'] is not None]
        unlimited = [r for r in results if r['max'] is None and r['current'] is not None]

        lines.append(f"Summary: {len(limited)} cgroups with limits, {len(unlimited)} unlimited")

    return '\n'.join(lines)


def output_json(results, issues):
    """Output results in JSON format"""
    # Filter to meaningful cgroups (with limits or significant usage)
    meaningful = [
        r for r in results
        if r['max'] is not None or (r['current'] is not None and r['current'] > 0)
    ]

    output = {
        'cgroups': meaningful,
        'issues': issues,
        'summary': {
            'total_cgroups': len(results),
            'with_limits': len([r for r in results if r['max'] is not None]),
            'critical_count': len([i for i in issues if i['severity'] == 'CRITICAL']),
            'warning_count': len([i for i in issues if i['severity'] == 'WARNING'])
        }
    }

    return json.dumps(output, indent=2)


def output_table(results, issues, warn_only, top_n):
    """Output results in table format"""
    lines = []

    # Sort by utilization
    sorted_results = sorted(
        [r for r in results if r['utilization'] is not None],
        key=lambda x: x['utilization'],
        reverse=True
    )

    if warn_only:
        # Only show cgroups with issues
        issue_cgroups = set(i['cgroup'] for i in issues)
        sorted_results = [r for r in sorted_results if r['name'] in issue_cgroups]

    lines.append(f"{'Cgroup':<45} {'Current':<10} {'Limit':<10} {'Util%':>7} {'Status':<10}")
    lines.append("-" * 85)

    for stats in sorted_results[:top_n]:
        name = stats['name']
        if len(name) > 43:
            name = "..." + name[-40:]

        current = format_bytes(stats['current'])
        max_val = format_bytes(stats['max'])
        util = stats['utilization']

        # Determine status
        status = "OK"
        cgroup_issues = [i for i in issues if i['cgroup'] == stats['name']]
        if any(i['severity'] == 'CRITICAL' for i in cgroup_issues):
            status = "CRITICAL"
        elif any(i['severity'] == 'WARNING' for i in cgroup_issues):
            status = "WARNING"

        lines.append(f"{name:<45} {current:<10} {max_val:<10} {util:>6.1f}% {status:<10}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor cgroup memory usage against configured limits",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         # Check all cgroups
  %(prog)s --warn 70 --crit 85     # Custom thresholds
  %(prog)s --format json           # JSON output for monitoring
  %(prog)s --top 20 --verbose      # Show top 20 with details
  %(prog)s --warn-only             # Only show issues
  %(prog)s --cgroup /system.slice  # Check specific cgroup

Memory Files (cgroup v2):
  memory.current  - Current memory usage in bytes
  memory.max      - Hard limit ("max" = unlimited)
  memory.high     - Soft limit (throttling threshold)
  memory.swap.*   - Swap usage and limits

Exit codes:
  0 - No issues detected
  1 - Warnings or critical issues found
  2 - Usage error or cgroup v2 not available

Notes:
  - Requires cgroup v2 unified hierarchy
  - High memory utilization (>80%%) indicates OOM risk
  - Containers without limits show as "unlimited"
  - Works with Docker, containerd, Kubernetes pods
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
        "--warn",
        type=float,
        default=80.0,
        help="Warning threshold percentage (default: %(default)s%%)"
    )

    parser.add_argument(
        "--crit",
        type=float,
        default=90.0,
        help="Critical threshold percentage (default: %(default)s%%)"
    )

    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Show top N memory consumers (default: %(default)s)"
    )

    parser.add_argument(
        "--cgroup",
        help="Monitor specific cgroup path (relative to /sys/fs/cgroup)"
    )

    parser.add_argument(
        "--min-usage",
        type=int,
        default=0,
        help="Minimum memory usage in bytes to include (default: %(default)s)"
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
        cgroup_paths = find_memory_cgroups()

    if not cgroup_paths:
        print("Error: No cgroups with memory controller found", file=sys.stderr)
        sys.exit(2)

    # Gather stats for all cgroups
    results = []
    all_issues = []

    for path in cgroup_paths:
        stats = get_cgroup_memory_stats(path)

        # Apply minimum usage filter
        if stats['current'] is not None and stats['current'] >= args.min_usage:
            results.append(stats)

            # Analyze for issues
            issues = analyze_cgroup(stats, args.warn, args.crit)
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
