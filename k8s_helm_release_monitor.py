#!/usr/bin/env python3
"""
Monitor Helm release health and deployment status in Kubernetes clusters.

This script provides visibility into Helm releases, including:
- Release status (deployed, failed, pending-install, pending-upgrade, etc.)
- Chart versions and app versions
- Release age and last deployment time
- Detection of failed or stalled releases
- Namespace-based filtering

Useful for monitoring Helm-managed applications in production environments.

Exit codes:
    0 - All Helm releases healthy (deployed status)
    1 - One or more releases in failed or problematic state
    2 - Usage error or helm not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def run_helm(args):
    """Run helm command and return output."""
    try:
        result = subprocess.run(
            ['helm'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        print("Error: helm not found in PATH", file=sys.stderr)
        print("Install helm: https://helm.sh/docs/intro/install/", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running helm: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_releases(namespace=None):
    """Get all Helm releases in JSON format."""
    args = ['list', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_helm(args)
    if not output.strip():
        return []
    return json.loads(output)


def parse_timestamp(timestamp_str):
    """Parse Helm timestamp string to datetime object."""
    if not timestamp_str:
        return None
    try:
        # Helm uses RFC3339 format: 2024-01-15T10:30:00.123456789Z
        # Python's fromisoformat doesn't handle nanoseconds, so truncate
        if '.' in timestamp_str:
            base, frac = timestamp_str.rsplit('.', 1)
            # Keep only microseconds (6 digits)
            frac = frac.rstrip('Z')[:6]
            timestamp_str = f"{base}.{frac}+00:00"
        else:
            timestamp_str = timestamp_str.replace('Z', '+00:00')
        return datetime.fromisoformat(timestamp_str)
    except (ValueError, AttributeError):
        return None


def calculate_age(timestamp):
    """Calculate human-readable age from timestamp."""
    if not timestamp:
        return "unknown"

    now = datetime.now(timezone.utc)
    delta = now - timestamp

    days = delta.days
    hours = delta.seconds // 3600
    minutes = (delta.seconds % 3600) // 60

    if days > 0:
        return f"{days}d{hours}h"
    elif hours > 0:
        return f"{hours}h{minutes}m"
    else:
        return f"{minutes}m"


def check_release_status(release):
    """Check release status and return health info."""
    status = release.get('status', 'unknown')
    name = release.get('name', 'unknown')
    namespace = release.get('namespace', 'default')
    chart = release.get('chart', 'unknown')
    app_version = release.get('app_version', 'unknown')
    revision = release.get('revision', 0)
    updated = release.get('updated', '')

    # Parse timestamp
    timestamp = parse_timestamp(updated)
    age = calculate_age(timestamp)

    # Determine health
    healthy_statuses = ['deployed']
    warning_statuses = ['pending-install', 'pending-upgrade', 'pending-rollback', 'uninstalling']
    failed_statuses = ['failed', 'superseded']

    is_healthy = status.lower() in healthy_statuses
    is_warning = status.lower() in warning_statuses
    is_failed = status.lower() in failed_statuses

    issues = []
    if is_failed:
        issues.append(f"Release in {status} state")
    elif is_warning:
        issues.append(f"Release in {status} state (operation in progress)")

    return {
        'name': name,
        'namespace': namespace,
        'status': status,
        'chart': chart,
        'app_version': app_version,
        'revision': revision,
        'updated': updated,
        'age': age,
        'healthy': is_healthy,
        'issues': issues
    }


def print_releases(releases, output_format, warn_only):
    """Print release information."""
    has_issues = False

    # Process all releases
    processed = []
    for release in releases:
        info = check_release_status(release)
        if info['issues']:
            has_issues = True
        if not warn_only or info['issues']:
            processed.append(info)

    if output_format == 'json':
        print(json.dumps(processed, indent=2))

    elif output_format == 'table':
        if not processed:
            print("No Helm releases found")
            return has_issues

        # Print header
        print(f"{'STATUS':<12} {'NAMESPACE':<20} {'NAME':<30} {'CHART':<35} {'APP VERSION':<15} {'AGE':<10}")
        print("-" * 122)

        for info in processed:
            status_marker = "" if info['healthy'] else "[!] "
            print(f"{status_marker}{info['status']:<12} {info['namespace']:<20} {info['name']:<30} "
                  f"{info['chart']:<35} {info['app_version']:<15} {info['age']:<10}")

            for issue in info['issues']:
                print(f"    WARNING: {issue}")

    else:  # plain format
        healthy_count = 0
        unhealthy_count = 0

        for info in processed:
            if info['healthy']:
                healthy_count += 1
            else:
                unhealthy_count += 1

            status_marker = "+" if info['healthy'] else "!"
            print(f"[{status_marker}] {info['namespace']}/{info['name']}")
            print(f"    Status: {info['status']}")
            print(f"    Chart: {info['chart']}")
            print(f"    App Version: {info['app_version']}")
            print(f"    Revision: {info['revision']}")
            print(f"    Age: {info['age']}")

            for issue in info['issues']:
                print(f"    WARNING: {issue}")

            print()

        # Print summary
        total = healthy_count + unhealthy_count
        if total > 0:
            print(f"Summary: {healthy_count}/{total} releases healthy, {unhealthy_count} with issues")
        else:
            print("No Helm releases found")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Helm release health and deployment status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all Helm releases
  %(prog)s -n production            # Check only in production namespace
  %(prog)s --warn-only              # Show only releases with issues
  %(prog)s --format json            # JSON output
  %(prog)s --format table           # Tabular output
  %(prog)s -w -f json               # JSON output, only problematic releases

Exit codes:
  0 - All Helm releases healthy (deployed status)
  1 - One or more releases in failed or problematic state
  2 - Usage error or helm unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to check (default: all namespaces)'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show releases with issues'
    )

    args = parser.parse_args()

    # Get Helm releases
    releases = get_releases(args.namespace)

    # Print status
    has_issues = print_releases(releases, args.format, args.warn_only)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
