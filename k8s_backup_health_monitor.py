#!/usr/bin/env python3
"""
Monitor Kubernetes backup health including Velero backups, VolumeSnapshots, and backup CronJobs.

This script provides comprehensive backup health monitoring for Kubernetes clusters,
checking backup schedules, recent backup completion status, snapshot health, and
backup-related CronJob execution. Essential for disaster recovery compliance.

Exit codes:
    0 - All backups healthy (recent successful backups exist)
    1 - Backup issues detected (stale, failed, or missing backups)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def run_kubectl(args, ignore_errors=False):
    """Run kubectl command and return output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=not ignore_errors
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        if ignore_errors:
            return e.returncode, e.stdout, e.stderr
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def parse_k8s_timestamp(timestamp_str):
    """Parse Kubernetes timestamp to datetime."""
    if not timestamp_str:
        return None
    try:
        # Handle both formats: with and without microseconds
        if '.' in timestamp_str:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        else:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return None


def get_age_hours(timestamp):
    """Get age in hours from timestamp."""
    if not timestamp:
        return float('inf')
    now = datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    delta = now - timestamp
    return delta.total_seconds() / 3600


def format_age(hours):
    """Format age in human-readable form."""
    if hours == float('inf'):
        return "unknown"
    if hours < 1:
        return f"{int(hours * 60)}m"
    if hours < 24:
        return f"{hours:.1f}h"
    days = hours / 24
    return f"{days:.1f}d"


def check_velero_backups(namespace, max_age_hours):
    """Check Velero backup health."""
    issues = []
    backups = []

    # Check if Velero CRDs exist
    rc, stdout, stderr = run_kubectl(
        ['api-resources', '--api-group=velero.io', '-o', 'name'],
        ignore_errors=True
    )
    if rc != 0 or 'backups' not in stdout:
        return None, []  # Velero not installed

    # Get backup schedules
    rc, stdout, stderr = run_kubectl(
        ['get', 'schedules.velero.io', '-A', '-o', 'json'],
        ignore_errors=True
    )
    schedules = []
    if rc == 0:
        try:
            data = json.loads(stdout)
            schedules = data.get('items', [])
        except json.JSONDecodeError:
            pass

    # Get recent backups
    rc, stdout, stderr = run_kubectl(
        ['get', 'backups.velero.io', '-A', '-o', 'json'],
        ignore_errors=True
    )
    if rc != 0:
        issues.append("Unable to query Velero backups")
        return issues, backups

    try:
        data = json.loads(stdout)
        backup_items = data.get('items', [])
    except json.JSONDecodeError:
        issues.append("Failed to parse Velero backup data")
        return issues, backups

    if not backup_items and schedules:
        issues.append("No Velero backups found but schedules exist")

    # Analyze backups
    for backup in backup_items:
        name = backup['metadata']['name']
        ns = backup['metadata'].get('namespace', 'velero')
        status = backup.get('status', {})
        phase = status.get('phase', 'Unknown')
        completion_time = parse_k8s_timestamp(status.get('completionTimestamp'))
        start_time = parse_k8s_timestamp(status.get('startTimestamp'))

        backup_info = {
            'name': name,
            'namespace': ns,
            'phase': phase,
            'type': 'velero',
            'completion_time': status.get('completionTimestamp'),
            'age_hours': get_age_hours(completion_time or start_time),
            'issues': []
        }

        # Check for issues
        if phase == 'Failed':
            backup_info['issues'].append(f"Backup failed: {status.get('failureReason', 'unknown')}")
        elif phase == 'PartiallyFailed':
            backup_info['issues'].append("Backup partially failed")
        elif phase not in ['Completed', 'InProgress', 'New']:
            backup_info['issues'].append(f"Unexpected phase: {phase}")

        backups.append(backup_info)

    # Check for stale backups (no recent successful backup)
    successful_backups = [b for b in backups if b['phase'] == 'Completed']
    if successful_backups:
        most_recent = min(successful_backups, key=lambda x: x['age_hours'])
        if most_recent['age_hours'] > max_age_hours:
            issues.append(
                f"Most recent successful Velero backup is {format_age(most_recent['age_hours'])} old "
                f"(threshold: {max_age_hours}h)"
            )

    return issues, backups


def check_volume_snapshots(namespace, max_age_hours):
    """Check VolumeSnapshot health."""
    issues = []
    snapshots = []

    # Check if VolumeSnapshot CRDs exist
    rc, stdout, stderr = run_kubectl(
        ['api-resources', '--api-group=snapshot.storage.k8s.io', '-o', 'name'],
        ignore_errors=True
    )
    if rc != 0 or 'volumesnapshots' not in stdout:
        return None, []  # VolumeSnapshots not available

    # Get VolumeSnapshots
    args = ['get', 'volumesnapshots', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('-A')

    rc, stdout, stderr = run_kubectl(args, ignore_errors=True)
    if rc != 0:
        issues.append("Unable to query VolumeSnapshots")
        return issues, snapshots

    try:
        data = json.loads(stdout)
        snapshot_items = data.get('items', [])
    except json.JSONDecodeError:
        issues.append("Failed to parse VolumeSnapshot data")
        return issues, snapshots

    for snap in snapshot_items:
        name = snap['metadata']['name']
        ns = snap['metadata'].get('namespace', 'default')
        status = snap.get('status', {})
        ready = status.get('readyToUse', False)
        creation_time = parse_k8s_timestamp(snap['metadata'].get('creationTimestamp'))
        restore_size = status.get('restoreSize', 'Unknown')

        snapshot_info = {
            'name': name,
            'namespace': ns,
            'ready': ready,
            'type': 'volumesnapshot',
            'creation_time': snap['metadata'].get('creationTimestamp'),
            'age_hours': get_age_hours(creation_time),
            'restore_size': restore_size,
            'issues': []
        }

        # Check for issues
        if not ready:
            error = status.get('error', {})
            if error:
                snapshot_info['issues'].append(f"Not ready: {error.get('message', 'unknown error')}")
            else:
                snapshot_info['issues'].append("Snapshot not ready")

        snapshots.append(snapshot_info)

    # Check for stale snapshots
    ready_snapshots = [s for s in snapshots if s['ready']]
    if ready_snapshots:
        most_recent = min(ready_snapshots, key=lambda x: x['age_hours'])
        if most_recent['age_hours'] > max_age_hours:
            issues.append(
                f"Most recent ready VolumeSnapshot is {format_age(most_recent['age_hours'])} old "
                f"(threshold: {max_age_hours}h)"
            )

    return issues, snapshots


def check_backup_cronjobs(namespace, max_age_hours):
    """Check backup-related CronJobs and their recent job status."""
    issues = []
    cronjobs = []

    # Common backup CronJob patterns
    backup_patterns = ['backup', 'etcd', 'snapshot', 'dump', 'archive']

    args = ['get', 'cronjobs', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('-A')

    rc, stdout, stderr = run_kubectl(args, ignore_errors=True)
    if rc != 0:
        return None, []

    try:
        data = json.loads(stdout)
        cronjob_items = data.get('items', [])
    except json.JSONDecodeError:
        issues.append("Failed to parse CronJob data")
        return issues, cronjobs

    for cj in cronjob_items:
        name = cj['metadata']['name']
        ns = cj['metadata'].get('namespace', 'default')

        # Check if this looks like a backup CronJob
        is_backup_related = any(pattern in name.lower() for pattern in backup_patterns)
        if not is_backup_related:
            continue

        spec = cj.get('spec', {})
        status = cj.get('status', {})
        schedule = spec.get('schedule', 'Unknown')
        suspended = spec.get('suspend', False)
        last_schedule = parse_k8s_timestamp(status.get('lastScheduleTime'))
        last_successful = parse_k8s_timestamp(status.get('lastSuccessfulTime'))

        cronjob_info = {
            'name': name,
            'namespace': ns,
            'schedule': schedule,
            'suspended': suspended,
            'type': 'cronjob',
            'last_schedule': status.get('lastScheduleTime'),
            'last_successful': status.get('lastSuccessfulTime'),
            'age_hours': get_age_hours(last_successful or last_schedule),
            'issues': []
        }

        # Check for issues
        if suspended:
            cronjob_info['issues'].append("CronJob is suspended")

        if last_successful:
            age = get_age_hours(last_successful)
            if age > max_age_hours:
                cronjob_info['issues'].append(
                    f"Last successful run was {format_age(age)} ago"
                )
        elif last_schedule:
            # Has scheduled but never succeeded
            cronjob_info['issues'].append("CronJob has never completed successfully")
        else:
            cronjob_info['issues'].append("CronJob has never run")

        cronjobs.append(cronjob_info)

    return issues, cronjobs


def print_results(velero_issues, velero_backups, snapshot_issues, snapshots,
                  cronjob_issues, cronjobs, output_format, warn_only, verbose):
    """Print backup health results."""
    all_issues = []
    if velero_issues:
        all_issues.extend(velero_issues)
    if snapshot_issues:
        all_issues.extend(snapshot_issues)
    if cronjob_issues:
        all_issues.extend(cronjob_issues)

    # Add item-level issues
    for item in velero_backups + snapshots + cronjobs:
        all_issues.extend(item.get('issues', []))

    has_issues = bool(all_issues)

    if output_format == 'json':
        output = {
            'velero': {
                'available': velero_issues is not None,
                'issues': velero_issues or [],
                'backups': velero_backups if verbose or not warn_only else [
                    b for b in velero_backups if b.get('issues')
                ]
            },
            'volumesnapshots': {
                'available': snapshot_issues is not None,
                'issues': snapshot_issues or [],
                'snapshots': snapshots if verbose or not warn_only else [
                    s for s in snapshots if s.get('issues')
                ]
            },
            'cronjobs': {
                'available': cronjob_issues is not None,
                'issues': cronjob_issues or [],
                'cronjobs': cronjobs if verbose or not warn_only else [
                    c for c in cronjobs if c.get('issues')
                ]
            },
            'summary': {
                'healthy': not has_issues,
                'total_issues': len(all_issues),
                'velero_backup_count': len(velero_backups),
                'snapshot_count': len(snapshots),
                'backup_cronjob_count': len(cronjobs)
            }
        }
        print(json.dumps(output, indent=2))
    else:
        # Plain format
        if velero_issues is not None:
            print("=== Velero Backups ===")
            if velero_backups:
                for backup in velero_backups:
                    if warn_only and not backup.get('issues'):
                        continue
                    status_icon = "!" if backup.get('issues') else "+"
                    print(f"  [{status_icon}] {backup['namespace']}/{backup['name']}")
                    print(f"      Phase: {backup['phase']} | Age: {format_age(backup['age_hours'])}")
                    for issue in backup.get('issues', []):
                        print(f"      WARNING: {issue}")
            else:
                print("  No Velero backups found")
            if velero_issues:
                for issue in velero_issues:
                    print(f"  ISSUE: {issue}")
            print()

        if snapshot_issues is not None:
            print("=== VolumeSnapshots ===")
            if snapshots:
                for snap in snapshots:
                    if warn_only and not snap.get('issues'):
                        continue
                    status_icon = "!" if snap.get('issues') else "+"
                    ready_str = "ready" if snap['ready'] else "not ready"
                    print(f"  [{status_icon}] {snap['namespace']}/{snap['name']}")
                    print(f"      Status: {ready_str} | Age: {format_age(snap['age_hours'])} | Size: {snap['restore_size']}")
                    for issue in snap.get('issues', []):
                        print(f"      WARNING: {issue}")
            else:
                print("  No VolumeSnapshots found")
            if snapshot_issues:
                for issue in snapshot_issues:
                    print(f"  ISSUE: {issue}")
            print()

        if cronjob_issues is not None:
            print("=== Backup CronJobs ===")
            if cronjobs:
                for cj in cronjobs:
                    if warn_only and not cj.get('issues'):
                        continue
                    status_icon = "!" if cj.get('issues') else "+"
                    suspended_str = " (SUSPENDED)" if cj['suspended'] else ""
                    print(f"  [{status_icon}] {cj['namespace']}/{cj['name']}{suspended_str}")
                    print(f"      Schedule: {cj['schedule']} | Last success: {format_age(cj['age_hours'])} ago")
                    for issue in cj.get('issues', []):
                        print(f"      WARNING: {issue}")
            else:
                print("  No backup-related CronJobs found")
            if cronjob_issues:
                for issue in cronjob_issues:
                    print(f"  ISSUE: {issue}")
            print()

        # Summary
        available_systems = []
        if velero_issues is not None:
            available_systems.append(f"{len(velero_backups)} Velero backups")
        if snapshot_issues is not None:
            available_systems.append(f"{len(snapshots)} VolumeSnapshots")
        if cronjob_issues is not None:
            available_systems.append(f"{len(cronjobs)} backup CronJobs")

        if not available_systems:
            print("No backup systems detected (Velero, VolumeSnapshots, or backup CronJobs)")
        else:
            status = "HEALTHY" if not has_issues else f"ISSUES DETECTED ({len(all_issues)})"
            print(f"Summary: {status}")
            print(f"  Found: {', '.join(available_systems)}")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes backup health (Velero, VolumeSnapshots, CronJobs)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all backup systems
  %(prog)s -n velero                # Check backups in specific namespace
  %(prog)s --max-age 48             # Alert if backups older than 48 hours
  %(prog)s --warn-only              # Show only items with issues
  %(prog)s --format json            # JSON output
  %(prog)s -v                       # Verbose output with all details

Exit codes:
  0 - All backups healthy
  1 - Backup issues detected
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to check (default: all namespaces)'
    )

    parser.add_argument(
        '--max-age', '-a',
        type=int,
        default=24,
        help='Maximum age in hours for backups before warning (default: 24)'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show items with warnings or issues'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed information'
    )

    args = parser.parse_args()

    # Check all backup systems
    velero_issues, velero_backups = check_velero_backups(args.namespace, args.max_age)
    snapshot_issues, snapshots = check_volume_snapshots(args.namespace, args.max_age)
    cronjob_issues, cronjobs = check_backup_cronjobs(args.namespace, args.max_age)

    # Print results
    has_issues = print_results(
        velero_issues, velero_backups,
        snapshot_issues, snapshots,
        cronjob_issues, cronjobs,
        args.format, args.warn_only, args.verbose
    )

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
