#!/usr/bin/env python3
"""
Monitor Kubernetes VolumeSnapshot health and backup operations.

This script provides visibility into VolumeSnapshot status and health:
- Failed or stuck VolumeSnapshots (not ready)
- VolumeSnapshots with errors during creation
- Old snapshots exceeding retention thresholds
- VolumeSnapshotContent orphaned (no snapshot reference)
- Missing VolumeSnapshotClass configuration
- Snapshot storage utilization trends

VolumeSnapshots are critical for backup/restore workflows, disaster recovery,
and data protection in Kubernetes environments using CSI drivers.

Exit codes:
    0 - All VolumeSnapshots healthy and ready
    1 - One or more VolumeSnapshots have issues
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def run_kubectl(args):
    """Run kubectl command and return output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        # VolumeSnapshot CRDs may not be installed
        if 'the server doesn\'t have a resource type' in e.stderr:
            print("Error: VolumeSnapshot CRDs not installed", file=sys.stderr)
            print("VolumeSnapshots require a CSI driver with snapshot support", file=sys.stderr)
            sys.exit(2)
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_volume_snapshots(namespace=None):
    """Get all VolumeSnapshots in JSON format."""
    args = ['get', 'volumesnapshots', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_volume_snapshot_contents():
    """Get all VolumeSnapshotContents in JSON format."""
    args = ['get', 'volumesnapshotcontents', '-o', 'json']
    output = run_kubectl(args)
    return json.loads(output)


def get_volume_snapshot_classes():
    """Get all VolumeSnapshotClasses in JSON format."""
    args = ['get', 'volumesnapshotclasses', '-o', 'json']
    output = run_kubectl(args)
    return json.loads(output)


def parse_age(creation_timestamp):
    """Parse creation timestamp and return age in days."""
    if not creation_timestamp:
        return 0

    try:
        # Parse ISO 8601 format
        created = datetime.fromisoformat(creation_timestamp.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        delta = now - created
        return delta.days
    except (ValueError, TypeError):
        return 0


def format_age(days):
    """Format age in human readable format."""
    if days == 0:
        return "<1d"
    elif days < 7:
        return f"{days}d"
    elif days < 30:
        weeks = days // 7
        return f"{weeks}w"
    elif days < 365:
        months = days // 30
        return f"{months}mo"
    else:
        years = days // 365
        return f"{years}y"


def check_snapshot_health(snapshot, retention_days):
    """Analyze a single VolumeSnapshot and return health status."""
    metadata = snapshot.get('metadata', {})
    status = snapshot.get('status', {})
    spec = snapshot.get('spec', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    creation_timestamp = metadata.get('creationTimestamp', '')

    issues = []
    warnings = []

    # Check readyToUse status
    ready_to_use = status.get('readyToUse', False)
    if not ready_to_use:
        # Check for error
        error = status.get('error', {})
        if error:
            error_msg = error.get('message', 'Unknown error')
            issues.append(f"Snapshot error: {error_msg}")
        else:
            # May still be creating
            bound_content = status.get('boundVolumeSnapshotContentName', '')
            if not bound_content:
                issues.append("Snapshot not ready (no bound content)")
            else:
                warnings.append("Snapshot not yet ready")

    # Check age against retention threshold
    age_days = parse_age(creation_timestamp)
    if retention_days > 0 and age_days > retention_days:
        warnings.append(f"Snapshot age ({format_age(age_days)}) exceeds retention threshold ({retention_days}d)")

    # Check for source reference
    source = spec.get('source', {})
    pvc_name = source.get('persistentVolumeClaimName', '')
    snapshot_content_name = source.get('volumeSnapshotContentName', '')

    if not pvc_name and not snapshot_content_name:
        warnings.append("No source PVC or content reference")

    # Get restore size if available
    restore_size = status.get('restoreSize', '')

    is_healthy = len(issues) == 0 and ready_to_use

    return is_healthy, issues, warnings, {
        'readyToUse': ready_to_use,
        'restoreSize': restore_size,
        'boundContent': status.get('boundVolumeSnapshotContentName', ''),
        'sourcePVC': pvc_name,
        'snapshotClass': spec.get('volumeSnapshotClassName', ''),
        'ageInDays': age_days
    }


def find_orphaned_contents(snapshots, contents):
    """Find VolumeSnapshotContents that have no matching VolumeSnapshot."""
    orphaned = []

    # Build set of bound content names from snapshots
    bound_contents = set()
    for snapshot in snapshots.get('items', []):
        content_name = snapshot.get('status', {}).get('boundVolumeSnapshotContentName', '')
        if content_name:
            bound_contents.add(content_name)

    # Check each content for orphan status
    for content in contents.get('items', []):
        name = content.get('metadata', {}).get('name', '')
        spec = content.get('spec', {})
        status = content.get('status', {})

        # Check if bound to a snapshot
        snapshot_ref = spec.get('volumeSnapshotRef', {})
        snapshot_name = snapshot_ref.get('name', '')
        snapshot_namespace = snapshot_ref.get('namespace', '')

        # Check deletion policy
        deletion_policy = spec.get('deletionPolicy', 'Delete')

        # A content is orphaned if it references a snapshot that doesn't exist
        if snapshot_name and name not in bound_contents:
            # Could be orphaned - check if snapshot still exists
            orphaned.append({
                'name': name,
                'referencedSnapshot': f"{snapshot_namespace}/{snapshot_name}" if snapshot_namespace else snapshot_name,
                'deletionPolicy': deletion_policy,
                'driver': spec.get('driver', 'unknown'),
                'restoreSize': status.get('restoreSize', '')
            })

    return orphaned


def print_status(snapshots, contents, classes, output_format, warn_only, retention_days, namespace_filter=None):
    """Print VolumeSnapshot status in requested format."""
    has_issues = False

    snapshot_items = snapshots.get('items', [])
    class_items = classes.get('items', [])

    if output_format == 'json':
        output = {
            'volumeSnapshots': [],
            'orphanedContents': [],
            'snapshotClasses': [],
            'summary': {}
        }

        healthy_count = 0
        unhealthy_count = 0

        for snapshot in snapshot_items:
            namespace = snapshot.get('metadata', {}).get('namespace', 'default')
            name = snapshot.get('metadata', {}).get('name', 'unknown')

            if namespace_filter and namespace != namespace_filter:
                continue

            is_healthy, issues, warnings, status_info = check_snapshot_health(snapshot, retention_days)

            if is_healthy:
                healthy_count += 1
            else:
                unhealthy_count += 1

            snapshot_info = {
                'namespace': namespace,
                'name': name,
                'healthy': is_healthy,
                'status': status_info,
                'issues': issues,
                'warnings': warnings
            }

            if not warn_only or issues or warnings:
                output['volumeSnapshots'].append(snapshot_info)
                if issues:
                    has_issues = True

        # Find orphaned contents
        orphaned = find_orphaned_contents(snapshots, contents)
        output['orphanedContents'] = orphaned
        if orphaned:
            has_issues = True

        # List snapshot classes
        for cls in class_items:
            cls_name = cls.get('metadata', {}).get('name', '')
            driver = cls.get('driver', 'unknown')
            deletion_policy = cls.get('deletionPolicy', 'Delete')
            output['snapshotClasses'].append({
                'name': cls_name,
                'driver': driver,
                'deletionPolicy': deletion_policy
            })

        output['summary'] = {
            'totalSnapshots': healthy_count + unhealthy_count,
            'healthySnapshots': healthy_count,
            'unhealthySnapshots': unhealthy_count,
            'orphanedContents': len(orphaned),
            'snapshotClasses': len(class_items)
        }

        print(json.dumps(output, indent=2))

    else:  # plain format
        healthy_count = 0
        unhealthy_count = 0

        print("=== VolumeSnapshot Health ===\n")

        for snapshot in snapshot_items:
            namespace = snapshot.get('metadata', {}).get('namespace', 'default')
            name = snapshot.get('metadata', {}).get('name', 'unknown')

            if namespace_filter and namespace != namespace_filter:
                continue

            is_healthy, issues, warnings, status_info = check_snapshot_health(snapshot, retention_days)

            if is_healthy:
                healthy_count += 1
            else:
                unhealthy_count += 1
                has_issues = True

            # Skip healthy if warn_only
            if warn_only and is_healthy and not warnings:
                continue

            # Print snapshot info
            status_marker = "OK" if is_healthy else "!!"
            ready_marker = "Ready" if status_info['readyToUse'] else "NotReady"
            print(f"[{status_marker}] {namespace}/{name}")
            print(f"    Status: {ready_marker}, Age: {format_age(status_info['ageInDays'])}")

            if status_info['restoreSize']:
                print(f"    Size: {status_info['restoreSize']}")

            if status_info['sourcePVC']:
                print(f"    Source PVC: {status_info['sourcePVC']}")

            if status_info['snapshotClass']:
                print(f"    Class: {status_info['snapshotClass']}")

            # Print issues
            for issue in issues:
                print(f"    ERROR: {issue}")

            # Print warnings
            for warning in warnings:
                print(f"    WARNING: {warning}")

            print()

        # Print summary
        total = healthy_count + unhealthy_count
        if total > 0:
            print(f"Snapshot Summary: {healthy_count}/{total} healthy, {unhealthy_count} with issues")
        else:
            print("No VolumeSnapshots found")

        # Check for orphaned contents
        orphaned = find_orphaned_contents(snapshots, contents)
        if orphaned:
            has_issues = True
            print(f"\n=== Orphaned VolumeSnapshotContents ({len(orphaned)}) ===\n")
            for content in orphaned:
                print(f"  {content['name']}")
                print(f"    Referenced Snapshot: {content['referencedSnapshot']} (not found)")
                print(f"    Deletion Policy: {content['deletionPolicy']}")
                if content['restoreSize']:
                    print(f"    Size: {content['restoreSize']}")
                print()

        # List snapshot classes
        if class_items and not warn_only:
            print(f"\n=== VolumeSnapshotClasses ({len(class_items)}) ===\n")
            for cls in class_items:
                cls_name = cls.get('metadata', {}).get('name', '')
                driver = cls.get('driver', 'unknown')
                deletion_policy = cls.get('deletionPolicy', 'Delete')
                print(f"  {cls_name}")
                print(f"    Driver: {driver}")
                print(f"    Deletion Policy: {deletion_policy}")
                print()

        if not class_items:
            print("\nWARNING: No VolumeSnapshotClasses found - snapshots may fail")
            has_issues = True

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes VolumeSnapshot health and backup operations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all VolumeSnapshots
  %(prog)s -n production            # Check only in production namespace
  %(prog)s --warn-only              # Show only snapshots with issues
  %(prog)s --retention-days 30      # Warn about snapshots older than 30 days
  %(prog)s --format json            # JSON output for automation

Exit codes:
  0 - All VolumeSnapshots healthy and ready
  1 - One or more VolumeSnapshots have issues
  2 - Usage error or kubectl/CRDs unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to check (default: all namespaces)'
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
        help='Only show snapshots with issues or warnings'
    )

    parser.add_argument(
        '--retention-days', '-r',
        type=int,
        default=0,
        help='Warn about snapshots older than this many days (0=disabled)'
    )

    args = parser.parse_args()

    # Get VolumeSnapshots
    snapshots = get_volume_snapshots(args.namespace)

    # Get VolumeSnapshotContents (cluster-scoped)
    contents = get_volume_snapshot_contents()

    # Get VolumeSnapshotClasses (cluster-scoped)
    classes = get_volume_snapshot_classes()

    # Print status
    has_issues = print_status(
        snapshots, contents, classes,
        args.format, args.warn_only, args.retention_days, args.namespace
    )

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
