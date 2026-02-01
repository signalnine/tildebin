#!/usr/bin/env python3
# boxctl:
#   category: k8s/storage
#   tags: [health, volumesnapshot, csi, kubernetes, backup]
#   requires: [kubectl]
#   privilege: none
#   related: [pv_health, pvc_stuck, storageclass_health]
#   brief: Monitor Kubernetes VolumeSnapshot health and backup operations

"""
Monitor Kubernetes VolumeSnapshot health and backup operations.

Provides visibility into VolumeSnapshot status and health:
- Failed or stuck VolumeSnapshots (not ready)
- VolumeSnapshots with errors during creation
- Old snapshots exceeding retention thresholds
- VolumeSnapshotContent orphaned (no snapshot reference)
- Missing VolumeSnapshotClass configuration

Returns exit code 1 if issues are detected.
"""

import argparse
import json
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_volume_snapshots(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get all VolumeSnapshots in JSON format."""
    cmd = ['kubectl', 'get', 'volumesnapshots', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')
    result = context.run(cmd)
    return json.loads(result.stdout)


def get_volume_snapshot_contents(context: Context) -> dict[str, Any]:
    """Get all VolumeSnapshotContents in JSON format."""
    result = context.run(['kubectl', 'get', 'volumesnapshotcontents', '-o', 'json'])
    return json.loads(result.stdout)


def get_volume_snapshot_classes(context: Context) -> dict[str, Any]:
    """Get all VolumeSnapshotClasses in JSON format."""
    result = context.run(['kubectl', 'get', 'volumesnapshotclasses', '-o', 'json'])
    return json.loads(result.stdout)


def parse_age(creation_timestamp: str | None) -> int:
    """Parse creation timestamp and return age in days."""
    if not creation_timestamp:
        return 0
    try:
        created = datetime.fromisoformat(creation_timestamp.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        delta = now - created
        return delta.days
    except (ValueError, TypeError):
        return 0


def format_age(days: int) -> str:
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


def check_snapshot_health(
    snapshot: dict[str, Any],
    retention_days: int
) -> tuple[bool, list[str], list[str], dict[str, Any]]:
    """Analyze a single VolumeSnapshot and return health status."""
    metadata = snapshot.get('metadata', {})
    status = snapshot.get('status', {})
    spec = snapshot.get('spec', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    creation_timestamp = metadata.get('creationTimestamp', '')

    issues = []
    warnings = []

    ready_to_use = status.get('readyToUse', False)
    if not ready_to_use:
        error = status.get('error', {})
        if error:
            error_msg = error.get('message', 'Unknown error')
            issues.append(f"Snapshot error: {error_msg}")
        else:
            bound_content = status.get('boundVolumeSnapshotContentName', '')
            if not bound_content:
                issues.append("Snapshot not ready (no bound content)")
            else:
                warnings.append("Snapshot not yet ready")

    age_days = parse_age(creation_timestamp)
    if retention_days > 0 and age_days > retention_days:
        warnings.append(f"Snapshot age ({format_age(age_days)}) exceeds retention threshold ({retention_days}d)")

    source = spec.get('source', {})
    pvc_name = source.get('persistentVolumeClaimName', '')
    snapshot_content_name = source.get('volumeSnapshotContentName', '')

    if not pvc_name and not snapshot_content_name:
        warnings.append("No source PVC or content reference")

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


def find_orphaned_contents(
    snapshots: dict[str, Any],
    contents: dict[str, Any]
) -> list[dict[str, Any]]:
    """Find VolumeSnapshotContents that have no matching VolumeSnapshot."""
    orphaned = []

    bound_contents = set()
    for snapshot in snapshots.get('items', []):
        content_name = snapshot.get('status', {}).get('boundVolumeSnapshotContentName', '')
        if content_name:
            bound_contents.add(content_name)

    for content in contents.get('items', []):
        name = content.get('metadata', {}).get('name', '')
        spec = content.get('spec', {})
        status = content.get('status', {})

        snapshot_ref = spec.get('volumeSnapshotRef', {})
        snapshot_name = snapshot_ref.get('name', '')
        snapshot_namespace = snapshot_ref.get('namespace', '')

        deletion_policy = spec.get('deletionPolicy', 'Delete')

        if snapshot_name and name not in bound_contents:
            orphaned.append({
                'name': name,
                'referencedSnapshot': f"{snapshot_namespace}/{snapshot_name}" if snapshot_namespace else snapshot_name,
                'deletionPolicy': deletion_policy,
                'driver': spec.get('driver', 'unknown'),
                'restoreSize': status.get('restoreSize', '')
            })

    return orphaned


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes VolumeSnapshot health and backup operations'
    )
    parser.add_argument('-n', '--namespace', help='Namespace to check (default: all)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show additional details')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only show snapshots with issues')
    parser.add_argument('-r', '--retention-days', type=int, default=0,
                        help='Warn about snapshots older than this (0=disabled)')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool('kubectl'):
        output.error('kubectl not found. Install kubectl to use this script.')
        return 2

    try:
        snapshots = get_volume_snapshots(context, opts.namespace)
        contents = get_volume_snapshot_contents(context)
        classes = get_volume_snapshot_classes(context)
    except Exception as e:
        error_msg = str(e)
        if "the server doesn't have a resource type" in error_msg:
            output.error("VolumeSnapshot CRDs not installed. Requires CSI driver with snapshot support.")
            return 2
        output.error(f'Failed to get Kubernetes data: {e}')
        return 2

    snapshot_items = snapshots.get('items', [])
    class_items = classes.get('items', [])

    has_issues = False
    healthy_count = 0
    unhealthy_count = 0
    snapshot_results = []

    for snapshot in snapshot_items:
        namespace = snapshot.get('metadata', {}).get('namespace', 'default')
        name = snapshot.get('metadata', {}).get('name', 'unknown')

        if opts.namespace and namespace != opts.namespace:
            continue

        is_healthy, issues, warnings, status_info = check_snapshot_health(snapshot, opts.retention_days)

        if is_healthy:
            healthy_count += 1
        else:
            unhealthy_count += 1
            has_issues = True

        if opts.warn_only and is_healthy and not warnings:
            continue

        snapshot_results.append({
            'namespace': namespace,
            'name': name,
            'healthy': is_healthy,
            'status': status_info,
            'issues': issues,
            'warnings': warnings
        })

    # Find orphaned contents
    orphaned = find_orphaned_contents(snapshots, contents)
    if orphaned:
        has_issues = True

    # List snapshot classes
    snapshot_classes = []
    for cls in class_items:
        cls_name = cls.get('metadata', {}).get('name', '')
        driver = cls.get('driver', 'unknown')
        deletion_policy = cls.get('deletionPolicy', 'Delete')
        snapshot_classes.append({
            'name': cls_name,
            'driver': driver,
            'deletionPolicy': deletion_policy
        })

    if not class_items:
        has_issues = True

    output.emit({
        'volumeSnapshots': snapshot_results,
        'orphanedContents': orphaned,
        'snapshotClasses': snapshot_classes,
        'summary': {
            'totalSnapshots': healthy_count + unhealthy_count,
            'healthySnapshots': healthy_count,
            'unhealthySnapshots': unhealthy_count,
            'orphanedContents': len(orphaned),
            'snapshotClasses': len(class_items)
        }
    })

    if has_issues:
        output.set_summary(f"{unhealthy_count} unhealthy snapshots, {len(orphaned)} orphaned contents")
    else:
        output.set_summary(f"{healthy_count} snapshots healthy")

    return 1 if has_issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
