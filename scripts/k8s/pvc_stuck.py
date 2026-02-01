#!/usr/bin/env python3
# boxctl:
#   category: k8s/storage
#   tags: [health, pvc, storage, kubernetes, pending]
#   requires: [kubectl]
#   privilege: none
#   related: [pv_health, storageclass_health, volume_attachment]
#   brief: Detect Kubernetes PVCs stuck in Pending state

"""
Detect Kubernetes PersistentVolumeClaims stuck in Pending state.

Identifies PVCs that have been pending for longer than a specified threshold
and provides diagnostic information about why they might be stuck.
Common causes include missing StorageClass, no matching PV, provisioner issues,
node affinity constraints, and insufficient capacity.

Returns exit code 1 if stuck PVCs are found.
"""

import argparse
import json
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_k8s_timestamp(timestamp_str: str | None) -> datetime | None:
    """Parse Kubernetes timestamp to datetime object."""
    if not timestamp_str:
        return None
    try:
        for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ']:
            try:
                return datetime.strptime(timestamp_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None
    except Exception:
        return None


def get_pvc_age_minutes(pvc: dict[str, Any]) -> float:
    """Get age of PVC in minutes."""
    creation_time = pvc['metadata'].get('creationTimestamp')
    if not creation_time:
        return 0
    created = parse_k8s_timestamp(creation_time)
    if not created:
        return 0
    now = datetime.now(timezone.utc)
    return (now - created).total_seconds() / 60


def format_duration(minutes: float) -> str:
    """Format duration in human-readable format."""
    if minutes < 60:
        return f"{int(minutes)}m"
    elif minutes < 1440:
        hours = int(minutes / 60)
        mins = int(minutes % 60)
        return f"{hours}h{mins}m"
    else:
        days = int(minutes / 1440)
        hours = int((minutes % 1440) / 60)
        return f"{days}d{hours}h"


def get_pvcs(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get PersistentVolumeClaims in JSON format."""
    cmd = ['kubectl', 'get', 'pvc', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')
    result = context.run(cmd)
    return json.loads(result.stdout)


def get_storage_classes(context: Context) -> dict[str, Any]:
    """Get StorageClasses in JSON format."""
    result = context.run(['kubectl', 'get', 'storageclasses', '-o', 'json'])
    return json.loads(result.stdout)


def get_persistent_volumes(context: Context) -> dict[str, Any]:
    """Get PersistentVolumes in JSON format."""
    result = context.run(['kubectl', 'get', 'pv', '-o', 'json'])
    return json.loads(result.stdout)


def diagnose_stuck_pvc(
    pvc: dict[str, Any],
    storage_classes: dict[str, Any],
    pvs: dict[str, Any]
) -> dict[str, Any]:
    """Diagnose why a PVC might be stuck in Pending state."""
    diagnostics = []
    spec = pvc.get('spec', {})

    requested_class = spec.get('storageClassName', '')
    requested_size = spec.get('resources', {}).get('requests', {}).get('storage', 'unknown')
    access_modes = spec.get('accessModes', [])
    volume_mode = spec.get('volumeMode', 'Filesystem')
    selector = spec.get('selector')
    volume_name = spec.get('volumeName')

    # Check if StorageClass exists
    sc_map = {sc['metadata']['name']: sc for sc in storage_classes.get('items', [])}

    if requested_class and requested_class not in sc_map:
        diagnostics.append(f"StorageClass '{requested_class}' does not exist")
    elif requested_class:
        sc = sc_map[requested_class]
        provisioner = sc.get('provisioner', 'unknown')

        if provisioner == 'kubernetes.io/no-provisioner':
            diagnostics.append("StorageClass uses no-provisioner (manual PV binding required)")

            available_pvs = [
                pv for pv in pvs.get('items', [])
                if pv['status'].get('phase') == 'Available'
                and pv['spec'].get('storageClassName') == requested_class
            ]
            if not available_pvs:
                diagnostics.append(f"No Available PVs found with StorageClass '{requested_class}'")
            else:
                diagnostics.append(f"Found {len(available_pvs)} Available PV(s) - check capacity/access modes")
    elif not requested_class:
        diagnostics.append("No StorageClass specified - using cluster default (if exists)")

    # Check if specific volumeName is requested but PV doesn't exist or isn't available
    if volume_name:
        pv_map = {pv['metadata']['name']: pv for pv in pvs.get('items', [])}
        if volume_name not in pv_map:
            diagnostics.append(f"Requested PV '{volume_name}' does not exist")
        else:
            pv = pv_map[volume_name]
            pv_phase = pv['status'].get('phase', 'Unknown')
            if pv_phase != 'Available':
                diagnostics.append(f"Requested PV '{volume_name}' is {pv_phase}, not Available")

    # Check selector constraints
    if selector:
        match_labels = selector.get('matchLabels', {})
        match_exprs = selector.get('matchExpressions', [])
        if match_labels or match_exprs:
            diagnostics.append("PVC has selector constraints - requires matching PV labels")

    # Check for access mode issues
    if 'ReadWriteMany' in access_modes:
        diagnostics.append("RWX access mode requested - requires shared storage support")

    return {
        'requested_class': requested_class or '(default)',
        'requested_size': requested_size,
        'access_modes': access_modes,
        'volume_mode': volume_mode,
        'diagnostics': diagnostics
    }


def analyze_pvcs(
    pvcs_data: dict[str, Any],
    storage_classes: dict[str, Any],
    pvs: dict[str, Any],
    threshold_minutes: int,
    namespace_filter: str | None
) -> list[dict[str, Any]]:
    """Analyze PVCs and find stuck ones."""
    stuck_pvcs = []

    for pvc in pvcs_data.get('items', []):
        phase = pvc.get('status', {}).get('phase', 'Unknown')

        if phase != 'Pending':
            continue

        ns = pvc['metadata']['namespace']
        name = pvc['metadata']['name']
        age_minutes = get_pvc_age_minutes(pvc)

        if namespace_filter and ns != namespace_filter:
            continue

        if age_minutes < threshold_minutes:
            continue

        diagnosis = diagnose_stuck_pvc(pvc, storage_classes, pvs)

        stuck_pvcs.append({
            'namespace': ns,
            'name': name,
            'age_minutes': age_minutes,
            'age_formatted': format_duration(age_minutes),
            'diagnosis': diagnosis
        })

    return stuck_pvcs


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no stuck PVCs, 1 = stuck PVCs found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Detect Kubernetes PVCs stuck in Pending state'
    )
    parser.add_argument('-t', '--threshold', type=int, default=5, metavar='MINUTES',
                        help='Minimum age in minutes to consider PVC stuck (default: 5)')
    parser.add_argument('-n', '--namespace', help='Namespace to check (default: all)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show additional details')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    if opts.threshold < 0:
        output.error('threshold must be non-negative')
        return 2

    # Check for kubectl
    if not context.check_tool('kubectl'):
        output.error('kubectl not found. Install kubectl to use this script.')
        return 2

    # Gather cluster state
    try:
        pvcs = get_pvcs(context, opts.namespace)
        storage_classes = get_storage_classes(context)
        pvs = get_persistent_volumes(context)
    except Exception as e:
        output.error(f'Failed to get Kubernetes data: {e}')
        return 2

    # Analyze for stuck PVCs
    stuck_pvcs = analyze_pvcs(pvcs, storage_classes, pvs, opts.threshold, opts.namespace)

    output.emit({
        'stuck_count': len(stuck_pvcs),
        'pvcs': stuck_pvcs,
        'threshold_minutes': opts.threshold
    })

    if stuck_pvcs:
        output.set_summary(f"{len(stuck_pvcs)} PVC(s) stuck in Pending state")
    else:
        output.set_summary("No stuck PVCs found")

    return 1 if stuck_pvcs else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
