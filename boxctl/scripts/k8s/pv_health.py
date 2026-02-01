#!/usr/bin/env python3
# boxctl:
#   category: k8s/storage
#   tags: [health, pv, storage, kubernetes]
#   requires: [kubectl]
#   privilege: none
#   related: [pvc_stuck, storageclass_health, volume_attachment]
#   brief: Check Kubernetes persistent volume health and storage status

"""
Check Kubernetes persistent volume (PV) health and storage status.

Provides comprehensive health checks for persistent volumes including:
- Volume phase status (Bound, Available, Released, Failed)
- PVC binding verification
- Released volumes with Retain policy (cleanup candidates)
- Very small capacity warnings

Returns exit code 1 if any PV has issues.
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_storage_quantity(quantity_str: str) -> int:
    """Parse Kubernetes storage quantity string to bytes."""
    if not quantity_str:
        return 0

    units = {
        'Ki': 1024,
        'Mi': 1024**2,
        'Gi': 1024**3,
        'Ti': 1024**4,
        'Pi': 1024**5,
        'K': 1000,
        'M': 1000**2,
        'G': 1000**3,
        'T': 1000**4,
        'P': 1000**5,
    }

    for suffix, multiplier in sorted(units.items(), key=lambda x: len(x[0]), reverse=True):
        if quantity_str.endswith(suffix):
            try:
                return int(quantity_str[:-len(suffix)]) * multiplier
            except ValueError:
                return 0

    try:
        return int(quantity_str)
    except ValueError:
        return 0


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human readable format."""
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}PiB"


def get_persistent_volumes(context: Context) -> dict[str, Any]:
    """Get all persistent volumes in JSON format."""
    result = context.run(['kubectl', 'get', 'pv', '-o', 'json'])
    return json.loads(result.stdout)


def get_persistent_volume_claims(context: Context) -> dict[str, Any]:
    """Get all persistent volume claims across all namespaces."""
    result = context.run(['kubectl', 'get', 'pvc', '-A', '-o', 'json'])
    return json.loads(result.stdout)


def check_pv_health(pv: dict[str, Any], pvc_map: dict[str, Any]) -> tuple[str, list[str]]:
    """Check persistent volume health and return issues."""
    issues = []
    name = pv['metadata']['name']
    status = pv['status'].get('phase', 'Unknown')
    claim_ref = pv['spec'].get('claimRef')
    capacity = pv['spec'].get('capacity', {})
    capacity_bytes = parse_storage_quantity(capacity.get('storage', '0'))

    # Check phase
    if status not in ['Available', 'Bound', 'Released']:
        issues.append(f"Abnormal phase: {status}")

    # Check if bound but claim doesn't exist
    if status == 'Bound' and claim_ref:
        claim_ns = claim_ref.get('namespace', '')
        claim_name = claim_ref.get('name', '')
        claim_key = f"{claim_ns}/{claim_name}"
        if claim_key not in pvc_map:
            issues.append(f"Bound to non-existent claim: {claim_key}")
        else:
            pvc = pvc_map[claim_key]
            if pvc['status'].get('phase') != 'Bound':
                issues.append(f"Claim {claim_key} not in Bound phase: {pvc['status'].get('phase')}")

    # Check for Released volumes with Retain policy
    if status == 'Released':
        reclaim_policy = pv['spec'].get('persistentVolumeReclaimPolicy', 'Retain')
        if reclaim_policy == 'Retain':
            issues.append("Released volume with Retain policy - consider manual cleanup")

    # Warn if capacity is very small (< 1Gi)
    if capacity_bytes > 0 and capacity_bytes < parse_storage_quantity('1Gi'):
        issues.append(f"Very small capacity: {format_bytes(capacity_bytes)}")

    return status, issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Check Kubernetes persistent volume health'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show additional details')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only show PVs with issues')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool('kubectl'):
        output.error('kubectl not found. Install kubectl to use this script.')
        return 2

    # Get PV and PVC data
    try:
        pvs_data = get_persistent_volumes(context)
        pvcs_data = get_persistent_volume_claims(context)
    except Exception as e:
        output.error(f'Failed to get Kubernetes data: {e}')
        return 2

    pvs = pvs_data.get('items', [])
    pvcs = pvcs_data.get('items', [])

    # Build PVC map for cross-reference
    pvc_map = {}
    for pvc in pvcs:
        ns = pvc['metadata']['namespace']
        name = pvc['metadata']['name']
        pvc_map[f"{ns}/{name}"] = pvc

    # Check each PV
    results = []
    has_issues = False
    healthy_count = 0
    warning_count = 0

    for pv in pvs:
        name = pv['metadata']['name']
        status, issues = check_pv_health(pv, pvc_map)
        capacity = pv['spec'].get('capacity', {})
        storage_class = pv['spec'].get('storageClassName', 'default')
        reclaim_policy = pv['spec'].get('persistentVolumeReclaimPolicy', 'Retain')

        if issues:
            warning_count += 1
            has_issues = True
        else:
            healthy_count += 1

        # Skip healthy if warn_only
        if opts.warn_only and not issues:
            continue

        pv_info = {
            'name': name,
            'phase': status,
            'capacity': capacity.get('storage', 'Unknown'),
            'reclaim_policy': reclaim_policy,
            'storage_class': storage_class,
            'issues': issues
        }

        # Add claim info if bound
        claim_ref = pv['spec'].get('claimRef')
        if claim_ref:
            pv_info['bound_to'] = f"{claim_ref.get('namespace', 'unknown')}/{claim_ref.get('name', 'unknown')}"

        results.append(pv_info)

    output.emit({'pvs': results, 'total': len(pvs), 'healthy': healthy_count, 'with_issues': warning_count})
    output.set_summary(f"{healthy_count}/{len(pvs)} volumes healthy, {warning_count} with issues")

    return 1 if has_issues else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
