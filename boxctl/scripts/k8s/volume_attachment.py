#!/usr/bin/env python3
# boxctl:
#   category: k8s/storage
#   tags: [health, volumeattachment, csi, kubernetes, storage]
#   requires: [kubectl]
#   privilege: none
#   related: [pv_health, pvc_stuck, storageclass_health]
#   brief: Analyze Kubernetes VolumeAttachment resources for health issues

"""
Analyze Kubernetes VolumeAttachment resources for health issues.

VolumeAttachments track which volumes are attached to which nodes. This script
identifies stale, orphaned, or problematic attachments that can cause:
- Pods stuck in ContainerCreating state
- Volumes that cannot be attached to new nodes
- Multi-attach violations for non-shareable volumes
- Node drain failures due to stuck attachments

Returns exit code 1 if issues are detected.
"""

import argparse
import json
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_timestamp(ts_str: str | None) -> datetime | None:
    """Parse Kubernetes timestamp to datetime."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def get_volume_attachments(context: Context) -> list[dict[str, Any]]:
    """Get all VolumeAttachment resources."""
    result = context.run(['kubectl', 'get', 'volumeattachments', '-o', 'json'])
    data = json.loads(result.stdout)
    return data.get('items', [])


def get_nodes(context: Context) -> dict[str, dict[str, Any]]:
    """Get all nodes in the cluster."""
    result = context.run(['kubectl', 'get', 'nodes', '-o', 'json'])
    data = json.loads(result.stdout)
    nodes = {}
    for node in data.get('items', []):
        name = node['metadata']['name']
        conditions = node.get('status', {}).get('conditions', [])
        ready = False
        for cond in conditions:
            if cond['type'] == 'Ready' and cond['status'] == 'True':
                ready = True
                break
        nodes[name] = {
            'ready': ready,
            'unschedulable': node.get('spec', {}).get('unschedulable', False)
        }
    return nodes


def get_pvs(context: Context) -> dict[str, dict[str, Any]]:
    """Get all PersistentVolumes."""
    result = context.run(['kubectl', 'get', 'pv', '-o', 'json'])
    data = json.loads(result.stdout)
    pvs = {}
    for pv in data.get('items', []):
        name = pv['metadata']['name']
        pvs[name] = {
            'status': pv.get('status', {}).get('phase', 'Unknown'),
            'access_modes': pv.get('spec', {}).get('accessModes', []),
            'storage_class': pv.get('spec', {}).get('storageClassName', ''),
            'claim': pv.get('spec', {}).get('claimRef', {})
        }
    return pvs


def analyze_attachment(
    va: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
    pvs: dict[str, dict[str, Any]],
    stale_threshold_hours: float
) -> dict[str, Any]:
    """Analyze a single VolumeAttachment for issues."""
    issues = []
    metadata = va.get('metadata', {})
    spec = va.get('spec', {})
    status = va.get('status', {})

    name = metadata.get('name', 'unknown')
    node_name = spec.get('nodeName', '')
    pv_name = spec.get('source', {}).get('persistentVolumeName', '')
    attacher = spec.get('attacher', '')

    attached = status.get('attached', False)
    attach_error = status.get('attachError', {})
    detach_error = status.get('detachError', {})

    creation_ts = parse_timestamp(metadata.get('creationTimestamp'))
    age_hours = 0.0
    if creation_ts:
        now = datetime.now(timezone.utc)
        age_hours = (now - creation_ts).total_seconds() / 3600

    # Check if node exists
    node_info = nodes.get(node_name)
    if not node_info:
        issues.append({
            'severity': 'error',
            'type': 'orphaned_node',
            'message': f'Attached to non-existent node: {node_name}'
        })
    elif not node_info['ready']:
        issues.append({
            'severity': 'warning',
            'type': 'node_not_ready',
            'message': f'Node {node_name} is not Ready'
        })

    # Check PV status
    pv_info = pvs.get(pv_name)
    if pv_info:
        if pv_info['status'] == 'Released':
            issues.append({
                'severity': 'warning',
                'type': 'pv_released',
                'message': f'PV {pv_name} is in Released state'
            })
        elif pv_info['status'] == 'Failed':
            issues.append({
                'severity': 'error',
                'type': 'pv_failed',
                'message': f'PV {pv_name} is in Failed state'
            })

    # Check for attachment errors
    if attach_error:
        error_msg = attach_error.get('message', 'Unknown error')
        issues.append({
            'severity': 'error',
            'type': 'attach_error',
            'message': f'Attach error: {error_msg[:100]}'
        })

    if detach_error:
        error_msg = detach_error.get('message', 'Unknown error')
        issues.append({
            'severity': 'error',
            'type': 'detach_error',
            'message': f'Detach error: {error_msg[:100]}'
        })

    # Check for stale unattached VolumeAttachments
    if not attached and age_hours > stale_threshold_hours:
        issues.append({
            'severity': 'warning',
            'type': 'stale_unattached',
            'message': f'Unattached for {age_hours:.1f} hours'
        })

    # Check for deletion timestamp (stuck in terminating)
    deletion_ts = metadata.get('deletionTimestamp')
    if deletion_ts:
        deletion_time = parse_timestamp(deletion_ts)
        if deletion_time:
            stuck_hours = (datetime.now(timezone.utc) - deletion_time).total_seconds() / 3600
            if stuck_hours > 1:
                issues.append({
                    'severity': 'error',
                    'type': 'stuck_terminating',
                    'message': f'Stuck in Terminating for {stuck_hours:.1f} hours'
                })

    return {
        'name': name,
        'node': node_name,
        'pv': pv_name,
        'attacher': attacher,
        'attached': attached,
        'age_hours': round(age_hours, 1),
        'issues': issues
    }


def check_multi_attach(
    attachments: list[dict[str, Any]],
    pvs: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Check for multi-attach violations on RWO volumes."""
    pv_nodes: dict[str, list[str]] = {}
    violations = []

    for att in attachments:
        pv = att['pv']
        node = att['node']
        if not att['attached']:
            continue

        if pv not in pv_nodes:
            pv_nodes[pv] = []
        pv_nodes[pv].append(node)

    for pv, nodes_list in pv_nodes.items():
        if len(nodes_list) > 1:
            pv_info = pvs.get(pv, {})
            access_modes = pv_info.get('access_modes', [])
            if 'ReadWriteOnce' in access_modes and 'ReadWriteMany' not in access_modes:
                violations.append({
                    'pv': pv,
                    'nodes': list(set(nodes_list)),
                    'severity': 'error',
                    'message': f'RWO volume {pv} attached to multiple nodes: {", ".join(set(nodes_list))}'
                })

    return violations


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
        description='Analyze Kubernetes VolumeAttachment resources for health issues'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed information')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only show VolumeAttachments with issues')
    parser.add_argument('--stale-hours', type=float, default=24.0,
                        help='Hours before unattached VA is stale (default: 24)')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool('kubectl'):
        output.error('kubectl not found. Install kubectl to use this script.')
        return 2

    try:
        # Gather data
        volume_attachments = get_volume_attachments(context)
        nodes = get_nodes(context)
        pvs = get_pvs(context)

        # Analyze each attachment
        analyzed = []
        for va in volume_attachments:
            result = analyze_attachment(va, nodes, pvs, opts.stale_hours)
            analyzed.append(result)

        # Sort by issue count (most issues first)
        analyzed.sort(key=lambda x: len(x['issues']), reverse=True)

        # Check for multi-attach violations
        violations = check_multi_attach(analyzed, pvs)

        # Filter if warn_only
        if opts.warn_only:
            analyzed = [a for a in analyzed if a['issues']]

        # Build summary
        total = len(volume_attachments)
        attached_count = sum(1 for va in volume_attachments if va.get('status', {}).get('attached', False))
        with_issues = sum(1 for a in analyzed if a['issues'])

        output.emit({
            'summary': {
                'total': total,
                'attached': attached_count,
                'with_issues': with_issues,
                'multi_attach_violations': len(violations)
            },
            'multi_attach_violations': violations,
            'attachments': analyzed
        })

        has_issues = any(a['issues'] for a in analyzed) or violations
        if has_issues:
            output.set_summary(f"{with_issues} VolumeAttachment issues, {len(violations)} multi-attach violations")
        else:
            output.set_summary(f"{total} VolumeAttachments healthy")

        return 1 if has_issues else 0

    except Exception as e:
        output.error(f'Failed to analyze VolumeAttachments: {e}')
        return 2


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
