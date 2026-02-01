#!/usr/bin/env python3
# boxctl:
#   category: k8s/storage
#   tags: [health, storageclass, csi, kubernetes, provisioner]
#   requires: [kubectl]
#   privilege: none
#   related: [pv_health, pvc_stuck, volume_attachment]
#   brief: Monitor Kubernetes StorageClass provisioners and CSI driver health

"""
Monitor Kubernetes StorageClass provisioners and CSI driver health.

Checks the health of storage provisioning infrastructure including:
- StorageClass configuration and default classes
- CSI driver pod health (provisioner, attacher, node driver pods)
- Pending/failed PVC detection
- Stuck volume attachments

Returns exit code 1 if issues are detected.
"""

import argparse
import json
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_storage_classes(context: Context) -> list[dict[str, Any]]:
    """Get all StorageClasses."""
    result = context.run(['kubectl', 'get', 'storageclasses', '-o', 'json'])
    data = json.loads(result.stdout)
    return data.get('items', [])


def get_pvcs(context: Context, namespace: str | None = None) -> list[dict[str, Any]]:
    """Get PersistentVolumeClaims."""
    cmd = ['kubectl', 'get', 'pvc', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')
    result = context.run(cmd)
    data = json.loads(result.stdout)
    return data.get('items', [])


def get_volume_attachments(context: Context) -> list[dict[str, Any]]:
    """Get VolumeAttachment resources."""
    try:
        result = context.run(['kubectl', 'get', 'volumeattachments', '-o', 'json'])
        data = json.loads(result.stdout)
        return data.get('items', [])
    except Exception:
        return []


def get_csi_pods(context: Context) -> list[dict[str, Any]]:
    """Get CSI driver pods from kube-system."""
    result = context.run(['kubectl', 'get', 'pods', '-n', 'kube-system', '-o', 'json'])
    data = json.loads(result.stdout)

    csi_pods = []
    for pod in data.get('items', []):
        name = pod['metadata']['name']
        if any(keyword in name.lower() for keyword in ['csi', 'provisioner', 'attacher', 'snapshotter']):
            csi_pods.append(pod)

    return csi_pods


def analyze_storage_classes(storage_classes: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Analyze StorageClass configuration."""
    issues = []
    info = []

    if not storage_classes:
        issues.append("No StorageClasses found in cluster")
        return issues, info

    default_classes = []
    for sc in storage_classes:
        name = sc['metadata']['name']
        provisioner = sc['provisioner']
        annotations = sc['metadata'].get('annotations', {})

        if annotations.get('storageclass.kubernetes.io/is-default-class') == 'true':
            default_classes.append(name)

        info.append(f"StorageClass: {name} (provisioner: {provisioner})")

    if not default_classes:
        issues.append("No default StorageClass configured")
    elif len(default_classes) > 1:
        issues.append(f"Multiple default StorageClasses found: {', '.join(default_classes)}")

    return issues, info


def analyze_csi_pods(csi_pods: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Analyze CSI driver pod health."""
    issues = []
    info = []

    if not csi_pods:
        info.append("No CSI driver pods found in kube-system namespace")
        return issues, info

    for pod in csi_pods:
        name = pod['metadata']['name']
        namespace = pod['metadata']['namespace']
        phase = pod['status'].get('phase', 'Unknown')

        if phase != 'Running':
            issues.append(f"CSI pod {namespace}/{name} not Running (phase: {phase})")
            continue

        container_statuses = pod['status'].get('containerStatuses', [])
        for container in container_statuses:
            container_name = container['name']
            ready = container.get('ready', False)
            restart_count = container.get('restartCount', 0)

            if not ready:
                issues.append(f"CSI pod {namespace}/{name} container {container_name} not ready")

            if restart_count > 5:
                issues.append(f"CSI pod {namespace}/{name} container {container_name} has {restart_count} restarts")

        info.append(f"CSI pod: {namespace}/{name} (phase: {phase})")

    return issues, info


def analyze_pvcs(pvcs: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Analyze PVC provisioning status."""
    issues = []
    info = []

    pending_pvcs = []
    failed_pvcs = []

    for pvc in pvcs:
        name = pvc['metadata']['name']
        namespace = pvc['metadata']['namespace']
        phase = pvc['status'].get('phase', 'Unknown')
        storage_class = pvc['spec'].get('storageClassName', 'default')

        if phase == 'Pending':
            pending_pvcs.append(f"{namespace}/{name} (StorageClass: {storage_class})")
        elif phase == 'Failed':
            failed_pvcs.append(f"{namespace}/{name} (StorageClass: {storage_class})")

    if pending_pvcs:
        issues.append(f"Found {len(pending_pvcs)} pending PVCs")
        for pvc in pending_pvcs[:5]:
            issues.append(f"  Pending PVC: {pvc}")
        if len(pending_pvcs) > 5:
            issues.append(f"  ... and {len(pending_pvcs) - 5} more")

    if failed_pvcs:
        issues.append(f"Found {len(failed_pvcs)} failed PVCs")
        for pvc in failed_pvcs:
            issues.append(f"  Failed PVC: {pvc}")

    info.append(f"Total PVCs: {len(pvcs)} (Pending: {len(pending_pvcs)}, Failed: {len(failed_pvcs)})")

    return issues, info


def analyze_volume_attachments(volume_attachments: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Analyze VolumeAttachment resources for stuck attachments."""
    issues = []
    info = []

    if not volume_attachments:
        info.append("No VolumeAttachments found")
        return issues, info

    stuck_attachments = []

    for va in volume_attachments:
        name = va['metadata']['name']
        attached = va['status'].get('attached', False)

        attach_error = va['status'].get('attachError', {})
        detach_error = va['status'].get('detachError', {})

        if attach_error:
            message = attach_error.get('message', 'Unknown error')
            stuck_attachments.append(f"{name}: Attach error - {message[:100]}")

        if detach_error:
            message = detach_error.get('message', 'Unknown error')
            stuck_attachments.append(f"{name}: Detach error - {message[:100]}")

        if not attached and not attach_error:
            stuck_attachments.append(f"{name}: Not attached (potential stuck state)")

    if stuck_attachments:
        issues.append(f"Found {len(stuck_attachments)} stuck volume attachments")
        for attachment in stuck_attachments[:5]:
            issues.append(f"  {attachment}")
        if len(stuck_attachments) > 5:
            issues.append(f"  ... and {len(stuck_attachments) - 5} more")

    info.append(f"Total VolumeAttachments: {len(volume_attachments)} (Stuck: {len(stuck_attachments)})")

    return issues, info


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
        description='Monitor Kubernetes StorageClass provisioners and CSI driver health'
    )
    parser.add_argument('-n', '--namespace',
                        help='Check PVCs in specific namespace (default: all)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed information')
    parser.add_argument('-w', '--warn-only', action='store_true',
                        help='Only show warnings and issues')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool('kubectl'):
        output.error('kubectl not found. Install kubectl to use this script.')
        return 2

    try:
        all_issues = []
        all_info = []

        # Analyze StorageClasses
        storage_classes = get_storage_classes(context)
        issues, info = analyze_storage_classes(storage_classes)
        all_issues.extend(issues)
        all_info.extend(info)

        # Analyze CSI driver pods
        csi_pods = get_csi_pods(context)
        issues, info = analyze_csi_pods(csi_pods)
        all_issues.extend(issues)
        all_info.extend(info)

        # Analyze PVCs
        pvcs = get_pvcs(context, opts.namespace)
        issues, info = analyze_pvcs(pvcs)
        all_issues.extend(issues)
        all_info.extend(info)

        # Analyze VolumeAttachments
        volume_attachments = get_volume_attachments(context)
        issues, info = analyze_volume_attachments(volume_attachments)
        all_issues.extend(issues)
        all_info.extend(info)

        output.emit({
            'status': 'unhealthy' if all_issues else 'healthy',
            'issues': all_issues,
            'info': all_info,
            'issue_count': len(all_issues),
            'storage_classes': len(storage_classes),
            'csi_pods': len(csi_pods),
            'pvcs': len(pvcs),
            'volume_attachments': len(volume_attachments)
        })

        if all_issues:
            output.set_summary(f"{len(all_issues)} storage infrastructure issues detected")
        else:
            output.set_summary("All storage provisioners healthy")

        return 1 if all_issues else 0

    except Exception as e:
        output.error(f'Failed to analyze storage infrastructure: {e}')
        return 2


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
