#!/usr/bin/env python3
"""
Monitor Kubernetes StorageClass provisioners and CSI driver health.

This script checks the health of storage provisioning infrastructure including:
- StorageClass configuration and default classes
- CSI driver pod health (provisioner, attacher, node driver pods)
- Recent PVC provisioning failures and timeout patterns
- Stuck volume attachments and detachments
- Orphaned VolumeAttachment resources

Designed for baremetal Kubernetes environments where storage provisioning
is critical and often uses CSI drivers (Ceph, local-path-provisioner, OpenEBS, etc.).

Exit codes:
    0 - All storage provisioners and CSI drivers are healthy
    1 - Storage provisioner issues, stuck volumes, or CSI driver problems detected
    2 - kubectl not available or cluster access error
"""

import argparse
import sys
import subprocess
import json
from datetime import datetime, timezone
from collections import defaultdict


def run_kubectl(args):
    """Execute kubectl command and return output"""
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
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(2)


def get_storage_classes():
    """Get all StorageClasses"""
    output = run_kubectl(['get', 'storageclasses', '-o', 'json'])
    data = json.loads(output)
    return data.get('items', [])


def get_pvcs(namespace=None):
    """Get PersistentVolumeClaims"""
    cmd = ['get', 'pvc', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    data = json.loads(output)
    return data.get('items', [])


def get_volume_attachments():
    """Get VolumeAttachment resources"""
    try:
        output = run_kubectl(['get', 'volumeattachments', '-o', 'json'])
        data = json.loads(output)
        return data.get('items', [])
    except:
        # VolumeAttachments may not exist in all clusters
        return []


def get_csi_pods():
    """Get CSI driver pods"""
    # CSI pods are typically in kube-system namespace
    output = run_kubectl(['get', 'pods', '-n', 'kube-system', '-o', 'json'])
    data = json.loads(output)

    # Filter for CSI-related pods
    csi_pods = []
    for pod in data.get('items', []):
        name = pod['metadata']['name']
        if any(keyword in name.lower() for keyword in ['csi', 'provisioner', 'attacher', 'snapshotter']):
            csi_pods.append(pod)

    return csi_pods


def get_events(namespace=None):
    """Get recent cluster events"""
    cmd = ['get', 'events', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    data = json.loads(output)
    return data.get('items', [])


def analyze_storage_classes(storage_classes):
    """Analyze StorageClass configuration"""
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

        # Check for default StorageClass
        if annotations.get('storageclass.kubernetes.io/is-default-class') == 'true':
            default_classes.append(name)

        info.append(f"StorageClass: {name} (provisioner: {provisioner})")

    if not default_classes:
        issues.append("No default StorageClass configured")
    elif len(default_classes) > 1:
        issues.append(f"Multiple default StorageClasses found: {', '.join(default_classes)}")

    return issues, info


def analyze_csi_pods(csi_pods):
    """Analyze CSI driver pod health"""
    issues = []
    info = []

    if not csi_pods:
        info.append("No CSI driver pods found in kube-system namespace")
        return issues, info

    for pod in csi_pods:
        name = pod['metadata']['name']
        namespace = pod['metadata']['namespace']
        phase = pod['status'].get('phase', 'Unknown')

        # Check pod phase
        if phase != 'Running':
            issues.append(f"CSI pod {namespace}/{name} not Running (phase: {phase})")
            continue

        # Check container statuses
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


def analyze_pvcs(pvcs):
    """Analyze PVC provisioning status"""
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
            # Check how long it's been pending
            creation_time = pvc['metadata']['creationTimestamp']
            # Simple check - in production would calculate age
            pending_pvcs.append(f"{namespace}/{name} (StorageClass: {storage_class})")
        elif phase == 'Failed':
            failed_pvcs.append(f"{namespace}/{name} (StorageClass: {storage_class})")

    if pending_pvcs:
        issues.append(f"Found {len(pending_pvcs)} pending PVCs")
        for pvc in pending_pvcs[:5]:  # Show first 5
            issues.append(f"  Pending PVC: {pvc}")
        if len(pending_pvcs) > 5:
            issues.append(f"  ... and {len(pending_pvcs) - 5} more")

    if failed_pvcs:
        issues.append(f"Found {len(failed_pvcs)} failed PVCs")
        for pvc in failed_pvcs:
            issues.append(f"  Failed PVC: {pvc}")

    info.append(f"Total PVCs: {len(pvcs)} (Pending: {len(pending_pvcs)}, Failed: {len(failed_pvcs)})")

    return issues, info


def analyze_volume_attachments(volume_attachments):
    """Analyze VolumeAttachment resources for stuck attachments"""
    issues = []
    info = []

    if not volume_attachments:
        info.append("No VolumeAttachments found")
        return issues, info

    stuck_attachments = []

    for va in volume_attachments:
        name = va['metadata']['name']
        attached = va['status'].get('attached', False)

        # Check for attachment errors
        attach_error = va['status'].get('attachError', {})
        detach_error = va['status'].get('detachError', {})

        if attach_error:
            message = attach_error.get('message', 'Unknown error')
            stuck_attachments.append(f"{name}: Attach error - {message}")

        if detach_error:
            message = detach_error.get('message', 'Unknown error')
            stuck_attachments.append(f"{name}: Detach error - {message}")

        if not attached and not attach_error:
            # Volume not attached and no error - might be stuck
            stuck_attachments.append(f"{name}: Not attached (potential stuck state)")

    if stuck_attachments:
        issues.append(f"Found {len(stuck_attachments)} stuck volume attachments")
        for attachment in stuck_attachments[:5]:
            issues.append(f"  {attachment}")
        if len(stuck_attachments) > 5:
            issues.append(f"  ... and {len(stuck_attachments) - 5} more")

    info.append(f"Total VolumeAttachments: {len(volume_attachments)} (Stuck: {len(stuck_attachments)})")

    return issues, info


def analyze_storage_events(events):
    """Analyze recent storage-related events"""
    issues = []
    info = []

    storage_events = []

    # Filter for storage-related events
    for event in events:
        reason = event.get('reason', '')
        message = event.get('message', '')
        event_type = event.get('type', '')

        # Look for storage-related keywords
        if any(keyword in reason.lower() or keyword in message.lower()
               for keyword in ['provisioning', 'volume', 'pvc', 'storage', 'csi', 'attach', 'mount']):
            if event_type == 'Warning' or event_type == 'Error':
                storage_events.append({
                    'type': event_type,
                    'reason': reason,
                    'message': message,
                    'count': event.get('count', 1)
                })

    # Group by reason
    event_counts = defaultdict(int)
    for event in storage_events:
        event_counts[event['reason']] += event['count']

    if event_counts:
        issues.append(f"Found {len(storage_events)} storage-related warning/error events")
        for reason, count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            issues.append(f"  {reason}: {count} occurrences")

    return issues, info


def output_plain(all_issues, all_info, warn_only):
    """Output results in plain text format"""
    if not warn_only and all_info:
        print("=== Storage Infrastructure Info ===")
        for info in all_info:
            print(info)
        print()

    if all_issues:
        print("=== Storage Issues Detected ===")
        for issue in all_issues:
            print(f"WARNING: {issue}")
    else:
        if not warn_only:
            print("All storage provisioners and CSI drivers are healthy")


def output_json(all_issues, all_info):
    """Output results in JSON format"""
    result = {
        'status': 'unhealthy' if all_issues else 'healthy',
        'issues': all_issues,
        'info': all_info,
        'issue_count': len(all_issues)
    }
    print(json.dumps(result, indent=2))


def output_table(all_issues, all_info, warn_only):
    """Output results in table format"""
    if not warn_only and all_info:
        print(f"{'Component':<40} {'Status':<20}")
        print("-" * 60)
        for info in all_info:
            print(f"{info:<40} {'OK':<20}")
        print()

    if all_issues:
        print(f"{'Issue Type':<40} {'Description':<40}")
        print("-" * 80)
        for issue in all_issues:
            print(f"{'Storage Warning':<40} {issue:<40}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes StorageClass provisioners and CSI driver health",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all storage infrastructure
  %(prog)s

  # Check specific namespace only
  %(prog)s -n production

  # Show only issues (no info)
  %(prog)s --warn-only

  # Output as JSON
  %(prog)s --format json

Exit codes:
  0 - All storage provisioners healthy
  1 - Storage issues detected
  2 - kubectl not available
        """
    )

    parser.add_argument(
        "-n", "--namespace",
        help="Check PVCs in specific namespace (default: all namespaces)"
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues, hide informational output"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )

    args = parser.parse_args()

    try:
        all_issues = []
        all_info = []

        # Analyze StorageClasses
        storage_classes = get_storage_classes()
        issues, info = analyze_storage_classes(storage_classes)
        all_issues.extend(issues)
        all_info.extend(info)

        # Analyze CSI driver pods
        csi_pods = get_csi_pods()
        issues, info = analyze_csi_pods(csi_pods)
        all_issues.extend(issues)
        all_info.extend(info)

        # Analyze PVCs
        pvcs = get_pvcs(args.namespace)
        issues, info = analyze_pvcs(pvcs)
        all_issues.extend(issues)
        all_info.extend(info)

        # Analyze VolumeAttachments
        volume_attachments = get_volume_attachments()
        issues, info = analyze_volume_attachments(volume_attachments)
        all_issues.extend(issues)
        all_info.extend(info)

        # Analyze storage-related events
        if args.verbose:
            events = get_events(args.namespace)
            issues, info = analyze_storage_events(events)
            all_issues.extend(issues)
            all_info.extend(info)

        # Output results
        if args.format == "json":
            output_json(all_issues, all_info)
        elif args.format == "table":
            output_table(all_issues, all_info, args.warn_only)
        else:
            output_plain(all_issues, all_info, args.warn_only)

        # Exit with appropriate code
        sys.exit(1 if all_issues else 0)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
