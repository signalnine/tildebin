#!/usr/bin/env python3
"""
Analyze Kubernetes VolumeAttachment resources for health issues.

VolumeAttachments track which volumes are attached to which nodes. This script
identifies stale, orphaned, or problematic attachments that can cause:
- Pods stuck in ContainerCreating state
- Volumes that cannot be attached to new nodes
- Multi-attach violations for non-shareable volumes
- Node drain failures due to stuck attachments

Useful for:
- Debugging pod scheduling issues related to storage
- Identifying orphaned attachments after node failures
- Detecting multi-attach problems with RWO volumes
- Pre-maintenance checks before node drains

Exit codes:
    0 - All VolumeAttachments healthy
    1 - Issues detected (stale, orphaned, or problematic attachments)
    2 - Usage error or kubectl not available
"""

import argparse
import sys
import subprocess
import json
from datetime import datetime, timezone


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
        print(f"Error: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_volume_attachments():
    """Get all VolumeAttachment resources"""
    output = run_kubectl(['get', 'volumeattachments', '-o', 'json'])
    data = json.loads(output)
    return data.get('items', [])


def get_nodes():
    """Get all nodes in the cluster"""
    output = run_kubectl(['get', 'nodes', '-o', 'json'])
    data = json.loads(output)
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


def get_pvs():
    """Get all PersistentVolumes"""
    output = run_kubectl(['get', 'pv', '-o', 'json'])
    data = json.loads(output)
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


def get_pods_using_pvc(pvc_name, namespace):
    """Find pods using a specific PVC"""
    output = run_kubectl([
        'get', 'pods', '-n', namespace, '-o', 'json'
    ])
    data = json.loads(output)
    pods = []
    for pod in data.get('items', []):
        volumes = pod.get('spec', {}).get('volumes', [])
        for vol in volumes:
            pvc = vol.get('persistentVolumeClaim', {})
            if pvc.get('claimName') == pvc_name:
                pods.append({
                    'name': pod['metadata']['name'],
                    'namespace': namespace,
                    'phase': pod.get('status', {}).get('phase', 'Unknown'),
                    'node': pod.get('spec', {}).get('nodeName', '')
                })
    return pods


def parse_timestamp(ts_str):
    """Parse Kubernetes timestamp to datetime"""
    if not ts_str:
        return None
    try:
        # Handle format: 2024-01-15T10:30:00Z
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def analyze_attachment(va, nodes, pvs, stale_threshold_hours):
    """Analyze a single VolumeAttachment for issues"""
    issues = []
    metadata = va.get('metadata', {})
    spec = va.get('spec', {})
    status = va.get('status', {})

    name = metadata.get('name', 'unknown')
    node_name = spec.get('nodeName', '')
    pv_name = spec.get('source', {}).get('persistentVolumeName', '')
    attacher = spec.get('attacher', '')

    # Check attachment status
    attached = status.get('attached', False)
    attach_error = status.get('attachError', {})
    detach_error = status.get('detachError', {})

    # Get creation time
    creation_ts = parse_timestamp(metadata.get('creationTimestamp'))
    age_hours = 0
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


def check_multi_attach(attachments, pvs):
    """Check for multi-attach violations on RWO volumes"""
    pv_nodes = {}  # pv_name -> [nodes]
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
            # Check if RWO (ReadWriteOnce)
            if 'ReadWriteOnce' in access_modes and 'ReadWriteMany' not in access_modes:
                violations.append({
                    'pv': pv,
                    'nodes': list(set(nodes_list)),
                    'severity': 'error',
                    'message': f'RWO volume {pv} attached to multiple nodes: {", ".join(set(nodes_list))}'
                })

    return violations


def output_plain(attachments, violations, warn_only, verbose):
    """Output results in plain text format"""
    print("Kubernetes VolumeAttachment Analysis")
    print("=" * 60)

    total = len(attachments)
    with_issues = sum(1 for a in attachments if a['issues'])
    attached_count = sum(1 for a in attachments if a['attached'])

    print(f"\nSummary:")
    print(f"  Total VolumeAttachments: {total}")
    print(f"  Currently attached: {attached_count}")
    print(f"  With issues: {with_issues}")
    print(f"  Multi-attach violations: {len(violations)}")

    if violations:
        print("\n" + "-" * 60)
        print("Multi-Attach Violations:")
        for v in violations:
            print(f"  [ERROR] {v['message']}")

    print("\n" + "-" * 60)
    print("VolumeAttachments:")

    for att in attachments:
        if warn_only and not att['issues']:
            continue

        status = "attached" if att['attached'] else "detached"
        issue_count = len(att['issues'])
        status_marker = "[!]" if issue_count > 0 else "[+]"

        print(f"\n{status_marker} {att['name']}")
        print(f"    Node: {att['node']}")
        print(f"    PV: {att['pv']}")
        print(f"    Status: {status}")
        print(f"    Age: {att['age_hours']} hours")

        if verbose:
            print(f"    Attacher: {att['attacher']}")

        for issue in att['issues']:
            severity = issue['severity'].upper()
            print(f"    [{severity}] {issue['message']}")

    print("\n" + "=" * 60)


def output_json(attachments, violations):
    """Output results in JSON format"""
    result = {
        'summary': {
            'total': len(attachments),
            'attached': sum(1 for a in attachments if a['attached']),
            'with_issues': sum(1 for a in attachments if a['issues']),
            'multi_attach_violations': len(violations)
        },
        'multi_attach_violations': violations,
        'attachments': attachments
    }
    print(json.dumps(result, indent=2))


def output_table(attachments, warn_only):
    """Output results in table format"""
    print(f"{'Name':<45} {'Node':<20} {'PV':<20} {'Status':<10} {'Issues'}")
    print("-" * 110)

    for att in attachments:
        if warn_only and not att['issues']:
            continue

        name = att['name'][:44]
        node = att['node'][:19] if att['node'] else '-'
        pv = att['pv'][:19] if att['pv'] else '-'
        status = "attached" if att['attached'] else "detached"
        issues = len(att['issues'])

        print(f"{name:<45} {node:<20} {pv:<20} {status:<10} {issues}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes VolumeAttachment resources for health issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Analyze all VolumeAttachments
  %(prog)s --warn-only          # Show only attachments with issues
  %(prog)s --format json        # JSON output for automation
  %(prog)s --stale-hours 2      # Flag unattached VAs older than 2 hours
"""
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
        help="Only show VolumeAttachments with issues"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )

    parser.add_argument(
        "--stale-hours",
        type=float,
        default=24.0,
        help="Hours before unattached VA is considered stale (default: %(default)s)"
    )

    args = parser.parse_args()

    try:
        # Gather data
        volume_attachments = get_volume_attachments()
        nodes = get_nodes()
        pvs = get_pvs()

        # Analyze each attachment
        analyzed = []
        for va in volume_attachments:
            result = analyze_attachment(va, nodes, pvs, args.stale_hours)
            analyzed.append(result)

        # Sort by issue count (most issues first)
        analyzed.sort(key=lambda x: len(x['issues']), reverse=True)

        # Check for multi-attach violations
        violations = check_multi_attach(analyzed, pvs)

        # Output results
        if args.format == "json":
            output_json(analyzed, violations)
        elif args.format == "table":
            output_table(analyzed, args.warn_only)
        else:
            output_plain(analyzed, violations, args.warn_only, args.verbose)

        # Exit code based on findings
        has_issues = any(a['issues'] for a in analyzed) or violations
        sys.exit(1 if has_issues else 0)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
