#!/usr/bin/env python3
"""
Detect Kubernetes PersistentVolumeClaims stuck in Pending state.

This script identifies PVCs that have been pending for longer than a specified
threshold and provides diagnostic information about why they might be stuck.
Common causes include missing StorageClass, no matching PV, provisioner issues,
node affinity constraints, and insufficient capacity.

Useful for monitoring storage provisioning health in large-scale Kubernetes
deployments, especially on baremetal where dynamic provisioning may be limited.

Exit codes:
    0 - No stuck PVCs found (all healthy or none exist)
    1 - One or more PVCs stuck in Pending state
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
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_pvcs(namespace=None):
    """Get PersistentVolumeClaims in JSON format."""
    cmd = ['get', 'pvc', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')
    output = run_kubectl(cmd)
    return json.loads(output)


def get_storage_classes():
    """Get StorageClasses in JSON format."""
    output = run_kubectl(['get', 'storageclasses', '-o', 'json'])
    return json.loads(output)


def get_persistent_volumes():
    """Get PersistentVolumes in JSON format."""
    output = run_kubectl(['get', 'pv', '-o', 'json'])
    return json.loads(output)


def get_events(namespace, pvc_name):
    """Get events related to a PVC."""
    try:
        output = run_kubectl([
            'get', 'events', '-n', namespace,
            '--field-selector', f'involvedObject.name={pvc_name},involvedObject.kind=PersistentVolumeClaim',
            '-o', 'json'
        ])
        return json.loads(output)
    except SystemExit:
        # Events might fail, don't exit the whole script
        return {'items': []}


def parse_k8s_timestamp(timestamp_str):
    """Parse Kubernetes timestamp to datetime object."""
    if not timestamp_str:
        return None
    try:
        # Handle both formats: with and without microseconds
        for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ']:
            try:
                return datetime.strptime(timestamp_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None
    except Exception:
        return None


def get_pvc_age_minutes(pvc):
    """Get age of PVC in minutes."""
    creation_time = pvc['metadata'].get('creationTimestamp')
    if not creation_time:
        return 0
    created = parse_k8s_timestamp(creation_time)
    if not created:
        return 0
    now = datetime.now(timezone.utc)
    return (now - created).total_seconds() / 60


def format_duration(minutes):
    """Format duration in human-readable format."""
    if minutes < 60:
        return f"{int(minutes)}m"
    elif minutes < 1440:  # Less than 24 hours
        hours = int(minutes / 60)
        mins = int(minutes % 60)
        return f"{hours}h{mins}m"
    else:
        days = int(minutes / 1440)
        hours = int((minutes % 1440) / 60)
        return f"{days}d{hours}h"


def diagnose_stuck_pvc(pvc, storage_classes, pvs, events_data):
    """Diagnose why a PVC might be stuck in Pending state."""
    diagnostics = []
    spec = pvc.get('spec', {})
    status = pvc.get('status', {})

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

        # Check if provisioner is known problematic
        if provisioner == 'kubernetes.io/no-provisioner':
            diagnostics.append(f"StorageClass uses no-provisioner (manual PV binding required)")

            # Check for available PVs that could match
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
        # No storage class specified
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
            diagnostics.append(f"PVC has selector constraints - requires matching PV labels")

    # Check events for provisioning errors
    events = events_data.get('items', [])
    recent_errors = []
    for event in events:
        if event.get('type') == 'Warning':
            reason = event.get('reason', '')
            message = event.get('message', '')
            if reason in ['ProvisioningFailed', 'FailedBinding', 'FailedScheduling', 'FailedMount']:
                recent_errors.append(f"{reason}: {message[:100]}")

    if recent_errors:
        # Only show most recent error
        diagnostics.append(f"Recent event: {recent_errors[-1]}")

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


def analyze_pvcs(pvcs_data, storage_classes, pvs, threshold_minutes, namespace_filter):
    """Analyze PVCs and find stuck ones."""
    stuck_pvcs = []

    for pvc in pvcs_data.get('items', []):
        phase = pvc.get('status', {}).get('phase', 'Unknown')

        # Only care about Pending PVCs
        if phase != 'Pending':
            continue

        ns = pvc['metadata']['namespace']
        name = pvc['metadata']['name']
        age_minutes = get_pvc_age_minutes(pvc)

        # Apply namespace filter if specified
        if namespace_filter and ns != namespace_filter:
            continue

        # Check if stuck longer than threshold
        if age_minutes < threshold_minutes:
            continue

        # Get events for this PVC
        events = get_events(ns, name)

        # Diagnose the issue
        diagnosis = diagnose_stuck_pvc(pvc, storage_classes, pvs, events)

        stuck_pvcs.append({
            'namespace': ns,
            'name': name,
            'age_minutes': age_minutes,
            'age_formatted': format_duration(age_minutes),
            'diagnosis': diagnosis
        })

    return stuck_pvcs


def print_plain(stuck_pvcs, verbose):
    """Print stuck PVCs in plain text format."""
    if not stuck_pvcs:
        print("No stuck PVCs found")
        return

    print(f"Found {len(stuck_pvcs)} PVC(s) stuck in Pending state:\n")

    for pvc in stuck_pvcs:
        ns = pvc['namespace']
        name = pvc['name']
        age = pvc['age_formatted']
        diag = pvc['diagnosis']

        print(f"PVC: {ns}/{name}")
        print(f"  Age: {age}")
        print(f"  StorageClass: {diag['requested_class']}")
        print(f"  Requested: {diag['requested_size']} ({', '.join(diag['access_modes'])})")

        if diag['diagnostics']:
            print("  Diagnostics:")
            for d in diag['diagnostics']:
                print(f"    - {d}")

        if verbose:
            print(f"  VolumeMode: {diag['volume_mode']}")

        print()

    print(f"Summary: {len(stuck_pvcs)} PVC(s) stuck in Pending state")


def print_json(stuck_pvcs):
    """Print stuck PVCs in JSON format."""
    output = {
        'stuck_count': len(stuck_pvcs),
        'pvcs': stuck_pvcs
    }
    print(json.dumps(output, indent=2))


def print_table(stuck_pvcs):
    """Print stuck PVCs in table format."""
    if not stuck_pvcs:
        print("No stuck PVCs found")
        return

    # Header
    print(f"{'NAMESPACE':<20} {'NAME':<30} {'AGE':<8} {'STORAGECLASS':<20} {'SIZE':<10} {'ISSUE'}")
    print("-" * 120)

    for pvc in stuck_pvcs:
        ns = pvc['namespace'][:20]
        name = pvc['name'][:30]
        age = pvc['age_formatted']
        sc = pvc['diagnosis']['requested_class'][:20]
        size = pvc['diagnosis']['requested_size'][:10]

        # Get first diagnostic or "Unknown"
        diags = pvc['diagnosis']['diagnostics']
        issue = diags[0][:40] if diags else "Unknown"

        print(f"{ns:<20} {name:<30} {age:<8} {sc:<20} {size:<10} {issue}")

    print()
    print(f"Total: {len(stuck_pvcs)} stuck PVC(s)")


def main():
    parser = argparse.ArgumentParser(
        description='Detect Kubernetes PVCs stuck in Pending state',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Find PVCs pending > 5 minutes (default)
  %(prog)s -t 60                # Find PVCs pending > 1 hour
  %(prog)s -n kube-system       # Check only kube-system namespace
  %(prog)s --format json        # JSON output for scripting
  %(prog)s --format table       # Table format for quick overview
  %(prog)s -v                   # Verbose output with more details

Exit codes:
  0 - No stuck PVCs found
  1 - One or more PVCs stuck in Pending state
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=5,
        metavar='MINUTES',
        help='Minimum age in minutes to consider PVC stuck (default: 5)'
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to check (default: all namespaces)'
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show additional diagnostic details'
    )

    args = parser.parse_args()

    if args.threshold < 0:
        print("Error: threshold must be non-negative", file=sys.stderr)
        sys.exit(2)

    # Gather cluster state
    pvcs = get_pvcs(args.namespace)
    storage_classes = get_storage_classes()
    pvs = get_persistent_volumes()

    # Analyze for stuck PVCs
    stuck_pvcs = analyze_pvcs(pvcs, storage_classes, pvs, args.threshold, args.namespace)

    # Output results
    if args.format == 'json':
        print_json(stuck_pvcs)
    elif args.format == 'table':
        print_table(stuck_pvcs)
    else:
        print_plain(stuck_pvcs, args.verbose)

    # Exit code based on findings
    sys.exit(1 if stuck_pvcs else 0)


if __name__ == '__main__':
    main()
