#!/usr/bin/env python3
"""
Check Kubernetes persistent volume (PV) health and storage status.

This script provides comprehensive health checks for persistent volumes in a Kubernetes
cluster, including volume claims, binding status, capacity, and reclaim policies.
Useful for monitoring storage in large-scale baremetal Kubernetes deployments.

Exit codes:
    0 - All persistent volumes healthy
    1 - One or more PVs unhealthy or warnings detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys


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
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_persistent_volumes():
    """Get all persistent volumes in JSON format."""
    output = run_kubectl(['get', 'pv', '-o', 'json'])
    return json.loads(output)


def get_persistent_volume_claims():
    """Get all persistent volume claims across all namespaces."""
    output = run_kubectl(['get', 'pvc', '-A', '-o', 'json'])
    return json.loads(output)


def parse_storage_quantity(quantity_str):
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

    # Plain number (bytes)
    try:
        return int(quantity_str)
    except ValueError:
        return 0


def format_bytes(bytes_val):
    """Format bytes to human readable format."""
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}PiB"


def check_pv_health(pv, pvc_map):
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
            # Check if PVC is in expected state
            pvc = pvc_map[claim_key]
            if pvc['status'].get('phase') != 'Bound':
                issues.append(f"Claim {claim_key} not in Bound phase: {pvc['status'].get('phase')}")

    # Check for Released volumes with Retain policy (should be cleaned up)
    if status == 'Released':
        reclaim_policy = pv['spec'].get('persistentVolumeReclaimPolicy', 'Retain')
        if reclaim_policy == 'Retain':
            issues.append("Released volume with Retain policy - consider manual cleanup")

    # Warn if capacity is very small
    if capacity_bytes > 0 and capacity_bytes < parse_storage_quantity('1Gi'):
        issues.append(f"Very small capacity: {format_bytes(capacity_bytes)}")

    return status, issues


def print_pv_status(pvs_data, pvcs_data, output_format, warn_only):
    """Print PV status in requested format."""
    pvs = pvs_data.get('items', [])
    pvcs = pvcs_data.get('items', [])

    # Build PVC map for cross-reference
    pvc_map = {}
    for pvc in pvcs:
        ns = pvc['metadata']['namespace']
        name = pvc['metadata']['name']
        pvc_map[f"{ns}/{name}"] = pvc

    if output_format == 'json':
        output = []
        for pv in pvs:
            name = pv['metadata']['name']
            status, issues = check_pv_health(pv, pvc_map)
            capacity = pv['spec'].get('capacity', {})

            pv_info = {
                'name': name,
                'phase': status,
                'capacity': capacity.get('storage', 'Unknown'),
                'reclaim_policy': pv['spec'].get('persistentVolumeReclaimPolicy', 'Unknown'),
                'storage_class': pv['spec'].get('storageClassName', 'default'),
                'issues': issues
            }

            # Add claim info if bound
            claim_ref = pv['spec'].get('claimRef')
            if claim_ref:
                pv_info['bound_to'] = f"{claim_ref.get('namespace', 'unknown')}/{claim_ref.get('name', 'unknown')}"

            # Filter if warn_only
            if not warn_only or issues:
                output.append(pv_info)

        print(json.dumps(output, indent=2))
        return any(pv['issues'] for pv in output)

    else:  # plain format
        has_issues = False
        healthy_count = 0
        warning_count = 0

        for pv in pvs:
            name = pv['metadata']['name']
            status, issues = check_pv_health(pv, pvc_map)
            capacity = pv['spec'].get('capacity', {})

            # Count status
            if not issues:
                healthy_count += 1
            else:
                warning_count += 1
                has_issues = True

            # Skip healthy volumes if warn_only
            if warn_only and not issues:
                continue

            # Print PV info
            print(f"PersistentVolume: {name} - {status}")

            # Print capacity and class
            capacity_str = capacity.get('storage', 'Unknown')
            storage_class = pv['spec'].get('storageClassName', 'default')
            reclaim_policy = pv['spec'].get('persistentVolumeReclaimPolicy', 'Retain')
            print(f"  Capacity: {capacity_str} | StorageClass: {storage_class} | RecaimPolicy: {reclaim_policy}")

            # Print claim info if bound
            claim_ref = pv['spec'].get('claimRef')
            if claim_ref:
                claim_ns = claim_ref.get('namespace', 'unknown')
                claim_name = claim_ref.get('name', 'unknown')
                print(f"  Bound to: {claim_ns}/{claim_name}")

            # Print issues
            if issues:
                for issue in issues:
                    print(f"  WARNING: {issue}")

            print()

        # Print summary
        total = len(pvs)
        print(f"Summary: {healthy_count}/{total} volumes healthy, {warning_count} with issues")

        return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Check Kubernetes persistent volume health and storage status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Check all PVs, plain output
  %(prog)s --warn-only        # Show only PVs with issues
  %(prog)s --format json      # JSON output
  %(prog)s -f json -w         # JSON output, only problematic PVs

Exit codes:
  0 - All persistent volumes healthy
  1 - One or more PVs unhealthy
  2 - Usage error or kubectl unavailable
        """
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
        help='Only show PVs with warnings or issues'
    )

    args = parser.parse_args()

    # Get PV and PVC data
    pvs_data = get_persistent_volumes()
    pvcs_data = get_persistent_volume_claims()

    # Print status
    has_issues = print_pv_status(pvs_data, pvcs_data, args.format, args.warn_only)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
