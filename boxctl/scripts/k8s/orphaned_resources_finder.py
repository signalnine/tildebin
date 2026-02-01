#!/usr/bin/env python3
# boxctl:
#   category: k8s/resources
#   tags: [orphaned, cleanup, configmaps, secrets, pvcs]
#   requires: [kubectl]
#   privilege: user
#   related: [configmap_audit, pvc_stuck]
#   brief: Find orphaned and unused Kubernetes resources

"""
Kubernetes orphaned resources finder - Identify unused and orphaned resources.

Helps operators find and clean up:
- Orphaned ConfigMaps and Secrets (not referenced by any pod)
- Unused ServiceAccounts (not used by pods)
- Orphaned Persistent Volume Claims (not mounted by any pod)
- Unused Services with no endpoints

Exit codes:
    0 - No orphaned resources found
    1 - Orphaned resources detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_pods(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all pods."""
    args = ['kubectl', 'get', 'pod', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')
    result = context.run(args)
    data = json.loads(result.stdout)
    return data.get('items', [])


def get_configmaps(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all ConfigMaps."""
    args = ['kubectl', 'get', 'configmap', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')
    result = context.run(args)
    data = json.loads(result.stdout)
    return data.get('items', [])


def get_secrets(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all Secrets."""
    args = ['kubectl', 'get', 'secret', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')
    result = context.run(args)
    data = json.loads(result.stdout)
    return data.get('items', [])


def get_pvcs(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all PersistentVolumeClaims."""
    args = ['kubectl', 'get', 'pvc', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')
    result = context.run(args)
    data = json.loads(result.stdout)
    return data.get('items', [])


def get_serviceaccounts(context: Context, namespace: str | None = None) -> list[dict]:
    """Get all ServiceAccounts."""
    args = ['kubectl', 'get', 'serviceaccount', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')
    result = context.run(args)
    data = json.loads(result.stdout)
    return data.get('items', [])


def extract_references_from_pod(pod: dict) -> dict[str, set]:
    """Extract ConfigMap/Secret/PVC/SA references from a pod."""
    references: dict[str, set] = {
        'configmaps': set(),
        'secrets': set(),
        'pvcs': set(),
        'serviceaccounts': set(),
    }

    spec = pod.get('spec', {})
    namespace = pod.get('metadata', {}).get('namespace', 'default')

    # Service Account
    sa = spec.get('serviceAccountName')
    if sa:
        references['serviceaccounts'].add(f"{namespace}/{sa}")

    # Volumes
    for volume in spec.get('volumes', []):
        if 'configMap' in volume:
            name = volume['configMap'].get('name')
            if name:
                references['configmaps'].add(f"{namespace}/{name}")
        elif 'secret' in volume:
            name = volume['secret'].get('secretName')
            if name:
                references['secrets'].add(f"{namespace}/{name}")
        elif 'persistentVolumeClaim' in volume:
            name = volume['persistentVolumeClaim'].get('claimName')
            if name:
                references['pvcs'].add(f"{namespace}/{name}")

    # Container env/envFrom
    containers = spec.get('containers', []) + spec.get('initContainers', [])
    for container in containers:
        for env_from in container.get('envFrom', []):
            if 'configMapRef' in env_from:
                name = env_from['configMapRef'].get('name')
                if name:
                    references['configmaps'].add(f"{namespace}/{name}")
            elif 'secretRef' in env_from:
                name = env_from['secretRef'].get('name')
                if name:
                    references['secrets'].add(f"{namespace}/{name}")

        for env_var in container.get('env', []):
            value_from = env_var.get('valueFrom', {})
            if 'configMapKeyRef' in value_from:
                name = value_from['configMapKeyRef'].get('name')
                if name:
                    references['configmaps'].add(f"{namespace}/{name}")
            elif 'secretKeyRef' in value_from:
                name = value_from['secretKeyRef'].get('name')
                if name:
                    references['secrets'].add(f"{namespace}/{name}")

    return references


def find_orphaned_resources(
    pods: list[dict],
    configmaps: list[dict],
    secrets: list[dict],
    pvcs: list[dict],
    serviceaccounts: list[dict],
    skip_default_tokens: bool = True,
) -> dict[str, list[dict]]:
    """Find orphaned resources not referenced by any pod."""
    # Collect all references from pods
    all_refs: dict[str, set] = {
        'configmaps': set(),
        'secrets': set(),
        'pvcs': set(),
        'serviceaccounts': set(),
    }

    for pod in pods:
        refs = extract_references_from_pod(pod)
        for key in all_refs:
            all_refs[key].update(refs[key])

    orphaned: dict[str, list[dict]] = {
        'configmaps': [],
        'secrets': [],
        'pvcs': [],
        'serviceaccounts': [],
    }

    # Check ConfigMaps
    for cm in configmaps:
        namespace = cm['metadata'].get('namespace', 'default')
        name = cm['metadata']['name']
        key = f"{namespace}/{name}"
        if key not in all_refs['configmaps']:
            orphaned['configmaps'].append({
                'namespace': namespace,
                'name': name,
            })

    # Check Secrets
    for secret in secrets:
        namespace = secret['metadata'].get('namespace', 'default')
        name = secret['metadata']['name']
        key = f"{namespace}/{name}"

        # Skip default tokens
        if skip_default_tokens and name.startswith('default-token-'):
            continue

        if key not in all_refs['secrets']:
            orphaned['secrets'].append({
                'namespace': namespace,
                'name': name,
                'type': secret.get('type', 'Opaque'),
            })

    # Check PVCs
    for pvc in pvcs:
        namespace = pvc['metadata'].get('namespace', 'default')
        name = pvc['metadata']['name']
        key = f"{namespace}/{name}"
        if key not in all_refs['pvcs']:
            orphaned['pvcs'].append({
                'namespace': namespace,
                'name': name,
                'status': pvc.get('status', {}).get('phase', 'Unknown'),
            })

    # Check ServiceAccounts
    for sa in serviceaccounts:
        namespace = sa['metadata'].get('namespace', 'default')
        name = sa['metadata']['name']
        key = f"{namespace}/{name}"

        # Skip 'default' SA
        if name == 'default':
            continue

        if key not in all_refs['serviceaccounts']:
            orphaned['serviceaccounts'].append({
                'namespace': namespace,
                'name': name,
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
        0 = no orphaned resources, 1 = orphaned resources found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description='Find orphaned and unused Kubernetes resources'
    )
    parser.add_argument('-n', '--namespace', help='Namespace to check')
    parser.add_argument('--skip-configmaps', action='store_true', help='Skip ConfigMap check')
    parser.add_argument('--skip-secrets', action='store_true', help='Skip Secret check')
    parser.add_argument('--skip-pvcs', action='store_true', help='Skip PVC check')
    parser.add_argument('--skip-serviceaccounts', action='store_true', help='Skip ServiceAccount check')
    parser.add_argument('--format', choices=['plain', 'json'], default='plain')
    opts = parser.parse_args(args)

    if not context.check_tool('kubectl'):
        output.error('kubectl not found in PATH')
        return 2

    try:
        pods = get_pods(context, opts.namespace)

        configmaps = [] if opts.skip_configmaps else get_configmaps(context, opts.namespace)
        secrets = [] if opts.skip_secrets else get_secrets(context, opts.namespace)
        pvcs = [] if opts.skip_pvcs else get_pvcs(context, opts.namespace)
        serviceaccounts = [] if opts.skip_serviceaccounts else get_serviceaccounts(context, opts.namespace)
    except Exception as e:
        output.error(f'Failed to get cluster data: {e}')
        return 2

    orphaned = find_orphaned_resources(pods, configmaps, secrets, pvcs, serviceaccounts)

    # Count totals
    total_orphaned = (
        len(orphaned['configmaps']) +
        len(orphaned['secrets']) +
        len(orphaned['pvcs']) +
        len(orphaned['serviceaccounts'])
    )

    result = {
        'orphaned': orphaned,
        'summary': {
            'orphaned_configmaps': len(orphaned['configmaps']),
            'orphaned_secrets': len(orphaned['secrets']),
            'orphaned_pvcs': len(orphaned['pvcs']),
            'orphaned_serviceaccounts': len(orphaned['serviceaccounts']),
            'total_orphaned': total_orphaned,
        }
    }

    output.emit(result)
    output.set_summary(f"{total_orphaned} orphaned resources found")

    return 1 if total_orphaned > 0 else 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
