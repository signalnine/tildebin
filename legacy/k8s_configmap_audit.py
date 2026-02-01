#!/usr/bin/env python3
"""
Audit Kubernetes ConfigMaps for common issues and best practices.

This script helps identify ConfigMap problems including:
- ConfigMaps approaching size limits (1MB)
- Unused ConfigMaps (not referenced by any pod)
- Large ConfigMaps that could cause etcd performance issues
- ConfigMaps with missing keys referenced by pods
- ConfigMaps in default namespace (potential security concern)

Exit codes:
    0 - No issues found
    1 - Issues detected (warnings)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


# ConfigMap size limit in Kubernetes (1MB)
CONFIGMAP_SIZE_LIMIT = 1024 * 1024
# Warning threshold (80% of limit)
SIZE_WARNING_THRESHOLD = 0.8 * CONFIGMAP_SIZE_LIMIT
# Large ConfigMap threshold for performance warnings (100KB)
LARGE_CONFIGMAP_THRESHOLD = 100 * 1024


def run_kubectl(args):
    """Execute kubectl command and return output."""
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
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/",
              file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_configmaps(namespace=None):
    """Get all ConfigMaps with their data."""
    cmd = ['get', 'configmaps', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output).get('items', [])


def get_pods(namespace=None):
    """Get all pods with their specs."""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    return json.loads(output).get('items', [])


def calculate_configmap_size(configmap):
    """Calculate the approximate size of a ConfigMap in bytes."""
    size = 0
    data = configmap.get('data', {})
    binary_data = configmap.get('binaryData', {})

    for key, value in data.items():
        size += len(key.encode('utf-8'))
        size += len(value.encode('utf-8')) if value else 0

    for key, value in binary_data.items():
        size += len(key.encode('utf-8'))
        # binaryData is base64 encoded, actual size is ~75% of encoded
        size += int(len(value) * 0.75) if value else 0

    return size


def get_configmap_references(pods):
    """Extract ConfigMap references from pods."""
    references = defaultdict(set)

    for pod in pods:
        pod_namespace = pod['metadata']['namespace']
        pod_name = pod['metadata']['name']
        spec = pod.get('spec', {})

        # Check volumes
        for volume in spec.get('volumes', []):
            if 'configMap' in volume:
                cm_name = volume['configMap'].get('name')
                if cm_name:
                    references[(pod_namespace, cm_name)].add(
                        f"pod/{pod_name} (volume)"
                    )

        # Check containers
        for container in spec.get('containers', []) + spec.get('initContainers', []):
            # Check envFrom
            for env_from in container.get('envFrom', []):
                if 'configMapRef' in env_from:
                    cm_name = env_from['configMapRef'].get('name')
                    if cm_name:
                        references[(pod_namespace, cm_name)].add(
                            f"pod/{pod_name} ({container['name']} envFrom)"
                        )

            # Check env valueFrom
            for env in container.get('env', []):
                value_from = env.get('valueFrom', {})
                if 'configMapKeyRef' in value_from:
                    cm_name = value_from['configMapKeyRef'].get('name')
                    if cm_name:
                        references[(pod_namespace, cm_name)].add(
                            f"pod/{pod_name} ({container['name']} env:{env['name']})"
                        )

    return references


def get_key_references(pods):
    """Extract specific key references from ConfigMaps in pods."""
    key_refs = defaultdict(set)

    for pod in pods:
        pod_namespace = pod['metadata']['namespace']
        pod_name = pod['metadata']['name']
        spec = pod.get('spec', {})

        # Check volumes with items
        for volume in spec.get('volumes', []):
            if 'configMap' in volume:
                cm_name = volume['configMap'].get('name')
                items = volume['configMap'].get('items', [])
                for item in items:
                    key = item.get('key')
                    if key:
                        key_refs[(pod_namespace, cm_name)].add(key)

        # Check containers for env valueFrom
        for container in spec.get('containers', []) + spec.get('initContainers', []):
            for env in container.get('env', []):
                value_from = env.get('valueFrom', {})
                if 'configMapKeyRef' in value_from:
                    cm_ref = value_from['configMapKeyRef']
                    cm_name = cm_ref.get('name')
                    key = cm_ref.get('key')
                    if cm_name and key:
                        key_refs[(pod_namespace, cm_name)].add(key)

    return key_refs


def audit_configmaps(configmaps, pods, verbose=False):
    """Audit ConfigMaps for issues."""
    issues = {
        'approaching_limit': [],
        'large_configmaps': [],
        'unused': [],
        'missing_keys': [],
        'default_namespace': [],
        'empty': []
    }

    cm_references = get_configmap_references(pods)
    key_references = get_key_references(pods)

    for cm in configmaps:
        name = cm['metadata']['name']
        namespace = cm['metadata']['namespace']
        cm_key = (namespace, name)

        # Skip system ConfigMaps
        if name.startswith('kube-') or namespace in ['kube-system', 'kube-public']:
            if not verbose:
                continue

        # Calculate size
        size = calculate_configmap_size(cm)
        size_kb = size / 1024

        # Check if approaching size limit
        if size >= SIZE_WARNING_THRESHOLD:
            issues['approaching_limit'].append({
                'namespace': namespace,
                'name': name,
                'size_bytes': size,
                'size_kb': round(size_kb, 2),
                'percent_of_limit': round((size / CONFIGMAP_SIZE_LIMIT) * 100, 1)
            })

        # Check for large ConfigMaps (performance concern)
        elif size >= LARGE_CONFIGMAP_THRESHOLD:
            issues['large_configmaps'].append({
                'namespace': namespace,
                'name': name,
                'size_bytes': size,
                'size_kb': round(size_kb, 2)
            })

        # Check if unused
        if cm_key not in cm_references:
            # Skip known system ConfigMaps
            if not (name.endswith('-lock') or
                    name.startswith('extension-apiserver-authentication') or
                    name.startswith('cluster-info') or
                    name.startswith('coredns') or
                    name.startswith('kubeadm-config') or
                    name.startswith('kubelet-config')):
                issues['unused'].append({
                    'namespace': namespace,
                    'name': name,
                    'size_bytes': size
                })

        # Check for missing keys
        if cm_key in key_references:
            cm_data = cm.get('data', {})
            cm_binary_data = cm.get('binaryData', {})
            all_keys = set(cm_data.keys()) | set(cm_binary_data.keys())

            missing = key_references[cm_key] - all_keys
            if missing:
                issues['missing_keys'].append({
                    'namespace': namespace,
                    'name': name,
                    'missing_keys': list(missing),
                    'available_keys': list(all_keys)
                })

        # Check for ConfigMaps in default namespace
        if namespace == 'default' and not name.startswith('kube-'):
            issues['default_namespace'].append({
                'namespace': namespace,
                'name': name
            })

        # Check for empty ConfigMaps
        data = cm.get('data', {})
        binary_data = cm.get('binaryData', {})
        if not data and not binary_data:
            issues['empty'].append({
                'namespace': namespace,
                'name': name
            })

    return issues


def format_output_plain(issues, warn_only=False):
    """Format output as plain text."""
    output = []
    has_issues = False

    if not warn_only:
        output.append("ConfigMap Audit Report")
        output.append("=" * 80)
        output.append("")

    # Critical: Approaching size limit
    if issues['approaching_limit']:
        has_issues = True
        output.append("CRITICAL: ConfigMaps approaching size limit (>80% of 1MB):")
        output.append("-" * 80)
        for cm in sorted(issues['approaching_limit'],
                        key=lambda x: x['size_bytes'], reverse=True):
            output.append(f"  {cm['namespace']}/{cm['name']}")
            output.append(f"    Size: {cm['size_kb']}KB ({cm['percent_of_limit']}% of limit)")
        output.append("")

    # Warning: Large ConfigMaps
    if issues['large_configmaps']:
        has_issues = True
        output.append("WARNING: Large ConfigMaps (>100KB, may impact etcd performance):")
        output.append("-" * 80)
        for cm in sorted(issues['large_configmaps'],
                        key=lambda x: x['size_bytes'], reverse=True):
            output.append(f"  {cm['namespace']}/{cm['name']}: {cm['size_kb']}KB")
        output.append("")

    # Warning: Missing keys
    if issues['missing_keys']:
        has_issues = True
        output.append("WARNING: ConfigMaps with missing keys referenced by pods:")
        output.append("-" * 80)
        for cm in issues['missing_keys']:
            output.append(f"  {cm['namespace']}/{cm['name']}")
            output.append(f"    Missing keys: {', '.join(cm['missing_keys'])}")
            output.append(f"    Available keys: {', '.join(cm['available_keys']) or '(none)'}")
        output.append("")

    # Info: Unused ConfigMaps
    if issues['unused'] and not warn_only:
        output.append("INFO: Potentially unused ConfigMaps (not referenced by any pod):")
        output.append("-" * 80)
        for cm in issues['unused'][:20]:  # Limit to top 20
            size_kb = cm['size_bytes'] / 1024
            output.append(f"  {cm['namespace']}/{cm['name']} ({size_kb:.1f}KB)")
        if len(issues['unused']) > 20:
            output.append(f"  ... and {len(issues['unused']) - 20} more")
        output.append("")

    # Info: Empty ConfigMaps
    if issues['empty'] and not warn_only:
        output.append("INFO: Empty ConfigMaps:")
        output.append("-" * 80)
        for cm in issues['empty'][:10]:
            output.append(f"  {cm['namespace']}/{cm['name']}")
        if len(issues['empty']) > 10:
            output.append(f"  ... and {len(issues['empty']) - 10} more")
        output.append("")

    # Info: ConfigMaps in default namespace
    if issues['default_namespace'] and not warn_only:
        output.append("INFO: ConfigMaps in 'default' namespace (consider organizing):")
        output.append("-" * 80)
        for cm in issues['default_namespace'][:10]:
            output.append(f"  {cm['name']}")
        if len(issues['default_namespace']) > 10:
            output.append(f"  ... and {len(issues['default_namespace']) - 10} more")
        output.append("")

    # Summary
    if not warn_only:
        output.append("Summary:")
        output.append("-" * 80)
        output.append(f"  Approaching limit: {len(issues['approaching_limit'])}")
        output.append(f"  Large (>100KB): {len(issues['large_configmaps'])}")
        output.append(f"  Missing keys: {len(issues['missing_keys'])}")
        output.append(f"  Potentially unused: {len(issues['unused'])}")
        output.append(f"  Empty: {len(issues['empty'])}")
        output.append(f"  In default namespace: {len(issues['default_namespace'])}")

    if not has_issues and not issues['unused'] and not issues['empty']:
        output.append("No ConfigMap issues detected.")

    return "\n".join(output)


def format_output_json(issues):
    """Format output as JSON."""
    return json.dumps(issues, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all ConfigMaps
  %(prog)s

  # Audit ConfigMaps in specific namespace
  %(prog)s -n production

  # Show only warnings (size limits, missing keys)
  %(prog)s --warn-only

  # Output as JSON for monitoring integration
  %(prog)s --format json

  # Include verbose output (show system ConfigMaps)
  %(prog)s --verbose

Exit codes:
  0 - No issues found
  1 - Issues detected (warnings)
  2 - Usage error or kubectl not available
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Audit ConfigMaps in specific namespace (default: all namespaces)'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Include system namespaces in audit'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings (size limits, missing keys)'
    )

    args = parser.parse_args()

    # Get ConfigMaps and pods
    configmaps = get_configmaps(args.namespace)
    pods = get_pods(args.namespace)

    if not configmaps:
        print("No ConfigMaps found.")
        sys.exit(0)

    # Audit ConfigMaps
    issues = audit_configmaps(configmaps, pods, verbose=args.verbose)

    # Format and print output
    if args.format == 'json':
        print(format_output_json(issues))
    else:
        print(format_output_plain(issues, warn_only=args.warn_only))

    # Exit with appropriate code
    critical_issues = (
        issues['approaching_limit'] or
        issues['missing_keys']
    )

    if critical_issues:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
