#!/usr/bin/env python3
"""
Kubernetes version skew checker - Detect version compatibility issues in clusters.

Validates Kubernetes version skew policy compliance:
- kubelet can be at most 3 minor versions behind kube-apiserver (N-3)
- kube-controller-manager, kube-scheduler can be at most 1 minor version behind (N-1)
- kubectl can be 1 minor version ahead or behind kube-apiserver (N+1 to N-1)

This is critical for:
- Cluster upgrade planning
- Identifying nodes that need updates
- Ensuring supportability and stability

Exit codes:
    0 - All components within version skew policy
    1 - Version skew violations detected
    2 - Usage error or missing dependency
"""

import argparse
import sys
import subprocess
import json
import re


def run_kubectl(args):
    """Execute kubectl command and return output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            return None, result.stderr
        return result.stdout, None
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        return None, "kubectl command timed out"


def parse_version(version_str):
    """Parse Kubernetes version string into components.

    Returns tuple: (major, minor, patch) or None if parsing fails.
    Handles formats like: v1.28.0, 1.28.0, v1.28.0-gke.1, v1.28.0+k3s1
    """
    if not version_str:
        return None

    # Clean up the version string
    version_str = version_str.strip()

    # Match version pattern
    match = re.match(r'v?(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))

    return None


def version_to_str(version_tuple):
    """Convert version tuple to string."""
    if version_tuple is None:
        return "unknown"
    return f"v{version_tuple[0]}.{version_tuple[1]}.{version_tuple[2]}"


def minor_version_diff(v1, v2):
    """Calculate minor version difference between two versions.

    Returns positive if v1 > v2, negative if v1 < v2.
    """
    if v1 is None or v2 is None:
        return None
    return v1[1] - v2[1]


def get_api_server_version():
    """Get the kube-apiserver version."""
    output, err = run_kubectl(['version', '-o', 'json'])
    if output is None:
        return None, err

    try:
        data = json.loads(output)
        server_version = data.get('serverVersion', {})
        version_str = f"{server_version.get('major', '0')}.{server_version.get('minor', '0').rstrip('+')}.0"
        # Also try gitVersion which is more complete
        git_version = server_version.get('gitVersion', '')
        if git_version:
            parsed = parse_version(git_version)
            if parsed:
                return parsed, None
        return parse_version(version_str), None
    except json.JSONDecodeError as e:
        return None, f"Failed to parse version JSON: {e}"


def get_node_versions():
    """Get kubelet versions for all nodes."""
    output, err = run_kubectl(['get', 'nodes', '-o', 'json'])
    if output is None:
        return None, err

    try:
        data = json.loads(output)
        nodes = []
        for node in data.get('items', []):
            name = node.get('metadata', {}).get('name', 'unknown')
            kubelet_version = node.get('status', {}).get('nodeInfo', {}).get('kubeletVersion', '')

            # Check if node is ready
            conditions = node.get('status', {}).get('conditions', [])
            is_ready = any(
                c.get('type') == 'Ready' and c.get('status') == 'True'
                for c in conditions
            )

            nodes.append({
                'name': name,
                'kubelet_version': kubelet_version,
                'kubelet_parsed': parse_version(kubelet_version),
                'is_ready': is_ready
            })
        return nodes, None
    except json.JSONDecodeError as e:
        return None, f"Failed to parse nodes JSON: {e}"


def get_control_plane_component_versions():
    """Get versions of control plane components from pods."""
    output, err = run_kubectl([
        'get', 'pods', '-n', 'kube-system',
        '-l', 'tier=control-plane',
        '-o', 'json'
    ])

    components = {}

    if output is None:
        # Try alternative: look for specific component pods
        for component in ['kube-controller-manager', 'kube-scheduler', 'etcd']:
            pod_output, pod_err = run_kubectl([
                'get', 'pods', '-n', 'kube-system',
                '-l', f'component={component}',
                '-o', 'json'
            ])
            if pod_output:
                try:
                    data = json.loads(pod_output)
                    for pod in data.get('items', []):
                        extract_component_version(pod, components)
                except json.JSONDecodeError:
                    pass
        return components if components else None, err

    try:
        data = json.loads(output)
        for pod in data.get('items', []):
            extract_component_version(pod, components)
        return components, None
    except json.JSONDecodeError as e:
        return None, f"Failed to parse pods JSON: {e}"


def extract_component_version(pod, components):
    """Extract version from pod spec."""
    labels = pod.get('metadata', {}).get('labels', {})
    component = labels.get('component', '')

    containers = pod.get('spec', {}).get('containers', [])
    for container in containers:
        image = container.get('image', '')
        # Extract version from image tag
        if ':' in image:
            tag = image.split(':')[-1]
            version = parse_version(tag)
            if version and component:
                components[component] = {
                    'version': version,
                    'version_str': tag,
                    'image': image
                }


def check_version_skew(api_version, nodes, components, verbose=False):
    """Check version skew compliance.

    Returns list of issues found.
    """
    issues = []

    if api_version is None:
        issues.append({
            'severity': 'ERROR',
            'component': 'kube-apiserver',
            'message': 'Unable to determine API server version'
        })
        return issues

    # Check kubelet versions (allowed: N-3 to N)
    for node in nodes:
        kubelet_v = node['kubelet_parsed']
        if kubelet_v is None:
            issues.append({
                'severity': 'WARNING',
                'component': f"node/{node['name']}",
                'message': f"Unable to parse kubelet version: {node['kubelet_version']}"
            })
            continue

        diff = minor_version_diff(api_version, kubelet_v)

        if diff is not None:
            if diff > 3:
                issues.append({
                    'severity': 'CRITICAL',
                    'component': f"node/{node['name']}",
                    'message': f"Kubelet {version_to_str(kubelet_v)} is {diff} minor versions behind API server {version_to_str(api_version)} (max allowed: 3)",
                    'node': node['name'],
                    'kubelet_version': node['kubelet_version'],
                    'api_version': version_to_str(api_version),
                    'skew': diff
                })
            elif diff < 0:
                issues.append({
                    'severity': 'WARNING',
                    'component': f"node/{node['name']}",
                    'message': f"Kubelet {version_to_str(kubelet_v)} is ahead of API server {version_to_str(api_version)}",
                    'node': node['name'],
                    'kubelet_version': node['kubelet_version'],
                    'api_version': version_to_str(api_version),
                    'skew': diff
                })
            elif verbose and diff > 0:
                issues.append({
                    'severity': 'INFO',
                    'component': f"node/{node['name']}",
                    'message': f"Kubelet {version_to_str(kubelet_v)} is {diff} minor version(s) behind API server (within policy)",
                    'node': node['name'],
                    'kubelet_version': node['kubelet_version'],
                    'api_version': version_to_str(api_version),
                    'skew': diff
                })

    # Check control plane components (allowed: N-1 to N)
    for component_name in ['kube-controller-manager', 'kube-scheduler']:
        if component_name in components:
            comp = components[component_name]
            comp_v = comp['version']
            diff = minor_version_diff(api_version, comp_v)

            if diff is not None and diff > 1:
                issues.append({
                    'severity': 'CRITICAL',
                    'component': component_name,
                    'message': f"{component_name} {version_to_str(comp_v)} is {diff} minor versions behind API server {version_to_str(api_version)} (max allowed: 1)",
                    'component_version': comp['version_str'],
                    'api_version': version_to_str(api_version),
                    'skew': diff
                })

    return issues


def print_plain(api_version, nodes, components, issues, warn_only=False):
    """Print results in plain format."""
    if not warn_only:
        print(f"API Server: {version_to_str(api_version)}")
        print()
        print("Node Versions:")
        for node in nodes:
            ready_str = "Ready" if node['is_ready'] else "NotReady"
            print(f"  {node['name']} kubelet={node['kubelet_version']} ({ready_str})")

        if components:
            print()
            print("Control Plane Components:")
            for name, comp in sorted(components.items()):
                print(f"  {name}: {comp['version_str']}")

        print()

    if issues:
        filtered = [i for i in issues if i['severity'] in ('CRITICAL', 'WARNING')] if warn_only else issues
        if filtered:
            print("Version Skew Issues:")
            for issue in filtered:
                print(f"  [{issue['severity']}] {issue['component']}: {issue['message']}")
    elif not warn_only:
        print("No version skew issues detected")


def print_table(api_version, nodes, components, issues, warn_only=False):
    """Print results in table format."""
    if not warn_only:
        print(f"API Server Version: {version_to_str(api_version)}")
        print()

        print(f"{'Node':<40} {'Kubelet Version':<20} {'Skew':<8} {'Status':<10}")
        print("-" * 80)

        for node in nodes:
            kubelet_v = node['kubelet_parsed']
            diff = minor_version_diff(api_version, kubelet_v) if api_version and kubelet_v else None
            skew_str = f"N-{diff}" if diff is not None and diff >= 0 else f"N+{abs(diff)}" if diff is not None else "?"
            ready_str = "Ready" if node['is_ready'] else "NotReady"
            print(f"{node['name']:<40} {node['kubelet_version']:<20} {skew_str:<8} {ready_str:<10}")

        print()

    if issues:
        filtered = [i for i in issues if i['severity'] in ('CRITICAL', 'WARNING')] if warn_only else issues
        if filtered:
            print(f"{'Severity':<10} {'Component':<30} {'Message':<40}")
            print("-" * 80)
            for issue in filtered:
                print(f"{issue['severity']:<10} {issue['component']:<30} {issue['message'][:40]}")
    elif not warn_only:
        print("All components within version skew policy")


def print_json(api_version, nodes, components, issues, warn_only=False):
    """Print results in JSON format."""
    result = {
        'api_server_version': version_to_str(api_version),
        'nodes': [
            {
                'name': n['name'],
                'kubelet_version': n['kubelet_version'],
                'is_ready': n['is_ready'],
                'skew': minor_version_diff(api_version, n['kubelet_parsed']) if api_version and n['kubelet_parsed'] else None
            }
            for n in nodes
        ],
        'control_plane_components': {
            name: {'version': comp['version_str']}
            for name, comp in components.items()
        } if components else {},
        'issues': [i for i in issues if i['severity'] in ('CRITICAL', 'WARNING')] if warn_only else issues,
        'compliant': len([i for i in issues if i['severity'] in ('CRITICAL', 'WARNING')]) == 0
    }
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Check Kubernetes cluster version skew compliance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Version Skew Policy:
  - kubelet: can be at most 3 minor versions behind kube-apiserver (N-3)
  - kube-controller-manager, kube-scheduler: at most 1 version behind (N-1)
  - kubectl: can be 1 minor version ahead or behind (N+1 to N-1)

Examples:
  %(prog)s                    # Check all version skew
  %(prog)s --format json      # Output in JSON format
  %(prog)s --warn-only        # Only show issues
"""
    )
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and issues"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including compliant nodes"
    )

    args = parser.parse_args()

    # Get API server version
    api_version, err = get_api_server_version()
    if err and api_version is None:
        print(f"Error: Failed to get API server version: {err}", file=sys.stderr)
        sys.exit(1)

    # Get node versions
    nodes, err = get_node_versions()
    if err and nodes is None:
        print(f"Error: Failed to get node versions: {err}", file=sys.stderr)
        sys.exit(1)
    nodes = nodes or []

    # Get control plane component versions (best effort)
    components, _ = get_control_plane_component_versions()
    components = components or {}

    # Check version skew
    issues = check_version_skew(api_version, nodes, components, args.verbose)

    # Output
    if args.format == "json":
        print_json(api_version, nodes, components, issues, args.warn_only)
    elif args.format == "table":
        print_table(api_version, nodes, components, issues, args.warn_only)
    else:
        print_plain(api_version, nodes, components, issues, args.warn_only)

    # Exit code based on issues
    has_critical = any(i['severity'] in ('CRITICAL', 'WARNING') for i in issues)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
