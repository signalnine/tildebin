#!/usr/bin/env python3
"""
Analyze ConfigMap and Secret sizes in Kubernetes clusters.

Identifies oversized ConfigMaps and Secrets that can cause:
- etcd performance degradation (etcd stores all objects)
- API server slowdowns during large object transfers
- Memory pressure on kubelet when mounting large volumes
- Hitting the 1MB Kubernetes object size limit

Useful for operators managing large-scale clusters where etcd health is critical.

Exit codes:
    0 - No oversized objects found
    1 - Oversized objects detected (above warning threshold)
    2 - Usage error or kubectl not available
"""

import argparse
import base64
import json
import subprocess
import sys


# Default thresholds in bytes
DEFAULT_WARN_THRESHOLD = 100 * 1024    # 100KB - consider optimizing
DEFAULT_CRIT_THRESHOLD = 500 * 1024    # 500KB - likely problematic
KUBERNETES_LIMIT = 1024 * 1024         # 1MB - hard limit


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


def get_configmaps(namespace=None):
    """Get all ConfigMaps in JSON format."""
    args = ['get', 'configmaps', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_secrets(namespace=None):
    """Get all Secrets in JSON format."""
    args = ['get', 'secrets', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def calculate_configmap_size(configmap):
    """Calculate the total size of a ConfigMap's data."""
    total_size = 0
    data = configmap.get('data', {})
    binary_data = configmap.get('binaryData', {})

    # Regular data (stored as strings)
    for key, value in data.items():
        if value:
            total_size += len(key.encode('utf-8'))
            total_size += len(value.encode('utf-8'))

    # Binary data (stored as base64)
    for key, value in binary_data.items():
        if value:
            total_size += len(key.encode('utf-8'))
            # Decode base64 to get actual size
            try:
                decoded = base64.b64decode(value)
                total_size += len(decoded)
            except Exception:
                total_size += len(value)

    return total_size


def calculate_secret_size(secret):
    """Calculate the total size of a Secret's data."""
    total_size = 0
    data = secret.get('data', {})
    string_data = secret.get('stringData', {})

    # Secret data is base64 encoded
    for key, value in data.items():
        if value:
            total_size += len(key.encode('utf-8'))
            try:
                decoded = base64.b64decode(value)
                total_size += len(decoded)
            except Exception:
                total_size += len(value)

    # String data (not encoded)
    for key, value in string_data.items():
        if value:
            total_size += len(key.encode('utf-8'))
            total_size += len(value.encode('utf-8'))

    return total_size


def get_key_sizes(obj, is_secret=False):
    """Get individual key sizes for detailed analysis."""
    key_sizes = []

    if is_secret:
        data = obj.get('data', {})
        for key, value in data.items():
            if value:
                try:
                    decoded = base64.b64decode(value)
                    size = len(decoded)
                except Exception:
                    size = len(value)
                key_sizes.append((key, size))

        string_data = obj.get('stringData', {})
        for key, value in string_data.items():
            if value:
                key_sizes.append((key, len(value.encode('utf-8'))))
    else:
        data = obj.get('data', {})
        for key, value in data.items():
            if value:
                key_sizes.append((key, len(value.encode('utf-8'))))

        binary_data = obj.get('binaryData', {})
        for key, value in binary_data.items():
            if value:
                try:
                    decoded = base64.b64decode(value)
                    size = len(decoded)
                except Exception:
                    size = len(value)
                key_sizes.append((key, size))

    return sorted(key_sizes, key=lambda x: x[1], reverse=True)


def format_size(size_bytes):
    """Format byte size in human-readable format."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f}MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f}KB"
    else:
        return f"{size_bytes}B"


def get_severity(size, warn_threshold, crit_threshold):
    """Determine severity based on size thresholds."""
    if size >= crit_threshold:
        return 'critical'
    elif size >= warn_threshold:
        return 'warning'
    return 'ok'


def analyze_objects(configmaps_data, secrets_data, warn_threshold, crit_threshold,
                    warn_only, verbose, skip_system):
    """Analyze all ConfigMaps and Secrets for size issues."""
    results = []

    # Analyze ConfigMaps
    for cm in configmaps_data.get('items', []):
        namespace = cm['metadata'].get('namespace', 'default')
        name = cm['metadata']['name']

        # Skip system namespaces if requested
        if skip_system and namespace.startswith('kube-'):
            continue

        size = calculate_configmap_size(cm)
        severity = get_severity(size, warn_threshold, crit_threshold)

        if warn_only and severity == 'ok':
            continue

        entry = {
            'type': 'ConfigMap',
            'namespace': namespace,
            'name': name,
            'size': size,
            'size_formatted': format_size(size),
            'severity': severity,
            'key_count': len(cm.get('data', {})) + len(cm.get('binaryData', {}))
        }

        if verbose and severity != 'ok':
            entry['keys'] = get_key_sizes(cm, is_secret=False)[:5]  # Top 5 largest keys

        results.append(entry)

    # Analyze Secrets
    for secret in secrets_data.get('items', []):
        namespace = secret['metadata'].get('namespace', 'default')
        name = secret['metadata']['name']
        secret_type = secret.get('type', 'Opaque')

        # Skip system namespaces if requested
        if skip_system and namespace.startswith('kube-'):
            continue

        # Skip service account tokens (managed by K8s)
        if secret_type == 'kubernetes.io/service-account-token':
            continue

        size = calculate_secret_size(secret)
        severity = get_severity(size, warn_threshold, crit_threshold)

        if warn_only and severity == 'ok':
            continue

        entry = {
            'type': 'Secret',
            'namespace': namespace,
            'name': name,
            'size': size,
            'size_formatted': format_size(size),
            'severity': severity,
            'secret_type': secret_type,
            'key_count': len(secret.get('data', {})) + len(secret.get('stringData', {}))
        }

        if verbose and severity != 'ok':
            # Only show key names, not values for secrets
            key_sizes = get_key_sizes(secret, is_secret=True)[:5]
            entry['keys'] = key_sizes

        results.append(entry)

    # Sort by size descending
    results.sort(key=lambda x: x['size'], reverse=True)
    return results


def print_plain(results, warn_threshold, crit_threshold, verbose):
    """Print results in plain text format."""
    if not results:
        print("No ConfigMaps or Secrets found matching criteria.")
        return

    # Print header
    print(f"ConfigMap/Secret Size Analysis")
    print(f"Warning threshold: {format_size(warn_threshold)}")
    print(f"Critical threshold: {format_size(crit_threshold)}")
    print(f"Kubernetes limit: {format_size(KUBERNETES_LIMIT)}")
    print("=" * 70)
    print()

    # Group by severity
    critical = [r for r in results if r['severity'] == 'critical']
    warning = [r for r in results if r['severity'] == 'warning']
    ok = [r for r in results if r['severity'] == 'ok']

    if critical:
        print("CRITICAL (consider immediate optimization):")
        print("-" * 50)
        for item in critical:
            marker = "!!"
            print(f"{marker} {item['type']}: {item['namespace']}/{item['name']}")
            print(f"   Size: {item['size_formatted']} ({item['key_count']} keys)")
            if verbose and 'keys' in item:
                print("   Largest keys:")
                for key, size in item['keys']:
                    print(f"     - {key}: {format_size(size)}")
            print()

    if warning:
        print("WARNING (should be optimized):")
        print("-" * 50)
        for item in warning:
            marker = "!"
            print(f"{marker}  {item['type']}: {item['namespace']}/{item['name']}")
            print(f"   Size: {item['size_formatted']} ({item['key_count']} keys)")
            if verbose and 'keys' in item:
                print("   Largest keys:")
                for key, size in item['keys']:
                    print(f"     - {key}: {format_size(size)}")
            print()

    if ok:
        print(f"OK ({len(ok)} objects below warning threshold)")
        if verbose:
            for item in ok[:10]:  # Show top 10 even if OK
                print(f"   {item['type']}: {item['namespace']}/{item['name']} - {item['size_formatted']}")
            if len(ok) > 10:
                print(f"   ... and {len(ok) - 10} more")
        print()

    # Summary
    print("=" * 70)
    print(f"Summary: {len(critical)} critical, {len(warning)} warning, {len(ok)} ok")

    total_size = sum(r['size'] for r in results)
    print(f"Total size analyzed: {format_size(total_size)}")


def print_json(results, warn_threshold, crit_threshold):
    """Print results in JSON format."""
    output = {
        'thresholds': {
            'warning_bytes': warn_threshold,
            'critical_bytes': crit_threshold,
            'kubernetes_limit_bytes': KUBERNETES_LIMIT
        },
        'summary': {
            'total_objects': len(results),
            'critical_count': len([r for r in results if r['severity'] == 'critical']),
            'warning_count': len([r for r in results if r['severity'] == 'warning']),
            'ok_count': len([r for r in results if r['severity'] == 'ok']),
            'total_size_bytes': sum(r['size'] for r in results)
        },
        'objects': results
    }
    print(json.dumps(output, indent=2))


def print_table(results, warn_threshold, crit_threshold):
    """Print results in table format."""
    if not results:
        print("No ConfigMaps or Secrets found matching criteria.")
        return

    # Header
    print(f"{'TYPE':<10} {'NAMESPACE':<20} {'NAME':<30} {'SIZE':>10} {'KEYS':>5} {'STATUS':<10}")
    print("-" * 90)

    for item in results:
        type_str = item['type'][:10]
        ns = item['namespace'][:20]
        name = item['name'][:30]
        size = item['size_formatted']
        keys = str(item['key_count'])
        status = item['severity'].upper()

        print(f"{type_str:<10} {ns:<20} {name:<30} {size:>10} {keys:>5} {status:<10}")

    # Summary line
    print("-" * 90)
    total = len(results)
    crit = len([r for r in results if r['severity'] == 'critical'])
    warn = len([r for r in results if r['severity'] == 'warning'])
    print(f"Total: {total} objects ({crit} critical, {warn} warning)")


def parse_size(size_str):
    """Parse size string like '100KB' or '1MB' into bytes."""
    size_str = size_str.strip().upper()
    if size_str.endswith('MB'):
        return int(float(size_str[:-2]) * 1024 * 1024)
    elif size_str.endswith('KB'):
        return int(float(size_str[:-2]) * 1024)
    elif size_str.endswith('B'):
        return int(size_str[:-1])
    else:
        return int(size_str)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze ConfigMap and Secret sizes in Kubernetes clusters',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Analyze all namespaces
  %(prog)s -n production             # Analyze specific namespace
  %(prog)s --warn-only               # Show only oversized objects
  %(prog)s --warn-threshold 50KB     # Custom warning threshold
  %(prog)s --format json             # JSON output for automation
  %(prog)s -v                        # Show largest keys in oversized objects

Thresholds:
  Default warning:  100KB (objects this size stress etcd)
  Default critical: 500KB (objects this size are problematic)
  Kubernetes limit: 1MB (hard limit, objects cannot exceed this)

Exit codes:
  0 - No objects above warning threshold
  1 - Objects found above warning threshold
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to analyze (default: all namespaces)'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show objects above warning threshold'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed information including largest keys'
    )

    parser.add_argument(
        '--warn-threshold',
        default='100KB',
        help='Warning threshold (default: 100KB). Examples: 50KB, 200KB, 1MB'
    )

    parser.add_argument(
        '--crit-threshold',
        default='500KB',
        help='Critical threshold (default: 500KB). Examples: 200KB, 500KB, 900KB'
    )

    parser.add_argument(
        '--skip-system',
        action='store_true',
        help='Skip kube-* system namespaces'
    )

    parser.add_argument(
        '--configmaps-only',
        action='store_true',
        help='Only analyze ConfigMaps'
    )

    parser.add_argument(
        '--secrets-only',
        action='store_true',
        help='Only analyze Secrets'
    )

    args = parser.parse_args()

    # Parse thresholds
    try:
        warn_threshold = parse_size(args.warn_threshold)
        crit_threshold = parse_size(args.crit_threshold)
    except ValueError as e:
        print(f"Error parsing threshold: {e}", file=sys.stderr)
        sys.exit(2)

    if warn_threshold >= crit_threshold:
        print("Error: Warning threshold must be less than critical threshold", file=sys.stderr)
        sys.exit(2)

    # Get data
    configmaps_data = {'items': []}
    secrets_data = {'items': []}

    if not args.secrets_only:
        configmaps_data = get_configmaps(args.namespace)

    if not args.configmaps_only:
        secrets_data = get_secrets(args.namespace)

    # Analyze
    results = analyze_objects(
        configmaps_data, secrets_data,
        warn_threshold, crit_threshold,
        args.warn_only, args.verbose, args.skip_system
    )

    # Output
    if args.format == 'json':
        print_json(results, warn_threshold, crit_threshold)
    elif args.format == 'table':
        print_table(results, warn_threshold, crit_threshold)
    else:
        print_plain(results, warn_threshold, crit_threshold, args.verbose)

    # Exit code based on findings
    has_issues = any(r['severity'] in ('warning', 'critical') for r in results)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
