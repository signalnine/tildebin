#!/usr/bin/env python3
"""
Check Kubernetes Ingress certificates and health status.

This script monitors Ingress resources in a Kubernetes cluster, checking:
- TLS certificate expiration dates and warnings
- Ingress backend service status and health
- Load balancer IP/hostname assignment
- Missing or invalid TLS secrets
- Service endpoint availability

Useful for preventing certificate-based outages and ensuring reliable ingress
routing in large-scale Kubernetes deployments.

Exit codes:
    0 - All ingresses healthy and certificates valid
    1 - Certificate warnings/expiration or ingress issues detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta
from collections import defaultdict


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


def get_all_ingresses(namespace=None):
    """Get all ingresses in JSON format."""
    args = ['get', 'ingress', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_secret(namespace, secret_name):
    """Get a secret from a namespace."""
    try:
        output = run_kubectl(['get', 'secret', secret_name, '-n', namespace, '-o', 'json'])
        return json.loads(output)
    except subprocess.CalledProcessError:
        return None


def get_service_endpoints(namespace, service_name):
    """Check if a service has endpoints."""
    try:
        output = run_kubectl(['get', 'endpoints', service_name, '-n', namespace, '-o', 'json'])
        endpoints = json.loads(output)
        subsets = endpoints.get('subsets', [])
        if not subsets:
            return False

        # Check if there are actual addresses
        for subset in subsets:
            if subset.get('addresses'):
                return True
        return False
    except subprocess.CalledProcessError:
        return False


def parse_certificate_expiry(cert_data):
    """Parse certificate and extract expiry date."""
    import base64
    import ssl
    import tempfile

    try:
        # cert_data is typically in PEM format
        if isinstance(cert_data, str):
            cert_bytes = cert_data.encode()
        else:
            cert_bytes = cert_data

        # Write to temp file for openssl
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as f:
            f.write(cert_bytes)
            temp_path = f.name

        try:
            # Use openssl to extract expiry
            result = subprocess.run(
                ['openssl', 'x509', '-in', temp_path, '-noout', '-enddate'],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                # Output format: notAfter=Nov 20 10:30:00 2025 GMT
                output = result.stdout.strip()
                if output.startswith('notAfter='):
                    date_str = output.replace('notAfter=', '')
                    # Parse the date
                    expiry = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
                    return expiry
        finally:
            import os
            os.unlink(temp_path)
    except Exception:
        pass

    return None


def check_ingress_tls(ingress):
    """Check TLS configuration and certificate expiry."""
    issues = []
    cert_info = []

    spec = ingress.get('spec', {})
    tls_configs = spec.get('tls', [])

    if not tls_configs:
        # Check if ingress should have TLS
        rules = spec.get('rules', [])
        if rules:
            issues.append("No TLS configuration found (unencrypted ingress)")
        return issues, cert_info

    namespace = ingress['metadata'].get('namespace', 'default')

    for tls_config in tls_configs:
        hosts = tls_config.get('hosts', [])
        secret_name = tls_config.get('secretName')

        if not secret_name:
            issues.append(f"TLS config missing secretName for hosts: {', '.join(hosts)}")
            continue

        # Get the secret
        secret = get_secret(namespace, secret_name)
        if not secret:
            issues.append(f"TLS secret '{secret_name}' not found in namespace '{namespace}'")
            continue

        # Extract certificate
        secret_data = secret.get('data', {})
        tls_crt = secret_data.get('tls.crt')

        if not tls_crt:
            issues.append(f"TLS secret '{secret_name}' missing tls.crt data")
            continue

        # Decode and check expiry
        import base64
        try:
            cert_pem = base64.b64decode(tls_crt).decode()
            expiry = parse_certificate_expiry(cert_pem)

            if expiry:
                now = datetime.utcnow()
                days_remaining = (expiry - now).days

                cert_info.append({
                    'secret': secret_name,
                    'hosts': hosts,
                    'expires': expiry.isoformat(),
                    'days_remaining': days_remaining
                })

                if days_remaining < 0:
                    issues.append(f"Certificate in '{secret_name}' EXPIRED {abs(days_remaining)} days ago")
                elif days_remaining < 7:
                    issues.append(f"Certificate in '{secret_name}' expires in {days_remaining} days")
                elif days_remaining < 30:
                    issues.append(f"Certificate in '{secret_name}' expires in {days_remaining} days (warning)")
        except Exception as e:
            issues.append(f"Failed to parse certificate in '{secret_name}': {str(e)}")

    return issues, cert_info


def check_ingress_status(ingress):
    """Check ingress status and load balancer assignment."""
    issues = []

    status = ingress.get('status', {})
    load_balancer = status.get('loadBalancer', {})
    ingress_ips = load_balancer.get('ingress', [])

    if not ingress_ips:
        issues.append("Load balancer has no assigned IP/hostname")
    else:
        for ingress_ip in ingress_ips:
            ip = ingress_ip.get('ip', '')
            hostname = ingress_ip.get('hostname', '')
            if not ip and not hostname:
                issues.append("Load balancer ingress entry has no IP or hostname")

    return issues


def check_ingress_backends(ingress):
    """Check if ingress backend services exist and have endpoints."""
    issues = []
    namespace = ingress['metadata'].get('namespace', 'default')
    spec = ingress.get('spec', {})
    rules = spec.get('rules', [])

    backend_checks = set()

    for rule in rules:
        rule_http = rule.get('http', {})
        paths = rule_http.get('paths', [])

        for path in paths:
            backend = path.get('backend', {})

            # Handle both old and new API formats
            service_name = backend.get('serviceName') or backend.get('service', {}).get('name')

            if service_name and (namespace, service_name) not in backend_checks:
                backend_checks.add((namespace, service_name))

                if not get_service_endpoints(namespace, service_name):
                    issues.append(f"Backend service '{service_name}' has no endpoints")

    return issues


def analyze_ingresses(ingresses_data, warn_only):
    """Analyze all ingresses and return issues."""
    ingresses = ingresses_data.get('items', [])
    results = []

    for ingress in ingresses:
        name = ingress['metadata']['name']
        namespace = ingress['metadata'].get('namespace', 'default')

        ingress_key = f"{namespace}/{name}"

        # Check TLS and certificates
        tls_issues, cert_info = check_ingress_tls(ingress)

        # Check ingress status
        status_issues = check_ingress_status(ingress)

        # Check backend services
        backend_issues = check_ingress_backends(ingress)

        all_issues = tls_issues + status_issues + backend_issues

        # Skip if no issues and warn_only is set
        if warn_only and not all_issues:
            continue

        ingress_info = {
            'namespace': namespace,
            'name': name,
            'issues': all_issues,
            'certificates': cert_info
        }

        results.append(ingress_info)

    return results


def print_results(results, output_format):
    """Print analysis results in requested format."""
    if output_format == 'json':
        print(json.dumps(results, indent=2))
    else:  # plain format
        total_ingresses = len(results)
        ingresses_with_issues = sum(1 for r in results if r['issues'])

        for ingress_info in results:
            namespace = ingress_info['namespace']
            name = ingress_info['name']
            issues = ingress_info['issues']
            certs = ingress_info['certificates']

            # Print ingress header
            status_marker = "⚠" if issues else "✓"
            print(f"{status_marker} Ingress: {namespace}/{name}")

            # Print certificate information
            if certs:
                print("  Certificates:")
                for cert in certs:
                    secret = cert['secret']
                    hosts = ', '.join(cert['hosts']) if cert['hosts'] else '(no hosts)'
                    days = cert['days_remaining']

                    if days < 0:
                        marker = "✗"
                    elif days < 7:
                        marker = "!"
                    else:
                        marker = "✓"

                    print(f"    {marker} {secret}: {hosts} ({days} days)")

            # Print issues
            if issues:
                print("  Issues:")
                for issue in issues:
                    print(f"    - {issue}")

            print()

        # Print summary
        print(f"Summary: {total_ingresses} ingresses analyzed, {ingresses_with_issues} with issues")

    # Return whether issues were found
    return any(r['issues'] for r in results)


def main():
    parser = argparse.ArgumentParser(
        description='Check Kubernetes Ingress certificates and health status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all ingresses across all namespaces
  %(prog)s -n production            # Check ingresses in production namespace only
  %(prog)s --warn-only              # Show only ingresses with issues
  %(prog)s --format json            # JSON output
  %(prog)s -w -f json               # JSON output, only problematic ingresses

Exit codes:
  0 - All ingresses healthy, certificates valid
  1 - Certificate warnings/expiration or ingress issues found
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to check (default: all namespaces)'
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
        help='Only show ingresses with warnings or issues'
    )

    args = parser.parse_args()

    # Get ingress data
    ingresses_data = get_all_ingresses(args.namespace)

    # Analyze ingresses
    results = analyze_ingresses(ingresses_data, args.warn_only)

    # Print results
    has_issues = print_results(results, args.format)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
