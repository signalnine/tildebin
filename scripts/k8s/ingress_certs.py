#!/usr/bin/env python3
# boxctl:
#   category: k8s/networking
#   tags: [ingress, certificates, tls, kubernetes, security]
#   requires: [kubectl]
#   privilege: user
#   brief: Check Ingress TLS certificates and health status
#   related: [ingress_health]

"""
Kubernetes Ingress certificate checker - Monitor TLS certificates and ingress health.

Monitors Ingress resources checking:
- TLS certificate expiration dates and warnings
- Ingress backend service status and health
- Load balancer IP/hostname assignment
- Missing or invalid TLS secrets
- Service endpoint availability

Exit codes:
    0 - All ingresses healthy and certificates valid
    1 - Certificate warnings/expiration or ingress issues detected
    2 - Usage error or kubectl not available
"""

import argparse
import base64
import json
import subprocess
import tempfile
import os
from datetime import datetime

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_certificate_expiry(cert_data: str, context: Context) -> datetime | None:
    """Parse certificate and extract expiry date."""
    try:
        # cert_data is typically in PEM format
        if isinstance(cert_data, str):
            cert_bytes = cert_data.encode()
        else:
            cert_bytes = cert_data

        # Write to temp file for openssl
        with tempfile.NamedTemporaryFile(mode="w+b", delete=False) as f:
            f.write(cert_bytes)
            temp_path = f.name

        try:
            # Use openssl to extract expiry
            result = context.run(
                ["openssl", "x509", "-in", temp_path, "-noout", "-enddate"]
            )

            if result.returncode == 0:
                # Output format: notAfter=Nov 20 10:30:00 2025 GMT
                output = result.stdout.strip()
                if output.startswith("notAfter="):
                    date_str = output.replace("notAfter=", "")
                    # Parse the date
                    expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                    return expiry
        finally:
            os.unlink(temp_path)
    except Exception:
        pass

    return None


def check_ingress_tls(
    ingress: dict, context: Context, namespace: str
) -> tuple[list, list]:
    """Check TLS configuration and certificate expiry."""
    issues = []
    cert_info = []

    spec = ingress.get("spec", {})
    tls_configs = spec.get("tls", [])

    if not tls_configs:
        # Check if ingress should have TLS
        rules = spec.get("rules", [])
        if rules:
            issues.append("No TLS configuration found (unencrypted ingress)")
        return issues, cert_info

    for tls_config in tls_configs:
        hosts = tls_config.get("hosts", [])
        secret_name = tls_config.get("secretName")

        if not secret_name:
            issues.append(
                f"TLS config missing secretName for hosts: {', '.join(hosts)}"
            )
            continue

        # Get the secret
        try:
            result = context.run(
                ["kubectl", "get", "secret", secret_name, "-n", namespace, "-o", "json"]
            )
            if result.returncode != 0:
                issues.append(
                    f"TLS secret '{secret_name}' not found in namespace '{namespace}'"
                )
                continue
            secret = json.loads(result.stdout)
        except Exception:
            issues.append(
                f"TLS secret '{secret_name}' not found in namespace '{namespace}'"
            )
            continue

        # Extract certificate
        secret_data = secret.get("data", {})
        tls_crt = secret_data.get("tls.crt")

        if not tls_crt:
            issues.append(f"TLS secret '{secret_name}' missing tls.crt data")
            continue

        # Decode and check expiry
        try:
            cert_pem = base64.b64decode(tls_crt).decode()
            expiry = parse_certificate_expiry(cert_pem, context)

            if expiry:
                now = datetime.utcnow()
                days_remaining = (expiry - now).days

                cert_info.append(
                    {
                        "secret": secret_name,
                        "hosts": hosts,
                        "expires": expiry.isoformat(),
                        "days_remaining": days_remaining,
                    }
                )

                if days_remaining < 0:
                    issues.append(
                        f"Certificate in '{secret_name}' EXPIRED {abs(days_remaining)} days ago"
                    )
                elif days_remaining < 7:
                    issues.append(
                        f"Certificate in '{secret_name}' expires in {days_remaining} days"
                    )
                elif days_remaining < 30:
                    issues.append(
                        f"Certificate in '{secret_name}' expires in {days_remaining} days (warning)"
                    )
        except Exception as e:
            issues.append(f"Failed to parse certificate in '{secret_name}': {str(e)}")

    return issues, cert_info


def check_ingress_status(ingress: dict) -> list:
    """Check ingress status and load balancer assignment."""
    issues = []

    status = ingress.get("status", {})
    load_balancer = status.get("loadBalancer", {})
    ingress_ips = load_balancer.get("ingress", [])

    if not ingress_ips:
        issues.append("Load balancer has no assigned IP/hostname")
    else:
        for ingress_ip in ingress_ips:
            ip = ingress_ip.get("ip", "")
            hostname = ingress_ip.get("hostname", "")
            if not ip and not hostname:
                issues.append("Load balancer ingress entry has no IP or hostname")

    return issues


def check_ingress_backends(ingress: dict, context: Context, namespace: str) -> list:
    """Check if ingress backend services exist and have endpoints."""
    issues = []
    spec = ingress.get("spec", {})
    rules = spec.get("rules", [])

    backend_checks = set()

    for rule in rules:
        rule_http = rule.get("http", {})
        paths = rule_http.get("paths", [])

        for path in paths:
            backend = path.get("backend", {})

            # Handle both old and new API formats
            service_name = backend.get("serviceName") or backend.get("service", {}).get(
                "name"
            )

            if service_name and (namespace, service_name) not in backend_checks:
                backend_checks.add((namespace, service_name))

                # Check if service has endpoints
                try:
                    result = context.run(
                        [
                            "kubectl",
                            "get",
                            "endpoints",
                            service_name,
                            "-n",
                            namespace,
                            "-o",
                            "json",
                        ]
                    )
                    if result.returncode != 0:
                        issues.append(
                            f"Backend service '{service_name}' has no endpoints"
                        )
                        continue
                    endpoints = json.loads(result.stdout)
                    subsets = endpoints.get("subsets", [])
                    has_addresses = False
                    for subset in subsets:
                        if subset.get("addresses"):
                            has_addresses = True
                            break
                    if not has_addresses:
                        issues.append(
                            f"Backend service '{service_name}' has no endpoints"
                        )
                except Exception:
                    issues.append(f"Backend service '{service_name}' has no endpoints")

    return issues


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
        description="Check Kubernetes Ingress certificates and health status"
    )
    parser.add_argument(
        "-n",
        "--namespace",
        help="Namespace to check (default: all namespaces)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show ingresses with warnings or issues",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get ingresses
    cmd = ["kubectl", "get", "ingress", "-o", "json"]
    if opts.namespace:
        cmd.extend(["-n", opts.namespace])
    else:
        cmd.append("--all-namespaces")

    try:
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        ingresses_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get ingresses: {e}")
        return 2

    ingresses = ingresses_data.get("items", [])
    results = []

    for ingress in ingresses:
        name = ingress["metadata"]["name"]
        namespace = ingress["metadata"].get("namespace", "default")

        # Check TLS and certificates
        tls_issues, cert_info = check_ingress_tls(ingress, context, namespace)

        # Check ingress status
        status_issues = check_ingress_status(ingress)

        # Check backend services
        backend_issues = check_ingress_backends(ingress, context, namespace)

        all_issues = tls_issues + status_issues + backend_issues

        # Skip if no issues and warn_only is set
        if opts.warn_only and not all_issues:
            continue

        ingress_info = {
            "namespace": namespace,
            "name": name,
            "issues": all_issues,
            "certificates": cert_info,
        }

        results.append(ingress_info)

    # Count statistics
    total_ingresses = len(results)
    ingresses_with_issues = sum(1 for r in results if r["issues"])

    # Output results
    if opts.format == "json":
        print(json.dumps(results, indent=2))
    else:  # plain format
        for ingress_info in results:
            namespace = ingress_info["namespace"]
            name = ingress_info["name"]
            issues = ingress_info["issues"]
            certs = ingress_info["certificates"]

            # Print ingress header
            status_marker = "[!]" if issues else "[+]"
            print(f"{status_marker} Ingress: {namespace}/{name}")

            # Print certificate information
            if certs:
                print("  Certificates:")
                for cert in certs:
                    secret = cert["secret"]
                    hosts = (
                        ", ".join(cert["hosts"]) if cert["hosts"] else "(no hosts)"
                    )
                    days = cert["days_remaining"]

                    if days < 0:
                        marker = "[X]"
                    elif days < 7:
                        marker = "[!]"
                    else:
                        marker = "[+]"

                    print(f"    {marker} {secret}: {hosts} ({days} days)")

            # Print issues
            if issues:
                print("  Issues:")
                for issue in issues:
                    print(f"    - {issue}")

            print()

        # Print summary
        print(
            f"Summary: {total_ingresses} ingresses analyzed, {ingresses_with_issues} with issues"
        )

    output.set_summary(
        f"ingresses={total_ingresses}, with_issues={ingresses_with_issues}"
    )

    # Return whether issues were found
    return 1 if ingresses_with_issues > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
