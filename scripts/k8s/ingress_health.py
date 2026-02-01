#!/usr/bin/env python3
# boxctl:
#   category: k8s/networking
#   tags: [ingress, tls, certificate, health]
#   requires: [kubectl]
#   privilege: user
#   related: [service_endpoint_monitor, secret_audit]
#   brief: Check Kubernetes Ingress health and TLS certificates

"""
Check Kubernetes Ingress certificates and health status.

Monitors Ingress resources in a Kubernetes cluster, checking:
- TLS certificate configuration
- Load balancer IP/hostname assignment
- Missing or invalid TLS secrets
- Ingress backend service status

Exit codes:
    0 - All ingresses healthy
    1 - Ingress issues detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_ingresses(context: Context, namespace: str | None = None) -> dict[str, Any]:
    """Get all ingresses in JSON format."""
    cmd = ["kubectl", "get", "ingress", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    return json.loads(result.stdout)


def get_secret(context: Context, namespace: str, secret_name: str) -> dict[str, Any] | None:
    """Get a secret from a namespace."""
    try:
        result = context.run(
            ["kubectl", "get", "secret", secret_name, "-n", namespace, "-o", "json"],
            check=False
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


def get_service_endpoints(context: Context, namespace: str, service_name: str) -> bool:
    """Check if a service has endpoints."""
    try:
        result = context.run(
            ["kubectl", "get", "endpoints", service_name, "-n", namespace, "-o", "json"],
            check=False
        )
        if result.returncode != 0:
            return False
        endpoints = json.loads(result.stdout)
        subsets = endpoints.get("subsets", [])
        if not subsets:
            return False

        for subset in subsets:
            if subset.get("addresses"):
                return True
        return False
    except Exception:
        return False


def check_ingress_tls(ingress: dict[str, Any], context: Context) -> tuple[list[str], list[dict[str, Any]]]:
    """Check TLS configuration."""
    issues = []
    cert_info = []

    spec = ingress.get("spec", {})
    tls_configs = spec.get("tls", [])
    namespace = ingress["metadata"].get("namespace", "default")

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
            issues.append(f"TLS config missing secretName for hosts: {', '.join(hosts)}")
            continue

        # Get the secret
        secret = get_secret(context, namespace, secret_name)
        if not secret:
            issues.append(f"TLS secret '{secret_name}' not found in namespace '{namespace}'")
            continue

        # Check secret has required data
        secret_data = secret.get("data", {})
        if "tls.crt" not in secret_data:
            issues.append(f"TLS secret '{secret_name}' missing tls.crt data")
            continue

        if "tls.key" not in secret_data:
            issues.append(f"TLS secret '{secret_name}' missing tls.key data")

        cert_info.append({
            "secret": secret_name,
            "hosts": hosts,
            "valid": True,
        })

    return issues, cert_info


def check_ingress_status(ingress: dict[str, Any]) -> list[str]:
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


def check_ingress_backends(ingress: dict[str, Any], context: Context) -> list[str]:
    """Check if ingress backend services exist and have endpoints."""
    issues = []
    namespace = ingress["metadata"].get("namespace", "default")
    spec = ingress.get("spec", {})
    rules = spec.get("rules", [])

    backend_checks = set()

    for rule in rules:
        rule_http = rule.get("http", {})
        paths = rule_http.get("paths", [])

        for path in paths:
            backend = path.get("backend", {})

            # Handle both old and new API formats
            service_name = backend.get("serviceName") or backend.get("service", {}).get("name")

            if service_name and (namespace, service_name) not in backend_checks:
                backend_checks.add((namespace, service_name))

                if not get_service_endpoints(context, namespace, service_name):
                    issues.append(f"Backend service '{service_name}' has no endpoints")

    return issues


def analyze_ingresses(
    ingresses_data: dict[str, Any],
    context: Context,
    warn_only: bool
) -> list[dict[str, Any]]:
    """Analyze all ingresses and return results."""
    ingresses = ingresses_data.get("items", [])
    results = []

    for ingress in ingresses:
        name = ingress["metadata"]["name"]
        namespace = ingress["metadata"].get("namespace", "default")

        # Check TLS
        tls_issues, cert_info = check_ingress_tls(ingress, context)

        # Check ingress status
        status_issues = check_ingress_status(ingress)

        # Check backend services
        backend_issues = check_ingress_backends(ingress, context)

        all_issues = tls_issues + status_issues + backend_issues

        # Skip if no issues and warn_only is set
        if warn_only and not all_issues:
            continue

        results.append({
            "namespace": namespace,
            "name": name,
            "issues": all_issues,
            "certificates": cert_info,
            "healthy": len(all_issues) == 0,
        })

    return results


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Check Kubernetes Ingress health and TLS certificates"
    )
    parser.add_argument("-n", "--namespace", help="Namespace to check (default: all)")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show issues")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl to use this script.")
        return 2

    try:
        ingresses_data = get_ingresses(context, opts.namespace)
    except Exception as e:
        output.error(f"Failed to get ingresses: {e}")
        return 2

    results = analyze_ingresses(ingresses_data, context, opts.warn_only)

    total_ingresses = len(results)
    ingresses_with_issues = sum(1 for r in results if r["issues"])
    healthy_count = total_ingresses - ingresses_with_issues

    output.emit({
        "ingresses": results,
        "summary": {
            "total": total_ingresses,
            "healthy": healthy_count,
            "with_issues": ingresses_with_issues,
        }
    })

    if ingresses_with_issues == 0:
        output.set_summary(f"{total_ingresses} ingresses healthy")
    else:
        output.set_summary(f"{ingresses_with_issues}/{total_ingresses} with issues")

    has_issues = any(r["issues"] for r in results)
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
