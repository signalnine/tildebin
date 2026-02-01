#!/usr/bin/env python3
# boxctl:
#   category: k8s/security
#   tags: [secret, tls, certificate, expiry, audit]
#   requires: [kubectl]
#   privilege: user
#   related: [configmap_audit, ingress_health]
#   brief: Monitor Kubernetes Secret age and TLS certificate expiration

"""
Monitor Kubernetes Secret age and TLS certificate expiration.

Analyzes Kubernetes secrets for:
- TLS certificate expiration dates (kubernetes.io/tls secrets)
- Stale secrets that haven't been updated in a long time
- Secrets approaching expiration thresholds
- Missing TLS data in kubernetes.io/tls secrets

Exit codes:
    0 - All secrets healthy
    1 - Expiring/expired secrets or issues detected
    2 - Usage error or kubectl not available
"""

import argparse
import base64
import json
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_secrets(context: Context, namespace: str | None = None) -> list[dict[str, Any]]:
    """Get all secrets in JSON format."""
    cmd = ["kubectl", "get", "secrets", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    return json.loads(result.stdout).get("items", [])


def parse_timestamp(ts_str: str | None) -> datetime | None:
    """Parse Kubernetes timestamp to datetime object."""
    if not ts_str:
        return None
    try:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
    except (ValueError, AttributeError):
        return None


def parse_x509_certificate(cert_pem: str, context: Context) -> dict[str, Any] | None:
    """Parse X.509 certificate and extract expiration info."""
    try:
        result = context.run(
            ["openssl", "x509", "-noout", "-dates", "-subject"],
            check=False,
            input=cert_pem
        )

        if result.returncode != 0:
            return None

        cert_info: dict[str, Any] = {}

        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("notBefore="):
                date_str = line.replace("notBefore=", "")
                try:
                    cert_info["not_before"] = datetime.strptime(
                        date_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            elif line.startswith("notAfter="):
                date_str = line.replace("notAfter=", "")
                try:
                    cert_info["not_after"] = datetime.strptime(
                        date_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            elif line.startswith("subject="):
                cert_info["subject"] = line.replace("subject=", "").strip()

        return cert_info if cert_info else None

    except Exception:
        return None


def analyze_secret(
    secret: dict[str, Any],
    context: Context,
    expiry_warn_days: int = 30,
    expiry_critical_days: int = 7,
    stale_days: int = 365
) -> dict[str, Any]:
    """Analyze a single secret for issues."""
    metadata = secret.get("metadata", {})
    secret_type = secret.get("type", "Opaque")
    data = secret.get("data", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    creation_time = parse_timestamp(metadata.get("creationTimestamp"))

    now = datetime.now(timezone.utc)
    age_days = None
    if creation_time:
        age_days = (now - creation_time).total_seconds() / 86400

    result: dict[str, Any] = {
        "name": name,
        "namespace": namespace,
        "type": secret_type,
        "creation_time": creation_time.isoformat() if creation_time else None,
        "age_days": round(age_days, 1) if age_days else None,
        "has_issue": False,
        "severity": "ok",
        "issues": [],
        "cert_info": None,
    }

    # Skip service account tokens (auto-managed)
    if secret_type == "kubernetes.io/service-account-token":
        result["skipped"] = True
        result["skip_reason"] = "Service account token (auto-managed)"
        return result

    # Check for stale secrets
    if age_days and age_days > stale_days:
        result["issues"].append(
            f"Secret is {int(age_days)} days old (stale threshold: {stale_days} days)"
        )
        result["has_issue"] = True
        if result["severity"] == "ok":
            result["severity"] = "warning"

    # For TLS secrets, check certificate expiration
    if secret_type == "kubernetes.io/tls":
        tls_crt = data.get("tls.crt")
        if tls_crt:
            try:
                cert_pem = base64.b64decode(tls_crt).decode("utf-8")
                cert_info = parse_x509_certificate(cert_pem, context)

                if cert_info:
                    result["cert_info"] = {
                        "subject": cert_info.get("subject"),
                        "not_before": cert_info.get("not_before").isoformat() if cert_info.get("not_before") else None,
                        "not_after": cert_info.get("not_after").isoformat() if cert_info.get("not_after") else None,
                    }

                    not_after = cert_info.get("not_after")
                    if not_after:
                        days_until_expiry = (not_after - now).total_seconds() / 86400
                        result["cert_info"]["days_until_expiry"] = round(days_until_expiry, 1)

                        if days_until_expiry < 0:
                            result["issues"].append(f"Certificate EXPIRED {abs(int(days_until_expiry))} days ago")
                            result["has_issue"] = True
                            result["severity"] = "critical"
                        elif days_until_expiry < expiry_critical_days:
                            result["issues"].append(f"Certificate expires in {int(days_until_expiry)} days (CRITICAL)")
                            result["has_issue"] = True
                            result["severity"] = "critical"
                        elif days_until_expiry < expiry_warn_days:
                            result["issues"].append(f"Certificate expires in {int(days_until_expiry)} days")
                            result["has_issue"] = True
                            if result["severity"] != "critical":
                                result["severity"] = "warning"
                else:
                    result["issues"].append("Could not parse TLS certificate")
                    result["has_issue"] = True
                    result["severity"] = "warning"

            except (base64.binascii.Error, UnicodeDecodeError):
                result["issues"].append("Invalid base64 in tls.crt")
                result["has_issue"] = True
                result["severity"] = "warning"
        else:
            result["issues"].append("TLS secret missing tls.crt")
            result["has_issue"] = True
            result["severity"] = "warning"

    return result


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
        description="Monitor Kubernetes Secret age and TLS certificate expiration"
    )
    parser.add_argument("-n", "--namespace", help="Namespace to check (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Include service account tokens")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show secrets with issues")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--expiry-warn", type=int, default=30, metavar="DAYS",
                        help="Days before certificate expiry to warn (default: 30)")
    parser.add_argument("--expiry-critical", type=int, default=7, metavar="DAYS",
                        help="Days before certificate expiry is critical (default: 7)")
    parser.add_argument("--stale-days", type=int, default=365, metavar="DAYS",
                        help="Days after which a secret is considered stale (default: 365)")
    parser.add_argument("--tls-only", action="store_true",
                        help="Only check TLS secrets")
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found. Install kubectl to use this script.")
        return 2

    try:
        secrets = get_secrets(context, opts.namespace)
    except Exception as e:
        output.error(f"Failed to get secrets: {e}")
        return 2

    # Filter for TLS only if requested
    if opts.tls_only:
        secrets = [s for s in secrets if s.get("type") == "kubernetes.io/tls"]

    # Analyze each secret
    secrets_data = [
        analyze_secret(
            secret,
            context,
            expiry_warn_days=opts.expiry_warn,
            expiry_critical_days=opts.expiry_critical,
            stale_days=opts.stale_days
        )
        for secret in secrets
    ]

    # Filter output
    if not opts.verbose:
        secrets_data = [s for s in secrets_data if not s.get("skipped")]

    if opts.warn_only:
        secrets_data = [s for s in secrets_data if s.get("has_issue")]

    # Calculate summary
    critical_count = sum(1 for s in secrets_data if s.get("severity") == "critical")
    warning_count = sum(1 for s in secrets_data if s.get("severity") == "warning")
    ok_count = sum(1 for s in secrets_data if s.get("severity") == "ok")

    output.emit({
        "secrets": secrets_data,
        "summary": {
            "total": len(secrets_data),
            "critical": critical_count,
            "warning": warning_count,
            "ok": ok_count,
        }
    })

    if critical_count == 0 and warning_count == 0:
        output.set_summary("All secrets healthy")
    else:
        output.set_summary(f"{critical_count} critical, {warning_count} warnings")

    has_issues = any(s.get("has_issue") for s in secrets_data if not s.get("skipped"))
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
