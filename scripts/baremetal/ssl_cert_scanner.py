#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [ssl, tls, certificates, security, expiration]
#   requires: [openssl]
#   privilege: user
#   related: [file_integrity, security_policy]
#   brief: Scan SSL/TLS certificates and check expiration status

"""
Scan filesystem for SSL/TLS certificates and check expiration status.

Discovers and monitors certificates on baremetal systems by scanning
common certificate locations and extracting expiration information.
Useful for preventing outages caused by expired certificates.

Returns:
    0 - All certificates valid
    1 - Expired or soon-to-expire certificates found
    2 - Error (openssl not available)
"""

import argparse
import re
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Default paths to scan for certificates
DEFAULT_CERT_PATHS = [
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/etc/pki/ca-trust/extracted/pem",
    "/etc/letsencrypt/live",
    "/etc/nginx/ssl",
    "/etc/apache2/ssl",
    "/etc/httpd/ssl",
    "/etc/docker/certs.d",
    "/etc/kubernetes/pki",
    "/var/lib/kubelet/pki",
    "/etc/etcd/pki",
]

# Certificate file extensions to look for
CERT_EXTENSIONS = (".pem", ".crt", ".cer", ".cert")


def find_certificate_files(context: Context, paths: list[str], recursive: bool = True) -> list[str]:
    """Find certificate files in the specified paths."""
    cert_files = []

    for path in paths:
        if not context.file_exists(path):
            continue

        # Check if it's a direct file path (has a cert extension)
        if path.endswith(CERT_EXTENSIONS):
            cert_files.append(path)
            continue

        # Use glob to find files in directories
        if recursive:
            for ext in CERT_EXTENSIONS:
                pattern = f"**/*{ext}"
                found = context.glob(pattern, root=path)
                cert_files.extend(found)
        else:
            for ext in CERT_EXTENSIONS:
                pattern = f"*{ext}"
                found = context.glob(pattern, root=path)
                cert_files.extend(found)

    return sorted(set(cert_files))


def parse_openssl_date(date_str: str) -> datetime | None:
    """Parse openssl date format (e.g., 'Nov 20 10:30:00 2025 GMT')."""
    try:
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(date_str, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def extract_cn(subject: str) -> str:
    """Extract Common Name from certificate subject."""
    if not subject:
        return "unknown"

    for part in subject.split(","):
        part = part.strip()
        if part.startswith("CN=") or part.startswith("CN ="):
            return part.split("=", 1)[1].strip()

    return subject[:50] if subject else "unknown"


def get_certificate_info(context: Context, cert_path: str, warning_days: int = 30) -> dict[str, Any] | None:
    """Extract certificate information using openssl."""
    result = context.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-dates", "-serial"],
        check=False,
    )

    if result.returncode != 0:
        return None

    output = result.stdout
    info: dict[str, Any] = {
        "path": cert_path,
        "subject": "",
        "issuer": "",
        "not_before": None,
        "not_after": None,
        "serial": "",
        "days_remaining": None,
        "status": "unknown",
    }

    for line in output.strip().split("\n"):
        if line.startswith("subject="):
            info["subject"] = line.replace("subject=", "").strip()
        elif line.startswith("issuer="):
            info["issuer"] = line.replace("issuer=", "").strip()
        elif line.startswith("notBefore="):
            date_str = line.replace("notBefore=", "").strip()
            info["not_before"] = date_str
        elif line.startswith("notAfter="):
            date_str = line.replace("notAfter=", "").strip()
            not_after = parse_openssl_date(date_str)
            info["not_after"] = date_str
            if not_after:
                now = datetime.now(timezone.utc)
                delta = not_after - now
                info["days_remaining"] = delta.days

                if info["days_remaining"] < 0:
                    info["status"] = "expired"
                elif info["days_remaining"] <= 7:
                    info["status"] = "critical"
                elif info["days_remaining"] <= warning_days:
                    info["status"] = "warning"
                else:
                    info["status"] = "valid"
        elif line.startswith("serial="):
            info["serial"] = line.replace("serial=", "").strip()

    info["common_name"] = extract_cn(info["subject"])
    return info


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
    parser = argparse.ArgumentParser(description="Scan SSL/TLS certificates and check expiration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-p", "--path", action="append", dest="paths", help="Path to scan (file or directory)")
    parser.add_argument("--days", type=int, default=30, help="Warning threshold in days (default: 30)")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show certificates with warnings")
    parser.add_argument("--no-recursive", action="store_true", help="Do not recursively scan directories")
    opts = parser.parse_args(args)

    # Check for openssl
    if not context.check_tool("openssl"):
        output.error("openssl not found. Install openssl package.")
        return 2

    # Determine paths to scan
    scan_paths = opts.paths if opts.paths else DEFAULT_CERT_PATHS

    # Find certificate files
    cert_files = find_certificate_files(context, scan_paths, recursive=not opts.no_recursive)

    if not cert_files:
        output.emit({"certificates": [], "summary": {"total": 0, "expired": 0, "warning": 0, "valid": 0}})
        output.set_summary("No certificates found")
        return 0

    # Analyze each certificate
    results = []
    has_issues = False

    for cert_path in cert_files:
        info = get_certificate_info(context, cert_path, opts.days)
        if info:
            if info["status"] in ("expired", "critical", "warning"):
                has_issues = True

            # Filter for warn-only mode
            if opts.warn_only and info["status"] == "valid":
                continue

            # Remove extra fields in non-verbose mode
            if not opts.verbose:
                info.pop("subject", None)
                info.pop("issuer", None)
                info.pop("serial", None)
                info.pop("not_before", None)

            results.append(info)

    # Calculate summary counts from all certs (not filtered)
    all_certs = []
    for cert_path in cert_files:
        info = get_certificate_info(context, cert_path, opts.days)
        if info:
            all_certs.append(info)

    expired = sum(1 for c in all_certs if c["status"] == "expired")
    critical = sum(1 for c in all_certs if c["status"] == "critical")
    warning = sum(1 for c in all_certs if c["status"] == "warning")
    valid = sum(1 for c in all_certs if c["status"] == "valid")

    output.emit({
        "certificates": results,
        "summary": {
            "total": len(all_certs),
            "expired": expired,
            "critical": critical,
            "warning": warning,
            "valid": valid,
        },
    })

    output.set_summary(f"{valid} valid, {expired} expired, {warning + critical} expiring soon")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
