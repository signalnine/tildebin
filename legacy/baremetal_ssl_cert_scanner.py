#!/usr/bin/env python3
"""
Scan filesystem for SSL/TLS certificates and check expiration status.

This script discovers and monitors certificates on baremetal systems by scanning
common certificate locations and extracting expiration information. Useful for
preventing outages caused by expired certificates in services like:
- Web servers (Apache, Nginx)
- Container runtimes (Docker, containerd)
- Databases (PostgreSQL, MySQL)
- Message queues (RabbitMQ, Kafka)
- Custom applications

Exit codes:
    0 - All certificates valid (or no certificates found)
    1 - Expired or soon-to-expire certificates found
    2 - Usage error or openssl not available
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from collections import defaultdict


# Default paths to scan for certificates
DEFAULT_CERT_PATHS = [
    '/etc/ssl/certs',
    '/etc/pki/tls/certs',
    '/etc/pki/ca-trust/extracted/pem',
    '/etc/letsencrypt/live',
    '/etc/nginx/ssl',
    '/etc/apache2/ssl',
    '/etc/httpd/ssl',
    '/etc/docker/certs.d',
    '/etc/kubernetes/pki',
    '/var/lib/kubelet/pki',
    '/etc/etcd/pki',
]

# Certificate file extensions to look for
CERT_EXTENSIONS = ('.pem', '.crt', '.cer', '.cert')


def check_openssl_available():
    """Check if openssl is installed."""
    try:
        result = subprocess.run(
            ['which', 'openssl'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def find_certificate_files(paths, recursive=True):
    """Find certificate files in the specified paths."""
    cert_files = []

    for path in paths:
        if not os.path.exists(path):
            continue

        if os.path.isfile(path):
            # Direct file path
            if path.endswith(CERT_EXTENSIONS) or is_pem_file(path):
                cert_files.append(path)
            continue

        if not os.path.isdir(path):
            continue

        if recursive:
            for root, dirs, files in os.walk(path):
                # Skip symlink directories to avoid loops
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for f in files:
                    filepath = os.path.join(root, f)
                    if f.endswith(CERT_EXTENSIONS) or is_pem_file(filepath):
                        cert_files.append(filepath)
        else:
            for f in os.listdir(path):
                filepath = os.path.join(path, f)
                if os.path.isfile(filepath):
                    if f.endswith(CERT_EXTENSIONS) or is_pem_file(filepath):
                        cert_files.append(filepath)

    return sorted(set(cert_files))


def is_pem_file(filepath):
    """Check if a file looks like a PEM certificate."""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            first_line = f.readline()
            return '-----BEGIN CERTIFICATE-----' in first_line
    except (IOError, OSError, PermissionError):
        return False


def get_certificate_info(cert_path):
    """Extract certificate information using openssl."""
    try:
        # Get subject, issuer, dates, and serial in one call
        result = subprocess.run(
            ['openssl', 'x509', '-in', cert_path, '-noout',
             '-subject', '-issuer', '-dates', '-serial'],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return None

        output = result.stdout
        info = {
            'path': cert_path,
            'subject': '',
            'issuer': '',
            'not_before': None,
            'not_after': None,
            'serial': '',
            'days_remaining': None,
            'status': 'unknown'
        }

        for line in output.strip().split('\n'):
            if line.startswith('subject='):
                info['subject'] = line.replace('subject=', '').strip()
            elif line.startswith('issuer='):
                info['issuer'] = line.replace('issuer=', '').strip()
            elif line.startswith('notBefore='):
                date_str = line.replace('notBefore=', '').strip()
                info['not_before'] = parse_openssl_date(date_str)
            elif line.startswith('notAfter='):
                date_str = line.replace('notAfter=', '').strip()
                info['not_after'] = parse_openssl_date(date_str)
            elif line.startswith('serial='):
                info['serial'] = line.replace('serial=', '').strip()

        # Calculate days remaining
        if info['not_after']:
            now = datetime.utcnow()
            delta = info['not_after'] - now
            info['days_remaining'] = delta.days

            if info['days_remaining'] < 0:
                info['status'] = 'expired'
            elif info['days_remaining'] <= 7:
                info['status'] = 'critical'
            elif info['days_remaining'] <= 30:
                info['status'] = 'warning'
            else:
                info['status'] = 'valid'

        return info

    except (subprocess.SubprocessError, Exception):
        return None


def parse_openssl_date(date_str):
    """Parse openssl date format (e.g., 'Nov 20 10:30:00 2025 GMT')."""
    try:
        return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
    except ValueError:
        try:
            # Alternative format without timezone
            return datetime.strptime(date_str, '%b %d %H:%M:%S %Y')
        except ValueError:
            return None


def extract_cn(subject):
    """Extract Common Name from certificate subject."""
    if not subject:
        return 'unknown'

    # Look for CN= in the subject
    for part in subject.split(','):
        part = part.strip()
        if part.startswith('CN=') or part.startswith('CN ='):
            return part.split('=', 1)[1].strip()

    return subject[:50] if subject else 'unknown'


def output_plain(results, warn_only=False, verbose=False):
    """Output results in plain text format."""
    if not results:
        print("No certificates found in scanned paths")
        return

    # Group by status
    by_status = defaultdict(list)
    for cert in results:
        by_status[cert['status']].append(cert)

    # Print summary header
    total = len(results)
    expired = len(by_status['expired'])
    critical = len(by_status['critical'])
    warning = len(by_status['warning'])
    valid = len(by_status['valid'])

    print(f"Certificate Summary: {total} total, {expired} expired, "
          f"{critical} critical, {warning} warning, {valid} valid")
    print()

    # Print problematic certs first
    for status in ['expired', 'critical', 'warning']:
        certs = by_status[status]
        if not certs:
            continue

        status_symbols = {
            'expired': '!!!',
            'critical': '!! ',
            'warning': '!  '
        }

        for cert in certs:
            cn = extract_cn(cert['subject'])
            days = cert['days_remaining']
            symbol = status_symbols[status]

            if days < 0:
                print(f"[{symbol}] {cn}: EXPIRED {abs(days)} days ago")
            else:
                print(f"[{symbol}] {cn}: expires in {days} days")

            if verbose:
                print(f"      Path: {cert['path']}")
                print(f"      Subject: {cert['subject']}")
                print(f"      Issuer: {cert['issuer']}")
                if cert['not_after']:
                    print(f"      Expires: {cert['not_after'].isoformat()}")
            print()

    # Print valid certs if not warn_only
    if not warn_only and by_status['valid']:
        print("Valid certificates:")
        for cert in by_status['valid']:
            cn = extract_cn(cert['subject'])
            days = cert['days_remaining']
            print(f"  [OK ] {cn}: {days} days remaining")
            if verbose:
                print(f"        Path: {cert['path']}")


def output_json(results):
    """Output results in JSON format."""
    # Convert datetime objects to ISO format strings
    output = []
    for cert in results:
        cert_copy = cert.copy()
        if cert_copy.get('not_before'):
            cert_copy['not_before'] = cert_copy['not_before'].isoformat()
        if cert_copy.get('not_after'):
            cert_copy['not_after'] = cert_copy['not_after'].isoformat()
        output.append(cert_copy)

    print(json.dumps(output, indent=2))


def output_table(results, warn_only=False):
    """Output results in table format."""
    if not results:
        print("No certificates found")
        return

    # Filter if warn_only
    if warn_only:
        results = [r for r in results if r['status'] != 'valid']

    if not results:
        print("No certificate issues found")
        return

    # Print header
    print(f"{'Status':<10} {'Days':<8} {'Common Name':<40} {'Path'}")
    print("-" * 100)

    # Sort by days remaining
    sorted_results = sorted(results, key=lambda x: x['days_remaining'] or -9999)

    for cert in sorted_results:
        status = cert['status'].upper()
        days = cert['days_remaining'] if cert['days_remaining'] is not None else 'N/A'
        cn = extract_cn(cert['subject'])[:38]
        path = cert['path']

        print(f"{status:<10} {str(days):<8} {cn:<40} {path}")


def main():
    parser = argparse.ArgumentParser(
        description='Scan filesystem for SSL/TLS certificates and check expiration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Scan default certificate paths
  %(prog)s -p /etc/nginx/ssl        # Scan specific directory
  %(prog)s -p /path/to/cert.pem     # Check specific certificate
  %(prog)s --warn-only              # Only show expired/expiring certs
  %(prog)s --days 60                # Warn for certs expiring within 60 days
  %(prog)s --format json            # JSON output for automation
  %(prog)s -v                       # Verbose output with full details

Exit codes:
  0 - All certificates valid
  1 - Expired or soon-to-expire certificates found
  2 - Usage error or openssl unavailable
        """
    )

    parser.add_argument(
        '-p', '--path',
        action='append',
        dest='paths',
        help='Path to scan (file or directory). Can be specified multiple times. '
             'Default: common system certificate locations'
    )

    parser.add_argument(
        '--days',
        type=int,
        default=30,
        help='Warning threshold in days (default: 30)'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed certificate information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show certificates with warnings or errors'
    )

    parser.add_argument(
        '--no-recursive',
        action='store_true',
        help='Do not recursively scan directories'
    )

    args = parser.parse_args()

    # Check for openssl
    if not check_openssl_available():
        print("Error: openssl not found in PATH", file=sys.stderr)
        print("Install openssl:", file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt-get install openssl", file=sys.stderr)
        print("  RHEL/CentOS: sudo yum install openssl", file=sys.stderr)
        sys.exit(2)

    # Determine paths to scan
    scan_paths = args.paths if args.paths else DEFAULT_CERT_PATHS

    # Find certificate files
    cert_files = find_certificate_files(scan_paths, recursive=not args.no_recursive)

    if not cert_files:
        if args.format == 'json':
            print('[]')
        else:
            print("No certificate files found in scanned paths")
        sys.exit(0)

    # Analyze each certificate
    results = []
    for cert_path in cert_files:
        info = get_certificate_info(cert_path)
        if info:
            # Apply custom warning threshold
            if info['days_remaining'] is not None and info['status'] == 'valid':
                if info['days_remaining'] <= args.days:
                    info['status'] = 'warning'
            results.append(info)

    # Filter for warn-only if using JSON (other formats handle internally)
    output_results = results
    if args.warn_only and args.format == 'json':
        output_results = [r for r in results if r['status'] != 'valid']

    # Output results
    if args.format == 'json':
        output_json(output_results)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.warn_only, args.verbose)

    # Determine exit code
    has_issues = any(r['status'] in ('expired', 'critical', 'warning') for r in results)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
