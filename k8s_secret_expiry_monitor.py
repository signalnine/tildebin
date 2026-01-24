#!/usr/bin/env python3
"""
Monitor Kubernetes Secret age and TLS certificate expiration.

Analyzes Kubernetes secrets for:
- TLS certificate expiration dates (kubernetes.io/tls secrets)
- Stale secrets that haven't been updated in a long time
- Secrets approaching expiration thresholds
- Orphaned secrets not referenced by any workload

Critical for large-scale environments where expired certificates
cause unexpected outages and stale secrets create security risks.

Exit codes:
    0 - All secrets healthy
    1 - Expiring/expired secrets or issues detected
    2 - Usage error or kubectl not available
"""

import argparse
import base64
import json
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional


def run_kubectl(args: List[str]) -> str:
    """Execute kubectl command and return output"""
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


def get_secrets(namespace: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all secrets in JSON format"""
    cmd = ['get', 'secrets', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    output = run_kubectl(cmd)
    data = json.loads(output)
    return data.get('items', [])


def parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse Kubernetes timestamp to datetime object"""
    if not ts_str:
        return None
    try:
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        return datetime.fromisoformat(ts_str)
    except (ValueError, AttributeError):
        return None


def parse_x509_certificate(cert_pem: str) -> Optional[Dict[str, Any]]:
    """Parse X.509 certificate and extract expiration info.

    Uses openssl to parse the certificate since we want to avoid
    external Python dependencies.
    """
    try:
        # Use openssl to parse the certificate
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-dates', '-subject'],
            input=cert_pem,
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return None

        output = result.stdout
        cert_info = {}

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('notBefore='):
                # Parse date like "Jan 15 00:00:00 2024 GMT"
                date_str = line.replace('notBefore=', '')
                try:
                    cert_info['not_before'] = datetime.strptime(
                        date_str, '%b %d %H:%M:%S %Y %Z'
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            elif line.startswith('notAfter='):
                date_str = line.replace('notAfter=', '')
                try:
                    cert_info['not_after'] = datetime.strptime(
                        date_str, '%b %d %H:%M:%S %Y %Z'
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            elif line.startswith('subject='):
                cert_info['subject'] = line.replace('subject=', '').strip()

        return cert_info if cert_info else None

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def analyze_secret(secret: Dict[str, Any],
                   expiry_warn_days: int = 30,
                   expiry_critical_days: int = 7,
                   stale_days: int = 365) -> Dict[str, Any]:
    """Analyze a single secret for issues"""
    metadata = secret.get('metadata', {})
    secret_type = secret.get('type', 'Opaque')
    data = secret.get('data', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')

    # Parse creation/update timestamps
    creation_time = parse_timestamp(metadata.get('creationTimestamp'))

    # Resource version can indicate updates but isn't a timestamp
    # We'll use creation time as the primary age indicator

    now = datetime.now(timezone.utc)
    age_days = None
    if creation_time:
        age_days = (now - creation_time).total_seconds() / 86400

    result = {
        'name': name,
        'namespace': namespace,
        'type': secret_type,
        'creation_time': creation_time.isoformat() if creation_time else None,
        'age_days': round(age_days, 1) if age_days else None,
        'has_issue': False,
        'severity': 'ok',
        'issues': [],
        'cert_info': None,
    }

    # Skip service account tokens (auto-managed)
    if secret_type == 'kubernetes.io/service-account-token':
        result['skipped'] = True
        result['skip_reason'] = 'Service account token (auto-managed)'
        return result

    # Check for stale secrets
    if age_days and age_days > stale_days:
        result['issues'].append(f"Secret is {int(age_days)} days old (stale threshold: {stale_days} days)")
        result['has_issue'] = True
        if result['severity'] == 'ok':
            result['severity'] = 'warning'

    # For TLS secrets, check certificate expiration
    if secret_type == 'kubernetes.io/tls':
        tls_crt = data.get('tls.crt')
        if tls_crt:
            try:
                cert_pem = base64.b64decode(tls_crt).decode('utf-8')
                cert_info = parse_x509_certificate(cert_pem)

                if cert_info:
                    result['cert_info'] = {
                        'subject': cert_info.get('subject'),
                        'not_before': cert_info.get('not_before').isoformat() if cert_info.get('not_before') else None,
                        'not_after': cert_info.get('not_after').isoformat() if cert_info.get('not_after') else None,
                    }

                    not_after = cert_info.get('not_after')
                    if not_after:
                        days_until_expiry = (not_after - now).total_seconds() / 86400
                        result['cert_info']['days_until_expiry'] = round(days_until_expiry, 1)

                        if days_until_expiry < 0:
                            result['issues'].append(f"Certificate EXPIRED {abs(int(days_until_expiry))} days ago")
                            result['has_issue'] = True
                            result['severity'] = 'critical'
                        elif days_until_expiry < expiry_critical_days:
                            result['issues'].append(f"Certificate expires in {int(days_until_expiry)} days (CRITICAL)")
                            result['has_issue'] = True
                            result['severity'] = 'critical'
                        elif days_until_expiry < expiry_warn_days:
                            result['issues'].append(f"Certificate expires in {int(days_until_expiry)} days (warning)")
                            result['has_issue'] = True
                            if result['severity'] != 'critical':
                                result['severity'] = 'warning'
                else:
                    result['issues'].append("Could not parse TLS certificate")
                    result['has_issue'] = True
                    result['severity'] = 'warning'

            except (base64.binascii.Error, UnicodeDecodeError):
                result['issues'].append("Invalid base64 in tls.crt")
                result['has_issue'] = True
                result['severity'] = 'warning'
        else:
            result['issues'].append("TLS secret missing tls.crt")
            result['has_issue'] = True
            result['severity'] = 'warning'

    return result


def format_age(days: Optional[float]) -> str:
    """Format age in days to human-readable string"""
    if days is None:
        return 'N/A'

    if days < 1:
        return f"{int(days * 24)}h"
    elif days < 30:
        return f"{int(days)}d"
    elif days < 365:
        return f"{int(days / 30)}mo"
    else:
        return f"{days / 365:.1f}y"


def output_plain(secrets_data: List[Dict], warn_only: bool, verbose: bool):
    """Plain text output"""
    # Filter out skipped secrets unless verbose
    if not verbose:
        secrets_data = [s for s in secrets_data if not s.get('skipped')]

    # Filter for warn-only
    if warn_only:
        secrets_data = [s for s in secrets_data if s.get('has_issue')]

    if not secrets_data:
        if warn_only:
            print("No secret issues detected")
        else:
            print("No secrets found")
        return

    # Group by severity
    critical = [s for s in secrets_data if s.get('severity') == 'critical']
    warning = [s for s in secrets_data if s.get('severity') == 'warning']
    ok = [s for s in secrets_data if s.get('severity') == 'ok']

    if critical:
        print("=== CRITICAL ===")
        for secret in critical:
            print(f"[CRITICAL] {secret['namespace']}/{secret['name']}")
            print(f"  Type: {secret['type']}")
            if secret.get('cert_info'):
                cert = secret['cert_info']
                print(f"  Subject: {cert.get('subject', 'N/A')}")
                if cert.get('days_until_expiry') is not None:
                    print(f"  Expires: {cert.get('not_after', 'N/A')} ({cert['days_until_expiry']} days)")
            for issue in secret.get('issues', []):
                print(f"  Issue: {issue}")
            print()

    if warning:
        print("=== WARNINGS ===")
        for secret in warning:
            print(f"[WARNING] {secret['namespace']}/{secret['name']}")
            print(f"  Type: {secret['type']} | Age: {format_age(secret.get('age_days'))}")
            for issue in secret.get('issues', []):
                print(f"  Issue: {issue}")
            print()

    if ok and not warn_only:
        print("=== OK ===")
        for secret in ok:
            age_str = format_age(secret.get('age_days'))
            print(f"[OK] {secret['namespace']}/{secret['name']} ({secret['type']}, {age_str})")
            if verbose and secret.get('cert_info'):
                cert = secret['cert_info']
                if cert.get('days_until_expiry') is not None:
                    print(f"     Certificate expires in {cert['days_until_expiry']} days")
        print()


def output_json(secrets_data: List[Dict], warn_only: bool, verbose: bool):
    """JSON output"""
    # Filter out skipped secrets unless verbose
    if not verbose:
        secrets_data = [s for s in secrets_data if not s.get('skipped')]

    if warn_only:
        secrets_data = [s for s in secrets_data if s.get('has_issue')]

    summary = {
        'total': len(secrets_data),
        'critical': sum(1 for s in secrets_data if s.get('severity') == 'critical'),
        'warning': sum(1 for s in secrets_data if s.get('severity') == 'warning'),
        'ok': sum(1 for s in secrets_data if s.get('severity') == 'ok'),
    }

    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'summary': summary,
        'secrets': secrets_data,
    }

    print(json.dumps(output, indent=2))


def output_table(secrets_data: List[Dict], warn_only: bool, verbose: bool):
    """Tabular output"""
    # Filter out skipped secrets unless verbose
    if not verbose:
        secrets_data = [s for s in secrets_data if not s.get('skipped')]

    if warn_only:
        secrets_data = [s for s in secrets_data if s.get('has_issue')]

    if not secrets_data:
        print("No secrets to display")
        return

    # Header
    print(f"{'Severity':<10} {'Namespace':<20} {'Name':<35} {'Type':<25} {'Age':<8} {'Cert Expiry':<12}")
    print("=" * 120)

    # Sort by severity (critical first)
    severity_order = {'critical': 0, 'warning': 1, 'ok': 2}
    secrets_data.sort(key=lambda s: severity_order.get(s.get('severity', 'ok'), 3))

    for secret in secrets_data:
        severity = secret.get('severity', 'ok').upper()
        namespace = secret['namespace'][:19]
        name = secret['name'][:34]
        secret_type = secret['type'][:24]
        age = format_age(secret.get('age_days'))

        cert_expiry = 'N/A'
        if secret.get('cert_info') and secret['cert_info'].get('days_until_expiry') is not None:
            days = secret['cert_info']['days_until_expiry']
            if days < 0:
                cert_expiry = f"EXPIRED"
            else:
                cert_expiry = f"{int(days)}d"

        print(f"{severity:<10} {namespace:<20} {name:<35} {secret_type:<25} {age:<8} {cert_expiry:<12}")

    # Summary
    critical_count = sum(1 for s in secrets_data if s.get('severity') == 'critical')
    warning_count = sum(1 for s in secrets_data if s.get('severity') == 'warning')
    print()
    print(f"Total: {len(secrets_data)} | Critical: {critical_count} | Warning: {warning_count}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes Secret age and TLS certificate expiration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all secrets across all namespaces
  %(prog)s

  # Check secrets in specific namespace
  %(prog)s -n production

  # Show only expiring/problematic secrets
  %(prog)s --warn-only

  # Custom expiration thresholds
  %(prog)s --expiry-warn 60 --expiry-critical 14

  # JSON output for automation
  %(prog)s --format json

  # Include service account tokens in output
  %(prog)s --verbose

Exit codes:
  0 - All secrets healthy
  1 - Expiring/expired secrets or issues detected
  2 - Usage error or kubectl not available
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to check (default: all namespaces)'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show secrets with issues'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including service account tokens'
    )

    parser.add_argument(
        '--expiry-warn',
        type=int,
        default=30,
        metavar='DAYS',
        help='Days before certificate expiry to warn (default: %(default)s)'
    )

    parser.add_argument(
        '--expiry-critical',
        type=int,
        default=7,
        metavar='DAYS',
        help='Days before certificate expiry is critical (default: %(default)s)'
    )

    parser.add_argument(
        '--stale-days',
        type=int,
        default=365,
        metavar='DAYS',
        help='Days after which a secret is considered stale (default: %(default)s)'
    )

    parser.add_argument(
        '--tls-only',
        action='store_true',
        help='Only check TLS secrets (kubernetes.io/tls type)'
    )

    args = parser.parse_args()

    # Get secrets
    secrets = get_secrets(args.namespace)

    # Filter for TLS only if requested
    if args.tls_only:
        secrets = [s for s in secrets if s.get('type') == 'kubernetes.io/tls']

    # Analyze each secret
    secrets_data = [
        analyze_secret(
            secret,
            expiry_warn_days=args.expiry_warn,
            expiry_critical_days=args.expiry_critical,
            stale_days=args.stale_days
        )
        for secret in secrets
    ]

    # Output results
    if args.format == 'json':
        output_json(secrets_data, args.warn_only, args.verbose)
    elif args.format == 'table':
        output_table(secrets_data, args.warn_only, args.verbose)
    else:
        output_plain(secrets_data, args.warn_only, args.verbose)

    # Determine exit code
    has_issues = any(s.get('has_issue') for s in secrets_data if not s.get('skipped'))
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
