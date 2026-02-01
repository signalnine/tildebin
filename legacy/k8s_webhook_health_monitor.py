#!/usr/bin/env python3
"""
Kubernetes Webhook Health Monitor

Monitors the health of admission webhooks (validating and mutating) in a Kubernetes cluster:
- Webhook configuration validation
- Certificate expiration checks
- Endpoint availability and connectivity
- Failure policy assessment (fail-open vs fail-closed risks)
- Timeout configuration analysis
- Recent webhook rejections and admission failures

Admission webhooks can become single points of failure that silently block deployments.
This tool provides visibility into webhook chains and identifies misconfigured or
failing webhooks before they impact production.

Exit codes:
    0 - All webhooks healthy and properly configured
    1 - Webhook issues detected (warnings or failures)
    2 - Usage error or missing dependencies
"""

import argparse
import base64
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional


def check_kubectl() -> bool:
    """Check if kubectl is available and configured."""
    try:
        result = subprocess.run(
            ['kubectl', 'cluster-info'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def get_validating_webhooks() -> Optional[List[Dict]]:
    """Get all validating webhook configurations."""
    try:
        result = subprocess.run(
            ['kubectl', 'get', 'validatingwebhookconfigurations', '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        data = json.loads(result.stdout)
        return data.get('items', [])
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def get_mutating_webhooks() -> Optional[List[Dict]]:
    """Get all mutating webhook configurations."""
    try:
        result = subprocess.run(
            ['kubectl', 'get', 'mutatingwebhookconfigurations', '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        data = json.loads(result.stdout)
        return data.get('items', [])
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def get_recent_events(hours: int = 1) -> Optional[List[Dict]]:
    """Get recent cluster events related to webhook failures."""
    try:
        result = subprocess.run(
            ['kubectl', 'get', 'events', '--all-namespaces', '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        data = json.loads(result.stdout)
        events = data.get('items', [])

        # Filter for webhook-related events
        webhook_events = []
        for event in events:
            message = event.get('message', '').lower()
            reason = event.get('reason', '').lower()

            if 'webhook' in message or 'admission' in message or 'webhook' in reason:
                webhook_events.append(event)

        return webhook_events
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None


def parse_certificate(cert_data: str) -> Optional[Dict]:
    """Parse certificate data to extract expiration information."""
    try:
        # Decode base64 certificate
        cert_bytes = base64.b64decode(cert_data)

        # Use openssl to parse certificate
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-enddate', '-subject'],
            input=cert_bytes,
            capture_output=True,
            timeout=5
        )

        if result.returncode != 0:
            return None

        output = result.stdout.decode('utf-8')

        # Parse expiration date
        expiry_str = None
        subject = None

        for line in output.split('\n'):
            if line.startswith('notAfter='):
                expiry_str = line.replace('notAfter=', '').strip()
            elif line.startswith('subject='):
                subject = line.replace('subject=', '').strip()

        if not expiry_str:
            return None

        # Parse the date string (format: "Jan 1 00:00:00 2025 GMT")
        from datetime import datetime
        expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
        expiry_date = expiry_date.replace(tzinfo=timezone.utc)

        days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days

        return {
            'expiry_date': expiry_date.isoformat(),
            'days_until_expiry': days_until_expiry,
            'subject': subject
        }
    except Exception:
        return None


def check_service_endpoint(namespace: str, service_name: str, port: int) -> Dict:
    """Check if a webhook service endpoint is available."""
    try:
        # Get service
        result = subprocess.run(
            ['kubectl', 'get', 'service', service_name, '-n', namespace, '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {
                'available': False,
                'reason': 'Service not found'
            }

        service = json.loads(result.stdout)

        # Get endpoints
        result = subprocess.run(
            ['kubectl', 'get', 'endpoints', service_name, '-n', namespace, '-o', 'json'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {
                'available': False,
                'reason': 'Endpoints not found'
            }

        endpoints = json.loads(result.stdout)
        subsets = endpoints.get('subsets', [])

        if not subsets:
            return {
                'available': False,
                'reason': 'No endpoint subsets'
            }

        ready_addresses = sum(len(subset.get('addresses', [])) for subset in subsets)

        if ready_addresses == 0:
            return {
                'available': False,
                'reason': 'No ready endpoints'
            }

        return {
            'available': True,
            'ready_endpoints': ready_addresses,
            'cluster_ip': service.get('spec', {}).get('clusterIP')
        }

    except (subprocess.SubprocessError, json.JSONDecodeError):
        return {
            'available': False,
            'reason': 'Error checking service'
        }


def analyze_webhook_health(validating_configs: List[Dict], mutating_configs: List[Dict],
                          events: Optional[List[Dict]], check_endpoints: bool = True) -> Tuple[List[str], List[str]]:
    """Analyze webhook configurations and return issues and warnings."""
    issues = []
    warnings = []

    all_configs = [
        ('validating', config) for config in (validating_configs or [])
    ] + [
        ('mutating', config) for config in (mutating_configs or [])
    ]

    if not all_configs:
        warnings.append("No admission webhooks found in cluster")
        return issues, warnings

    for webhook_type, config in all_configs:
        config_name = config.get('metadata', {}).get('name', 'unknown')
        webhooks = config.get('webhooks', [])

        for webhook in webhooks:
            webhook_name = webhook.get('name', 'unknown')
            full_name = f"{webhook_type}/{config_name}/{webhook_name}"

            # Check failure policy
            failure_policy = webhook.get('failurePolicy', 'Fail')
            if failure_policy == 'Ignore':
                warnings.append(
                    f"{full_name}: Failure policy is 'Ignore' (fail-open) - "
                    f"failures will silently allow requests"
                )

            # Check timeout settings
            timeout_seconds = webhook.get('timeoutSeconds', 10)
            if timeout_seconds > 15:
                warnings.append(
                    f"{full_name}: Timeout is {timeout_seconds}s (high latency risk)"
                )
            elif timeout_seconds < 5:
                warnings.append(
                    f"{full_name}: Timeout is {timeout_seconds}s (may cause premature failures)"
                )

            # Check side effects
            side_effects = webhook.get('sideEffects', 'Unknown')
            if side_effects == 'Unknown':
                warnings.append(
                    f"{full_name}: Side effects are 'Unknown' (deprecated, should be explicit)"
                )

            # Check client config
            client_config = webhook.get('clientConfig', {})

            # Check CA bundle
            ca_bundle = client_config.get('caBundle')
            if ca_bundle:
                cert_info = parse_certificate(ca_bundle)
                if cert_info:
                    days_left = cert_info['days_until_expiry']
                    if days_left < 0:
                        issues.append(
                            f"{full_name}: Certificate EXPIRED {abs(days_left)} days ago"
                        )
                    elif days_left < 7:
                        issues.append(
                            f"{full_name}: Certificate expires in {days_left} days (critical)"
                        )
                    elif days_left < 30:
                        warnings.append(
                            f"{full_name}: Certificate expires in {days_left} days"
                        )

            # Check service endpoint
            service = client_config.get('service')
            if service and check_endpoints:
                namespace = service.get('namespace', 'default')
                service_name = service.get('name')
                port = service.get('port', 443)

                if service_name:
                    endpoint_status = check_service_endpoint(namespace, service_name, port)

                    if not endpoint_status.get('available'):
                        issues.append(
                            f"{full_name}: Service endpoint unavailable - "
                            f"{endpoint_status.get('reason')}"
                        )
                    elif endpoint_status.get('ready_endpoints', 0) < 2:
                        warnings.append(
                            f"{full_name}: Only {endpoint_status.get('ready_endpoints')} "
                            f"endpoint(s) (consider HA)"
                        )

            # Check admission review versions
            admission_review_versions = webhook.get('admissionReviewVersions', [])
            if 'v1' not in admission_review_versions:
                warnings.append(
                    f"{full_name}: Does not support AdmissionReview v1 (deprecated)"
                )

            # Check match policy
            match_policy = webhook.get('matchPolicy', 'Equivalent')
            if match_policy == 'Exact':
                # This is fine, just informational
                pass

            # Check object selector
            object_selector = webhook.get('objectSelector')
            namespace_selector = webhook.get('namespaceSelector')

            if not object_selector and not namespace_selector:
                # Webhook applies to all objects - could be intentional
                rules = webhook.get('rules', [])
                if rules:
                    # Check if it's too broad
                    for rule in rules:
                        operations = rule.get('operations', [])
                        resources = rule.get('resources', [])

                        if '*' in operations or '*' in resources:
                            warnings.append(
                                f"{full_name}: Very broad scope (all operations/resources) "
                                f"with no selectors - may impact cluster performance"
                            )
                            break

    # Check for webhook-related failures in events
    if events:
        webhook_failures = defaultdict(int)

        for event in events:
            message = event.get('message', '')
            reason = event.get('reason', '')

            if 'failed' in message.lower() or 'error' in message.lower():
                # Try to extract webhook name from message
                webhook_name = 'unknown'
                for word in message.split():
                    if 'webhook' in word.lower():
                        webhook_name = word
                        break

                webhook_failures[webhook_name] += 1

        for webhook_name, count in webhook_failures.items():
            if count > 5:
                issues.append(
                    f"Webhook {webhook_name}: {count} recent failures detected in events"
                )
            elif count > 0:
                warnings.append(
                    f"Webhook {webhook_name}: {count} recent failures detected in events"
                )

    return issues, warnings


def format_plain(validating_configs: List[Dict], mutating_configs: List[Dict],
                issues: List[str], warnings: List[str]) -> str:
    """Format output in plain text."""
    lines = []
    lines.append("Kubernetes Webhook Health Check")
    lines.append("=" * 60)
    lines.append("")

    # Summary
    validating_count = len(validating_configs) if validating_configs else 0
    mutating_count = len(mutating_configs) if mutating_configs else 0

    lines.append(f"Webhook Summary:")
    lines.append(f"  Validating webhook configurations: {validating_count}")
    lines.append(f"  Mutating webhook configurations: {mutating_count}")
    lines.append("")

    # List webhooks
    all_configs = [
        ('Validating', config) for config in (validating_configs or [])
    ] + [
        ('Mutating', config) for config in (mutating_configs or [])
    ]

    if all_configs:
        lines.append("Configured Webhooks:")
        for webhook_type, config in all_configs:
            config_name = config.get('metadata', {}).get('name', 'unknown')
            webhooks = config.get('webhooks', [])

            for webhook in webhooks:
                webhook_name = webhook.get('name', 'unknown')
                failure_policy = webhook.get('failurePolicy', 'Fail')
                timeout = webhook.get('timeoutSeconds', 10)

                lines.append(
                    f"  [{webhook_type}] {config_name}/{webhook_name}"
                )
                lines.append(
                    f"    Policy: {failure_policy}, Timeout: {timeout}s"
                )
        lines.append("")

    # Issues and warnings
    if issues:
        lines.append("ISSUES:")
        for issue in issues:
            lines.append(f"  ✗ {issue}")
        lines.append("")

    if warnings:
        lines.append("WARNINGS:")
        for warning in warnings:
            lines.append(f"  ⚠ {warning}")
        lines.append("")

    if not issues and not warnings:
        lines.append("✓ All webhook health checks passed")

    return "\n".join(lines)


def format_json(validating_configs: List[Dict], mutating_configs: List[Dict],
               issues: List[str], warnings: List[str]) -> str:
    """Format output as JSON."""
    webhook_summary = []

    all_configs = [
        ('validating', config) for config in (validating_configs or [])
    ] + [
        ('mutating', config) for config in (mutating_configs or [])
    ]

    for webhook_type, config in all_configs:
        config_name = config.get('metadata', {}).get('name', 'unknown')
        webhooks = config.get('webhooks', [])

        for webhook in webhooks:
            webhook_info = {
                'type': webhook_type,
                'config_name': config_name,
                'name': webhook.get('name', 'unknown'),
                'failure_policy': webhook.get('failurePolicy', 'Fail'),
                'timeout_seconds': webhook.get('timeoutSeconds', 10),
                'side_effects': webhook.get('sideEffects', 'Unknown'),
                'admission_review_versions': webhook.get('admissionReviewVersions', [])
            }

            # Add certificate info if available
            client_config = webhook.get('clientConfig', {})
            ca_bundle = client_config.get('caBundle')
            if ca_bundle:
                cert_info = parse_certificate(ca_bundle)
                if cert_info:
                    webhook_info['certificate'] = {
                        'days_until_expiry': cert_info['days_until_expiry'],
                        'expiry_date': cert_info['expiry_date']
                    }

            webhook_summary.append(webhook_info)

    return json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'summary': {
            'total_webhooks': len(webhook_summary),
            'validating_configs': len(validating_configs) if validating_configs else 0,
            'mutating_configs': len(mutating_configs) if mutating_configs else 0
        },
        'webhooks': webhook_summary,
        'issues': issues,
        'warnings': warnings,
        'healthy': len(issues) == 0
    }, indent=2)


def format_table(validating_configs: List[Dict], mutating_configs: List[Dict],
                issues: List[str], warnings: List[str]) -> str:
    """Format output as a table."""
    lines = []

    # Header
    lines.append("+" + "-" * 98 + "+")
    lines.append("| Kubernetes Webhook Health Check" + " " * 66 + "|")
    lines.append("+" + "-" * 98 + "+")

    # Webhooks table
    all_configs = [
        ('Validating', config) for config in (validating_configs or [])
    ] + [
        ('Mutating', config) for config in (mutating_configs or [])
    ]

    if all_configs:
        lines.append(f"| {'Type':<12} | {'Config/Name':<40} | {'Policy':<10} | {'Timeout':<8} | {'Status':<10} |")
        lines.append("+" + "-" * 98 + "+")

        for webhook_type, config in all_configs:
            config_name = config.get('metadata', {}).get('name', 'unknown')
            webhooks = config.get('webhooks', [])

            for webhook in webhooks:
                webhook_name = webhook.get('name', 'unknown')
                full_name = f"{config_name}/{webhook_name}"[:40]
                failure_policy = webhook.get('failurePolicy', 'Fail')[:10]
                timeout = f"{webhook.get('timeoutSeconds', 10)}s"

                # Determine status
                status = "OK"
                for issue in issues:
                    if full_name in issue:
                        status = "ERROR"
                        break
                if status == "OK":
                    for warning in warnings:
                        if full_name in warning:
                            status = "WARNING"
                            break

                lines.append(
                    f"| {webhook_type:<12} | {full_name:<40} | {failure_policy:<10} | "
                    f"{timeout:<8} | {status:<10} |"
                )

        lines.append("+" + "-" * 98 + "+")

    # Issues and warnings
    if issues or warnings:
        lines.append("| Issues & Warnings" + " " * 80 + "|")
        lines.append("+" + "-" * 98 + "+")

        for issue in issues:
            issue_text = f"ERROR: {issue}"[:96]
            lines.append(f"| {issue_text:<96} |")

        for warning in warnings:
            warning_text = f"WARN: {warning}"[:96]
            lines.append(f"| {warning_text:<96} |")

        lines.append("+" + "-" * 98 + "+")
    else:
        lines.append("| Status: All checks passed" + " " * 71 + "|")
        lines.append("+" + "-" * 98 + "+")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes admission webhook health',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check webhook health with plain output
  %(prog)s

  # JSON output for monitoring systems
  %(prog)s --format json

  # Only show problems
  %(prog)s --warn-only

  # Skip endpoint connectivity checks (faster)
  %(prog)s --no-endpoint-check

  # Check recent webhook failures in events
  %(prog)s --check-events

Exit codes:
  0 - All webhooks healthy and properly configured
  1 - Webhook issues detected
  2 - Usage error or missing dependencies
        """
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues or warnings are detected'
    )
    parser.add_argument(
        '--no-endpoint-check',
        action='store_true',
        help='Skip service endpoint connectivity checks (faster but less thorough)'
    )
    parser.add_argument(
        '--check-events',
        action='store_true',
        help='Check recent cluster events for webhook failures (slower)'
    )

    args = parser.parse_args()

    # Check dependencies
    if not check_kubectl():
        print("Error: kubectl is not available or not configured", file=sys.stderr)
        print("Please install kubectl and configure access to a cluster", file=sys.stderr)
        return 2

    # Gather webhook configurations
    validating_configs = get_validating_webhooks()
    mutating_configs = get_mutating_webhooks()

    # Get events if requested
    events = None
    if args.check_events:
        events = get_recent_events()

    # Analyze health
    issues, warnings = analyze_webhook_health(
        validating_configs or [],
        mutating_configs or [],
        events,
        check_endpoints=not args.no_endpoint_check
    )

    # Format output
    if args.format == 'json':
        output = format_json(validating_configs or [], mutating_configs or [], issues, warnings)
    elif args.format == 'table':
        output = format_table(validating_configs or [], mutating_configs or [], issues, warnings)
    else:
        output = format_plain(validating_configs or [], mutating_configs or [], issues, warnings)

    # Print output (respecting --warn-only)
    if not args.warn_only or issues or warnings:
        print(output)

    # Return appropriate exit code
    if issues:
        return 1
    else:
        return 0


if __name__ == '__main__':
    sys.exit(main())
