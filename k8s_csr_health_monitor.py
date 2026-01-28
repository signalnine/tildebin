#!/usr/bin/env python3
"""
Monitor Kubernetes CertificateSigningRequest (CSR) health and approval status.

Analyzes CSRs in the cluster to detect:
- Pending CSRs that haven't been approved/denied (potential stuck requests)
- Denied CSRs that may indicate configuration issues
- CSR approval latency (time from creation to approval)
- CSR age distribution for capacity planning
- Failed or expired CSRs

CertificateSigningRequests are critical for:
- Node bootstrap (kubelet certificate requests)
- cert-manager certificate issuance
- Service mesh mTLS certificate rotation
- Custom certificate workflows

Exit codes:
    0 - All CSRs healthy, no pending requests beyond threshold
    1 - Issues detected (long-pending, denied, or failed CSRs)
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional


def run_kubectl(args: List[str]) -> str:
    """Execute kubectl command and return output."""
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


def get_csrs() -> List[Dict[str, Any]]:
    """Get all CertificateSigningRequests in JSON format."""
    output = run_kubectl(['get', 'csr', '-o', 'json'])
    data = json.loads(output)
    return data.get('items', [])


def parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse Kubernetes timestamp to datetime object."""
    if not ts_str:
        return None
    try:
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        return datetime.fromisoformat(ts_str)
    except (ValueError, AttributeError):
        return None


def get_csr_status(csr: Dict[str, Any]) -> str:
    """Determine the status of a CSR from its conditions."""
    conditions = csr.get('status', {}).get('conditions', [])

    if not conditions:
        return 'Pending'

    for condition in conditions:
        cond_type = condition.get('type', '')
        if cond_type == 'Approved':
            return 'Approved'
        elif cond_type == 'Denied':
            return 'Denied'
        elif cond_type == 'Failed':
            return 'Failed'

    return 'Pending'


def get_approval_time(csr: Dict[str, Any]) -> Optional[datetime]:
    """Get the time when the CSR was approved/denied."""
    conditions = csr.get('status', {}).get('conditions', [])

    for condition in conditions:
        last_update = condition.get('lastUpdateTime')
        if last_update:
            return parse_timestamp(last_update)

    return None


def analyze_csr(csr: Dict[str, Any],
                pending_warn_minutes: int = 10,
                pending_critical_minutes: int = 60) -> Dict[str, Any]:
    """Analyze a single CSR for issues."""
    metadata = csr.get('metadata', {})
    spec = csr.get('spec', {})

    name = metadata.get('name', 'unknown')
    creation_time = parse_timestamp(metadata.get('creationTimestamp'))

    now = datetime.now(timezone.utc)
    age_minutes = None
    if creation_time:
        age_minutes = (now - creation_time).total_seconds() / 60

    status = get_csr_status(csr)
    approval_time = get_approval_time(csr)

    # Calculate approval latency if approved
    approval_latency_seconds = None
    if status == 'Approved' and creation_time and approval_time:
        approval_latency_seconds = (approval_time - creation_time).total_seconds()

    result = {
        'name': name,
        'status': status,
        'signer_name': spec.get('signerName', 'unknown'),
        'username': spec.get('username', 'unknown'),
        'creation_time': creation_time.isoformat() if creation_time else None,
        'age_minutes': round(age_minutes, 1) if age_minutes else None,
        'approval_latency_seconds': round(approval_latency_seconds, 1) if approval_latency_seconds else None,
        'has_certificate': bool(csr.get('status', {}).get('certificate')),
        'has_issue': False,
        'severity': 'ok',
        'issues': [],
    }

    # Check for issues
    if status == 'Pending':
        if age_minutes and age_minutes > pending_critical_minutes:
            result['issues'].append(
                f"CSR pending for {int(age_minutes)} minutes (critical threshold: {pending_critical_minutes}min)"
            )
            result['has_issue'] = True
            result['severity'] = 'critical'
        elif age_minutes and age_minutes > pending_warn_minutes:
            result['issues'].append(
                f"CSR pending for {int(age_minutes)} minutes (warn threshold: {pending_warn_minutes}min)"
            )
            result['has_issue'] = True
            result['severity'] = 'warning'

    elif status == 'Denied':
        result['issues'].append("CSR was denied")
        result['has_issue'] = True
        result['severity'] = 'warning'

        # Get denial reason if available
        conditions = csr.get('status', {}).get('conditions', [])
        for condition in conditions:
            if condition.get('type') == 'Denied':
                reason = condition.get('reason', '')
                message = condition.get('message', '')
                if reason or message:
                    result['issues'].append(f"Reason: {reason} - {message}")

    elif status == 'Failed':
        result['issues'].append("CSR failed")
        result['has_issue'] = True
        result['severity'] = 'critical'

        # Get failure reason if available
        conditions = csr.get('status', {}).get('conditions', [])
        for condition in conditions:
            if condition.get('type') == 'Failed':
                reason = condition.get('reason', '')
                message = condition.get('message', '')
                if reason or message:
                    result['issues'].append(f"Reason: {reason} - {message}")

    elif status == 'Approved' and not result['has_certificate']:
        # Approved but no certificate issued yet
        if age_minutes and age_minutes > pending_warn_minutes:
            result['issues'].append(
                f"CSR approved but certificate not yet issued ({int(age_minutes)} minutes)"
            )
            result['has_issue'] = True
            result['severity'] = 'warning'

    return result


def format_duration(minutes: Optional[float]) -> str:
    """Format duration in minutes to human-readable string."""
    if minutes is None:
        return 'N/A'

    if minutes < 1:
        return f"{int(minutes * 60)}s"
    elif minutes < 60:
        return f"{int(minutes)}m"
    elif minutes < 1440:
        return f"{minutes / 60:.1f}h"
    else:
        return f"{minutes / 1440:.1f}d"


def output_plain(csrs_data: List[Dict], warn_only: bool, verbose: bool):
    """Plain text output."""
    if warn_only:
        csrs_data = [c for c in csrs_data if c.get('has_issue')]

    if not csrs_data:
        if warn_only:
            print("No CSR issues detected")
        else:
            print("No CSRs found")
        return

    # Group by severity
    critical = [c for c in csrs_data if c.get('severity') == 'critical']
    warning = [c for c in csrs_data if c.get('severity') == 'warning']
    ok = [c for c in csrs_data if c.get('severity') == 'ok']

    # Group by status for summary
    pending = [c for c in csrs_data if c.get('status') == 'Pending']
    approved = [c for c in csrs_data if c.get('status') == 'Approved']
    denied = [c for c in csrs_data if c.get('status') == 'Denied']
    failed = [c for c in csrs_data if c.get('status') == 'Failed']

    if critical:
        print("=== CRITICAL ===")
        for csr in critical:
            print(f"[CRITICAL] {csr['name']}")
            print(f"  Status: {csr['status']} | Age: {format_duration(csr.get('age_minutes'))}")
            print(f"  Signer: {csr['signer_name']}")
            print(f"  Username: {csr['username']}")
            for issue in csr.get('issues', []):
                print(f"  Issue: {issue}")
            print()

    if warning:
        print("=== WARNINGS ===")
        for csr in warning:
            print(f"[WARNING] {csr['name']}")
            print(f"  Status: {csr['status']} | Age: {format_duration(csr.get('age_minutes'))}")
            print(f"  Signer: {csr['signer_name']}")
            for issue in csr.get('issues', []):
                print(f"  Issue: {issue}")
            print()

    if ok and not warn_only:
        print("=== OK ===")
        for csr in ok:
            age_str = format_duration(csr.get('age_minutes'))
            latency = csr.get('approval_latency_seconds')
            latency_str = f", latency: {latency}s" if latency else ""
            print(f"[OK] {csr['name']} ({csr['status']}, age: {age_str}{latency_str})")
            if verbose:
                print(f"     Signer: {csr['signer_name']}")
                print(f"     Username: {csr['username']}")
        print()

    # Print summary
    print("=== SUMMARY ===")
    print(f"Total CSRs: {len(csrs_data)}")
    print(f"  Pending: {len(pending)}")
    print(f"  Approved: {len(approved)}")
    print(f"  Denied: {len(denied)}")
    print(f"  Failed: {len(failed)}")

    # Calculate average approval latency for approved CSRs
    latencies = [c['approval_latency_seconds'] for c in approved if c.get('approval_latency_seconds')]
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)
        print(f"Approval latency: avg={avg_latency:.1f}s, max={max_latency:.1f}s")


def output_json(csrs_data: List[Dict], warn_only: bool, verbose: bool):
    """JSON output."""
    if warn_only:
        csrs_data = [c for c in csrs_data if c.get('has_issue')]

    # Calculate statistics
    pending = [c for c in csrs_data if c.get('status') == 'Pending']
    approved = [c for c in csrs_data if c.get('status') == 'Approved']
    denied = [c for c in csrs_data if c.get('status') == 'Denied']
    failed = [c for c in csrs_data if c.get('status') == 'Failed']

    latencies = [c['approval_latency_seconds'] for c in approved if c.get('approval_latency_seconds')]

    summary = {
        'total': len(csrs_data),
        'by_status': {
            'pending': len(pending),
            'approved': len(approved),
            'denied': len(denied),
            'failed': len(failed),
        },
        'by_severity': {
            'critical': sum(1 for c in csrs_data if c.get('severity') == 'critical'),
            'warning': sum(1 for c in csrs_data if c.get('severity') == 'warning'),
            'ok': sum(1 for c in csrs_data if c.get('severity') == 'ok'),
        },
        'approval_latency': {
            'avg_seconds': round(sum(latencies) / len(latencies), 1) if latencies else None,
            'max_seconds': round(max(latencies), 1) if latencies else None,
            'min_seconds': round(min(latencies), 1) if latencies else None,
        } if latencies else None
    }

    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'summary': summary,
        'csrs': csrs_data,
    }

    print(json.dumps(output, indent=2))


def output_table(csrs_data: List[Dict], warn_only: bool, verbose: bool):
    """Tabular output."""
    if warn_only:
        csrs_data = [c for c in csrs_data if c.get('has_issue')]

    if not csrs_data:
        print("No CSRs to display")
        return

    # Header
    print(f"{'Severity':<10} {'Name':<50} {'Status':<10} {'Age':<8} {'Signer':<40}")
    print("=" * 120)

    # Sort by severity (critical first)
    severity_order = {'critical': 0, 'warning': 1, 'ok': 2}
    csrs_data.sort(key=lambda c: severity_order.get(c.get('severity', 'ok'), 3))

    for csr in csrs_data:
        severity = csr.get('severity', 'ok').upper()
        name = csr['name'][:49]
        status = csr['status']
        age = format_duration(csr.get('age_minutes'))
        signer = csr['signer_name'][:39]

        print(f"{severity:<10} {name:<50} {status:<10} {age:<8} {signer:<40}")

    # Summary
    critical_count = sum(1 for c in csrs_data if c.get('severity') == 'critical')
    warning_count = sum(1 for c in csrs_data if c.get('severity') == 'warning')
    pending_count = sum(1 for c in csrs_data if c.get('status') == 'Pending')
    print()
    print(f"Total: {len(csrs_data)} | Critical: {critical_count} | Warning: {warning_count} | Pending: {pending_count}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes CertificateSigningRequest health and approval status",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all CSRs in the cluster
  %(prog)s

  # Show only CSRs with issues
  %(prog)s --warn-only

  # Custom pending thresholds (5 min warn, 30 min critical)
  %(prog)s --pending-warn 5 --pending-critical 30

  # JSON output for automation
  %(prog)s --format json

  # Table output with details
  %(prog)s --format table --verbose

Exit codes:
  0 - All CSRs healthy, no pending beyond threshold
  1 - Issues detected (long-pending, denied, or failed CSRs)
  2 - Usage error or kubectl not available
        """
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
        help='Only show CSRs with issues'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    parser.add_argument(
        '--pending-warn',
        type=int,
        default=10,
        metavar='MINUTES',
        help='Minutes pending before warning (default: %(default)s)'
    )

    parser.add_argument(
        '--pending-critical',
        type=int,
        default=60,
        metavar='MINUTES',
        help='Minutes pending before critical (default: %(default)s)'
    )

    args = parser.parse_args()

    # Get CSRs
    csrs = get_csrs()

    # Analyze each CSR
    csrs_data = [
        analyze_csr(
            csr,
            pending_warn_minutes=args.pending_warn,
            pending_critical_minutes=args.pending_critical
        )
        for csr in csrs
    ]

    # Output results
    if args.format == 'json':
        output_json(csrs_data, args.warn_only, args.verbose)
    elif args.format == 'table':
        output_table(csrs_data, args.warn_only, args.verbose)
    else:
        output_plain(csrs_data, args.warn_only, args.verbose)

    # Determine exit code
    has_issues = any(c.get('has_issue') for c in csrs_data)
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
