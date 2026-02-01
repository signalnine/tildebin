#!/usr/bin/env python3
"""
Scan systemd service units for security configuration issues.

This script wraps `systemd-analyze security` to audit service hardening and
identify units with poor security posture. It helps administrators:

- Identify services lacking sandboxing (PrivateTmp, ProtectSystem, etc.)
- Find services running with excessive privileges
- Detect units missing recommended hardening options
- Prioritize security improvements by exposure score
- Track security posture improvements over time

The exposure score (0.0-10.0) indicates how exposed a service is:
- 0.0-2.0: Well hardened (OK)
- 2.1-4.5: Moderate exposure (MEDIUM)
- 4.6-6.5: Elevated exposure (EXPOSED)
- 6.6-10.0: High exposure (UNSAFE)

Exit codes:
    0 - All services within acceptable thresholds
    1 - Services found with exposure above threshold
    2 - Missing systemd-analyze or usage error
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


def run_command(cmd):
    """Execute a command and return output."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}"
    except Exception as e:
        return -1, "", str(e)


def check_systemd_analyze_available():
    """Check if systemd-analyze is available and supports security subcommand."""
    returncode, stdout, stderr = run_command(['systemd-analyze', '--version'])
    if returncode != 0:
        return False, "systemd-analyze not found"

    # Check if security subcommand is available (systemd 239+)
    returncode, _, stderr = run_command(['systemd-analyze', 'security', '--help'])
    if returncode != 0:
        return False, "systemd-analyze security not available (requires systemd 239+)"

    return True, None


def get_service_list():
    """Get list of active service units."""
    returncode, stdout, _ = run_command([
        'systemctl', 'list-units', '--type=service', '--state=active',
        '--no-legend', '--no-pager', '--plain'
    ])

    if returncode != 0:
        return []

    services = []
    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split()
        if parts:
            service = parts[0]
            if service.endswith('.service'):
                services.append(service)

    return services


def analyze_service_security(service):
    """Analyze security of a single service unit."""
    returncode, stdout, stderr = run_command([
        'systemd-analyze', 'security', '--no-pager', service
    ])

    if returncode != 0:
        return None

    # Parse the output - last line contains overall score
    lines = stdout.strip().split('\n')

    result = {
        'service': service,
        'exposure': None,
        'rating': None,
        'findings': [],
    }

    for line in lines:
        line = line.strip()

        # Parse the overall exposure line
        # Format: "→ Overall exposure level for xxx.service: X.X RATING"
        if line.startswith('→') and 'Overall exposure' in line:
            parts = line.split(':')
            if len(parts) >= 2:
                score_part = parts[1].strip()
                score_parts = score_part.split()
                if score_parts:
                    try:
                        result['exposure'] = float(score_parts[0])
                        if len(score_parts) >= 2:
                            result['rating'] = score_parts[1]
                    except ValueError:
                        pass

        # Parse individual findings (lines with ✓, ✗, or other indicators)
        elif '✗' in line or '✓' in line or '○' in line:
            # Extract the finding details
            parts = line.split(None, 2)
            if len(parts) >= 2:
                status = parts[0]
                name = parts[1] if len(parts) > 1 else ''
                description = parts[2] if len(parts) > 2 else ''

                if '✗' in status:
                    result['findings'].append({
                        'status': 'bad',
                        'name': name.rstrip('='),
                        'description': description
                    })
                elif '○' in status:
                    result['findings'].append({
                        'status': 'neutral',
                        'name': name.rstrip('='),
                        'description': description
                    })

    return result


def get_all_security_scores():
    """Get security scores for all active services."""
    # Use systemd-analyze security without arguments for overview
    returncode, stdout, stderr = run_command([
        'systemd-analyze', 'security', '--no-pager'
    ])

    if returncode != 0:
        return []

    results = []
    lines = stdout.strip().split('\n')

    # Skip header line
    for line in lines[1:]:
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 3:
            service = parts[0]
            try:
                exposure = float(parts[1])
                rating = parts[2] if len(parts) > 2 else 'UNKNOWN'

                results.append({
                    'service': service,
                    'exposure': exposure,
                    'rating': rating,
                })
            except ValueError:
                continue

    return results


def get_rating_from_score(score):
    """Convert numeric score to rating."""
    if score <= 2.0:
        return 'OK'
    elif score <= 4.5:
        return 'MEDIUM'
    elif score <= 6.5:
        return 'EXPOSED'
    else:
        return 'UNSAFE'


def filter_services(services, threshold, warn_only):
    """Filter services based on threshold and warn_only flag."""
    if warn_only:
        return [s for s in services if s['exposure'] is not None and s['exposure'] > threshold]
    return services


def output_plain(services, threshold, verbose=False):
    """Output results in plain text format."""
    if not services:
        print("No services to analyze")
        return

    # Sort by exposure score descending
    services = sorted(services, key=lambda x: x.get('exposure') or 0, reverse=True)

    warnings = [s for s in services if s.get('exposure') is not None and s['exposure'] > threshold]

    if verbose:
        print(f"Systemd Service Security Scan")
        print(f"Threshold: {threshold}")
        print(f"Services analyzed: {len(services)}")
        print(f"Services above threshold: {len(warnings)}")
        print()

    print(f"{'SERVICE':<45} {'SCORE':>6} {'RATING':<10}")
    print("-" * 65)

    for svc in services:
        service = svc.get('service', 'unknown')
        exposure = svc.get('exposure')
        rating = svc.get('rating', 'UNKNOWN')

        if exposure is None:
            score_str = 'N/A'
        else:
            score_str = f"{exposure:.1f}"

        # Truncate service name if too long
        if len(service) > 44:
            service = service[:41] + '...'

        # Mark services above threshold
        marker = '*' if exposure is not None and exposure > threshold else ' '
        print(f"{marker}{service:<44} {score_str:>6} {rating:<10}")

    if warnings:
        print()
        print(f"* {len(warnings)} service(s) above threshold ({threshold})")


def output_json(services, threshold):
    """Output results in JSON format."""
    output = {
        'threshold': threshold,
        'total_services': len(services),
        'services_above_threshold': len([s for s in services if s.get('exposure') is not None and s['exposure'] > threshold]),
        'services': sorted(services, key=lambda x: x.get('exposure') or 0, reverse=True)
    }
    print(json.dumps(output, indent=2))


def output_table(services, threshold):
    """Output results in compact table format."""
    # Group by rating
    by_rating = defaultdict(list)
    for svc in services:
        rating = svc.get('rating', 'UNKNOWN')
        by_rating[rating].append(svc)

    print(f"{'RATING':<10} {'COUNT':>6} {'SERVICES'}")
    print("-" * 60)

    for rating in ['UNSAFE', 'EXPOSED', 'MEDIUM', 'OK', 'UNKNOWN']:
        if rating in by_rating:
            count = len(by_rating[rating])
            services_list = ', '.join(s['service'].replace('.service', '') for s in by_rating[rating][:5])
            if len(by_rating[rating]) > 5:
                services_list += f', ... (+{len(by_rating[rating]) - 5} more)'
            print(f"{rating:<10} {count:>6} {services_list}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Scan systemd service units for security configuration issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Scan all active services
  %(prog)s --threshold 5.0        # Flag services with score > 5.0
  %(prog)s --warn-only            # Only show services above threshold
  %(prog)s --service sshd.service # Scan specific service with details
  %(prog)s --format json          # JSON output for automation

Security Ratings:
  OK      (0.0-2.0)  - Well hardened service
  MEDIUM  (2.1-4.5)  - Moderate exposure, consider hardening
  EXPOSED (4.6-6.5)  - Elevated exposure, should be hardened
  UNSAFE  (6.6-10.0) - High exposure, needs immediate attention

Exit codes:
  0 - All services within threshold
  1 - Services found above threshold
  2 - Missing systemd-analyze or usage error
"""
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=6.5,
        help="Exposure score threshold for warnings (default: %(default)s)"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show services above threshold"
    )

    parser.add_argument(
        "-s", "--service",
        help="Analyze specific service (shows detailed findings)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show additional details"
    )

    args = parser.parse_args()

    # Check for systemd-analyze
    available, error = check_systemd_analyze_available()
    if not available:
        print(f"Error: {error}", file=sys.stderr)
        print("Install systemd or upgrade to version 239+", file=sys.stderr)
        sys.exit(2)

    # Handle single service analysis
    if args.service:
        result = analyze_service_security(args.service)
        if result is None:
            print(f"Error: Could not analyze {args.service}", file=sys.stderr)
            sys.exit(1)

        if args.format == 'json':
            print(json.dumps(result, indent=2))
        else:
            print(f"Service: {result['service']}")
            print(f"Exposure Score: {result['exposure']}")
            print(f"Rating: {result['rating']}")
            if result['findings'] and args.verbose:
                print("\nFindings (issues):")
                for f in result['findings']:
                    if f['status'] == 'bad':
                        print(f"  ✗ {f['name']}: {f['description']}")

        sys.exit(0 if result['exposure'] is not None and result['exposure'] <= args.threshold else 1)

    # Get all service security scores
    services = get_all_security_scores()

    if not services:
        print("No services found to analyze", file=sys.stderr)
        sys.exit(1)

    # Filter if warn-only
    display_services = filter_services(services, args.threshold, args.warn_only)

    # Output results
    if args.format == 'json':
        output_json(display_services, args.threshold)
    elif args.format == 'table':
        output_table(display_services, args.threshold)
    else:
        output_plain(display_services, args.threshold, args.verbose)

    # Exit code based on threshold
    warnings = [s for s in services if s.get('exposure') is not None and s['exposure'] > args.threshold]
    sys.exit(1 if warnings else 0)


if __name__ == "__main__":
    main()
