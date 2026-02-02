#!/usr/bin/env python3
# boxctl:
#   category: baremetal/systemd
#   tags: [systemd, security, hardening, audit, sandbox]
#   requires: [systemd-analyze]
#   privilege: none
#   related: [systemd_deps, systemd_service_monitor, sysctl_security_audit]
#   brief: Scan systemd service units for security configuration issues

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
"""

import argparse
import re
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_security_overview(output_text: str) -> list[dict[str, Any]]:
    """Parse systemd-analyze security output for all services."""
    results = []
    lines = output_text.strip().split('\n')

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


def parse_service_security(output_text: str, service: str) -> dict[str, Any]:
    """Parse detailed security analysis for a single service."""
    result = {
        'service': service,
        'exposure': None,
        'rating': None,
        'findings': [],
    }

    lines = output_text.strip().split('\n')

    for line in lines:
        line = line.strip()

        # Parse the overall exposure line
        if line.startswith('\u2192') and 'Overall exposure' in line:
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

        # Parse individual findings
        elif '\u2717' in line or '\u2713' in line or '\u25cb' in line:
            parts = line.split(None, 2)
            if len(parts) >= 2:
                status = parts[0]
                name = parts[1] if len(parts) > 1 else ''
                description = parts[2] if len(parts) > 2 else ''

                if '\u2717' in status:  # Cross mark - bad
                    result['findings'].append({
                        'status': 'bad',
                        'name': name.rstrip('='),
                        'description': description
                    })
                elif '\u25cb' in status:  # Circle - neutral
                    result['findings'].append({
                        'status': 'neutral',
                        'name': name.rstrip('='),
                        'description': description
                    })

    return result


def get_rating_from_score(score: float) -> str:
    """Convert numeric score to rating."""
    if score <= 2.0:
        return 'OK'
    elif score <= 4.5:
        return 'MEDIUM'
    elif score <= 6.5:
        return 'EXPOSED'
    else:
        return 'UNSAFE'


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
        description="Scan systemd service units for security configuration issues"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show additional details")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-t", "--threshold", type=float, default=6.5,
                        help="Exposure score threshold for warnings (default: 6.5)")
    parser.add_argument("-s", "--service",
                        help="Analyze specific service (shows detailed findings)")
    opts = parser.parse_args(args)

    # Check for systemd-analyze
    if not context.check_tool("systemd-analyze"):
        output.error("systemd-analyze not found")
        return 2

    # Check if security subcommand is available
    result = context.run(['systemd-analyze', 'security', '--help'], check=False)
    if result.returncode != 0:
        output.error("systemd-analyze security not available (requires systemd 239+)")
        return 2

    # Handle single service analysis
    if opts.service:
        result = context.run(
            ['systemd-analyze', 'security', '--no-pager', opts.service],
            check=False
        )
        if result.returncode != 0:
            output.error(f"Could not analyze {opts.service}")
            return 1

        analysis = parse_service_security(result.stdout, opts.service)

        output.emit({
            'service': analysis['service'],
            'exposure': analysis['exposure'],
            'rating': analysis['rating'],
            'findings': analysis['findings'] if opts.verbose else [],
            'findings_count': len([f for f in analysis['findings'] if f['status'] == 'bad']),
        })

        if analysis['exposure'] is not None:
            output.set_summary(f"{opts.service}: {analysis['exposure']:.1f} ({analysis['rating']})")
        else:
            output.set_summary(f"{opts.service}: analysis failed")

        return 0 if analysis['exposure'] is not None and analysis['exposure'] <= opts.threshold else 1

    # Get all service security scores
    result = context.run(['systemd-analyze', 'security', '--no-pager'], check=False)
    if result.returncode != 0:
        output.error("Failed to run systemd-analyze security")
        return 2

    services = parse_security_overview(result.stdout)

    if not services:
        output.error("No services found to analyze")
        return 1

    # Filter and sort services
    services_above_threshold = [s for s in services if s['exposure'] is not None and s['exposure'] > opts.threshold]
    services_sorted = sorted(services, key=lambda x: x.get('exposure') or 0, reverse=True)

    # Build output
    output_data = {
        'threshold': opts.threshold,
        'total_services': len(services),
        'services_above_threshold': len(services_above_threshold),
        'services': services_sorted,
        'by_rating': {
            'UNSAFE': len([s for s in services if s.get('rating') == 'UNSAFE']),
            'EXPOSED': len([s for s in services if s.get('rating') == 'EXPOSED']),
            'MEDIUM': len([s for s in services if s.get('rating') == 'MEDIUM']),
            'OK': len([s for s in services if s.get('rating') == 'OK']),
        }
    }

    output.emit(output_data)

    # Set summary
    if services_above_threshold:
        output.set_summary(f"{len(services_above_threshold)}/{len(services)} services above threshold {opts.threshold}")
    else:
        output.set_summary(f"All {len(services)} services within threshold")

    # Exit code based on threshold
    return 1 if services_above_threshold else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
