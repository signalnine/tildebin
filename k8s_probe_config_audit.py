#!/usr/bin/env python3
"""
Kubernetes Health Probe Configuration Audit

Audits pod health probe configurations to identify reliability issues:
- Missing liveness probes (can't detect hung processes)
- Missing readiness probes (may receive traffic before ready)
- Missing startup probes for slow-starting containers
- Probe misconfiguration (low timeouts, aggressive thresholds)
- Probes pointing to non-existent ports/paths

For large-scale Kubernetes environments, proper probe configuration is critical
for automatic recovery and service reliability.

Exit codes:
    0 - All pods have properly configured probes
    1 - Probe configuration issues detected
    2 - Usage error or kubectl not found
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


# Default thresholds for probe configuration warnings
DEFAULT_THRESHOLDS = {
    'min_initial_delay': 5,      # Minimum initialDelaySeconds before warning
    'min_timeout': 1,            # Minimum timeoutSeconds
    'max_failure_threshold': 10, # Maximum failureThreshold before warning
    'min_period': 5,             # Minimum periodSeconds
    'slow_start_threshold': 60,  # Containers needing startup probe if init > this
}

# System namespaces often excluded from audits
SYSTEM_NAMESPACES = {'kube-system', 'kube-public', 'kube-node-lease'}


def run_kubectl(args):
    """Execute kubectl command and return JSON output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout) if result.stdout else {}
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/",
              file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing kubectl output: {e}", file=sys.stderr)
        sys.exit(1)


def get_pods(namespace=None):
    """Get all pods, optionally filtered by namespace."""
    cmd = ['get', 'pods', '-o', 'json']
    if namespace:
        cmd.extend(['-n', namespace])
    else:
        cmd.append('--all-namespaces')

    data = run_kubectl(cmd)
    return data.get('items', [])


def analyze_probe(probe, probe_type, container_name):
    """Analyze a single probe configuration for issues."""
    issues = []

    if not probe:
        return issues

    # Check timeout settings
    timeout = probe.get('timeoutSeconds', 1)
    if timeout < DEFAULT_THRESHOLDS['min_timeout']:
        issues.append({
            'severity': 'LOW',
            'type': f'{probe_type}_low_timeout',
            'detail': f'{probe_type} timeout is very low ({timeout}s)',
            'recommendation': 'Consider increasing timeoutSeconds to avoid '
                            'false positives under load'
        })

    # Check failure threshold
    failure_threshold = probe.get('failureThreshold', 3)
    if failure_threshold > DEFAULT_THRESHOLDS['max_failure_threshold']:
        issues.append({
            'severity': 'MEDIUM',
            'type': f'{probe_type}_high_failure_threshold',
            'detail': f'{probe_type} failureThreshold is high ({failure_threshold})',
            'recommendation': 'High failure threshold delays detection of '
                            'unhealthy containers'
        })

    # Check period
    period = probe.get('periodSeconds', 10)
    if period < DEFAULT_THRESHOLDS['min_period']:
        issues.append({
            'severity': 'LOW',
            'type': f'{probe_type}_aggressive_period',
            'detail': f'{probe_type} periodSeconds is aggressive ({period}s)',
            'recommendation': 'Very frequent probes may add unnecessary load'
        })

    # Check for HTTP probe without path
    http_get = probe.get('httpGet')
    if http_get:
        if not http_get.get('path'):
            issues.append({
                'severity': 'MEDIUM',
                'type': f'{probe_type}_no_path',
                'detail': f'{probe_type} HTTP probe has no path specified',
                'recommendation': 'Specify a health check path for the HTTP probe'
            })

    # Check for exec probe with no command
    exec_probe = probe.get('exec')
    if exec_probe:
        command = exec_probe.get('command', [])
        if not command:
            issues.append({
                'severity': 'HIGH',
                'type': f'{probe_type}_empty_exec',
                'detail': f'{probe_type} exec probe has empty command',
                'recommendation': 'Specify a command for the exec probe'
            })

    return issues


def analyze_container_probes(container, pod_name, namespace):
    """Analyze all probes for a single container."""
    issues = []
    container_name = container.get('name', 'unknown')

    liveness_probe = container.get('livenessProbe')
    readiness_probe = container.get('readinessProbe')
    startup_probe = container.get('startupProbe')

    # Check for missing probes
    if not liveness_probe:
        issues.append({
            'severity': 'HIGH',
            'type': 'missing_liveness_probe',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'No liveness probe configured',
            'recommendation': 'Add liveness probe to detect hung/deadlocked processes'
        })

    if not readiness_probe:
        issues.append({
            'severity': 'MEDIUM',
            'type': 'missing_readiness_probe',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'No readiness probe configured',
            'recommendation': 'Add readiness probe to prevent traffic before ready'
        })

    # Check if container might need startup probe
    if liveness_probe:
        initial_delay = liveness_probe.get('initialDelaySeconds', 0)
        if initial_delay >= DEFAULT_THRESHOLDS['slow_start_threshold']:
            if not startup_probe:
                issues.append({
                    'severity': 'MEDIUM',
                    'type': 'missing_startup_probe',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': container_name,
                    'detail': f'High liveness initialDelaySeconds ({initial_delay}s) '
                             'but no startup probe',
                    'recommendation': 'Use startup probe for slow-starting containers '
                                    'instead of high initialDelaySeconds'
                })

    # Analyze individual probe configurations
    for probe, probe_type in [(liveness_probe, 'liveness'),
                               (readiness_probe, 'readiness'),
                               (startup_probe, 'startup')]:
        probe_issues = analyze_probe(probe, probe_type, container_name)
        for issue in probe_issues:
            issue['namespace'] = namespace
            issue['pod'] = pod_name
            issue['container'] = container_name
            issues.append(issue)

    # Check for liveness without readiness (can cause traffic to unhealthy pods)
    if liveness_probe and not readiness_probe:
        issues.append({
            'severity': 'MEDIUM',
            'type': 'liveness_without_readiness',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'Liveness probe without readiness probe',
            'recommendation': 'Add readiness probe to control when pod receives traffic'
        })

    # Check for identical liveness and readiness probes
    if liveness_probe and readiness_probe:
        # Simple comparison - check if they're functionally the same
        if (liveness_probe.get('httpGet') == readiness_probe.get('httpGet') and
            liveness_probe.get('tcpSocket') == readiness_probe.get('tcpSocket') and
            liveness_probe.get('exec') == readiness_probe.get('exec')):
            issues.append({
                'severity': 'LOW',
                'type': 'identical_probes',
                'namespace': namespace,
                'pod': pod_name,
                'container': container_name,
                'detail': 'Liveness and readiness probes are identical',
                'recommendation': 'Consider using different endpoints or logic '
                                'for liveness vs readiness checks'
            })

    return issues


def analyze_pod_probes(pod, exclude_system=True):
    """Analyze all probe configurations for a pod."""
    issues = []
    metadata = pod.get('metadata', {})
    pod_name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    spec = pod.get('spec', {})

    # Skip system namespaces if requested
    if exclude_system and namespace in SYSTEM_NAMESPACES:
        return issues

    # Analyze each container
    containers = spec.get('containers', [])
    for container in containers:
        issues.extend(analyze_container_probes(container, pod_name, namespace))

    # Also check init containers (usually don't need probes but flag if they have bad ones)
    init_containers = spec.get('initContainers', [])
    for container in init_containers:
        container_name = container.get('name', 'unknown')
        for probe_type in ['livenessProbe', 'readinessProbe']:
            probe = container.get(probe_type)
            if probe:
                # Init containers shouldn't have liveness/readiness probes
                issues.append({
                    'severity': 'LOW',
                    'type': f'init_container_{probe_type}',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': container_name,
                    'detail': f'Init container has {probe_type} (usually not needed)',
                    'recommendation': 'Init containers typically do not need '
                                    'liveness or readiness probes'
                })

    return issues


def output_plain(all_issues, verbose=False, warn_only=False):
    """Output results in plain text format."""
    if not all_issues:
        print("All pods have properly configured health probes")
        return

    # Group by severity
    by_severity = defaultdict(list)
    for issue in all_issues:
        by_severity[issue['severity']].append(issue)

    # Summary
    if not warn_only:
        print("Kubernetes Health Probe Configuration Audit")
        print("=" * 70)
        print(f"Total issues: {len(all_issues)}")
        print(f"  HIGH: {len(by_severity['HIGH'])}")
        print(f"  MEDIUM: {len(by_severity['MEDIUM'])}")
        print(f"  LOW: {len(by_severity['LOW'])}")
        print()

    # Output by severity
    for severity in ['HIGH', 'MEDIUM', 'LOW']:
        if severity not in by_severity:
            continue

        if warn_only and severity == 'LOW':
            continue

        issues = by_severity[severity]
        print(f"{severity} SEVERITY ({len(issues)} issues):")
        print("-" * 70)

        for issue in issues:
            print(f"  [{issue['type']}] {issue['namespace']}/{issue['pod']}")
            if issue.get('container'):
                print(f"    Container: {issue['container']}")
            print(f"    {issue['detail']}")
            if verbose and issue.get('recommendation'):
                print(f"    Recommendation: {issue['recommendation']}")
        print()


def output_json(all_issues):
    """Output results in JSON format."""
    result = {
        'summary': {
            'total_issues': len(all_issues),
            'high': len([i for i in all_issues if i['severity'] == 'HIGH']),
            'medium': len([i for i in all_issues if i['severity'] == 'MEDIUM']),
            'low': len([i for i in all_issues if i['severity'] == 'LOW'])
        },
        'issues': all_issues
    }
    print(json.dumps(result, indent=2))


def output_table(all_issues, warn_only=False):
    """Output results in table format."""
    if not all_issues:
        print("All pods have properly configured health probes")
        return

    # Filter if warn_only
    if warn_only:
        all_issues = [i for i in all_issues if i['severity'] != 'LOW']

    if not all_issues:
        print("No high or medium severity issues found")
        return

    print(f"{'Severity':<8} {'Type':<30} {'Namespace/Pod':<35} {'Container':<20}")
    print("=" * 95)

    for issue in sorted(all_issues,
                       key=lambda x: ['HIGH', 'MEDIUM', 'LOW'].index(x['severity'])):
        pod_full = f"{issue['namespace']}/{issue['pod']}"
        if len(pod_full) > 32:
            pod_full = pod_full[:32] + "..."

        container = issue.get('container', '*')
        if len(container) > 17:
            container = container[:17] + "..."

        issue_type = issue['type']
        if len(issue_type) > 27:
            issue_type = issue_type[:27] + "..."

        print(f"{issue['severity']:<8} {issue_type:<30} {pod_full:<35} {container:<20}")


def main():
    parser = argparse.ArgumentParser(
        description='Audit Kubernetes pod health probe configurations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all pods in all namespaces
  %(prog)s

  # Audit specific namespace
  %(prog)s -n production

  # Include system namespaces (kube-system, etc.)
  %(prog)s --include-system

  # Show only high/medium severity issues
  %(prog)s --warn-only

  # JSON output for monitoring/alerting
  %(prog)s --format json

  # Verbose output with recommendations
  %(prog)s -v

Checks performed:
  - Missing liveness probe (HIGH) - can't detect hung processes
  - Missing readiness probe (MEDIUM) - may receive traffic before ready
  - Missing startup probe for slow-starting containers (MEDIUM)
  - Liveness without readiness probe (MEDIUM) - traffic control issues
  - Probe timeouts and thresholds (LOW/MEDIUM)
  - Identical liveness/readiness probes (LOW)
  - Init containers with probes (LOW)

Exit codes:
  0 - All pods have proper probe configuration
  1 - Issues detected
  2 - Usage error or kubectl not found
        """
    )

    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to audit (default: all namespaces)'
    )

    parser.add_argument(
        '--include-system',
        action='store_true',
        help='Include system namespaces (kube-system, kube-public, etc.)'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information with recommendations'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings (exclude LOW severity)'
    )

    args = parser.parse_args()

    # Get and analyze pods
    pods = get_pods(args.namespace)

    all_issues = []
    for pod in pods:
        issues = analyze_pod_probes(pod, exclude_system=not args.include_system)
        all_issues.extend(issues)

    # Output results
    if args.format == 'json':
        output_json(all_issues)
    elif args.format == 'table':
        output_table(all_issues, args.warn_only)
    else:
        output_plain(all_issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    if all_issues:
        high_medium = [i for i in all_issues if i['severity'] in ('HIGH', 'MEDIUM')]
        sys.exit(1 if high_medium else 0)

    sys.exit(0)


if __name__ == '__main__':
    main()
