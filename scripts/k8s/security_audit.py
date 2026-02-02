#!/usr/bin/env python3
# boxctl:
#   category: k8s/security
#   tags: [security, audit, capabilities, privileged, kubernetes]
#   requires: [kubectl]
#   brief: Audit pod security contexts and capabilities
#   privilege: user
#   related: [image_registry, annotation_audit]

"""
Kubernetes Pod Security Context Audit

Audits pod security contexts and Linux capabilities to identify security risks:
- Privileged containers (full host access)
- Containers running as root (UID 0)
- Dangerous Linux capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.)
- Missing readOnlyRootFilesystem
- Host namespace sharing (hostPID, hostIPC, hostNetwork)
- Missing security profiles (AppArmor, Seccomp)
- Containers that can escalate privileges

Exit codes:
    0 - No critical security issues detected
    1 - Security issues or warnings found
    2 - Usage error or kubectl not found
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


# Capabilities that are considered dangerous
DANGEROUS_CAPS = {
    'CAP_SYS_ADMIN': 'CRITICAL',   # Near-root privileges, container escape risk
    'CAP_NET_ADMIN': 'HIGH',       # Network configuration, sniffing
    'CAP_SYS_PTRACE': 'HIGH',      # Process tracing, container escape risk
    'CAP_SYS_MODULE': 'CRITICAL',  # Load kernel modules
    'CAP_SYS_RAWIO': 'CRITICAL',   # Raw I/O access
    'CAP_SYS_BOOT': 'HIGH',        # Reboot system
    'CAP_NET_RAW': 'MEDIUM',       # Raw network sockets
    'CAP_DAC_OVERRIDE': 'MEDIUM',  # Bypass file permissions
    'CAP_SETUID': 'MEDIUM',        # Change UID
    'CAP_SETGID': 'MEDIUM',        # Change GID
    'CAP_FOWNER': 'MEDIUM',        # Bypass file ownership
    'ALL': 'CRITICAL',             # All capabilities
}


def check_container_security(container: dict, pod_name: str, namespace: str, pod_spec: dict) -> list:
    """Check a container's security context for issues."""
    issues = []
    container_name = container.get('name', 'unknown')
    sec_ctx = container.get('securityContext', {})
    pod_sec_ctx = pod_spec.get('securityContext', {})

    # Check privileged mode
    if sec_ctx.get('privileged', False):
        issues.append({
            'severity': 'CRITICAL',
            'type': 'privileged_container',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'Container runs in privileged mode (full host access)'
        })

    # Check if running as root
    run_as_user = sec_ctx.get('runAsUser', pod_sec_ctx.get('runAsUser'))
    run_as_non_root = sec_ctx.get('runAsNonRoot', pod_sec_ctx.get('runAsNonRoot', False))

    if run_as_user == 0:
        issues.append({
            'severity': 'HIGH',
            'type': 'root_user',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'Container explicitly runs as root (UID 0)'
        })
    elif not run_as_non_root and run_as_user is None:
        issues.append({
            'severity': 'MEDIUM',
            'type': 'no_run_as_non_root',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'runAsNonRoot not set - container may run as root'
        })

    # Check privilege escalation
    allow_priv_esc = sec_ctx.get('allowPrivilegeEscalation')
    if allow_priv_esc is True:
        issues.append({
            'severity': 'HIGH',
            'type': 'allow_privilege_escalation',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'allowPrivilegeEscalation is enabled'
        })
    elif allow_priv_esc is None and not sec_ctx.get('privileged', False):
        # Default is true unless privileged is false
        issues.append({
            'severity': 'LOW',
            'type': 'default_privilege_escalation',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'allowPrivilegeEscalation not explicitly disabled'
        })

    # Check capabilities
    capabilities = sec_ctx.get('capabilities', {})
    added_caps = capabilities.get('add', [])

    for cap in added_caps:
        cap_upper = cap.upper()
        # Handle both 'CAP_' prefixed and non-prefixed
        cap_check = cap_upper if cap_upper.startswith('CAP_') else f'CAP_{cap_upper}'

        if cap_check in DANGEROUS_CAPS or cap_upper in DANGEROUS_CAPS:
            severity = DANGEROUS_CAPS.get(cap_check, DANGEROUS_CAPS.get(cap_upper, 'MEDIUM'))
            issues.append({
                'severity': severity,
                'type': 'dangerous_capability',
                'namespace': namespace,
                'pod': pod_name,
                'container': container_name,
                'detail': f'Dangerous capability added: {cap}'
            })

    # Check readOnlyRootFilesystem
    if not sec_ctx.get('readOnlyRootFilesystem', False):
        issues.append({
            'severity': 'LOW',
            'type': 'writable_root_fs',
            'namespace': namespace,
            'pod': pod_name,
            'container': container_name,
            'detail': 'readOnlyRootFilesystem not set - container can modify filesystem'
        })

    return issues


def check_pod_security(pod: dict) -> list:
    """Check a pod's security configuration for issues."""
    issues = []
    metadata = pod.get('metadata', {})
    pod_name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')
    annotations = metadata.get('annotations', {})
    spec = pod.get('spec', {})

    # Check host namespaces
    if spec.get('hostPID', False):
        issues.append({
            'severity': 'CRITICAL',
            'type': 'host_pid',
            'namespace': namespace,
            'pod': pod_name,
            'container': '*',
            'detail': 'Pod shares host PID namespace (can see/signal host processes)'
        })

    if spec.get('hostIPC', False):
        issues.append({
            'severity': 'HIGH',
            'type': 'host_ipc',
            'namespace': namespace,
            'pod': pod_name,
            'container': '*',
            'detail': 'Pod shares host IPC namespace'
        })

    if spec.get('hostNetwork', False):
        issues.append({
            'severity': 'HIGH',
            'type': 'host_network',
            'namespace': namespace,
            'pod': pod_name,
            'container': '*',
            'detail': 'Pod uses host network namespace'
        })

    # Check security profiles (AppArmor, Seccomp)
    has_apparmor = any(k.startswith('container.apparmor.security.beta.kubernetes.io/')
                       for k in annotations.keys())

    seccomp_profile = spec.get('securityContext', {}).get('seccompProfile')
    has_seccomp = seccomp_profile is not None

    if not has_apparmor and not has_seccomp:
        issues.append({
            'severity': 'LOW',
            'type': 'no_security_profile',
            'namespace': namespace,
            'pod': pod_name,
            'container': '*',
            'detail': 'No AppArmor or Seccomp security profile configured'
        })

    # Check host path volumes
    volumes = spec.get('volumes', [])
    for volume in volumes:
        host_path = volume.get('hostPath')
        if host_path:
            path = host_path.get('path', '')

            # Critical paths
            critical_paths = ['/', '/etc', '/var', '/root', '/home', '/proc', '/sys']
            is_critical = any(path == cp or path.startswith(cp + '/') for cp in critical_paths)

            if is_critical:
                issues.append({
                    'severity': 'HIGH',
                    'type': 'sensitive_host_path',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': '*',
                    'detail': f'hostPath volume mounts sensitive path: {path}'
                })
            else:
                issues.append({
                    'severity': 'MEDIUM',
                    'type': 'host_path_volume',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': '*',
                    'detail': f'hostPath volume mounted: {path}'
                })

    # Check containers
    containers = spec.get('containers', [])
    init_containers = spec.get('initContainers', [])

    for container in containers + init_containers:
        issues.extend(check_container_security(container, pod_name, namespace, spec))

    return issues


def output_plain(all_issues: list, verbose: bool = False, warn_only: bool = False) -> None:
    """Output results in plain text format."""
    if not all_issues:
        if not warn_only:
            print("No pod security issues detected")
        return

    # Group by severity
    by_severity = defaultdict(list)
    for issue in all_issues:
        by_severity[issue['severity']].append(issue)

    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if severity not in by_severity:
            continue

        if warn_only and severity == 'LOW':
            continue

        print(f"\n{severity} SEVERITY ISSUES ({len(by_severity[severity])}):")
        print("=" * 70)

        for issue in by_severity[severity]:
            if verbose:
                print(f"  Type: {issue['type']}")
                print(f"  Pod: {issue['namespace']}/{issue['pod']}")
                print(f"  Container: {issue['container']}")
                print(f"  Detail: {issue['detail']}")
                print()
            else:
                print(f"  [{issue['type']}] {issue['namespace']}/{issue['pod']}")
                if issue['container'] != '*':
                    print(f"    Container: {issue['container']}")
                print(f"    {issue['detail']}")


def output_json(all_issues: list) -> None:
    """Output results in JSON format."""
    result = {
        'summary': {
            'total_issues': len(all_issues),
            'critical': len([i for i in all_issues if i['severity'] == 'CRITICAL']),
            'high': len([i for i in all_issues if i['severity'] == 'HIGH']),
            'medium': len([i for i in all_issues if i['severity'] == 'MEDIUM']),
            'low': len([i for i in all_issues if i['severity'] == 'LOW'])
        },
        'issues': all_issues
    }
    print(json.dumps(result, indent=2))


def output_table(all_issues: list, warn_only: bool = False) -> None:
    """Output results in table format."""
    if not all_issues:
        print("No pod security issues detected")
        return

    # Filter if warn_only
    if warn_only:
        all_issues = [i for i in all_issues if i['severity'] != 'LOW']

    if not all_issues:
        print("No warnings or critical issues detected")
        return

    print(f"{'Severity':<10} {'Type':<28} {'Namespace/Pod':<35} {'Detail':<40}")
    print("=" * 115)

    for issue in sorted(all_issues, key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x['severity'])):
        pod_full = f"{issue['namespace']}/{issue['pod']}"
        if len(pod_full) > 32:
            pod_full = pod_full[:32] + "..."

        detail = issue['detail']
        if len(detail) > 37:
            detail = detail[:37] + "..."

        print(f"{issue['severity']:<10} {issue['type']:<28} {pod_full:<35} {detail:<40}")


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no critical issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes pod security contexts and capabilities"
    )
    parser.add_argument(
        "-n", "--namespace",
        help="Namespace to audit (default: all namespaces)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings (exclude LOW severity)"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Build namespace args
    ns_args = ["-n", opts.namespace] if opts.namespace else ["--all-namespaces"]

    # Get pods
    try:
        result = context.run(["kubectl", "get", "pods", "-o", "json"] + ns_args)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods_data = json.loads(result.stdout)
        pods = pods_data.get('items', [])
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    # Analyze pods
    all_issues = []
    for pod in pods:
        all_issues.extend(check_pod_security(pod))

    # Output results
    if opts.format == 'json':
        output_json(all_issues)
    elif opts.format == 'table':
        output_table(all_issues, opts.warn_only)
    else:
        output_plain(all_issues, opts.verbose, opts.warn_only)

    # Summary
    critical = len([i for i in all_issues if i['severity'] == 'CRITICAL'])
    high = len([i for i in all_issues if i['severity'] == 'HIGH'])
    medium = len([i for i in all_issues if i['severity'] == 'MEDIUM'])
    low = len([i for i in all_issues if i['severity'] == 'LOW'])
    output.set_summary(f"issues={len(all_issues)}, critical={critical}, high={high}, medium={medium}, low={low}")

    # Exit with appropriate code
    if all_issues:
        critical_high = [i for i in all_issues if i['severity'] in ('CRITICAL', 'HIGH')]
        if critical_high:
            return 1
        # Medium/Low issues still exit 1 unless warn_only
        return 0 if opts.warn_only else 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
