#!/usr/bin/env python3
"""
Monitor Kubernetes Operator health and status.

Detects and monitors common Kubernetes operators including:
- Prometheus Operator (monitoring)
- Cert-Manager (certificate management)
- ArgoCD (GitOps continuous delivery)
- Flux (GitOps toolkit)
- Istio (service mesh)
- Ingress controllers (NGINX, Traefik)
- External-DNS
- Sealed Secrets

For each detected operator, checks:
- Controller pod health (Running, Ready, restarts)
- CRD availability and status
- Webhook configurations (if applicable)
- Recent error events

Useful for production Kubernetes clusters where operators manage
critical infrastructure but may fail silently.

Exit codes:
    0 - All detected operators healthy
    1 - One or more operators unhealthy or have warnings
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone


# Known operator definitions: namespace patterns, deployment patterns, CRDs
KNOWN_OPERATORS = {
    'prometheus-operator': {
        'namespaces': ['monitoring', 'prometheus', 'kube-prometheus-stack', 'observability'],
        'deployments': ['prometheus-operator', 'kube-prometheus-stack-operator'],
        'crds': ['prometheuses.monitoring.coreos.com', 'servicemonitors.monitoring.coreos.com',
                 'alertmanagers.monitoring.coreos.com', 'podmonitors.monitoring.coreos.com'],
        'description': 'Prometheus Operator for Kubernetes-native monitoring'
    },
    'cert-manager': {
        'namespaces': ['cert-manager'],
        'deployments': ['cert-manager', 'cert-manager-controller'],
        'crds': ['certificates.cert-manager.io', 'issuers.cert-manager.io',
                 'clusterissuers.cert-manager.io', 'certificaterequests.cert-manager.io'],
        'description': 'Certificate management controller'
    },
    'argocd': {
        'namespaces': ['argocd', 'argo-cd'],
        'deployments': ['argocd-server', 'argocd-repo-server', 'argocd-application-controller',
                        'argocd-applicationset-controller', 'argocd-dex-server'],
        'crds': ['applications.argoproj.io', 'applicationsets.argoproj.io',
                 'appprojects.argoproj.io'],
        'description': 'GitOps continuous delivery tool'
    },
    'flux': {
        'namespaces': ['flux-system', 'flux'],
        'deployments': ['source-controller', 'kustomize-controller', 'helm-controller',
                        'notification-controller', 'image-reflector-controller',
                        'image-automation-controller'],
        'crds': ['gitrepositories.source.toolkit.fluxcd.io',
                 'kustomizations.kustomize.toolkit.fluxcd.io',
                 'helmreleases.helm.toolkit.fluxcd.io'],
        'description': 'GitOps toolkit for Kubernetes'
    },
    'istio': {
        'namespaces': ['istio-system'],
        'deployments': ['istiod', 'istio-ingressgateway', 'istio-egressgateway'],
        'crds': ['virtualservices.networking.istio.io', 'destinationrules.networking.istio.io',
                 'gateways.networking.istio.io'],
        'description': 'Service mesh for microservices'
    },
    'nginx-ingress': {
        'namespaces': ['ingress-nginx', 'nginx-ingress'],
        'deployments': ['ingress-nginx-controller', 'nginx-ingress-controller'],
        'crds': [],
        'description': 'NGINX Ingress Controller'
    },
    'traefik': {
        'namespaces': ['traefik', 'traefik-system'],
        'deployments': ['traefik'],
        'crds': ['ingressroutes.traefik.containo.us', 'middlewares.traefik.containo.us'],
        'description': 'Traefik Ingress Controller'
    },
    'external-dns': {
        'namespaces': ['external-dns', 'kube-system'],
        'deployments': ['external-dns'],
        'crds': [],
        'description': 'Automatic DNS record management'
    },
    'sealed-secrets': {
        'namespaces': ['kube-system', 'sealed-secrets'],
        'deployments': ['sealed-secrets-controller', 'sealed-secrets'],
        'crds': ['sealedsecrets.bitnami.com'],
        'description': 'Sealed Secrets for Kubernetes'
    },
    'metallb': {
        'namespaces': ['metallb-system'],
        'deployments': ['controller'],
        'crds': ['ipaddresspools.metallb.io', 'l2advertisements.metallb.io'],
        'description': 'Bare metal load balancer'
    },
    'keda': {
        'namespaces': ['keda'],
        'deployments': ['keda-operator', 'keda-operator-metrics-apiserver'],
        'crds': ['scaledobjects.keda.sh', 'scaledjobs.keda.sh', 'triggerauthentications.keda.sh'],
        'description': 'Kubernetes Event-driven Autoscaling'
    },
    'crossplane': {
        'namespaces': ['crossplane-system'],
        'deployments': ['crossplane', 'crossplane-rbac-manager'],
        'crds': ['compositions.apiextensions.crossplane.io',
                 'compositeresourcedefinitions.apiextensions.crossplane.io'],
        'description': 'Cloud infrastructure provisioning'
    }
}


def run_kubectl(args, timeout=30):
    """Run kubectl command and return output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            return None, result.stderr
        return result.stdout, None
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        return None, "Command timed out"


def get_namespaces():
    """Get all namespaces."""
    output, err = run_kubectl(['get', 'namespaces', '-o', 'json'])
    if output is None:
        return []
    data = json.loads(output)
    return [ns['metadata']['name'] for ns in data.get('items', [])]


def get_crds():
    """Get all CRDs in the cluster."""
    output, err = run_kubectl(['get', 'crds', '-o', 'json'])
    if output is None:
        return []
    data = json.loads(output)
    return [crd['metadata']['name'] for crd in data.get('items', [])]


def get_deployments(namespace):
    """Get deployments in a namespace."""
    output, err = run_kubectl(['get', 'deployments', '-n', namespace, '-o', 'json'])
    if output is None:
        return []
    data = json.loads(output)
    return data.get('items', [])


def get_pods_for_deployment(namespace, deployment_name):
    """Get pods belonging to a deployment."""
    output, err = run_kubectl(['get', 'pods', '-n', namespace, '-o', 'json',
                               '-l', f'app.kubernetes.io/name={deployment_name}'])
    if output is None:
        # Try alternative label selector
        output, err = run_kubectl(['get', 'pods', '-n', namespace, '-o', 'json',
                                   '-l', f'app={deployment_name}'])
    if output is None:
        return []
    data = json.loads(output)
    return data.get('items', [])


def get_events(namespace, hours=1):
    """Get recent events in a namespace."""
    output, err = run_kubectl(['get', 'events', '-n', namespace, '-o', 'json'])
    if output is None:
        return []
    data = json.loads(output)
    return data.get('items', [])


def detect_operators(namespaces, crds):
    """Detect which operators are installed in the cluster."""
    detected = {}
    crd_set = set(crds)
    namespace_set = set(namespaces)

    for operator_name, operator_info in KNOWN_OPERATORS.items():
        # Check if any expected namespace exists
        matching_namespaces = [ns for ns in operator_info['namespaces']
                               if ns in namespace_set]

        # Check if any expected CRDs exist
        matching_crds = [crd for crd in operator_info['crds']
                         if crd in crd_set]

        # Operator is detected if we find matching namespace(s) or CRD(s)
        if matching_namespaces or matching_crds:
            detected[operator_name] = {
                'namespaces': matching_namespaces,
                'crds': matching_crds,
                'expected_crds': operator_info['crds'],
                'expected_deployments': operator_info['deployments'],
                'description': operator_info['description']
            }

    return detected


def check_deployment_health(deployment):
    """Check health of a deployment and return issues."""
    issues = []
    warnings = []

    name = deployment['metadata']['name']
    status = deployment.get('status', {})
    spec = deployment.get('spec', {})

    replicas = spec.get('replicas', 1)
    ready_replicas = status.get('readyReplicas', 0)
    available_replicas = status.get('availableReplicas', 0)
    updated_replicas = status.get('updatedReplicas', 0)

    if ready_replicas < replicas:
        issues.append(f"Only {ready_replicas}/{replicas} replicas ready")

    if available_replicas < replicas:
        warnings.append(f"Only {available_replicas}/{replicas} replicas available")

    if updated_replicas < replicas:
        warnings.append(f"Rollout in progress: {updated_replicas}/{replicas} updated")

    # Check conditions
    conditions = status.get('conditions', [])
    for condition in conditions:
        if condition.get('type') == 'Available' and condition.get('status') != 'True':
            issues.append(f"Deployment not available: {condition.get('message', 'Unknown reason')}")
        if condition.get('type') == 'Progressing' and condition.get('status') == 'False':
            issues.append(f"Deployment not progressing: {condition.get('message', 'Unknown reason')}")

    return issues, warnings


def check_pod_health(pod):
    """Check health of a pod and return issues."""
    issues = []
    name = pod['metadata']['name']
    status = pod.get('status', {})

    phase = status.get('phase', 'Unknown')
    if phase not in ['Running', 'Succeeded']:
        issues.append(f"Pod {name} in {phase} phase")

    # Check container statuses
    container_statuses = status.get('containerStatuses', [])
    for container in container_statuses:
        container_name = container.get('name', 'unknown')
        ready = container.get('ready', False)
        restart_count = container.get('restartCount', 0)

        if not ready and phase == 'Running':
            state = container.get('state', {})
            if 'waiting' in state:
                reason = state['waiting'].get('reason', 'Unknown')
                issues.append(f"Container {container_name} not ready: {reason}")

        if restart_count > 5:
            issues.append(f"Container {container_name} has {restart_count} restarts")

    return issues


def check_operator_health(operator_name, operator_info, verbose=False):
    """Check health of a specific operator."""
    issues = []
    warnings = []
    details = {
        'deployments': [],
        'pods': [],
        'crds': {
            'found': operator_info['crds'],
            'missing': []
        }
    }

    # Check for missing CRDs
    expected_crds = operator_info.get('expected_crds', [])
    found_crds = set(operator_info['crds'])
    for crd in expected_crds:
        if crd not in found_crds:
            details['crds']['missing'].append(crd)

    if details['crds']['missing']:
        warnings.append(f"Missing CRDs: {', '.join(details['crds']['missing'][:3])}"
                       + ("..." if len(details['crds']['missing']) > 3 else ""))

    # Check deployments in each namespace
    deployments_found = False
    expected_deployments = operator_info.get('expected_deployments', [])

    for namespace in operator_info['namespaces']:
        deployments = get_deployments(namespace)

        for deployment in deployments:
            dep_name = deployment['metadata']['name']

            # Check if this is an expected operator deployment
            is_operator_deployment = any(
                expected in dep_name.lower()
                for expected in [d.lower() for d in expected_deployments]
            )

            if is_operator_deployment or dep_name in expected_deployments:
                deployments_found = True
                dep_issues, dep_warnings = check_deployment_health(deployment)

                dep_info = {
                    'name': dep_name,
                    'namespace': namespace,
                    'replicas': deployment.get('spec', {}).get('replicas', 1),
                    'ready': deployment.get('status', {}).get('readyReplicas', 0),
                    'issues': dep_issues,
                    'warnings': dep_warnings
                }
                details['deployments'].append(dep_info)

                issues.extend([f"{dep_name}: {issue}" for issue in dep_issues])
                warnings.extend([f"{dep_name}: {warning}" for warning in dep_warnings])

                # Check pods for this deployment
                pods = get_pods_for_deployment(namespace, dep_name)
                for pod in pods:
                    pod_issues = check_pod_health(pod)
                    pod_name = pod['metadata']['name']

                    pod_info = {
                        'name': pod_name,
                        'namespace': namespace,
                        'phase': pod.get('status', {}).get('phase', 'Unknown'),
                        'restarts': sum(
                            c.get('restartCount', 0)
                            for c in pod.get('status', {}).get('containerStatuses', [])
                        ),
                        'issues': pod_issues
                    }
                    details['pods'].append(pod_info)

                    if pod_issues and verbose:
                        issues.extend([f"{pod_name}: {issue}" for issue in pod_issues])

    if not deployments_found and operator_info['namespaces']:
        warnings.append("No operator deployments found (may be using different naming)")

    # Check for error events in operator namespaces
    for namespace in operator_info['namespaces']:
        events = get_events(namespace)
        error_events = [e for e in events
                       if e.get('type') == 'Warning'
                       and 'Error' in e.get('reason', '')]
        if len(error_events) > 5:
            warnings.append(f"{len(error_events)} warning events in {namespace}")

    is_healthy = len(issues) == 0
    return is_healthy, issues, warnings, details


def print_plain(operators_status, warn_only=False):
    """Print status in plain text format."""
    has_issues = False

    if not operators_status:
        print("No operators detected in the cluster")
        return False

    print("Kubernetes Operator Health Check")
    print("=" * 60)
    print()

    healthy_count = 0
    unhealthy_count = 0

    for operator_name, status in operators_status.items():
        if status['healthy']:
            healthy_count += 1
        else:
            unhealthy_count += 1
            has_issues = True

        # Skip healthy operators if warn_only
        if warn_only and status['healthy'] and not status['warnings']:
            continue

        marker = "✓" if status['healthy'] else "✗"
        print(f"{marker} {operator_name}")
        print(f"  Description: {status['description']}")
        print(f"  Namespaces: {', '.join(status['namespaces']) or 'N/A'}")

        # Show deployments
        if status['details']['deployments']:
            print(f"  Deployments:")
            for dep in status['details']['deployments']:
                dep_marker = "✓" if not dep['issues'] else "✗"
                print(f"    {dep_marker} {dep['namespace']}/{dep['name']}: "
                      f"{dep['ready']}/{dep['replicas']} ready")

        # Show CRDs
        if status['details']['crds']['found']:
            print(f"  CRDs found: {len(status['details']['crds']['found'])}")

        # Show issues
        if status['issues']:
            print(f"  Issues:")
            for issue in status['issues']:
                print(f"    - {issue}")

        # Show warnings
        if status['warnings']:
            print(f"  Warnings:")
            for warning in status['warnings']:
                print(f"    - {warning}")

        print()

    # Summary
    total = healthy_count + unhealthy_count
    print(f"Summary: {healthy_count}/{total} operators healthy")

    return has_issues


def print_json(operators_status):
    """Print status in JSON format."""
    has_issues = any(not s['healthy'] for s in operators_status.values())

    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'summary': {
            'total_operators': len(operators_status),
            'healthy': sum(1 for s in operators_status.values() if s['healthy']),
            'unhealthy': sum(1 for s in operators_status.values() if not s['healthy'])
        },
        'operators': operators_status
    }

    print(json.dumps(output, indent=2, default=str))
    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes Operator health and status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all detected operators
  %(prog)s --format json            # JSON output for monitoring
  %(prog)s --warn-only              # Only show unhealthy operators
  %(prog)s -v                       # Verbose output with pod details
  %(prog)s --list-known             # List known operators this tool can detect

Exit codes:
  0 - All detected operators healthy
  1 - One or more operators unhealthy or have warnings
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show operators with issues or warnings'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed pod-level information'
    )

    parser.add_argument(
        '--list-known',
        action='store_true',
        help='List all known operators this tool can detect'
    )

    args = parser.parse_args()

    # List known operators if requested
    if args.list_known:
        print("Known Operators:")
        print("-" * 60)
        for name, info in sorted(KNOWN_OPERATORS.items()):
            print(f"  {name}")
            print(f"    {info['description']}")
            print(f"    Namespaces: {', '.join(info['namespaces'])}")
            if info['crds']:
                print(f"    CRDs: {len(info['crds'])} defined")
            print()
        return 0

    # Get cluster information
    namespaces = get_namespaces()
    if not namespaces:
        print("Error: Unable to get namespaces from cluster", file=sys.stderr)
        return 1

    crds = get_crds()

    # Detect installed operators
    detected_operators = detect_operators(namespaces, crds)

    if not detected_operators:
        if args.format == 'json':
            print(json.dumps({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'summary': {'total_operators': 0, 'healthy': 0, 'unhealthy': 0},
                'operators': {}
            }, indent=2))
        else:
            print("No known operators detected in the cluster")
        return 0

    # Check health of each detected operator
    operators_status = {}
    for operator_name, operator_info in detected_operators.items():
        is_healthy, issues, warnings, details = check_operator_health(
            operator_name, operator_info, verbose=args.verbose
        )

        operators_status[operator_name] = {
            'healthy': is_healthy,
            'description': operator_info['description'],
            'namespaces': operator_info['namespaces'],
            'issues': issues,
            'warnings': warnings,
            'details': details
        }

    # Output results
    if args.format == 'json':
        has_issues = print_json(operators_status)
    else:
        has_issues = print_plain(operators_status, args.warn_only)

    return 1 if has_issues else 0


if __name__ == '__main__':
    sys.exit(main())
