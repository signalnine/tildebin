#!/usr/bin/env python3
"""
Kubernetes orphaned resources finder - Identify unused and orphaned resources.

Helps operators find and clean up:
- Empty namespaces with no pods or workloads
- Orphaned ConfigMaps and Secrets (not referenced by any pod)
- Unused ServiceAccounts (not used by pods)
- Orphaned Persistent Volume Claims
- Unused Services with no endpoints
"""

import argparse
import subprocess
import json
import sys


def run_kubectl(args):
    """Run kubectl command and return JSON output, or None if it fails."""
    try:
        result = subprocess.run(
            ["kubectl", "-o", "json"] + args,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return None
        return None
    except FileNotFoundError:
        print("Error: kubectl not found. Please install kubectl.", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print("Error: kubectl command timed out.", file=sys.stderr)
        return None


def get_all_namespaces():
    """Get list of all namespaces."""
    result = run_kubectl(["get", "namespace"])
    if result is None:
        return []
    return [ns["metadata"]["name"] for ns in result.get("items", [])]


def count_pods_in_namespace(namespace):
    """Count pods in a namespace."""
    result = run_kubectl(["get", "pods", "-n", namespace])
    if result is None:
        return 0
    return len(result.get("items", []))


def count_workloads_in_namespace(namespace):
    """Count total workloads (Deployments, StatefulSets, DaemonSets, Jobs) in namespace."""
    count = 0
    for resource_type in ["deployments", "statefulsets", "daemonsets", "jobs"]:
        result = run_kubectl(["get", resource_type, "-n", namespace])
        if result is not None:
            count += len(result.get("items", []))
    return count


def find_empty_namespaces():
    """Find namespaces with no pods or workloads."""
    empty_namespaces = []
    namespaces = get_all_namespaces()

    for namespace in namespaces:
        # Skip system namespaces
        if namespace.startswith("kube-") or namespace.startswith("olm"):
            continue

        pod_count = count_pods_in_namespace(namespace)
        workload_count = count_workloads_in_namespace(namespace)

        if pod_count == 0 and workload_count == 0:
            empty_namespaces.append(namespace)

    return empty_namespaces


def get_configmaps_in_namespace(namespace):
    """Get all ConfigMaps in a namespace."""
    result = run_kubectl(["get", "configmap", "-n", namespace])
    if result is None:
        return []
    return result.get("items", [])


def get_secrets_in_namespace(namespace):
    """Get all Secrets in a namespace."""
    result = run_kubectl(["get", "secret", "-n", namespace])
    if result is None:
        return []
    return result.get("items", [])


def get_pods_in_namespace(namespace):
    """Get all pods in a namespace."""
    result = run_kubectl(["get", "pod", "-n", namespace])
    if result is None:
        return []
    return result.get("items", [])


def extract_volume_references(pod):
    """Extract ConfigMap/Secret references from a pod's volumes."""
    references = {"configmaps": set(), "secrets": set()}
    spec = pod.get("spec", {})
    volumes = spec.get("volumes", [])

    for volume in volumes:
        if "configMap" in volume:
            references["configmaps"].add(volume["configMap"].get("name"))
        elif "secret" in volume:
            references["secrets"].add(volume["secret"].get("secretName"))

    # Also check env variables for configmap/secret references
    containers = spec.get("containers", [])
    init_containers = spec.get("initContainers", [])

    for container in containers + init_containers:
        env_from = container.get("envFrom", [])
        for env in env_from:
            if "configMapRef" in env:
                references["configmaps"].add(env["configMapRef"].get("name"))
            elif "secretRef" in env:
                references["secrets"].add(env["secretRef"].get("name"))

    return references


def find_orphaned_configmaps_secrets(namespace):
    """Find orphaned ConfigMaps and Secrets in a namespace."""
    pods = get_pods_in_namespace(namespace)
    configmaps = get_configmaps_in_namespace(namespace)
    secrets = get_secrets_in_namespace(namespace)

    referenced_configmaps = set()
    referenced_secrets = set()

    for pod in pods:
        refs = extract_volume_references(pod)
        referenced_configmaps.update(refs["configmaps"])
        referenced_secrets.update(refs["secrets"])

    orphaned = {"configmaps": [], "secrets": []}

    # Skip default-token secrets (automatically managed by K8s)
    for secret in secrets:
        name = secret["metadata"]["name"]
        if not name.startswith("default-token-") and name not in referenced_secrets:
            orphaned["secrets"].append(name)

    for cm in configmaps:
        name = cm["metadata"]["name"]
        if name not in referenced_configmaps:
            orphaned["configmaps"].append(name)

    return orphaned


def get_service_accounts_in_namespace(namespace):
    """Get all ServiceAccounts in a namespace."""
    result = run_kubectl(["get", "serviceaccount", "-n", namespace])
    if result is None:
        return []
    return result.get("items", [])


def find_unused_service_accounts(namespace):
    """Find ServiceAccounts that are not used by any pod."""
    pods = get_pods_in_namespace(namespace)
    service_accounts = get_service_accounts_in_namespace(namespace)

    # Collect SA references from pods
    used_sas = set()
    for pod in pods:
        sa = pod.get("spec", {}).get("serviceAccountName")
        if sa:
            used_sas.add(sa)

    unused = []
    for sa in service_accounts:
        name = sa["metadata"]["name"]
        # Skip default SA (automatically used)
        if name != "default" and name not in used_sas:
            unused.append(name)

    return unused


def get_pvcs_in_namespace(namespace):
    """Get all PersistentVolumeClaims in a namespace."""
    result = run_kubectl(["get", "pvc", "-n", namespace])
    if result is None:
        return []
    return result.get("items", [])


def find_orphaned_pvcs(namespace):
    """Find PVCs not mounted by any pod."""
    pods = get_pods_in_namespace(namespace)
    pvcs = get_pvcs_in_namespace(namespace)

    # Collect PVC references from pods
    mounted_pvcs = set()
    for pod in pods:
        volumes = pod.get("spec", {}).get("volumes", [])
        for volume in volumes:
            if "persistentVolumeClaim" in volume:
                mounted_pvcs.add(volume["persistentVolumeClaim"].get("claimName"))

    orphaned = []
    for pvc in pvcs:
        name = pvc["metadata"]["name"]
        if name not in mounted_pvcs:
            orphaned.append(name)

    return orphaned


def get_services_in_namespace(namespace):
    """Get all Services in a namespace."""
    result = run_kubectl(["get", "service", "-n", namespace])
    if result is None:
        return []
    return result.get("items", [])


def get_endpoints_in_namespace(namespace):
    """Get all Endpoints in a namespace."""
    result = run_kubectl(["get", "endpoints", "-n", namespace])
    if result is None:
        return []
    return result.get("items", [])


def find_unused_services(namespace):
    """Find Services with no endpoints (no backing pods)."""
    services = get_services_in_namespace(namespace)
    endpoints = get_endpoints_in_namespace(namespace)

    # Build endpoint map
    endpoints_map = {}
    for ep in endpoints:
        name = ep["metadata"]["name"]
        subsets = ep.get("subsets", [])
        endpoints_map[name] = len(subsets) > 0 and any(s.get("addresses") for s in subsets)

    unused = []
    for service in services:
        name = service["metadata"]["name"]
        svc_type = service.get("spec", {}).get("type", "ClusterIP")

        # Skip ExternalName services and headless services
        if svc_type == "ExternalName":
            continue
        if service.get("spec", {}).get("clusterIP") == "None":
            continue

        # Check if service has endpoints
        has_endpoints = endpoints_map.get(name, False)
        if not has_endpoints:
            unused.append(name)

    return unused


def output_plain(results):
    """Output results in plain text format."""
    print("Kubernetes Orphaned Resources Report")
    print("=" * 80)
    print()

    if results["empty_namespaces"]:
        print("Empty Namespaces (no pods or workloads):")
        print("-" * 40)
        for ns in results["empty_namespaces"]:
            print(f"  {ns}")
        print()

    if results["orphaned_by_namespace"]:
        print("Orphaned Resources by Namespace:")
        print("-" * 40)
        for namespace, resources in results["orphaned_by_namespace"].items():
            if any(resources.values()):
                print(f"\n{namespace}:")
                if resources["configmaps"]:
                    print(f"  Orphaned ConfigMaps ({len(resources['configmaps'])}):")
                    for cm in resources["configmaps"]:
                        print(f"    - {cm}")
                if resources["secrets"]:
                    print(f"  Orphaned Secrets ({len(resources['secrets'])}):")
                    for secret in resources["secrets"]:
                        print(f"    - {secret}")
                if resources["pvcs"]:
                    print(f"  Orphaned PVCs ({len(resources['pvcs'])}):")
                    for pvc in resources["pvcs"]:
                        print(f"    - {pvc}")
                if resources["unused_services"]:
                    print(f"  Services with no endpoints ({len(resources['unused_services'])}):")
                    for svc in resources["unused_services"]:
                        print(f"    - {svc}")
                if resources["unused_sas"]:
                    print(f"  Unused ServiceAccounts ({len(resources['unused_sas'])}):")
                    for sa in resources["unused_sas"]:
                        print(f"    - {sa}")


def output_json(results):
    """Output results in JSON format."""
    print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Find orphaned and unused Kubernetes resources"
    )
    parser.add_argument(
        "--namespace", "-n",
        help="Check specific namespace only (default: all namespaces)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)"
    )
    parser.add_argument(
        "--skip-empty-namespaces",
        action="store_true",
        help="Skip checking for empty namespaces"
    )
    parser.add_argument(
        "--skip-configmaps",
        action="store_true",
        help="Skip checking for orphaned ConfigMaps"
    )
    parser.add_argument(
        "--skip-secrets",
        action="store_true",
        help="Skip checking for orphaned Secrets"
    )
    parser.add_argument(
        "--skip-pvcs",
        action="store_true",
        help="Skip checking for orphaned PVCs"
    )
    parser.add_argument(
        "--skip-services",
        action="store_true",
        help="Skip checking for unused Services"
    )
    parser.add_argument(
        "--skip-service-accounts",
        action="store_true",
        help="Skip checking for unused ServiceAccounts"
    )

    args = parser.parse_args()

    results = {
        "empty_namespaces": [],
        "orphaned_by_namespace": {}
    }

    # Find empty namespaces
    if not args.skip_empty_namespaces:
        results["empty_namespaces"] = find_empty_namespaces()

    # Determine which namespaces to check
    if args.namespace:
        namespaces = [args.namespace]
    else:
        namespaces = get_all_namespaces()

    # Find orphaned resources in each namespace
    for namespace in namespaces:
        # Skip system namespaces unless explicitly requested
        if not args.namespace and (namespace.startswith("kube-") or namespace.startswith("olm")):
            continue

        orphaned = {
            "configmaps": [],
            "secrets": [],
            "pvcs": [],
            "unused_services": [],
            "unused_sas": []
        }

        if not args.skip_configmaps or not args.skip_secrets:
            orphaned_cm_sec = find_orphaned_configmaps_secrets(namespace)
            if not args.skip_configmaps:
                orphaned["configmaps"] = orphaned_cm_sec["configmaps"]
            if not args.skip_secrets:
                orphaned["secrets"] = orphaned_cm_sec["secrets"]

        if not args.skip_pvcs:
            orphaned["pvcs"] = find_orphaned_pvcs(namespace)

        if not args.skip_services:
            orphaned["unused_services"] = find_unused_services(namespace)

        if not args.skip_service_accounts:
            orphaned["unused_sas"] = find_unused_service_accounts(namespace)

        # Only include namespace if it has orphaned resources
        if any(orphaned.values()):
            results["orphaned_by_namespace"][namespace] = orphaned

    # Output results
    if args.format == "json":
        output_json(results)
    else:
        output_plain(results)

    # Exit with error if any orphaned resources found
    has_orphaned = (
        results["empty_namespaces"] or
        any(
            any(resources.values())
            for resources in results["orphaned_by_namespace"].values()
        )
    )

    sys.exit(1 if has_orphaned else 0)


if __name__ == "__main__":
    main()
