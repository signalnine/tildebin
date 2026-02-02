#!/usr/bin/env python3
# boxctl:
#   category: k8s/resources
#   tags: [resources, kubernetes, rightsizing, optimization, capacity]
#   requires: [kubectl]
#   brief: Analyze resource requests/limits to identify right-sizing opportunities
#   privilege: user
#   related: [pod_resource_audit, resource_request_efficiency, node_capacity]

"""
Kubernetes resource right-sizer - Identify resource optimization opportunities.

Compares configured resource requests/limits against actual usage (via metrics-server)
to identify workloads that are over-provisioned or under-provisioned.

Analyzes:
- Pods requesting far more CPU/memory than they use
- Pods at risk of OOM due to insufficient limits
- Resource optimization recommendations
- Namespace resource efficiency

Useful for:
- Cost optimization
- Capacity planning
- Performance tuning
- Resource audit

Exit codes:
    0 - All workloads appropriately sized
    1 - Right-sizing opportunities found
    2 - Usage error or kubectl/metrics unavailable
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_cpu(cpu_str: str | None) -> int | None:
    """Parse CPU string to millicores (int)."""
    if not cpu_str:
        return None
    cpu_str = str(cpu_str).strip()
    if cpu_str.endswith("m"):
        return int(cpu_str[:-1])
    elif cpu_str.endswith("n"):
        return int(cpu_str[:-1]) // 1000000
    else:
        try:
            return int(float(cpu_str) * 1000)
        except ValueError:
            return None


def parse_memory(mem_str: str | None) -> int | None:
    """Parse memory string to bytes (int)."""
    if not mem_str:
        return None
    mem_str = str(mem_str).strip()

    multipliers = {
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
    }

    for suffix, multiplier in multipliers.items():
        if mem_str.endswith(suffix):
            try:
                return int(float(mem_str[: -len(suffix)]) * multiplier)
            except ValueError:
                return None

    try:
        return int(mem_str)
    except ValueError:
        return None


def format_cpu(millicores: int | None) -> str:
    """Format millicores to human-readable string."""
    if millicores is None:
        return "N/A"
    if millicores >= 1000:
        return f"{millicores / 1000:.1f}"
    return f"{millicores}m"


def format_memory(bytes_val: int | None) -> str:
    """Format bytes to human-readable string."""
    if bytes_val is None:
        return "N/A"
    if bytes_val >= 1024**3:
        return f"{bytes_val / (1024 ** 3):.1f}Gi"
    elif bytes_val >= 1024**2:
        return f"{bytes_val / (1024 ** 2):.0f}Mi"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.0f}Ki"
    return f"{bytes_val}B"


def parse_metrics_output(output: str, namespace: str | None) -> dict:
    """Parse kubectl top pods output."""
    metrics = {}
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3:
            if namespace:
                pod_name = parts[0]
                ns = namespace
                cpu = parts[1]
                mem = parts[2]
            else:
                if len(parts) < 4:
                    continue
                ns = parts[0]
                pod_name = parts[1]
                cpu = parts[2]
                mem = parts[3]

            key = f"{ns}/{pod_name}"
            metrics[key] = {"cpu": parse_cpu(cpu), "memory": parse_memory(mem)}

    return metrics


def analyze_pod(pod: dict, metrics: dict) -> dict | None:
    """Analyze a single pod's resource efficiency."""
    metadata = pod.get("metadata", {})
    spec = pod.get("spec", {})
    status = pod.get("status", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")
    key = f"{namespace}/{name}"

    phase = status.get("phase", "")
    if phase != "Running":
        return None

    owner_refs = metadata.get("ownerReferences", [])
    owner_kind = owner_refs[0].get("kind", "None") if owner_refs else "None"
    owner_name = owner_refs[0].get("name", "None") if owner_refs else "None"

    total_cpu_request = 0
    total_cpu_limit = 0
    total_mem_request = 0
    total_mem_limit = 0
    has_requests = False
    has_limits = False

    containers = spec.get("containers", [])
    for container in containers:
        resources = container.get("resources", {})
        requests = resources.get("requests", {})
        limits = resources.get("limits", {})

        cpu_req = parse_cpu(requests.get("cpu"))
        cpu_lim = parse_cpu(limits.get("cpu"))
        mem_req = parse_memory(requests.get("memory"))
        mem_lim = parse_memory(limits.get("memory"))

        if cpu_req:
            total_cpu_request += cpu_req
            has_requests = True
        if cpu_lim:
            total_cpu_limit += cpu_lim
            has_limits = True
        if mem_req:
            total_mem_request += mem_req
            has_requests = True
        if mem_lim:
            total_mem_limit += mem_lim
            has_limits = True

    usage = metrics.get(key, {})
    actual_cpu = usage.get("cpu")
    actual_mem = usage.get("memory")

    cpu_efficiency = None
    mem_efficiency = None

    if actual_cpu is not None and total_cpu_request > 0:
        cpu_efficiency = (actual_cpu / total_cpu_request) * 100
    if actual_mem is not None and total_mem_request > 0:
        mem_efficiency = (actual_mem / total_mem_request) * 100

    return {
        "name": name,
        "namespace": namespace,
        "owner_kind": owner_kind,
        "owner_name": owner_name,
        "cpu_request": total_cpu_request if has_requests else None,
        "cpu_limit": total_cpu_limit if has_limits else None,
        "cpu_actual": actual_cpu,
        "cpu_efficiency": cpu_efficiency,
        "mem_request": total_mem_request if has_requests else None,
        "mem_limit": total_mem_limit if has_limits else None,
        "mem_actual": actual_mem,
        "mem_efficiency": mem_efficiency,
        "has_requests": has_requests,
        "has_limits": has_limits,
    }


def categorize_findings(
    analyses: list, cpu_threshold: int = 30, mem_threshold: int = 30
) -> dict:
    """Categorize pods by their resource efficiency."""
    categories = {
        "over_provisioned": [],
        "under_provisioned": [],
        "no_requests": [],
        "no_limits": [],
        "efficient": [],
        "no_metrics": [],
    }

    for analysis in analyses:
        if analysis is None:
            continue

        has_metrics = analysis["cpu_actual"] is not None or analysis["mem_actual"] is not None

        if not has_metrics:
            categories["no_metrics"].append(analysis)
            continue

        if not analysis["has_requests"]:
            categories["no_requests"].append(analysis)
            continue

        if not analysis["has_limits"]:
            categories["no_limits"].append(analysis)

        cpu_over = (
            analysis["cpu_efficiency"] is not None
            and analysis["cpu_efficiency"] < cpu_threshold
        )
        mem_over = (
            analysis["mem_efficiency"] is not None
            and analysis["mem_efficiency"] < mem_threshold
        )

        if cpu_over or mem_over:
            categories["over_provisioned"].append(analysis)
            continue

        cpu_under = (
            analysis["cpu_efficiency"] is not None and analysis["cpu_efficiency"] > 90
        )
        mem_under = (
            analysis["mem_efficiency"] is not None and analysis["mem_efficiency"] > 90
        )

        if cpu_under or mem_under:
            categories["under_provisioned"].append(analysis)
            continue

        categories["efficient"].append(analysis)

    return categories


def calculate_savings(categories: dict) -> tuple:
    """Calculate potential resource savings from right-sizing."""
    total_cpu_savings = 0
    total_mem_savings = 0

    for pod in categories["over_provisioned"]:
        if pod["cpu_request"] and pod["cpu_actual"]:
            suggested = int(pod["cpu_actual"] * 1.5)
            savings = pod["cpu_request"] - suggested
            if savings > 0:
                total_cpu_savings += savings

        if pod["mem_request"] and pod["mem_actual"]:
            suggested = int(pod["mem_actual"] * 1.2)
            savings = pod["mem_request"] - suggested
            if savings > 0:
                total_mem_savings += savings

    return total_cpu_savings, total_mem_savings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all sized, 1 = opportunities found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes resource requests/limits for right-sizing"
    )
    parser.add_argument(
        "-n", "--namespace", help="Kubernetes namespace to analyze (default: all namespaces)"
    )
    parser.add_argument(
        "--cpu-threshold",
        type=int,
        default=30,
        help="CPU efficiency threshold %% below which pod is over-provisioned (default: 30)",
    )
    parser.add_argument(
        "--mem-threshold",
        type=int,
        default=30,
        help="Memory efficiency threshold %% below which pod is over-provisioned (default: 30)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "table", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show over/under-provisioned workloads",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed recommendations"
    )
    parser.add_argument(
        "--exclude-namespace",
        action="append",
        default=[],
        help="Namespaces to exclude (can be specified multiple times)",
    )
    opts = parser.parse_args(args)

    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get pods
    try:
        cmd = ["kubectl", "get", "pods", "-o", "json"]
        if opts.namespace:
            cmd.extend(["-n", opts.namespace])
        else:
            cmd.append("--all-namespaces")
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods = json.loads(result.stdout).get("items", [])
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    if not pods:
        if opts.format == "json":
            print(json.dumps({"summary": {"total": 0}, "categories": {}}))
        else:
            print("No pods found")
        return 0

    # Get metrics
    metrics = {}
    try:
        cmd = ["kubectl", "top", "pods", "--no-headers"]
        if opts.namespace:
            cmd.extend(["-n", opts.namespace])
        else:
            cmd.append("--all-namespaces")
        result = context.run(cmd)
        if result.returncode == 0:
            metrics = parse_metrics_output(result.stdout, opts.namespace)
    except Exception:
        pass

    if not metrics:
        output.error(
            "Warning: No metrics available. Is metrics-server running? "
            "Install: https://github.com/kubernetes-sigs/metrics-server"
        )

    # Analyze each pod
    analyses = []
    for pod in pods:
        ns = pod.get("metadata", {}).get("namespace", "")
        if ns in opts.exclude_namespace:
            continue
        analysis = analyze_pod(pod, metrics)
        if analysis:
            analyses.append(analysis)

    if not analyses:
        if opts.format == "json":
            print(json.dumps({"summary": {"total": 0}, "categories": {}}))
        else:
            print("No running pods found")
        return 0

    # Categorize findings
    categories = categorize_findings(
        analyses, cpu_threshold=opts.cpu_threshold, mem_threshold=opts.mem_threshold
    )

    cpu_savings, mem_savings = calculate_savings(categories)

    has_issues = (
        len(categories["over_provisioned"]) > 0
        or len(categories["under_provisioned"]) > 0
        or len(categories["no_requests"]) > 0
    )

    # Output results
    if opts.format == "json":
        result_data = {
            "summary": {
                "total": len([a for a in analyses if a is not None]),
                "over_provisioned": len(categories["over_provisioned"]),
                "under_provisioned": len(categories["under_provisioned"]),
                "missing_requests": len(categories["no_requests"]),
                "efficient": len(categories["efficient"]),
                "no_metrics": len(categories["no_metrics"]),
            },
            "potential_savings": {
                "cpu_millicores": cpu_savings,
                "memory_bytes": mem_savings,
                "cpu_formatted": format_cpu(cpu_savings),
                "memory_formatted": format_memory(mem_savings),
            },
            "categories": {
                "over_provisioned": categories["over_provisioned"],
                "under_provisioned": categories["under_provisioned"],
                "missing_requests": categories["no_requests"],
                "missing_limits": categories["no_limits"],
                "efficient": categories["efficient"],
            },
        }
        print(json.dumps(result_data, indent=2, default=str))
    elif opts.format == "table":
        if opts.warn_only:
            pods_to_show = (
                categories["over_provisioned"] + categories["under_provisioned"]
            )
        else:
            pods_to_show = [a for a in analyses if a is not None]

        print(
            f"{'NAMESPACE':<15} {'POD':<30} {'CPU%':<8} {'MEM%':<8} "
            f"{'CPU REQ':<10} {'MEM REQ':<10} {'STATUS':<15}"
        )
        print("-" * 106)

        for pod in sorted(pods_to_show, key=lambda x: (x["mem_efficiency"] or 100)):
            ns = (
                pod["namespace"][:13] + ".."
                if len(pod["namespace"]) > 15
                else pod["namespace"]
            )
            name = pod["name"][:28] + ".." if len(pod["name"]) > 30 else pod["name"]
            cpu_eff = (
                f"{pod['cpu_efficiency']:.0f}%" if pod["cpu_efficiency"] else "N/A"
            )
            mem_eff = (
                f"{pod['mem_efficiency']:.0f}%" if pod["mem_efficiency"] else "N/A"
            )

            if pod in categories["over_provisioned"]:
                status = "OVER-PROV"
            elif pod in categories["under_provisioned"]:
                status = "UNDER-PROV"
            elif pod in categories["no_requests"]:
                status = "NO-REQ"
            else:
                status = "OK"

            print(
                f"{ns:<15} {name:<30} {cpu_eff:<8} {mem_eff:<8} "
                f"{format_cpu(pod['cpu_request']):<10} "
                f"{format_memory(pod['mem_request']):<10} {status:<15}"
            )

        print()
        print(
            f"Total: {len(pods_to_show)} | "
            f"Over: {len(categories['over_provisioned'])} | "
            f"Under: {len(categories['under_provisioned'])}"
        )
    else:  # plain
        total = len([a for a in analyses if a is not None])
        over_count = len(categories["over_provisioned"])
        under_count = len(categories["under_provisioned"])
        no_req_count = len(categories["no_requests"])

        if not opts.warn_only:
            print("Resource Right-Sizing Analysis")
            print("=" * 80)
            print(f"Total running pods analyzed: {total}")
            print(f"  Over-provisioned: {over_count}")
            print(f"  Under-provisioned: {under_count}")
            print(f"  Missing requests: {no_req_count}")
            print(f"  Efficiently sized: {len(categories['efficient'])}")
            print(f"  No metrics available: {len(categories['no_metrics'])}")
            print()

        if categories["over_provisioned"]:
            print(f"Over-Provisioned Workloads ({over_count}):")
            print("-" * 80)
            for pod in sorted(
                categories["over_provisioned"],
                key=lambda x: (x["mem_efficiency"] or 100),
            ):
                cpu_eff = (
                    f"{pod['cpu_efficiency']:.0f}%"
                    if pod["cpu_efficiency"]
                    else "N/A"
                )
                mem_eff = (
                    f"{pod['mem_efficiency']:.0f}%"
                    if pod["mem_efficiency"]
                    else "N/A"
                )

                print(f"  {pod['namespace']}/{pod['name']}")
                print(f"    Owner: {pod['owner_kind']}/{pod['owner_name']}")
                print(
                    f"    CPU: {format_cpu(pod['cpu_actual'])} used / "
                    f"{format_cpu(pod['cpu_request'])} requested ({cpu_eff})"
                )
                print(
                    f"    Memory: {format_memory(pod['mem_actual'])} used / "
                    f"{format_memory(pod['mem_request'])} requested ({mem_eff})"
                )

                if opts.verbose:
                    if pod["cpu_actual"] and pod["cpu_request"]:
                        suggested_cpu = int(pod["cpu_actual"] * 1.5)
                        print(f"    Suggested CPU request: {format_cpu(suggested_cpu)}")
                    if pod["mem_actual"] and pod["mem_request"]:
                        suggested_mem = int(pod["mem_actual"] * 1.2)
                        print(
                            f"    Suggested memory request: {format_memory(suggested_mem)}"
                        )
                print()

        if categories["under_provisioned"]:
            print(f"Under-Provisioned Workloads ({under_count}):")
            print("-" * 80)
            for pod in sorted(
                categories["under_provisioned"],
                key=lambda x: -(x["mem_efficiency"] or 0),
            ):
                cpu_eff = (
                    f"{pod['cpu_efficiency']:.0f}%"
                    if pod["cpu_efficiency"]
                    else "N/A"
                )
                mem_eff = (
                    f"{pod['mem_efficiency']:.0f}%"
                    if pod["mem_efficiency"]
                    else "N/A"
                )

                print(f"  {pod['namespace']}/{pod['name']}")
                print(f"    Owner: {pod['owner_kind']}/{pod['owner_name']}")
                print(
                    f"    CPU: {format_cpu(pod['cpu_actual'])} used / "
                    f"{format_cpu(pod['cpu_request'])} requested ({cpu_eff})"
                )
                print(
                    f"    Memory: {format_memory(pod['mem_actual'])} used / "
                    f"{format_memory(pod['mem_request'])} requested ({mem_eff})"
                )
                print()

        if categories["no_requests"] and not opts.warn_only:
            print(f"Missing Resource Requests ({no_req_count}):")
            print("-" * 80)
            for pod in categories["no_requests"][:10]:
                print(f"  {pod['namespace']}/{pod['name']}")
            if len(categories["no_requests"]) > 10:
                print(f"  ... and {len(categories['no_requests']) - 10} more")
            print()

        if categories["over_provisioned"]:
            print("Potential Savings (if right-sized):")
            print("-" * 80)
            print(f"  CPU: {format_cpu(cpu_savings)} cores could be reclaimed")
            print(f"  Memory: {format_memory(mem_savings)} could be reclaimed")
            print()

        if not categories["over_provisioned"] and opts.warn_only:
            print("All workloads are appropriately sized")

    output.set_summary(
        f"total={total}, over={len(categories['over_provisioned'])}, "
        f"under={len(categories['under_provisioned'])}"
    )

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
