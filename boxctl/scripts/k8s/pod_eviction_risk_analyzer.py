#!/usr/bin/env python3
# boxctl:
#   category: k8s/pods
#   tags: [health, kubernetes, pods, eviction, qos, resources]
#   requires: [kubectl]
#   brief: Analyze pods at risk of eviction due to resource pressure

"""
Analyze Kubernetes pods at risk of eviction.

Identifies pods likely to be evicted due to node memory pressure, disk pressure,
or other kubelet eviction policies. Analyzes QoS class, resource limits, and
node conditions.

Exit codes:
    0: No pods at high risk of eviction
    1: One or more pods at risk of eviction detected
    2: Usage error or kubectl not available
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_memory_value(mem_str: str) -> int:
    """
    Parse Kubernetes memory string to bytes.
    Examples: "512Mi" -> 536870912, "1Gi" -> 1073741824
    """
    if not mem_str:
        return 0

    mem_str = mem_str.strip().upper()

    # Extract numeric and unit parts
    numeric_part = ""
    unit_part = ""
    for i, char in enumerate(mem_str):
        if char.isdigit() or char == ".":
            numeric_part += char
        else:
            unit_part = mem_str[i:]
            break

    if not numeric_part:
        return 0

    value = float(numeric_part)

    units = {
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
        "KI": 1024,
        "MI": 1024**2,
        "GI": 1024**3,
        "TI": 1024**4,
    }

    unit_key = unit_part.rstrip("B").upper() if unit_part else ""
    multiplier = units.get(unit_key, 1)

    return int(value * multiplier)


def get_nodes_with_pressure(context: Context) -> dict[str, dict]:
    """Get all nodes and their pressure conditions."""
    result = context.run(["kubectl", "get", "nodes", "-o", "json"])
    if result.returncode != 0:
        raise RuntimeError(f"kubectl failed: {result.stderr}")

    nodes_data = json.loads(result.stdout)
    pressure_nodes = {}

    for node in nodes_data.get("items", []):
        node_name = node.get("metadata", {}).get("name", "unknown")
        conditions = node.get("status", {}).get("conditions", [])

        pressure_info = {
            "memory_pressure": False,
            "disk_pressure": False,
            "pid_pressure": False,
            "not_ready": False,
        }

        for condition in conditions:
            cond_type = condition.get("type", "")
            cond_status = condition.get("status", "Unknown")

            if cond_type == "MemoryPressure" and cond_status == "True":
                pressure_info["memory_pressure"] = True
            elif cond_type == "DiskPressure" and cond_status == "True":
                pressure_info["disk_pressure"] = True
            elif cond_type == "PIDPressure" and cond_status == "True":
                pressure_info["pid_pressure"] = True
            elif cond_type == "Ready" and cond_status == "False":
                pressure_info["not_ready"] = True

        if any(pressure_info.values()):
            pressure_nodes[node_name] = pressure_info

    return pressure_nodes


def get_pods(context: Context, namespace: str | None = None) -> dict:
    """Get all pods with their resource requests/limits."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    result = context.run(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"kubectl failed: {result.stderr}")
    return json.loads(result.stdout)


def determine_qos_class(pod: dict) -> str:
    """Determine QoS class of a pod."""
    containers = pod.get("spec", {}).get("containers", [])

    has_memory_limit = False
    has_memory_request = False
    has_cpu_limit = False
    has_cpu_request = False

    for container in containers:
        resources = container.get("resources", {})
        limits = resources.get("limits", {})
        requests = resources.get("requests", {})

        if limits.get("memory"):
            has_memory_limit = True
        if requests.get("memory"):
            has_memory_request = True
        if limits.get("cpu"):
            has_cpu_limit = True
        if requests.get("cpu"):
            has_cpu_request = True

    # Guaranteed: all containers have limits and requests, and they're equal
    if has_memory_limit and has_memory_request and has_cpu_limit and has_cpu_request:
        all_equal = True
        for container in containers:
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            requests = resources.get("requests", {})
            if limits != requests:
                all_equal = False
                break
        if all_equal:
            return "Guaranteed"

    # BestEffort: no requests or limits
    if not has_memory_request and not has_memory_limit and not has_cpu_request and not has_cpu_limit:
        return "BestEffort"

    return "Burstable"


def analyze_pod_eviction_risk(pod: dict, pressure_nodes: dict[str, dict]) -> tuple[str, list[str]]:
    """
    Analyze a pod for eviction risk.

    Returns:
        Tuple of (risk_level, risk_reasons)
    """
    node_name = pod.get("spec", {}).get("nodeName")
    risk_reasons = []

    # Check if pod is on a node with pressure
    if node_name and node_name in pressure_nodes:
        pressure_info = pressure_nodes[node_name]
        if pressure_info["memory_pressure"]:
            risk_reasons.append("Node has MemoryPressure condition")
        if pressure_info["disk_pressure"]:
            risk_reasons.append("Node has DiskPressure condition")
        if pressure_info["pid_pressure"]:
            risk_reasons.append("Node has PIDPressure condition")
        if pressure_info["not_ready"]:
            risk_reasons.append("Node is NotReady")

    # Determine QoS class
    qos_class = determine_qos_class(pod)

    if qos_class == "BestEffort":
        risk_reasons.append("QoS class: BestEffort (evicted first)")
    elif qos_class == "Burstable":
        risk_reasons.append("QoS class: Burstable (evicted after Guaranteed)")

    # Check for memory limits
    containers = pod.get("spec", {}).get("containers", [])
    containers_without_memory = []

    for container in containers:
        container_name = container.get("name", "unknown")
        resources = container.get("resources", {})
        limits = resources.get("limits", {})
        requests = resources.get("requests", {})

        if not limits.get("memory") and not requests.get("memory"):
            containers_without_memory.append(container_name)

    if containers_without_memory:
        risk_reasons.append(f"Containers without memory limits: {', '.join(containers_without_memory)}")

    # Check for OOMKilled history
    container_statuses = pod.get("status", {}).get("containerStatuses", [])
    for cs in container_statuses:
        restart_count = cs.get("restartCount", 0)
        if restart_count > 5:
            risk_reasons.append(f"High restart count: {restart_count}")

        last_state = cs.get("lastState", {})
        if "terminated" in last_state:
            terminated = last_state["terminated"]
            if terminated.get("reason") == "OOMKilled":
                risk_reasons.append(f"Container {cs.get('name')} was OOMKilled")

    # Determine risk level
    risk_level = "LOW"

    if not risk_reasons:
        risk_level = "NONE"
    elif any("MemoryPressure" in r for r in risk_reasons) or any("OOMKilled" in r for r in risk_reasons):
        risk_level = "CRITICAL"
    elif qos_class == "BestEffort":
        risk_level = "HIGH"
    elif qos_class == "Burstable" and containers_without_memory:
        risk_level = "HIGH"
    elif any("Pressure" in r or "NotReady" in r for r in risk_reasons):
        risk_level = "MEDIUM"
    elif containers_without_memory:
        risk_level = "MEDIUM"

    return risk_level, risk_reasons


def format_output_plain(pods_data: list[dict]) -> str:
    """Format output as plain text."""
    lines = []
    for pod in pods_data:
        ns = pod.get("namespace", "unknown")
        name = pod.get("name", "unknown")
        risk = pod.get("risk_level", "UNKNOWN")
        qos = pod.get("qos_class", "Unknown")
        reasons_str = "; ".join(pod.get("reasons", []))[:60]
        lines.append(f"{ns:20} {name:40} {risk:10} {qos:15} {reasons_str}")
    return "\n".join(lines)


def format_output_table(pods_data: list[dict]) -> str:
    """Format output as ASCII table."""
    lines = []
    lines.append(f"{'NAMESPACE':<20} {'POD NAME':<40} {'RISK':<10} {'QOS':<15} {'REASONS':<50}")
    lines.append("-" * 135)

    for pod in pods_data:
        ns = pod.get("namespace", "unknown")
        name = pod.get("name", "unknown")
        risk = pod.get("risk_level", "UNKNOWN")
        qos = pod.get("qos_class", "Unknown")
        reasons = pod.get("reasons", [])
        reasons_str = "; ".join(reasons)[:50] if reasons else ""
        lines.append(f"{ns:<20} {name:<40} {risk:<10} {qos:<15} {reasons_str:<50}")

    return "\n".join(lines)


def format_output_json(pods_data: list[dict]) -> str:
    """Format output as JSON."""
    output = {
        "pods_at_risk": len([p for p in pods_data if p["risk_level"] not in ("NONE", "LOW")]),
        "pods": pods_data,
    }
    return json.dumps(output, indent=2)


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no risk, 1 = risk found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze pods at risk of eviction due to resource pressure"
    )
    parser.add_argument(
        "-n", "--namespace", help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["plain", "table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show pods at risk of eviction"
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get pods
    try:
        pods_data = get_pods(context, opts.namespace)
        pods = pods_data.get("items", [])
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    if not pods:
        print("No pods found")
        output.set_summary("no pods")
        return 0

    # Get nodes with pressure
    try:
        pressure_nodes = get_nodes_with_pressure(context)
    except Exception as e:
        output.error(f"Failed to get nodes: {e}")
        return 2

    # Analyze each pod
    pods_at_risk = []
    all_analyzed_pods = []

    for pod in pods:
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name", "unknown")
        qos_class = determine_qos_class(pod)
        risk_level, risk_reasons = analyze_pod_eviction_risk(pod, pressure_nodes)

        pod_info = {
            "namespace": namespace,
            "name": pod_name,
            "qos_class": qos_class,
            "risk_level": risk_level,
            "reasons": risk_reasons,
        }

        all_analyzed_pods.append(pod_info)

        if risk_level not in ("NONE", "LOW"):
            pods_at_risk.append(pod_info)

    # Determine what to output
    output_pods = pods_at_risk if opts.warn_only else all_analyzed_pods

    if not output_pods:
        if opts.warn_only:
            print("No pods at risk of eviction found")
        output.set_summary("no at-risk pods")
        return 0 if not pods_at_risk else 1

    # Output
    if opts.format == "plain":
        print(format_output_plain(output_pods))
    elif opts.format == "table":
        print(format_output_table(output_pods))
    elif opts.format == "json":
        print(format_output_json(output_pods))

    output.set_summary(f"at_risk={len(pods_at_risk)}")

    return 1 if pods_at_risk else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
