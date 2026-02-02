#!/usr/bin/env python3
# boxctl:
#   category: k8s/reliability
#   tags: [probes, kubernetes, health, reliability, liveness, readiness]
#   requires: [kubectl]
#   brief: Audit pod health probe configurations for reliability issues
#   privilege: user
#   related: [container_restart_analyzer, pod_resource_audit]

"""
Kubernetes health probe configuration audit - Identify reliability issues.

Checks for:
- Missing liveness probes (can't detect hung processes)
- Missing readiness probes (may receive traffic before ready)
- Missing startup probes for slow-starting containers
- Probe misconfiguration (low timeouts, aggressive thresholds)
- Identical liveness and readiness probes

Useful for:
- Reliability audits
- Service availability improvements
- Container health monitoring
- Pre-production validation

Exit codes:
    0 - All pods have properly configured probes
    1 - Probe configuration issues detected
    2 - Usage error or kubectl not found
"""

import argparse
import json
from collections import defaultdict

from boxctl.core.context import Context
from boxctl.core.output import Output


# Default thresholds for probe configuration warnings
DEFAULT_THRESHOLDS = {
    "min_initial_delay": 5,
    "min_timeout": 1,
    "max_failure_threshold": 10,
    "min_period": 5,
    "slow_start_threshold": 60,
}

# System namespaces often excluded from audits
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


def analyze_probe(probe: dict | None, probe_type: str, container_name: str) -> list:
    """Analyze a single probe configuration for issues."""
    issues = []

    if not probe:
        return issues

    timeout = probe.get("timeoutSeconds", 1)
    if timeout < DEFAULT_THRESHOLDS["min_timeout"]:
        issues.append(
            {
                "severity": "LOW",
                "type": f"{probe_type}_low_timeout",
                "detail": f"{probe_type} timeout is very low ({timeout}s)",
                "recommendation": "Consider increasing timeoutSeconds to avoid "
                "false positives under load",
            }
        )

    failure_threshold = probe.get("failureThreshold", 3)
    if failure_threshold > DEFAULT_THRESHOLDS["max_failure_threshold"]:
        issues.append(
            {
                "severity": "MEDIUM",
                "type": f"{probe_type}_high_failure_threshold",
                "detail": f"{probe_type} failureThreshold is high ({failure_threshold})",
                "recommendation": "High failure threshold delays detection of "
                "unhealthy containers",
            }
        )

    period = probe.get("periodSeconds", 10)
    if period < DEFAULT_THRESHOLDS["min_period"]:
        issues.append(
            {
                "severity": "LOW",
                "type": f"{probe_type}_aggressive_period",
                "detail": f"{probe_type} periodSeconds is aggressive ({period}s)",
                "recommendation": "Very frequent probes may add unnecessary load",
            }
        )

    http_get = probe.get("httpGet")
    if http_get:
        if not http_get.get("path"):
            issues.append(
                {
                    "severity": "MEDIUM",
                    "type": f"{probe_type}_no_path",
                    "detail": f"{probe_type} HTTP probe has no path specified",
                    "recommendation": "Specify a health check path for the HTTP probe",
                }
            )

    exec_probe = probe.get("exec")
    if exec_probe:
        command = exec_probe.get("command", [])
        if not command:
            issues.append(
                {
                    "severity": "HIGH",
                    "type": f"{probe_type}_empty_exec",
                    "detail": f"{probe_type} exec probe has empty command",
                    "recommendation": "Specify a command for the exec probe",
                }
            )

    return issues


def analyze_container_probes(container: dict, pod_name: str, namespace: str) -> list:
    """Analyze all probes for a single container."""
    issues = []
    container_name = container.get("name", "unknown")

    liveness_probe = container.get("livenessProbe")
    readiness_probe = container.get("readinessProbe")
    startup_probe = container.get("startupProbe")

    if not liveness_probe:
        issues.append(
            {
                "severity": "HIGH",
                "type": "missing_liveness_probe",
                "namespace": namespace,
                "pod": pod_name,
                "container": container_name,
                "detail": "No liveness probe configured",
                "recommendation": "Add liveness probe to detect hung/deadlocked processes",
            }
        )

    if not readiness_probe:
        issues.append(
            {
                "severity": "MEDIUM",
                "type": "missing_readiness_probe",
                "namespace": namespace,
                "pod": pod_name,
                "container": container_name,
                "detail": "No readiness probe configured",
                "recommendation": "Add readiness probe to prevent traffic before ready",
            }
        )

    if liveness_probe:
        initial_delay = liveness_probe.get("initialDelaySeconds", 0)
        if initial_delay >= DEFAULT_THRESHOLDS["slow_start_threshold"]:
            if not startup_probe:
                issues.append(
                    {
                        "severity": "MEDIUM",
                        "type": "missing_startup_probe",
                        "namespace": namespace,
                        "pod": pod_name,
                        "container": container_name,
                        "detail": f"High liveness initialDelaySeconds ({initial_delay}s) "
                        "but no startup probe",
                        "recommendation": "Use startup probe for slow-starting containers "
                        "instead of high initialDelaySeconds",
                    }
                )

    for probe, probe_type in [
        (liveness_probe, "liveness"),
        (readiness_probe, "readiness"),
        (startup_probe, "startup"),
    ]:
        probe_issues = analyze_probe(probe, probe_type, container_name)
        for issue in probe_issues:
            issue["namespace"] = namespace
            issue["pod"] = pod_name
            issue["container"] = container_name
            issues.append(issue)

    if liveness_probe and not readiness_probe:
        issues.append(
            {
                "severity": "MEDIUM",
                "type": "liveness_without_readiness",
                "namespace": namespace,
                "pod": pod_name,
                "container": container_name,
                "detail": "Liveness probe without readiness probe",
                "recommendation": "Add readiness probe to control when pod receives traffic",
            }
        )

    if liveness_probe and readiness_probe:
        if (
            liveness_probe.get("httpGet") == readiness_probe.get("httpGet")
            and liveness_probe.get("tcpSocket") == readiness_probe.get("tcpSocket")
            and liveness_probe.get("exec") == readiness_probe.get("exec")
        ):
            issues.append(
                {
                    "severity": "LOW",
                    "type": "identical_probes",
                    "namespace": namespace,
                    "pod": pod_name,
                    "container": container_name,
                    "detail": "Liveness and readiness probes are identical",
                    "recommendation": "Consider using different endpoints or logic "
                    "for liveness vs readiness checks",
                }
            )

    return issues


def analyze_pod_probes(pod: dict, exclude_system: bool = True) -> list:
    """Analyze all probe configurations for a pod."""
    issues = []
    metadata = pod.get("metadata", {})
    pod_name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")
    spec = pod.get("spec", {})

    if exclude_system and namespace in SYSTEM_NAMESPACES:
        return issues

    containers = spec.get("containers", [])
    for container in containers:
        issues.extend(analyze_container_probes(container, pod_name, namespace))

    init_containers = spec.get("initContainers", [])
    for container in init_containers:
        container_name = container.get("name", "unknown")
        for probe_type in ["livenessProbe", "readinessProbe"]:
            probe = container.get(probe_type)
            if probe:
                issues.append(
                    {
                        "severity": "LOW",
                        "type": f"init_container_{probe_type}",
                        "namespace": namespace,
                        "pod": pod_name,
                        "container": container_name,
                        "detail": f"Init container has {probe_type} (usually not needed)",
                        "recommendation": "Init containers typically do not need "
                        "liveness or readiness probes",
                    }
                )

    return issues


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
        description="Audit Kubernetes pod health probe configurations"
    )
    parser.add_argument(
        "-n", "--namespace", help="Namespace to audit (default: all namespaces)"
    )
    parser.add_argument(
        "--include-system",
        action="store_true",
        help="Include system namespaces (kube-system, kube-public, etc.)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["plain", "table", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information with recommendations",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show warnings (exclude LOW severity)",
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

    all_issues = []
    for pod in pods:
        issues = analyze_pod_probes(pod, exclude_system=not opts.include_system)
        all_issues.extend(issues)

    # Output results
    if opts.format == "json":
        result_data = {
            "summary": {
                "total_issues": len(all_issues),
                "high": len([i for i in all_issues if i["severity"] == "HIGH"]),
                "medium": len([i for i in all_issues if i["severity"] == "MEDIUM"]),
                "low": len([i for i in all_issues if i["severity"] == "LOW"]),
            },
            "issues": all_issues,
        }
        print(json.dumps(result_data, indent=2))
    elif opts.format == "table":
        if not all_issues:
            print("All pods have properly configured health probes")
        else:
            display_issues = all_issues
            if opts.warn_only:
                display_issues = [i for i in all_issues if i["severity"] != "LOW"]

            if not display_issues:
                print("No high or medium severity issues found")
            else:
                print(
                    f"{'Severity':<8} {'Type':<30} {'Namespace/Pod':<35} {'Container':<20}"
                )
                print("=" * 95)

                for issue in sorted(
                    display_issues,
                    key=lambda x: ["HIGH", "MEDIUM", "LOW"].index(x["severity"]),
                ):
                    pod_full = f"{issue['namespace']}/{issue['pod']}"
                    if len(pod_full) > 32:
                        pod_full = pod_full[:32] + "..."

                    container = issue.get("container", "*")
                    if len(container) > 17:
                        container = container[:17] + "..."

                    issue_type = issue["type"]
                    if len(issue_type) > 27:
                        issue_type = issue_type[:27] + "..."

                    print(
                        f"{issue['severity']:<8} {issue_type:<30} "
                        f"{pod_full:<35} {container:<20}"
                    )
    else:  # plain
        if not all_issues:
            print("All pods have properly configured health probes")
        else:
            by_severity = defaultdict(list)
            for issue in all_issues:
                by_severity[issue["severity"]].append(issue)

            if not opts.warn_only:
                print("Kubernetes Health Probe Configuration Audit")
                print("=" * 70)
                print(f"Total issues: {len(all_issues)}")
                print(f"  HIGH: {len(by_severity['HIGH'])}")
                print(f"  MEDIUM: {len(by_severity['MEDIUM'])}")
                print(f"  LOW: {len(by_severity['LOW'])}")
                print()

            for severity in ["HIGH", "MEDIUM", "LOW"]:
                if severity not in by_severity:
                    continue

                if opts.warn_only and severity == "LOW":
                    continue

                issues = by_severity[severity]
                print(f"{severity} SEVERITY ({len(issues)} issues):")
                print("-" * 70)

                for issue in issues:
                    print(f"  [{issue['type']}] {issue['namespace']}/{issue['pod']}")
                    if issue.get("container"):
                        print(f"    Container: {issue['container']}")
                    print(f"    {issue['detail']}")
                    if opts.verbose and issue.get("recommendation"):
                        print(f"    Recommendation: {issue['recommendation']}")
                print()

    high_medium = [i for i in all_issues if i["severity"] in ("HIGH", "MEDIUM")]
    output.set_summary(
        f"issues={len(all_issues)}, high={len([i for i in all_issues if i['severity'] == 'HIGH'])}, "
        f"medium={len([i for i in all_issues if i['severity'] == 'MEDIUM'])}"
    )

    return 1 if high_medium else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
