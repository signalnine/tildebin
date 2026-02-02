#!/usr/bin/env python3
# boxctl:
#   category: k8s/troubleshooting
#   tags: [images, kubernetes, troubleshooting, pull, registry]
#   requires: [kubectl]
#   privilege: user
#   brief: Analyze image pull issues across the cluster
#   related: [image_policy]

"""
Kubernetes image pull analyzer - Diagnose image pull failures and performance.

Analyzes image pull issues across the cluster including:
- ImagePullBackOff and ErrImagePull errors
- Image pull times and patterns
- Registry connectivity problems
- Authentication failures
- Slow image pulls indicating registry cache issues

Exit codes:
    0 - No image pull issues detected
    1 - Image pull issues found
    2 - Usage error or kubectl not available
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def analyze_pod_image_status(pod: dict) -> list:
    """Analyze image pull status for a pod."""
    issues = []
    namespace = pod["metadata"]["namespace"]
    name = pod["metadata"]["name"]

    # Check container statuses
    container_statuses = pod.get("status", {}).get("containerStatuses", [])
    init_container_statuses = pod.get("status", {}).get("initContainerStatuses", [])

    all_statuses = container_statuses + init_container_statuses

    for status in all_statuses:
        container_name = status["name"]
        image = status["image"]

        # Check for image pull errors
        waiting = status.get("state", {}).get("waiting", {})
        if waiting:
            reason = waiting.get("reason", "")
            message = waiting.get("message", "")

            if reason in ["ImagePullBackOff", "ErrImagePull"]:
                issues.append(
                    {
                        "type": "image_pull_backoff",
                        "severity": "error",
                        "namespace": namespace,
                        "pod": name,
                        "container": container_name,
                        "image": image,
                        "reason": reason,
                        "message": message,
                    }
                )

        # Check for authentication errors in terminated state
        terminated = status.get("lastState", {}).get("terminated", {})
        if terminated:
            reason = terminated.get("reason", "")
            message = terminated.get("message", "")

            if "authentication" in message.lower() or "unauthorized" in message.lower():
                issues.append(
                    {
                        "type": "auth_failure",
                        "severity": "error",
                        "namespace": namespace,
                        "pod": name,
                        "container": container_name,
                        "image": image,
                        "reason": reason,
                        "message": message,
                    }
                )

    return issues


def analyze_events(events: dict, max_age_minutes: int = 60) -> list:
    """Analyze events for image pull related issues."""
    issues = []

    for event in events.get("items", []):
        reason = event.get("reason", "")
        message = event.get("message", "")
        event_type = event.get("type", "")

        # Filter for image-related events
        if reason not in ["Failed", "BackOff", "Pulling", "Pulled"]:
            continue

        # Check event age
        last_timestamp = event.get("lastTimestamp")
        if not last_timestamp:
            continue

        # Parse timestamp
        try:
            event_time = datetime.fromisoformat(last_timestamp.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            age_minutes = (now - event_time).total_seconds() / 60

            if age_minutes > max_age_minutes:
                continue
        except Exception:
            continue

        # Extract relevant information
        involved_object = event.get("involvedObject", {})
        namespace = involved_object.get("namespace", "unknown")
        pod_name = involved_object.get("name", "unknown")

        # Detect slow pulls
        if reason == "Pulling" and event_type == "Normal":
            issues.append(
                {
                    "type": "pulling",
                    "severity": "info",
                    "namespace": namespace,
                    "pod": pod_name,
                    "message": message,
                    "timestamp": last_timestamp,
                }
            )

        # Detect pull failures
        if reason in ["Failed", "BackOff"] and "image" in message.lower():
            severity = "error" if event_type == "Warning" else "warning"
            issues.append(
                {
                    "type": "pull_failure",
                    "severity": severity,
                    "namespace": namespace,
                    "pod": pod_name,
                    "reason": reason,
                    "message": message,
                    "timestamp": last_timestamp,
                }
            )

    return issues


def aggregate_issues(issues: list) -> dict:
    """Aggregate issues by type and image."""
    aggregated = {
        "by_type": defaultdict(int),
        "by_image": defaultdict(int),
        "by_namespace": defaultdict(int),
        "by_node": defaultdict(int),
        "total": len(issues),
    }

    for issue in issues:
        issue_type = issue.get("type", "unknown")
        aggregated["by_type"][issue_type] += 1

        if "image" in issue:
            image = issue["image"]
            aggregated["by_image"][image] += 1

        if "namespace" in issue:
            namespace = issue["namespace"]
            aggregated["by_namespace"][namespace] += 1

        if "node" in issue:
            node = issue["node"]
            aggregated["by_node"][node] += 1

    return aggregated


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes image pull issues and performance"
    )
    parser.add_argument(
        "-n", "--namespace", help="Namespace to check (default: all namespaces)"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed information"
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show warnings and errors",
    )
    parser.add_argument(
        "--max-age",
        type=int,
        default=60,
        help="Maximum age of events to analyze in minutes (default: 60)",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get pods
    pod_cmd = ["kubectl", "get", "pods", "-o", "json"]
    if opts.namespace:
        pod_cmd.extend(["-n", opts.namespace])
    else:
        pod_cmd.append("--all-namespaces")

    try:
        result = context.run(pod_cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        pods = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get pods: {e}")
        return 2

    # Get events
    event_cmd = ["kubectl", "get", "events", "-o", "json"]
    if opts.namespace:
        event_cmd.extend(["-n", opts.namespace])
    else:
        event_cmd.append("--all-namespaces")

    try:
        result = context.run(event_cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        events = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get events: {e}")
        return 2

    # Analyze issues
    all_issues = []

    # Analyze pod statuses
    for pod in pods.get("items", []):
        pod_issues = analyze_pod_image_status(pod)
        all_issues.extend(pod_issues)

    # Analyze events
    event_issues = analyze_events(events, opts.max_age)
    all_issues.extend(event_issues)

    # Aggregate results
    aggregated = aggregate_issues(all_issues)

    # Filter if warn-only
    if opts.warn_only:
        all_issues = [
            i for i in all_issues if i.get("severity") in ["error", "warning"]
        ]

    # Count errors
    error_count = sum(1 for i in all_issues if i.get("severity") == "error")

    # Output results
    if opts.format == "json":
        result = {
            "summary": {
                "total_issues": len(all_issues),
                "by_type": dict(aggregated["by_type"]),
                "by_image": dict(aggregated["by_image"]),
                "by_namespace": dict(aggregated["by_namespace"]),
            },
            "issues": all_issues,
        }
        print(json.dumps(result, indent=2))
    elif opts.format == "table":
        if not all_issues:
            print("No image pull issues detected")
        else:
            print(f"Image Pull Issues Summary (Total: {len(all_issues)})")
            print()

            # Summary table
            print(f"{'Type':<25} {'Count':<10}")
            print("-" * 35)
            for issue_type, count in sorted(aggregated["by_type"].items()):
                print(f"{issue_type:<25} {count:<10}")
            print()

            # Top images with issues
            if aggregated["by_image"]:
                print(f"{'Image':<60} {'Count':<10}")
                print("-" * 70)
                for image, count in sorted(
                    aggregated["by_image"].items(), key=lambda x: x[1], reverse=True
                )[:10]:
                    image_short = image if len(image) <= 60 else image[:57] + "..."
                    print(f"{image_short:<60} {count:<10}")
    else:  # plain format
        if not all_issues:
            print("No image pull issues detected")
        else:
            print(f"Found {len(all_issues)} image pull issues\n")

            # Summary by type
            print("Issues by type:")
            for issue_type, count in sorted(aggregated["by_type"].items()):
                print(f"  {issue_type}: {count}")
            print()

            # Issues by image
            if aggregated["by_image"]:
                print("Issues by image:")
                for image, count in sorted(
                    aggregated["by_image"].items(), key=lambda x: x[1], reverse=True
                )[:10]:
                    print(f"  {image}: {count}")
                print()

            # Detailed issues
            if opts.verbose:
                print("Detailed issues:")
                for issue in all_issues:
                    severity = issue.get("severity", "info").upper()
                    issue_type = issue.get("type", "unknown")
                    namespace = issue.get("namespace", "unknown")
                    pod = issue.get("pod", "unknown")

                    print(f"[{severity}] {issue_type}")
                    print(f"  Namespace: {namespace}")
                    print(f"  Pod: {pod}")

                    if "container" in issue:
                        print(f"  Container: {issue['container']}")
                    if "image" in issue:
                        print(f"  Image: {issue['image']}")
                    if "message" in issue:
                        print(f"  Message: {issue['message']}")
                    print()

    output.set_summary(f"issues={len(all_issues)}, errors={error_count}")

    # Exit with appropriate code
    return 1 if error_count > 0 else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
