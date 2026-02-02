#!/usr/bin/env python3
# boxctl:
#   category: k8s/batch
#   tags: [jobs, cronjobs, kubernetes, batch, failures]
#   requires: [kubectl]
#   privilege: user
#   brief: Analyze Job and CronJob failures with root cause analysis
#   related: [job_health, job_status]

"""
Kubernetes Job failure analyzer - Identify patterns and root causes of batch failures.

Analyzes Job failures, categorizes causes, and provides remediation:
- ImagePullBackOff, resource limits, deadline exceeded
- OOMKilled containers
- Init container failures
- CronJob scheduling issues

Exit codes:
    0 - No failures or only informational findings
    1 - Job failures detected with warnings
    2 - Usage error or kubectl not found
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_duration(duration_str: str) -> int:
    """Parse Kubernetes duration string to minutes."""
    if not duration_str:
        return 0

    total_minutes = 0
    duration_str = str(duration_str)

    # Handle simple integer (seconds)
    if duration_str.isdigit():
        return int(duration_str) // 60

    # Parse format like "1h30m", "30m", "2h"
    hours = re.search(r"(\d+)h", duration_str)
    minutes = re.search(r"(\d+)m", duration_str)
    seconds = re.search(r"(\d+)s", duration_str)

    if hours:
        total_minutes += int(hours.group(1)) * 60
    if minutes:
        total_minutes += int(minutes.group(1))
    if seconds:
        total_minutes += int(seconds.group(1)) // 60

    return total_minutes


def analyze_job_failure(job: dict, pods: list) -> dict:
    """Analyze why a job failed."""
    failure_info = {
        "category": "Unknown",
        "reason": "Unknown",
        "details": [],
        "pod_statuses": [],
    }

    # Check job conditions
    conditions = job.get("status", {}).get("conditions", [])
    for condition in conditions:
        if condition.get("type") == "Failed" and condition.get("status") == "True":
            reason = condition.get("reason", "Unknown")
            message = condition.get("message", "")

            if reason == "DeadlineExceeded":
                failure_info["category"] = "DeadlineExceeded"
                failure_info["reason"] = "Job exceeded activeDeadlineSeconds"
                failure_info["details"].append(message)
            elif reason == "BackoffLimitExceeded":
                failure_info["category"] = "BackoffLimitExceeded"
                failure_info["reason"] = "Job exceeded backoffLimit retries"
                failure_info["details"].append(message)
            else:
                failure_info["reason"] = reason
                failure_info["details"].append(message)

    # Analyze pod failures for more detail
    for pod in pods:
        pod_name = pod["metadata"]["name"]
        pod_phase = pod.get("status", {}).get("phase", "Unknown")

        pod_status = {"name": pod_name, "phase": pod_phase, "containers": []}

        # Check container statuses
        container_statuses = pod.get("status", {}).get("containerStatuses", [])
        for container in container_statuses:
            container_info = {
                "name": container["name"],
                "state": "Unknown",
                "reason": None,
                "exit_code": None,
            }

            # Check current state
            state = container.get("state", {})
            if "terminated" in state:
                terminated = state["terminated"]
                container_info["state"] = "Terminated"
                container_info["reason"] = terminated.get("reason")
                container_info["exit_code"] = terminated.get("exitCode")

                # Categorize based on termination reason
                if terminated.get("reason") == "OOMKilled":
                    failure_info["category"] = "OOMKilled"
                    failure_info["reason"] = "Container killed due to memory limit"
                elif terminated.get("exitCode", 0) != 0:
                    if failure_info["category"] == "Unknown":
                        failure_info["category"] = "ApplicationError"
                        failure_info["reason"] = (
                            f"Container exited with code {terminated.get('exitCode')}"
                        )

            elif "waiting" in state:
                waiting = state["waiting"]
                container_info["state"] = "Waiting"
                container_info["reason"] = waiting.get("reason")

                # Check for image pull issues
                if waiting.get("reason") in ["ImagePullBackOff", "ErrImagePull"]:
                    failure_info["category"] = "ImagePullFailure"
                    failure_info["reason"] = "Failed to pull container image"
                    failure_info["details"].append(waiting.get("message", ""))
                elif waiting.get("reason") == "CreateContainerConfigError":
                    failure_info["category"] = "ConfigError"
                    failure_info["reason"] = "Failed to create container config"
                    failure_info["details"].append(waiting.get("message", ""))

            pod_status["containers"].append(container_info)

        # Check init container statuses
        init_statuses = pod.get("status", {}).get("initContainerStatuses", [])
        for init_container in init_statuses:
            state = init_container.get("state", {})
            if "waiting" in state:
                reason = state["waiting"].get("reason", "")
                if reason in ["ImagePullBackOff", "ErrImagePull"]:
                    failure_info["category"] = "InitContainerImagePullFailure"
                    failure_info["reason"] = "Failed to pull init container image"
            elif "terminated" in state:
                if state["terminated"].get("exitCode", 0) != 0:
                    if failure_info["category"] == "Unknown":
                        failure_info["category"] = "InitContainerError"
                        failure_info["reason"] = "Init container failed"

        failure_info["pod_statuses"].append(pod_status)

    return failure_info


def analyze_cronjob_issues(cronjob: dict, jobs: list) -> list:
    """Analyze CronJob health and issues."""
    issues = []
    cronjob_name = cronjob["metadata"]["name"]

    spec = cronjob.get("spec", {})
    status = cronjob.get("status", {})

    # Check if suspended
    if spec.get("suspend", False):
        issues.append({"type": "Suspended", "message": "CronJob is suspended"})

    # Check last schedule time
    last_schedule = status.get("lastScheduleTime")
    if last_schedule:
        try:
            last_schedule_time = datetime.fromisoformat(
                last_schedule.replace("Z", "+00:00")
            )
            hours_since_last = (
                datetime.now(last_schedule_time.tzinfo) - last_schedule_time
            ).total_seconds() / 3600

            # If more than 24h since last schedule, might be an issue
            if hours_since_last > 24:
                issues.append(
                    {
                        "type": "StaleSchedule",
                        "message": f"No jobs scheduled in {int(hours_since_last)} hours",
                    }
                )
        except (ValueError, TypeError):
            pass

    # Check for too many active jobs (possible stuck jobs)
    active_jobs = status.get("active", [])
    concurrency_policy = spec.get("concurrencyPolicy", "Allow")

    if len(active_jobs) > 1 and concurrency_policy == "Forbid":
        issues.append(
            {
                "type": "ConcurrencyViolation",
                "message": f"{len(active_jobs)} active jobs with Forbid policy",
            }
        )

    # Check failed job history
    failed_jobs_limit = spec.get("failedJobsHistoryLimit", 1)
    related_failed_jobs = [
        j
        for j in jobs
        if j["metadata"].get("ownerReferences", [{}])[0].get("name") == cronjob_name
        and j.get("status", {}).get("failed", 0) > 0
    ]

    if len(related_failed_jobs) >= failed_jobs_limit:
        issues.append(
            {
                "type": "HighFailureRate",
                "message": f"{len(related_failed_jobs)} recent failed jobs",
            }
        )

    return issues


def suggest_remediation(failure_category: str, job_info: dict) -> list:
    """Suggest remediation based on failure category."""
    suggestions = []

    if failure_category == "DeadlineExceeded":
        suggestions.append("Job took longer than activeDeadlineSeconds")
        suggestions.append("Consider increasing spec.activeDeadlineSeconds")
        suggestions.append("Review job performance and optimize execution time")
        suggestions.append("Check for resource contention or slow dependencies")

    elif failure_category == "BackoffLimitExceeded":
        suggestions.append("Job failed too many times (exceeded backoffLimit)")
        suggestions.append("Check pod logs for failure reason")
        suggestions.append("Verify external dependencies are available")
        suggestions.append(
            "Consider increasing spec.backoffLimit for transient failures"
        )

    elif failure_category == "OOMKilled":
        suggestions.append("Container was killed due to memory limit")
        suggestions.append("Increase memory limits in job spec")
        suggestions.append("Profile application memory usage")
        suggestions.append("Check for memory leaks in batch processing code")

    elif failure_category == "ImagePullFailure":
        suggestions.append("Failed to pull container image")
        suggestions.append("Verify image name and tag exist")
        suggestions.append("Check imagePullSecrets for private registries")
        suggestions.append("Verify network connectivity to registry")

    elif failure_category == "InitContainerImagePullFailure":
        suggestions.append("Failed to pull init container image")
        suggestions.append("Verify init container image exists")
        suggestions.append("Check imagePullSecrets configuration")

    elif failure_category == "ConfigError":
        suggestions.append("Container configuration error")
        suggestions.append("Verify ConfigMap and Secret references exist")
        suggestions.append("Check volume mounts and environment variables")

    elif failure_category == "InitContainerError":
        suggestions.append("Init container failed")
        suggestions.append("Check init container logs")
        suggestions.append("Verify init container dependencies are met")

    elif failure_category == "ApplicationError":
        suggestions.append("Application exited with error")
        suggestions.append("Check job pod logs for error details")
        suggestions.append("Verify input data and configuration")
        suggestions.append("Review application error handling")

    else:
        suggestions.append("Unknown failure - check job events and pod logs")
        ns = job_info.get("namespace", "default")
        name = job_info.get("name", "unknown")
        suggestions.append(f"kubectl describe job {name} -n {ns}")
        suggestions.append(f"kubectl logs -l job-name={name} -n {ns}")

    return suggestions


def get_failed_jobs(jobs_data: dict, timeframe_hours: int | None = None) -> list:
    """Filter jobs to only failed ones, optionally within timeframe."""
    failed_jobs = []

    for job in jobs_data.get("items", []):
        status = job.get("status", {})

        # Check if job failed
        is_failed = False
        conditions = status.get("conditions", [])
        for condition in conditions:
            if condition.get("type") == "Failed" and condition.get("status") == "True":
                is_failed = True
                break

        # Also check if failed count > 0
        if status.get("failed", 0) > 0:
            is_failed = True

        if not is_failed:
            continue

        # Filter by timeframe if specified
        if timeframe_hours:
            completion_time = status.get("completionTime") or status.get("startTime")
            if completion_time:
                try:
                    job_time = datetime.fromisoformat(
                        completion_time.replace("Z", "+00:00")
                    )
                    cutoff = datetime.now(job_time.tzinfo) - timedelta(
                        hours=timeframe_hours
                    )
                    if job_time < cutoff:
                        continue
                except (ValueError, TypeError):
                    pass

        failed_jobs.append(job)

    return failed_jobs


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no failures, 1 = failures found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes Job and CronJob failures"
    )
    parser.add_argument(
        "-n",
        "--namespace",
        help="Analyze failures in specific namespace (default: all namespaces)",
    )
    parser.add_argument(
        "--timeframe",
        type=int,
        metavar="HOURS",
        help="Only analyze failures within last N hours",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed analysis with remediation suggestions",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show warnings (skip summary sections)",
    )
    parser.add_argument(
        "--include-cronjobs",
        action="store_true",
        help="Include CronJob health analysis",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json"],
        default="plain",
        help="Output format (default: plain)",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Get jobs
    cmd = ["kubectl", "get", "jobs", "-o", "json"]
    if opts.namespace:
        cmd.extend(["-n", opts.namespace])
    else:
        cmd.append("--all-namespaces")

    try:
        result = context.run(cmd)
        if result.returncode != 0:
            output.error(f"kubectl failed: {result.stderr}")
            return 2
        jobs_data = json.loads(result.stdout)
    except Exception as e:
        output.error(f"Failed to get jobs: {e}")
        return 2

    failed_jobs = get_failed_jobs(jobs_data, opts.timeframe)

    # Initialize analysis
    analysis = {
        "total_failed": len(failed_jobs),
        "cronjobs_with_issues": 0,
        "by_category": defaultdict(list),
        "by_namespace": defaultdict(int),
        "failed_jobs": [],
        "cronjob_issues": [],
    }

    # Analyze each failed job
    for job in failed_jobs:
        job_name = job["metadata"]["name"]
        job_namespace = job["metadata"]["namespace"]

        # Get pods for this job
        pods = []
        try:
            pods_cmd = [
                "kubectl",
                "get",
                "pods",
                "-n",
                job_namespace,
                "-l",
                f"job-name={job_name}",
                "-o",
                "json",
            ]
            pods_result = context.run(pods_cmd)
            if pods_result.returncode == 0:
                pods = json.loads(pods_result.stdout).get("items", [])
        except Exception:
            pass

        # Analyze failure
        failure_info = analyze_job_failure(job, pods)

        # Get owner reference (CronJob)
        owner_refs = job["metadata"].get("ownerReferences", [])
        cronjob_owner = None
        for ref in owner_refs:
            if ref.get("kind") == "CronJob":
                cronjob_owner = ref.get("name")
                break

        job_info = {
            "name": job_name,
            "namespace": job_namespace,
            "failure_category": failure_info["category"],
            "failure_reason": failure_info["reason"],
            "failure_details": failure_info["details"],
            "pod_statuses": failure_info["pod_statuses"],
            "cronjob_owner": cronjob_owner,
            "failed_count": job.get("status", {}).get("failed", 0),
        }

        analysis["by_category"][failure_info["category"]].append(job_info)
        analysis["by_namespace"][job_namespace] += 1
        analysis["failed_jobs"].append(job_info)

    # Analyze CronJobs if requested
    if opts.include_cronjobs:
        cron_cmd = ["kubectl", "get", "cronjobs", "-o", "json"]
        if opts.namespace:
            cron_cmd.extend(["-n", opts.namespace])
        else:
            cron_cmd.append("--all-namespaces")

        try:
            result = context.run(cron_cmd)
            if result.returncode == 0:
                cronjobs_data = json.loads(result.stdout)
                all_jobs = jobs_data.get("items", [])

                for cronjob in cronjobs_data.get("items", []):
                    issues = analyze_cronjob_issues(cronjob, all_jobs)
                    if issues:
                        analysis["cronjobs_with_issues"] += 1
                        analysis["cronjob_issues"].append(
                            {
                                "name": cronjob["metadata"]["name"],
                                "namespace": cronjob["metadata"]["namespace"],
                                "issues": issues,
                            }
                        )
        except Exception:
            pass

    # Format and print output
    if opts.format == "json":
        output_data = {
            "total_failed": analysis["total_failed"],
            "cronjobs_with_issues": analysis["cronjobs_with_issues"],
            "by_category": {k: len(v) for k, v in analysis["by_category"].items()},
            "by_namespace": dict(analysis["by_namespace"]),
            "failed_jobs": analysis["failed_jobs"],
            "cronjob_issues": analysis["cronjob_issues"],
        }
        print(json.dumps(output_data, indent=2, default=str))
    else:  # plain format
        if not opts.warn_only:
            print("Kubernetes Job Failure Analysis")
            print("=" * 80)
            print(f"Total failed jobs: {analysis['total_failed']}")
            print(f"Total CronJobs with issues: {analysis['cronjobs_with_issues']}")
            print()

        # Failures by category
        if analysis["by_category"] and not opts.warn_only:
            print("Failures by Category:")
            print("-" * 80)
            for category, jobs in sorted(
                analysis["by_category"].items(), key=lambda x: len(x[1]), reverse=True
            ):
                print(f"  {category}: {len(jobs)} jobs")
            print()

        # Failures by namespace
        if analysis["by_namespace"] and not opts.warn_only:
            print("Failures by Namespace:")
            print("-" * 80)
            for namespace, count in sorted(
                analysis["by_namespace"].items(), key=lambda x: x[1], reverse=True
            )[:10]:
                print(f"  {namespace}: {count} failures")
            print()

        # High-priority failed jobs
        if analysis["failed_jobs"]:
            print("Failed Jobs:")
            print("-" * 80)
            for job_info in sorted(
                analysis["failed_jobs"],
                key=lambda x: x.get("failed_count", 0),
                reverse=True,
            )[:20]:
                print(f"  {job_info['namespace']}/{job_info['name']}")
                print(f"    Category: {job_info['failure_category']}")
                print(f"    Reason: {job_info['failure_reason']}")

                if job_info.get("cronjob_owner"):
                    print(f"    CronJob: {job_info['cronjob_owner']}")

                if opts.verbose:
                    suggestions = suggest_remediation(
                        job_info["failure_category"], job_info
                    )
                    if suggestions:
                        print("    Remediation:")
                        for suggestion in suggestions[:3]:
                            print(f"      - {suggestion}")
                print()

        # CronJob issues
        if analysis["cronjob_issues"]:
            print("CronJob Issues:")
            print("-" * 80)
            for cronjob_info in analysis["cronjob_issues"]:
                print(f"  {cronjob_info['namespace']}/{cronjob_info['name']}")
                for issue in cronjob_info["issues"]:
                    print(f"    - {issue['type']}: {issue['message']}")
                print()

        if not analysis["failed_jobs"] and not analysis["cronjob_issues"]:
            print("No job failures or CronJob issues detected.")

    output.set_summary(
        f"failed_jobs={analysis['total_failed']}, cronjob_issues={analysis['cronjobs_with_issues']}"
    )

    # Exit with appropriate code
    if analysis["total_failed"] > 0 or analysis["cronjobs_with_issues"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
