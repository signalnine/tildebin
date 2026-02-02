#!/usr/bin/env python3
# boxctl:
#   category: k8s/batch
#   tags: [jobs, cronjobs, kubernetes, batch, health]
#   requires: [kubectl]
#   privilege: user
#   brief: Monitor Job and CronJob health and execution patterns
#   related: [job_failures, job_status]

"""
Kubernetes Job health monitor - Track batch workload health and patterns.

Analyzes batch workload health including:
- Job completion status (successful, failed, active)
- CronJob scheduling health (last schedule, successful runs)
- Long-running or stuck jobs
- Failed job patterns and error messages
- Jobs without TTL after finished cleanup
- CronJobs with consecutive failures

Exit codes:
    0 - All jobs and cronjobs healthy
    1 - Failed or stuck jobs detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
from datetime import datetime, timezone

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_timestamp(ts_str: str | None) -> datetime | None:
    """Parse Kubernetes timestamp to datetime object."""
    if not ts_str:
        return None
    try:
        # Handle both 'Z' and timezone-aware formats
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
    except (ValueError, AttributeError):
        return None


def analyze_job(job: dict) -> dict:
    """Analyze a single job for issues."""
    metadata = job.get("metadata", {})
    status = job.get("status", {})
    spec = job.get("spec", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    # Job status
    succeeded = status.get("succeeded", 0)
    failed = status.get("failed", 0)
    active = status.get("active", 0)

    # Timestamps
    start_time = parse_timestamp(status.get("startTime"))
    completion_time = parse_timestamp(status.get("completionTime"))

    # Calculate age
    creation_timestamp = parse_timestamp(metadata.get("creationTimestamp"))
    age_seconds = None
    if creation_timestamp:
        age_seconds = (datetime.now(timezone.utc) - creation_timestamp).total_seconds()

    # Determine status
    job_status = "Unknown"
    has_issue = False
    issue_details = []

    if succeeded > 0:
        job_status = "Completed"
    elif failed > 0:
        job_status = "Failed"
        has_issue = True
        issue_details.append(f"Failed {failed} times")
    elif active > 0:
        job_status = "Running"
        # Check if job is running too long (>24 hours)
        if start_time:
            running_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()
            if running_seconds > 86400:  # 24 hours
                has_issue = True
                issue_details.append(
                    f"Running for {running_seconds/3600:.1f} hours"
                )
    else:
        job_status = "Pending"
        # Pending for too long is suspicious (>1 hour)
        if age_seconds and age_seconds > 3600:
            has_issue = True
            issue_details.append(f"Pending for {age_seconds/60:.0f} minutes")

    # Check for TTL configuration
    ttl_seconds = spec.get("ttlSecondsAfterFinished")
    if ttl_seconds is None and job_status == "Completed":
        issue_details.append("No TTL cleanup configured")

    return {
        "name": name,
        "namespace": namespace,
        "status": job_status,
        "succeeded": succeeded,
        "failed": failed,
        "active": active,
        "age_seconds": age_seconds,
        "has_issue": has_issue,
        "issues": issue_details,
        "ttl_configured": ttl_seconds is not None,
        "start_time": start_time.isoformat() if start_time else None,
        "completion_time": completion_time.isoformat() if completion_time else None,
    }


def analyze_cronjob(cronjob: dict) -> dict:
    """Analyze a single cronjob for issues."""
    metadata = cronjob.get("metadata", {})
    status = cronjob.get("status", {})
    spec = cronjob.get("spec", {})

    name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    # CronJob status
    last_schedule = parse_timestamp(status.get("lastScheduleTime"))
    last_successful = parse_timestamp(status.get("lastSuccessfulTime"))
    active_jobs = status.get("active", [])

    # Check if suspended
    suspended = spec.get("suspend", False)
    schedule = spec.get("schedule", "unknown")

    # Determine status
    has_issue = False
    issue_details = []

    if suspended:
        issue_details.append("CronJob is suspended")
        has_issue = True

    # Check if last schedule was recent
    if last_schedule:
        time_since_schedule = (
            datetime.now(timezone.utc) - last_schedule
        ).total_seconds()
        # If not scheduled in last 25 hours (accounting for daily jobs), might be an issue
        if time_since_schedule > 90000 and not suspended:  # 25 hours
            issue_details.append(
                f"Not scheduled for {time_since_schedule/3600:.1f} hours"
            )
            has_issue = True

    # Check if last successful is much older than last schedule
    if last_schedule and last_successful:
        schedule_vs_success = (last_schedule - last_successful).total_seconds()
        if schedule_vs_success > 3600:  # Last few runs failed
            issue_details.append("Recent runs failing")
            has_issue = True
    elif last_schedule and not last_successful:
        issue_details.append("No successful runs recorded")
        has_issue = True

    # Too many active jobs might indicate stuck jobs
    if len(active_jobs) > 3:
        issue_details.append(f"{len(active_jobs)} jobs running concurrently")
        has_issue = True

    return {
        "name": name,
        "namespace": namespace,
        "schedule": schedule,
        "suspended": suspended,
        "active_jobs": len(active_jobs),
        "last_schedule": last_schedule.isoformat() if last_schedule else None,
        "last_successful": last_successful.isoformat() if last_successful else None,
        "has_issue": has_issue,
        "issues": issue_details,
    }


def format_age(seconds: float | None) -> str:
    """Format age in seconds to human-readable string."""
    if seconds is None:
        return "N/A"

    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds/60)}m"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}h"
    else:
        return f"{seconds/86400:.1f}d"


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor Kubernetes Job and CronJob health"
    )
    parser.add_argument(
        "-n",
        "--namespace",
        help="Namespace to check (default: all namespaces)",
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-w",
        "--warn-only",
        action="store_true",
        help="Only show jobs and cronjobs with issues",
    )
    parser.add_argument(
        "--skip-jobs",
        action="store_true",
        help="Skip job analysis, only check cronjobs",
    )
    parser.add_argument(
        "--skip-cronjobs",
        action="store_true",
        help="Skip cronjob analysis, only check jobs",
    )
    opts = parser.parse_args(args)

    # Check for kubectl
    if not context.check_tool("kubectl"):
        output.error("kubectl not found in PATH")
        return 2

    # Collect data
    jobs_data = []
    cronjobs_data = []

    if not opts.skip_jobs:
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
            jobs = json.loads(result.stdout).get("items", [])
            jobs_data = [analyze_job(job) for job in jobs]
        except Exception as e:
            output.error(f"Failed to get jobs: {e}")
            return 2

    if not opts.skip_cronjobs:
        cmd = ["kubectl", "get", "cronjobs", "-o", "json"]
        if opts.namespace:
            cmd.extend(["-n", opts.namespace])
        else:
            cmd.append("--all-namespaces")

        try:
            result = context.run(cmd)
            if result.returncode != 0:
                output.error(f"kubectl failed: {result.stderr}")
                return 2
            cronjobs = json.loads(result.stdout).get("items", [])
            cronjobs_data = [analyze_cronjob(cj) for cj in cronjobs]
        except Exception as e:
            output.error(f"Failed to get cronjobs: {e}")
            return 2

    # Filter if warn-only
    if opts.warn_only:
        jobs_data = [j for j in jobs_data if j["has_issue"]]
        cronjobs_data = [cj for cj in cronjobs_data if cj["has_issue"]]

    # Calculate summary
    jobs_with_issues = sum(1 for j in jobs_data if j["has_issue"])
    cronjobs_with_issues = sum(1 for cj in cronjobs_data if cj["has_issue"])

    # Output results
    if opts.format == "json":
        output_data = {
            "jobs": jobs_data,
            "cronjobs": cronjobs_data,
            "summary": {
                "total_jobs": len(jobs_data),
                "jobs_with_issues": jobs_with_issues,
                "total_cronjobs": len(cronjobs_data),
                "cronjobs_with_issues": cronjobs_with_issues,
            },
        }
        print(json.dumps(output_data, indent=2))

    elif opts.format == "table":
        # Jobs table
        if jobs_data:
            print("=== Jobs ===")
            print(
                f"{'Namespace':<20} {'Name':<30} {'Status':<12} {'Age':<8} {'S/F/A':<10} {'Issues'}"
            )
            print("-" * 120)

            for job in jobs_data:
                age_str = format_age(job["age_seconds"])
                sfa = f"{job['succeeded']}/{job['failed']}/{job['active']}"
                issues_str = ", ".join(job["issues"]) if job["issues"] else "-"

                print(
                    f"{job['namespace']:<20} {job['name']:<30} {job['status']:<12} "
                    f"{age_str:<8} {sfa:<10} {issues_str}"
                )
            print()

        # CronJobs table
        if cronjobs_data:
            print("=== CronJobs ===")
            print(
                f"{'Namespace':<20} {'Name':<30} {'Schedule':<15} {'Active':<8} {'Issues'}"
            )
            print("-" * 110)

            for cj in cronjobs_data:
                schedule = (
                    cj["schedule"][:14]
                    if len(cj["schedule"]) > 14
                    else cj["schedule"]
                )
                issues_str = ", ".join(cj["issues"]) if cj["issues"] else "-"

                print(
                    f"{cj['namespace']:<20} {cj['name']:<30} {schedule:<15} "
                    f"{cj['active_jobs']:<8} {issues_str}"
                )
            print()

    else:  # plain format
        # Jobs
        if jobs_data:
            print("=== Jobs ===")
            for job in jobs_data:
                status_marker = "[!]" if job["has_issue"] else "[+]"
                age_str = format_age(job["age_seconds"])

                print(f"{status_marker} {job['namespace']}/{job['name']}")
                print(f"  Status: {job['status']} | Age: {age_str}")
                print(
                    f"  Succeeded: {job['succeeded']} | Failed: {job['failed']} | Active: {job['active']}"
                )

                if job["issues"]:
                    print(f"  Issues: {', '.join(job['issues'])}")
                print()

        # CronJobs
        if cronjobs_data:
            print("=== CronJobs ===")
            for cj in cronjobs_data:
                status_marker = "[!]" if cj["has_issue"] else "[+]"

                print(f"{status_marker} {cj['namespace']}/{cj['name']}")
                print(f"  Schedule: {cj['schedule']} | Suspended: {cj['suspended']}")
                print(f"  Active Jobs: {cj['active_jobs']}")

                if cj["last_schedule"]:
                    print(f"  Last Schedule: {cj['last_schedule']}")
                if cj["last_successful"]:
                    print(f"  Last Success: {cj['last_successful']}")

                if cj["issues"]:
                    print(f"  Issues: {', '.join(cj['issues'])}")
                print()

    output.set_summary(
        f"jobs={len(jobs_data)}, jobs_with_issues={jobs_with_issues}, "
        f"cronjobs={len(cronjobs_data)}, cronjobs_with_issues={cronjobs_with_issues}"
    )

    # Determine exit code
    has_issues = jobs_with_issues > 0 or cronjobs_with_issues > 0
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
