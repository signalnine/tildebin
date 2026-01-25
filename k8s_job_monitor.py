#!/usr/bin/env python3
"""
Monitor Kubernetes Jobs and CronJobs status and health.

This script provides visibility into Job and CronJob health, including:
- Job completion status (succeeded, failed, active)
- Job duration and timing
- CronJob schedule and last run status
- Failed job detection with reason analysis
- Stuck or long-running job detection

Useful for monitoring batch workloads in large-scale Kubernetes deployments.

Exit codes:
    0 - All jobs healthy (no failed jobs, no stuck jobs)
    1 - One or more jobs failed or stuck
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone


def run_kubectl(args):
    """Run kubectl command and return output."""
    try:
        result = subprocess.run(
            ['kubectl'] + args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_jobs(namespace=None):
    """Get all jobs in JSON format."""
    args = ['get', 'jobs', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_cronjobs(namespace=None):
    """Get all cronjobs in JSON format."""
    args = ['get', 'cronjobs', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def parse_duration(start_time, completion_time=None):
    """Calculate duration between two timestamps."""
    if not start_time:
        return None

    try:
        start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        if completion_time:
            end = datetime.fromisoformat(completion_time.replace('Z', '+00:00'))
        else:
            end = datetime.now(timezone.utc)

        duration = end - start
        return duration.total_seconds()
    except (ValueError, TypeError):
        return None


def format_duration(seconds):
    """Format duration in human-readable format."""
    if seconds is None:
        return "unknown"

    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{minutes}m{secs}s"
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h{minutes}m"


def check_job_status(job, max_duration_hours=24):
    """Check job status and return health info."""
    status = job.get('status', {})
    spec = job.get('spec', {})
    metadata = job.get('metadata', {})

    succeeded = status.get('succeeded', 0)
    failed = status.get('failed', 0)
    active = status.get('active', 0)

    start_time = status.get('startTime')
    completion_time = status.get('completionTime')

    completions = spec.get('completions', 1)
    parallelism = spec.get('parallelism', 1)
    backoff_limit = spec.get('backoffLimit', 6)

    issues = []
    is_healthy = True

    # Check if job has failed
    conditions = status.get('conditions', [])
    for condition in conditions:
        if condition.get('type') == 'Failed' and condition.get('status') == 'True':
            reason = condition.get('reason', 'Unknown')
            message = condition.get('message', '')
            issues.append(f"Job failed: {reason} - {message}")
            is_healthy = False

    # Check if job is stuck (active for too long)
    if active > 0 and start_time:
        duration = parse_duration(start_time)
        if duration and duration > (max_duration_hours * 3600):
            issues.append(f"Job running for {format_duration(duration)} (exceeds {max_duration_hours}h threshold)")
            is_healthy = False

    # Check for excessive failures
    if failed > 0:
        if failed >= backoff_limit:
            issues.append(f"Job has {failed} failures (reached backoff limit of {backoff_limit})")
            is_healthy = False
        else:
            issues.append(f"Job has {failed} failure(s)")

    # Check completion status
    if completion_time:
        if succeeded < completions:
            issues.append(f"Job completed but only {succeeded}/{completions} succeeded")
            is_healthy = False
    elif active == 0 and succeeded == 0 and failed == 0:
        issues.append("Job has not started")

    duration = parse_duration(start_time, completion_time)

    return is_healthy, issues, {
        'succeeded': succeeded,
        'failed': failed,
        'active': active,
        'completions': completions,
        'parallelism': parallelism,
        'duration_seconds': duration,
        'start_time': start_time,
        'completion_time': completion_time
    }


def check_cronjob_status(cronjob):
    """Check cronjob status and return health info."""
    status = cronjob.get('status', {})
    spec = cronjob.get('spec', {})

    schedule = spec.get('schedule', '')
    suspend = spec.get('suspend', False)
    concurrency_policy = spec.get('concurrencyPolicy', 'Allow')

    last_schedule_time = status.get('lastScheduleTime')
    last_successful_time = status.get('lastSuccessfulTime')
    active = status.get('active', [])

    issues = []
    is_healthy = True

    # Check if suspended
    if suspend:
        issues.append("CronJob is suspended")
        # Suspended is not necessarily unhealthy, just informational

    # Check if never scheduled
    if not last_schedule_time:
        issues.append("CronJob has never been scheduled")

    # Check for stuck active jobs
    if len(active) > 1 and concurrency_policy == 'Forbid':
        issues.append(f"Multiple active jobs ({len(active)}) with Forbid concurrency policy")
        is_healthy = False

    # Check time since last successful run
    if last_successful_time:
        time_since_success = parse_duration(last_successful_time)
        # If more than 48 hours since last success, warn
        if time_since_success and time_since_success > (48 * 3600):
            issues.append(f"No successful run in {format_duration(time_since_success)}")
            is_healthy = False

    return is_healthy, issues, {
        'schedule': schedule,
        'suspend': suspend,
        'concurrency_policy': concurrency_policy,
        'last_schedule_time': last_schedule_time,
        'last_successful_time': last_successful_time,
        'active_jobs': len(active)
    }


def print_status(jobs, cronjobs, output_format, warn_only, failed_only, namespace_filter=None):
    """Print job and cronjob status."""
    has_issues = False

    if output_format == 'json':
        output = {'jobs': [], 'cronjobs': []}

        # Process jobs
        for job in jobs.get('items', []):
            name = job['metadata']['name']
            ns = job['metadata'].get('namespace', 'default')

            if namespace_filter and ns != namespace_filter:
                continue

            is_healthy, issues, info = check_job_status(job)

            job_info = {
                'namespace': ns,
                'name': name,
                'healthy': is_healthy,
                'succeeded': info['succeeded'],
                'failed': info['failed'],
                'active': info['active'],
                'completions': info['completions'],
                'duration': format_duration(info['duration_seconds']),
                'issues': issues
            }

            if failed_only and is_healthy:
                continue
            if warn_only and not issues:
                continue

            output['jobs'].append(job_info)
            if not is_healthy:
                has_issues = True

        # Process cronjobs
        for cj in cronjobs.get('items', []):
            name = cj['metadata']['name']
            ns = cj['metadata'].get('namespace', 'default')

            if namespace_filter and ns != namespace_filter:
                continue

            is_healthy, issues, info = check_cronjob_status(cj)

            cj_info = {
                'namespace': ns,
                'name': name,
                'healthy': is_healthy,
                'schedule': info['schedule'],
                'suspended': info['suspend'],
                'active_jobs': info['active_jobs'],
                'last_schedule': info['last_schedule_time'],
                'last_success': info['last_successful_time'],
                'issues': issues
            }

            if failed_only and is_healthy:
                continue
            if warn_only and not issues:
                continue

            output['cronjobs'].append(cj_info)
            if not is_healthy:
                has_issues = True

        print(json.dumps(output, indent=2))

    else:  # plain format
        healthy_jobs = 0
        unhealthy_jobs = 0
        healthy_cronjobs = 0
        unhealthy_cronjobs = 0

        # Process jobs
        print("=== Jobs ===")
        job_items = jobs.get('items', [])
        if not job_items:
            print("No jobs found.")
        else:
            for job in job_items:
                name = job['metadata']['name']
                ns = job['metadata'].get('namespace', 'default')

                if namespace_filter and ns != namespace_filter:
                    continue

                is_healthy, issues, info = check_job_status(job)

                if is_healthy:
                    healthy_jobs += 1
                else:
                    unhealthy_jobs += 1
                    has_issues = True

                if failed_only and is_healthy:
                    continue
                if warn_only and not issues:
                    continue

                status_marker = "+" if is_healthy else "!"
                duration_str = format_duration(info['duration_seconds'])

                print(f"[{status_marker}] {ns}/{name}")
                print(f"    Status: {info['succeeded']}/{info['completions']} succeeded, "
                      f"{info['failed']} failed, {info['active']} active")
                print(f"    Duration: {duration_str}")

                if issues:
                    for issue in issues:
                        print(f"    WARNING: {issue}")

        print()

        # Process cronjobs
        print("=== CronJobs ===")
        cj_items = cronjobs.get('items', [])
        if not cj_items:
            print("No cronjobs found.")
        else:
            for cj in cj_items:
                name = cj['metadata']['name']
                ns = cj['metadata'].get('namespace', 'default')

                if namespace_filter and ns != namespace_filter:
                    continue

                is_healthy, issues, info = check_cronjob_status(cj)

                if is_healthy:
                    healthy_cronjobs += 1
                else:
                    unhealthy_cronjobs += 1
                    has_issues = True

                if failed_only and is_healthy:
                    continue
                if warn_only and not issues:
                    continue

                status_marker = "+" if is_healthy else "!"
                suspend_marker = " (SUSPENDED)" if info['suspend'] else ""

                print(f"[{status_marker}] {ns}/{name}{suspend_marker}")
                print(f"    Schedule: {info['schedule']}")
                print(f"    Active jobs: {info['active_jobs']}")
                if info['last_schedule_time']:
                    print(f"    Last scheduled: {info['last_schedule_time']}")
                if info['last_successful_time']:
                    print(f"    Last success: {info['last_successful_time']}")

                if issues:
                    for issue in issues:
                        print(f"    WARNING: {issue}")

        print()

        # Print summary
        total_jobs = healthy_jobs + unhealthy_jobs
        total_cronjobs = healthy_cronjobs + unhealthy_cronjobs
        print(f"Summary: {healthy_jobs}/{total_jobs} jobs healthy, "
              f"{healthy_cronjobs}/{total_cronjobs} cronjobs healthy")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes Jobs and CronJobs status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all jobs and cronjobs
  %(prog)s -n production            # Check only in production namespace
  %(prog)s --warn-only              # Show only jobs with issues
  %(prog)s --failed-only            # Show only failed jobs
  %(prog)s --format json            # JSON output
  %(prog)s --max-duration 12        # Flag jobs running > 12 hours

Exit codes:
  0 - All jobs healthy
  1 - One or more jobs failed or stuck
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to check (default: all namespaces)'
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
        help='Only show jobs with issues'
    )

    parser.add_argument(
        '--failed-only',
        action='store_true',
        help='Only show failed jobs'
    )

    parser.add_argument(
        '--max-duration',
        type=int,
        default=24,
        help='Maximum job duration in hours before flagging as stuck (default: 24)'
    )

    args = parser.parse_args()

    # Get jobs and cronjobs
    jobs = get_jobs(args.namespace)
    cronjobs = get_cronjobs(args.namespace)

    # Print status
    has_issues = print_status(
        jobs, cronjobs,
        args.format, args.warn_only, args.failed_only,
        args.namespace
    )

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
