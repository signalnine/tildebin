#!/usr/bin/env python3
"""
Detect Horizontal Pod Autoscaler (HPA) thrashing in Kubernetes clusters.

HPA thrashing occurs when autoscalers rapidly scale up and down, causing:
- Application instability and connection drops
- Wasted resources from constant pod churn
- Increased scheduling pressure on the cluster
- Poor user experience from capacity fluctuations

This script analyzes HPA scaling events to identify:
- Rapid scale-up/scale-down cycles (thrashing)
- HPAs stuck at min or max replicas
- HPAs with metrics unavailable
- Scaling frequency anomalies

Exit codes:
    0 - No thrashing detected, all HPAs healthy
    1 - Thrashing or issues detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
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


def get_hpas(namespace=None):
    """Get all HPAs in JSON format."""
    args = ['get', 'hpa', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    return json.loads(output)


def get_events(namespace=None, field_selector=None):
    """Get Kubernetes events in JSON format."""
    args = ['get', 'events', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    if field_selector:
        args.extend(['--field-selector', field_selector])

    output = run_kubectl(args)
    return json.loads(output)


def parse_event_time(event):
    """Parse event timestamp, handling various formats."""
    # Try lastTimestamp first (older format)
    timestamp = event.get('lastTimestamp')
    if not timestamp:
        # Try eventTime (newer format)
        timestamp = event.get('eventTime')
    if not timestamp:
        # Fall back to firstTimestamp
        timestamp = event.get('firstTimestamp')
    if not timestamp:
        return None

    # Handle microseconds by truncating to 6 digits
    if '.' in timestamp:
        base, frac = timestamp.rsplit('.', 1)
        # Remove timezone suffix from fraction
        if 'Z' in frac:
            frac = frac.replace('Z', '')
            frac = frac[:6]  # Truncate to 6 digits
            timestamp = f"{base}.{frac}Z"
        elif '+' in frac:
            frac_part, tz = frac.split('+', 1)
            frac_part = frac_part[:6]
            timestamp = f"{base}.{frac_part}+{tz}"

    try:
        # Try ISO format with Z suffix
        if timestamp.endswith('Z'):
            return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def analyze_hpa_events(events, hpa_name, namespace):
    """Analyze scaling events for a specific HPA."""
    scaling_events = []

    for event in events.get('items', []):
        involved = event.get('involvedObject', {})
        if involved.get('kind') != 'HorizontalPodAutoscaler':
            continue
        if involved.get('name') != hpa_name:
            continue
        if event.get('metadata', {}).get('namespace') != namespace:
            continue

        reason = event.get('reason', '')
        message = event.get('message', '')
        event_time = parse_event_time(event)
        count = event.get('count', 1)

        if reason in ('SuccessfulRescale', 'ScaledUpReplicas', 'ScaledDownReplicas'):
            scaling_events.append({
                'time': event_time,
                'reason': reason,
                'message': message,
                'count': count
            })

    return scaling_events


def detect_thrashing(scaling_events, window_minutes=30, threshold=4):
    """
    Detect thrashing based on scaling event frequency.

    Thrashing is defined as multiple scale-up/scale-down cycles
    within a short time window.
    """
    if not scaling_events:
        return False, 0, []

    # Sort events by time
    sorted_events = sorted(
        [e for e in scaling_events if e['time'] is not None],
        key=lambda x: x['time']
    )

    if not sorted_events:
        return False, 0, []

    # Count events in the window
    now = datetime.now(timezone.utc)
    recent_events = []

    for event in sorted_events:
        age_minutes = (now - event['time']).total_seconds() / 60
        if age_minutes <= window_minutes:
            recent_events.append(event)

    event_count = sum(e.get('count', 1) for e in recent_events)
    is_thrashing = event_count >= threshold

    return is_thrashing, event_count, recent_events


def check_hpa_status(hpa):
    """Check HPA status and return health info."""
    metadata = hpa.get('metadata', {})
    spec = hpa.get('spec', {})
    status = hpa.get('status', {})

    name = metadata.get('name', 'unknown')
    namespace = metadata.get('namespace', 'default')

    min_replicas = spec.get('minReplicas', 1)
    max_replicas = spec.get('maxReplicas', 1)
    current_replicas = status.get('currentReplicas', 0)
    desired_replicas = status.get('desiredReplicas', 0)

    issues = []

    # Check if stuck at min
    if current_replicas == min_replicas and desired_replicas == min_replicas:
        # Not necessarily an issue, but worth noting
        pass

    # Check if stuck at max (potential capacity issue)
    if current_replicas == max_replicas and desired_replicas >= max_replicas:
        issues.append({
            'type': 'at_max',
            'message': f'HPA at maximum replicas ({max_replicas}), may need capacity increase'
        })

    # Check conditions
    conditions = status.get('conditions', [])
    for condition in conditions:
        cond_type = condition.get('type', '')
        cond_status = condition.get('status', 'Unknown')
        reason = condition.get('reason', '')
        message = condition.get('message', '')

        if cond_type == 'ScalingActive' and cond_status != 'True':
            issues.append({
                'type': 'scaling_inactive',
                'message': f'Scaling not active: {reason} - {message}'
            })

        if cond_type == 'AbleToScale' and cond_status != 'True':
            issues.append({
                'type': 'unable_to_scale',
                'message': f'Unable to scale: {reason} - {message}'
            })

    # Check current metrics
    current_metrics = status.get('currentMetrics', [])
    if not current_metrics:
        issues.append({
            'type': 'no_metrics',
            'message': 'No current metrics available'
        })

    return {
        'name': name,
        'namespace': namespace,
        'min_replicas': min_replicas,
        'max_replicas': max_replicas,
        'current_replicas': current_replicas,
        'desired_replicas': desired_replicas,
        'issues': issues
    }


def analyze_hpas(hpas, events, window_minutes, threshold):
    """Analyze all HPAs for thrashing and issues."""
    results = []

    for hpa in hpas.get('items', []):
        hpa_status = check_hpa_status(hpa)

        # Get scaling events for this HPA
        scaling_events = analyze_hpa_events(
            events,
            hpa_status['name'],
            hpa_status['namespace']
        )

        # Detect thrashing
        is_thrashing, event_count, recent_events = detect_thrashing(
            scaling_events, window_minutes, threshold
        )

        if is_thrashing:
            hpa_status['issues'].append({
                'type': 'thrashing',
                'message': f'Thrashing detected: {event_count} scaling events in {window_minutes} minutes'
            })

        hpa_status['scaling_events_count'] = event_count
        hpa_status['is_thrashing'] = is_thrashing
        hpa_status['recent_scaling_events'] = [
            {
                'time': e['time'].isoformat() if e['time'] else None,
                'reason': e['reason'],
                'message': e['message']
            }
            for e in recent_events
        ]

        results.append(hpa_status)

    return results


def print_results(results, output_format, warn_only, verbose):
    """Print analysis results."""
    has_issues = False

    # Filter results if warn_only
    if warn_only:
        results = [r for r in results if r['issues'] or r['is_thrashing']]

    if output_format == 'json':
        print(json.dumps(results, indent=2, default=str))
        for r in results:
            if r['issues'] or r['is_thrashing']:
                has_issues = True
    else:
        # Plain format
        thrashing_count = 0
        issue_count = 0

        for r in results:
            name = r['name']
            namespace = r['namespace']
            is_thrashing = r['is_thrashing']
            issues = r['issues']

            if is_thrashing:
                thrashing_count += 1
                has_issues = True
            if issues:
                issue_count += 1
                has_issues = True

            # Determine status marker
            if is_thrashing:
                marker = "!!"
            elif issues:
                marker = "!"
            else:
                marker = "ok"

            print(f"[{marker}] {namespace}/{name}")
            print(f"    Replicas: {r['current_replicas']}/{r['desired_replicas']} "
                  f"(min: {r['min_replicas']}, max: {r['max_replicas']})")
            print(f"    Scaling events (recent): {r['scaling_events_count']}")

            if is_thrashing:
                print(f"    THRASHING DETECTED")

            for issue in issues:
                print(f"    WARNING: {issue['message']}")

            if verbose and r['recent_scaling_events']:
                print("    Recent scaling events:")
                for event in r['recent_scaling_events'][:5]:
                    time_str = event['time'][:19] if event['time'] else 'unknown'
                    print(f"      - [{time_str}] {event['reason']}: {event['message'][:60]}")

            print()

        # Summary
        total = len(results) if not warn_only else thrashing_count + issue_count
        print(f"Summary: {len(results)} HPAs analyzed")
        if thrashing_count > 0:
            print(f"  Thrashing: {thrashing_count} HPAs")
        if issue_count > 0:
            print(f"  With issues: {issue_count} HPAs")
        if thrashing_count == 0 and issue_count == 0:
            print("  All HPAs healthy")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Detect HPA thrashing in Kubernetes clusters',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check all HPAs in all namespaces
  %(prog)s -n production            # Check HPAs in production namespace
  %(prog)s --warn-only              # Show only HPAs with issues
  %(prog)s --format json            # JSON output
  %(prog)s --window 60 --threshold 6  # Custom detection parameters
  %(prog)s -v                       # Verbose output with event details

Exit codes:
  0 - No thrashing or issues detected
  1 - Thrashing or issues found
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
        help='Only show HPAs with thrashing or issues'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed scaling event information'
    )

    parser.add_argument(
        '--window',
        type=int,
        default=30,
        help='Time window in minutes to analyze for thrashing (default: 30)'
    )

    parser.add_argument(
        '--threshold',
        type=int,
        default=4,
        help='Number of scaling events in window to consider thrashing (default: 4)'
    )

    args = parser.parse_args()

    # Validate parameters
    if args.window < 1:
        print("Error: --window must be at least 1 minute", file=sys.stderr)
        sys.exit(2)

    if args.threshold < 2:
        print("Error: --threshold must be at least 2", file=sys.stderr)
        sys.exit(2)

    # Get HPAs
    hpas = get_hpas(args.namespace)

    if not hpas.get('items'):
        if args.format == 'json':
            print(json.dumps([]))
        else:
            print("No HPAs found")
        sys.exit(0)

    # Get events
    events = get_events(args.namespace)

    # Analyze HPAs
    results = analyze_hpas(hpas, events, args.window, args.threshold)

    # Print results
    has_issues = print_results(results, args.format, args.warn_only, args.verbose)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
