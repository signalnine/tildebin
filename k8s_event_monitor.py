#!/usr/bin/env python3
"""
Monitor Kubernetes events to track cluster issues and anomalies.

This script aggregates and displays Kubernetes events from the cluster,
helping administrators identify issues before they impact workloads.
Useful for monitoring large-scale baremetal Kubernetes deployments.

Exit codes:
    0 - No critical events found
    1 - Warning or error events detected
    2 - Usage error or kubectl not available
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta


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


def get_events(namespace=None, minutes=None):
    """Get events in JSON format."""
    args = ['get', 'events', '-o', 'json']
    if namespace:
        args.extend(['-n', namespace])
    else:
        args.append('--all-namespaces')

    output = run_kubectl(args)
    events_data = json.loads(output)

    # Filter by time if specified
    if minutes and minutes > 0:
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        filtered_events = []
        for event in events_data.get('items', []):
            event_time_str = event['firstTimestamp']
            event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
            if event_time > cutoff:
                filtered_events.append(event)
        events_data['items'] = filtered_events

    return events_data


def categorize_events(events_data):
    """Categorize events by type and reason."""
    categories = defaultdict(list)
    warnings = []
    errors = []

    for event in events_data.get('items', []):
        event_type = event.get('type', 'Normal')
        reason = event.get('reason', 'Unknown')
        namespace = event['metadata'].get('namespace', 'default')
        involved_object = event['involvedObject']
        object_name = involved_object.get('name', 'unknown')
        object_kind = involved_object.get('kind', 'Unknown')
        message = event.get('message', '')
        count = event.get('count', 1)
        last_timestamp = event.get('lastTimestamp', '')

        event_info = {
            'namespace': namespace,
            'type': event_type,
            'reason': reason,
            'object': f"{object_kind}/{object_name}",
            'message': message,
            'count': count,
            'last_timestamp': last_timestamp
        }

        categories[f"{event_type}:{reason}"].append(event_info)

        # Track warnings and errors
        if event_type == 'Warning':
            warnings.append(event_info)
        elif event_type == 'Error':
            errors.append(event_info)

    return categories, warnings, errors


def print_results(categories, warnings, errors, output_format, warn_only):
    """Print event analysis results."""
    if output_format == 'json':
        output = {
            'errors': errors,
            'warnings': warnings,
            'summary': {
                'error_count': len(errors),
                'warning_count': len(warnings),
                'total_categories': len(categories)
            }
        }
        print(json.dumps(output, indent=2))
    else:  # plain format
        if warnings or errors:
            if errors:
                print("=== ERRORS ===\n")
                for error in errors:
                    print(f"[{error['namespace']}] {error['reason']} - {error['object']}")
                    print(f"  Message: {error['message']}")
                    if error['count'] > 1:
                        print(f"  Count: {error['count']}")
                    print(f"  Last: {error['last_timestamp']}")
                    print()

            if warnings:
                print("=== WARNINGS ===\n")
                for warning in warnings:
                    print(f"[{warning['namespace']}] {warning['reason']} - {warning['object']}")
                    print(f"  Message: {warning['message']}")
                    if warning['count'] > 1:
                        print(f"  Count: {warning['count']}")
                    print(f"  Last: {warning['last_timestamp']}")
                    print()
        elif not warn_only:
            print("No events found")

        # Print summary
        print(f"Summary: {len(errors)} errors, {len(warnings)} warnings, {len(categories)} event types")

    return len(errors) > 0 or len(warnings) > 0


def print_categories(categories):
    """Print categorized event summary."""
    print("\n=== Event Categories ===\n")
    for category, events in sorted(categories.items()):
        event_type, reason = category.split(':')
        print(f"{event_type} - {reason}: {len(events)} events")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Kubernetes events to track cluster issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Show all events across all namespaces
  %(prog)s -n production            # Show events in production namespace only
  %(prog)s --minutes 30             # Show events from last 30 minutes
  %(prog)s --warn-only              # Show only warnings and errors
  %(prog)s --format json            # JSON output
  %(prog)s -w -f json --minutes 60  # Recent errors/warnings in JSON

Exit codes:
  0 - No critical events
  1 - Warning or error events found
  2 - Usage error or kubectl unavailable
        """
    )

    parser.add_argument(
        '--namespace', '-n',
        help='Namespace to monitor (default: all namespaces)'
    )

    parser.add_argument(
        '--minutes', '-m',
        type=int,
        help='Show events from last N minutes (default: all)'
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
        help='Only show warnings and errors'
    )

    parser.add_argument(
        '--categories', '-c',
        action='store_true',
        help='Show event category summary'
    )

    args = parser.parse_args()

    # Get events
    events_data = get_events(args.namespace, args.minutes)

    # Categorize events
    categories, warnings, errors = categorize_events(events_data)

    # Print results
    has_issues = print_results(categories, warnings, errors, args.format, args.warn_only)

    # Show categories if requested
    if args.categories and args.format == 'plain':
        print_categories(categories)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
