#!/usr/bin/env python3
"""
Monitor kernel log message rates to detect anomalies.

This script analyzes the rate of kernel messages (via dmesg) to detect unusual
spikes that may indicate hardware problems, driver issues, or system instability.
In large-scale baremetal environments, a sudden increase in kernel message rate
often precedes hardware failures or system issues.

Features:
- Calculates messages per minute from kernel ring buffer
- Detects rate anomalies using configurable thresholds
- Categorizes message severity (emerg, alert, crit, err, warn, notice, info, debug)
- Tracks rate trends over time windows
- Identifies burst patterns (many messages in short period)

Exit codes:
    0 - Normal message rate, no anomalies detected
    1 - Elevated message rate or anomalies detected
    2 - Usage error or dmesg not available
"""

import argparse
import sys
import subprocess
import re
import json
from collections import defaultdict
from datetime import datetime, timedelta


# Kernel log priority levels (matching syslog)
PRIORITY_LEVELS = {
    'emerg': 0,
    'alert': 1,
    'crit': 2,
    'err': 3,
    'warn': 4,
    'notice': 5,
    'info': 6,
    'debug': 7,
}

# Default thresholds (messages per minute)
DEFAULT_WARN_RATE = 50   # Warning if > 50 msgs/min
DEFAULT_CRIT_RATE = 200  # Critical if > 200 msgs/min
DEFAULT_BURST_THRESHOLD = 20  # Burst if > 20 msgs in 5 seconds


def run_dmesg():
    """Execute dmesg command with timestamps and return output"""
    # Try with --time-format=iso first (newer dmesg)
    try:
        result = subprocess.run(
            ['dmesg', '--time-format=iso'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout, 'iso'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback to -T for human-readable timestamps
    try:
        result = subprocess.run(
            ['dmesg', '-T'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout, 'human'
    except FileNotFoundError:
        print("Error: 'dmesg' command not found", file=sys.stderr)
        print("Install with: sudo apt-get install util-linux", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print("Error: dmesg command timed out", file=sys.stderr)
        sys.exit(1)

    # Last resort: basic dmesg without timestamps
    try:
        result = subprocess.run(
            ['dmesg'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout, 'none'
    except Exception as e:
        print(f"Error running dmesg: {e}", file=sys.stderr)
        sys.exit(1)


def parse_iso_timestamp(ts_str):
    """Parse ISO format timestamp from dmesg"""
    # Format: 2024-01-15T10:30:45,123456+00:00
    try:
        # Remove microseconds and timezone for simpler parsing
        ts_clean = re.sub(r',\d+[+-]\d{2}:\d{2}$', '', ts_str)
        return datetime.fromisoformat(ts_clean)
    except (ValueError, AttributeError):
        return None


def parse_human_timestamp(ts_str):
    """Parse human-readable timestamp from dmesg -T"""
    # Format: [Mon Jan 15 10:30:45 2024]
    try:
        ts_clean = ts_str.strip('[]')
        return datetime.strptime(ts_clean, '%a %b %d %H:%M:%S %Y')
    except (ValueError, AttributeError):
        return None


def parse_dmesg_line(line, time_format):
    """Parse a single dmesg line and extract timestamp and message"""
    if not line.strip():
        return None, None, None

    timestamp = None
    priority = 'info'  # Default priority

    if time_format == 'iso':
        # ISO format: 2024-01-15T10:30:45,123456+00:00 kernel: message
        match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^]]*)\s+(.*)$', line)
        if match:
            timestamp = parse_iso_timestamp(match.group(1))
            message = match.group(2)
        else:
            message = line
    elif time_format == 'human':
        # Human format: [Mon Jan 15 10:30:45 2024] message
        match = re.match(r'^\[([^\]]+)\]\s+(.*)$', line)
        if match:
            timestamp = parse_human_timestamp(match.group(1))
            message = match.group(2)
        else:
            message = line
    else:
        # No timestamp format
        message = line

    # Try to extract priority from message (e.g., "<3>message" or "kern.err: message")
    priority_match = re.match(r'^<(\d)>\s*(.*)$', message)
    if priority_match:
        prio_num = int(priority_match.group(1))
        for name, num in PRIORITY_LEVELS.items():
            if num == prio_num:
                priority = name
                break
        message = priority_match.group(2)

    return timestamp, priority, message


def analyze_message_rates(output, time_format, window_minutes=5):
    """Analyze message rates from dmesg output"""
    messages = []
    priority_counts = defaultdict(int)

    for line in output.split('\n'):
        timestamp, priority, message = parse_dmesg_line(line, time_format)
        if message:
            messages.append({
                'timestamp': timestamp,
                'priority': priority,
                'message': message,
            })
            priority_counts[priority] += 1

    if not messages:
        return {
            'total_messages': 0,
            'messages_per_minute': 0,
            'recent_rate': 0,
            'priority_breakdown': {},
            'time_window_minutes': 0,
            'bursts': [],
            'has_timestamps': False,
            'high_priority_count': 0,
        }

    # Check if we have timestamps
    timestamps = [m['timestamp'] for m in messages if m['timestamp']]
    has_timestamps = len(timestamps) > 0

    if has_timestamps and len(timestamps) >= 2:
        # Calculate time window from actual timestamps
        min_time = min(timestamps)
        max_time = max(timestamps)
        time_span = (max_time - min_time).total_seconds()
        time_window_minutes = max(time_span / 60.0, 0.1)  # At least 0.1 min

        # Calculate messages per minute
        messages_per_minute = len(messages) / time_window_minutes if time_window_minutes > 0 else 0

        # Detect bursts (many messages in short time)
        bursts = detect_bursts(messages, timestamps)

        # Calculate rate for recent window
        recent_cutoff = max_time - timedelta(minutes=window_minutes)
        recent_messages = [m for m in messages if m['timestamp'] and m['timestamp'] >= recent_cutoff]
        recent_rate = len(recent_messages) / window_minutes if recent_messages else 0
    else:
        # No usable timestamps - estimate based on buffer size
        time_window_minutes = None
        messages_per_minute = None
        bursts = []
        recent_rate = None

    return {
        'total_messages': len(messages),
        'messages_per_minute': messages_per_minute,
        'recent_rate': recent_rate,
        'priority_breakdown': dict(priority_counts),
        'time_window_minutes': time_window_minutes,
        'bursts': bursts,
        'has_timestamps': has_timestamps,
        'high_priority_count': sum(
            priority_counts.get(p, 0)
            for p in ['emerg', 'alert', 'crit', 'err']
        ),
    }


def detect_bursts(messages, timestamps, burst_window_secs=5, burst_threshold=20):
    """Detect message bursts (many messages in short time window)"""
    if len(timestamps) < burst_threshold:
        return []

    bursts = []
    sorted_timestamps = sorted(timestamps)

    i = 0
    while i < len(sorted_timestamps):
        window_end = sorted_timestamps[i] + timedelta(seconds=burst_window_secs)
        count = 0
        j = i

        while j < len(sorted_timestamps) and sorted_timestamps[j] <= window_end:
            count += 1
            j += 1

        if count >= burst_threshold:
            bursts.append({
                'start': sorted_timestamps[i].isoformat() if sorted_timestamps[i] else None,
                'count': count,
                'duration_secs': burst_window_secs,
            })
            i = j  # Skip past this burst
        else:
            i += 1

    return bursts


def evaluate_health(stats, warn_rate, crit_rate, burst_threshold):
    """Evaluate system health based on message rates"""
    issues = []
    status = 'OK'

    if stats['messages_per_minute'] is not None:
        rate = stats['messages_per_minute']
        if rate >= crit_rate:
            issues.append({
                'severity': 'CRITICAL',
                'message': f"Very high message rate: {rate:.1f} msgs/min (threshold: {crit_rate})",
            })
            status = 'CRITICAL'
        elif rate >= warn_rate:
            issues.append({
                'severity': 'WARNING',
                'message': f"Elevated message rate: {rate:.1f} msgs/min (threshold: {warn_rate})",
            })
            if status != 'CRITICAL':
                status = 'WARNING'

    # Check for bursts
    if stats['bursts']:
        for burst in stats['bursts']:
            if burst['count'] >= burst_threshold * 2:
                issues.append({
                    'severity': 'CRITICAL',
                    'message': f"Severe burst detected: {burst['count']} messages in {burst['duration_secs']}s",
                })
                status = 'CRITICAL'
            else:
                issues.append({
                    'severity': 'WARNING',
                    'message': f"Burst detected: {burst['count']} messages in {burst['duration_secs']}s",
                })
                if status != 'CRITICAL':
                    status = 'WARNING'

    # Check high-priority message count
    if stats['high_priority_count'] > 10:
        issues.append({
            'severity': 'WARNING',
            'message': f"High number of error-level messages: {stats['high_priority_count']}",
        })
        if status == 'OK':
            status = 'WARNING'

    return status, issues


def output_plain(stats, status, issues, warn_only=False, verbose=False):
    """Output results in plain text format"""
    if status == 'OK' and warn_only:
        return

    print(f"Kernel Log Rate Monitor - Status: {status}")
    print("=" * 50)

    if stats['has_timestamps']:
        if stats['messages_per_minute'] is not None:
            print(f"Overall rate: {stats['messages_per_minute']:.1f} messages/minute")
        if stats['recent_rate'] is not None:
            print(f"Recent rate (5 min): {stats['recent_rate']:.1f} messages/minute")
        if stats['time_window_minutes']:
            print(f"Time window: {stats['time_window_minutes']:.1f} minutes")
    else:
        print("Note: Timestamps not available, rate calculation not possible")

    print(f"Total messages in buffer: {stats['total_messages']}")

    if verbose and stats['priority_breakdown']:
        print("\nPriority breakdown:")
        for priority in ['emerg', 'alert', 'crit', 'err', 'warn', 'notice', 'info', 'debug']:
            count = stats['priority_breakdown'].get(priority, 0)
            if count > 0:
                print(f"  {priority:8s}: {count}")

    if issues:
        print("\nIssues detected:")
        for issue in issues:
            marker = "!!!" if issue['severity'] == 'CRITICAL' else " ! "
            print(f"{marker} [{issue['severity']}] {issue['message']}")

    if stats['bursts'] and verbose:
        print("\nBurst events:")
        for burst in stats['bursts']:
            print(f"  - {burst['count']} messages at {burst['start']}")


def output_json(stats, status, issues):
    """Output results in JSON format"""
    output = {
        'status': status,
        'statistics': {
            'total_messages': stats['total_messages'],
            'messages_per_minute': stats['messages_per_minute'],
            'recent_rate': stats['recent_rate'],
            'time_window_minutes': stats['time_window_minutes'],
            'has_timestamps': stats['has_timestamps'],
            'high_priority_count': stats['high_priority_count'],
            'priority_breakdown': stats['priority_breakdown'],
        },
        'bursts': stats['bursts'],
        'issues': issues,
    }
    print(json.dumps(output, indent=2, default=str))


def output_table(stats, status, issues, warn_only=False):
    """Output results in table format"""
    if status == 'OK' and warn_only:
        return

    print(f"{'Metric':<30} {'Value':<20} {'Status':<10}")
    print("=" * 60)

    rate_status = 'OK'
    for issue in issues:
        if 'rate' in issue['message'].lower():
            rate_status = issue['severity']
            break

    if stats['messages_per_minute'] is not None:
        print(f"{'Messages/minute':<30} {stats['messages_per_minute']:<20.1f} {rate_status:<10}")
    else:
        print(f"{'Messages/minute':<30} {'N/A':<20} {'UNKNOWN':<10}")

    print(f"{'Total messages':<30} {stats['total_messages']:<20} {'':<10}")
    print(f"{'High priority (err+)':<30} {stats['high_priority_count']:<20} {'':<10}")
    print(f"{'Burst events':<30} {len(stats['bursts']):<20} {'':<10}")

    if issues:
        print("\n" + "-" * 60)
        print("Issues:")
        for issue in issues:
            print(f"  [{issue['severity']}] {issue['message']}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Monitor kernel log message rates to detect anomalies',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check current message rates
  %(prog)s --format json            # JSON output for monitoring systems
  %(prog)s --warn-rate 100          # Custom warning threshold
  %(prog)s -v                       # Verbose output with priority breakdown
  %(prog)s --warn-only              # Only show if issues detected

Use cases:
  - Early detection of hardware issues (disk, memory, PCIe)
  - Identifying driver problems causing log spam
  - Monitoring system stability in production environments
  - Alerting on unusual kernel activity in datacenter monitoring
        """
    )

    parser.add_argument(
        '--warn-rate',
        type=float,
        default=DEFAULT_WARN_RATE,
        help=f'Warning threshold in messages/minute (default: {DEFAULT_WARN_RATE})'
    )

    parser.add_argument(
        '--crit-rate',
        type=float,
        default=DEFAULT_CRIT_RATE,
        help=f'Critical threshold in messages/minute (default: {DEFAULT_CRIT_RATE})'
    )

    parser.add_argument(
        '--burst-threshold',
        type=int,
        default=DEFAULT_BURST_THRESHOLD,
        help=f'Burst detection threshold (msgs in 5 sec) (default: {DEFAULT_BURST_THRESHOLD})'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including priority breakdown'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues are detected'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn_rate >= args.crit_rate:
        print("Error: warn-rate must be less than crit-rate", file=sys.stderr)
        sys.exit(2)

    # Run dmesg and get output
    output, time_format = run_dmesg()

    # Analyze message rates
    stats = analyze_message_rates(output, time_format)

    # Evaluate health
    status, issues = evaluate_health(
        stats,
        args.warn_rate,
        args.crit_rate,
        args.burst_threshold
    )

    # Output results
    if args.format == 'json':
        output_json(stats, status, issues)
    elif args.format == 'table':
        output_table(stats, status, issues, args.warn_only)
    else:  # plain
        output_plain(stats, status, issues, args.warn_only, args.verbose)

    # Exit based on status
    if status == 'CRITICAL' or status == 'WARNING':
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
