#!/usr/bin/env python3
"""
Monitor syslog/journald message rates for baremetal systems.

Detects log storms, excessive logging from specific services, and unusual
message rate patterns that may indicate:
- Runaway services generating excessive logs
- Log storms that can fill disk space rapidly
- Security events (brute force attempts, etc.)
- Application failures causing repeated error logging
- Kernel issues generating console spam

This is critical for large-scale baremetal environments where:
- Log storage is finite and shared
- Log storms can mask important messages
- Excessive I/O from logging impacts performance
- Central log aggregation has rate limits

Exit codes:
    0 - Message rates are within normal thresholds
    1 - Message rates exceed thresholds (warnings/issues found)
    2 - Usage error or journalctl not available
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime


def check_journalctl_available():
    """Check if journalctl is available"""
    try:
        result = subprocess.run(
            ['which', 'journalctl'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_journal_stats(since_minutes=5):
    """Get journal message statistics for the specified time window"""
    try:
        # Get messages from the last N minutes
        result = subprocess.run(
            ['journalctl', '--since', f'{since_minutes} minutes ago',
             '--no-pager', '-o', 'json', '--output-fields=_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,PRIORITY'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return None, result.stderr

        messages = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    msg = json.loads(line)
                    messages.append(msg)
                except json.JSONDecodeError:
                    continue

        return messages, None

    except subprocess.TimeoutExpired:
        return None, "Timeout reading journal"
    except FileNotFoundError:
        return None, "journalctl not found"
    except Exception as e:
        return None, str(e)


def get_disk_usage():
    """Get journal disk usage"""
    try:
        result = subprocess.run(
            ['journalctl', '--disk-usage'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            # Parse output like "Archived and active journals take up 1.2G in the file system."
            output = result.stdout.strip()
            # Extract size
            parts = output.split()
            for i, part in enumerate(parts):
                if part in ['up', 'take']:
                    if i + 1 < len(parts):
                        return parts[i + 1]
            return output
        return None

    except Exception:
        return None


def analyze_messages(messages, since_minutes, rate_threshold, top_count):
    """Analyze message statistics"""
    total_count = len(messages)
    rate_per_minute = total_count / since_minutes if since_minutes > 0 else 0

    # Count by source (unit or identifier)
    source_counts = {}
    priority_counts = {
        '0': 0,  # emerg
        '1': 0,  # alert
        '2': 0,  # crit
        '3': 0,  # err
        '4': 0,  # warning
        '5': 0,  # notice
        '6': 0,  # info
        '7': 0,  # debug
    }

    for msg in messages:
        # Get source
        source = msg.get('_SYSTEMD_UNIT') or msg.get('SYSLOG_IDENTIFIER') or 'unknown'
        source_counts[source] = source_counts.get(source, 0) + 1

        # Get priority
        priority = msg.get('PRIORITY', '6')
        if priority in priority_counts:
            priority_counts[priority] = priority_counts.get(priority, 0) + 1

    # Sort sources by count
    top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:top_count]

    # Calculate per-source rates
    top_sources_with_rates = [
        {
            'source': source,
            'count': count,
            'rate_per_minute': count / since_minutes if since_minutes > 0 else 0,
            'percentage': (count / total_count * 100) if total_count > 0 else 0,
        }
        for source, count in top_sources
    ]

    # Identify high-rate sources
    high_rate_sources = [
        s for s in top_sources_with_rates
        if s['rate_per_minute'] > rate_threshold
    ]

    # Priority summary
    priority_summary = {
        'emergency': priority_counts['0'],
        'alert': priority_counts['1'],
        'critical': priority_counts['2'],
        'error': priority_counts['3'],
        'warning': priority_counts['4'],
        'notice': priority_counts['5'],
        'info': priority_counts['6'],
        'debug': priority_counts['7'],
    }

    return {
        'total_count': total_count,
        'rate_per_minute': rate_per_minute,
        'top_sources': top_sources_with_rates,
        'high_rate_sources': high_rate_sources,
        'priority_summary': priority_summary,
        'unique_sources': len(source_counts),
    }


def collect_data(since_minutes=5, rate_threshold=100, top_count=10):
    """Collect syslog rate data"""
    messages, error = get_journal_stats(since_minutes)

    if error:
        return None, error

    analysis = analyze_messages(messages, since_minutes, rate_threshold, top_count)
    disk_usage = get_disk_usage()

    data = {
        'timestamp': datetime.now().isoformat(),
        'window_minutes': since_minutes,
        'rate_threshold': rate_threshold,
        'disk_usage': disk_usage,
        **analysis,
        'has_issues': len(analysis['high_rate_sources']) > 0,
    }

    return data, None


def output_plain(data, verbose=False, warn_only=False):
    """Output in plain text format"""
    if warn_only and not data['has_issues']:
        return

    print(f"Syslog Rate Monitor - Last {data['window_minutes']} minutes")
    print("=" * 60)
    print(f"Total messages: {data['total_count']}")
    print(f"Rate: {data['rate_per_minute']:.1f} msg/min")
    print(f"Unique sources: {data['unique_sources']}")

    if data['disk_usage']:
        print(f"Journal disk usage: {data['disk_usage']}")

    print()

    # Priority breakdown
    ps = data['priority_summary']
    high_priority = ps['emergency'] + ps['alert'] + ps['critical'] + ps['error']
    if high_priority > 0 or verbose:
        print("Priority breakdown:")
        if ps['emergency'] > 0:
            print(f"  EMERGENCY: {ps['emergency']}")
        if ps['alert'] > 0:
            print(f"  ALERT:     {ps['alert']}")
        if ps['critical'] > 0:
            print(f"  CRITICAL:  {ps['critical']}")
        if ps['error'] > 0:
            print(f"  ERROR:     {ps['error']}")
        if verbose:
            print(f"  WARNING:   {ps['warning']}")
            print(f"  NOTICE:    {ps['notice']}")
            print(f"  INFO:      {ps['info']}")
            print(f"  DEBUG:     {ps['debug']}")
        print()

    # High rate sources
    if data['high_rate_sources']:
        print(f"HIGH RATE SOURCES (>{data['rate_threshold']} msg/min):")
        print("-" * 60)
        for source in data['high_rate_sources']:
            print(f"  !!! {source['source']}")
            print(f"      {source['count']} msgs, {source['rate_per_minute']:.1f}/min, "
                  f"{source['percentage']:.1f}% of total")
        print()

    # Top sources
    if verbose or not data['high_rate_sources']:
        print(f"Top {len(data['top_sources'])} sources:")
        print("-" * 60)
        for source in data['top_sources']:
            marker = "!!!" if source['rate_per_minute'] > data['rate_threshold'] else "   "
            print(f"{marker} {source['source']:<40} "
                  f"{source['count']:>6} msgs  {source['rate_per_minute']:>6.1f}/min")


def output_json(data):
    """Output in JSON format"""
    print(json.dumps(data, indent=2))


def output_table(data, warn_only=False):
    """Output in table format"""
    if warn_only and not data['has_issues']:
        return

    print(f"{'Source':<45} {'Count':>8} {'Rate/min':>10} {'%':>6}")
    print("=" * 73)

    for source in data['top_sources']:
        marker = "*" if source['rate_per_minute'] > data['rate_threshold'] else " "
        print(f"{marker}{source['source']:<44} {source['count']:>8} "
              f"{source['rate_per_minute']:>10.1f} {source['percentage']:>5.1f}%")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Monitor syslog/journald message rates for baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Check last 5 minutes
  %(prog)s --since 15                # Check last 15 minutes
  %(prog)s --threshold 50            # Alert if any source > 50 msg/min
  %(prog)s --format json             # JSON output for automation
  %(prog)s -w                        # Only output if issues found
  %(prog)s --top 20 -v               # Show top 20 sources with details

Use cases:
  - Detect runaway services flooding logs
  - Monitor for log storms before disk fills
  - Identify noisy services for log filtering
  - Detect security events (brute force attempts)
  - Pre-flight check before log rotation

Exit codes:
  0 - Message rates within thresholds
  1 - High rate sources detected
  2 - Error (journalctl unavailable, etc.)
        """
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
        help='Show detailed information including all priority levels'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if high-rate sources detected'
    )

    parser.add_argument(
        '--since',
        type=int,
        default=5,
        metavar='MINUTES',
        help='Time window to analyze in minutes (default: %(default)s)'
    )

    parser.add_argument(
        '--threshold',
        type=int,
        default=100,
        metavar='RATE',
        help='Message rate threshold per source (msgs/min) to trigger warning (default: %(default)s)'
    )

    parser.add_argument(
        '--top',
        type=int,
        default=10,
        metavar='N',
        help='Number of top sources to display (default: %(default)s)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.since <= 0:
        print("Error: --since must be positive", file=sys.stderr)
        sys.exit(2)

    if args.threshold <= 0:
        print("Error: --threshold must be positive", file=sys.stderr)
        sys.exit(2)

    if args.top <= 0:
        print("Error: --top must be positive", file=sys.stderr)
        sys.exit(2)

    # Check for journalctl
    if not check_journalctl_available():
        print("Error: journalctl not found in PATH", file=sys.stderr)
        print("This script requires systemd-journald", file=sys.stderr)
        sys.exit(2)

    # Collect data
    data, error = collect_data(
        since_minutes=args.since,
        rate_threshold=args.threshold,
        top_count=args.top
    )

    if error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    # Output
    if args.format == 'json':
        output_json(data)
    elif args.format == 'table':
        output_table(data, warn_only=args.warn_only)
    else:
        output_plain(data, verbose=args.verbose, warn_only=args.warn_only)

    # Exit code based on findings
    if data['has_issues']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
