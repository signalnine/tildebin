#!/usr/bin/env python3
"""
Monitor logrotate status and log file health for baremetal systems.

Detects log rotation issues that can lead to disk exhaustion:
- Log files that have grown too large (failed rotation)
- Logrotate state file issues
- Recent logrotate errors
- Log directories consuming excessive disk space
- Missing or stale compressed logs

This is critical for large-scale baremetal environments where:
- Unrotated logs can fill disks unexpectedly
- Log storage is finite and shared
- Central log aggregation depends on proper rotation
- Compliance requires log retention policies

Exit codes:
    0 - Log rotation is healthy, no issues detected
    1 - Warnings or issues found (large logs, errors)
    2 - Usage error or required tools not available
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path


# Default paths to check
DEFAULT_LOG_DIRS = [
    '/var/log',
]

# Default logrotate paths
LOGROTATE_STATE_FILE = '/var/lib/logrotate/status'
LOGROTATE_STATE_FILE_ALT = '/var/lib/logrotate.status'
LOGROTATE_CONF = '/etc/logrotate.conf'
LOGROTATE_D = '/etc/logrotate.d'

# Thresholds
DEFAULT_MAX_LOG_SIZE_MB = 100
DEFAULT_MAX_DIR_SIZE_GB = 10
DEFAULT_MAX_AGE_DAYS = 7


def check_logrotate_available():
    """Check if logrotate is available"""
    try:
        result = subprocess.run(
            ['which', 'logrotate'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_file_size_mb(path):
    """Get file size in megabytes"""
    try:
        return os.path.getsize(path) / (1024 * 1024)
    except (OSError, IOError):
        return 0


def get_dir_size_bytes(path):
    """Get directory size in bytes"""
    total = 0
    try:
        for entry in os.scandir(path):
            if entry.is_file(follow_symlinks=False):
                total += entry.stat().st_size
            elif entry.is_dir(follow_symlinks=False):
                total += get_dir_size_bytes(entry.path)
    except (OSError, PermissionError):
        pass
    return total


def parse_logrotate_state():
    """Parse logrotate state file to get last rotation times"""
    state = {}

    # Try both possible state file locations
    state_file = None
    for path in [LOGROTATE_STATE_FILE, LOGROTATE_STATE_FILE_ALT]:
        if os.path.exists(path):
            state_file = path
            break

    if not state_file:
        return None, "Logrotate state file not found"

    try:
        with open(state_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('logrotate state'):
                    continue

                # Format: "/var/log/file" 2024-1-15-12:0:0
                # Or newer: "/var/log/file" 2024-1-15-12:0:0
                parts = line.rsplit(None, 1)
                if len(parts) == 2:
                    log_path = parts[0].strip('"')
                    date_str = parts[1]

                    # Parse date (format varies: YYYY-M-D-H:M:S or YYYY-M-D)
                    try:
                        # Try full format first
                        if '-' in date_str and ':' in date_str:
                            date_parts = date_str.replace(':', '-').split('-')
                            if len(date_parts) >= 6:
                                dt = datetime(
                                    int(date_parts[0]),
                                    int(date_parts[1]),
                                    int(date_parts[2]),
                                    int(date_parts[3]),
                                    int(date_parts[4]),
                                    int(date_parts[5])
                                )
                                state[log_path] = dt
                    except (ValueError, IndexError):
                        continue

        return state, None

    except (IOError, PermissionError) as e:
        return None, f"Cannot read state file: {e}"


def find_large_logs(log_dirs, max_size_mb):
    """Find log files exceeding size threshold"""
    large_logs = []

    for log_dir in log_dirs:
        if not os.path.isdir(log_dir):
            continue

        try:
            for root, dirs, files in os.walk(log_dir):
                # Skip compressed archives in size check
                for filename in files:
                    # Skip already rotated/compressed files
                    if any(filename.endswith(ext) for ext in ['.gz', '.bz2', '.xz', '.zst', '.lz4']):
                        continue

                    filepath = os.path.join(root, filename)

                    try:
                        size_mb = get_file_size_mb(filepath)
                        if size_mb >= max_size_mb:
                            # Get modification time
                            mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                            large_logs.append({
                                'path': filepath,
                                'size_mb': round(size_mb, 2),
                                'modified': mtime.isoformat(),
                                'age_days': (datetime.now() - mtime).days,
                            })
                    except (OSError, IOError):
                        continue

        except (OSError, PermissionError):
            continue

    return sorted(large_logs, key=lambda x: x['size_mb'], reverse=True)


def find_stale_logs(logrotate_state, max_age_days):
    """Find logs that haven't been rotated in too long"""
    if not logrotate_state:
        return []

    stale_logs = []
    now = datetime.now()
    threshold = now - timedelta(days=max_age_days)

    for log_path, last_rotation in logrotate_state.items():
        if last_rotation < threshold:
            # Check if the log file still exists
            if os.path.exists(log_path):
                age_days = (now - last_rotation).days
                stale_logs.append({
                    'path': log_path,
                    'last_rotation': last_rotation.isoformat(),
                    'age_days': age_days,
                })

    return sorted(stale_logs, key=lambda x: x['age_days'], reverse=True)


def check_logrotate_errors():
    """Check for recent logrotate errors in journal/syslog"""
    errors = []

    # Try journalctl first
    try:
        result = subprocess.run(
            ['journalctl', '-u', 'logrotate', '--since', '7 days ago',
             '-p', 'err', '--no-pager', '-o', 'short'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split('\n')[:10]:
                if line.strip():
                    errors.append({
                        'source': 'journalctl',
                        'message': line.strip()
                    })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Also check /var/log/syslog or /var/log/messages
    for syslog_path in ['/var/log/syslog', '/var/log/messages']:
        if os.path.exists(syslog_path):
            try:
                result = subprocess.run(
                    ['grep', '-i', 'logrotate.*error\\|logrotate.*fail', syslog_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split('\n')[:5]:
                        if line.strip():
                            errors.append({
                                'source': syslog_path,
                                'message': line.strip()[:200]
                            })
            except (subprocess.TimeoutExpired, OSError):
                pass
            break

    return errors


def get_log_directory_sizes(log_dirs, max_dir_size_gb):
    """Get sizes of log directories"""
    dir_sizes = []

    for log_dir in log_dirs:
        if not os.path.isdir(log_dir):
            continue

        try:
            size_bytes = get_dir_size_bytes(log_dir)
            size_gb = size_bytes / (1024 * 1024 * 1024)
            dir_sizes.append({
                'path': log_dir,
                'size_gb': round(size_gb, 2),
                'size_bytes': size_bytes,
                'exceeds_threshold': size_gb >= max_dir_size_gb,
            })
        except (OSError, PermissionError):
            continue

    return sorted(dir_sizes, key=lambda x: x['size_gb'], reverse=True)


def check_logrotate_config():
    """Basic validation of logrotate configuration"""
    issues = []

    # Check main config exists
    if not os.path.exists(LOGROTATE_CONF):
        issues.append({
            'severity': 'WARNING',
            'message': f'Main config not found: {LOGROTATE_CONF}'
        })

    # Check logrotate.d exists
    if not os.path.isdir(LOGROTATE_D):
        issues.append({
            'severity': 'WARNING',
            'message': f'Config directory not found: {LOGROTATE_D}'
        })
    else:
        # Count config files
        try:
            config_count = len([f for f in os.listdir(LOGROTATE_D)
                               if os.path.isfile(os.path.join(LOGROTATE_D, f))])
            if config_count == 0:
                issues.append({
                    'severity': 'WARNING',
                    'message': f'No config files in {LOGROTATE_D}'
                })
        except OSError:
            pass

    # Try to validate config with logrotate -d
    if check_logrotate_available():
        try:
            result = subprocess.run(
                ['logrotate', '-d', LOGROTATE_CONF],
                capture_output=True,
                text=True,
                timeout=30
            )
            # Check stderr for errors
            if result.returncode != 0 or 'error:' in result.stderr.lower():
                error_lines = [l for l in result.stderr.split('\n')
                              if 'error' in l.lower()][:3]
                for line in error_lines:
                    issues.append({
                        'severity': 'CRITICAL',
                        'message': f'Config error: {line.strip()[:100]}'
                    })
        except (subprocess.TimeoutExpired, OSError):
            pass

    return issues


def collect_data(log_dirs, max_log_size_mb, max_dir_size_gb, max_age_days):
    """Collect all logrotate status data"""
    # Parse state file
    logrotate_state, state_error = parse_logrotate_state()

    # Find issues
    large_logs = find_large_logs(log_dirs, max_log_size_mb)
    stale_logs = find_stale_logs(logrotate_state, max_age_days)
    dir_sizes = get_log_directory_sizes(log_dirs, max_dir_size_gb)
    errors = check_logrotate_errors()
    config_issues = check_logrotate_config()

    # Calculate summary
    has_issues = (
        len(large_logs) > 0 or
        len(stale_logs) > 0 or
        len(errors) > 0 or
        any(d['exceeds_threshold'] for d in dir_sizes) or
        any(i['severity'] == 'CRITICAL' for i in config_issues)
    )

    data = {
        'timestamp': datetime.now().isoformat(),
        'thresholds': {
            'max_log_size_mb': max_log_size_mb,
            'max_dir_size_gb': max_dir_size_gb,
            'max_age_days': max_age_days,
        },
        'state_file_ok': logrotate_state is not None,
        'state_file_error': state_error,
        'tracked_logs': len(logrotate_state) if logrotate_state else 0,
        'large_logs': large_logs,
        'stale_logs': stale_logs,
        'directory_sizes': dir_sizes,
        'recent_errors': errors,
        'config_issues': config_issues,
        'has_issues': has_issues,
        'summary': {
            'large_log_count': len(large_logs),
            'stale_log_count': len(stale_logs),
            'error_count': len(errors),
            'config_issue_count': len(config_issues),
            'directories_over_threshold': sum(1 for d in dir_sizes if d['exceeds_threshold']),
        }
    }

    return data


def output_plain(data, verbose=False, warn_only=False):
    """Output in plain text format"""
    if warn_only and not data['has_issues']:
        return

    print("Logrotate Status Monitor")
    print("=" * 60)
    print(f"Timestamp: {data['timestamp']}")
    print(f"State file: {'OK' if data['state_file_ok'] else 'NOT FOUND'}")
    if data['state_file_ok']:
        print(f"Tracked logs: {data['tracked_logs']}")
    print()

    # Config issues
    if data['config_issues']:
        print("CONFIGURATION ISSUES:")
        print("-" * 60)
        for issue in data['config_issues']:
            marker = "!!!" if issue['severity'] == 'CRITICAL' else "   "
            print(f"{marker} [{issue['severity']}] {issue['message']}")
        print()

    # Recent errors
    if data['recent_errors']:
        print(f"RECENT LOGROTATE ERRORS ({len(data['recent_errors'])}):")
        print("-" * 60)
        for error in data['recent_errors'][:5]:
            print(f"  !!! {error['message'][:80]}")
        print()

    # Large logs
    if data['large_logs']:
        print(f"LARGE LOG FILES (>{data['thresholds']['max_log_size_mb']}MB):")
        print("-" * 60)
        for log in data['large_logs'][:10]:
            print(f"  !!! {log['path']}")
            print(f"      {log['size_mb']} MB, {log['age_days']} days old")
        print()

    # Stale logs
    if data['stale_logs']:
        print(f"STALE LOGS (not rotated in >{data['thresholds']['max_age_days']} days):")
        print("-" * 60)
        for log in data['stale_logs'][:10]:
            print(f"  !!! {log['path']}")
            print(f"      Last rotated: {log['last_rotation']} ({log['age_days']} days ago)")
        print()

    # Directory sizes
    if verbose or any(d['exceeds_threshold'] for d in data['directory_sizes']):
        print("LOG DIRECTORY SIZES:")
        print("-" * 60)
        for d in data['directory_sizes']:
            marker = "!!!" if d['exceeds_threshold'] else "   "
            print(f"{marker} {d['path']}: {d['size_gb']} GB")
        print()

    # Summary
    if not data['has_issues']:
        print("No logrotate issues detected")
    else:
        s = data['summary']
        print("SUMMARY:")
        print(f"  Large logs: {s['large_log_count']}")
        print(f"  Stale logs: {s['stale_log_count']}")
        print(f"  Recent errors: {s['error_count']}")
        print(f"  Config issues: {s['config_issue_count']}")
        print(f"  Directories over threshold: {s['directories_over_threshold']}")


def output_json(data):
    """Output in JSON format"""
    print(json.dumps(data, indent=2))


def output_table(data, warn_only=False):
    """Output in table format"""
    if warn_only and not data['has_issues']:
        return

    # Large logs table
    if data['large_logs']:
        print(f"{'Log File':<50} {'Size (MB)':>10} {'Age (days)':>12}")
        print("=" * 75)
        for log in data['large_logs'][:15]:
            path = log['path']
            if len(path) > 48:
                path = "..." + path[-45:]
            print(f"{path:<50} {log['size_mb']:>10.1f} {log['age_days']:>12}")
        print()

    # Directory sizes table
    if data['directory_sizes']:
        print(f"{'Directory':<50} {'Size (GB)':>10} {'Status':>12}")
        print("=" * 75)
        for d in data['directory_sizes']:
            path = d['path']
            if len(path) > 48:
                path = "..." + path[-45:]
            status = "OVER" if d['exceeds_threshold'] else "OK"
            print(f"{path:<50} {d['size_gb']:>10.1f} {status:>12}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Monitor logrotate status and log file health for baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Check default /var/log
  %(prog)s --log-dir /var/log /opt/logs  # Check multiple directories
  %(prog)s --max-size 50             # Alert on logs > 50MB
  %(prog)s --max-age 3               # Alert on logs not rotated in 3 days
  %(prog)s --format json             # JSON output for automation
  %(prog)s -w                        # Only output if issues found

Use cases:
  - Detect failed log rotation before disk fills
  - Monitor log directory growth trends
  - Verify logrotate configuration is valid
  - Pre-flight check before deployments
  - Compliance audit for log retention

Exit codes:
  0 - Log rotation healthy, no issues
  1 - Issues detected (large logs, errors, etc.)
  2 - Error (missing tools, permission denied)
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
        help='Show detailed information including all directory sizes'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues detected'
    )

    parser.add_argument(
        '--log-dir',
        nargs='+',
        default=DEFAULT_LOG_DIRS,
        metavar='DIR',
        help='Log directories to check (default: /var/log)'
    )

    parser.add_argument(
        '--max-size',
        type=float,
        default=DEFAULT_MAX_LOG_SIZE_MB,
        metavar='MB',
        help='Maximum log file size in MB before warning (default: %(default)s)'
    )

    parser.add_argument(
        '--max-dir-size',
        type=float,
        default=DEFAULT_MAX_DIR_SIZE_GB,
        metavar='GB',
        help='Maximum log directory size in GB before warning (default: %(default)s)'
    )

    parser.add_argument(
        '--max-age',
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        metavar='DAYS',
        help='Maximum days since last rotation before warning (default: %(default)s)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.max_size <= 0:
        print("Error: --max-size must be positive", file=sys.stderr)
        sys.exit(2)

    if args.max_dir_size <= 0:
        print("Error: --max-dir-size must be positive", file=sys.stderr)
        sys.exit(2)

    if args.max_age <= 0:
        print("Error: --max-age must be positive", file=sys.stderr)
        sys.exit(2)

    # Validate log directories exist
    valid_dirs = []
    for log_dir in args.log_dir:
        if os.path.isdir(log_dir):
            valid_dirs.append(log_dir)
        else:
            print(f"Warning: Directory not found: {log_dir}", file=sys.stderr)

    if not valid_dirs:
        print("Error: No valid log directories specified", file=sys.stderr)
        sys.exit(2)

    # Collect data
    data = collect_data(
        log_dirs=valid_dirs,
        max_log_size_mb=args.max_size,
        max_dir_size_gb=args.max_dir_size,
        max_age_days=args.max_age
    )

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
