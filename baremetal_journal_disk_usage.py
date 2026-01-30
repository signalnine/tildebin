#!/usr/bin/env python3
"""
Monitor systemd journal disk usage and health on baremetal systems.

Checks journal disk consumption, identifies chatty services generating excessive
logs, and verifies journal configuration. Critical for preventing disk exhaustion
on systems with verbose logging or misconfigured journal rotation.

Exit codes:
    0 - Success (journal usage within acceptable limits)
    1 - Warning/Critical issues detected (high usage or corrupt journals)
    2 - Usage error or missing dependencies (journalctl not available)
"""

import argparse
import json
import os
import re
import subprocess
import sys


def check_journalctl_available():
    """Check if journalctl is available."""
    try:
        subprocess.run(
            ['journalctl', '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_journal_disk_usage():
    """Get journal disk usage statistics using journalctl --disk-usage."""
    try:
        result = subprocess.run(
            ['journalctl', '--disk-usage'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        return parse_disk_usage(result.stdout)
    except subprocess.CalledProcessError as e:
        return {'error': str(e.stderr)}


def parse_disk_usage(output):
    """
    Parse journalctl --disk-usage output.

    Example outputs:
    - "Archived and active journals take up 1.2G in the file system."
    - "Journals take up 256.0M on disk."
    """
    data = {
        'total_bytes': 0,
        'total_human': 'unknown',
    }

    # Match patterns like "1.2G", "256.0M", "512K", "1.5T"
    match = re.search(r'take up\s+([0-9.]+)([KMGTP]?)\s', output, re.IGNORECASE)
    if match:
        value = float(match.group(1))
        unit = match.group(2).upper() if match.group(2) else 'B'

        multipliers = {
            'B': 1,
            'K': 1024,
            'M': 1024 ** 2,
            'G': 1024 ** 3,
            'T': 1024 ** 4,
            'P': 1024 ** 5,
        }

        data['total_bytes'] = int(value * multipliers.get(unit, 1))
        data['total_human'] = f"{value}{unit}"

    return data


def get_journal_config():
    """Read journal configuration from journald.conf."""
    config = {
        'SystemMaxUse': None,
        'RuntimeMaxUse': None,
        'SystemKeepFree': None,
        'RuntimeKeepFree': None,
        'MaxFileSec': None,
        'MaxRetentionSec': None,
        'Compress': None,
        'Storage': None,
    }

    config_paths = [
        '/etc/systemd/journald.conf',
        '/etc/systemd/journald.conf.d/',
    ]

    # Read main config
    if os.path.exists('/etc/systemd/journald.conf'):
        try:
            with open('/etc/systemd/journald.conf', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or '=' not in line:
                        continue
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    if key in config and value:
                        config[key] = value
        except (IOError, OSError):
            pass

    # Read drop-in configs
    dropin_dir = '/etc/systemd/journald.conf.d/'
    if os.path.isdir(dropin_dir):
        try:
            for filename in sorted(os.listdir(dropin_dir)):
                if filename.endswith('.conf'):
                    filepath = os.path.join(dropin_dir, filename)
                    with open(filepath, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('#') or '=' not in line:
                                continue
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            if key in config and value:
                                config[key] = value
        except (IOError, OSError):
            pass

    return config


def get_journal_directory_size():
    """Get actual sizes of journal directories."""
    dirs = {
        '/var/log/journal': {'exists': False, 'size_bytes': 0},
        '/run/log/journal': {'exists': False, 'size_bytes': 0},
    }

    for journal_dir in dirs:
        if os.path.isdir(journal_dir):
            dirs[journal_dir]['exists'] = True
            total_size = 0
            try:
                for dirpath, dirnames, filenames in os.walk(journal_dir):
                    for filename in filenames:
                        filepath = os.path.join(dirpath, filename)
                        try:
                            total_size += os.path.getsize(filepath)
                        except OSError:
                            pass
                dirs[journal_dir]['size_bytes'] = total_size
            except OSError:
                pass

    return dirs


def get_top_log_producers(limit=10):
    """
    Get the top log-producing systemd units.

    Uses journalctl to count messages per unit.
    """
    producers = []

    try:
        # Get list of units with journal entries
        result = subprocess.run(
            ['journalctl', '--field=_SYSTEMD_UNIT', '--no-pager'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
            timeout=30
        )

        units = [u.strip() for u in result.stdout.strip().split('\n') if u.strip()]

        # Count entries per unit (sample recent entries for speed)
        unit_counts = {}
        for unit in units[:50]:  # Limit to avoid slow queries
            try:
                count_result = subprocess.run(
                    ['journalctl', '-u', unit, '--since', '24 hours ago',
                     '--output=short', '--no-pager', '-q'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10
                )
                # Count lines as proxy for message count
                count = len(count_result.stdout.strip().split('\n'))
                if count > 0:
                    unit_counts[unit] = count
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                pass

        # Sort and limit
        sorted_units = sorted(unit_counts.items(), key=lambda x: x[1], reverse=True)
        for unit, count in sorted_units[:limit]:
            producers.append({'unit': unit, 'messages_24h': count})

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return producers


def verify_journal_integrity():
    """
    Verify journal file integrity using journalctl --verify.

    Returns dict with verification status.
    """
    result = {
        'verified': False,
        'errors': [],
        'warnings': [],
        'files_checked': 0,
    }

    try:
        verify_result = subprocess.run(
            ['journalctl', '--verify', '--quiet'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120  # Journal verification can be slow
        )

        # Exit code 0 means all good
        if verify_result.returncode == 0:
            result['verified'] = True
        else:
            result['verified'] = False
            # Parse any error messages
            for line in verify_result.stderr.split('\n'):
                if line.strip():
                    if 'error' in line.lower():
                        result['errors'].append(line.strip())
                    elif 'warning' in line.lower():
                        result['warnings'].append(line.strip())

    except subprocess.TimeoutExpired:
        result['errors'].append('Verification timed out after 120 seconds')
    except subprocess.CalledProcessError as e:
        result['errors'].append(f'Verification failed: {e}')

    return result


def bytes_to_human(size_bytes):
    """Convert bytes to human-readable format."""
    for unit in ['B', 'K', 'M', 'G', 'T']:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f}P"


def parse_size_to_bytes(size_str):
    """Parse human-readable size to bytes (e.g., '500M' -> 524288000)."""
    if not size_str:
        return None

    match = re.match(r'^([0-9.]+)\s*([KMGTP]?)$', size_str.strip(), re.IGNORECASE)
    if not match:
        return None

    value = float(match.group(1))
    unit = match.group(2).upper() if match.group(2) else 'B'

    multipliers = {
        'B': 1,
        'K': 1024,
        'M': 1024 ** 2,
        'G': 1024 ** 3,
        'T': 1024 ** 4,
        'P': 1024 ** 5,
    }

    return int(value * multipliers.get(unit, 1))


def assess_status(usage_data, config, warn_threshold_pct, crit_threshold_pct,
                  warn_threshold_bytes, crit_threshold_bytes, integrity):
    """
    Assess journal health status.

    Returns: 'OK', 'WARNING', 'CRITICAL'
    """
    issues = []

    # Check integrity
    if integrity and not integrity.get('verified', True):
        if integrity.get('errors'):
            return 'CRITICAL', ['Journal integrity verification failed']
        elif integrity.get('warnings'):
            issues.append('Journal verification warnings')

    current_bytes = usage_data.get('total_bytes', 0)

    # Check against configured max
    max_use = config.get('SystemMaxUse')
    if max_use:
        max_bytes = parse_size_to_bytes(max_use)
        if max_bytes and current_bytes > 0:
            pct_used = (current_bytes / max_bytes) * 100
            if pct_used >= crit_threshold_pct:
                return 'CRITICAL', [f'Journal usage at {pct_used:.1f}% of configured max']
            elif pct_used >= warn_threshold_pct:
                issues.append(f'Journal usage at {pct_used:.1f}% of configured max')

    # Check absolute thresholds
    if crit_threshold_bytes and current_bytes >= crit_threshold_bytes:
        return 'CRITICAL', [f'Journal size ({bytes_to_human(current_bytes)}) exceeds critical threshold']
    elif warn_threshold_bytes and current_bytes >= warn_threshold_bytes:
        issues.append(f'Journal size ({bytes_to_human(current_bytes)}) exceeds warning threshold')

    # Check for no compression
    if config.get('Compress') and config['Compress'].lower() == 'no':
        issues.append('Journal compression is disabled')

    # Check storage mode
    if config.get('Storage') == 'volatile':
        issues.append('Journal storage is volatile (not persistent)')

    if issues:
        return 'WARNING', issues

    return 'OK', []


def format_plain(data, status, issues, verbose=False):
    """Format journal data as plain text."""
    output = []

    output.append(f"Journal Disk Usage Monitor: [{status}]")
    output.append("")

    # Show issues if any
    if issues:
        for issue in issues:
            output.append(f"  ! {issue}")
        output.append("")

    # Disk usage
    usage = data.get('usage', {})
    output.append(f"  Total Usage: {usage.get('total_human', 'unknown')}")

    # Directory breakdown
    dirs = data.get('directories', {})
    for dir_path, info in dirs.items():
        if info.get('exists'):
            size_human = bytes_to_human(info.get('size_bytes', 0))
            output.append(f"    {dir_path}: {size_human}")

    # Configuration
    if verbose:
        output.append("")
        output.append("  Configuration:")
        config = data.get('config', {})
        for key, value in config.items():
            if value:
                output.append(f"    {key}: {value}")

    # Top producers
    producers = data.get('top_producers', [])
    if producers:
        output.append("")
        output.append("  Top Log Producers (24h):")
        for p in producers[:5]:
            output.append(f"    {p['unit']}: {p['messages_24h']} messages")

    # Integrity
    if verbose:
        integrity = data.get('integrity', {})
        output.append("")
        output.append(f"  Integrity: {'Verified' if integrity.get('verified') else 'Issues detected'}")
        for err in integrity.get('errors', []):
            output.append(f"    ERROR: {err}")
        for warn in integrity.get('warnings', []):
            output.append(f"    WARNING: {warn}")

    return '\n'.join(output)


def format_json(data, status, issues):
    """Format journal data as JSON."""
    output = {
        'status': status,
        'issues': issues,
        **data
    }
    return json.dumps(output, indent=2)


def format_table(data, status, issues):
    """Format journal data as a table."""
    output = []

    header = f"{'METRIC':<35} {'VALUE':<25} {'STATUS':<15}"
    separator = '-' * len(header)
    output.append(header)
    output.append(separator)

    output.append(f"{'Overall Status':<35} {status:<25} {'':<15}")

    usage = data.get('usage', {})
    output.append(f"{'Total Journal Size':<35} {usage.get('total_human', 'unknown'):<25} {'':<15}")

    dirs = data.get('directories', {})
    for dir_path, info in dirs.items():
        if info.get('exists'):
            size_human = bytes_to_human(info.get('size_bytes', 0))
            output.append(f"{dir_path:<35} {size_human:<25} {'':<15}")

    config = data.get('config', {})
    if config.get('SystemMaxUse'):
        output.append(f"{'Configured Max (SystemMaxUse)':<35} {config['SystemMaxUse']:<25} {'':<15}")

    integrity = data.get('integrity', {})
    integrity_status = 'Verified' if integrity.get('verified') else 'FAILED'
    int_display = 'WARNING' if not integrity.get('verified') else ''
    output.append(f"{'Journal Integrity':<35} {integrity_status:<25} {int_display:<15}")

    if issues:
        output.append(separator)
        output.append("Issues:")
        for issue in issues:
            output.append(f"  - {issue}")

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor systemd journal disk usage and health.',
        epilog='''
Examples:
  # Check journal disk usage
  baremetal_journal_disk_usage.py

  # Show detailed information including top log producers
  baremetal_journal_disk_usage.py --verbose

  # Output as JSON for monitoring systems
  baremetal_journal_disk_usage.py --format json

  # Custom thresholds (warn at 70% of max, critical at 90%)
  baremetal_journal_disk_usage.py --warn-pct 70 --crit-pct 90

  # Absolute size thresholds (warn at 1GB, critical at 4GB)
  baremetal_journal_disk_usage.py --warn-size 1G --crit-size 4G

  # Skip slow integrity verification
  baremetal_journal_disk_usage.py --skip-verify

Exit codes:
  0 - Journal usage within acceptable limits
  1 - Warning or critical issues detected
  2 - Usage error or missing dependencies
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including config and integrity'
    )
    parser.add_argument(
        '--warn-pct',
        type=float,
        default=80.0,
        help='Warning threshold as percentage of configured max (default: 80)'
    )
    parser.add_argument(
        '--crit-pct',
        type=float,
        default=95.0,
        help='Critical threshold as percentage of configured max (default: 95)'
    )
    parser.add_argument(
        '--warn-size',
        type=str,
        default=None,
        help='Warning threshold as absolute size (e.g., 2G, 500M)'
    )
    parser.add_argument(
        '--crit-size',
        type=str,
        default=None,
        help='Critical threshold as absolute size (e.g., 4G, 1G)'
    )
    parser.add_argument(
        '--skip-verify',
        action='store_true',
        help='Skip journal integrity verification (faster)'
    )
    parser.add_argument(
        '--skip-producers',
        action='store_true',
        help='Skip identifying top log producers (faster)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn_pct <= 0 or args.crit_pct <= 0:
        print("Error: Percentage thresholds must be positive", file=sys.stderr)
        return 2

    if args.warn_pct >= args.crit_pct:
        print("Error: Warning percentage must be less than critical percentage",
              file=sys.stderr)
        return 2

    # Parse size thresholds
    warn_bytes = parse_size_to_bytes(args.warn_size) if args.warn_size else None
    crit_bytes = parse_size_to_bytes(args.crit_size) if args.crit_size else None

    if args.warn_size and warn_bytes is None:
        print(f"Error: Invalid warning size format: {args.warn_size}", file=sys.stderr)
        return 2

    if args.crit_size and crit_bytes is None:
        print(f"Error: Invalid critical size format: {args.crit_size}", file=sys.stderr)
        return 2

    if warn_bytes and crit_bytes and warn_bytes >= crit_bytes:
        print("Error: Warning size must be less than critical size", file=sys.stderr)
        return 2

    # Check for journalctl
    if not check_journalctl_available():
        print("Error: journalctl not found.", file=sys.stderr)
        print("This system may not be using systemd.", file=sys.stderr)
        return 2

    # Gather data
    data = {
        'usage': get_journal_disk_usage(),
        'config': get_journal_config(),
        'directories': get_journal_directory_size(),
        'top_producers': [] if args.skip_producers else get_top_log_producers(),
        'integrity': {} if args.skip_verify else verify_journal_integrity(),
    }

    # Check for errors in usage collection
    if 'error' in data['usage']:
        print(f"Error getting journal usage: {data['usage']['error']}", file=sys.stderr)
        return 1

    # Assess status
    status, issues = assess_status(
        data['usage'],
        data['config'],
        args.warn_pct,
        args.crit_pct,
        warn_bytes,
        crit_bytes,
        data['integrity']
    )

    # Format output
    if args.format == 'json':
        output = format_json(data, status, issues)
    elif args.format == 'table':
        output = format_table(data, status, issues)
    else:
        output = format_plain(data, status, issues, args.verbose)

    print(output)

    # Return exit code based on status
    if status in ('CRITICAL', 'WARNING'):
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
