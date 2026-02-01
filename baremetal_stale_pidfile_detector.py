#!/usr/bin/env python3
"""
Detect stale PID files that reference non-existent processes.

PID files are commonly used by daemons to record their process ID. When services
crash or are killed improperly, these files can become stale (referencing PIDs
that no longer exist or belong to different processes). This causes issues with
service startup and monitoring.

Common PID file locations:
  /var/run/*.pid
  /run/*.pid
  /var/lock/*.pid
  /tmp/*.pid

Exit codes:
    0 - No stale PID files detected
    1 - Stale PID files found
    2 - Usage error or missing permissions
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime


def get_process_name(pid):
    """Get the process name for a given PID, or None if process doesn't exist."""
    try:
        with open('/proc/{}/comm'.format(pid), 'r') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None


def get_process_cmdline(pid):
    """Get the full command line for a given PID."""
    try:
        with open('/proc/{}/cmdline'.format(pid), 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            return cmdline if cmdline else None
    except (IOError, OSError):
        return None


def read_pidfile(filepath):
    """Read and parse a PID file. Returns PID as int or None if invalid."""
    try:
        with open(filepath, 'r') as f:
            content = f.read().strip()
            # Handle multi-line PID files (some include additional info)
            first_line = content.split('\n')[0].strip()
            pid = int(first_line)
            if pid > 0:
                return pid
            return None
    except (IOError, OSError, ValueError):
        return None


def process_exists(pid):
    """Check if a process with the given PID exists."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def get_file_age_seconds(filepath):
    """Get the age of a file in seconds."""
    try:
        mtime = os.path.getmtime(filepath)
        return int(datetime.now().timestamp() - mtime)
    except OSError:
        return 0


def format_age(seconds):
    """Format seconds into human-readable age string."""
    if seconds < 60:
        return '{}s'.format(seconds)
    elif seconds < 3600:
        return '{}m'.format(seconds // 60)
    elif seconds < 86400:
        return '{}h'.format(seconds // 3600)
    else:
        return '{}d'.format(seconds // 86400)


def find_pidfiles(directories, recursive=False):
    """Find all PID files in the specified directories."""
    pidfiles = []

    for directory in directories:
        if not os.path.isdir(directory):
            continue

        if recursive:
            pattern = os.path.join(directory, '**', '*.pid')
            matches = glob.glob(pattern, recursive=True)
        else:
            pattern = os.path.join(directory, '*.pid')
            matches = glob.glob(pattern)

        pidfiles.extend(matches)

    # Also check common subdirectories without .pid extension patterns
    # Some services use /var/run/service/pid format
    for directory in directories:
        if not os.path.isdir(directory):
            continue

        # Check for files named exactly 'pid' in subdirectories
        if recursive:
            for root, dirs, files in os.walk(directory):
                if 'pid' in files:
                    pidfiles.append(os.path.join(root, 'pid'))

    return sorted(set(pidfiles))


def analyze_pidfile(filepath, check_name=False):
    """
    Analyze a PID file and return its status.

    Returns dict with:
        - filepath: path to the PID file
        - pid: the PID from the file (or None)
        - status: 'valid', 'stale', 'invalid', or 'mismatch'
        - process_name: name of current process (if valid)
        - expected_name: name expected based on filename
        - age_seconds: age of the PID file
        - details: human-readable status details
    """
    result = {
        'filepath': filepath,
        'pid': None,
        'status': 'invalid',
        'process_name': None,
        'expected_name': None,
        'age_seconds': get_file_age_seconds(filepath),
        'details': ''
    }

    # Try to determine expected service name from filename
    basename = os.path.basename(filepath)
    if basename.endswith('.pid'):
        result['expected_name'] = basename[:-4]
    elif basename == 'pid':
        # Use parent directory name
        result['expected_name'] = os.path.basename(os.path.dirname(filepath))

    # Read the PID
    pid = read_pidfile(filepath)
    if pid is None:
        result['details'] = 'Cannot read or parse PID file'
        return result

    result['pid'] = pid

    # Check if process exists
    if not process_exists(pid):
        result['status'] = 'stale'
        result['details'] = 'Process {} does not exist'.format(pid)
        return result

    # Process exists - get its name
    process_name = get_process_name(pid)
    result['process_name'] = process_name

    # Check for name mismatch if requested
    if check_name and result['expected_name'] and process_name:
        # Normalize names for comparison (some variations are acceptable)
        expected_lower = result['expected_name'].lower()
        actual_lower = process_name.lower()

        # Check if either contains the other (handles cases like 'nginx' vs 'nginx.conf')
        if expected_lower not in actual_lower and actual_lower not in expected_lower:
            result['status'] = 'mismatch'
            result['details'] = 'PID {} belongs to "{}" not "{}"'.format(
                pid, process_name, result['expected_name']
            )
            return result

    result['status'] = 'valid'
    result['details'] = 'Process {} ({}) is running'.format(pid, process_name or 'unknown')
    return result


def main():
    parser = argparse.ArgumentParser(
        description='Detect stale PID files that reference non-existent processes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Check default directories
  %(prog)s -d /var/run /tmp          # Check specific directories
  %(prog)s --recursive               # Search subdirectories
  %(prog)s --check-name              # Also detect PID/name mismatches
  %(prog)s --format json             # JSON output for automation

Default directories checked:
  /var/run, /run, /var/lock, /tmp

Exit codes:
  0 - No stale PID files detected
  1 - Stale PID files found
  2 - Usage error or permission issues
"""
    )
    parser.add_argument(
        '-d', '--directories',
        nargs='+',
        default=['/var/run', '/run', '/var/lock', '/tmp'],
        metavar='DIR',
        help='Directories to search for PID files (default: /var/run /run /var/lock /tmp)'
    )
    parser.add_argument(
        '-r', '--recursive',
        action='store_true',
        help='Search directories recursively'
    )
    parser.add_argument(
        '--check-name',
        action='store_true',
        help='Also report PID files where process name does not match filename'
    )
    parser.add_argument(
        '--min-age',
        type=int,
        default=0,
        metavar='SECONDS',
        help='Only report stale files older than N seconds (default: 0)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show all PID files, not just stale ones'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings (stale or mismatched PID files)'
    )

    args = parser.parse_args()

    # Find all PID files
    pidfiles = find_pidfiles(args.directories, args.recursive)

    if not pidfiles:
        if args.format == 'json':
            print(json.dumps({
                'pidfiles': [],
                'summary': {
                    'total': 0,
                    'valid': 0,
                    'stale': 0,
                    'mismatch': 0,
                    'invalid': 0
                },
                'has_issues': False,
                'timestamp': datetime.now().isoformat()
            }, indent=2))
        elif not args.warn_only:
            print('[OK] No PID files found in searched directories')
        sys.exit(0)

    # Analyze each PID file
    results = []
    for pidfile in pidfiles:
        result = analyze_pidfile(pidfile, args.check_name)

        # Apply age filter for stale files
        if result['status'] == 'stale' and result['age_seconds'] < args.min_age:
            result['status'] = 'valid'  # Too new to report
            result['details'] = 'Stale but below age threshold'

        results.append(result)

    # Categorize results
    stale = [r for r in results if r['status'] == 'stale']
    mismatch = [r for r in results if r['status'] == 'mismatch']
    invalid = [r for r in results if r['status'] == 'invalid']
    valid = [r for r in results if r['status'] == 'valid']

    has_issues = bool(stale or mismatch)

    # Output results
    if args.format == 'json':
        output = {
            'pidfiles': results if args.verbose else [r for r in results if r['status'] != 'valid'],
            'summary': {
                'total': len(results),
                'valid': len(valid),
                'stale': len(stale),
                'mismatch': len(mismatch),
                'invalid': len(invalid)
            },
            'has_issues': has_issues,
            'timestamp': datetime.now().isoformat()
        }
        print(json.dumps(output, indent=2))

    elif args.format == 'table':
        print('{:<50} {:<8} {:<8} {:<20}'.format(
            'PID FILE', 'PID', 'AGE', 'STATUS'
        ))
        print('-' * 90)

        for r in results:
            if args.warn_only and r['status'] == 'valid':
                continue

            pid_str = str(r['pid']) if r['pid'] else '-'
            age_str = format_age(r['age_seconds'])
            status_str = r['status'].upper()
            if r['status'] == 'stale':
                status_str = 'STALE'
            elif r['status'] == 'mismatch':
                status_str = 'MISMATCH'
            elif r['status'] == 'invalid':
                status_str = 'INVALID'
            else:
                status_str = 'OK'

            print('{:<50} {:<8} {:<8} {:<20}'.format(
                r['filepath'][:50],
                pid_str,
                age_str,
                status_str
            ))

        print()
        print('Summary: {} total, {} valid, {} stale, {} mismatch, {} invalid'.format(
            len(results), len(valid), len(stale), len(mismatch), len(invalid)
        ))

    else:  # plain format
        if stale:
            print('Stale PID files ({} found):'.format(len(stale)))
            for r in stale:
                age_str = format_age(r['age_seconds'])
                print('  [STALE] {} (pid={}, age={})'.format(
                    r['filepath'], r['pid'], age_str
                ))
                if args.verbose:
                    print('          {}'.format(r['details']))
            print()

        if mismatch:
            print('PID/Name mismatches ({} found):'.format(len(mismatch)))
            for r in mismatch:
                print('  [WARN] {} - {}'.format(r['filepath'], r['details']))
            print()

        if invalid and args.verbose:
            print('Invalid PID files ({} found):'.format(len(invalid)))
            for r in invalid:
                print('  [INFO] {} - {}'.format(r['filepath'], r['details']))
            print()

        if args.verbose and valid:
            print('Valid PID files ({} found):'.format(len(valid)))
            for r in valid:
                print('  [OK] {} (pid={}, process={})'.format(
                    r['filepath'], r['pid'], r['process_name'] or 'unknown'
                ))
            print()

        # Summary
        if not has_issues:
            if not args.warn_only:
                print('[OK] No stale PID files detected ({} files checked)'.format(len(results)))
        else:
            print('[WARN] Found {} stale and {} mismatched PID files'.format(
                len(stale), len(mismatch)
            ))

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
