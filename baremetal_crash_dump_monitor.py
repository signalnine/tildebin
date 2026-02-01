#!/usr/bin/env python3
"""
Monitor kernel crash dumps and kdump configuration on baremetal systems.

This script checks the health of crash dump mechanisms and identifies any
historical kernel panics or crashes. Essential for baremetal systems where
understanding crash history is critical for reliability analysis.

Features:
- Check if kdump service is configured and active
- Verify crash dump directory exists and has proper permissions
- List historical crash dumps with timestamps and sizes
- Detect recent crashes that may need investigation
- Check crashkernel reservation in boot parameters

Exit codes:
    0 - Kdump healthy, no recent crashes
    1 - Issues found (kdump misconfigured, recent crashes detected)
    2 - Usage error or missing dependencies
"""

import argparse
import sys
import os
import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path


def run_command(cmd, check=False):
    """
    Run a shell command and return result.

    Args:
        cmd: Command as list of strings
        check: If True, raise on non-zero exit

    Returns:
        tuple: (return_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        if check and result.returncode != 0:
            return result.returncode, result.stdout, result.stderr
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def check_kdump_service():
    """
    Check if kdump service is enabled and active.

    Returns:
        dict: Service status information
    """
    result = {
        'installed': False,
        'enabled': False,
        'active': False,
        'status': 'unknown'
    }

    # Check if kdump is installed (try systemd first, then init)
    rc, stdout, stderr = run_command(['systemctl', 'is-enabled', 'kdump'])
    if rc == 0:
        result['installed'] = True
        result['enabled'] = stdout.strip() == 'enabled'
    elif 'No such file' not in stderr and 'not found' not in stderr.lower():
        # Service exists but may be disabled
        result['installed'] = True
        result['enabled'] = False

    # Check if service is active
    rc, stdout, stderr = run_command(['systemctl', 'is-active', 'kdump'])
    if rc == 0:
        result['active'] = stdout.strip() == 'active'
        result['status'] = stdout.strip()
    else:
        result['status'] = stdout.strip() if stdout.strip() else 'inactive'

    # On systems without systemd, check for alternative crash mechanisms
    if not result['installed']:
        # Check for kexec-tools
        rc, stdout, _ = run_command(['which', 'kdump'])
        if rc == 0:
            result['installed'] = True
            result['status'] = 'kexec-tools installed'

    return result


def check_crashkernel_reservation():
    """
    Check if crashkernel memory is reserved in boot parameters.

    Returns:
        dict: Crashkernel reservation info
    """
    result = {
        'reserved': False,
        'size': None,
        'cmdline_param': None
    }

    try:
        with open('/proc/cmdline', 'r') as f:
            cmdline = f.read().strip()

        # Look for crashkernel parameter
        for param in cmdline.split():
            if param.startswith('crashkernel='):
                result['reserved'] = True
                result['cmdline_param'] = param
                result['size'] = param.split('=')[1]
                break

    except (IOError, OSError):
        pass

    # Also check /sys/kernel/kexec_crash_size
    try:
        with open('/sys/kernel/kexec_crash_size', 'r') as f:
            crash_size = int(f.read().strip())
            if crash_size > 0:
                result['reserved'] = True
                result['actual_bytes'] = crash_size
    except (IOError, OSError, ValueError):
        pass

    return result


def get_crash_directories():
    """
    Get list of common crash dump directories.

    Returns:
        list: Paths that exist on this system
    """
    common_paths = [
        '/var/crash',
        '/var/spool/abrt',
        '/var/lib/systemd/coredump',
        '/var/log/dump',
    ]

    existing = []
    for path in common_paths:
        if os.path.isdir(path):
            existing.append(path)

    return existing


def analyze_crash_directory(path):
    """
    Analyze a crash dump directory for crash files.

    Args:
        path: Directory path to analyze

    Returns:
        dict: Analysis results including crash list
    """
    result = {
        'path': path,
        'exists': False,
        'readable': False,
        'writable': False,
        'crashes': [],
        'total_size_bytes': 0,
        'crash_count': 0
    }

    if not os.path.exists(path):
        return result

    result['exists'] = True
    result['readable'] = os.access(path, os.R_OK)
    result['writable'] = os.access(path, os.W_OK)

    if not result['readable']:
        return result

    try:
        for entry in os.scandir(path):
            if entry.is_dir():
                # Check for vmcore or crash dump directories
                crash_info = analyze_crash_entry(entry.path)
                if crash_info:
                    result['crashes'].append(crash_info)
                    result['total_size_bytes'] += crash_info.get('size_bytes', 0)
            elif entry.is_file():
                # Check for crash-related files
                if any(name in entry.name.lower() for name in ['vmcore', 'dump', 'crash', 'core']):
                    stat = entry.stat()
                    crash_info = {
                        'path': entry.path,
                        'name': entry.name,
                        'type': 'file',
                        'size_bytes': stat.st_size,
                        'mtime': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'age_days': (datetime.now() - datetime.fromtimestamp(stat.st_mtime)).days
                    }
                    result['crashes'].append(crash_info)
                    result['total_size_bytes'] += stat.st_size

        result['crash_count'] = len(result['crashes'])

    except PermissionError:
        result['readable'] = False
    except OSError as e:
        result['error'] = str(e)

    return result


def analyze_crash_entry(path):
    """
    Analyze a single crash dump entry (file or directory).

    Args:
        path: Path to crash entry

    Returns:
        dict or None: Crash info if this is a crash dump
    """
    try:
        stat_info = os.stat(path)
        mtime = datetime.fromtimestamp(stat_info.st_mtime)
        age_days = (datetime.now() - mtime).days

        # Calculate total size for directories
        if os.path.isdir(path):
            total_size = 0
            for root, dirs, files in os.walk(path):
                for f in files:
                    try:
                        total_size += os.path.getsize(os.path.join(root, f))
                    except OSError:
                        pass
            size_bytes = total_size

            # Check for vmcore file inside
            vmcore_path = os.path.join(path, 'vmcore')
            has_vmcore = os.path.exists(vmcore_path)
        else:
            size_bytes = stat_info.st_size
            has_vmcore = 'vmcore' in os.path.basename(path).lower()

        return {
            'path': path,
            'name': os.path.basename(path),
            'type': 'directory' if os.path.isdir(path) else 'file',
            'has_vmcore': has_vmcore,
            'size_bytes': size_bytes,
            'mtime': mtime.isoformat(),
            'age_days': age_days
        }

    except (OSError, PermissionError):
        return None


def check_dmesg_for_crashes():
    """
    Check dmesg for kernel panic or crash indicators.

    Returns:
        dict: Crash indicators found in dmesg
    """
    result = {
        'checked': False,
        'indicators': [],
        'panic_count': 0,
        'oops_count': 0
    }

    # Patterns that indicate crashes or serious issues
    patterns = [
        ('panic', 'Kernel panic'),
        ('Oops', 'Kernel Oops'),
        ('BUG:', 'Kernel BUG'),
        ('RIP:', 'Instruction pointer dump'),
        ('Call Trace:', 'Stack trace'),
        ('Hardware Error', 'Hardware error'),
        ('Machine Check Exception', 'MCE error'),
    ]

    rc, stdout, stderr = run_command(['dmesg', '-T'])
    if rc != 0:
        # Try without timestamp if -T not supported
        rc, stdout, stderr = run_command(['dmesg'])

    if rc == 0:
        result['checked'] = True
        lines = stdout.split('\n')

        for line in lines:
            for pattern, description in patterns:
                if pattern.lower() in line.lower():
                    result['indicators'].append({
                        'pattern': pattern,
                        'description': description,
                        'line': line[:200]  # Truncate long lines
                    })
                    if 'panic' in pattern.lower():
                        result['panic_count'] += 1
                    if 'oops' in pattern.lower():
                        result['oops_count'] += 1
                    break  # Only match first pattern per line

    return result


def format_bytes(size_bytes):
    """Format bytes to human readable format."""
    if size_bytes >= 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    elif size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes} B"


def output_plain(data, args):
    """Output results in plain text format."""
    kdump = data['kdump_service']
    crashkernel = data['crashkernel']
    issues = data['issues']

    if not args.warn_only:
        print("=== Crash Dump Monitor ===")
        print()

        # Kdump status
        print("Kdump Service Status:")
        status_icon = "✓" if kdump['active'] else "✗"
        print(f"  Installed: {'Yes' if kdump['installed'] else 'No'}")
        print(f"  Enabled:   {'Yes' if kdump['enabled'] else 'No'}")
        print(f"  Active:    {status_icon} {kdump['status']}")
        print()

        # Crashkernel reservation
        print("Crashkernel Reservation:")
        if crashkernel['reserved']:
            print(f"  Reserved: Yes")
            if crashkernel.get('size'):
                print(f"  Size: {crashkernel['size']}")
            if crashkernel.get('actual_bytes'):
                print(f"  Actual: {format_bytes(crashkernel['actual_bytes'])}")
        else:
            print("  Reserved: No (crashkernel= not in boot params)")
        print()

        # Crash directories
        print("Crash Directories:")
        for dir_info in data['crash_directories']:
            path = dir_info['path']
            if dir_info['exists']:
                count = dir_info['crash_count']
                size = format_bytes(dir_info['total_size_bytes'])
                print(f"  {path}: {count} crash(es), {size}")
                if args.verbose and dir_info['crashes']:
                    for crash in dir_info['crashes'][:5]:  # Show max 5
                        print(f"    - {crash['name']} ({crash['age_days']} days old)")
            else:
                print(f"  {path}: not found")
        print()

        # Recent crashes summary
        total_crashes = sum(d['crash_count'] for d in data['crash_directories'])
        recent_crashes = sum(
            len([c for c in d['crashes'] if c.get('age_days', 999) <= args.recent_days])
            for d in data['crash_directories']
        )
        if total_crashes > 0:
            print(f"Total crash dumps found: {total_crashes}")
            print(f"Crashes in last {args.recent_days} days: {recent_crashes}")
            print()

    # Issues
    if issues:
        print("Issues Detected:")
        for issue in issues:
            print(f"  [{issue['severity']}] {issue['message']}")
    elif not args.warn_only:
        print("No issues detected - crash dump system appears healthy")


def output_json(data, args):
    """Output results in JSON format."""
    print(json.dumps(data, indent=2, default=str))


def output_table(data, args):
    """Output results in table format."""
    kdump = data['kdump_service']
    crashkernel = data['crashkernel']
    issues = data['issues']

    if not args.warn_only:
        print("┌" + "─" * 70 + "┐")
        print("│" + " Crash Dump Monitor ".center(70) + "│")
        print("├" + "─" * 70 + "┤")

        # Status row
        kdump_status = "Active" if kdump['active'] else "Inactive"
        crash_status = "Reserved" if crashkernel['reserved'] else "Not Reserved"
        print(f"│ Kdump: {kdump_status:<20} Crashkernel: {crash_status:<20}     │")
        print("├" + "─" * 70 + "┤")

        # Crash directories
        print(f"│ {'Directory':<35} {'Crashes':>10} {'Size':>15}    │")
        print("├" + "─" * 70 + "┤")

        for dir_info in data['crash_directories']:
            path = dir_info['path'][:35]
            count = dir_info['crash_count'] if dir_info['exists'] else '-'
            size = format_bytes(dir_info['total_size_bytes']) if dir_info['exists'] else '-'
            print(f"│ {path:<35} {str(count):>10} {size:>15}    │")

        print("├" + "─" * 70 + "┤")

    # Issues
    if issues:
        for issue in issues:
            line = f" [{issue['severity']}] {issue['message']}"[:68]
            print(f"│{line:<70}│")
    else:
        if not args.warn_only:
            print(f"│{' No issues detected':^70}│")

    if not args.warn_only:
        print("└" + "─" * 70 + "┘")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor kernel crash dumps and kdump configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic status check
  %(prog)s

  # JSON output for monitoring integration
  %(prog)s --format json

  # Verbose output with crash details
  %(prog)s --verbose

  # Only show issues (for alerting)
  %(prog)s --warn-only

  # Check for crashes in last 7 days
  %(prog)s --recent-days 7

Kdump Configuration:
  To enable kdump on most Linux distributions:
    1. Install kexec-tools package
    2. Add crashkernel=auto to kernel boot parameters
    3. Enable and start kdump service:
       systemctl enable --now kdump

Exit codes:
  0 - Kdump healthy, no recent crashes
  1 - Issues found (misconfigured kdump or recent crashes)
  2 - Usage error
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
        help='Show detailed information including crash dump contents'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if issues are detected'
    )

    parser.add_argument(
        '--recent-days',
        type=int,
        default=30,
        metavar='DAYS',
        help='Consider crashes within N days as recent (default: 30)'
    )

    parser.add_argument(
        '--check-dmesg',
        action='store_true',
        help='Also check dmesg for crash indicators'
    )

    args = parser.parse_args()

    if args.recent_days < 1:
        print("Error: --recent-days must be at least 1", file=sys.stderr)
        sys.exit(2)

    # Collect all information
    kdump_status = check_kdump_service()
    crashkernel_info = check_crashkernel_reservation()
    crash_dirs = get_crash_directories()

    # Analyze each crash directory
    dir_analyses = []
    for path in crash_dirs:
        analysis = analyze_crash_directory(path)
        dir_analyses.append(analysis)

    # Also check default path even if it doesn't exist
    default_checked = False
    for d in dir_analyses:
        if d['path'] == '/var/crash':
            default_checked = True
            break
    if not default_checked:
        dir_analyses.insert(0, analyze_crash_directory('/var/crash'))

    # Optionally check dmesg
    dmesg_info = None
    if args.check_dmesg:
        dmesg_info = check_dmesg_for_crashes()

    # Identify issues
    issues = []

    if not kdump_status['installed']:
        issues.append({
            'severity': 'WARNING',
            'message': 'Kdump is not installed - crash dumps will not be captured'
        })
    elif not kdump_status['enabled']:
        issues.append({
            'severity': 'WARNING',
            'message': 'Kdump service is not enabled'
        })
    elif not kdump_status['active']:
        issues.append({
            'severity': 'WARNING',
            'message': 'Kdump service is not active'
        })

    if not crashkernel_info['reserved']:
        issues.append({
            'severity': 'WARNING',
            'message': 'Crashkernel memory not reserved - add crashkernel=auto to boot params'
        })

    # Check for recent crashes
    for dir_info in dir_analyses:
        for crash in dir_info.get('crashes', []):
            age_days = crash.get('age_days', 999)
            if age_days <= args.recent_days:
                issues.append({
                    'severity': 'CRITICAL',
                    'message': f"Recent crash dump found: {crash['name']} ({age_days} days old)"
                })

    # Check dmesg if requested
    if dmesg_info and dmesg_info['checked']:
        if dmesg_info['panic_count'] > 0:
            issues.append({
                'severity': 'CRITICAL',
                'message': f"Kernel panic indicators found in dmesg ({dmesg_info['panic_count']} occurrences)"
            })
        if dmesg_info['oops_count'] > 0:
            issues.append({
                'severity': 'WARNING',
                'message': f"Kernel Oops found in dmesg ({dmesg_info['oops_count']} occurrences)"
            })

    # Compile results
    data = {
        'kdump_service': kdump_status,
        'crashkernel': crashkernel_info,
        'crash_directories': dir_analyses,
        'issues': issues,
        'check_time': datetime.now().isoformat()
    }

    if dmesg_info:
        data['dmesg_analysis'] = dmesg_info

    # Handle warn-only mode
    if args.warn_only and not issues:
        sys.exit(0)

    # Output results
    if args.format == 'json':
        output_json(data, args)
    elif args.format == 'table':
        output_table(data, args)
    else:
        output_plain(data, args)

    # Exit code based on issues
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)

    sys.exit(1 if (has_critical or has_warning) else 0)


if __name__ == '__main__':
    main()
