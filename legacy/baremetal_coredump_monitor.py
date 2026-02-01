#!/usr/bin/env python3
"""
Monitor coredump configuration and storage for production debugging.

This script monitors the system's coredump handling configuration and storage
to ensure crash dumps are properly captured for post-mortem debugging. Critical
for large-scale baremetal environments where:

- Production crashes need to be analyzed for root cause
- Disk space must be managed to prevent coredump storage exhaustion
- Coredump patterns must be correctly configured for collection tools
- systemd-coredump or kernel coredumps need verification

Checks performed:
- Core pattern configuration (kernel.core_pattern)
- Core file size limits (ulimit -c)
- Coredump storage location and available space
- systemd-coredump configuration (if applicable)
- Recent coredump files and their sizes
- Coredump compression settings

Exit codes:
    0 - Coredump configuration is healthy
    1 - Issues detected (misconfiguration or storage concerns)
    2 - Usage error or system files not accessible
"""

import argparse
import sys
import os
import json
import glob
import re
from datetime import datetime


def read_core_pattern():
    """Read kernel core_pattern setting.

    Returns:
        str: The core pattern string
    """
    try:
        with open('/proc/sys/kernel/core_pattern', 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        print("Error: /proc/sys/kernel/core_pattern not found", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Permission denied reading core_pattern", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error reading core_pattern: {e}", file=sys.stderr)
        sys.exit(2)


def read_core_uses_pid():
    """Read kernel core_uses_pid setting.

    Returns:
        bool: True if PID is appended to core files
    """
    try:
        with open('/proc/sys/kernel/core_uses_pid', 'r') as f:
            return f.read().strip() == '1'
    except Exception:
        return False


def read_core_pipe_limit():
    """Read kernel core_pipe_limit setting.

    Returns:
        int: Maximum concurrent pipe handler processes
    """
    try:
        with open('/proc/sys/kernel/core_pipe_limit', 'r') as f:
            return int(f.read().strip())
    except Exception:
        return 0


def check_systemd_coredump():
    """Check if systemd-coredump is in use and its configuration.

    Returns:
        dict: systemd-coredump configuration info
    """
    info = {
        'enabled': False,
        'storage': None,
        'compress': None,
        'max_use': None,
        'external_size_max': None,
        'journal_size_max': None
    }

    # Check if core_pattern points to systemd-coredump
    core_pattern = read_core_pattern()
    if 'systemd-coredump' in core_pattern:
        info['enabled'] = True

    # Try to read coredump.conf
    config_paths = [
        '/etc/systemd/coredump.conf',
        '/etc/systemd/coredump.conf.d/*.conf'
    ]

    for config_path in config_paths:
        for path in glob.glob(config_path):
            try:
                with open(path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('#') or '=' not in line:
                            continue
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()

                        if key == 'Storage':
                            info['storage'] = value
                        elif key == 'Compress':
                            info['compress'] = value
                        elif key == 'MaxUse':
                            info['max_use'] = value
                        elif key == 'ExternalSizeMax':
                            info['external_size_max'] = value
                        elif key == 'JournalSizeMax':
                            info['journal_size_max'] = value
            except Exception:
                continue

    return info


def get_coredump_directory(core_pattern, systemd_info):
    """Determine where coredumps are stored.

    Args:
        core_pattern: The kernel core pattern
        systemd_info: systemd-coredump configuration

    Returns:
        str or None: Path to coredump directory
    """
    # systemd-coredump stores in /var/lib/systemd/coredump
    if systemd_info['enabled']:
        if systemd_info['storage'] == 'external':
            return '/var/lib/systemd/coredump'
        elif systemd_info['storage'] == 'journal':
            return None  # Stored in journal
        elif systemd_info['storage'] == 'none':
            return None

    # Check if core_pattern specifies a directory
    if core_pattern.startswith('|'):
        # Piped to external program
        return None

    # Extract directory from pattern
    if '/' in core_pattern:
        return os.path.dirname(core_pattern)

    # Default: current working directory of crashed process
    return None


def get_directory_usage(path):
    """Get disk usage information for a directory.

    Args:
        path: Directory path

    Returns:
        dict: Disk usage information
    """
    if not path or not os.path.exists(path):
        return None

    try:
        statvfs = os.statvfs(path)
        block_size = statvfs.f_frsize
        total = statvfs.f_blocks * block_size
        free = statvfs.f_bfree * block_size
        available = statvfs.f_bavail * block_size
        used = total - free

        return {
            'path': path,
            'total_bytes': total,
            'used_bytes': used,
            'available_bytes': available,
            'used_percent': (used / total * 100) if total > 0 else 0
        }
    except Exception:
        return None


def find_recent_coredumps(directory, max_files=10):
    """Find recent coredump files.

    Args:
        directory: Directory to search
        max_files: Maximum number of files to return

    Returns:
        list: List of coredump file info dicts
    """
    coredumps = []

    if not directory or not os.path.exists(directory):
        return coredumps

    try:
        # Look for core files
        patterns = ['core*', '*.core', '*.coredump']
        files = []

        for pattern in patterns:
            files.extend(glob.glob(os.path.join(directory, pattern)))

        # Get file info and sort by mtime
        for filepath in files:
            try:
                stat = os.stat(filepath)
                coredumps.append({
                    'path': filepath,
                    'size_bytes': stat.st_size,
                    'mtime': stat.st_mtime,
                    'mtime_str': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
            except Exception:
                continue

        # Sort by modification time (newest first)
        coredumps.sort(key=lambda x: x['mtime'], reverse=True)

    except Exception:
        pass

    return coredumps[:max_files]


def check_ulimit():
    """Check core file size limit.

    Returns:
        dict: Ulimit information
    """
    import resource

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
        return {
            'soft_limit': soft if soft != resource.RLIM_INFINITY else 'unlimited',
            'hard_limit': hard if hard != resource.RLIM_INFINITY else 'unlimited',
            'enabled': soft != 0
        }
    except Exception:
        return {
            'soft_limit': 'unknown',
            'hard_limit': 'unknown',
            'enabled': True  # Assume enabled if we can't check
        }


def check_abrt():
    """Check if ABRT (Automatic Bug Reporting Tool) is configured.

    Returns:
        dict: ABRT configuration info
    """
    info = {
        'installed': False,
        'enabled': False
    }

    # Check if abrtd is running
    try:
        for pid_dir in os.listdir('/proc'):
            if not pid_dir.isdigit():
                continue
            try:
                with open(f'/proc/{pid_dir}/comm', 'r') as f:
                    if 'abrt' in f.read().strip():
                        info['enabled'] = True
                        break
            except Exception:
                continue
    except Exception:
        pass

    # Check if ABRT config exists
    if os.path.exists('/etc/abrt/abrt.conf'):
        info['installed'] = True

    return info


def analyze_configuration(core_pattern, systemd_info, ulimit_info, storage_info):
    """Analyze coredump configuration and return issues.

    Args:
        core_pattern: Kernel core pattern
        systemd_info: systemd-coredump configuration
        ulimit_info: Core file ulimit settings
        storage_info: Storage usage information

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    # Check if coredumps are disabled
    if core_pattern == '' or core_pattern == '/dev/null':
        issues.append({
            'severity': 'WARNING',
            'category': 'configuration',
            'message': 'Core dumps disabled (core_pattern is empty or /dev/null)'
        })

    # Check ulimit
    if not ulimit_info['enabled']:
        issues.append({
            'severity': 'WARNING',
            'category': 'ulimit',
            'message': 'Core file size limit is 0 - no core dumps will be generated'
        })

    # Check systemd-coredump storage setting
    if systemd_info['enabled']:
        if systemd_info['storage'] == 'none':
            issues.append({
                'severity': 'WARNING',
                'category': 'systemd',
                'message': 'systemd-coredump storage set to none - cores discarded'
            })
        elif systemd_info['storage'] == 'journal':
            issues.append({
                'severity': 'INFO',
                'category': 'systemd',
                'message': 'Coredumps stored in journal - may be truncated for large cores'
            })

    # Check storage space
    if storage_info:
        if storage_info['used_percent'] > 90:
            issues.append({
                'severity': 'CRITICAL',
                'category': 'storage',
                'message': f"Coredump storage {storage_info['used_percent']:.1f}% full - "
                          f"new dumps may fail"
            })
        elif storage_info['used_percent'] > 75:
            issues.append({
                'severity': 'WARNING',
                'category': 'storage',
                'message': f"Coredump storage {storage_info['used_percent']:.1f}% full - "
                          f"consider cleanup"
            })

    # Check pipe limit for piped patterns
    if core_pattern.startswith('|'):
        pipe_limit = read_core_pipe_limit()
        if pipe_limit == 0:
            issues.append({
                'severity': 'WARNING',
                'category': 'configuration',
                'message': 'core_pipe_limit is 0 - concurrent crashes may lose dumps'
            })

    return issues


def format_bytes(size):
    """Format bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size) < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def output_plain(data, args):
    """Output results in plain text format."""
    if not args.warn_only:
        print("Coredump Configuration")
        print("-" * 50)
        print(f"Core Pattern: {data['core_pattern']}")

        ulimit = data['ulimit']
        soft = ulimit['soft_limit']
        if isinstance(soft, int):
            soft = format_bytes(soft)
        print(f"Core Size Limit: {soft} (soft), {ulimit['hard_limit']} (hard)")
        print(f"Core Uses PID: {data['core_uses_pid']}")

        if data['systemd_coredump']['enabled']:
            sd = data['systemd_coredump']
            print(f"\nsystemd-coredump: enabled")
            if sd['storage']:
                print(f"  Storage: {sd['storage']}")
            if sd['compress']:
                print(f"  Compress: {sd['compress']}")
            if sd['max_use']:
                print(f"  Max Use: {sd['max_use']}")

        if data['storage']:
            storage = data['storage']
            print(f"\nStorage Location: {storage['path']}")
            print(f"  Used: {format_bytes(storage['used_bytes'])} / "
                  f"{format_bytes(storage['total_bytes'])} "
                  f"({storage['used_percent']:.1f}%)")
            print(f"  Available: {format_bytes(storage['available_bytes'])}")

        if data['recent_coredumps']:
            print(f"\nRecent Coredumps ({len(data['recent_coredumps'])} found):")
            for core in data['recent_coredumps'][:5]:
                size = format_bytes(core['size_bytes'])
                print(f"  {os.path.basename(core['path'])}: {size} ({core['mtime_str']})")

        print()

    # Print issues
    if data['issues']:
        for issue in data['issues']:
            if args.warn_only and issue['severity'] == 'INFO':
                continue
            print(f"[{issue['severity']}] {issue['message']}")
    elif not args.warn_only:
        print("No coredump configuration issues detected.")


def output_json(data, args):
    """Output results in JSON format."""
    print(json.dumps(data, indent=2, default=str))


def output_table(data, args):
    """Output results in table format."""
    if not args.warn_only:
        print("=" * 70)
        print("COREDUMP CONFIGURATION STATUS")
        print("=" * 70)
        print()

        print(f"{'Setting':<30} {'Value':<40}")
        print("-" * 70)
        print(f"{'Core Pattern':<30} {data['core_pattern'][:40]}")

        ulimit = data['ulimit']
        limit_str = str(ulimit['soft_limit'])
        if isinstance(ulimit['soft_limit'], int):
            limit_str = format_bytes(ulimit['soft_limit'])
        print(f"{'Core Size Limit (soft)':<30} {limit_str}")
        print(f"{'Core Uses PID':<30} {data['core_uses_pid']}")

        sd = data['systemd_coredump']
        print(f"{'systemd-coredump':<30} {'Enabled' if sd['enabled'] else 'Disabled'}")
        if sd['enabled'] and sd['storage']:
            print(f"{'  Storage Mode':<30} {sd['storage']}")

        print()

        if data['storage']:
            storage = data['storage']
            print(f"{'Storage Path':<30} {storage['path']}")
            print(f"{'Storage Used':<30} {format_bytes(storage['used_bytes'])} "
                  f"({storage['used_percent']:.1f}%)")
            print(f"{'Storage Available':<30} {format_bytes(storage['available_bytes'])}")
            print()

        if data['recent_coredumps']:
            print("RECENT COREDUMPS")
            print("-" * 70)
            print(f"{'File':<35} {'Size':<15} {'Date':<20}")
            print("-" * 70)
            for core in data['recent_coredumps'][:5]:
                name = os.path.basename(core['path'])[:34]
                size = format_bytes(core['size_bytes'])
                date = core['mtime_str'][:19]
                print(f"{name:<35} {size:<15} {date:<20}")
            print()

    if data['issues']:
        filtered = [i for i in data['issues']
                    if not (args.warn_only and i['severity'] == 'INFO')]
        if filtered:
            print("ISSUES DETECTED")
            print("=" * 70)
            for issue in filtered:
                print(f"[{issue['severity']}] {issue['message']}")
            print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor coredump configuration and storage',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check coredump configuration
  %(prog)s --format json        # JSON output for monitoring
  %(prog)s --verbose            # Show additional details
  %(prog)s --warn-only          # Only show warnings/errors

Common core patterns:
  core                          # Simple core file in cwd
  /var/crash/core.%%p.%%e       # With PID and executable name
  |/usr/lib/systemd/systemd-coredump ...  # systemd-coredump

Troubleshooting:
  - If cores not generating: check ulimit -c (should be 'unlimited')
  - For containerized apps: check Docker/K8s coredump settings
  - For systemd: use 'coredumpctl list' to view stored dumps

Exit codes:
  0 - Configuration is healthy
  1 - Issues detected
  2 - Usage error or system files not accessible
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
        help='Show additional details'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors'
    )

    parser.add_argument(
        '--storage-warn',
        type=int,
        default=75,
        metavar='PERCENT',
        help='Storage warning threshold (default: 75%%)'
    )

    parser.add_argument(
        '--storage-crit',
        type=int,
        default=90,
        metavar='PERCENT',
        help='Storage critical threshold (default: 90%%)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if not (0 <= args.storage_warn <= 100):
        print("Error: --storage-warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if not (0 <= args.storage_crit <= 100):
        print("Error: --storage-crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.storage_crit <= args.storage_warn:
        print("Error: --storage-crit must be greater than --storage-warn",
              file=sys.stderr)
        sys.exit(2)

    # Gather information
    core_pattern = read_core_pattern()
    core_uses_pid = read_core_uses_pid()
    systemd_info = check_systemd_coredump()
    ulimit_info = check_ulimit()
    abrt_info = check_abrt()

    # Determine coredump directory and check storage
    coredump_dir = get_coredump_directory(core_pattern, systemd_info)
    storage_info = get_directory_usage(coredump_dir)
    recent_coredumps = find_recent_coredumps(coredump_dir)

    # Analyze configuration
    issues = analyze_configuration(
        core_pattern, systemd_info, ulimit_info, storage_info
    )

    # Build result data
    data = {
        'core_pattern': core_pattern,
        'core_uses_pid': core_uses_pid,
        'core_pipe_limit': read_core_pipe_limit(),
        'ulimit': ulimit_info,
        'systemd_coredump': systemd_info,
        'abrt': abrt_info,
        'storage': storage_info,
        'recent_coredumps': recent_coredumps,
        'issues': issues
    }

    # Output results
    if args.format == 'json':
        output_json(data, args)
    elif args.format == 'table':
        output_table(data, args)
    else:
        output_plain(data, args)

    # Determine exit code
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
