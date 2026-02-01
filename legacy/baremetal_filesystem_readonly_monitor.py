#!/usr/bin/env python3
"""
Monitor filesystems for read-only status and detect storage issues.

This script checks all mounted filesystems to detect those that have been
remounted read-only (often due to underlying storage errors, disk failures,
or I/O errors). It also checks recent kernel messages for related I/O errors.

Read-only filesystems are a common cause of application failures that can be
difficult to diagnose, especially in production environments with many hosts.

Exit codes:
    0 - All filesystems are read-write (healthy)
    1 - One or more filesystems are read-only or issues detected
    2 - Usage error or missing dependencies

Examples:
    # Check all filesystems
    baremetal_filesystem_readonly_monitor.py

    # JSON output for monitoring systems
    baremetal_filesystem_readonly_monitor.py --format json

    # Show only filesystems with issues
    baremetal_filesystem_readonly_monitor.py --warn-only

    # Verbose output with kernel messages
    baremetal_filesystem_readonly_monitor.py -v
"""

import argparse
import sys
import os
import subprocess
import json
from datetime import datetime


def run_command(cmd):
    """Execute shell command and return result"""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def get_mounted_filesystems():
    """Get list of mounted filesystems from /proc/mounts"""
    filesystems = []

    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    device = parts[0]
                    mount_point = parts[1]
                    fs_type = parts[2]
                    options = parts[3]

                    # Skip virtual/special filesystems
                    skip_types = ['proc', 'sysfs', 'devpts', 'tmpfs', 'devtmpfs',
                                  'cgroup', 'cgroup2', 'pstore', 'bpf', 'tracefs',
                                  'debugfs', 'hugetlbfs', 'mqueue', 'configfs',
                                  'fusectl', 'selinuxfs', 'securityfs', 'efivarfs',
                                  'autofs', 'overlay']

                    if fs_type in skip_types:
                        continue

                    # Parse mount options
                    opts = options.split(',')
                    is_readonly = 'ro' in opts

                    filesystems.append({
                        'device': device,
                        'mount_point': mount_point,
                        'fs_type': fs_type,
                        'options': options,
                        'readonly': is_readonly
                    })

    except IOError as e:
        print(f"Error reading /proc/mounts: {e}", file=sys.stderr)
        return []

    return filesystems


def check_kernel_messages():
    """Check dmesg for recent I/O errors"""
    io_errors = []

    # Check if we can read dmesg
    returncode, stdout, stderr = run_command(['dmesg', '-T'])

    if returncode != 0:
        # Try without -T flag (timestamps)
        returncode, stdout, stderr = run_command(['dmesg'])
        if returncode != 0:
            return []  # Can't read dmesg, not critical

    # Look for common I/O error patterns
    error_patterns = [
        'I/O error',
        'Buffer I/O error',
        'end_request: I/O error',
        'sd.*: FAILED Result',
        'remounting filesystem read-only',
        'Remounting filesystem read-only',
        'EXT4-fs error',
        'XFS.*: metadata I/O error',
        'btrfs.*: read-only filesystem',
    ]

    for line in stdout.split('\n')[-500:]:  # Check last 500 lines
        for pattern in error_patterns:
            if pattern.lower() in line.lower():
                io_errors.append(line.strip())
                break

    return io_errors


def test_write_access(mount_point):
    """Test if filesystem is actually writable"""
    if not os.access(mount_point, os.W_OK):
        return False, "No write permission"

    # Try to create a test file (if we have permission)
    test_file = os.path.join(mount_point, f'.write_test_{os.getpid()}')
    try:
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        return True, "Write successful"
    except (IOError, OSError) as e:
        if 'Read-only file system' in str(e):
            return False, "Read-only file system (write test failed)"
        return None, f"Write test inconclusive: {e}"


def output_plain(filesystems, kernel_errors, verbose, warn_only):
    """Plain text output"""
    has_issues = False

    for fs in filesystems:
        if warn_only and not fs['readonly'] and not fs.get('write_test_failed'):
            continue

        status = "RO" if fs['readonly'] else "RW"

        # Check write test results
        write_status = ""
        if fs.get('write_test_failed'):
            status = "RO"
            write_status = " (write test failed)"
            has_issues = True
        elif fs['readonly']:
            has_issues = True

        print(f"{fs['mount_point']:<30} {status:<5} {fs['fs_type']:<10} {fs['device']}{write_status}")

        if verbose and fs['readonly']:
            print(f"  Options: {fs['options']}")

    if verbose and kernel_errors:
        print("\nRecent kernel I/O errors:")
        for error in kernel_errors[-10:]:  # Show last 10
            print(f"  {error}")

    return has_issues


def output_json(filesystems, kernel_errors):
    """JSON output"""
    output = {
        'timestamp': datetime.now().isoformat(),
        'filesystems': filesystems,
        'kernel_errors': kernel_errors,
        'readonly_count': sum(1 for fs in filesystems if fs['readonly'] or fs.get('write_test_failed')),
        'total_count': len(filesystems)
    }
    print(json.dumps(output, indent=2))

    return output['readonly_count'] > 0


def output_table(filesystems, kernel_errors, verbose, warn_only):
    """Tabular output"""
    if warn_only:
        filesystems = [fs for fs in filesystems if fs['readonly'] or fs.get('write_test_failed')]

    if not filesystems:
        print("No filesystem issues detected")
        return False

    # Print header
    print(f"{'Mount Point':<30} {'Status':<8} {'Type':<10} {'Device':<30}")
    print("-" * 80)

    has_issues = False
    for fs in filesystems:
        status = "RO" if (fs['readonly'] or fs.get('write_test_failed')) else "RW"
        if status == "RO":
            has_issues = True
            status = "⚠ RO"

        print(f"{fs['mount_point']:<30} {status:<8} {fs['fs_type']:<10} {fs['device']:<30}")

    if verbose and kernel_errors:
        print(f"\nRecent I/O errors: {len(kernel_errors)}")
        for error in kernel_errors[-5:]:
            print(f"  {error}")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor filesystems for read-only status and storage issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Check all filesystems
  %(prog)s --format json      # JSON output for monitoring
  %(prog)s --warn-only        # Show only issues
  %(prog)s -v                 # Verbose with kernel errors

Exit codes:
  0 - All filesystems are read-write (healthy)
  1 - One or more filesystems are read-only or have issues
  2 - Usage error or missing dependency
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
        help='Show detailed information including kernel errors'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show filesystems with issues'
    )

    parser.add_argument(
        '--test-write',
        action='store_true',
        help='Perform actual write tests on filesystems (requires write permission)'
    )

    args = parser.parse_args()

    # Get mounted filesystems
    filesystems = get_mounted_filesystems()

    if not filesystems:
        print("Error: Could not read mounted filesystems", file=sys.stderr)
        sys.exit(2)

    # Optionally test write access
    if args.test_write:
        for fs in filesystems:
            # Only test on typical data filesystems
            if fs['mount_point'] in ['/', '/home', '/var', '/tmp', '/opt', '/usr/local']:
                writable, msg = test_write_access(fs['mount_point'])
                if writable is False:
                    fs['write_test_failed'] = True
                    fs['write_test_msg'] = msg

    # Check kernel messages for I/O errors
    kernel_errors = []
    if args.verbose or any(fs['readonly'] for fs in filesystems):
        kernel_errors = check_kernel_messages()

    # Output results
    if args.format == 'json':
        has_issues = output_json(filesystems, kernel_errors)
    elif args.format == 'table':
        has_issues = output_table(filesystems, kernel_errors, args.verbose, args.warn_only)
    else:  # plain
        has_issues = output_plain(filesystems, kernel_errors, args.verbose, args.warn_only)

    # Exit based on findings
    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
