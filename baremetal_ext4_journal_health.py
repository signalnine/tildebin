#!/usr/bin/env python3
"""
Monitor ext4 filesystem journal health and detect potential issues.

This script checks ext4 filesystems for journal-related health indicators:
- Journal device status and configuration
- Journal transaction statistics
- Journal size vs filesystem size ratio
- Journal checkpoint and commit times
- Error flags in superblock that indicate journal recovery events
- Filesystem features affecting journal behavior

In large-scale baremetal environments, journal issues can indicate:
- Underlying storage problems
- Power loss recovery events
- Filesystem corruption risks
- Performance bottlenecks from undersized journals

Exit codes:
    0 - All ext4 filesystems have healthy journals
    1 - Journal warnings or errors detected
    2 - Usage error, missing dependency, or permission denied

Examples:
    # Check all ext4 filesystems
    baremetal_ext4_journal_health.py

    # JSON output for monitoring systems
    baremetal_ext4_journal_health.py --format json

    # Check specific device
    baremetal_ext4_journal_health.py --device /dev/sda1

    # Show only warnings
    baremetal_ext4_journal_health.py --warn-only
"""

import argparse
import sys
import os
import subprocess
import json
import re
from datetime import datetime


def run_command(cmd):
    """Execute shell command and return result."""
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd.split()[0]}"
    except Exception as e:
        return -1, "", str(e)


def check_tool_available(tool_name):
    """Check if a system tool is available."""
    try:
        result = subprocess.run(
            ['which', tool_name],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_ext4_filesystems():
    """Get list of mounted ext4 filesystems from /proc/mounts."""
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

                    if fs_type == 'ext4':
                        filesystems.append({
                            'device': device,
                            'mount_point': mount_point,
                            'options': options.split(',')
                        })
    except IOError as e:
        print(f"Error reading /proc/mounts: {e}", file=sys.stderr)
        return []

    return filesystems


def parse_dumpe2fs_output(output):
    """Parse dumpe2fs output for journal and filesystem information."""
    info = {
        'journal_uuid': None,
        'journal_device': None,
        'journal_size': None,
        'journal_length': None,
        'filesystem_size': None,
        'block_size': None,
        'mount_count': None,
        'max_mount_count': None,
        'last_checked': None,
        'check_interval': None,
        'filesystem_state': None,
        'error_behavior': None,
        'errors_count': None,
        'first_error_time': None,
        'last_error_time': None,
        'features': [],
        'journal_features': [],
        'journal_users': None,
    }

    for line in output.split('\n'):
        line = line.strip()

        # Journal information
        if line.startswith('Journal UUID:'):
            info['journal_uuid'] = line.split(':', 1)[1].strip()
        elif line.startswith('Journal device:'):
            info['journal_device'] = line.split(':', 1)[1].strip()
        elif line.startswith('Journal size:'):
            size_str = line.split(':', 1)[1].strip()
            # Parse size like "128M" or "64M"
            match = re.match(r'(\d+)([KMGTP]?)', size_str)
            if match:
                size = int(match.group(1))
                unit = match.group(2)
                multipliers = {'': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4, 'P': 1024**5}
                info['journal_size'] = size * multipliers.get(unit, 1)
        elif line.startswith('Journal length:'):
            try:
                info['journal_length'] = int(line.split(':', 1)[1].strip())
            except ValueError:
                pass

        # Filesystem information
        elif line.startswith('Block count:'):
            try:
                info['filesystem_blocks'] = int(line.split(':', 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith('Block size:'):
            try:
                info['block_size'] = int(line.split(':', 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith('Mount count:'):
            try:
                info['mount_count'] = int(line.split(':', 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith('Maximum mount count:'):
            try:
                max_count = line.split(':', 1)[1].strip()
                info['max_mount_count'] = int(max_count) if max_count != '-1' else None
            except ValueError:
                pass

        # State and errors
        elif line.startswith('Filesystem state:'):
            info['filesystem_state'] = line.split(':', 1)[1].strip()
        elif line.startswith('Errors behavior:'):
            info['error_behavior'] = line.split(':', 1)[1].strip()
        elif line.startswith('FS Error count:'):
            try:
                info['errors_count'] = int(line.split(':', 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith('First error time:'):
            info['first_error_time'] = line.split(':', 1)[1].strip()
        elif line.startswith('Last error time:'):
            info['last_error_time'] = line.split(':', 1)[1].strip()

        # Features
        elif line.startswith('Filesystem features:'):
            features_str = line.split(':', 1)[1].strip()
            info['features'] = features_str.split()
        elif line.startswith('Journal features:'):
            features_str = line.split(':', 1)[1].strip()
            info['journal_features'] = features_str.split()
        elif line.startswith('Journal users:'):
            info['journal_users'] = line.split(':', 1)[1].strip()

        # Timing information
        elif line.startswith('Last checked:'):
            info['last_checked'] = line.split(':', 1)[1].strip()
        elif line.startswith('Check interval:'):
            interval_str = line.split(':', 1)[1].strip()
            # Parse interval like "0 (<none>)" or "15552000 (6 months)"
            match = re.match(r'(\d+)', interval_str)
            if match:
                info['check_interval'] = int(match.group(1))

    # Calculate filesystem size if we have the data
    if info.get('filesystem_blocks') and info.get('block_size'):
        info['filesystem_size'] = info['filesystem_blocks'] * info['block_size']

    return info


def analyze_journal_health(device, info):
    """Analyze journal health and return issues found."""
    issues = []
    warnings = []

    # Check filesystem state
    if info.get('filesystem_state'):
        state = info['filesystem_state'].lower()
        if 'error' in state:
            issues.append({
                'severity': 'CRITICAL',
                'type': 'state',
                'message': f"Filesystem in error state: {info['filesystem_state']}"
            })
        elif state != 'clean':
            warnings.append({
                'severity': 'WARNING',
                'type': 'state',
                'message': f"Filesystem state is not clean: {info['filesystem_state']}"
            })

    # Check for recorded errors
    if info.get('errors_count') and info['errors_count'] > 0:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'errors',
            'message': f"Filesystem has {info['errors_count']} recorded error(s)"
        })
        if info.get('last_error_time'):
            issues.append({
                'severity': 'INFO',
                'type': 'errors',
                'message': f"Last error occurred: {info['last_error_time']}"
            })

    # Check journal size ratio
    if info.get('journal_size') and info.get('filesystem_size'):
        ratio = info['journal_size'] / info['filesystem_size']
        # Journal should typically be 0.1-1% of filesystem size
        # Very small journals can cause performance issues
        if ratio < 0.0001:  # Less than 0.01%
            warnings.append({
                'severity': 'WARNING',
                'type': 'size',
                'message': f"Journal size may be too small ({info['journal_size'] / (1024*1024):.1f}MB for {info['filesystem_size'] / (1024**3):.1f}GB filesystem)"
            })

    # Check journal features
    if info.get('journal_features'):
        if 'journal_checksum' not in info['journal_features'] and 'journal_checksum_v3' not in ' '.join(info['journal_features']):
            # Check for v3 checksums in features
            has_checksum = any('checksum' in f.lower() for f in info['journal_features'])
            if not has_checksum:
                warnings.append({
                    'severity': 'INFO',
                    'type': 'features',
                    'message': "Journal checksums not enabled (recommended for data integrity)"
                })

    # Check filesystem features related to journaling
    if info.get('features'):
        if 'has_journal' not in info['features']:
            issues.append({
                'severity': 'CRITICAL',
                'type': 'features',
                'message': "Filesystem does not have journaling enabled"
            })

        # Check for metadata_csum which provides additional protection
        if 'metadata_csum' not in info['features']:
            # Not critical, but worth noting for new filesystems
            pass  # Don't warn, as many older filesystems don't have this

    # Check mount count vs max mount count
    if info.get('mount_count') and info.get('max_mount_count'):
        if info['mount_count'] >= info['max_mount_count']:
            warnings.append({
                'severity': 'WARNING',
                'type': 'fsck',
                'message': f"Filesystem has reached max mount count ({info['mount_count']}/{info['max_mount_count']}), fsck recommended"
            })

    # Check for external journal device
    if info.get('journal_device') and info['journal_device'] != '<none>':
        # External journal - worth noting
        warnings.append({
            'severity': 'INFO',
            'type': 'config',
            'message': f"Using external journal device: {info['journal_device']}"
        })

    return issues, warnings


def check_journal_via_sysfs(device):
    """Check journal status via sysfs if available."""
    # Extract device name (e.g., sda1 from /dev/sda1)
    device_name = os.path.basename(device)

    sysfs_info = {}

    # Check for journal commit interval (if available)
    commit_interval_path = f"/sys/fs/ext4/{device_name}/commit_interval"
    if os.path.exists(commit_interval_path):
        try:
            with open(commit_interval_path, 'r') as f:
                sysfs_info['commit_interval'] = int(f.read().strip())
        except (IOError, ValueError):
            pass

    # Check for errors behavior
    errors_path = f"/sys/fs/ext4/{device_name}/errors_count"
    if os.path.exists(errors_path):
        try:
            with open(errors_path, 'r') as f:
                sysfs_info['errors_count'] = int(f.read().strip())
        except (IOError, ValueError):
            pass

    # Check for warning count
    warning_path = f"/sys/fs/ext4/{device_name}/warning_count"
    if os.path.exists(warning_path):
        try:
            with open(warning_path, 'r') as f:
                sysfs_info['warning_count'] = int(f.read().strip())
        except (IOError, ValueError):
            pass

    return sysfs_info


def check_dmesg_for_journal_errors(device):
    """Check dmesg for recent journal-related errors."""
    errors = []

    returncode, stdout, stderr = run_command(['dmesg', '-T'])
    if returncode != 0:
        returncode, stdout, stderr = run_command(['dmesg'])
        if returncode != 0:
            return errors

    # Patterns that indicate journal issues
    error_patterns = [
        (r'EXT4-fs.*journal.*error', 'Journal error'),
        (r'EXT4-fs.*Remounting filesystem read-only', 'Filesystem remounted read-only'),
        (r'JBD2:.*I/O error', 'Journal I/O error'),
        (r'JBD2:.*detected aborted journal', 'Aborted journal detected'),
        (r'EXT4-fs.*recovery complete', 'Journal recovery performed'),
        (r'EXT4-fs.*mounted filesystem.*without journal', 'Mounted without journal'),
        (r'EXT4-fs.*failed to load journal', 'Failed to load journal'),
    ]

    device_name = os.path.basename(device)

    for line in stdout.split('\n')[-1000:]:  # Check last 1000 lines
        for pattern, description in error_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Check if this is related to our device
                if device_name in line or device in line or 'EXT4-fs' in line:
                    errors.append({
                        'type': description,
                        'message': line.strip()
                    })
                    break

    return errors


def get_journal_info(device, verbose=False):
    """Get comprehensive journal information for an ext4 device."""
    result = {
        'device': device,
        'status': 'unknown',
        'issues': [],
        'warnings': [],
        'info': {},
        'dmesg_errors': []
    }

    # Run dumpe2fs to get filesystem info
    returncode, stdout, stderr = run_command(['dumpe2fs', '-h', device])

    if returncode != 0:
        if 'Permission denied' in stderr or 'Operation not permitted' in stderr:
            result['status'] = 'permission_denied'
            result['issues'].append({
                'severity': 'ERROR',
                'type': 'access',
                'message': f"Permission denied reading {device} (run as root)"
            })
        else:
            result['status'] = 'error'
            result['issues'].append({
                'severity': 'ERROR',
                'type': 'access',
                'message': f"Failed to read filesystem info: {stderr.strip()}"
            })
        return result

    # Parse dumpe2fs output
    info = parse_dumpe2fs_output(stdout)
    result['info'] = info

    # Analyze journal health
    issues, warnings = analyze_journal_health(device, info)
    result['issues'].extend(issues)
    result['warnings'].extend(warnings)

    # Check sysfs for additional info
    sysfs_info = check_journal_via_sysfs(device)
    if sysfs_info:
        result['info']['sysfs'] = sysfs_info
        if sysfs_info.get('errors_count', 0) > 0:
            result['issues'].append({
                'severity': 'WARNING',
                'type': 'sysfs',
                'message': f"Sysfs reports {sysfs_info['errors_count']} error(s)"
            })
        if sysfs_info.get('warning_count', 0) > 0:
            result['warnings'].append({
                'severity': 'INFO',
                'type': 'sysfs',
                'message': f"Sysfs reports {sysfs_info['warning_count']} warning(s)"
            })

    # Check dmesg for journal errors
    if verbose:
        dmesg_errors = check_dmesg_for_journal_errors(device)
        result['dmesg_errors'] = dmesg_errors
        for error in dmesg_errors:
            result['issues'].append({
                'severity': 'WARNING',
                'type': 'dmesg',
                'message': f"Kernel message: {error['type']}"
            })

    # Determine overall status
    if any(i['severity'] == 'CRITICAL' for i in result['issues']):
        result['status'] = 'critical'
    elif any(i['severity'] in ['ERROR', 'WARNING'] for i in result['issues']):
        result['status'] = 'warning'
    elif result['issues'] or result['warnings']:
        result['status'] = 'info'
    else:
        result['status'] = 'healthy'

    return result


def output_plain(results, verbose, warn_only):
    """Plain text output format."""
    has_issues = False

    for result in results:
        device = result['device']
        mount_point = result.get('mount_point', 'N/A')
        status = result['status']

        # Skip healthy filesystems in warn-only mode
        if warn_only and status == 'healthy':
            continue

        status_indicator = {
            'healthy': '[OK]',
            'info': '[INFO]',
            'warning': '[WARN]',
            'critical': '[CRIT]',
            'error': '[ERR]',
            'permission_denied': '[PERM]',
            'unknown': '[??]'
        }.get(status, '[??]')

        print(f"{status_indicator} {device} ({mount_point})")

        if status in ['critical', 'warning', 'error']:
            has_issues = True

        if verbose or status != 'healthy':
            info = result.get('info', {})

            if info.get('filesystem_state'):
                print(f"    State: {info['filesystem_state']}")

            if info.get('journal_size'):
                journal_mb = info['journal_size'] / (1024 * 1024)
                print(f"    Journal size: {journal_mb:.1f}MB")

            if info.get('errors_count'):
                print(f"    Error count: {info['errors_count']}")

            if info.get('mount_count') and info.get('max_mount_count'):
                print(f"    Mount count: {info['mount_count']}/{info['max_mount_count']}")

        # Print issues and warnings
        for issue in result.get('issues', []):
            if warn_only and issue['severity'] == 'INFO':
                continue
            print(f"    [{issue['severity']}] {issue['message']}")

        for warning in result.get('warnings', []):
            if warn_only and warning['severity'] == 'INFO':
                continue
            print(f"    [{warning['severity']}] {warning['message']}")

        if verbose and result.get('dmesg_errors'):
            print("    Recent kernel messages:")
            for error in result['dmesg_errors'][:5]:
                print(f"      - {error['type']}: {error['message'][:60]}...")

    return has_issues


def output_json(results):
    """JSON output format."""
    output = {
        'timestamp': datetime.now().isoformat(),
        'filesystems': results,
        'summary': {
            'total': len(results),
            'healthy': sum(1 for r in results if r['status'] == 'healthy'),
            'warning': sum(1 for r in results if r['status'] in ['warning', 'info']),
            'critical': sum(1 for r in results if r['status'] == 'critical'),
            'error': sum(1 for r in results if r['status'] in ['error', 'permission_denied'])
        }
    }

    # Simplify info for JSON output (remove None values)
    for fs in output['filesystems']:
        if 'info' in fs:
            fs['info'] = {k: v for k, v in fs['info'].items() if v is not None}

    print(json.dumps(output, indent=2, default=str))

    return output['summary']['critical'] > 0 or output['summary']['error'] > 0


def output_table(results, verbose, warn_only):
    """Tabular output format."""
    if warn_only:
        results = [r for r in results if r['status'] != 'healthy']

    if not results:
        print("No ext4 journal issues detected")
        return False

    print(f"{'Device':<20} {'Mount':<20} {'Status':<10} {'Journal':<12} {'State':<15}")
    print("-" * 80)

    has_issues = False
    for result in results:
        device = result['device'][:19]
        mount = result.get('mount_point', 'N/A')[:19]
        status = result['status'].upper()[:9]

        info = result.get('info', {})
        journal_size = 'N/A'
        if info.get('journal_size'):
            journal_size = f"{info['journal_size'] / (1024*1024):.0f}MB"

        state = info.get('filesystem_state', 'N/A')[:14]

        print(f"{device:<20} {mount:<20} {status:<10} {journal_size:<12} {state:<15}")

        if result['status'] in ['critical', 'warning', 'error']:
            has_issues = True

    print("-" * 80)

    # Print issues summary
    all_issues = []
    for result in results:
        for issue in result.get('issues', []):
            all_issues.append(f"{result['device']}: {issue['message']}")

    if all_issues:
        print("\nIssues:")
        for issue in all_issues[:10]:  # Limit to 10
            print(f"  {issue}")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor ext4 filesystem journal health',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Check all ext4 filesystems
  %(prog)s --format json          # JSON output for monitoring
  %(prog)s --device /dev/sda1     # Check specific device
  %(prog)s --warn-only            # Only show issues
  %(prog)s -v                     # Verbose with kernel messages

What This Tool Detects:
  - Filesystem error states requiring fsck
  - Journal errors recorded in superblock
  - Undersized journals causing performance issues
  - Missing journal checksum protection
  - Mount count approaching fsck threshold
  - Recent journal recovery events in dmesg

Exit codes:
  0 - All ext4 journals healthy
  1 - Journal warnings or errors detected
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
        help='Show detailed information including kernel messages'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show filesystems with issues'
    )

    parser.add_argument(
        '-d', '--device',
        help='Check specific device instead of all ext4 filesystems'
    )

    args = parser.parse_args()

    # Check for dumpe2fs
    if not check_tool_available('dumpe2fs'):
        print("Error: 'dumpe2fs' not found in PATH", file=sys.stderr)
        print("Install with: sudo apt-get install e2fsprogs", file=sys.stderr)
        sys.exit(2)

    # Get filesystems to check
    if args.device:
        # Check specific device
        filesystems = [{'device': args.device, 'mount_point': 'specified', 'options': []}]
    else:
        # Get all mounted ext4 filesystems
        filesystems = get_ext4_filesystems()

        if not filesystems:
            if args.format == 'json':
                print(json.dumps({'timestamp': datetime.now().isoformat(), 'filesystems': [], 'summary': {'total': 0}}))
            else:
                print("No ext4 filesystems found")
            sys.exit(0)

    # Check each filesystem
    results = []
    for fs in filesystems:
        result = get_journal_info(fs['device'], args.verbose)
        result['mount_point'] = fs['mount_point']
        result['mount_options'] = fs['options']
        results.append(result)

    # Output results
    if args.format == 'json':
        has_issues = output_json(results)
    elif args.format == 'table':
        has_issues = output_table(results, args.verbose, args.warn_only)
    else:  # plain
        has_issues = output_plain(results, args.verbose, args.warn_only)

    # Determine exit code
    has_critical = any(r['status'] == 'critical' for r in results)
    has_error = any(r['status'] in ['error', 'permission_denied'] for r in results)
    has_warning = any(r['status'] == 'warning' for r in results)

    if has_critical or has_error or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
