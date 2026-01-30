#!/usr/bin/env python3
"""
Monitor XFS filesystem health and detect potential issues.

This script checks XFS filesystems for health indicators:
- Filesystem geometry and allocation group status
- Free space fragmentation levels
- Log device status and configuration
- Mount options affecting performance and reliability
- Realtime device status (if configured)
- Quota usage and limits
- Recent filesystem errors from kernel logs

In large-scale baremetal environments, XFS health monitoring is critical for:
- High-performance storage systems (default fs for RHEL/CentOS)
- Large file workloads (media, scientific data, databases)
- Detecting fragmentation before performance degrades
- Monitoring log device sizing issues
- Identifying filesystems needing xfs_repair

Exit codes:
    0 - All XFS filesystems are healthy
    1 - Warnings or errors detected
    2 - Usage error, missing dependency, or permission denied

Examples:
    # Check all XFS filesystems
    baremetal_xfs_health_monitor.py

    # JSON output for monitoring systems
    baremetal_xfs_health_monitor.py --format json

    # Check specific mount point
    baremetal_xfs_health_monitor.py --mount /data

    # Show only warnings
    baremetal_xfs_health_monitor.py --warn-only
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


def get_xfs_filesystems():
    """Get list of mounted XFS filesystems from /proc/mounts."""
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

                    if fs_type == 'xfs':
                        filesystems.append({
                            'device': device,
                            'mount_point': mount_point,
                            'options': options.split(',')
                        })
    except IOError as e:
        print(f"Error reading /proc/mounts: {e}", file=sys.stderr)
        return []

    return filesystems


def parse_xfs_info(output):
    """Parse xfs_info output for filesystem information."""
    info = {
        'meta_data': {},
        'data': {},
        'naming': {},
        'log': {},
        'realtime': {},
    }

    current_section = None

    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Detect section
        if line.startswith('meta-data='):
            current_section = 'meta_data'
        elif line.startswith('data'):
            current_section = 'data'
        elif line.startswith('naming'):
            current_section = 'naming'
        elif line.startswith('log'):
            current_section = 'log'
        elif line.startswith('realtime'):
            current_section = 'realtime'

        # Parse key=value pairs
        # Format: "meta-data=/dev/sda1          isize=512    agcount=4, agsize=65536 blks"
        pairs = re.findall(r'(\w+)=([^\s,]+)', line)
        for key, value in pairs:
            if current_section:
                # Convert numeric values
                if value.isdigit():
                    value = int(value)
                info[current_section][key] = value

        # Parse special formats like "agsize=65536 blks"
        blks_match = re.search(r'agsize=(\d+)\s+blks', line)
        if blks_match and current_section:
            info[current_section]['agsize_blocks'] = int(blks_match.group(1))

        # Parse sectsz and attr values
        sectsz_match = re.search(r'sectsz=(\d+)', line)
        if sectsz_match and current_section:
            info[current_section]['sectsz'] = int(sectsz_match.group(1))

        # Parse log version
        version_match = re.search(r'version=(\d+)', line)
        if version_match and current_section:
            info[current_section]['version'] = int(version_match.group(1))

        # Parse bsize
        bsize_match = re.search(r'bsize=(\d+)', line)
        if bsize_match and current_section:
            info[current_section]['bsize'] = int(bsize_match.group(1))

        # Parse blocks
        blocks_match = re.search(r'blocks=(\d+)', line)
        if blocks_match and current_section:
            info[current_section]['blocks'] = int(blocks_match.group(1))

        # Parse sunit and swidth (stripe unit/width)
        sunit_match = re.search(r'sunit=(\d+)', line)
        if sunit_match and current_section:
            info[current_section]['sunit'] = int(sunit_match.group(1))

        swidth_match = re.search(r'swidth=(\d+)', line)
        if swidth_match and current_section:
            info[current_section]['swidth'] = int(swidth_match.group(1))

    return info


def get_xfs_free_extents(mount_point):
    """Get free extent information using xfs_db (requires root)."""
    info = {
        'total_free_blocks': 0,
        'total_free_extents': 0,
        'avg_extent_size': 0,
        'fragmentation_score': 0,
    }

    # xfs_db requires unmounted filesystem or special access
    # Use xfs_spaceman for mounted filesystems if available
    if check_tool_available('xfs_spaceman'):
        returncode, stdout, stderr = run_command(
            ['xfs_spaceman', '-c', 'freesp -s', mount_point]
        )
        if returncode == 0 and stdout:
            # Parse freesp output
            lines = stdout.strip().split('\n')
            for line in lines:
                if 'total free' in line.lower():
                    match = re.search(r'(\d+)\s+extents', line)
                    if match:
                        info['total_free_extents'] = int(match.group(1))
                    match = re.search(r'(\d+)\s+blocks', line)
                    if match:
                        info['total_free_blocks'] = int(match.group(1))

            if info['total_free_extents'] > 0 and info['total_free_blocks'] > 0:
                info['avg_extent_size'] = info['total_free_blocks'] / info['total_free_extents']
                # Higher fragmentation = more extents for same space
                # Score: 0-100 where 100 is heavily fragmented
                # Ideal avg extent size is filesystem-dependent, use 1000 blocks as baseline
                if info['avg_extent_size'] < 10:
                    info['fragmentation_score'] = 90
                elif info['avg_extent_size'] < 100:
                    info['fragmentation_score'] = 60
                elif info['avg_extent_size'] < 1000:
                    info['fragmentation_score'] = 30
                else:
                    info['fragmentation_score'] = 10

    return info


def get_df_info(mount_point):
    """Get disk usage information from df."""
    info = {
        'size_bytes': 0,
        'used_bytes': 0,
        'available_bytes': 0,
        'use_percent': 0,
    }

    returncode, stdout, stderr = run_command(['df', '-B1', mount_point])
    if returncode == 0:
        lines = stdout.strip().split('\n')
        if len(lines) >= 2:
            # Parse df output (skip header)
            parts = lines[1].split()
            if len(parts) >= 5:
                try:
                    info['size_bytes'] = int(parts[1])
                    info['used_bytes'] = int(parts[2])
                    info['available_bytes'] = int(parts[3])
                    use_str = parts[4].rstrip('%')
                    info['use_percent'] = int(use_str) if use_str.isdigit() else 0
                except (ValueError, IndexError):
                    pass

    return info


def check_mount_options(options):
    """Analyze mount options for potential issues."""
    issues = []
    recommendations = []

    # Critical options to check
    if 'nobarrier' in options or 'barrier=0' in options:
        issues.append({
            'severity': 'WARNING',
            'type': 'mount_option',
            'message': "Filesystem mounted with barriers disabled (data loss risk on power failure)"
        })

    if 'noquota' in options:
        recommendations.append({
            'severity': 'INFO',
            'type': 'mount_option',
            'message': "Quotas disabled"
        })

    # Performance-related options
    if 'noatime' not in options and 'relatime' not in options:
        recommendations.append({
            'severity': 'INFO',
            'type': 'mount_option',
            'message': "Consider noatime/relatime for better performance"
        })

    # Check for discard (SSD TRIM)
    if 'discard' in options:
        recommendations.append({
            'severity': 'INFO',
            'type': 'mount_option',
            'message': "Online discard enabled (consider fstrim for better performance)"
        })

    # Check for inode options
    if 'inode64' in options:
        recommendations.append({
            'severity': 'INFO',
            'type': 'mount_option',
            'message': "64-bit inode numbers enabled (good for large filesystems)"
        })

    return issues, recommendations


def check_dmesg_for_xfs_errors(device):
    """Check dmesg for recent XFS-related errors."""
    errors = []

    returncode, stdout, stderr = run_command(['dmesg', '-T'])
    if returncode != 0:
        returncode, stdout, stderr = run_command(['dmesg'])
        if returncode != 0:
            return errors

    # Patterns that indicate XFS issues
    error_patterns = [
        (r'XFS.*error', 'XFS error'),
        (r'XFS.*corruption', 'Filesystem corruption'),
        (r'XFS.*shutdown', 'Filesystem shutdown'),
        (r'XFS.*I/O error', 'I/O error'),
        (r'XFS.*metadata.*error', 'Metadata error'),
        (r'XFS.*log.*error', 'Log error'),
        (r'XFS.*recovery', 'Log recovery performed'),
        (r'XFS.*unmount.*unclean', 'Unclean unmount'),
        (r'XFS.*force.*shutdown', 'Forced shutdown'),
    ]

    device_name = os.path.basename(device) if device.startswith('/dev/') else device

    for line in stdout.split('\n')[-1000:]:  # Check last 1000 lines
        for pattern, description in error_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Check if this is related to our device
                if device_name in line or 'XFS' in line:
                    errors.append({
                        'type': description,
                        'message': line.strip()
                    })
                    break

    return errors


def analyze_xfs_health(mount_point, xfs_info, df_info, mount_options, verbose=False):
    """Analyze XFS filesystem health and return issues found."""
    issues = []
    warnings = []

    # Check disk usage
    if df_info.get('use_percent', 0) >= 95:
        issues.append({
            'severity': 'CRITICAL',
            'type': 'space',
            'message': f"Filesystem is {df_info['use_percent']}% full"
        })
    elif df_info.get('use_percent', 0) >= 85:
        warnings.append({
            'severity': 'WARNING',
            'type': 'space',
            'message': f"Filesystem is {df_info['use_percent']}% full"
        })

    # Check log configuration
    log_info = xfs_info.get('log', {})
    data_info = xfs_info.get('data', {})

    if log_info.get('blocks') and data_info.get('blocks'):
        log_blocks = log_info.get('blocks', 0)
        data_blocks = data_info.get('blocks', 0)
        if data_blocks > 0:
            log_ratio = log_blocks / data_blocks
            # XFS log should typically be 0.1-0.5% of data for large filesystems
            # Minimum recommended is ~32MB (65536 blocks at 512 byte sectors)
            log_size_mb = (log_blocks * log_info.get('bsize', 512)) / (1024 * 1024)
            if log_size_mb < 32:
                warnings.append({
                    'severity': 'WARNING',
                    'type': 'log',
                    'message': f"Log size ({log_size_mb:.0f}MB) may be too small for optimal performance"
                })

    # Check for external log device
    if log_info.get('external'):
        warnings.append({
            'severity': 'INFO',
            'type': 'config',
            'message': "Using external log device"
        })

    # Check allocation group count
    if data_info.get('agcount'):
        agcount = data_info.get('agcount')
        # Typically 4-16 AGs is optimal, more can indicate suboptimal mkfs
        if agcount > 64:
            warnings.append({
                'severity': 'INFO',
                'type': 'geometry',
                'message': f"High allocation group count ({agcount}) may indicate suboptimal filesystem creation"
            })

    # Check sector size alignment
    meta_info = xfs_info.get('meta_data', {})
    if meta_info.get('sectsz') and meta_info.get('sectsz') < 4096:
        # Modern drives often have 4K physical sectors
        warnings.append({
            'severity': 'INFO',
            'type': 'geometry',
            'message': f"Sector size {meta_info['sectsz']} may not be optimal for modern storage"
        })

    # Check mount options
    opt_issues, opt_recommendations = check_mount_options(mount_options)
    issues.extend(opt_issues)
    warnings.extend(opt_recommendations)

    # Check realtime device
    rt_info = xfs_info.get('realtime', {})
    if rt_info.get('blocks') and rt_info.get('blocks') > 0:
        warnings.append({
            'severity': 'INFO',
            'type': 'config',
            'message': f"Realtime device configured with {rt_info['blocks']} blocks"
        })

    return issues, warnings


def get_xfs_health(fs_entry, verbose=False):
    """Get comprehensive health information for an XFS filesystem."""
    device = fs_entry['device']
    mount_point = fs_entry['mount_point']
    options = fs_entry['options']

    result = {
        'device': device,
        'mount_point': mount_point,
        'status': 'unknown',
        'issues': [],
        'warnings': [],
        'info': {},
        'dmesg_errors': []
    }

    # Get xfs_info
    returncode, stdout, stderr = run_command(['xfs_info', mount_point])

    if returncode != 0:
        if 'Permission denied' in stderr or 'Operation not permitted' in stderr:
            result['status'] = 'permission_denied'
            result['issues'].append({
                'severity': 'ERROR',
                'type': 'access',
                'message': f"Permission denied reading {mount_point}"
            })
        else:
            result['status'] = 'error'
            result['issues'].append({
                'severity': 'ERROR',
                'type': 'access',
                'message': f"Failed to get filesystem info: {stderr.strip()}"
            })
        return result

    # Parse xfs_info output
    xfs_info = parse_xfs_info(stdout)
    result['info']['xfs'] = xfs_info

    # Get disk usage
    df_info = get_df_info(mount_point)
    result['info']['usage'] = df_info

    # Get fragmentation info (if tools available)
    frag_info = get_xfs_free_extents(mount_point)
    if frag_info.get('total_free_extents'):
        result['info']['fragmentation'] = frag_info
        if frag_info.get('fragmentation_score', 0) > 70:
            result['warnings'].append({
                'severity': 'WARNING',
                'type': 'fragmentation',
                'message': f"High free space fragmentation (score: {frag_info['fragmentation_score']})"
            })

    # Analyze health
    issues, warnings = analyze_xfs_health(mount_point, xfs_info, df_info, options, verbose)
    result['issues'].extend(issues)
    result['warnings'].extend(warnings)

    # Check dmesg for errors
    if verbose:
        dmesg_errors = check_dmesg_for_xfs_errors(device)
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
        mount_point = result['mount_point']
        device = result['device']
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

        print(f"{status_indicator} {mount_point} ({device})")

        if status in ['critical', 'warning', 'error']:
            has_issues = True

        if verbose or status != 'healthy':
            usage = result.get('info', {}).get('usage', {})
            if usage.get('use_percent'):
                size_gb = usage.get('size_bytes', 0) / (1024**3)
                print(f"    Usage: {usage['use_percent']}% of {size_gb:.1f}GB")

            xfs = result.get('info', {}).get('xfs', {})
            if xfs.get('data', {}).get('agcount'):
                print(f"    Allocation groups: {xfs['data']['agcount']}")

            frag = result.get('info', {}).get('fragmentation', {})
            if frag.get('fragmentation_score'):
                print(f"    Fragmentation score: {frag['fragmentation_score']}")

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
                print(f"      - {error['type']}")

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

    print(json.dumps(output, indent=2, default=str))

    return output['summary']['critical'] > 0 or output['summary']['error'] > 0


def output_table(results, verbose, warn_only):
    """Tabular output format."""
    if warn_only:
        results = [r for r in results if r['status'] != 'healthy']

    if not results:
        print("No XFS health issues detected")
        return False

    print(f"{'Mount Point':<25} {'Device':<20} {'Status':<10} {'Usage':<8} {'AGs':<6}")
    print("-" * 75)

    has_issues = False
    for result in results:
        mount = result['mount_point'][:24]
        device = result['device'][:19]
        status = result['status'].upper()[:9]

        usage = result.get('info', {}).get('usage', {})
        use_pct = f"{usage.get('use_percent', 0)}%"

        xfs = result.get('info', {}).get('xfs', {})
        agcount = str(xfs.get('data', {}).get('agcount', 'N/A'))

        print(f"{mount:<25} {device:<20} {status:<10} {use_pct:<8} {agcount:<6}")

        if result['status'] in ['critical', 'warning', 'error']:
            has_issues = True

    print("-" * 75)

    # Print issues summary
    all_issues = []
    for result in results:
        for issue in result.get('issues', []):
            all_issues.append(f"{result['mount_point']}: {issue['message']}")

    if all_issues:
        print("\nIssues:")
        for issue in all_issues[:10]:  # Limit to 10
            print(f"  {issue}")

    return has_issues


def main():
    parser = argparse.ArgumentParser(
        description='Monitor XFS filesystem health',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Check all XFS filesystems
  %(prog)s --format json          # JSON output for monitoring
  %(prog)s --mount /data          # Check specific mount point
  %(prog)s --warn-only            # Only show issues
  %(prog)s -v                     # Verbose with kernel messages

What This Tool Detects:
  - Disk space usage approaching critical levels
  - Suboptimal log device configuration
  - Mount options that risk data integrity
  - Free space fragmentation levels
  - Allocation group configuration issues
  - Recent XFS errors in kernel logs
  - Filesystem geometry problems

Exit codes:
  0 - All XFS filesystems healthy
  1 - Warnings or errors detected
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
        '-m', '--mount',
        help='Check specific mount point instead of all XFS filesystems'
    )

    args = parser.parse_args()

    # Check for xfs_info
    if not check_tool_available('xfs_info'):
        print("Error: 'xfs_info' not found in PATH", file=sys.stderr)
        print("Install with: sudo apt-get install xfsprogs", file=sys.stderr)
        print("         or: sudo yum install xfsprogs", file=sys.stderr)
        sys.exit(2)

    # Get filesystems to check
    if args.mount:
        # Check if it's actually an XFS mount
        all_fs = get_xfs_filesystems()
        matching = [fs for fs in all_fs if fs['mount_point'] == args.mount]
        if not matching:
            print(f"Error: {args.mount} is not an XFS mount point", file=sys.stderr)
            sys.exit(2)
        filesystems = matching
    else:
        # Get all mounted XFS filesystems
        filesystems = get_xfs_filesystems()

        if not filesystems:
            if args.format == 'json':
                print(json.dumps({'timestamp': datetime.now().isoformat(), 'filesystems': [], 'summary': {'total': 0}}))
            else:
                print("No XFS filesystems found")
            sys.exit(0)

    # Check each filesystem
    results = []
    for fs in filesystems:
        result = get_xfs_health(fs, args.verbose)
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
