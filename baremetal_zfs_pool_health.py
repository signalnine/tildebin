#!/usr/bin/env python3
"""
Monitor ZFS pool health and configuration.

This script monitors ZFS storage pools to detect health issues and potential
problems. Useful for:

- Detecting degraded or faulted pools before data loss
- Monitoring pool capacity and fragmentation
- Identifying slow or failing devices (high error counts)
- Tracking scrub status and age
- Detecting missing or removed devices

The script uses zpool and zfs commands to gather pool status and reports
issues based on configurable thresholds.

Exit codes:
    0 - All ZFS pools healthy, no issues detected
    1 - Warnings or errors found (degraded pools, high capacity, etc.)
    2 - Usage error, ZFS tools not installed, or no ZFS pools configured
"""

import argparse
import sys
import json
import subprocess
import re
from datetime import datetime, timedelta


def run_command(cmd):
    """Execute shell command and return result.

    Args:
        cmd: List of command arguments

    Returns:
        tuple: (return_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def check_zfs_available():
    """Check if ZFS tools are available.

    Returns:
        bool: True if zpool command is available
    """
    returncode, _, _ = run_command(['which', 'zpool'])
    return returncode == 0


def get_pool_list():
    """Get list of ZFS pools.

    Returns:
        list: List of pool names or None on error
    """
    cmd = ['zpool', 'list', '-H', '-o', 'name']
    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return None

    pools = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
    return pools


def get_pool_properties(pool_name):
    """Get pool properties using zpool list.

    Args:
        pool_name: Name of the ZFS pool

    Returns:
        dict: Pool properties or None on error
    """
    cmd = [
        'zpool', 'list', '-H', '-p',
        '-o', 'name,size,alloc,free,frag,cap,health,altroot',
        pool_name
    ]

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return None

    parts = stdout.strip().split('\t')
    if len(parts) < 7:
        return None

    return {
        'name': parts[0],
        'size_bytes': int(parts[1]) if parts[1].isdigit() else 0,
        'alloc_bytes': int(parts[2]) if parts[2].isdigit() else 0,
        'free_bytes': int(parts[3]) if parts[3].isdigit() else 0,
        'fragmentation': int(parts[4]) if parts[4].isdigit() else 0,
        'capacity': int(parts[5]) if parts[5].isdigit() else 0,
        'health': parts[6],
        'altroot': parts[7] if len(parts) > 7 and parts[7] != '-' else None
    }


def get_pool_status(pool_name):
    """Get detailed pool status including device state.

    Args:
        pool_name: Name of the ZFS pool

    Returns:
        dict: Pool status details or None on error
    """
    cmd = ['zpool', 'status', '-v', pool_name]
    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return None

    status = {
        'name': pool_name,
        'state': None,
        'scan': None,
        'scrub_age_days': None,
        'devices': [],
        'errors': None,
        'status_message': None
    }

    lines = stdout.split('\n')
    current_section = None

    for line in lines:
        line_stripped = line.strip()

        # Parse state
        if line_stripped.startswith('state:'):
            status['state'] = line_stripped.split(':', 1)[1].strip()

        # Parse status message
        elif line_stripped.startswith('status:'):
            status['status_message'] = line_stripped.split(':', 1)[1].strip()

        # Parse scan/scrub information
        elif line_stripped.startswith('scan:'):
            status['scan'] = line_stripped.split(':', 1)[1].strip()
            # Try to extract scrub age
            status['scrub_age_days'] = parse_scrub_age(status['scan'])

        # Parse errors
        elif line_stripped.startswith('errors:'):
            status['errors'] = line_stripped.split(':', 1)[1].strip()

        # Parse device lines (indented under config section)
        elif line.startswith('\t') and not line_stripped.startswith('NAME'):
            device = parse_device_line(line)
            if device:
                status['devices'].append(device)

    return status


def parse_scrub_age(scan_line):
    """Parse scrub age from scan status line.

    Args:
        scan_line: The scan status line from zpool status

    Returns:
        int or None: Days since last scrub
    """
    if not scan_line:
        return None

    # Look for "scrub repaired ... on Day Mon DD HH:MM:SS YYYY"
    # Or "scrub in progress since ..."
    if 'scrub in progress' in scan_line.lower():
        return 0  # Scrub currently running

    if 'none requested' in scan_line.lower():
        return None  # Never scrubbed

    # Try to parse date from common formats
    # Example: "scrub repaired 0B in 00:05:30 with 0 errors on Sun Jan 26 10:00:00 2025"
    date_patterns = [
        r'on\s+\w+\s+(\w+)\s+(\d+)\s+[\d:]+\s+(\d{4})',  # on Day Mon DD HH:MM:SS YYYY
        r'(\w+)\s+(\d+),?\s+(\d{4})',  # Mon DD, YYYY
    ]

    for pattern in date_patterns:
        match = re.search(pattern, scan_line)
        if match:
            try:
                month_str = match.group(1)
                day = int(match.group(2))
                year = int(match.group(3))

                # Convert month name to number
                months = {
                    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
                    'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
                    'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
                }
                month = months.get(month_str[:3])
                if month:
                    scrub_date = datetime(year, month, day)
                    age = (datetime.now() - scrub_date).days
                    return max(0, age)
            except (ValueError, KeyError):
                pass

    return None


def parse_device_line(line):
    """Parse a device line from zpool status output.

    Args:
        line: A line from the config section

    Returns:
        dict or None: Device information
    """
    # Device lines look like:
    #   sda       ONLINE       0     0     0
    #   mirror-0  ONLINE       0     0     0
    parts = line.split()

    if len(parts) < 2:
        return None

    # Skip header and pool-level lines
    if parts[0] in ['NAME', 'STATE', 'READ', 'WRITE', 'CKSUM']:
        return None

    device = {
        'name': parts[0],
        'state': parts[1] if len(parts) > 1 else 'UNKNOWN',
        'read_errors': int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
        'write_errors': int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0,
        'checksum_errors': int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
        'is_vdev': parts[0].startswith(('mirror', 'raidz', 'spare', 'log', 'cache'))
    }

    # Calculate total errors
    device['total_errors'] = (
        device['read_errors'] +
        device['write_errors'] +
        device['checksum_errors']
    )

    return device


def format_bytes(bytes_val):
    """Format bytes to human readable format.

    Args:
        bytes_val: Size in bytes

    Returns:
        str: Human readable size string
    """
    if bytes_val is None or bytes_val == 0:
        return 'N/A'
    if bytes_val >= 1024 ** 4:
        return f"{bytes_val / (1024 ** 4):.1f} TiB"
    elif bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.1f} GiB"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.1f} MiB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KiB"
    else:
        return f"{bytes_val} B"


def analyze_pools(pools_data, capacity_warn, capacity_crit, frag_warn,
                  scrub_warn_days, error_threshold):
    """Analyze pools for health issues.

    Args:
        pools_data: List of pool data dictionaries
        capacity_warn: Warning threshold for pool capacity
        capacity_crit: Critical threshold for pool capacity
        frag_warn: Warning threshold for fragmentation
        scrub_warn_days: Warning threshold for scrub age
        error_threshold: Threshold for device errors

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    for pool in pools_data:
        props = pool['properties']
        status = pool['status']
        pool_name = props['name']

        # Check pool health state
        if props['health'] not in ['ONLINE', 'DEGRADED']:
            severity = 'CRITICAL'
            issues.append({
                'severity': severity,
                'component': 'pool',
                'pool': pool_name,
                'metric': 'health',
                'value': props['health'],
                'message': f"Pool {pool_name} is {props['health']}"
            })
        elif props['health'] == 'DEGRADED':
            issues.append({
                'severity': 'CRITICAL',
                'component': 'pool',
                'pool': pool_name,
                'metric': 'health',
                'value': 'DEGRADED',
                'message': f"Pool {pool_name} is DEGRADED - redundancy compromised"
            })

        # Check capacity
        if props['capacity'] >= capacity_crit:
            issues.append({
                'severity': 'CRITICAL',
                'component': 'pool',
                'pool': pool_name,
                'metric': 'capacity',
                'value': props['capacity'],
                'threshold': capacity_crit,
                'message': f"Pool {pool_name} critically full: {props['capacity']}% used "
                           f"({format_bytes(props['free_bytes'])} free)"
            })
        elif props['capacity'] >= capacity_warn:
            issues.append({
                'severity': 'WARNING',
                'component': 'pool',
                'pool': pool_name,
                'metric': 'capacity',
                'value': props['capacity'],
                'threshold': capacity_warn,
                'message': f"Pool {pool_name} running low: {props['capacity']}% used "
                           f"({format_bytes(props['free_bytes'])} free)"
            })

        # Check fragmentation
        if props['fragmentation'] >= frag_warn:
            issues.append({
                'severity': 'WARNING',
                'component': 'pool',
                'pool': pool_name,
                'metric': 'fragmentation',
                'value': props['fragmentation'],
                'threshold': frag_warn,
                'message': f"Pool {pool_name} fragmentation high: {props['fragmentation']}%"
            })

        # Check scrub age
        if status and status['scrub_age_days'] is not None:
            if status['scrub_age_days'] >= scrub_warn_days:
                issues.append({
                    'severity': 'WARNING',
                    'component': 'pool',
                    'pool': pool_name,
                    'metric': 'scrub_age_days',
                    'value': status['scrub_age_days'],
                    'threshold': scrub_warn_days,
                    'message': f"Pool {pool_name} not scrubbed for "
                               f"{status['scrub_age_days']} days"
                })
        elif status and 'none requested' in (status['scan'] or '').lower():
            issues.append({
                'severity': 'WARNING',
                'component': 'pool',
                'pool': pool_name,
                'metric': 'scrub_age_days',
                'value': None,
                'message': f"Pool {pool_name} has never been scrubbed"
            })

        # Check device states and errors
        if status and status['devices']:
            for device in status['devices']:
                # Skip vdev entries (mirror-0, raidz1-0, etc.)
                if device['is_vdev']:
                    continue

                # Check device state
                if device['state'] not in ['ONLINE', 'AVAIL']:
                    severity = 'CRITICAL' if device['state'] in ['FAULTED', 'OFFLINE', 'REMOVED'] else 'WARNING'
                    issues.append({
                        'severity': severity,
                        'component': 'device',
                        'pool': pool_name,
                        'device': device['name'],
                        'metric': 'state',
                        'value': device['state'],
                        'message': f"Device {device['name']} in pool {pool_name} is {device['state']}"
                    })

                # Check device errors
                if device['total_errors'] >= error_threshold:
                    severity = 'CRITICAL' if device['total_errors'] >= error_threshold * 10 else 'WARNING'
                    issues.append({
                        'severity': severity,
                        'component': 'device',
                        'pool': pool_name,
                        'device': device['name'],
                        'metric': 'errors',
                        'value': device['total_errors'],
                        'threshold': error_threshold,
                        'message': f"Device {device['name']} in pool {pool_name} has errors: "
                                   f"read={device['read_errors']}, write={device['write_errors']}, "
                                   f"cksum={device['checksum_errors']}"
                    })

        # Check pool errors
        if status and status['errors'] and status['errors'].lower() != 'no known data errors':
            issues.append({
                'severity': 'CRITICAL',
                'component': 'pool',
                'pool': pool_name,
                'metric': 'data_errors',
                'value': status['errors'],
                'message': f"Pool {pool_name} has data errors: {status['errors']}"
            })

    return issues


def output_plain(pools_data, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only:
        print("ZFS Pool Health Summary")
        print(f"  Pools: {len(pools_data)}")
        print()

        if verbose:
            for pool in pools_data:
                props = pool['properties']
                status = pool['status']

                print(f"Pool: {props['name']}")
                print(f"  Health: {props['health']}")
                print(f"  Size: {format_bytes(props['size_bytes'])}")
                print(f"  Used: {format_bytes(props['alloc_bytes'])} ({props['capacity']}%)")
                print(f"  Free: {format_bytes(props['free_bytes'])}")
                print(f"  Fragmentation: {props['fragmentation']}%")

                if status:
                    if status['scan']:
                        print(f"  Scan: {status['scan']}")
                    if status['scrub_age_days'] is not None:
                        print(f"  Days since scrub: {status['scrub_age_days']}")
                    if status['errors']:
                        print(f"  Errors: {status['errors']}")

                    # List devices
                    devices = [d for d in status['devices'] if not d['is_vdev']]
                    if devices:
                        print("  Devices:")
                        for dev in devices:
                            errors = f" (errors: R={dev['read_errors']} W={dev['write_errors']} C={dev['checksum_errors']})" if dev['total_errors'] > 0 else ""
                            print(f"    {dev['name']}: {dev['state']}{errors}")
                print()

    # Print issues
    if issues:
        for issue in issues:
            severity = issue['severity']

            if warn_only and severity == 'INFO':
                continue

            prefix = {
                'CRITICAL': '[CRITICAL]',
                'WARNING': '[WARNING]',
                'INFO': '[INFO]'
            }.get(severity, '[UNKNOWN]')

            print(f"{prefix} {issue['message']}")
    elif not warn_only:
        print("No issues detected.")


def output_json(pools_data, issues, verbose):
    """Output results in JSON format."""
    result = {
        'summary': {
            'pools': len(pools_data)
        },
        'issues': issues
    }

    if verbose:
        result['pools'] = []
        for pool in pools_data:
            pool_info = {
                'properties': pool['properties'],
                'status': pool['status']
            }
            result['pools'].append(pool_info)

    print(json.dumps(result, indent=2, default=str))


def output_table(pools_data, issues, verbose, warn_only):
    """Output results in table format."""
    if not warn_only:
        print("=" * 80)
        print("ZFS POOL HEALTH SUMMARY")
        print("=" * 80)
        print(f"{'Pool':<15} {'Health':<12} {'Size':<10} {'Used':<10} {'Free':<10} {'Frag':<8}")
        print("-" * 80)

        for pool in pools_data:
            props = pool['properties']
            print(f"{props['name']:<15} "
                  f"{props['health']:<12} "
                  f"{format_bytes(props['size_bytes']):<10} "
                  f"{props['capacity']}%{'':<6} "
                  f"{format_bytes(props['free_bytes']):<10} "
                  f"{props['fragmentation']}%")

        print("=" * 80)
        print()

        if verbose:
            for pool in pools_data:
                status = pool['status']
                if status and status['devices']:
                    devices = [d for d in status['devices'] if not d['is_vdev']]
                    if devices:
                        print(f"DEVICES IN {pool['properties']['name']}")
                        print("-" * 80)
                        print(f"{'Device':<20} {'State':<12} {'Read Err':<10} {'Write Err':<10} {'Cksum Err':<10}")
                        print("-" * 80)
                        for dev in devices:
                            print(f"{dev['name']:<20} "
                                  f"{dev['state']:<12} "
                                  f"{dev['read_errors']:<10} "
                                  f"{dev['write_errors']:<10} "
                                  f"{dev['checksum_errors']:<10}")
                        print()

    # Print issues
    if issues:
        print("ISSUES DETECTED")
        print("=" * 80)
        for issue in issues:
            severity = issue['severity']

            if warn_only and severity == 'INFO':
                continue

            print(f"[{severity}] {issue['message']}")
        print()
    elif not warn_only:
        print("No issues detected.")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor ZFS pool health and configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check ZFS pool health with default thresholds
  %(prog)s --capacity-warn 70       # Warn when pools reach 70%% capacity
  %(prog)s --format json            # JSON output for monitoring tools
  %(prog)s --verbose                # Show detailed pool and device information
  %(prog)s --warn-only              # Only show warnings/errors

Thresholds:
  --capacity-warn: Pool capacity warning threshold (default: 80%%)
  --capacity-crit: Pool capacity critical threshold (default: 90%%)
  --frag-warn: Pool fragmentation warning threshold (default: 50%%)
  --scrub-warn: Days since last scrub warning threshold (default: 14)
  --error-threshold: Device error count threshold (default: 1)

Exit codes:
  0 - All ZFS pools healthy
  1 - Warnings or critical issues detected
  2 - Usage error or ZFS tools not available
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
        help='Show detailed pool and device information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--capacity-warn',
        type=int,
        default=80,
        metavar='PCT',
        help='Warning threshold for pool capacity (default: 80%%)'
    )

    parser.add_argument(
        '--capacity-crit',
        type=int,
        default=90,
        metavar='PCT',
        help='Critical threshold for pool capacity (default: 90%%)'
    )

    parser.add_argument(
        '--frag-warn',
        type=int,
        default=50,
        metavar='PCT',
        help='Warning threshold for fragmentation (default: 50%%)'
    )

    parser.add_argument(
        '--scrub-warn',
        type=int,
        default=14,
        metavar='DAYS',
        help='Warning threshold for days since last scrub (default: 14)'
    )

    parser.add_argument(
        '--error-threshold',
        type=int,
        default=1,
        metavar='COUNT',
        help='Device error count threshold (default: 1)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.capacity_warn < 0 or args.capacity_warn > 100:
        print("Error: capacity warning threshold must be between 0 and 100",
              file=sys.stderr)
        sys.exit(2)
    if args.capacity_crit < 0 or args.capacity_crit > 100:
        print("Error: capacity critical threshold must be between 0 and 100",
              file=sys.stderr)
        sys.exit(2)
    if args.capacity_warn >= args.capacity_crit:
        print("Error: capacity warning threshold must be less than critical",
              file=sys.stderr)
        sys.exit(2)
    if args.frag_warn < 0 or args.frag_warn > 100:
        print("Error: fragmentation warning threshold must be between 0 and 100",
              file=sys.stderr)
        sys.exit(2)

    # Check for ZFS tools
    if not check_zfs_available():
        print("Error: ZFS tools not found (zpool)", file=sys.stderr)
        print("Install with: sudo apt-get install zfsutils-linux", file=sys.stderr)
        sys.exit(2)

    # Get pool list
    pools = get_pool_list()

    if not pools:
        if args.format == 'json':
            print(json.dumps({'message': 'No ZFS pools found', 'issues': []}))
        else:
            print("No ZFS pools found on this system.")
        sys.exit(0)

    # Gather pool data
    pools_data = []
    for pool_name in pools:
        props = get_pool_properties(pool_name)
        status = get_pool_status(pool_name)

        if props:
            pools_data.append({
                'properties': props,
                'status': status
            })

    if not pools_data:
        if args.format == 'json':
            print(json.dumps({'message': 'Unable to read ZFS pool information', 'issues': []}))
        else:
            print("Error: Unable to read ZFS pool information.", file=sys.stderr)
        sys.exit(1)

    # Analyze for issues
    issues = analyze_pools(
        pools_data,
        args.capacity_warn,
        args.capacity_crit,
        args.frag_warn,
        args.scrub_warn,
        args.error_threshold
    )

    # Output results
    if args.format == 'json':
        output_json(pools_data, issues, args.verbose)
    elif args.format == 'table':
        output_table(pools_data, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(pools_data, issues, args.verbose, args.warn_only)

    # Determine exit code based on issues
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
