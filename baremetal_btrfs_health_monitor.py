#!/usr/bin/env python3
"""
Monitor BTRFS filesystem health and configuration.

This script monitors BTRFS filesystems to detect health issues and potential
problems. Useful for:

- Detecting device errors or missing devices in BTRFS arrays
- Monitoring filesystem usage and metadata space
- Tracking scrub status and age
- Identifying balance operation status
- Detecting RAID degradation

The script uses btrfs commands to gather filesystem status and reports
issues based on configurable thresholds.

Exit codes:
    0 - All BTRFS filesystems healthy, no issues detected
    1 - Warnings or errors found (degraded arrays, high usage, etc.)
    2 - Usage error, BTRFS tools not installed, or no BTRFS filesystems found
"""

import argparse
import sys
import json
import subprocess
import re
from datetime import datetime


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


def check_btrfs_available():
    """Check if BTRFS tools are available.

    Returns:
        bool: True if btrfs command is available
    """
    returncode, _, _ = run_command(['which', 'btrfs'])
    return returncode == 0


def get_btrfs_filesystems():
    """Get list of mounted BTRFS filesystems.

    Returns:
        list: List of mount point dictionaries or None on error
    """
    returncode, stdout, stderr = run_command(['findmnt', '-t', 'btrfs', '-n', '-o', 'TARGET,SOURCE,OPTIONS'])

    if returncode != 0:
        return None

    filesystems = []
    seen_devices = set()

    for line in stdout.strip().split('\n'):
        if not line.strip():
            continue

        parts = line.split(None, 2)
        if len(parts) < 2:
            continue

        mount_point = parts[0]
        source = parts[1]
        options = parts[2] if len(parts) > 2 else ""

        # Extract the base device (handle subvolumes)
        # Source might be like /dev/sda1[/subvol]
        base_device = source.split('[')[0]

        # Skip if we've already processed this device (subvolume mounts)
        if base_device in seen_devices:
            continue
        seen_devices.add(base_device)

        filesystems.append({
            'mount_point': mount_point,
            'device': base_device,
            'options': options
        })

    return filesystems


def get_filesystem_usage(mount_point):
    """Get BTRFS filesystem usage information.

    Args:
        mount_point: Path to the mounted filesystem

    Returns:
        dict: Usage information or None on error
    """
    cmd = ['btrfs', 'filesystem', 'usage', '-b', mount_point]
    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return None

    usage = {
        'total_bytes': 0,
        'used_bytes': 0,
        'free_bytes': 0,
        'free_estimated_bytes': 0,
        'data_ratio': 1.0,
        'metadata_ratio': 1.0,
        'data_used_bytes': 0,
        'metadata_used_bytes': 0,
        'system_used_bytes': 0,
        'unallocated_bytes': 0
    }

    for line in stdout.split('\n'):
        line = line.strip()

        # Parse overall usage
        if line.startswith('Device size:'):
            match = re.search(r'(\d+)', line)
            if match:
                usage['total_bytes'] = int(match.group(1))

        elif line.startswith('Used:'):
            match = re.search(r'(\d+)', line)
            if match:
                usage['used_bytes'] = int(match.group(1))

        elif line.startswith('Free (estimated):'):
            match = re.search(r'(\d+)', line)
            if match:
                usage['free_estimated_bytes'] = int(match.group(1))

        elif line.startswith('Free (statfs'):
            match = re.search(r'(\d+)', line)
            if match:
                usage['free_bytes'] = int(match.group(1))

        elif line.startswith('Data ratio:'):
            match = re.search(r'([\d.]+)', line)
            if match:
                usage['data_ratio'] = float(match.group(1))

        elif line.startswith('Metadata ratio:'):
            match = re.search(r'([\d.]+)', line)
            if match:
                usage['metadata_ratio'] = float(match.group(1))

        elif line.startswith('Data,'):
            match = re.search(r'used=(\d+)', line)
            if match:
                usage['data_used_bytes'] = int(match.group(1))

        elif line.startswith('Metadata,'):
            match = re.search(r'used=(\d+)', line)
            if match:
                usage['metadata_used_bytes'] = int(match.group(1))

        elif line.startswith('System,'):
            match = re.search(r'used=(\d+)', line)
            if match:
                usage['system_used_bytes'] = int(match.group(1))

        elif line.startswith('Unallocated:'):
            match = re.search(r'(\d+)', line)
            if match:
                usage['unallocated_bytes'] = int(match.group(1))

    # Calculate usage percentage
    if usage['total_bytes'] > 0:
        usage['used_percent'] = (usage['used_bytes'] / usage['total_bytes']) * 100
    else:
        usage['used_percent'] = 0

    return usage


def get_device_stats(mount_point):
    """Get BTRFS device statistics (error counts).

    Args:
        mount_point: Path to the mounted filesystem

    Returns:
        list: List of device stat dictionaries or None on error
    """
    cmd = ['btrfs', 'device', 'stats', mount_point]
    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return None

    devices = {}
    current_device = None

    for line in stdout.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Parse device path from stat lines like:
        # [/dev/sda1].write_io_errs    0
        match = re.match(r'\[([^\]]+)\]\.(\w+)\s+(\d+)', line)
        if match:
            device = match.group(1)
            stat_name = match.group(2)
            stat_value = int(match.group(3))

            if device not in devices:
                devices[device] = {
                    'device': device,
                    'write_io_errs': 0,
                    'read_io_errs': 0,
                    'flush_io_errs': 0,
                    'corruption_errs': 0,
                    'generation_errs': 0,
                    'total_errors': 0
                }

            devices[device][stat_name] = stat_value

    # Calculate total errors for each device
    for device in devices.values():
        device['total_errors'] = (
            device['write_io_errs'] +
            device['read_io_errs'] +
            device['flush_io_errs'] +
            device['corruption_errs'] +
            device['generation_errs']
        )

    return list(devices.values())


def get_scrub_status(mount_point):
    """Get BTRFS scrub status for a filesystem.

    Args:
        mount_point: Path to the mounted filesystem

    Returns:
        dict: Scrub status information or None on error
    """
    cmd = ['btrfs', 'scrub', 'status', mount_point]
    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return None

    status = {
        'running': False,
        'last_scrub': None,
        'scrub_age_days': None,
        'errors_found': 0,
        'errors_corrected': 0,
        'errors_uncorrectable': 0,
        'bytes_scrubbed': 0
    }

    for line in stdout.split('\n'):
        line = line.strip()

        if 'Status:' in line:
            status['running'] = 'running' in line.lower()

        elif line.startswith('Scrub started:') or line.startswith('Scrub finished:'):
            # Parse date like "Scrub started:    Sun Jan 26 10:00:00 2025"
            match = re.search(r':\s+(.+)$', line)
            if match:
                date_str = match.group(1).strip()
                status['last_scrub'] = parse_scrub_date(date_str)
                if status['last_scrub']:
                    age = (datetime.now() - status['last_scrub']).days
                    status['scrub_age_days'] = max(0, age)

        elif 'Error summary:' in line:
            # Parse error counts
            # Example: "Error summary:    csum=0 super=0 verify_errors=0 read_errors=0"
            for match in re.finditer(r'(\w+)=(\d+)', line):
                error_type = match.group(1)
                count = int(match.group(2))
                if error_type in ['csum', 'super', 'verify_errors', 'read_errors']:
                    status['errors_found'] += count

        elif 'Total to scrub:' in line or 'data_bytes_scrubbed:' in line:
            match = re.search(r'(\d+)', line)
            if match:
                status['bytes_scrubbed'] = int(match.group(1))

        elif 'corrected_errors' in line:
            match = re.search(r'(\d+)', line)
            if match:
                status['errors_corrected'] = int(match.group(1))

        elif 'uncorrectable_errors' in line:
            match = re.search(r'(\d+)', line)
            if match:
                status['errors_uncorrectable'] = int(match.group(1))

    # Handle "no stats available" case
    if 'no stats available' in stdout.lower():
        status['last_scrub'] = None
        status['scrub_age_days'] = None

    return status


def parse_scrub_date(date_str):
    """Parse a date string from BTRFS scrub output.

    Args:
        date_str: Date string like "Sun Jan 26 10:00:00 2025"

    Returns:
        datetime or None: Parsed datetime
    """
    formats = [
        '%a %b %d %H:%M:%S %Y',  # Sun Jan 26 10:00:00 2025
        '%Y-%m-%d %H:%M:%S',     # 2025-01-26 10:00:00
    ]

    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    return None


def get_filesystem_info(mount_point):
    """Get BTRFS filesystem information (label, UUID, devices).

    Args:
        mount_point: Path to the mounted filesystem

    Returns:
        dict: Filesystem information or None on error
    """
    cmd = ['btrfs', 'filesystem', 'show', mount_point]
    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return None

    info = {
        'label': None,
        'uuid': None,
        'total_devices': 0,
        'devices': [],
        'missing_devices': 0
    }

    for line in stdout.split('\n'):
        line = line.strip()

        # Parse label and UUID from first line
        # Label: 'mylabel'  uuid: 12345678-...
        if 'Label:' in line:
            label_match = re.search(r"Label:\s*'?([^']*)'?", line)
            if label_match:
                label = label_match.group(1).strip()
                if label and label != 'none':
                    info['label'] = label

            uuid_match = re.search(r'uuid:\s*([0-9a-f-]+)', line, re.I)
            if uuid_match:
                info['uuid'] = uuid_match.group(1)

        # Parse total devices
        elif 'Total devices' in line:
            match = re.search(r'Total devices\s+(\d+)', line)
            if match:
                info['total_devices'] = int(match.group(1))

        # Parse device lines
        # devid    1 size 100.00GiB used 50.00GiB path /dev/sda1
        elif 'devid' in line:
            dev_match = re.search(r'devid\s+(\d+)\s+size\s+(\S+)\s+used\s+(\S+)\s+path\s+(\S+)', line)
            if dev_match:
                info['devices'].append({
                    'devid': int(dev_match.group(1)),
                    'size': dev_match.group(2),
                    'used': dev_match.group(3),
                    'path': dev_match.group(4)
                })

            # Check for missing devices
            if '*** Some devices missing' in line or 'missing' in line.lower():
                info['missing_devices'] += 1

    return info


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


def analyze_filesystems(filesystems_data, capacity_warn, capacity_crit,
                        scrub_warn_days, error_threshold):
    """Analyze filesystems for health issues.

    Args:
        filesystems_data: List of filesystem data dictionaries
        capacity_warn: Warning threshold for capacity percentage
        capacity_crit: Critical threshold for capacity percentage
        scrub_warn_days: Warning threshold for scrub age in days
        error_threshold: Threshold for device errors

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    for fs in filesystems_data:
        mount_point = fs['mount_point']
        usage = fs.get('usage', {})
        scrub = fs.get('scrub', {})
        device_stats = fs.get('device_stats', [])
        info = fs.get('info', {})

        # Check capacity
        used_percent = usage.get('used_percent', 0)
        if used_percent >= capacity_crit:
            issues.append({
                'severity': 'CRITICAL',
                'component': 'filesystem',
                'mount_point': mount_point,
                'metric': 'capacity',
                'value': used_percent,
                'threshold': capacity_crit,
                'message': f"BTRFS {mount_point} critically full: {used_percent:.1f}% used "
                           f"({format_bytes(usage.get('free_estimated_bytes', 0))} free)"
            })
        elif used_percent >= capacity_warn:
            issues.append({
                'severity': 'WARNING',
                'component': 'filesystem',
                'mount_point': mount_point,
                'metric': 'capacity',
                'value': used_percent,
                'threshold': capacity_warn,
                'message': f"BTRFS {mount_point} running low: {used_percent:.1f}% used "
                           f"({format_bytes(usage.get('free_estimated_bytes', 0))} free)"
            })

        # Check for missing devices (RAID degradation)
        if info.get('missing_devices', 0) > 0:
            issues.append({
                'severity': 'CRITICAL',
                'component': 'filesystem',
                'mount_point': mount_point,
                'metric': 'missing_devices',
                'value': info['missing_devices'],
                'message': f"BTRFS {mount_point} has {info['missing_devices']} missing device(s) - "
                           f"RAID may be degraded!"
            })

        # Check scrub age
        if scrub and scrub.get('scrub_age_days') is not None:
            scrub_age = scrub['scrub_age_days']
            if scrub_age >= scrub_warn_days:
                issues.append({
                    'severity': 'WARNING',
                    'component': 'filesystem',
                    'mount_point': mount_point,
                    'metric': 'scrub_age_days',
                    'value': scrub_age,
                    'threshold': scrub_warn_days,
                    'message': f"BTRFS {mount_point} not scrubbed for {scrub_age} days "
                               f"(threshold: {scrub_warn_days} days)"
                })
        elif scrub and scrub.get('last_scrub') is None and not scrub.get('running', False):
            issues.append({
                'severity': 'WARNING',
                'component': 'filesystem',
                'mount_point': mount_point,
                'metric': 'scrub_age_days',
                'value': None,
                'message': f"BTRFS {mount_point} has never been scrubbed"
            })

        # Check scrub errors
        if scrub:
            if scrub.get('errors_uncorrectable', 0) > 0:
                issues.append({
                    'severity': 'CRITICAL',
                    'component': 'filesystem',
                    'mount_point': mount_point,
                    'metric': 'scrub_errors',
                    'value': scrub['errors_uncorrectable'],
                    'message': f"BTRFS {mount_point} scrub found {scrub['errors_uncorrectable']} "
                               f"UNCORRECTABLE errors!"
                })
            elif scrub.get('errors_found', 0) > 0:
                issues.append({
                    'severity': 'WARNING',
                    'component': 'filesystem',
                    'mount_point': mount_point,
                    'metric': 'scrub_errors',
                    'value': scrub['errors_found'],
                    'message': f"BTRFS {mount_point} scrub found {scrub['errors_found']} errors "
                               f"({scrub.get('errors_corrected', 0)} corrected)"
                })

        # Check device I/O errors
        for dev in device_stats:
            if dev['total_errors'] >= error_threshold:
                severity = 'CRITICAL' if dev['total_errors'] >= error_threshold * 10 else 'WARNING'
                issues.append({
                    'severity': severity,
                    'component': 'device',
                    'mount_point': mount_point,
                    'device': dev['device'],
                    'metric': 'io_errors',
                    'value': dev['total_errors'],
                    'threshold': error_threshold,
                    'message': f"Device {dev['device']} ({mount_point}) has errors: "
                               f"write={dev['write_io_errs']}, read={dev['read_io_errs']}, "
                               f"flush={dev['flush_io_errs']}, corruption={dev['corruption_errs']}"
                })

    return issues


def output_plain(filesystems_data, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only:
        print("BTRFS Filesystem Health Summary")
        print(f"  Filesystems: {len(filesystems_data)}")
        print()

        if verbose:
            for fs in filesystems_data:
                usage = fs.get('usage', {})
                scrub = fs.get('scrub', {})
                info = fs.get('info', {})

                print(f"Mount: {fs['mount_point']}")
                print(f"  Device: {fs['device']}")

                if info.get('label'):
                    print(f"  Label: {info['label']}")
                if info.get('uuid'):
                    print(f"  UUID: {info['uuid']}")

                if usage:
                    print(f"  Size: {format_bytes(usage.get('total_bytes', 0))}")
                    print(f"  Used: {format_bytes(usage.get('used_bytes', 0))} "
                          f"({usage.get('used_percent', 0):.1f}%)")
                    print(f"  Free: {format_bytes(usage.get('free_estimated_bytes', 0))}")
                    if usage.get('data_ratio', 1.0) > 1.0:
                        print(f"  Data ratio: {usage['data_ratio']:.2f}")
                    if usage.get('metadata_ratio', 1.0) > 1.0:
                        print(f"  Metadata ratio: {usage['metadata_ratio']:.2f}")

                if scrub:
                    if scrub.get('running'):
                        print(f"  Scrub: Running")
                    elif scrub.get('scrub_age_days') is not None:
                        print(f"  Last scrub: {scrub['scrub_age_days']} days ago")
                    else:
                        print(f"  Last scrub: Never")

                # Show devices with errors
                device_stats = fs.get('device_stats', [])
                devices_with_errors = [d for d in device_stats if d['total_errors'] > 0]
                if devices_with_errors:
                    print(f"  Devices with errors:")
                    for dev in devices_with_errors:
                        print(f"    {dev['device']}: {dev['total_errors']} total errors")

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


def output_json(filesystems_data, issues, verbose):
    """Output results in JSON format."""
    result = {
        'summary': {
            'filesystems': len(filesystems_data)
        },
        'issues': issues
    }

    if verbose:
        result['filesystems'] = filesystems_data

    print(json.dumps(result, indent=2, default=str))


def output_table(filesystems_data, issues, verbose, warn_only):
    """Output results in table format."""
    if not warn_only:
        print("=" * 80)
        print("BTRFS FILESYSTEM HEALTH SUMMARY")
        print("=" * 80)
        print(f"{'Mount Point':<25} {'Size':<10} {'Used':<10} {'Free':<10} {'Usage':<8} {'Scrub':<12}")
        print("-" * 80)

        for fs in filesystems_data:
            usage = fs.get('usage', {})
            scrub = fs.get('scrub', {})

            scrub_str = 'Running' if scrub.get('running') else (
                f"{scrub.get('scrub_age_days', '?')}d ago" if scrub.get('scrub_age_days') is not None else 'Never'
            )

            print(f"{fs['mount_point']:<25} "
                  f"{format_bytes(usage.get('total_bytes', 0)):<10} "
                  f"{format_bytes(usage.get('used_bytes', 0)):<10} "
                  f"{format_bytes(usage.get('free_estimated_bytes', 0)):<10} "
                  f"{usage.get('used_percent', 0):.1f}%{'':<4} "
                  f"{scrub_str:<12}")

        print("=" * 80)
        print()

        if verbose:
            for fs in filesystems_data:
                device_stats = fs.get('device_stats', [])
                if device_stats:
                    print(f"DEVICES IN {fs['mount_point']}")
                    print("-" * 80)
                    print(f"{'Device':<25} {'Write Err':<12} {'Read Err':<12} {'Corruption':<12} {'Total':<10}")
                    print("-" * 80)
                    for dev in device_stats:
                        print(f"{dev['device']:<25} "
                              f"{dev['write_io_errs']:<12} "
                              f"{dev['read_io_errs']:<12} "
                              f"{dev['corruption_errs']:<12} "
                              f"{dev['total_errors']:<10}")
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
        description='Monitor BTRFS filesystem health and configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check BTRFS health with default thresholds
  %(prog)s --capacity-warn 70       # Warn when filesystems reach 70%% capacity
  %(prog)s --format json            # JSON output for monitoring tools
  %(prog)s --verbose                # Show detailed filesystem information
  %(prog)s --warn-only              # Only show warnings/errors

Thresholds:
  --capacity-warn: Filesystem capacity warning threshold (default: 80%%)
  --capacity-crit: Filesystem capacity critical threshold (default: 90%%)
  --scrub-warn: Days since last scrub warning threshold (default: 30)
  --error-threshold: Device error count threshold (default: 1)

Exit codes:
  0 - All BTRFS filesystems healthy
  1 - Warnings or critical issues detected
  2 - Usage error or BTRFS tools not available
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
        help='Show detailed filesystem and device information'
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
        help='Warning threshold for filesystem capacity (default: 80%%)'
    )

    parser.add_argument(
        '--capacity-crit',
        type=int,
        default=90,
        metavar='PCT',
        help='Critical threshold for filesystem capacity (default: 90%%)'
    )

    parser.add_argument(
        '--scrub-warn',
        type=int,
        default=30,
        metavar='DAYS',
        help='Warning threshold for days since last scrub (default: 30)'
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

    # Check for BTRFS tools
    if not check_btrfs_available():
        print("Error: BTRFS tools not found (btrfs)", file=sys.stderr)
        print("Install with: sudo apt-get install btrfs-progs", file=sys.stderr)
        sys.exit(2)

    # Get list of BTRFS filesystems
    filesystems = get_btrfs_filesystems()

    if not filesystems:
        if args.format == 'json':
            print(json.dumps({'message': 'No BTRFS filesystems found', 'issues': []}))
        else:
            print("No BTRFS filesystems found on this system.")
        sys.exit(0)

    # Gather data for each filesystem
    filesystems_data = []
    for fs in filesystems:
        mount_point = fs['mount_point']

        fs_data = {
            'mount_point': mount_point,
            'device': fs['device'],
            'options': fs['options'],
            'usage': get_filesystem_usage(mount_point),
            'scrub': get_scrub_status(mount_point),
            'device_stats': get_device_stats(mount_point),
            'info': get_filesystem_info(mount_point)
        }
        filesystems_data.append(fs_data)

    if not filesystems_data:
        if args.format == 'json':
            print(json.dumps({'message': 'Unable to read BTRFS filesystem information', 'issues': []}))
        else:
            print("Error: Unable to read BTRFS filesystem information.", file=sys.stderr)
        sys.exit(1)

    # Analyze for issues
    issues = analyze_filesystems(
        filesystems_data,
        args.capacity_warn,
        args.capacity_crit,
        args.scrub_warn,
        args.error_threshold
    )

    # Output results
    if args.format == 'json':
        output_json(filesystems_data, issues, args.verbose)
    elif args.format == 'table':
        output_table(filesystems_data, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(filesystems_data, issues, args.verbose, args.warn_only)

    # Determine exit code based on issues
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
