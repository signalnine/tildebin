#!/usr/bin/env python3
"""
Monitor dm-multipath I/O path health and configuration.

This script monitors multipath device mapper configurations to detect
path failures, degraded states, and configuration issues. Useful for:

- Detecting failed or degraded paths to SAN/NAS storage
- Monitoring path priority and load balancing health
- Identifying devices with reduced redundancy
- Tracking path flapping and checker failures
- Validating multipath configurations

The script uses multipathd and multipath commands to gather status and
reports issues based on configurable thresholds.

Exit codes:
    0 - All multipath devices healthy, no issues detected
    1 - Warnings or errors found (failed paths, degraded devices, etc.)
    2 - Usage error, multipath tools not installed, or no multipath configured
"""

import argparse
import sys
import json
import subprocess
import re


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


def check_multipath_available():
    """Check if multipath tools are available.

    Returns:
        bool: True if multipath commands are available
    """
    returncode, _, _ = run_command(['which', 'multipath'])
    return returncode == 0


def check_multipathd_running():
    """Check if multipathd daemon is running.

    Returns:
        bool: True if multipathd is running
    """
    returncode, stdout, _ = run_command(['multipathd', 'show', 'daemon'])
    if returncode == 0 and 'running' in stdout.lower():
        return True
    # Try systemctl as fallback
    returncode, stdout, _ = run_command(['systemctl', 'is-active', 'multipathd'])
    return returncode == 0 and 'active' in stdout


def get_multipath_topology():
    """Get multipath topology using multipath command.

    Returns:
        str: Raw multipath topology output or None on error
    """
    # Try multipathd first (more detailed)
    returncode, stdout, stderr = run_command(['multipathd', 'show', 'topology'])
    if returncode == 0 and stdout.strip():
        return stdout

    # Fallback to multipath -ll
    returncode, stdout, stderr = run_command(['multipath', '-ll'])
    if returncode == 0:
        return stdout

    return None


def get_multipath_status():
    """Get multipath device status from multipathd.

    Returns:
        str: Raw status output or None on error
    """
    returncode, stdout, stderr = run_command(['multipathd', 'show', 'status'])
    if returncode == 0:
        return stdout
    return None


def get_path_states():
    """Get individual path states from multipathd.

    Returns:
        str: Raw path status output or None on error
    """
    returncode, stdout, stderr = run_command(['multipathd', 'show', 'paths'])
    if returncode == 0:
        return stdout
    return None


def parse_multipath_topology(topology_output):
    """Parse multipath topology output into structured data.

    Args:
        topology_output: Raw output from multipath -ll or multipathd show topology

    Returns:
        list: List of multipath device dictionaries
    """
    devices = []
    current_device = None
    current_group = None

    if not topology_output:
        return devices

    lines = topology_output.strip().split('\n')

    for line in lines:
        # Match device line: mpatha (360...) dm-0 VENDOR,PRODUCT
        # or: mpath0 (36001...) dm-2 HP,LOGICAL VOLUME
        device_match = re.match(
            r'^(\S+)\s+\(([^)]+)\)\s+(dm-\d+)\s+(.+)$',
            line.strip()
        )

        if device_match:
            if current_device:
                devices.append(current_device)

            current_device = {
                'name': device_match.group(1),
                'wwid': device_match.group(2),
                'dm_device': device_match.group(3),
                'vendor_product': device_match.group(4).strip(),
                'size': None,
                'features': None,
                'hwhandler': None,
                'path_groups': [],
                'total_paths': 0,
                'active_paths': 0,
                'failed_paths': 0,
                'paths': []
            }
            current_group = None
            continue

        # Match size line: size=100G features='1 queue_if_no_path' hwhandler='1 alua'
        size_match = re.match(
            r'^\s*size=(\S+)\s+features=\'([^\']*)\'\s+hwhandler=\'([^\']*)\'',
            line
        )
        if size_match and current_device:
            current_device['size'] = size_match.group(1)
            current_device['features'] = size_match.group(2)
            current_device['hwhandler'] = size_match.group(3)
            continue

        # Match path group line: `-+- policy='service-time 0' prio=50 status=active
        # or: |-+- policy='round-robin 0' prio=1 status=enabled
        group_match = re.match(
            r'^\s*[|`]-\+-\s+policy=\'([^\']+)\'\s+prio=(\d+)\s+status=(\w+)',
            line
        )
        if group_match and current_device:
            current_group = {
                'policy': group_match.group(1),
                'priority': int(group_match.group(2)),
                'status': group_match.group(3),
                'paths': []
            }
            current_device['path_groups'].append(current_group)
            continue

        # Match path line: `- 8:0:0:1 sda 8:0  active ready running
        # or: |- 1:0:0:0 sdb 8:16 active ready running
        path_match = re.match(
            r'^\s*[|`]-\s+(\d+:\d+:\d+:\d+)\s+(\S+)\s+(\S+)\s+(\w+)\s+(\w+)\s+(\w+)',
            line
        )
        if path_match and current_device:
            path = {
                'hctl': path_match.group(1),
                'device': path_match.group(2),
                'major_minor': path_match.group(3),
                'dm_state': path_match.group(4),
                'path_state': path_match.group(5),
                'checker_state': path_match.group(6)
            }

            current_device['paths'].append(path)
            current_device['total_paths'] += 1

            if path['dm_state'] == 'active' and path['path_state'] == 'ready':
                current_device['active_paths'] += 1
            elif path['dm_state'] == 'failed' or path['path_state'] == 'faulty':
                current_device['failed_paths'] += 1

            if current_group:
                current_group['paths'].append(path)
            continue

    # Don't forget the last device
    if current_device:
        devices.append(current_device)

    return devices


def parse_paths_output(paths_output):
    """Parse multipathd show paths output.

    Args:
        paths_output: Raw output from multipathd show paths

    Returns:
        list: List of path dictionaries
    """
    paths = []

    if not paths_output:
        return paths

    lines = paths_output.strip().split('\n')

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            path = {
                'hctl': parts[0],
                'device': parts[1],
                'multipath': parts[2] if len(parts) > 6 else None,
                'dm_state': parts[-3] if len(parts) > 6 else parts[2],
                'path_state': parts[-2] if len(parts) > 6 else parts[3],
                'checker_state': parts[-1] if len(parts) > 6 else parts[4]
            }
            paths.append(path)

    return paths


def analyze_devices(devices, min_paths_warn, min_paths_crit):
    """Analyze multipath devices for issues.

    Args:
        devices: List of multipath device dictionaries
        min_paths_warn: Warning threshold for minimum active paths
        min_paths_crit: Critical threshold for minimum active paths

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    for device in devices:
        name = device['name']
        wwid = device['wwid']

        # Check for completely failed device (no active paths)
        if device['active_paths'] == 0:
            issues.append({
                'severity': 'CRITICAL',
                'component': 'device',
                'name': name,
                'wwid': wwid,
                'metric': 'active_paths',
                'value': 0,
                'total': device['total_paths'],
                'message': f"Device {name} has NO active paths! "
                           f"(0/{device['total_paths']} paths active)"
            })
            continue

        # Check for failed paths
        if device['failed_paths'] > 0:
            issues.append({
                'severity': 'WARNING',
                'component': 'device',
                'name': name,
                'wwid': wwid,
                'metric': 'failed_paths',
                'value': device['failed_paths'],
                'total': device['total_paths'],
                'message': f"Device {name} has {device['failed_paths']} failed path(s) "
                           f"({device['active_paths']}/{device['total_paths']} paths active)"
            })

        # Check minimum path thresholds
        if device['active_paths'] <= min_paths_crit:
            issues.append({
                'severity': 'CRITICAL',
                'component': 'device',
                'name': name,
                'wwid': wwid,
                'metric': 'active_paths',
                'value': device['active_paths'],
                'threshold': min_paths_crit,
                'message': f"Device {name} critically low on paths: "
                           f"{device['active_paths']}/{device['total_paths']} active "
                           f"(threshold: {min_paths_crit})"
            })
        elif device['active_paths'] <= min_paths_warn:
            issues.append({
                'severity': 'WARNING',
                'component': 'device',
                'name': name,
                'wwid': wwid,
                'metric': 'active_paths',
                'value': device['active_paths'],
                'threshold': min_paths_warn,
                'message': f"Device {name} running low on paths: "
                           f"{device['active_paths']}/{device['total_paths']} active "
                           f"(threshold: {min_paths_warn})"
            })

        # Check individual path states
        for path in device['paths']:
            if path['dm_state'] == 'failed':
                issues.append({
                    'severity': 'WARNING',
                    'component': 'path',
                    'name': f"{name}/{path['device']}",
                    'hctl': path['hctl'],
                    'metric': 'dm_state',
                    'value': path['dm_state'],
                    'message': f"Path {path['device']} ({path['hctl']}) on {name} "
                               f"is in failed state"
                })
            elif path['path_state'] == 'faulty':
                issues.append({
                    'severity': 'WARNING',
                    'component': 'path',
                    'name': f"{name}/{path['device']}",
                    'hctl': path['hctl'],
                    'metric': 'path_state',
                    'value': path['path_state'],
                    'message': f"Path {path['device']} ({path['hctl']}) on {name} "
                               f"is faulty"
                })
            elif path['checker_state'] not in ['running', 'ready', 'active']:
                # Ghost, shaky, or other abnormal states
                issues.append({
                    'severity': 'INFO',
                    'component': 'path',
                    'name': f"{name}/{path['device']}",
                    'hctl': path['hctl'],
                    'metric': 'checker_state',
                    'value': path['checker_state'],
                    'message': f"Path {path['device']} ({path['hctl']}) on {name} "
                               f"has checker state: {path['checker_state']}"
                })

        # Check path group status
        for i, group in enumerate(device['path_groups']):
            if group['status'] == 'disabled':
                issues.append({
                    'severity': 'INFO',
                    'component': 'path_group',
                    'name': f"{name}/group{i}",
                    'metric': 'status',
                    'value': group['status'],
                    'message': f"Path group {i} on {name} is disabled "
                               f"(policy: {group['policy']}, prio: {group['priority']})"
                })

    return issues


def output_plain(devices, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only:
        print("Multipath Health Summary")
        print(f"  Multipath Devices: {len(devices)}")

        total_paths = sum(d['total_paths'] for d in devices)
        active_paths = sum(d['active_paths'] for d in devices)
        failed_paths = sum(d['failed_paths'] for d in devices)

        print(f"  Total Paths: {total_paths}")
        print(f"  Active Paths: {active_paths}")
        print(f"  Failed Paths: {failed_paths}")
        print()

        if verbose and devices:
            print("Devices:")
            for device in devices:
                status = "OK" if device['failed_paths'] == 0 else "DEGRADED"
                print(f"  {device['name']} ({device['dm_device']}): "
                      f"{device['active_paths']}/{device['total_paths']} paths "
                      f"[{status}]")
                if device['size']:
                    print(f"    Size: {device['size']}, "
                          f"Vendor: {device['vendor_product']}")
                if verbose:
                    for path in device['paths']:
                        state = f"{path['dm_state']}/{path['path_state']}"
                        print(f"    - {path['device']} ({path['hctl']}): {state}")
            print()

    # Print issues
    if issues:
        for issue in issues:
            severity = issue['severity']

            # Skip INFO messages in warn-only mode
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


def output_json(devices, issues, verbose):
    """Output results in JSON format."""
    total_paths = sum(d['total_paths'] for d in devices)
    active_paths = sum(d['active_paths'] for d in devices)
    failed_paths = sum(d['failed_paths'] for d in devices)

    result = {
        'summary': {
            'devices': len(devices),
            'total_paths': total_paths,
            'active_paths': active_paths,
            'failed_paths': failed_paths
        },
        'issues': issues
    }

    if verbose:
        result['devices'] = devices

    print(json.dumps(result, indent=2, default=str))


def output_table(devices, issues, verbose, warn_only):
    """Output results in table format."""
    if not warn_only:
        print("=" * 75)
        print("MULTIPATH HEALTH SUMMARY")
        print("=" * 75)

        total_paths = sum(d['total_paths'] for d in devices)
        active_paths = sum(d['active_paths'] for d in devices)
        failed_paths = sum(d['failed_paths'] for d in devices)

        print(f"{'Metric':<25} {'Value':<15}")
        print("-" * 75)
        print(f"{'Multipath Devices':<25} {len(devices):<15}")
        print(f"{'Total Paths':<25} {total_paths:<15}")
        print(f"{'Active Paths':<25} {active_paths:<15}")
        print(f"{'Failed Paths':<25} {failed_paths:<15}")
        print("=" * 75)
        print()

        if verbose and devices:
            print("DEVICE DETAILS")
            print("=" * 75)
            print(f"{'Name':<12} {'DM':<8} {'Size':<10} "
                  f"{'Active':<8} {'Failed':<8} {'Status':<10}")
            print("-" * 75)
            for device in devices:
                status = "OK" if device['failed_paths'] == 0 else "DEGRADED"
                size = device['size'] if device['size'] else 'N/A'
                print(f"{device['name']:<12} {device['dm_device']:<8} "
                      f"{size:<10} {device['active_paths']:<8} "
                      f"{device['failed_paths']:<8} {status:<10}")
            print("=" * 75)
            print()

            if verbose:
                print("PATH DETAILS")
                print("=" * 75)
                print(f"{'Device':<12} {'Path':<8} {'HCTL':<12} "
                      f"{'DM State':<12} {'Path State':<12} {'Checker':<10}")
                print("-" * 75)
                for device in devices:
                    for path in device['paths']:
                        print(f"{device['name']:<12} {path['device']:<8} "
                              f"{path['hctl']:<12} {path['dm_state']:<12} "
                              f"{path['path_state']:<12} {path['checker_state']:<10}")
                print("=" * 75)
                print()

    # Print issues
    if issues:
        print("ISSUES DETECTED")
        print("=" * 75)
        for issue in issues:
            severity = issue['severity']

            # Skip INFO messages in warn-only mode
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
        description='Monitor dm-multipath device health and path status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check multipath health
  %(prog)s --min-paths-warn 2       # Warn if fewer than 2 active paths
  %(prog)s --format json            # JSON output for monitoring tools
  %(prog)s --verbose                # Show detailed path information
  %(prog)s --warn-only              # Only show warnings/errors

Thresholds:
  --min-paths-warn: Warn if active paths <= this value (default: 1)
  --min-paths-crit: Critical if active paths <= this value (default: 0)

Exit codes:
  0 - All multipath devices healthy
  1 - Warnings or critical issues detected
  2 - Usage error or multipath tools not available
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
        help='Show detailed path information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--min-paths-warn',
        type=int,
        default=1,
        metavar='N',
        help='Warn if active paths <= N (default: 1)'
    )

    parser.add_argument(
        '--min-paths-crit',
        type=int,
        default=0,
        metavar='N',
        help='Critical if active paths <= N (default: 0)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.min_paths_warn < 0:
        print("Error: --min-paths-warn must be >= 0", file=sys.stderr)
        sys.exit(2)

    if args.min_paths_crit < 0:
        print("Error: --min-paths-crit must be >= 0", file=sys.stderr)
        sys.exit(2)

    if args.min_paths_warn < args.min_paths_crit:
        print("Error: --min-paths-warn must be >= --min-paths-crit",
              file=sys.stderr)
        sys.exit(2)

    # Check for multipath tools
    if not check_multipath_available():
        print("Error: multipath tools not found", file=sys.stderr)
        print("Install with: sudo apt-get install multipath-tools",
              file=sys.stderr)
        sys.exit(2)

    # Check if multipathd is running
    if not check_multipathd_running():
        if args.format == 'json':
            print(json.dumps({
                'message': 'multipathd service not running',
                'issues': []
            }))
        else:
            print("multipathd service is not running.")
            print("Start with: sudo systemctl start multipathd")
        sys.exit(2)

    # Get multipath topology
    topology = get_multipath_topology()

    if not topology or not topology.strip():
        if args.format == 'json':
            print(json.dumps({
                'message': 'No multipath devices configured',
                'issues': []
            }))
        else:
            print("No multipath devices configured on this system.")
        sys.exit(0)

    # Parse topology
    devices = parse_multipath_topology(topology)

    if not devices:
        if args.format == 'json':
            print(json.dumps({
                'message': 'No multipath devices found',
                'issues': []
            }))
        else:
            print("No multipath devices found.")
        sys.exit(0)

    # Analyze for issues
    issues = analyze_devices(devices, args.min_paths_warn, args.min_paths_crit)

    # Output results
    if args.format == 'json':
        output_json(devices, issues, args.verbose)
    elif args.format == 'table':
        output_table(devices, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(devices, issues, args.verbose, args.warn_only)

    # Determine exit code based on issues
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
