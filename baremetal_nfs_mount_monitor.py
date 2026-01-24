#!/usr/bin/env python3
"""
Monitor NFS mount health on baremetal systems.

Checks NFS mount status, validates connectivity to NFS servers, detects stale
mounts, monitors mount options, and reports latency issues. Essential for
large-scale environments where shared storage failures cause cascading problems.

Exit codes:
    0 - All NFS mounts healthy and responsive
    1 - NFS mount issues detected (stale mounts, connectivity problems, warnings)
    2 - Usage error or missing dependency
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time


def parse_proc_mounts():
    """Parse /proc/mounts to find NFS mounts."""
    mounts = []

    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]

                    # Check for NFS filesystem types
                    if fstype in ('nfs', 'nfs4', 'nfs3'):
                        mount_info = {
                            'device': device,
                            'mountpoint': mountpoint,
                            'fstype': fstype,
                            'options': options.split(','),
                            'server': None,
                            'export': None
                        }

                        # Parse server:export from device
                        if ':' in device:
                            server_part, export_part = device.split(':', 1)
                            mount_info['server'] = server_part
                            mount_info['export'] = export_part

                        mounts.append(mount_info)
    except FileNotFoundError:
        return None
    except PermissionError:
        return None

    return mounts


def parse_etc_fstab():
    """Parse /etc/fstab for configured NFS mounts."""
    fstab_entries = []

    try:
        with open('/etc/fstab', 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                parts = line.split()
                if len(parts) >= 4:
                    device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]

                    if fstype in ('nfs', 'nfs4', 'nfs3'):
                        entry = {
                            'device': device,
                            'mountpoint': mountpoint,
                            'fstype': fstype,
                            'options': options.split(','),
                            'server': None,
                            'export': None
                        }

                        if ':' in device:
                            server_part, export_part = device.split(':', 1)
                            entry['server'] = server_part
                            entry['export'] = export_part

                        fstab_entries.append(entry)
    except FileNotFoundError:
        return []
    except PermissionError:
        return []

    return fstab_entries


def check_mount_accessible(mountpoint, timeout=5):
    """Check if a mount point is accessible (not stale)."""
    result = {
        'accessible': False,
        'latency_ms': None,
        'error': None,
        'stale': False
    }

    try:
        start_time = time.time()

        # Use stat with timeout to check if mount is responsive
        # A stale NFS mount will hang on stat()
        proc = subprocess.run(
            ['stat', '--format=%F', mountpoint],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        end_time = time.time()
        result['latency_ms'] = (end_time - start_time) * 1000

        if proc.returncode == 0:
            result['accessible'] = True
        else:
            result['error'] = proc.stderr.strip() or 'stat failed'
            # Check for stale file handle error
            if 'stale' in proc.stderr.lower() or 'stale' in proc.stdout.lower():
                result['stale'] = True

    except subprocess.TimeoutExpired:
        result['error'] = 'timeout - mount may be stale or server unreachable'
        result['stale'] = True
    except FileNotFoundError:
        result['error'] = 'stat command not found'
    except Exception as e:
        result['error'] = str(e)

    return result


def check_server_reachability(server, timeout=2):
    """Check if NFS server is reachable via ping."""
    result = {
        'server': server,
        'reachable': False,
        'latency_ms': None,
        'error': None
    }

    try:
        # Use ping with count=1 and timeout
        proc = subprocess.run(
            ['ping', '-c', '1', '-W', str(timeout), server],
            capture_output=True,
            text=True,
            timeout=timeout + 1
        )

        if proc.returncode == 0:
            result['reachable'] = True
            # Extract latency from ping output
            match = re.search(r'time[=<](\d+\.?\d*)', proc.stdout)
            if match:
                result['latency_ms'] = float(match.group(1))
        else:
            result['error'] = 'host unreachable'

    except subprocess.TimeoutExpired:
        result['error'] = 'timeout'
    except FileNotFoundError:
        result['error'] = 'ping command not found'
    except Exception as e:
        result['error'] = str(e)

    return result


def check_nfs_port_open(server, port=2049, timeout=2):
    """Check if NFS port is open on server."""
    import socket

    result = {
        'port_open': False,
        'port': port,
        'latency_ms': None,
        'error': None
    }

    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        connect_result = sock.connect_ex((server, port))
        end_time = time.time()

        if connect_result == 0:
            result['port_open'] = True
            result['latency_ms'] = (end_time - start_time) * 1000
        else:
            result['error'] = f'connection refused or filtered'

        sock.close()

    except socket.timeout:
        result['error'] = 'timeout'
    except socket.gaierror as e:
        result['error'] = f'DNS resolution failed: {e}'
    except Exception as e:
        result['error'] = str(e)

    return result


def get_nfs_stats(mountpoint):
    """Get NFS statistics for a mount point from /proc/self/mountstats."""
    stats = {
        'available': False,
        'version': None,
        'read_bytes': None,
        'write_bytes': None,
        'retrans': None,
        'timeouts': None
    }

    try:
        with open('/proc/self/mountstats', 'r') as f:
            content = f.read()

        # Find the section for this mountpoint
        pattern = rf'device .+ mounted on {re.escape(mountpoint)} with fstype nfs\d?'
        match = re.search(pattern, content)
        if not match:
            return stats

        start_pos = match.start()
        # Find the next mount section or end of file
        next_match = re.search(r'\ndevice ', content[start_pos + 1:])
        if next_match:
            section = content[start_pos:start_pos + 1 + next_match.start()]
        else:
            section = content[start_pos:]

        stats['available'] = True

        # Extract NFS version
        version_match = re.search(r'vers[=:](\d+)', section)
        if version_match:
            stats['version'] = int(version_match.group(1))

        # Extract retransmissions
        retrans_match = re.search(r'retrans:\s*(\d+)', section)
        if retrans_match:
            stats['retrans'] = int(retrans_match.group(1))

        # Extract timeouts
        timeout_match = re.search(r'timeout:\s*(\d+)', section)
        if timeout_match:
            stats['timeouts'] = int(timeout_match.group(1))

    except (FileNotFoundError, PermissionError):
        pass
    except Exception:
        pass

    return stats


def analyze_mount_options(options):
    """Analyze mount options and identify potential issues."""
    issues = []
    info = {
        'hard': False,
        'soft': False,
        'intr': False,
        'noac': False,
        'actimeo': None,
        'timeo': None,
        'retrans': None,
        'rsize': None,
        'wsize': None
    }

    for opt in options:
        if opt == 'hard':
            info['hard'] = True
        elif opt == 'soft':
            info['soft'] = True
        elif opt == 'intr':
            info['intr'] = True
        elif opt == 'noac':
            info['noac'] = True
        elif opt.startswith('actimeo='):
            info['actimeo'] = int(opt.split('=')[1])
        elif opt.startswith('timeo='):
            info['timeo'] = int(opt.split('=')[1])
        elif opt.startswith('retrans='):
            info['retrans'] = int(opt.split('=')[1])
        elif opt.startswith('rsize='):
            info['rsize'] = int(opt.split('=')[1])
        elif opt.startswith('wsize='):
            info['wsize'] = int(opt.split('=')[1])

    # Check for soft mounts (can cause silent data corruption)
    if info['soft']:
        issues.append({
            'severity': 'warning',
            'type': 'soft_mount',
            'message': 'Soft mount detected - may cause silent failures on server issues'
        })

    # Check for missing intr option on hard mounts
    if info['hard'] and not info['intr']:
        issues.append({
            'severity': 'info',
            'type': 'no_intr',
            'message': 'Hard mount without intr option - processes may become unkillable'
        })

    return info, issues


def analyze_nfs_health(mounts, fstab_entries, mount_checks, server_checks, port_checks):
    """Analyze overall NFS health and return issues."""
    issues = []
    warnings = []

    # Check for stale mounts
    for mountpoint, check in mount_checks.items():
        if check['stale']:
            issues.append({
                'severity': 'critical',
                'type': 'stale_mount',
                'message': f"Stale NFS mount detected: {mountpoint}",
                'mountpoint': mountpoint
            })
        elif not check['accessible']:
            issues.append({
                'severity': 'critical',
                'type': 'mount_inaccessible',
                'message': f"NFS mount not accessible: {mountpoint} ({check['error']})",
                'mountpoint': mountpoint
            })
        elif check['latency_ms'] and check['latency_ms'] > 1000:
            warnings.append({
                'severity': 'warning',
                'type': 'mount_slow',
                'message': f"NFS mount responding slowly: {mountpoint} ({check['latency_ms']:.0f}ms)",
                'mountpoint': mountpoint,
                'latency_ms': check['latency_ms']
            })

    # Check server reachability
    for server, check in server_checks.items():
        if not check['reachable']:
            issues.append({
                'severity': 'critical',
                'type': 'server_unreachable',
                'message': f"NFS server unreachable: {server} ({check['error']})",
                'server': server
            })

    # Check NFS port accessibility
    for server, check in port_checks.items():
        if not check['port_open']:
            issues.append({
                'severity': 'critical',
                'type': 'nfs_port_closed',
                'message': f"NFS port {check['port']} not accessible on {server}: {check['error']}",
                'server': server,
                'port': check['port']
            })

    # Check for unmounted fstab entries
    mounted_points = {m['mountpoint'] for m in mounts}
    for entry in fstab_entries:
        if entry['mountpoint'] not in mounted_points:
            # Skip entries with noauto option
            if 'noauto' not in entry['options']:
                warnings.append({
                    'severity': 'warning',
                    'type': 'unmounted_fstab',
                    'message': f"NFS mount in fstab but not mounted: {entry['mountpoint']}",
                    'mountpoint': entry['mountpoint'],
                    'device': entry['device']
                })

    # Check mount options
    for mount in mounts:
        opt_info, opt_issues = analyze_mount_options(mount['options'])
        for issue in opt_issues:
            issue['mountpoint'] = mount['mountpoint']
            if issue['severity'] == 'warning':
                warnings.append(issue)
            else:
                issues.append(issue)

    return issues, warnings


def format_plain(mounts, fstab_entries, mount_checks, server_checks, port_checks,
                 issues, warnings, verbose=False):
    """Format NFS health data as plain text."""
    output = []

    output.append("NFS Mount Health Monitor")
    output.append("=" * 60)
    output.append("")

    if not mounts:
        output.append("No NFS mounts found.")
        output.append("")
    else:
        output.append(f"Active NFS Mounts: {len(mounts)}")
        output.append("-" * 40)

        for mount in mounts:
            mountpoint = mount['mountpoint']
            check = mount_checks.get(mountpoint, {})

            status = "[OK]" if check.get('accessible') else "[FAIL]"
            if check.get('stale'):
                status = "[STALE]"

            latency = ""
            if check.get('latency_ms'):
                latency = f" ({check['latency_ms']:.0f}ms)"

            output.append(f"  {status} {mountpoint}")
            output.append(f"       Server: {mount['server']}")
            output.append(f"       Export: {mount['export']}")
            output.append(f"       Type: {mount['fstype']}{latency}")

            if verbose:
                output.append(f"       Options: {', '.join(mount['options'][:5])}")
                if len(mount['options']) > 5:
                    output.append(f"                (+{len(mount['options']) - 5} more)")

            output.append("")

    # Server status
    if server_checks:
        output.append("NFS Servers:")
        output.append("-" * 40)

        for server, check in server_checks.items():
            if check['reachable']:
                latency = f" ({check['latency_ms']:.0f}ms)" if check['latency_ms'] else ""
                output.append(f"  [OK] {server}{latency}")
            else:
                output.append(f"  [FAIL] {server}: {check['error']}")

        output.append("")

    # Port checks
    if port_checks and verbose:
        output.append("NFS Port Status:")
        output.append("-" * 40)

        for server, check in port_checks.items():
            if check['port_open']:
                output.append(f"  [OK] {server}:{check['port']}")
            else:
                output.append(f"  [FAIL] {server}:{check['port']}: {check['error']}")

        output.append("")

    # Issues
    if issues:
        output.append("Issues:")
        output.append("-" * 40)
        for issue in issues:
            severity = issue['severity'].upper()
            output.append(f"  [{severity}] {issue['message']}")
        output.append("")

    if warnings:
        output.append("Warnings:")
        output.append("-" * 40)
        for warning in warnings:
            output.append(f"  [WARNING] {warning['message']}")
        output.append("")

    # Summary
    if not issues and not warnings:
        output.append(f"Status: All {len(mounts)} NFS mount(s) healthy")
    elif not issues:
        output.append(f"Status: NFS mounts functional with {len(warnings)} warning(s)")
    else:
        critical_count = sum(1 for i in issues if i['severity'] == 'critical')
        output.append(f"Status: {len(issues)} issue(s) detected ({critical_count} critical)")

    return '\n'.join(output)


def format_json(mounts, fstab_entries, mount_checks, server_checks, port_checks,
                issues, warnings):
    """Format NFS health data as JSON."""
    data = {
        'mounts': mounts,
        'fstab_entries': fstab_entries,
        'mount_checks': mount_checks,
        'server_checks': server_checks,
        'port_checks': port_checks,
        'issues': issues,
        'warnings': warnings,
        'healthy': len([i for i in issues if i['severity'] == 'critical']) == 0,
        'mount_count': len(mounts)
    }
    return json.dumps(data, indent=2)


def format_table(mounts, fstab_entries, mount_checks, server_checks, port_checks,
                 issues, warnings):
    """Format NFS health data as a table."""
    output = []

    output.append(f"{'MOUNTPOINT':<30} {'SERVER':<20} {'STATUS':<10} {'LATENCY':<12}")
    output.append("-" * 72)

    for mount in mounts:
        mountpoint = mount['mountpoint'][:30]
        server = (mount['server'] or 'unknown')[:20]
        check = mount_checks.get(mount['mountpoint'], {})

        if check.get('stale'):
            status = "STALE"
        elif check.get('accessible'):
            status = "OK"
        else:
            status = "FAIL"

        latency = f"{check.get('latency_ms', 0):.0f}ms" if check.get('latency_ms') else "-"

        output.append(f"{mountpoint:<30} {server:<20} {status:<10} {latency:<12}")

    if not mounts:
        output.append("No NFS mounts found")

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor NFS mount health on baremetal systems.',
        epilog='''
Examples:
  # Check all NFS mount health
  %(prog)s

  # Show detailed information
  %(prog)s --verbose

  # Output as JSON for monitoring systems
  %(prog)s --format json

  # Skip connectivity checks (faster, local only)
  %(prog)s --no-connectivity

  # Custom timeout for slow networks
  %(prog)s --timeout 10

  # Only show issues
  %(prog)s --warn-only

Exit codes:
  0 - All NFS mounts healthy
  1 - NFS issues detected
  2 - Usage error
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
        help='Show detailed information including mount options'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    parser.add_argument(
        '--no-connectivity',
        action='store_true',
        help='Skip server connectivity and port checks'
    )

    parser.add_argument(
        '--no-fstab',
        action='store_true',
        help='Skip checking /etc/fstab for unmounted entries'
    )

    parser.add_argument(
        '--timeout',
        type=float,
        default=5.0,
        help='Timeout in seconds for mount accessibility checks (default: 5.0)'
    )

    parser.add_argument(
        '--nfs-port',
        type=int,
        default=2049,
        help='NFS port to check (default: 2049)'
    )

    args = parser.parse_args()

    # Validate timeout
    if args.timeout <= 0:
        print("Error: Timeout must be a positive number", file=sys.stderr)
        return 2

    # Parse current mounts
    mounts = parse_proc_mounts()
    if mounts is None:
        print("Error: Cannot read /proc/mounts", file=sys.stderr)
        return 2

    # Parse fstab
    fstab_entries = []
    if not args.no_fstab:
        fstab_entries = parse_etc_fstab()

    # Check mount accessibility
    mount_checks = {}
    for mount in mounts:
        mount_checks[mount['mountpoint']] = check_mount_accessible(
            mount['mountpoint'],
            timeout=args.timeout
        )

    # Check server reachability and ports
    server_checks = {}
    port_checks = {}

    if not args.no_connectivity:
        servers = {m['server'] for m in mounts if m['server']}

        for server in servers:
            server_checks[server] = check_server_reachability(server, timeout=2)
            port_checks[server] = check_nfs_port_open(server, port=args.nfs_port, timeout=2)

    # Analyze health
    issues, warnings = analyze_nfs_health(
        mounts, fstab_entries, mount_checks, server_checks, port_checks
    )

    # Filter for warn-only mode
    if args.warn_only and not issues and not warnings:
        if args.format == 'json':
            print(json.dumps({'healthy': True, 'mount_count': len(mounts), 'issues': [], 'warnings': []}))
        else:
            print(f"All {len(mounts)} NFS mount(s) healthy - no issues to report")
        return 0

    # Format output
    if args.format == 'json':
        output = format_json(
            mounts, fstab_entries, mount_checks, server_checks, port_checks,
            issues, warnings
        )
    elif args.format == 'table':
        output = format_table(
            mounts, fstab_entries, mount_checks, server_checks, port_checks,
            issues, warnings
        )
    else:
        output = format_plain(
            mounts, fstab_entries, mount_checks, server_checks, port_checks,
            issues, warnings, args.verbose
        )

    print(output)

    # Return exit code based on issues
    critical_issues = [i for i in issues if i['severity'] == 'critical']
    if critical_issues:
        return 1
    elif issues:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
