#!/usr/bin/env python3
"""
Monitor DRBD (Distributed Replicated Block Device) replication health.

This script monitors DRBD resources to detect synchronization issues,
split-brain conditions, and replication lag. Useful for:

- Detecting out-of-sync or disconnected DRBD resources
- Monitoring replication state (Primary/Secondary roles)
- Identifying split-brain conditions
- Tracking synchronization progress during resync
- Validating DRBD configuration and disk states

The script parses /proc/drbd (kernel < 8.4) and uses drbdadm/drbdsetup
commands for newer versions to gather status information.

Exit codes:
    0 - All DRBD resources healthy and synchronized
    1 - Warnings or errors found (out-of-sync, degraded, etc.)
    2 - Usage error, DRBD not installed, or no resources configured
"""

import argparse
import sys
import json
import subprocess
import os
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


def check_drbd_available():
    """Check if DRBD tools are available.

    Returns:
        bool: True if drbdadm is available
    """
    returncode, _, _ = run_command(['which', 'drbdadm'])
    return returncode == 0


def check_drbd_module_loaded():
    """Check if DRBD kernel module is loaded.

    Returns:
        bool: True if drbd module is loaded
    """
    returncode, stdout, _ = run_command(['lsmod'])
    if returncode == 0:
        return 'drbd' in stdout
    # Fallback: check /proc/drbd
    return os.path.exists('/proc/drbd')


def get_drbd_status_json():
    """Get DRBD status using drbdsetup (DRBD 9+).

    Returns:
        dict or None: Parsed JSON status or None if unavailable
    """
    returncode, stdout, stderr = run_command(['drbdsetup', 'status', '--json'])
    if returncode == 0 and stdout.strip():
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return None
    return None


def get_drbd_status_text():
    """Get DRBD status using drbdadm status.

    Returns:
        str or None: Status text output or None
    """
    returncode, stdout, stderr = run_command(['drbdadm', 'status'])
    if returncode == 0:
        return stdout
    return None


def parse_proc_drbd():
    """Parse /proc/drbd for DRBD 8.x systems.

    Returns:
        list: List of resource dictionaries
    """
    resources = []

    if not os.path.exists('/proc/drbd'):
        return resources

    try:
        with open('/proc/drbd', 'r') as f:
            content = f.read()
    except (IOError, PermissionError):
        return resources

    # Parse version line
    # version: 8.4.11 (api:1/proto:86-101)
    current_resource = None

    for line in content.split('\n'):
        line = line.strip()

        # Skip version line
        if line.startswith('version:'):
            continue

        # Resource line format:
        # 0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----
        resource_match = re.match(
            r'^(\d+):\s+cs:(\S+)\s+ro:(\S+)/(\S+)\s+ds:(\S+)/(\S+)',
            line
        )

        if resource_match:
            resource = {
                'name': f'drbd{resource_match.group(1)}',
                'minor': int(resource_match.group(1)),
                'connection_state': resource_match.group(2),
                'local_role': resource_match.group(3),
                'peer_role': resource_match.group(4),
                'local_disk_state': resource_match.group(5),
                'peer_disk_state': resource_match.group(6),
                'sync_percent': None,
                'out_of_sync_kb': 0,
                'connections': []
            }

            # Check for sync progress in subsequent data
            # ns:0 nr:0 dw:0 dr:0 al:0 bm:0 lo:0 pe:0 ua:0 ap:0 ep:1 wo:f oos:0
            oos_match = re.search(r'oos:(\d+)', line)
            if oos_match:
                resource['out_of_sync_kb'] = int(oos_match.group(1))

            resources.append(resource)
            current_resource = resource

        # Sync progress line
        # [>...................] sync'ed:  0.1% (3898420/3899824)K
        sync_match = re.search(r"sync'ed:\s+([\d.]+)%", line)
        if sync_match and current_resource:
            current_resource['sync_percent'] = float(sync_match.group(1))

    return resources


def parse_drbdadm_status(status_text):
    """Parse drbdadm status output into structured data.

    Args:
        status_text: Raw output from drbdadm status

    Returns:
        list: List of resource dictionaries
    """
    resources = []

    if not status_text:
        return resources

    current_resource = None

    for line in status_text.split('\n'):
        # Resource line: r0 role:Primary
        resource_match = re.match(r'^(\S+)\s+role:(\S+)', line)
        if resource_match:
            if current_resource:
                resources.append(current_resource)

            current_resource = {
                'name': resource_match.group(1),
                'local_role': resource_match.group(2),
                'peer_role': None,
                'local_disk_state': None,
                'peer_disk_state': None,
                'connection_state': None,
                'sync_percent': None,
                'out_of_sync_kb': 0,
                'connections': []
            }
            continue

        if not current_resource:
            continue

        # Disk line:   disk:UpToDate
        disk_match = re.match(r'^\s+disk:(\S+)', line)
        if disk_match:
            current_resource['local_disk_state'] = disk_match.group(1)
            continue

        # Connection line:   peer connection:Connected
        # or: hostname role:Secondary
        conn_match = re.match(r'^\s+(\S+)\s+(?:connection:|role:)(\S+)', line)
        if conn_match:
            peer_name = conn_match.group(1)
            state = conn_match.group(2)

            if state in ['Primary', 'Secondary', 'Unknown']:
                current_resource['peer_role'] = state
            else:
                current_resource['connection_state'] = state

            continue

        # Peer disk line:     peer-disk:UpToDate
        peer_disk_match = re.match(r'^\s+peer-disk:(\S+)', line)
        if peer_disk_match:
            current_resource['peer_disk_state'] = peer_disk_match.group(1)
            continue

        # Replication state:     replication:SyncSource peer-disk:Inconsistent
        repl_match = re.match(r'^\s+replication:(\S+)', line)
        if repl_match:
            current_resource['connection_state'] = repl_match.group(1)
            continue

        # Sync progress: done:45.23
        sync_match = re.search(r'done:([\d.]+)', line)
        if sync_match:
            current_resource['sync_percent'] = float(sync_match.group(1))

    if current_resource:
        resources.append(current_resource)

    return resources


def parse_drbd_json_status(json_data):
    """Parse DRBD 9+ JSON status into resource list.

    Args:
        json_data: Parsed JSON from drbdsetup status --json

    Returns:
        list: List of resource dictionaries
    """
    resources = []

    if not json_data:
        return resources

    for res in json_data:
        resource = {
            'name': res.get('name', 'unknown'),
            'local_role': res.get('role', 'Unknown'),
            'peer_role': None,
            'local_disk_state': None,
            'peer_disk_state': None,
            'connection_state': None,
            'sync_percent': None,
            'out_of_sync_kb': 0,
            'connections': []
        }

        # Get local disk state from devices
        devices = res.get('devices', [])
        if devices:
            resource['local_disk_state'] = devices[0].get('disk-state', 'Unknown')
            resource['out_of_sync_kb'] = devices[0].get('out-of-sync', 0) // 1024

        # Get connection and peer info
        connections = res.get('connections', [])
        for conn in connections:
            conn_info = {
                'peer': conn.get('name', 'unknown'),
                'state': conn.get('connection-state', 'Unknown'),
                'peer_role': conn.get('peer-role', 'Unknown'),
                'peer_disk_state': None
            }

            # Get peer disk state
            peer_devices = conn.get('peer_devices', [])
            if peer_devices:
                conn_info['peer_disk_state'] = peer_devices[0].get('peer-disk-state', 'Unknown')

                # Get sync progress
                repl_state = peer_devices[0].get('replication-state', None)
                if repl_state and 'Sync' in str(repl_state):
                    done = peer_devices[0].get('done', None)
                    if done is not None:
                        resource['sync_percent'] = float(done)

            resource['connections'].append(conn_info)

            # Set primary connection info
            if resource['peer_role'] is None:
                resource['peer_role'] = conn_info['peer_role']
                resource['peer_disk_state'] = conn_info['peer_disk_state']
                resource['connection_state'] = conn_info['state']

        resources.append(resource)

    return resources


def get_drbd_resources():
    """Get all DRBD resources using the best available method.

    Returns:
        list: List of resource dictionaries
    """
    # Try DRBD 9+ JSON first
    json_status = get_drbd_status_json()
    if json_status:
        return parse_drbd_json_status(json_status)

    # Try drbdadm status
    status_text = get_drbd_status_text()
    if status_text:
        return parse_drbdadm_status(status_text)

    # Fall back to /proc/drbd for DRBD 8.x
    return parse_proc_drbd()


def analyze_resources(resources, sync_warn_threshold, sync_crit_threshold):
    """Analyze DRBD resources for issues.

    Args:
        resources: List of resource dictionaries
        sync_warn_threshold: Warning if sync percent below this
        sync_crit_threshold: Critical if sync percent below this

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    # Connection states that indicate problems
    bad_connection_states = [
        'StandAlone', 'Disconnecting', 'Unconnected', 'Timeout',
        'BrokenPipe', 'NetworkFailure', 'ProtocolError',
        'TearDown', 'WFConnection', 'WFReportParams'
    ]

    # Disk states that indicate problems
    bad_disk_states = [
        'Diskless', 'Failed', 'Inconsistent', 'Outdated',
        'DUnknown', 'Attaching'
    ]

    # Disk states that indicate sync in progress
    syncing_disk_states = ['Inconsistent']

    for resource in resources:
        name = resource['name']

        # Check connection state
        conn_state = resource.get('connection_state')
        if conn_state in bad_connection_states:
            severity = 'CRITICAL' if conn_state in ['StandAlone', 'Disconnecting'] else 'WARNING'
            issues.append({
                'severity': severity,
                'component': 'connection',
                'resource': name,
                'metric': 'connection_state',
                'value': conn_state,
                'message': f"Resource {name} connection state: {conn_state}"
            })

        # Check for split-brain (both Primary)
        if resource.get('local_role') == 'Primary' and resource.get('peer_role') == 'Primary':
            issues.append({
                'severity': 'CRITICAL',
                'component': 'role',
                'resource': name,
                'metric': 'split_brain',
                'value': 'Primary/Primary',
                'message': f"Resource {name} SPLIT-BRAIN detected! Both nodes are Primary"
            })

        # Check local disk state
        local_disk = resource.get('local_disk_state')
        if local_disk in bad_disk_states:
            # Inconsistent during sync is expected
            is_syncing = resource.get('sync_percent') is not None
            if local_disk == 'Inconsistent' and is_syncing:
                issues.append({
                    'severity': 'INFO',
                    'component': 'disk',
                    'resource': name,
                    'metric': 'local_disk_state',
                    'value': local_disk,
                    'message': f"Resource {name} local disk syncing ({resource['sync_percent']:.1f}% complete)"
                })
            else:
                severity = 'CRITICAL' if local_disk in ['Failed', 'Diskless'] else 'WARNING'
                issues.append({
                    'severity': severity,
                    'component': 'disk',
                    'resource': name,
                    'metric': 'local_disk_state',
                    'value': local_disk,
                    'message': f"Resource {name} local disk state: {local_disk}"
                })

        # Check peer disk state
        peer_disk = resource.get('peer_disk_state')
        if peer_disk and peer_disk in bad_disk_states:
            is_syncing = resource.get('sync_percent') is not None
            if peer_disk == 'Inconsistent' and is_syncing:
                pass  # Already reported above
            else:
                severity = 'CRITICAL' if peer_disk in ['Failed', 'Diskless'] else 'WARNING'
                issues.append({
                    'severity': severity,
                    'component': 'disk',
                    'resource': name,
                    'metric': 'peer_disk_state',
                    'value': peer_disk,
                    'message': f"Resource {name} peer disk state: {peer_disk}"
                })

        # Check sync progress thresholds
        sync_percent = resource.get('sync_percent')
        if sync_percent is not None:
            if sync_percent < sync_crit_threshold:
                issues.append({
                    'severity': 'CRITICAL',
                    'component': 'sync',
                    'resource': name,
                    'metric': 'sync_percent',
                    'value': sync_percent,
                    'threshold': sync_crit_threshold,
                    'message': f"Resource {name} sync critically low: {sync_percent:.1f}% "
                               f"(threshold: {sync_crit_threshold}%)"
                })
            elif sync_percent < sync_warn_threshold:
                issues.append({
                    'severity': 'WARNING',
                    'component': 'sync',
                    'resource': name,
                    'metric': 'sync_percent',
                    'value': sync_percent,
                    'threshold': sync_warn_threshold,
                    'message': f"Resource {name} sync progress: {sync_percent:.1f}% "
                               f"(threshold: {sync_warn_threshold}%)"
                })

        # Check for out-of-sync data
        out_of_sync = resource.get('out_of_sync_kb', 0)
        if out_of_sync > 0:
            issues.append({
                'severity': 'WARNING',
                'component': 'sync',
                'resource': name,
                'metric': 'out_of_sync_kb',
                'value': out_of_sync,
                'message': f"Resource {name} has {out_of_sync} KB out of sync"
            })

    return issues


def output_plain(resources, issues, verbose, warn_only):
    """Output results in plain text format."""
    if not warn_only:
        print("DRBD Health Summary")
        print(f"  DRBD Resources: {len(resources)}")

        healthy = sum(1 for r in resources
                      if r.get('connection_state') in ['Connected', 'SyncSource', 'SyncTarget', None]
                      and r.get('local_disk_state') == 'UpToDate')
        print(f"  Healthy Resources: {healthy}")
        print(f"  Degraded Resources: {len(resources) - healthy}")
        print()

        if verbose and resources:
            print("Resources:")
            for resource in resources:
                role = f"{resource.get('local_role', 'Unknown')}/{resource.get('peer_role', 'Unknown')}"
                disk = f"{resource.get('local_disk_state', 'Unknown')}/{resource.get('peer_disk_state', 'Unknown')}"
                conn = resource.get('connection_state', 'Unknown')

                status = "OK"
                if resource.get('local_disk_state') != 'UpToDate':
                    status = "DEGRADED"
                if resource.get('connection_state') in ['StandAlone', 'Disconnecting']:
                    status = "CRITICAL"

                print(f"  {resource['name']}: {role} ds:{disk} conn:{conn} [{status}]")

                if resource.get('sync_percent') is not None:
                    print(f"    Sync progress: {resource['sync_percent']:.1f}%")

                if resource.get('out_of_sync_kb', 0) > 0:
                    print(f"    Out of sync: {resource['out_of_sync_kb']} KB")

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


def output_json(resources, issues, verbose):
    """Output results in JSON format."""
    healthy = sum(1 for r in resources
                  if r.get('connection_state') in ['Connected', 'SyncSource', 'SyncTarget', None]
                  and r.get('local_disk_state') == 'UpToDate')

    result = {
        'summary': {
            'resources': len(resources),
            'healthy': healthy,
            'degraded': len(resources) - healthy
        },
        'issues': issues
    }

    if verbose:
        result['resources'] = resources

    print(json.dumps(result, indent=2, default=str))


def output_table(resources, issues, verbose, warn_only):
    """Output results in table format."""
    if not warn_only:
        print("=" * 80)
        print("DRBD HEALTH SUMMARY")
        print("=" * 80)

        healthy = sum(1 for r in resources
                      if r.get('connection_state') in ['Connected', 'SyncSource', 'SyncTarget', None]
                      and r.get('local_disk_state') == 'UpToDate')

        print(f"{'Metric':<25} {'Value':<15}")
        print("-" * 80)
        print(f"{'DRBD Resources':<25} {len(resources):<15}")
        print(f"{'Healthy':<25} {healthy:<15}")
        print(f"{'Degraded':<25} {len(resources) - healthy:<15}")
        print("=" * 80)
        print()

        if verbose and resources:
            print("RESOURCE DETAILS")
            print("=" * 80)
            print(f"{'Resource':<12} {'Role':<18} {'Disk State':<22} {'Connection':<15} {'Status':<10}")
            print("-" * 80)
            for resource in resources:
                role = f"{resource.get('local_role', '?')}/{resource.get('peer_role', '?')}"
                disk = f"{resource.get('local_disk_state', '?')}/{resource.get('peer_disk_state', '?')}"
                conn = resource.get('connection_state', 'Unknown') or 'N/A'

                status = "OK"
                if resource.get('local_disk_state') != 'UpToDate':
                    status = "DEGRADED"
                if resource.get('connection_state') in ['StandAlone', 'Disconnecting']:
                    status = "CRITICAL"

                print(f"{resource['name']:<12} {role:<18} {disk:<22} {conn:<15} {status:<10}")

                if resource.get('sync_percent') is not None:
                    print(f"  -> Syncing: {resource['sync_percent']:.1f}% complete")

            print("=" * 80)
            print()

    # Print issues
    if issues:
        print("ISSUES DETECTED")
        print("=" * 80)
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
        description='Monitor DRBD replication health and synchronization status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Check DRBD health
  %(prog)s --format json            # JSON output for monitoring tools
  %(prog)s --verbose                # Show detailed resource information
  %(prog)s --warn-only              # Only show warnings/errors
  %(prog)s --sync-warn 50           # Warn if sync below 50%%

Thresholds:
  --sync-warn: Warn if sync percent < this value (default: 90)
  --sync-crit: Critical if sync percent < this value (default: 50)

Exit codes:
  0 - All DRBD resources healthy and synchronized
  1 - Warnings or critical issues detected
  2 - Usage error or DRBD not available
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
        help='Show detailed resource information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors, suppress normal output'
    )

    parser.add_argument(
        '--sync-warn',
        type=float,
        default=90.0,
        metavar='PERCENT',
        help='Warn if sync percent < PERCENT (default: 90)'
    )

    parser.add_argument(
        '--sync-crit',
        type=float,
        default=50.0,
        metavar='PERCENT',
        help='Critical if sync percent < PERCENT (default: 50)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.sync_warn < 0 or args.sync_warn > 100:
        print("Error: --sync-warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.sync_crit < 0 or args.sync_crit > 100:
        print("Error: --sync-crit must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.sync_warn < args.sync_crit:
        print("Error: --sync-warn must be >= --sync-crit", file=sys.stderr)
        sys.exit(2)

    # Check for DRBD tools
    if not check_drbd_available():
        print("Error: DRBD tools not found (drbdadm)", file=sys.stderr)
        print("Install with: sudo apt-get install drbd-utils", file=sys.stderr)
        sys.exit(2)

    # Check if DRBD module is loaded
    if not check_drbd_module_loaded():
        if args.format == 'json':
            print(json.dumps({
                'message': 'DRBD kernel module not loaded',
                'issues': []
            }))
        else:
            print("DRBD kernel module is not loaded.")
            print("Load with: sudo modprobe drbd")
        sys.exit(2)

    # Get DRBD resources
    resources = get_drbd_resources()

    if not resources:
        if args.format == 'json':
            print(json.dumps({
                'message': 'No DRBD resources configured',
                'summary': {'resources': 0, 'healthy': 0, 'degraded': 0},
                'issues': []
            }))
        else:
            print("No DRBD resources configured on this system.")
        sys.exit(0)

    # Analyze for issues
    issues = analyze_resources(resources, args.sync_warn, args.sync_crit)

    # Output results
    if args.format == 'json':
        output_json(resources, issues, args.verbose)
    elif args.format == 'table':
        output_table(resources, issues, args.verbose, args.warn_only)
    else:  # plain
        output_plain(resources, issues, args.verbose, args.warn_only)

    # Determine exit code based on issues
    has_critical = any(issue['severity'] == 'CRITICAL' for issue in issues)
    has_warning = any(issue['severity'] == 'WARNING' for issue in issues)

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
