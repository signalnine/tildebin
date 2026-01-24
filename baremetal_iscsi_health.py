#!/usr/bin/env python3
"""
Monitor iSCSI session health and connectivity on baremetal servers.

This script checks iSCSI initiator health including:
- Active iSCSI sessions and their state
- Target connectivity and availability
- Session error counts and recovery events
- Multipath status for iSCSI devices
- Portal connectivity and redundancy

Useful for monitoring SAN storage connectivity in baremetal datacenters.

Exit codes:
    0 - All iSCSI sessions healthy
    1 - Issues found (degraded sessions, errors, connectivity problems)
    2 - Usage error or required tools not available
"""

import argparse
import json
import os
import re
import subprocess
import sys


def run_command(cmd):
    """Execute a command and return output."""
    try:
        if isinstance(cmd, str):
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def check_tool_available(tool_name):
    """Check if a tool is available in PATH."""
    returncode, _, _ = run_command(f"which {tool_name}")
    return returncode == 0


def check_iscsiadm_available():
    """Check if iscsiadm is installed."""
    if not check_tool_available("iscsiadm"):
        print("Error: iscsiadm not found in PATH", file=sys.stderr)
        print("Install with: sudo apt-get install open-iscsi", file=sys.stderr)
        print("         or: sudo yum install iscsi-initiator-utils", file=sys.stderr)
        return False
    return True


def get_iscsi_sessions():
    """Get list of active iSCSI sessions."""
    returncode, stdout, stderr = run_command("iscsiadm -m session")

    if returncode != 0:
        if "No active sessions" in stderr:
            return []
        return None

    sessions = []
    for line in stdout.strip().split('\n'):
        if not line:
            continue

        # Parse session line: transport: [sid] ip:port,tpgt targetname
        # Example: tcp: [1] 192.168.1.100:3260,1 iqn.2023-01.com.example:target1
        match = re.match(r'(\w+):\s+\[(\d+)\]\s+([\d.]+):(\d+),(\d+)\s+(.+)', line)
        if match:
            sessions.append({
                'transport': match.group(1),
                'sid': match.group(2),
                'portal_ip': match.group(3),
                'portal_port': match.group(4),
                'tpgt': match.group(5),
                'target': match.group(6)
            })

    return sessions


def get_session_details(sid):
    """Get detailed information for a specific session."""
    returncode, stdout, stderr = run_command(f"iscsiadm -m session -r {sid} -P 3")

    if returncode != 0:
        return None

    details = {
        'state': 'unknown',
        'internal_iscsid_state': 'unknown',
        'recovery_count': 0,
        'timeout_errors': 0,
        'login_errors': 0,
        'devices': [],
        'connections': []
    }

    current_section = None
    current_device = None

    for line in stdout.split('\n'):
        line = line.strip()

        # Session state
        if 'iSCSI Session State:' in line:
            details['state'] = line.split(':')[1].strip()
        elif 'Internal iscsid Session State:' in line:
            details['internal_iscsid_state'] = line.split(':')[1].strip()

        # Error counts from session stats
        if 'recovery_tmo:' in line:
            match = re.search(r'recovery_tmo:\s*(\d+)', line)
            if match:
                details['recovery_timeout'] = int(match.group(1))

        # Connection info
        if 'Connection:' in line:
            current_section = 'connection'
            conn = {'state': 'unknown'}
            details['connections'].append(conn)
        elif current_section == 'connection':
            if 'Persistent Portal:' in line:
                details['connections'][-1]['portal'] = line.split(':')[1].strip() + ':' + line.split(':')[2].strip() if len(line.split(':')) > 2 else line.split(':')[1].strip()
            elif 'Connection State:' in line:
                details['connections'][-1]['state'] = line.split(':')[1].strip()

        # Device info
        if 'Attached scsi disk' in line:
            match = re.search(r'Attached scsi disk\s+(\w+)\s+State:\s+(\w+)', line)
            if match:
                details['devices'].append({
                    'name': match.group(1),
                    'state': match.group(2)
                })

    return details


def get_session_stats(sid):
    """Get session statistics (error counts)."""
    returncode, stdout, stderr = run_command(f"iscsiadm -m session -r {sid} -s")

    if returncode != 0:
        return None

    stats = {
        'txdata_octets': 0,
        'rxdata_octets': 0,
        'dataout_pdus': 0,
        'datain_pdus': 0,
        'timeout_errors': 0,
        'digest_errors': 0,
        'connection_errors': 0
    }

    for line in stdout.split('\n'):
        line = line.strip()

        if 'txdata_octets:' in line:
            match = re.search(r'txdata_octets:\s*(\d+)', line)
            if match:
                stats['txdata_octets'] = int(match.group(1))
        elif 'rxdata_octets:' in line:
            match = re.search(r'rxdata_octets:\s*(\d+)', line)
            if match:
                stats['rxdata_octets'] = int(match.group(1))
        elif 'timeout_err:' in line:
            match = re.search(r'timeout_err:\s*(\d+)', line)
            if match:
                stats['timeout_errors'] = int(match.group(1))
        elif 'digest_err:' in line:
            match = re.search(r'digest_err:\s*(\d+)', line)
            if match:
                stats['digest_errors'] = int(match.group(1))

    return stats


def get_multipath_status():
    """Get multipath status for iSCSI devices if multipath is configured."""
    if not check_tool_available("multipath"):
        return None

    returncode, stdout, stderr = run_command("multipath -ll")

    if returncode != 0:
        return None

    multipaths = []
    current_mpath = None

    for line in stdout.split('\n'):
        # New multipath device line
        if line and not line.startswith(' ') and not line.startswith('\t'):
            if current_mpath:
                multipaths.append(current_mpath)

            parts = line.split()
            if len(parts) >= 2:
                current_mpath = {
                    'name': parts[0],
                    'wwid': parts[1] if len(parts) > 1 else 'unknown',
                    'paths': [],
                    'status': 'unknown'
                }

                # Look for status in dm-X format
                if 'dm-' in line:
                    current_mpath['dm_device'] = re.search(r'dm-\d+', line).group() if re.search(r'dm-\d+', line) else None

        # Path line
        elif current_mpath and ('running' in line or 'faulty' in line or 'active' in line):
            path_match = re.search(r'(\d+:\d+:\d+:\d+)\s+(\w+)\s+\d+:\d+\s+(\w+)\s+(\w+)', line)
            if path_match:
                current_mpath['paths'].append({
                    'hctl': path_match.group(1),
                    'device': path_match.group(2),
                    'dm_state': path_match.group(3),
                    'path_state': path_match.group(4)
                })

    if current_mpath:
        multipaths.append(current_mpath)

    return multipaths


def check_portal_connectivity(portal_ip, portal_port):
    """Check if portal is reachable."""
    returncode, _, _ = run_command(f"timeout 5 bash -c 'echo > /dev/tcp/{portal_ip}/{portal_port}' 2>/dev/null")
    return returncode == 0


def analyze_session(session, details, stats, verbose):
    """Analyze a session and return issues found."""
    issues = []
    warnings = []

    target = session['target']
    sid = session['sid']
    portal = f"{session['portal_ip']}:{session['portal_port']}"

    # Check session state
    if details:
        if details['state'] != 'LOGGED_IN':
            issues.append(f"Session not logged in (state: {details['state']})")

        # Check connection states
        for conn in details.get('connections', []):
            if conn.get('state') != 'LOGGED_IN':
                issues.append(f"Connection degraded (state: {conn.get('state', 'unknown')})")

        # Check attached devices
        for device in details.get('devices', []):
            if device['state'] != 'running':
                issues.append(f"Device {device['name']} not running (state: {device['state']})")

    # Check stats for errors
    if stats:
        if stats['timeout_errors'] > 0:
            warnings.append(f"Timeout errors: {stats['timeout_errors']}")
        if stats['digest_errors'] > 0:
            warnings.append(f"Digest errors: {stats['digest_errors']}")

    # Check portal connectivity
    if not check_portal_connectivity(session['portal_ip'], session['portal_port']):
        issues.append(f"Portal {portal} not reachable")

    return issues, warnings


def analyze_multipath(multipaths):
    """Analyze multipath configuration for issues."""
    issues = []
    warnings = []

    if not multipaths:
        return issues, warnings

    for mpath in multipaths:
        active_paths = 0
        faulty_paths = 0

        for path in mpath.get('paths', []):
            if path.get('path_state') == 'active' or path.get('dm_state') == 'active':
                active_paths += 1
            elif path.get('path_state') == 'faulty' or path.get('dm_state') == 'faulty':
                faulty_paths += 1

        total_paths = len(mpath.get('paths', []))

        if faulty_paths > 0:
            issues.append(f"Multipath {mpath['name']}: {faulty_paths}/{total_paths} paths faulty")
        elif active_paths < total_paths and total_paths > 1:
            warnings.append(f"Multipath {mpath['name']}: only {active_paths}/{total_paths} paths active")
        elif active_paths == 1 and total_paths == 1:
            warnings.append(f"Multipath {mpath['name']}: single path (no redundancy)")

    return issues, warnings


def print_plain(results, warn_only, verbose):
    """Print results in plain text format."""
    sessions = results['sessions']
    multipath = results.get('multipath')
    has_issues = False

    if not sessions:
        print("No active iSCSI sessions found")
        return False

    print("iSCSI Session Health Report")
    print("=" * 60)

    for session_result in sessions:
        session = session_result['session']
        details = session_result.get('details', {})
        stats = session_result.get('stats', {})
        issues = session_result['issues']
        warnings = session_result['warnings']

        if warn_only and not issues and not warnings:
            continue

        if issues:
            has_issues = True
            status = "ERROR"
        elif warnings:
            status = "WARN"
        else:
            status = "OK"

        portal = f"{session['portal_ip']}:{session['portal_port']}"
        print(f"\n[{status}] Target: {session['target']}")
        print(f"     Portal: {portal} (SID: {session['sid']})")

        if details:
            state = details.get('state', 'unknown')
            print(f"     State: {state}")

            if verbose and details.get('devices'):
                print("     Devices:")
                for device in details['devices']:
                    print(f"       - {device['name']}: {device['state']}")

        if verbose and stats:
            tx = stats.get('txdata_octets', 0)
            rx = stats.get('rxdata_octets', 0)
            print(f"     I/O: TX {tx} bytes, RX {rx} bytes")

        if issues:
            print("     Issues:")
            for issue in issues:
                print(f"       - {issue}")

        if warnings:
            print("     Warnings:")
            for warning in warnings:
                print(f"       - {warning}")

    # Multipath status
    if multipath:
        print("\n" + "-" * 60)
        print("Multipath Status:")

        mp_issues = results.get('multipath_issues', [])
        mp_warnings = results.get('multipath_warnings', [])

        if mp_issues:
            has_issues = True

        for mpath in multipath:
            path_count = len(mpath.get('paths', []))
            active = sum(1 for p in mpath.get('paths', []) if p.get('path_state') == 'active' or p.get('dm_state') == 'active')
            print(f"  {mpath['name']}: {active}/{path_count} paths active")

        if mp_issues:
            print("  Issues:")
            for issue in mp_issues:
                print(f"    - {issue}")

        if mp_warnings:
            print("  Warnings:")
            for warning in mp_warnings:
                print(f"    - {warning}")

    # Summary
    print("\n" + "=" * 60)
    total = len(sessions)
    with_issues = sum(1 for s in sessions if s['issues'])
    with_warnings = sum(1 for s in sessions if s['warnings'])
    print(f"Summary: {total} sessions, {with_issues} with errors, {with_warnings} with warnings")

    return has_issues or with_issues > 0


def print_json(results):
    """Print results in JSON format."""
    print(json.dumps(results, indent=2))
    return any(s['issues'] for s in results['sessions'])


def main():
    parser = argparse.ArgumentParser(
        description='Monitor iSCSI session health and connectivity',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check all iSCSI sessions
  %(prog)s --warn-only          # Show only sessions with issues
  %(prog)s --format json        # JSON output for monitoring
  %(prog)s -v                   # Verbose output with device details

Exit codes:
  0 - All iSCSI sessions healthy
  1 - Issues found (degraded sessions, errors)
  2 - Usage error or iscsiadm not available
        """
    )

    parser.add_argument(
        '--format', '-f',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '--warn-only', '-w',
        action='store_true',
        help='Only show sessions with warnings or issues'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed session information'
    )

    parser.add_argument(
        '--skip-multipath',
        action='store_true',
        help='Skip multipath status check'
    )

    args = parser.parse_args()

    # Check for iscsiadm
    if not check_iscsiadm_available():
        sys.exit(2)

    # Get sessions
    sessions = get_iscsi_sessions()
    if sessions is None:
        print("Error: Failed to get iSCSI sessions", file=sys.stderr)
        sys.exit(1)

    # Analyze each session
    session_results = []
    for session in sessions:
        details = get_session_details(session['sid'])
        stats = get_session_stats(session['sid'])
        issues, warnings = analyze_session(session, details, stats, args.verbose)

        session_results.append({
            'session': session,
            'details': details,
            'stats': stats,
            'issues': issues,
            'warnings': warnings
        })

    # Get multipath status
    multipath = None
    mp_issues = []
    mp_warnings = []

    if not args.skip_multipath:
        multipath = get_multipath_status()
        if multipath:
            mp_issues, mp_warnings = analyze_multipath(multipath)

    results = {
        'sessions': session_results,
        'multipath': multipath,
        'multipath_issues': mp_issues,
        'multipath_warnings': mp_warnings,
        'summary': {
            'total_sessions': len(sessions),
            'sessions_with_issues': sum(1 for s in session_results if s['issues']),
            'sessions_with_warnings': sum(1 for s in session_results if s['warnings'])
        }
    }

    # Output
    if args.format == 'json':
        has_issues = print_json(results)
    else:
        has_issues = print_plain(results, args.warn_only, args.verbose)

    sys.exit(1 if has_issues else 0)


if __name__ == '__main__':
    main()
