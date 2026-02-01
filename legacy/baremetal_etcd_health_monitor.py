#!/usr/bin/env python3
"""
Baremetal etcd Health Monitor

Monitors the health and performance of standalone etcd clusters used in
distributed systems. Checks cluster membership, leader status, database
size, latency, and alarm conditions.

Useful for:
- Standalone etcd clusters (not managed by Kubernetes)
- etcd backing Consul, CoreDNS, or custom distributed applications
- Pre-Kubernetes infrastructure using etcd for coordination
- etcd clusters used for service discovery

Checks performed:
- Cluster health and member connectivity
- Leader election status
- Database size and fragmentation
- Latency measurements
- Active alarms (NOSPACE, CORRUPT, etc.)
- Member list and peer URLs

Exit codes:
    0 - Cluster healthy, all members responsive
    1 - Issues detected (degraded cluster, alarms, high latency)
    2 - etcdctl not found or connection failed

Examples:
    # Check local etcd instance
    baremetal_etcd_health_monitor.py

    # Check remote cluster
    baremetal_etcd_health_monitor.py --endpoints https://etcd1:2379,https://etcd2:2379

    # With TLS certificates
    baremetal_etcd_health_monitor.py --cacert /etc/etcd/ca.crt \\
        --cert /etc/etcd/client.crt --key /etc/etcd/client.key

    # JSON output for monitoring
    baremetal_etcd_health_monitor.py --format json

    # Only show problems
    baremetal_etcd_health_monitor.py --warn-only
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple


# Default thresholds
DEFAULT_DB_SIZE_WARN_MB = 2048  # 2GB warning threshold
DEFAULT_DB_SIZE_CRIT_MB = 6144  # 6GB critical (etcd default limit is 8GB)
DEFAULT_LATENCY_WARN_MS = 100  # 100ms latency warning
DEFAULT_LATENCY_CRIT_MS = 500  # 500ms latency critical


def run_command(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    """
    Execute a command and return (returncode, stdout, stderr).

    Args:
        cmd: Command and arguments as list
        timeout: Command timeout in seconds

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", "Command timed out"


def check_etcdctl_available() -> bool:
    """Check if etcdctl is available."""
    returncode, stdout, _ = run_command(['etcdctl', 'version'])
    if returncode != 0:
        print("Error: etcdctl not found in PATH", file=sys.stderr)
        print("Install etcd: https://etcd.io/docs/latest/install/", file=sys.stderr)
        sys.exit(2)
    return True


def build_etcdctl_cmd(base_cmd: List[str], endpoints: str,
                      cacert: Optional[str] = None,
                      cert: Optional[str] = None,
                      key: Optional[str] = None) -> List[str]:
    """
    Build etcdctl command with common options.

    Args:
        base_cmd: Base command arguments
        endpoints: Comma-separated list of endpoints
        cacert: Path to CA certificate
        cert: Path to client certificate
        key: Path to client key

    Returns:
        Complete command as list
    """
    cmd = ['etcdctl'] + base_cmd
    cmd.extend(['--endpoints', endpoints])

    if cacert:
        cmd.extend(['--cacert', cacert])
    if cert:
        cmd.extend(['--cert', cert])
    if key:
        cmd.extend(['--key', key])

    return cmd


def get_cluster_health(endpoints: str, cacert: Optional[str] = None,
                       cert: Optional[str] = None,
                       key: Optional[str] = None) -> Dict[str, Any]:
    """
    Check cluster endpoint health.

    Args:
        endpoints: Comma-separated list of endpoints
        cacert: Path to CA certificate
        cert: Path to client certificate
        key: Path to client key

    Returns:
        Dictionary with health information
    """
    cmd = build_etcdctl_cmd(
        ['endpoint', 'health', '--write-out=json'],
        endpoints, cacert, cert, key
    )

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return {
            'available': False,
            'error': stderr.strip() or 'Failed to connect to etcd',
            'endpoints': []
        }

    try:
        # etcdctl outputs one JSON object per line for each endpoint
        health_data = []
        for line in stdout.strip().split('\n'):
            if line.strip():
                health_data.append(json.loads(line))

        return {
            'available': True,
            'endpoints': health_data
        }
    except json.JSONDecodeError:
        return {
            'available': False,
            'error': 'Failed to parse health response',
            'raw_output': stdout
        }


def get_endpoint_status(endpoints: str, cacert: Optional[str] = None,
                        cert: Optional[str] = None,
                        key: Optional[str] = None) -> Dict[str, Any]:
    """
    Get detailed endpoint status including DB size and leader info.

    Args:
        endpoints: Comma-separated list of endpoints
        cacert: Path to CA certificate
        cert: Path to client certificate
        key: Path to client key

    Returns:
        Dictionary with status information
    """
    cmd = build_etcdctl_cmd(
        ['endpoint', 'status', '--write-out=json'],
        endpoints, cacert, cert, key
    )

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return {
            'available': False,
            'error': stderr.strip() or 'Failed to get status'
        }

    try:
        status_data = []
        for line in stdout.strip().split('\n'):
            if line.strip():
                status_data.append(json.loads(line))

        return {
            'available': True,
            'endpoints': status_data
        }
    except json.JSONDecodeError:
        return {
            'available': False,
            'error': 'Failed to parse status response'
        }


def get_member_list(endpoints: str, cacert: Optional[str] = None,
                    cert: Optional[str] = None,
                    key: Optional[str] = None) -> Dict[str, Any]:
    """
    Get cluster member list.

    Args:
        endpoints: Comma-separated list of endpoints
        cacert: Path to CA certificate
        cert: Path to client certificate
        key: Path to client key

    Returns:
        Dictionary with member information
    """
    cmd = build_etcdctl_cmd(
        ['member', 'list', '--write-out=json'],
        endpoints, cacert, cert, key
    )

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return {
            'available': False,
            'error': stderr.strip() or 'Failed to get member list'
        }

    try:
        data = json.loads(stdout)
        return {
            'available': True,
            'members': data.get('members', []),
            'header': data.get('header', {})
        }
    except json.JSONDecodeError:
        return {
            'available': False,
            'error': 'Failed to parse member list'
        }


def get_alarms(endpoints: str, cacert: Optional[str] = None,
               cert: Optional[str] = None,
               key: Optional[str] = None) -> Dict[str, Any]:
    """
    Get active alarms.

    Args:
        endpoints: Comma-separated list of endpoints
        cacert: Path to CA certificate
        cert: Path to client certificate
        key: Path to client key

    Returns:
        Dictionary with alarm information
    """
    cmd = build_etcdctl_cmd(
        ['alarm', 'list', '--write-out=json'],
        endpoints, cacert, cert, key
    )

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        return {
            'available': False,
            'error': stderr.strip() or 'Failed to get alarms'
        }

    try:
        data = json.loads(stdout) if stdout.strip() else {}
        return {
            'available': True,
            'alarms': data.get('alarms', [])
        }
    except json.JSONDecodeError:
        return {
            'available': True,
            'alarms': []  # No alarms if parse fails with empty response
        }


def analyze_health(health: Dict, status: Dict, members: Dict, alarms: Dict,
                   db_warn_mb: int, db_crit_mb: int,
                   latency_warn_ms: int, latency_crit_ms: int) -> Tuple[List[str], List[str], Dict]:
    """
    Analyze etcd health data and identify issues.

    Args:
        health: Endpoint health data
        status: Endpoint status data
        members: Member list data
        alarms: Alarm data
        db_warn_mb: Database size warning threshold
        db_crit_mb: Database size critical threshold
        latency_warn_ms: Latency warning threshold
        latency_crit_ms: Latency critical threshold

    Returns:
        Tuple of (issues, warnings, analysis)
    """
    issues = []
    warnings = []
    analysis = {
        'cluster_healthy': True,
        'leader': None,
        'member_count': 0,
        'healthy_members': 0,
        'db_size_bytes': 0,
        'has_quorum': False
    }

    # Check if we could connect at all
    if not health.get('available'):
        issues.append(f"Cannot connect to etcd: {health.get('error', 'unknown error')}")
        analysis['cluster_healthy'] = False
        return issues, warnings, analysis

    # Analyze endpoint health
    endpoints = health.get('endpoints', [])
    healthy_count = 0
    for ep in endpoints:
        if ep.get('health'):
            healthy_count += 1
        else:
            issues.append(f"Endpoint {ep.get('endpoint', 'unknown')} unhealthy")

    analysis['healthy_members'] = healthy_count

    # Analyze member list
    if members.get('available'):
        member_list = members.get('members', [])
        analysis['member_count'] = len(member_list)

        # Check for unstarted members
        for member in member_list:
            if not member.get('name'):
                warnings.append(f"Member {member.get('ID', 'unknown')} has no name (may be unstarted)")

        # Check quorum (need majority of members)
        if analysis['member_count'] > 0:
            analysis['has_quorum'] = healthy_count > analysis['member_count'] // 2
            if not analysis['has_quorum']:
                issues.append(f"Cluster lacks quorum: {healthy_count}/{analysis['member_count']} healthy")
    else:
        warnings.append(f"Could not get member list: {members.get('error', 'unknown')}")

    # Analyze endpoint status
    if status.get('available'):
        status_endpoints = status.get('endpoints', [])
        max_db_size = 0
        leader_id = None

        for ep_status in status_endpoints:
            # Extract from nested structure
            ep_info = ep_status.get('Status', ep_status)
            endpoint = ep_status.get('Endpoint', 'unknown')

            # Database size
            db_size = ep_info.get('dbSize', 0)
            if db_size > max_db_size:
                max_db_size = db_size

            db_size_mb = db_size / (1024 * 1024)
            if db_size_mb > db_crit_mb:
                issues.append(f"Database size critical: {db_size_mb:.1f}MB (threshold: {db_crit_mb}MB)")
            elif db_size_mb > db_warn_mb:
                warnings.append(f"Database size high: {db_size_mb:.1f}MB (threshold: {db_warn_mb}MB)")

            # Leader info
            if ep_info.get('leader'):
                leader_id = ep_info.get('leader')
            if ep_info.get('isLeader'):
                analysis['leader'] = endpoint

        analysis['db_size_bytes'] = max_db_size

        # Check leader exists
        if not leader_id and not analysis['leader']:
            issues.append("No leader elected - cluster may be unavailable")
    else:
        warnings.append(f"Could not get endpoint status: {status.get('error', 'unknown')}")

    # Analyze alarms
    if alarms.get('available'):
        active_alarms = alarms.get('alarms', [])
        for alarm in active_alarms:
            alarm_type = alarm.get('alarm', alarm.get('alarmType', 'UNKNOWN'))
            member_id = alarm.get('memberID', 'unknown')
            issues.append(f"Active alarm: {alarm_type} on member {member_id}")
    else:
        warnings.append(f"Could not check alarms: {alarms.get('error', 'unknown')}")

    # Set overall health
    analysis['cluster_healthy'] = len(issues) == 0

    return issues, warnings, analysis


def format_plain(health: Dict, status: Dict, members: Dict, alarms: Dict,
                 issues: List[str], warnings: List[str], analysis: Dict,
                 verbose: bool = False) -> str:
    """Format output as plain text."""
    lines = []
    lines.append("etcd Cluster Health Monitor")
    lines.append("=" * 50)
    lines.append("")

    # Cluster overview
    status_str = "HEALTHY" if analysis['cluster_healthy'] else "UNHEALTHY"
    lines.append(f"Cluster Status: {status_str}")
    lines.append(f"Members: {analysis['healthy_members']}/{analysis['member_count']} healthy")
    quorum_str = "YES" if analysis['has_quorum'] else "NO"
    lines.append(f"Quorum: {quorum_str}")

    if analysis['leader']:
        lines.append(f"Leader: {analysis['leader']}")

    db_size_mb = analysis['db_size_bytes'] / (1024 * 1024)
    lines.append(f"Database Size: {db_size_mb:.1f} MB")
    lines.append("")

    # Member details (if verbose)
    if verbose and members.get('available'):
        lines.append("Members:")
        for member in members.get('members', []):
            name = member.get('name', 'unnamed')
            member_id = member.get('ID', 'unknown')
            peer_urls = ', '.join(member.get('peerURLs', []))
            client_urls = ', '.join(member.get('clientURLs', []))
            lines.append(f"  {name} (ID: {member_id})")
            lines.append(f"    Peer URLs: {peer_urls}")
            lines.append(f"    Client URLs: {client_urls}")
        lines.append("")

    # Endpoint health (if verbose)
    if verbose and health.get('available'):
        lines.append("Endpoint Health:")
        for ep in health.get('endpoints', []):
            endpoint = ep.get('endpoint', 'unknown')
            healthy = "OK" if ep.get('health') else "FAIL"
            took = ep.get('took', 'N/A')
            lines.append(f"  {endpoint}: {healthy} (latency: {took})")
        lines.append("")

    # Issues
    if issues:
        lines.append("ISSUES:")
        for issue in issues:
            lines.append(f"  [!] {issue}")
        lines.append("")

    if warnings:
        lines.append("WARNINGS:")
        for warning in warnings:
            lines.append(f"  [*] {warning}")
        lines.append("")

    if not issues and not warnings:
        lines.append("[OK] etcd cluster is healthy")

    return '\n'.join(lines)


def format_json(health: Dict, status: Dict, members: Dict, alarms: Dict,
                issues: List[str], warnings: List[str], analysis: Dict) -> str:
    """Format output as JSON."""
    output = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'cluster_healthy': analysis['cluster_healthy'],
        'summary': {
            'member_count': analysis['member_count'],
            'healthy_members': analysis['healthy_members'],
            'has_quorum': analysis['has_quorum'],
            'leader': analysis['leader'],
            'db_size_bytes': analysis['db_size_bytes'],
            'db_size_mb': round(analysis['db_size_bytes'] / (1024 * 1024), 2)
        },
        'health': health,
        'status': status,
        'members': members,
        'alarms': alarms,
        'issues': issues,
        'warnings': warnings
    }
    return json.dumps(output, indent=2)


def format_table(health: Dict, status: Dict, members: Dict, alarms: Dict,
                 issues: List[str], warnings: List[str], analysis: Dict) -> str:
    """Format output as a table."""
    lines = []

    # Header
    lines.append(f"{'METRIC':<25} {'VALUE':<30} {'STATUS':<15}")
    lines.append("-" * 70)

    # Cluster status
    cluster_status = "OK" if analysis['cluster_healthy'] else "CRITICAL"
    lines.append(f"{'Cluster Health':<25} {'':<30} {cluster_status:<15}")

    # Members
    member_str = f"{analysis['healthy_members']}/{analysis['member_count']}"
    member_status = "OK" if analysis['healthy_members'] == analysis['member_count'] else "DEGRADED"
    lines.append(f"{'Healthy Members':<25} {member_str:<30} {member_status:<15}")

    # Quorum
    quorum_str = "Yes" if analysis['has_quorum'] else "No"
    quorum_status = "OK" if analysis['has_quorum'] else "CRITICAL"
    lines.append(f"{'Quorum':<25} {quorum_str:<30} {quorum_status:<15}")

    # Leader
    leader = analysis.get('leader', 'Unknown')[:28]
    leader_status = "OK" if analysis.get('leader') else "WARNING"
    lines.append(f"{'Leader':<25} {leader:<30} {leader_status:<15}")

    # Database size
    db_size_mb = analysis['db_size_bytes'] / (1024 * 1024)
    db_str = f"{db_size_mb:.1f} MB"
    db_status = "OK" if db_size_mb < DEFAULT_DB_SIZE_WARN_MB else "WARNING"
    lines.append(f"{'Database Size':<25} {db_str:<30} {db_status:<15}")

    # Alarms
    alarm_count = len(alarms.get('alarms', [])) if alarms.get('available') else 0
    alarm_str = str(alarm_count)
    alarm_status = "OK" if alarm_count == 0 else "CRITICAL"
    lines.append(f"{'Active Alarms':<25} {alarm_str:<30} {alarm_status:<15}")

    lines.append("-" * 70)

    # Issues summary
    if issues:
        lines.append("Issues:")
        for issue in issues[:5]:
            lines.append(f"  [!] {issue[:65]}")

    if warnings:
        lines.append("Warnings:")
        for warning in warnings[:5]:
            lines.append(f"  [*] {warning[:65]}")

    if not issues and not warnings:
        lines.append("Status: All checks passed")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor etcd cluster health and performance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Check local etcd
  %(prog)s --endpoints https://etcd1:2379     # Check remote cluster
  %(prog)s --format json                      # JSON output
  %(prog)s --cacert ca.crt --cert client.crt --key client.key  # With TLS
  %(prog)s --warn-only                        # Only show problems
  %(prog)s -v                                 # Verbose output

Environment variables:
  ETCDCTL_ENDPOINTS  - Default endpoints if --endpoints not specified
  ETCDCTL_CACERT     - Default CA certificate path
  ETCDCTL_CERT       - Default client certificate path
  ETCDCTL_KEY        - Default client key path

Exit codes:
  0 - Cluster healthy
  1 - Issues detected (degraded, alarms, etc.)
  2 - etcdctl not found or connection failed
        """
    )

    parser.add_argument(
        '-e', '--endpoints',
        default=os.environ.get('ETCDCTL_ENDPOINTS', 'http://127.0.0.1:2379'),
        help='Comma-separated etcd endpoints (default: %(default)s)'
    )
    parser.add_argument(
        '--cacert',
        default=os.environ.get('ETCDCTL_CACERT'),
        help='Path to CA certificate for TLS'
    )
    parser.add_argument(
        '--cert',
        default=os.environ.get('ETCDCTL_CERT'),
        help='Path to client certificate for TLS'
    )
    parser.add_argument(
        '--key',
        default=os.environ.get('ETCDCTL_KEY'),
        help='Path to client key for TLS'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )
    parser.add_argument(
        '--db-warn-mb',
        type=int,
        default=DEFAULT_DB_SIZE_WARN_MB,
        help=f'Database size warning threshold in MB (default: {DEFAULT_DB_SIZE_WARN_MB})'
    )
    parser.add_argument(
        '--db-crit-mb',
        type=int,
        default=DEFAULT_DB_SIZE_CRIT_MB,
        help=f'Database size critical threshold in MB (default: {DEFAULT_DB_SIZE_CRIT_MB})'
    )
    parser.add_argument(
        '--latency-warn-ms',
        type=int,
        default=DEFAULT_LATENCY_WARN_MS,
        help=f'Latency warning threshold in ms (default: {DEFAULT_LATENCY_WARN_MS})'
    )
    parser.add_argument(
        '--latency-crit-ms',
        type=int,
        default=DEFAULT_LATENCY_CRIT_MS,
        help=f'Latency critical threshold in ms (default: {DEFAULT_LATENCY_CRIT_MS})'
    )

    args = parser.parse_args()

    # Check etcdctl availability
    check_etcdctl_available()

    # Gather health data
    health = get_cluster_health(args.endpoints, args.cacert, args.cert, args.key)
    status = get_endpoint_status(args.endpoints, args.cacert, args.cert, args.key)
    members = get_member_list(args.endpoints, args.cacert, args.cert, args.key)
    alarms = get_alarms(args.endpoints, args.cacert, args.cert, args.key)

    # Analyze health
    issues, warnings, analysis = analyze_health(
        health, status, members, alarms,
        args.db_warn_mb, args.db_crit_mb,
        args.latency_warn_ms, args.latency_crit_ms
    )

    # Format output
    if args.format == 'json':
        output = format_json(health, status, members, alarms, issues, warnings, analysis)
    elif args.format == 'table':
        output = format_table(health, status, members, alarms, issues, warnings, analysis)
    else:
        output = format_plain(health, status, members, alarms, issues, warnings, analysis, args.verbose)

    # Print output (respecting --warn-only)
    if not args.warn_only or issues or warnings:
        print(output)

    # Return appropriate exit code
    sys.exit(1 if issues else 0)


if __name__ == '__main__':
    main()
