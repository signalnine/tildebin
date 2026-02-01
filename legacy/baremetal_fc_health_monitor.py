#!/usr/bin/env python3
"""
Monitor Fibre Channel (FC) host bus adapter (HBA) health for SAN environments.

Fibre Channel is a high-speed networking technology commonly used to connect
servers to storage area networks (SANs) in enterprise datacenters. This script
monitors FC HBA health by checking:

- HBA port states (online, linkdown, offline)
- Port speed and negotiated link speed
- Error counters (invalid CRC, link failures, loss of sync/signal)
- FC fabric login status (FLOGI, PLOGI)
- SCSI target visibility through FC

Common causes of Fibre Channel issues:
- Cable problems (bent, dirty connectors, exceeding distance limits)
- SFP module failures or compatibility issues
- Zoning misconfiguration on FC switches
- Fabric login failures due to WWPN conflicts
- Buffer credit starvation causing performance issues

Remediation:
- Check cable connections and SFP modules
- Verify zoning configuration on FC switches
- Check for WWPN conflicts in fabric nameserver
- Monitor buffer credits with fc_host statistics
- Update HBA firmware and drivers consistently

Exit codes:
    0 - Fibre Channel fabric healthy, no errors
    1 - Warnings or errors detected (error counters, port issues)
    2 - Cannot read FC status or no FC HBAs found
"""

import argparse
import sys
import json
import os
import subprocess
import re


def check_tool_available(tool_name):
    """
    Check if a command-line tool is available.

    Args:
        tool_name: Name of the tool to check

    Returns:
        bool: True if tool is available
    """
    try:
        result = subprocess.run(
            ['which', tool_name],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def run_command(cmd, timeout=30):
    """
    Execute a shell command and return result.

    Args:
        cmd: Command as list of strings
        timeout: Timeout in seconds

    Returns:
        tuple: (returncode, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def read_sysfs_attr(path):
    """
    Read a sysfs attribute file.

    Args:
        path: Path to sysfs file

    Returns:
        str: File contents or None if unreadable
    """
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, PermissionError, FileNotFoundError):
        return None


def get_fc_hosts():
    """
    Get list of Fibre Channel host adapters from /sys/class/fc_host.

    Returns:
        list: List of FC host dictionaries
    """
    hosts = []
    fc_host_path = '/sys/class/fc_host'

    if not os.path.isdir(fc_host_path):
        return hosts

    try:
        for host_name in os.listdir(fc_host_path):
            host_path = os.path.join(fc_host_path, host_name)
            if not os.path.isdir(host_path):
                continue

            host = {
                'name': host_name,
                'path': host_path,
            }

            # Read host attributes
            attrs = [
                'port_state', 'port_type', 'port_name', 'node_name',
                'speed', 'supported_speeds', 'maxframe_size',
                'fabric_name', 'symbolic_name', 'supported_classes',
                'port_id', 'tgtid_bind_type'
            ]

            for attr in attrs:
                attr_path = os.path.join(host_path, attr)
                value = read_sysfs_attr(attr_path)
                if value is not None:
                    host[attr] = value

            # Get statistics
            stats_path = os.path.join(host_path, 'statistics')
            if os.path.isdir(stats_path):
                host['statistics'] = get_fc_statistics(stats_path)

            hosts.append(host)

    except (OSError, IOError):
        pass

    return hosts


def get_fc_statistics(stats_path):
    """
    Get FC port statistics from sysfs.

    Args:
        stats_path: Path to statistics directory

    Returns:
        dict: Statistics values
    """
    stats = {}

    # Error counters (non-zero indicates issues)
    error_counters = [
        'invalid_crc_count',
        'invalid_tx_word_count',
        'link_failure_count',
        'loss_of_signal_count',
        'loss_of_sync_count',
        'prim_seq_protocol_err_count',
        'dumped_frames',
        'error_frames',
        'nos_count',
        'fcp_packet_aborts',
        'fcp_frame_alloc_failures',
    ]

    # Performance/traffic counters
    traffic_counters = [
        'rx_frames',
        'tx_frames',
        'rx_words',
        'tx_words',
        'lip_count',
        'seconds_since_last_reset',
        'fcp_input_megabytes',
        'fcp_output_megabytes',
        'fcp_input_requests',
        'fcp_output_requests',
        'fcp_control_requests',
    ]

    for counter in error_counters + traffic_counters:
        counter_path = os.path.join(stats_path, counter)
        value = read_sysfs_attr(counter_path)
        if value is not None:
            try:
                # Handle hex values (some counters are in hex)
                if value.startswith('0x'):
                    stats[counter] = int(value, 16)
                else:
                    stats[counter] = int(value)
            except ValueError:
                stats[counter] = value

    return stats


def get_fc_remote_ports(host_name):
    """
    Get remote port (target) information for an FC host.

    Args:
        host_name: FC host name (e.g., host0)

    Returns:
        list: List of remote port dictionaries
    """
    remote_ports = []
    rport_base = f'/sys/class/fc_remote_ports'

    if not os.path.isdir(rport_base):
        return remote_ports

    try:
        for rport_name in os.listdir(rport_base):
            rport_path = os.path.join(rport_base, rport_name)
            if not os.path.isdir(rport_path):
                continue

            # Check if this remote port belongs to our host
            # Remote port names are like "rport-0:0-0" where first number is host
            if not rport_name.startswith('rport-'):
                continue

            # Extract host number from rport name
            match = re.match(r'rport-(\d+):', rport_name)
            if not match:
                continue

            rport_host_num = match.group(1)
            host_num = host_name.replace('host', '')

            if rport_host_num != host_num:
                continue

            rport = {
                'name': rport_name,
                'path': rport_path,
            }

            # Read remote port attributes
            attrs = [
                'port_name', 'node_name', 'port_state',
                'roles', 'port_id', 'supported_classes',
                'dev_loss_tmo', 'fast_io_fail_tmo'
            ]

            for attr in attrs:
                attr_path = os.path.join(rport_path, attr)
                value = read_sysfs_attr(attr_path)
                if value is not None:
                    rport[attr] = value

            remote_ports.append(rport)

    except (OSError, IOError):
        pass

    return remote_ports


def get_scsi_hosts_mapping():
    """
    Get mapping of FC hosts to SCSI hosts.

    Returns:
        dict: Mapping of fc_host name to scsi_host info
    """
    mapping = {}
    scsi_host_path = '/sys/class/scsi_host'

    if not os.path.isdir(scsi_host_path):
        return mapping

    try:
        for host_name in os.listdir(scsi_host_path):
            host_path = os.path.join(scsi_host_path, host_name)

            # Check if this is an FC host by looking for fc_host link
            fc_host_link = os.path.join(host_path, 'device', 'fc_host', host_name)
            if os.path.exists(fc_host_link):
                mapping[host_name] = {
                    'scsi_host': host_name,
                    'path': host_path
                }

                # Get additional info
                for attr in ['proc_name', 'state', 'active_mode']:
                    attr_path = os.path.join(host_path, attr)
                    value = read_sysfs_attr(attr_path)
                    if value is not None:
                        mapping[host_name][attr] = value

    except (OSError, IOError):
        pass

    return mapping


def analyze_health(hosts):
    """
    Analyze Fibre Channel health and generate issues list.

    Args:
        hosts: List of FC hosts

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    if not hosts:
        issues.append({
            'severity': 'ERROR',
            'type': 'no_hosts',
            'message': "No Fibre Channel HBAs found. Check if FC kernel modules are loaded (lpfc, qla2xxx, etc)."
        })
        return issues

    for host in hosts:
        host_name = host['name']

        # Check port state
        port_state = host.get('port_state', 'Unknown')
        if port_state != 'Online':
            severity = 'WARNING' if port_state in ['Linkdown', 'Offline'] else 'ERROR'
            issues.append({
                'severity': severity,
                'type': 'port_not_online',
                'host': host_name,
                'port_state': port_state,
                'message': f"{host_name}: Port state is {port_state} (expected Online). "
                          f"Check cable, SFP, and switch port."
            })

        # Check speed
        speed = host.get('speed', 'Unknown')
        if speed == 'Unknown' or speed == 'unknown':
            if port_state == 'Online':
                issues.append({
                    'severity': 'WARNING',
                    'type': 'speed_unknown',
                    'host': host_name,
                    'message': f"{host_name}: Port is Online but speed is unknown."
                })
        elif 'Gbit' in speed:
            # Check for speed mismatch with supported speeds
            supported = host.get('supported_speeds', '')
            if supported and speed not in supported:
                issues.append({
                    'severity': 'INFO',
                    'type': 'speed_mismatch',
                    'host': host_name,
                    'speed': speed,
                    'supported': supported,
                    'message': f"{host_name}: Running at {speed}, supported: {supported}"
                })

        # Check fabric connectivity
        fabric_name = host.get('fabric_name', '')
        if port_state == 'Online' and (not fabric_name or fabric_name == '0x0'):
            issues.append({
                'severity': 'WARNING',
                'type': 'no_fabric',
                'host': host_name,
                'message': f"{host_name}: Port is Online but not logged into fabric. "
                          f"Check zoning and switch configuration."
            })

        # Analyze statistics
        stats = host.get('statistics', {})

        # Error counter thresholds
        error_thresholds = {
            'invalid_crc_count': (0, "CRC errors indicate cable/SFP issues"),
            'link_failure_count': (0, "Link failures indicate physical connectivity problems"),
            'loss_of_signal_count': (0, "Signal loss indicates cable/SFP/distance issues"),
            'loss_of_sync_count': (0, "Sync loss indicates speed negotiation or cable issues"),
            'error_frames': (0, "Error frames indicate protocol-level issues"),
            'fcp_packet_aborts': (10, "Packet aborts may indicate target issues"),
        }

        for counter, (threshold, hint) in error_thresholds.items():
            value = stats.get(counter, 0)
            if isinstance(value, int) and value > threshold:
                # Determine severity based on value
                if value > threshold * 10 + 100:
                    severity = 'ERROR'
                else:
                    severity = 'WARNING'

                issues.append({
                    'severity': severity,
                    'type': 'error_counter',
                    'host': host_name,
                    'counter': counter,
                    'value': value,
                    'message': f"{host_name}: {counter}={value}. {hint}"
                })

        # Get and check remote ports (targets)
        remote_ports = get_fc_remote_ports(host_name)
        host['remote_ports'] = remote_ports

        if port_state == 'Online' and not remote_ports:
            issues.append({
                'severity': 'WARNING',
                'type': 'no_targets',
                'host': host_name,
                'message': f"{host_name}: Port is Online but no remote targets visible. "
                          f"Check zoning configuration."
            })

        # Check remote port health
        for rport in remote_ports:
            rport_state = rport.get('port_state', 'Unknown')
            if rport_state not in ['Online', 'Blocked']:
                issues.append({
                    'severity': 'WARNING',
                    'type': 'target_not_online',
                    'host': host_name,
                    'remote_port': rport['name'],
                    'port_state': rport_state,
                    'message': f"{host_name}: Remote port {rport['name']} is {rport_state}"
                })

    return issues


def format_plain(hosts, issues, verbose=False, warn_only=False):
    """Format output as plain text."""
    lines = []

    if warn_only and not issues:
        return "No Fibre Channel issues detected"

    if not warn_only:
        lines.append("Fibre Channel Health Monitor")
        lines.append("=" * 65)
        lines.append("")

        if hosts:
            lines.append(f"FC Host Bus Adapters: {len(hosts)}")
            for host in hosts:
                port_state = host.get('port_state', 'Unknown')
                speed = host.get('speed', 'Unknown')
                port_name = host.get('port_name', 'N/A')
                node_name = host.get('node_name', 'N/A')
                fabric_name = host.get('fabric_name', 'N/A')

                status_mark = " " if port_state == 'Online' else "!"
                lines.append(f"  {status_mark} {host['name']}: {port_state} at {speed}")
                lines.append(f"      WWPN: {port_name}")
                lines.append(f"      WWNN: {node_name}")
                if fabric_name and fabric_name != '0x0':
                    lines.append(f"      Fabric: {fabric_name}")

                # Show remote ports
                remote_ports = host.get('remote_ports', [])
                if remote_ports:
                    lines.append(f"      Targets: {len(remote_ports)}")
                    if verbose:
                        for rport in remote_ports:
                            rport_state = rport.get('port_state', 'Unknown')
                            rport_wwpn = rport.get('port_name', 'N/A')
                            roles = rport.get('roles', 'N/A')
                            lines.append(f"        - {rport['name']}: {rport_state} ({roles}) WWPN={rport_wwpn}")

                # Show statistics in verbose mode
                if verbose and 'statistics' in host:
                    stats = host['statistics']

                    # Traffic counters
                    rx_frames = stats.get('rx_frames', 0)
                    tx_frames = stats.get('tx_frames', 0)
                    if rx_frames or tx_frames:
                        lines.append(f"      Traffic: RX={rx_frames:,} frames, TX={tx_frames:,} frames")

                    fcp_in = stats.get('fcp_input_megabytes', 0)
                    fcp_out = stats.get('fcp_output_megabytes', 0)
                    if fcp_in or fcp_out:
                        lines.append(f"      FCP I/O: IN={fcp_in:,} MB, OUT={fcp_out:,} MB")

                    # Show non-zero error counters
                    error_counters = [
                        'invalid_crc_count', 'link_failure_count',
                        'loss_of_signal_count', 'loss_of_sync_count',
                        'error_frames', 'fcp_packet_aborts'
                    ]
                    errors = [(k, stats[k]) for k in error_counters
                              if k in stats and isinstance(stats[k], int) and stats[k] > 0]
                    if errors:
                        lines.append(f"      Errors: {', '.join(f'{k}={v}' for k, v in errors)}")

                lines.append("")
        else:
            lines.append("No Fibre Channel HBAs found")
            lines.append("")

    # Issues
    if issues:
        lines.append("Issues Detected:")
        lines.append("-" * 65)
        for issue in sorted(issues, key=lambda x: (
            x['severity'] != 'ERROR',
            x['severity'] != 'WARNING',
            x['severity'] != 'INFO'
        )):
            if issue['severity'] == 'ERROR':
                marker = "!!!"
            elif issue['severity'] == 'WARNING':
                marker = " ! "
            else:
                marker = "   "
            lines.append(f"{marker}[{issue['severity']}] {issue['message']}")
        lines.append("")
    elif not warn_only:
        lines.append("Status: Fibre Channel fabric healthy")

    return '\n'.join(lines)


def format_json(hosts, issues):
    """Format output as JSON."""
    has_errors = any(i['severity'] == 'ERROR' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    # Count total targets
    total_targets = sum(len(h.get('remote_ports', [])) for h in hosts)

    output = {
        'hosts': hosts,
        'issues': issues,
        'healthy': not has_errors and not has_warnings,
        'summary': {
            'host_count': len(hosts),
            'target_count': total_targets,
            'error_count': sum(1 for i in issues if i['severity'] == 'ERROR'),
            'warning_count': sum(1 for i in issues if i['severity'] == 'WARNING'),
        }
    }
    return json.dumps(output, indent=2)


def format_table(hosts, issues):
    """Format output as a table."""
    lines = []

    # Host table
    lines.append(f"{'Host':<10} {'State':<12} {'Speed':<12} {'WWPN':<25} {'Targets':<8}")
    lines.append("=" * 70)

    for host in hosts:
        wwpn = host.get('port_name', 'N/A')
        if wwpn and len(wwpn) > 24:
            wwpn = wwpn[:24] + '...'
        target_count = len(host.get('remote_ports', []))
        lines.append(f"{host['name']:<10} "
                    f"{host.get('port_state', 'N/A'):<12} "
                    f"{host.get('speed', 'N/A'):<12} "
                    f"{wwpn:<25} "
                    f"{target_count:<8}")

    if not hosts:
        lines.append("(no FC HBAs found)")

    # Issues summary
    if issues:
        lines.append("")
        lines.append("Issues:")
        for issue in issues:
            lines.append(f"  [{issue['severity']}] {issue['message']}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor Fibre Channel HBA health for SAN environments',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic FC health check
  %(prog)s -v                       # Show detailed stats and targets
  %(prog)s --format json            # JSON output for scripting
  %(prog)s --warn-only              # Only show if issues detected

Fibre Channel troubleshooting tips:
  - Check port state with: cat /sys/class/fc_host/host*/port_state
  - View HBA info: systool -c fc_host -v (requires sysfsutils)
  - Check targets: ls /sys/class/fc_remote_ports/
  - Verify zoning: Use FC switch management interface
  - Check multipath: multipath -ll

Common FC drivers:
  - lpfc: Emulex/Broadcom HBAs
  - qla2xxx: QLogic/Marvell HBAs
  - bfa: Brocade HBAs

Exit codes:
  0 - Fibre Channel fabric healthy
  1 - Warnings or errors detected
  2 - Cannot read FC status or no HBAs
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
        help='Show detailed statistics and target information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if issues are detected'
    )

    args = parser.parse_args()

    # Check for FC sysfs
    if not os.path.isdir('/sys/class/fc_host'):
        print("Error: /sys/class/fc_host not found", file=sys.stderr)
        print("Fibre Channel kernel modules may not be loaded.", file=sys.stderr)
        print("Try: modprobe lpfc (Emulex) or modprobe qla2xxx (QLogic)", file=sys.stderr)
        sys.exit(2)

    # Gather data
    hosts = get_fc_hosts()

    # If no hosts found, exit with error
    if not hosts:
        if args.format == 'json':
            print(json.dumps({
                'hosts': [],
                'issues': [{'severity': 'ERROR', 'type': 'no_hosts',
                           'message': 'No Fibre Channel HBAs found'}],
                'healthy': False,
                'summary': {
                    'host_count': 0,
                    'target_count': 0,
                    'error_count': 1,
                    'warning_count': 0
                }
            }, indent=2))
        else:
            print("Error: No Fibre Channel HBAs found", file=sys.stderr)
            print("Check if FC hardware is present and modules loaded", file=sys.stderr)
        sys.exit(2)

    # Analyze health
    issues = analyze_health(hosts)

    # Handle warn-only mode with no issues
    if args.warn_only and not issues:
        if args.format == 'json':
            print(json.dumps({'healthy': True, 'issues': []}))
        sys.exit(0)

    # Format output
    if args.format == 'json':
        output = format_json(hosts, issues)
    elif args.format == 'table':
        output = format_table(hosts, issues)
    else:
        output = format_plain(hosts, issues, verbose=args.verbose, warn_only=args.warn_only)

    print(output)

    # Exit code based on severity
    has_errors = any(i['severity'] == 'ERROR' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    if has_errors or has_warnings:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
