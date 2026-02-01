#!/usr/bin/env python3
"""
Monitor InfiniBand and RDMA health for high-performance computing environments.

InfiniBand (IB) is a high-throughput, low-latency networking technology commonly
used in HPC clusters, storage networks, and high-performance datacenters. This
script monitors IB fabric health by checking:

- Port states and physical link status
- Error counters (symbol errors, link recoveries, CRC errors)
- Performance counters (data transmitted/received)
- Subnet manager (SM) connectivity
- RDMA device availability

Common causes of InfiniBand issues:
- Cable problems (bent, dirty connectors, exceeding length limits)
- Faulty HCAs (Host Channel Adapters) or switches
- Subnet manager failover or misconfiguration
- Firmware mismatches across fabric
- Congestion from traffic patterns

Remediation:
- Check cable connections and replace suspect cables
- Clear error counters after fixing issues: perfquery -x -c <lid>
- Verify SM health: sminfo, smpquery
- Update firmware consistently across fabric
- Check for proper RDMA device permissions

Exit codes:
    0 - InfiniBand fabric healthy, no errors
    1 - Warnings or errors detected (error counters, port issues)
    2 - Cannot read InfiniBand status or no IB devices found
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


def get_ib_devices():
    """
    Get list of InfiniBand devices from /sys/class/infiniband.

    Returns:
        list: List of IB device dictionaries
    """
    devices = []
    ib_path = '/sys/class/infiniband'

    if not os.path.isdir(ib_path):
        return devices

    try:
        for device_name in os.listdir(ib_path):
            device_path = os.path.join(ib_path, device_name)
            if not os.path.isdir(device_path):
                continue

            device = {
                'name': device_name,
                'path': device_path,
                'ports': [],
            }

            # Read device attributes
            for attr in ['node_type', 'node_guid', 'fw_ver', 'board_id', 'hca_type']:
                attr_path = os.path.join(device_path, attr)
                if os.path.isfile(attr_path):
                    try:
                        with open(attr_path, 'r') as f:
                            device[attr] = f.read().strip()
                    except (IOError, PermissionError):
                        pass

            # Get port information
            ports_path = os.path.join(device_path, 'ports')
            if os.path.isdir(ports_path):
                for port_name in sorted(os.listdir(ports_path)):
                    port_path = os.path.join(ports_path, port_name)
                    if not os.path.isdir(port_path):
                        continue

                    port_info = {
                        'port': int(port_name),
                        'path': port_path,
                    }

                    # Read port attributes
                    for attr in ['state', 'phys_state', 'rate', 'lid', 'sm_lid', 'link_layer']:
                        attr_path = os.path.join(port_path, attr)
                        if os.path.isfile(attr_path):
                            try:
                                with open(attr_path, 'r') as f:
                                    value = f.read().strip()
                                    # Parse state values like "4: ACTIVE"
                                    if ':' in value:
                                        value = value.split(':', 1)[1].strip()
                                    port_info[attr] = value
                            except (IOError, PermissionError):
                                pass

                    device['ports'].append(port_info)

            devices.append(device)

    except (OSError, IOError):
        pass

    return devices


def get_port_counters(device_name, port_num):
    """
    Get error and performance counters for an IB port.

    Args:
        device_name: IB device name (e.g., mlx5_0)
        port_num: Port number

    Returns:
        dict: Counter values
    """
    counters = {}
    counters_path = f'/sys/class/infiniband/{device_name}/ports/{port_num}/counters'

    if not os.path.isdir(counters_path):
        return counters

    # Error counters (non-zero indicates issues)
    error_counters = [
        'symbol_error',
        'link_error_recovery',
        'link_downed',
        'port_rcv_errors',
        'port_rcv_remote_physical_errors',
        'port_rcv_switch_relay_errors',
        'port_xmit_discards',
        'port_xmit_constraint_errors',
        'port_rcv_constraint_errors',
        'local_link_integrity_errors',
        'excessive_buffer_overrun_errors',
        'VL15_dropped',
    ]

    # Performance counters
    perf_counters = [
        'port_rcv_data',
        'port_xmit_data',
        'port_rcv_packets',
        'port_xmit_packets',
        'unicast_rcv_packets',
        'unicast_xmit_packets',
        'multicast_rcv_packets',
        'multicast_xmit_packets',
    ]

    for counter in error_counters + perf_counters:
        counter_path = os.path.join(counters_path, counter)
        if os.path.isfile(counter_path):
            try:
                with open(counter_path, 'r') as f:
                    value = f.read().strip()
                    counters[counter] = int(value)
            except (IOError, PermissionError, ValueError):
                pass

    return counters


def get_rdma_devices():
    """
    Get RDMA device information from /sys/class/infiniband_verbs.

    Returns:
        list: List of RDMA device info
    """
    devices = []
    verbs_path = '/sys/class/infiniband_verbs'

    if not os.path.isdir(verbs_path):
        return devices

    try:
        for uverbs_name in os.listdir(verbs_path):
            uverbs_path = os.path.join(verbs_path, uverbs_name)
            if not os.path.isdir(uverbs_path):
                continue

            device = {
                'uverbs': uverbs_name,
                'path': uverbs_path,
            }

            # Read device link to get IB device name
            device_link = os.path.join(uverbs_path, 'device')
            if os.path.islink(device_link):
                real_path = os.path.realpath(device_link)
                device['ib_device'] = os.path.basename(os.path.dirname(real_path))

            # Check abi_version
            abi_path = os.path.join(uverbs_path, 'abi_version')
            if os.path.isfile(abi_path):
                try:
                    with open(abi_path, 'r') as f:
                        device['abi_version'] = int(f.read().strip())
                except (IOError, ValueError):
                    pass

            devices.append(device)

    except (OSError, IOError):
        pass

    return devices


def check_ibstat():
    """
    Run ibstat command for additional fabric information.

    Returns:
        dict: Parsed ibstat output or None
    """
    if not check_tool_available('ibstat'):
        return None

    returncode, stdout, stderr = run_command(['ibstat', '-p'])
    if returncode != 0:
        return None

    # Parse ibstat output
    ports = []
    for line in stdout.strip().split('\n'):
        if line.strip():
            ports.append(line.strip())

    return {'port_guids': ports} if ports else None


def check_sm_status():
    """
    Check subnet manager status using sminfo.

    Returns:
        dict: SM status or None
    """
    if not check_tool_available('sminfo'):
        return None

    returncode, stdout, stderr = run_command(['sminfo'])
    if returncode != 0:
        return None

    # Parse sminfo output
    # Example: "sminfo: sm lid:1 sm guid:0x... priority:14 state:4 MASTER"
    sm_info = {'raw': stdout.strip()}

    # Extract SM state
    match = re.search(r'state:(\d+)\s+(\w+)', stdout)
    if match:
        sm_info['state_num'] = int(match.group(1))
        sm_info['state'] = match.group(2)

    # Extract SM LID
    match = re.search(r'sm lid:(\d+)', stdout)
    if match:
        sm_info['sm_lid'] = int(match.group(1))

    # Extract priority
    match = re.search(r'priority:(\d+)', stdout)
    if match:
        sm_info['priority'] = int(match.group(1))

    return sm_info


def analyze_health(devices, rdma_devices, sm_status):
    """
    Analyze InfiniBand health and generate issues list.

    Args:
        devices: List of IB devices
        rdma_devices: List of RDMA devices
        sm_status: Subnet manager status

    Returns:
        list: List of issue dictionaries
    """
    issues = []

    if not devices:
        issues.append({
            'severity': 'ERROR',
            'type': 'no_devices',
            'message': "No InfiniBand devices found. Check if IB kernel modules are loaded (ib_core, mlx5_ib)."
        })
        return issues

    for device in devices:
        device_name = device['name']

        # Check firmware version (informational)
        if 'fw_ver' not in device:
            issues.append({
                'severity': 'INFO',
                'type': 'no_firmware_info',
                'device': device_name,
                'message': f"Cannot read firmware version for {device_name}"
            })

        for port in device.get('ports', []):
            port_num = port['port']
            port_id = f"{device_name}:{port_num}"

            # Check port state
            state = port.get('state', 'UNKNOWN')
            phys_state = port.get('phys_state', 'UNKNOWN')

            if state != 'ACTIVE':
                severity = 'WARNING' if state in ['INIT', 'ARMED'] else 'ERROR'
                issues.append({
                    'severity': severity,
                    'type': 'port_not_active',
                    'device': device_name,
                    'port': port_num,
                    'state': state,
                    'phys_state': phys_state,
                    'message': f"Port {port_id} is not ACTIVE (state={state}, phys={phys_state})"
                })

            # Check physical state
            if phys_state not in ['LinkUp', 'LINKUP']:
                if state == 'ACTIVE':
                    # Strange - active but link not up
                    issues.append({
                        'severity': 'WARNING',
                        'type': 'phys_state_mismatch',
                        'device': device_name,
                        'port': port_num,
                        'phys_state': phys_state,
                        'message': f"Port {port_id} state mismatch: ACTIVE but phys_state={phys_state}"
                    })

            # Check LID assignment
            lid = port.get('lid')
            if lid in [None, '0', '0x0', 0]:
                if state == 'ACTIVE':
                    issues.append({
                        'severity': 'WARNING',
                        'type': 'no_lid',
                        'device': device_name,
                        'port': port_num,
                        'message': f"Port {port_id} is ACTIVE but has no LID assigned. Check SM connectivity."
                    })

            # Check SM LID
            sm_lid = port.get('sm_lid')
            if sm_lid in [None, '0', '0x0', 0] and state == 'ACTIVE':
                issues.append({
                    'severity': 'WARNING',
                    'type': 'no_sm_lid',
                    'device': device_name,
                    'port': port_num,
                    'message': f"Port {port_id} cannot see Subnet Manager (sm_lid=0)"
                })

            # Get and analyze counters
            counters = get_port_counters(device_name, port_num)
            port['counters'] = counters

            # Check error counters
            error_thresholds = {
                'symbol_error': 0,
                'link_error_recovery': 0,
                'link_downed': 0,
                'port_rcv_errors': 0,
                'port_rcv_remote_physical_errors': 0,
                'port_xmit_discards': 10,  # Some discards may be normal
                'local_link_integrity_errors': 0,
                'excessive_buffer_overrun_errors': 0,
            }

            for counter, threshold in error_thresholds.items():
                value = counters.get(counter, 0)
                if value > threshold:
                    severity = 'ERROR' if value > threshold * 10 + 100 else 'WARNING'
                    issues.append({
                        'severity': severity,
                        'type': 'error_counter',
                        'device': device_name,
                        'port': port_num,
                        'counter': counter,
                        'value': value,
                        'message': f"Port {port_id} has {counter}={value}. "
                                  f"Consider clearing counters after investigation: perfquery -x -c"
                    })

    # Check RDMA device availability
    if not rdma_devices:
        issues.append({
            'severity': 'WARNING',
            'type': 'no_rdma_devices',
            'message': "No RDMA verbs devices found (/sys/class/infiniband_verbs). "
                      "RDMA applications may not work."
        })

    # Check subnet manager status
    if sm_status:
        sm_state = sm_status.get('state', '')
        if sm_state and sm_state not in ['MASTER', 'STANDBY']:
            issues.append({
                'severity': 'WARNING',
                'type': 'sm_state',
                'state': sm_state,
                'message': f"Subnet Manager state is {sm_state}. Expected MASTER or STANDBY."
            })
    elif devices:
        # We have devices but couldn't check SM
        issues.append({
            'severity': 'INFO',
            'type': 'sm_check_unavailable',
            'message': "Cannot check Subnet Manager status (sminfo not available)"
        })

    return issues


def format_plain(devices, rdma_devices, sm_status, issues, verbose=False, warn_only=False):
    """Format output as plain text."""
    lines = []

    if warn_only and not issues:
        return "No InfiniBand issues detected"

    if not warn_only:
        lines.append("InfiniBand Health Monitor")
        lines.append("=" * 60)
        lines.append("")

        # Device summary
        if devices:
            lines.append(f"InfiniBand Devices: {len(devices)}")
            for device in devices:
                fw_ver = device.get('fw_ver', 'N/A')
                node_type = device.get('node_type', 'N/A')
                lines.append(f"  {device['name']}: type={node_type}, fw={fw_ver}")

                for port in device.get('ports', []):
                    state = port.get('state', 'UNKNOWN')
                    phys_state = port.get('phys_state', 'UNKNOWN')
                    rate = port.get('rate', 'N/A')
                    lid = port.get('lid', 'N/A')
                    status_mark = " " if state == 'ACTIVE' else "!"
                    lines.append(f"   {status_mark} Port {port['port']}: {state} ({phys_state}) "
                               f"rate={rate} LID={lid}")

                    # Show counters in verbose mode
                    if verbose and 'counters' in port:
                        counters = port['counters']
                        # Show error counters with non-zero values
                        error_counters = [
                            'symbol_error', 'link_error_recovery', 'link_downed',
                            'port_rcv_errors', 'port_xmit_discards'
                        ]
                        errors = [(k, counters[k]) for k in error_counters
                                  if k in counters and counters[k] > 0]
                        if errors:
                            lines.append(f"       Errors: {', '.join(f'{k}={v}' for k, v in errors)}")

                        # Show performance counters
                        rx_data = counters.get('port_rcv_data', 0)
                        tx_data = counters.get('port_xmit_data', 0)
                        rx_pkts = counters.get('port_rcv_packets', 0)
                        tx_pkts = counters.get('port_xmit_packets', 0)
                        lines.append(f"       Traffic: RX={rx_data:,} bytes/{rx_pkts:,} pkts, "
                                   f"TX={tx_data:,} bytes/{tx_pkts:,} pkts")

            lines.append("")
        else:
            lines.append("No InfiniBand devices found")
            lines.append("")

        # RDMA devices
        if rdma_devices:
            lines.append(f"RDMA Verbs Devices: {len(rdma_devices)}")
            for rdma in rdma_devices:
                ib_dev = rdma.get('ib_device', 'N/A')
                abi = rdma.get('abi_version', 'N/A')
                lines.append(f"  {rdma['uverbs']}: ib_device={ib_dev}, abi={abi}")
            lines.append("")

        # Subnet manager status
        if sm_status:
            lines.append("Subnet Manager:")
            state = sm_status.get('state', 'UNKNOWN')
            sm_lid = sm_status.get('sm_lid', 'N/A')
            priority = sm_status.get('priority', 'N/A')
            lines.append(f"  State: {state}, LID: {sm_lid}, Priority: {priority}")
            lines.append("")

    # Issues
    if issues:
        lines.append("Issues Detected:")
        lines.append("-" * 60)
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
        lines.append("Status: InfiniBand fabric healthy")

    return '\n'.join(lines)


def format_json(devices, rdma_devices, sm_status, issues):
    """Format output as JSON."""
    # Determine health status
    has_errors = any(i['severity'] == 'ERROR' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    output = {
        'devices': devices,
        'rdma_devices': rdma_devices,
        'sm_status': sm_status,
        'issues': issues,
        'healthy': not has_errors and not has_warnings,
        'summary': {
            'device_count': len(devices),
            'rdma_device_count': len(rdma_devices),
            'error_count': sum(1 for i in issues if i['severity'] == 'ERROR'),
            'warning_count': sum(1 for i in issues if i['severity'] == 'WARNING'),
        }
    }
    return json.dumps(output, indent=2)


def format_table(devices, rdma_devices, sm_status, issues):
    """Format output as a table."""
    lines = []

    # Device table
    lines.append(f"{'Device':<12} {'Port':<5} {'State':<10} {'Phys State':<12} {'Rate':<15} {'LID':<6}")
    lines.append("=" * 62)

    for device in devices:
        for port in device.get('ports', []):
            lines.append(f"{device['name']:<12} {port['port']:<5} "
                        f"{port.get('state', 'N/A'):<10} "
                        f"{port.get('phys_state', 'N/A'):<12} "
                        f"{port.get('rate', 'N/A'):<15} "
                        f"{port.get('lid', 'N/A'):<6}")

    if not devices:
        lines.append("(no devices found)")

    # Issues summary
    if issues:
        lines.append("")
        lines.append("Issues:")
        for issue in issues:
            lines.append(f"  [{issue['severity']}] {issue['message']}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor InfiniBand and RDMA health for HPC environments',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Basic IB health check
  %(prog)s -v                       # Show detailed counters and traffic stats
  %(prog)s --format json            # JSON output for scripting
  %(prog)s --warn-only              # Only show if issues detected

InfiniBand troubleshooting tips:
  - Check cable connections and switch port LEDs
  - Verify SM is running: sminfo, smpquery
  - View error counters: perfquery <lid>
  - Clear counters after fixing: perfquery -x -c <lid>
  - Check fabric topology: ibnetdiscover
  - Verify RDMA connectivity: ibping, rping

Exit codes:
  0 - InfiniBand fabric healthy
  1 - Warnings or errors detected
  2 - Cannot read IB status or no devices
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
        help='Show detailed counter and traffic statistics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only output if issues are detected'
    )

    args = parser.parse_args()

    # Check for InfiniBand sysfs
    if not os.path.isdir('/sys/class/infiniband'):
        print("Error: /sys/class/infiniband not found", file=sys.stderr)
        print("InfiniBand kernel modules may not be loaded.", file=sys.stderr)
        print("Try: modprobe ib_core mlx5_ib (for Mellanox)", file=sys.stderr)
        sys.exit(2)

    # Gather data
    devices = get_ib_devices()
    rdma_devices = get_rdma_devices()
    sm_status = check_sm_status()

    # If no devices found, exit with error
    if not devices:
        if args.format == 'json':
            print(json.dumps({
                'devices': [],
                'rdma_devices': [],
                'sm_status': None,
                'issues': [{'severity': 'ERROR', 'type': 'no_devices',
                           'message': 'No InfiniBand devices found'}],
                'healthy': False
            }, indent=2))
        else:
            print("Error: No InfiniBand devices found", file=sys.stderr)
            print("Check if IB hardware is present and modules loaded", file=sys.stderr)
        sys.exit(2)

    # Analyze health
    issues = analyze_health(devices, rdma_devices, sm_status)

    # Handle warn-only mode with no issues
    if args.warn_only and not issues:
        if args.format == 'json':
            print(json.dumps({'healthy': True, 'issues': []}))
        sys.exit(0)

    # Format output
    if args.format == 'json':
        output = format_json(devices, rdma_devices, sm_status, issues)
    elif args.format == 'table':
        output = format_table(devices, rdma_devices, sm_status, issues)
    else:
        output = format_plain(devices, rdma_devices, sm_status, issues,
                             verbose=args.verbose, warn_only=args.warn_only)

    print(output)

    # Exit code based on severity
    has_errors = any(i['severity'] == 'ERROR' for i in issues)
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)

    if has_errors or has_warnings:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
