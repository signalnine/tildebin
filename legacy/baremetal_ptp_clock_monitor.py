#!/usr/bin/env python3
"""
Monitor PTP (Precision Time Protocol) clock synchronization status.

Checks PTP hardware timestamps, clock offset, path delay, and synchronization
state for systems requiring high-precision time (HPC, trading, telecom).
Integrates with ptp4l/phc2sys or reads directly from /sys/class/ptp.

Exit codes:
    0 - PTP clocks synchronized and healthy
    1 - PTP synchronization issues detected (high offset, not locked)
    2 - Usage error or PTP not available
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys


def run_command(cmd, timeout=10):
    """Execute a command and return result."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def check_tool_available(tool_name):
    """Check if a system tool is available."""
    returncode, _, _ = run_command("which {}".format(tool_name))
    return returncode == 0


def get_ptp_devices():
    """
    Get list of PTP hardware clock devices.

    Returns list of dicts with device info.
    """
    devices = []

    # Check /sys/class/ptp for PTP devices
    ptp_path = "/sys/class/ptp"
    if not os.path.exists(ptp_path):
        return devices

    for ptp_dir in sorted(glob.glob(os.path.join(ptp_path, "ptp*"))):
        device_name = os.path.basename(ptp_dir)
        device_info = {
            'name': device_name,
            'path': "/dev/{}".format(device_name),
            'sysfs': ptp_dir,
            'clock_name': None,
            'max_adj': None,
            'n_alarms': None,
            'n_pins': None,
            'pps': False
        }

        # Read clock name
        clock_name_file = os.path.join(ptp_dir, "clock_name")
        if os.path.exists(clock_name_file):
            try:
                with open(clock_name_file, 'r') as f:
                    device_info['clock_name'] = f.read().strip()
            except (IOError, OSError):
                pass

        # Read max adjustment
        max_adj_file = os.path.join(ptp_dir, "max_adjustment")
        if os.path.exists(max_adj_file):
            try:
                with open(max_adj_file, 'r') as f:
                    device_info['max_adj'] = int(f.read().strip())
            except (IOError, OSError, ValueError):
                pass

        # Read number of alarms
        n_alarms_file = os.path.join(ptp_dir, "n_alarms")
        if os.path.exists(n_alarms_file):
            try:
                with open(n_alarms_file, 'r') as f:
                    device_info['n_alarms'] = int(f.read().strip())
            except (IOError, OSError, ValueError):
                pass

        # Read number of pins
        n_pins_file = os.path.join(ptp_dir, "n_pins")
        if os.path.exists(n_pins_file):
            try:
                with open(n_pins_file, 'r') as f:
                    device_info['n_pins'] = int(f.read().strip())
            except (IOError, OSError, ValueError):
                pass

        # Check for PPS support
        pps_file = os.path.join(ptp_dir, "pps_available")
        if os.path.exists(pps_file):
            try:
                with open(pps_file, 'r') as f:
                    device_info['pps'] = f.read().strip() == "1"
            except (IOError, OSError):
                pass

        # Try to find associated network interface
        for net_dir in glob.glob("/sys/class/net/*/device/ptp"):
            try:
                link = os.readlink(net_dir)
                if device_name in link:
                    iface = os.path.basename(os.path.dirname(os.path.dirname(net_dir)))
                    device_info['interface'] = iface
                    break
            except OSError:
                continue

        devices.append(device_info)

    return devices


def get_ptp4l_status():
    """
    Get PTP synchronization status from ptp4l via pmc.

    Returns dict with sync status or None if not available.
    """
    if not check_tool_available("pmc"):
        return None

    status = {
        'available': False,
        'state': None,
        'offset_ns': None,
        'mean_path_delay_ns': None,
        'master_id': None,
        'port_state': None
    }

    # Try to get current data set
    returncode, stdout, stderr = run_command(
        "pmc -u -b 0 'GET CURRENT_DATA_SET' 2>/dev/null"
    )

    if returncode == 0 and stdout:
        status['available'] = True

        # Parse offset from master
        match = re.search(r'offsetFromMaster\s+(-?\d+)', stdout)
        if match:
            status['offset_ns'] = int(match.group(1))

        # Parse mean path delay
        match = re.search(r'meanPathDelay\s+(-?\d+)', stdout)
        if match:
            status['mean_path_delay_ns'] = int(match.group(1))

    # Get port state
    returncode, stdout, stderr = run_command(
        "pmc -u -b 0 'GET PORT_DATA_SET' 2>/dev/null"
    )

    if returncode == 0 and stdout:
        # Parse port state
        match = re.search(r'portState\s+(\w+)', stdout)
        if match:
            status['port_state'] = match.group(1)

    # Get parent data set for master info
    returncode, stdout, stderr = run_command(
        "pmc -u -b 0 'GET PARENT_DATA_SET' 2>/dev/null"
    )

    if returncode == 0 and stdout:
        # Parse master clock ID
        match = re.search(r'parentPortIdentity\s+([\da-f.:]+)', stdout, re.IGNORECASE)
        if match:
            status['master_id'] = match.group(1)

    # Determine overall state
    if status['port_state']:
        if status['port_state'].upper() == 'SLAVE':
            status['state'] = 'synchronized'
        elif status['port_state'].upper() == 'MASTER':
            status['state'] = 'master'
        elif status['port_state'].upper() in ('LISTENING', 'UNCALIBRATED'):
            status['state'] = 'acquiring'
        else:
            status['state'] = status['port_state'].lower()

    return status


def get_phc2sys_status():
    """
    Get PHC to system clock synchronization status.

    Returns dict with sync status or None if not available.
    """
    # Check if phc2sys is running
    returncode, stdout, stderr = run_command("pgrep -f phc2sys")

    if returncode != 0:
        return None

    status = {
        'running': True,
        'offset_ns': None,
        'frequency_ppb': None
    }

    # Try to get status from systemd journal
    returncode, stdout, stderr = run_command(
        "journalctl -u phc2sys --no-pager -n 5 2>/dev/null | tail -1"
    )

    if returncode == 0 and stdout:
        # Parse recent offset from log
        # Format: phc2sys[1234]: sys offset    123 s2 freq  -1234 delay  456
        match = re.search(r'offset\s+(-?\d+)\s+\w+\s+freq\s+(-?\d+)', stdout)
        if match:
            status['offset_ns'] = int(match.group(1))
            status['frequency_ppb'] = int(match.group(2))

    return status


def check_ntp_ptp_conflict():
    """
    Check if NTP/chrony is running alongside PTP (potential conflict).

    Returns warning message if conflict detected, None otherwise.
    """
    warnings = []

    # Check for ntpd
    returncode, _, _ = run_command("pgrep -x ntpd")
    if returncode == 0:
        warnings.append("ntpd is running - may conflict with PTP")

    # Check for chronyd
    returncode, _, _ = run_command("pgrep -x chronyd")
    if returncode == 0:
        # Check if chrony is configured to not adjust system clock
        returncode, stdout, _ = run_command("chronyc tracking 2>/dev/null")
        if returncode == 0 and 'System time' in stdout:
            warnings.append("chronyd is running and adjusting system clock - may conflict with phc2sys")

    # Check for systemd-timesyncd
    returncode, _, _ = run_command("pgrep -x systemd-timesyn")
    if returncode == 0:
        warnings.append("systemd-timesyncd is running - may conflict with PTP")

    return warnings if warnings else None


def check_ptp_health(offset_threshold_ns=1000, delay_threshold_ns=10000):
    """
    Perform comprehensive PTP health check.

    Returns dict with overall health status.
    """
    health = {
        'status': 'unknown',
        'devices': [],
        'ptp4l': None,
        'phc2sys': None,
        'warnings': [],
        'issues': []
    }

    # Get PTP devices
    devices = get_ptp_devices()
    health['devices'] = devices

    if not devices:
        health['status'] = 'no_ptp'
        health['issues'].append('No PTP hardware clock devices found')
        return health

    # Get ptp4l status
    ptp4l_status = get_ptp4l_status()
    health['ptp4l'] = ptp4l_status

    # Get phc2sys status
    phc2sys_status = get_phc2sys_status()
    health['phc2sys'] = phc2sys_status

    # Check for NTP/PTP conflicts
    conflicts = check_ntp_ptp_conflict()
    if conflicts:
        health['warnings'].extend(conflicts)

    # Determine overall status
    has_issues = False

    if ptp4l_status:
        if ptp4l_status['state'] == 'synchronized':
            # Check offset
            if ptp4l_status['offset_ns'] is not None:
                offset_abs = abs(ptp4l_status['offset_ns'])
                if offset_abs > offset_threshold_ns:
                    health['issues'].append(
                        'PTP offset {}ns exceeds threshold {}ns'.format(
                            ptp4l_status['offset_ns'], offset_threshold_ns
                        )
                    )
                    has_issues = True

            # Check path delay
            if ptp4l_status['mean_path_delay_ns'] is not None:
                if ptp4l_status['mean_path_delay_ns'] > delay_threshold_ns:
                    health['warnings'].append(
                        'High mean path delay: {}ns'.format(
                            ptp4l_status['mean_path_delay_ns']
                        )
                    )

        elif ptp4l_status['state'] == 'master':
            health['status'] = 'master'

        elif ptp4l_status['state'] == 'acquiring':
            health['issues'].append('PTP still acquiring sync (state: {})'.format(
                ptp4l_status['port_state']
            ))
            has_issues = True

        elif ptp4l_status['available']:
            health['issues'].append('PTP in unexpected state: {}'.format(
                ptp4l_status['port_state']
            ))
            has_issues = True
    else:
        # ptp4l not running but we have PTP devices
        health['warnings'].append('ptp4l not running or pmc not available')

    # Check phc2sys if available
    if phc2sys_status and phc2sys_status['running']:
        if phc2sys_status['offset_ns'] is not None:
            offset_abs = abs(phc2sys_status['offset_ns'])
            if offset_abs > offset_threshold_ns:
                health['issues'].append(
                    'PHC to system clock offset {}ns exceeds threshold'.format(
                        phc2sys_status['offset_ns']
                    )
                )
                has_issues = True

    # Set final status
    if health['issues']:
        health['status'] = 'degraded'
    elif ptp4l_status and ptp4l_status['state'] == 'synchronized':
        health['status'] = 'synchronized'
    elif ptp4l_status and ptp4l_status['state'] == 'master':
        health['status'] = 'master'
    elif devices and not ptp4l_status:
        health['status'] = 'unconfigured'
    else:
        health['status'] = 'unknown'

    return health


def format_plain_output(health, verbose=False):
    """Format health check results as plain text."""
    lines = []
    lines.append('PTP Clock Status:')
    lines.append('=' * 60)
    lines.append('')

    # Overall status
    status_map = {
        'synchronized': '[OK] PTP Synchronized',
        'master': '[OK] PTP Master Mode',
        'degraded': '[WARN] PTP Degraded',
        'acquiring': '[WARN] PTP Acquiring Sync',
        'unconfigured': '[WARN] PTP Devices Present but Not Configured',
        'no_ptp': '[INFO] No PTP Hardware Found',
        'unknown': '[WARN] PTP Status Unknown'
    }
    lines.append('Status: {}'.format(status_map.get(health['status'], health['status'])))
    lines.append('')

    # PTP Devices
    if health['devices']:
        lines.append('PTP Hardware Clocks:')
        for dev in health['devices']:
            iface_str = ' ({})'.format(dev.get('interface', 'unknown interface'))
            pps_str = ' [PPS]' if dev.get('pps') else ''
            lines.append('  {} - {}{}{}'.format(
                dev['name'],
                dev.get('clock_name', 'unknown'),
                iface_str,
                pps_str
            ))
            if verbose and dev.get('max_adj'):
                lines.append('    Max adjustment: {} ppb'.format(dev['max_adj']))
        lines.append('')

    # ptp4l status
    if health['ptp4l'] and health['ptp4l']['available']:
        ptp4l = health['ptp4l']
        lines.append('ptp4l Status:')
        lines.append('  Port State: {}'.format(ptp4l.get('port_state', 'unknown')))

        if ptp4l.get('offset_ns') is not None:
            lines.append('  Offset from Master: {} ns'.format(ptp4l['offset_ns']))

        if ptp4l.get('mean_path_delay_ns') is not None:
            lines.append('  Mean Path Delay: {} ns'.format(ptp4l['mean_path_delay_ns']))

        if ptp4l.get('master_id'):
            lines.append('  Master Clock ID: {}'.format(ptp4l['master_id']))
        lines.append('')

    # phc2sys status
    if health['phc2sys'] and health['phc2sys']['running']:
        phc2sys = health['phc2sys']
        lines.append('phc2sys Status: Running')
        if phc2sys.get('offset_ns') is not None:
            lines.append('  System Clock Offset: {} ns'.format(phc2sys['offset_ns']))
        if phc2sys.get('frequency_ppb') is not None:
            lines.append('  Frequency Adjustment: {} ppb'.format(phc2sys['frequency_ppb']))
        lines.append('')

    # Issues
    if health['issues']:
        lines.append('Issues:')
        for issue in health['issues']:
            lines.append('  - {}'.format(issue))
        lines.append('')

    # Warnings
    if health['warnings']:
        lines.append('Warnings:')
        for warning in health['warnings']:
            lines.append('  - {}'.format(warning))
        lines.append('')

    return '\n'.join(lines)


def format_json_output(health):
    """Format health check results as JSON."""
    return json.dumps(health, indent=2)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor PTP (Precision Time Protocol) clock synchronization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
PTP provides sub-microsecond time synchronization for applications requiring
high precision (HPC, trading, telecom). This tool monitors:

  - PTP hardware clock devices (/dev/ptp*)
  - ptp4l synchronization state and offset
  - phc2sys (PHC to system clock sync)
  - Potential conflicts with NTP/chrony

Exit codes:
  0 - PTP synchronized or operating as master
  1 - PTP issues detected (high offset, not locked, conflicts)
  2 - PTP not available or usage error

Examples:
  %(prog)s                           # Basic status check
  %(prog)s --offset-threshold 500    # Alert if offset > 500ns
  %(prog)s --format json             # JSON output for monitoring
  %(prog)s --verbose                 # Show detailed device info
'''
    )

    parser.add_argument(
        '--offset-threshold',
        type=int,
        default=1000,
        metavar='NS',
        help='Offset threshold in nanoseconds (default: %(default)s)'
    )

    parser.add_argument(
        '--delay-threshold',
        type=int,
        default=10000,
        metavar='NS',
        help='Path delay threshold in nanoseconds (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only report if there are issues or warnings'
    )

    args = parser.parse_args()

    # Perform health check
    health = check_ptp_health(
        offset_threshold_ns=args.offset_threshold,
        delay_threshold_ns=args.delay_threshold
    )

    # Apply warn-only filter
    if args.warn_only:
        if health['status'] in ('synchronized', 'master') and not health['issues'] and not health['warnings']:
            sys.exit(0)

    # Output results
    if args.format == 'json':
        print(format_json_output(health))
    else:
        print(format_plain_output(health, verbose=args.verbose))

    # Determine exit code
    if health['status'] == 'no_ptp':
        sys.exit(2)
    elif health['status'] in ('degraded', 'acquiring', 'unknown') or health['issues']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
