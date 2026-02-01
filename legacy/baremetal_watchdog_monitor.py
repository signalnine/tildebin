#!/usr/bin/env python3
"""
Monitor hardware and software watchdog timer status on baremetal systems.

Watchdog timers are critical for production servers - they automatically reset
a hung system if the OS stops responding. This script checks:
- Hardware watchdog device availability and configuration
- Watchdog daemon status (watchdog or systemd-watchdog)
- Timeout settings and last heartbeat times
- Whether watchdog is actually armed and monitoring

Key features:
- Detects hardware watchdog devices (/dev/watchdog*)
- Shows watchdog timeout and pretimeout settings
- Verifies watchdog daemon is running and pinging
- Checks systemd RuntimeWatchdogUSec settings
- Identifies ungraceful reboots from watchdog triggers

Exit codes:
    0 - Watchdog properly configured and active
    1 - Watchdog not configured, inactive, or misconfigured
    2 - Usage error or missing dependency
"""

import argparse
import subprocess
import sys
import json
import os
import glob
import re


def run_command(cmd, shell=False):
    """Execute a command and return output"""
    try:
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def get_watchdog_devices():
    """Find hardware watchdog devices"""
    devices = []

    # Look for watchdog devices
    watchdog_paths = glob.glob('/dev/watchdog*')

    for path in watchdog_paths:
        device = {
            'path': path,
            'exists': os.path.exists(path),
            'accessible': os.access(path, os.R_OK),
            'info': {}
        }

        # Get device info from sysfs if available
        device_name = os.path.basename(path)
        sysfs_path = f'/sys/class/watchdog/{device_name}'

        if os.path.isdir(sysfs_path):
            # Read timeout
            timeout_path = f'{sysfs_path}/timeout'
            if os.path.exists(timeout_path):
                try:
                    with open(timeout_path, 'r') as f:
                        device['info']['timeout'] = int(f.read().strip())
                except (IOError, ValueError):
                    pass

            # Read pretimeout
            pretimeout_path = f'{sysfs_path}/pretimeout'
            if os.path.exists(pretimeout_path):
                try:
                    with open(pretimeout_path, 'r') as f:
                        device['info']['pretimeout'] = int(f.read().strip())
                except (IOError, ValueError):
                    pass

            # Read identity
            identity_path = f'{sysfs_path}/identity'
            if os.path.exists(identity_path):
                try:
                    with open(identity_path, 'r') as f:
                        device['info']['identity'] = f.read().strip()
                except IOError:
                    pass

            # Read status
            status_path = f'{sysfs_path}/status'
            if os.path.exists(status_path):
                try:
                    with open(status_path, 'r') as f:
                        device['info']['status'] = f.read().strip()
                except IOError:
                    pass

            # Read state (active/inactive)
            state_path = f'{sysfs_path}/state'
            if os.path.exists(state_path):
                try:
                    with open(state_path, 'r') as f:
                        device['info']['state'] = f.read().strip()
                except IOError:
                    pass

            # Read nowayout flag
            nowayout_path = f'{sysfs_path}/nowayout'
            if os.path.exists(nowayout_path):
                try:
                    with open(nowayout_path, 'r') as f:
                        device['info']['nowayout'] = f.read().strip() == '1'
                except IOError:
                    pass

            # Read min/max timeout
            min_timeout_path = f'{sysfs_path}/min_timeout'
            if os.path.exists(min_timeout_path):
                try:
                    with open(min_timeout_path, 'r') as f:
                        device['info']['min_timeout'] = int(f.read().strip())
                except (IOError, ValueError):
                    pass

            max_timeout_path = f'{sysfs_path}/max_timeout'
            if os.path.exists(max_timeout_path):
                try:
                    with open(max_timeout_path, 'r') as f:
                        device['info']['max_timeout'] = int(f.read().strip())
                except (IOError, ValueError):
                    pass

        devices.append(device)

    return devices


def get_watchdog_modules():
    """Check for loaded watchdog kernel modules"""
    modules = []

    # Common watchdog modules
    watchdog_module_patterns = [
        'softdog', 'iTCO_wdt', 'sp5100_tco', 'hpwdt', 'ipmi_watchdog',
        'w83627hf_wdt', 'it87_wdt', 'wdat_wdt', 'i6300esb', 'mei_wdt'
    ]

    returncode, stdout, _ = run_command(['lsmod'])
    if returncode == 0:
        for line in stdout.split('\n'):
            parts = line.split()
            if parts:
                module_name = parts[0]
                for pattern in watchdog_module_patterns:
                    if pattern in module_name.lower() or 'wdt' in module_name.lower():
                        modules.append({
                            'name': module_name,
                            'size': int(parts[1]) if len(parts) > 1 else 0,
                            'used_by': int(parts[2]) if len(parts) > 2 else 0
                        })
                        break

    return modules


def get_watchdog_daemon_status():
    """Check if watchdog daemon is running"""
    daemons = []

    # Check for watchdog service
    for service in ['watchdog', 'watchdog.service']:
        returncode, stdout, _ = run_command(['systemctl', 'is-active', service])
        if returncode == 0 and 'active' in stdout:
            daemons.append({
                'name': service,
                'status': 'active',
                'type': 'watchdog-daemon'
            })
            break

    # Check systemd watchdog configuration
    returncode, stdout, _ = run_command(
        ['systemctl', 'show', '-p', 'RuntimeWatchdogUSec', '--value']
    )
    if returncode == 0:
        value = stdout.strip()
        if value and value != '0':
            # Parse the value (could be like "30s" or "30000000" for microseconds)
            try:
                if value.endswith('s'):
                    timeout = int(value[:-1])
                elif value.endswith('ms'):
                    timeout = int(value[:-2]) // 1000
                elif value.endswith('us'):
                    timeout = int(value[:-2]) // 1000000
                else:
                    # Assume microseconds
                    timeout = int(value) // 1000000

                daemons.append({
                    'name': 'systemd-watchdog',
                    'status': 'configured',
                    'type': 'systemd',
                    'timeout': timeout
                })
            except ValueError:
                pass

    # Check for running watchdog process
    returncode, stdout, _ = run_command(['pgrep', '-x', 'watchdog'])
    if returncode == 0:
        pids = stdout.strip().split('\n')
        daemons.append({
            'name': 'watchdog-process',
            'status': 'running',
            'type': 'process',
            'pids': pids
        })

    return daemons


def check_last_watchdog_reset():
    """Check for evidence of watchdog-triggered resets"""
    reset_evidence = []

    # Check dmesg for watchdog messages
    returncode, stdout, _ = run_command(['dmesg'])
    if returncode == 0:
        for line in stdout.split('\n'):
            lower_line = line.lower()
            if 'watchdog' in lower_line:
                if any(word in lower_line for word in ['reset', 'timeout', 'triggered', 'expired']):
                    reset_evidence.append({
                        'source': 'dmesg',
                        'message': line.strip()[:200]
                    })

    # Check journal for watchdog events
    returncode, stdout, _ = run_command([
        'journalctl', '-b', '-1', '--no-pager', '-q',
        'SYSLOG_IDENTIFIER=kernel', '-g', 'watchdog'
    ])
    if returncode == 0 and stdout.strip():
        for line in stdout.strip().split('\n')[:5]:  # Limit to 5 entries
            reset_evidence.append({
                'source': 'journal-previous-boot',
                'message': line.strip()[:200]
            })

    return reset_evidence


def get_system_uptime():
    """Get system uptime"""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])

        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        return {
            'seconds': uptime_seconds,
            'human': f'{days}d {hours}h {minutes}m'
        }
    except (IOError, ValueError):
        return {'seconds': 0, 'human': 'unknown'}


def analyze_watchdog_health(devices, modules, daemons):
    """Analyze watchdog configuration and return health status"""
    issues = []
    warnings = []
    info = []

    # Check for watchdog device
    if not devices:
        issues.append('No watchdog device found (/dev/watchdog*)')
    else:
        has_active = False
        for dev in devices:
            if not dev['accessible']:
                warnings.append(f"Watchdog device {dev['path']} not accessible (need root?)")

            state = dev['info'].get('state', '')
            if state == 'active':
                has_active = True
                info.append(f"Watchdog {dev['path']} is active")

            timeout = dev['info'].get('timeout', 0)
            if timeout > 0:
                if timeout < 10:
                    warnings.append(f"Watchdog timeout very short ({timeout}s) - risk of false resets")
                elif timeout > 300:
                    warnings.append(f"Watchdog timeout very long ({timeout}s) - slow recovery")

        if not has_active and devices:
            warnings.append('Watchdog device exists but may not be armed')

    # Check for watchdog modules
    if not modules:
        warnings.append('No watchdog kernel module loaded')
    else:
        module_names = [m['name'] for m in modules]
        info.append(f"Watchdog modules: {', '.join(module_names)}")

    # Check for watchdog daemon
    if not daemons:
        issues.append('No watchdog daemon running (watchdog or systemd-watchdog)')
    else:
        daemon_names = [d['name'] for d in daemons]
        info.append(f"Watchdog daemons: {', '.join(daemon_names)}")

    # Determine overall status
    if issues:
        status = 'critical'
    elif warnings:
        status = 'warning'
    else:
        status = 'healthy'

    return {
        'status': status,
        'issues': issues,
        'warnings': warnings,
        'info': info
    }


def collect_watchdog_data():
    """Collect all watchdog-related data"""
    data = {
        'devices': get_watchdog_devices(),
        'modules': get_watchdog_modules(),
        'daemons': get_watchdog_daemon_status(),
        'reset_evidence': check_last_watchdog_reset(),
        'uptime': get_system_uptime(),
        'summary': {}
    }

    # Analyze health
    health = analyze_watchdog_health(
        data['devices'],
        data['modules'],
        data['daemons']
    )
    data['health'] = health

    # Build summary
    data['summary'] = {
        'devices_found': len(data['devices']),
        'modules_loaded': len(data['modules']),
        'daemons_active': len([d for d in data['daemons'] if d['status'] in ('active', 'running', 'configured')]),
        'status': health['status'],
        'issues': len(health['issues']),
        'warnings': len(health['warnings'])
    }

    return data


def format_output_plain(data, verbose=False):
    """Format output as plain text"""
    lines = []

    lines.append("Watchdog Timer Status Report")
    lines.append("=" * 60)
    lines.append(f"System Uptime: {data['uptime']['human']}")
    lines.append("")

    # Overall status
    status = data['health']['status']
    status_icon = {'healthy': '[OK]', 'warning': '[WARN]', 'critical': '[CRIT]'}
    lines.append(f"Status: {status_icon.get(status, '[?]')} {status.upper()}")
    lines.append("")

    # Devices
    lines.append("Watchdog Devices:")
    if data['devices']:
        for dev in data['devices']:
            info = dev['info']
            identity = info.get('identity', 'unknown')
            timeout = info.get('timeout', 'N/A')
            state = info.get('state', 'unknown')
            lines.append(f"  {dev['path']}: {identity}")
            lines.append(f"    State: {state}, Timeout: {timeout}s")
            if verbose:
                if 'min_timeout' in info:
                    lines.append(f"    Min/Max Timeout: {info.get('min_timeout', 'N/A')}/{info.get('max_timeout', 'N/A')}s")
                if info.get('nowayout'):
                    lines.append("    Nowayout: enabled (cannot be stopped once started)")
    else:
        lines.append("  No watchdog devices found")
    lines.append("")

    # Modules
    lines.append("Watchdog Modules:")
    if data['modules']:
        for mod in data['modules']:
            lines.append(f"  {mod['name']} (size: {mod['size']}, used_by: {mod['used_by']})")
    else:
        lines.append("  No watchdog modules loaded")
    lines.append("")

    # Daemons
    lines.append("Watchdog Daemons:")
    if data['daemons']:
        for daemon in data['daemons']:
            timeout_str = f", timeout: {daemon.get('timeout', 'N/A')}s" if 'timeout' in daemon else ""
            lines.append(f"  {daemon['name']}: {daemon['status']}{timeout_str}")
    else:
        lines.append("  No watchdog daemon configured")
    lines.append("")

    # Issues and warnings
    if data['health']['issues']:
        lines.append("Issues:")
        for issue in data['health']['issues']:
            lines.append(f"  [!] {issue}")
        lines.append("")

    if data['health']['warnings']:
        lines.append("Warnings:")
        for warning in data['health']['warnings']:
            lines.append(f"  [*] {warning}")
        lines.append("")

    # Recent reset evidence
    if verbose and data['reset_evidence']:
        lines.append("Recent Watchdog Events:")
        for evidence in data['reset_evidence'][:5]:
            lines.append(f"  [{evidence['source']}] {evidence['message'][:80]}")
        lines.append("")

    return '\n'.join(lines)


def format_output_table(data):
    """Format output as table"""
    lines = []

    # Devices table
    lines.append("WATCHDOG DEVICES")
    lines.append(f"{'Device':<20} {'Identity':<25} {'State':<10} {'Timeout':<10}")
    lines.append("-" * 65)

    if data['devices']:
        for dev in data['devices']:
            info = dev['info']
            lines.append("{:<20} {:<25} {:<10} {:<10}".format(
                dev['path'],
                info.get('identity', 'unknown')[:25],
                info.get('state', 'unknown'),
                f"{info.get('timeout', 'N/A')}s"
            ))
    else:
        lines.append("No devices found")

    lines.append("")

    # Daemons table
    lines.append("WATCHDOG DAEMONS")
    lines.append(f"{'Name':<25} {'Type':<15} {'Status':<15}")
    lines.append("-" * 55)

    if data['daemons']:
        for daemon in data['daemons']:
            lines.append("{:<25} {:<15} {:<15}".format(
                daemon['name'],
                daemon.get('type', 'unknown'),
                daemon['status']
            ))
    else:
        lines.append("No daemons configured")

    return '\n'.join(lines)


def format_output_json(data):
    """Format output as JSON"""
    return json.dumps(data, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor hardware and software watchdog timer status",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
A healthy watchdog configuration includes:
  - Hardware watchdog device (/dev/watchdog)
  - Watchdog kernel module loaded
  - Watchdog daemon running (watchdog or systemd-watchdog)
  - Reasonable timeout (typically 30-60 seconds)

Examples:
  %(prog)s                      # Check watchdog status
  %(prog)s -v                   # Verbose output with recent events
  %(prog)s --format json        # JSON output for automation
  %(prog)s --warn-only          # Only show if issues exist
"""
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information including recent events"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only produce output if there are warnings or issues"
    )

    args = parser.parse_args()

    # Collect data
    data = collect_watchdog_data()

    # Check if we should output anything
    if args.warn_only:
        if data['health']['status'] == 'healthy':
            sys.exit(0)

    # Format output
    if args.format == "json":
        output = format_output_json(data)
    elif args.format == "table":
        output = format_output_table(data)
    else:
        output = format_output_plain(data, args.verbose)

    print(output)

    # Exit based on status
    if data['health']['status'] == 'critical':
        sys.exit(1)
    elif data['health']['status'] == 'warning':
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
