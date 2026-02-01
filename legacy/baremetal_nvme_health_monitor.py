#!/usr/bin/env python3
"""
Monitor NVMe drive health and performance metrics.

Checks NVMe-specific health indicators including:
- Temperature and thermal throttling status
- Spare capacity and wear level
- Media and data integrity errors
- Controller health and available spare threshold
- Power-on hours and unsafe shutdowns
- Namespace utilization

NVMe drives expose detailed SMART/Health information via the nvme-cli tool.
This script parses nvme smart-log output to detect potential failures before
they impact production workloads.

Critical metrics to watch:
- available_spare: Below threshold indicates drive replacement needed
- media_errors: Any non-zero value indicates data integrity issues
- temperature: Drives throttle above warning threshold
- critical_warning: Bitmap of critical conditions

Exit codes:
    0 - All NVMe drives healthy
    1 - Warnings or errors detected (degraded drives, high wear, etc.)
    2 - Usage error or nvme-cli not available
"""

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional


def check_nvme_cli_available() -> bool:
    """Check if nvme-cli tool is available."""
    try:
        result = subprocess.run(
            ['which', 'nvme'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_nvme_devices() -> List[str]:
    """Get list of NVMe devices in the system."""
    devices = []

    # Method 1: Check /dev/nvme* devices
    try:
        result = subprocess.run(
            ['ls', '/dev/'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            for line in result.stdout.split():
                # Match nvme0n1, nvme1n1, etc. (namespace devices)
                if re.match(r'^nvme\d+n\d+$', line):
                    devices.append(f'/dev/{line}')
    except Exception:
        pass

    # Method 2: Use nvme list if available
    if not devices:
        try:
            result = subprocess.run(
                ['nvme', 'list', '-o', 'json'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for device in data.get('Devices', []):
                    dev_path = device.get('DevicePath')
                    if dev_path:
                        devices.append(dev_path)
        except (json.JSONDecodeError, Exception):
            pass

    return sorted(set(devices))


def parse_smart_log(output: str) -> Dict[str, Any]:
    """Parse nvme smart-log output into a dictionary."""
    data = {}

    for line in output.strip().split('\n'):
        line = line.strip()
        if not line or ':' not in line:
            continue

        # Split on first colon
        parts = line.split(':', 1)
        if len(parts) != 2:
            continue

        key = parts[0].strip().lower().replace(' ', '_').replace('-', '_')
        value_str = parts[1].strip()

        # Parse numeric values
        # Handle formats like "42 C" (temperature), "100%" (percentage)
        # Handle formats like "0" (count), "1,234" (with commas)
        value_str_clean = value_str.replace(',', '').replace('%', '').strip()

        # Extract just the number if there's a unit
        match = re.match(r'^([\d.]+)', value_str_clean)
        if match:
            num_str = match.group(1)
            try:
                if '.' in num_str:
                    data[key] = float(num_str)
                else:
                    data[key] = int(num_str)
            except ValueError:
                data[key] = value_str
        else:
            data[key] = value_str

        # Store original string for reference
        data[f'{key}_raw'] = value_str

    return data


def get_nvme_smart_log(device: str) -> Optional[Dict[str, Any]]:
    """Get SMART log data for an NVMe device."""
    try:
        result = subprocess.run(
            ['nvme', 'smart-log', device],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return None

        return parse_smart_log(result.stdout)
    except Exception:
        return None


def get_nvme_id_ctrl(device: str) -> Optional[Dict[str, str]]:
    """Get controller identification data."""
    # Extract controller path from namespace path (nvme0n1 -> nvme0)
    ctrl_match = re.match(r'(/dev/nvme\d+)', device)
    if not ctrl_match:
        return None

    ctrl_path = ctrl_match.group(1)

    try:
        result = subprocess.run(
            ['nvme', 'id-ctrl', ctrl_path],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return None

        data = {}
        for line in result.stdout.strip().split('\n'):
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower()
                    value = parts[1].strip()
                    data[key] = value

        return data
    except Exception:
        return None


def analyze_drive_health(device: str, smart_data: Dict[str, Any],
                         id_data: Optional[Dict[str, str]],
                         temp_warn: int, temp_crit: int,
                         spare_warn: int) -> Dict[str, Any]:
    """Analyze NVMe drive health and return status."""
    result = {
        'device': device,
        'status': 'healthy',
        'issues': [],
        'warnings': [],
        'metrics': {},
    }

    # Extract model and serial if available
    if id_data:
        result['model'] = id_data.get('mn', 'Unknown').strip()
        result['serial'] = id_data.get('sn', 'Unknown').strip()
        result['firmware'] = id_data.get('fr', 'Unknown').strip()

    # Critical warning bitmap (bit 0-4 indicate various critical conditions)
    critical_warning = smart_data.get('critical_warning', 0)
    if isinstance(critical_warning, int) and critical_warning > 0:
        result['status'] = 'critical'
        result['issues'].append({
            'type': 'critical_warning',
            'value': critical_warning,
            'message': f'Critical warning flags set: {critical_warning}'
        })

        # Decode specific warnings
        if critical_warning & 0x01:
            result['issues'].append({
                'type': 'spare_below_threshold',
                'message': 'Available spare space below threshold'
            })
        if critical_warning & 0x02:
            result['issues'].append({
                'type': 'temperature_exceeded',
                'message': 'Temperature exceeded critical threshold'
            })
        if critical_warning & 0x04:
            result['issues'].append({
                'type': 'reliability_degraded',
                'message': 'NVM subsystem reliability degraded'
            })
        if critical_warning & 0x08:
            result['issues'].append({
                'type': 'read_only',
                'message': 'Media placed in read-only mode'
            })
        if critical_warning & 0x10:
            result['issues'].append({
                'type': 'volatile_backup_failed',
                'message': 'Volatile memory backup device failed'
            })

    # Temperature (in Celsius, from Kelvin if needed)
    temperature = smart_data.get('temperature', None)
    if temperature is None:
        # Try alternate key
        temperature = smart_data.get('composite_temperature', None)

    if temperature is not None:
        # Some drives report in Kelvin
        if temperature > 200:
            temperature = temperature - 273

        result['metrics']['temperature_c'] = temperature

        if temperature >= temp_crit:
            result['status'] = 'critical'
            result['issues'].append({
                'type': 'temperature_critical',
                'value': temperature,
                'threshold': temp_crit,
                'message': f'Temperature {temperature}°C exceeds critical threshold ({temp_crit}°C)'
            })
        elif temperature >= temp_warn:
            if result['status'] == 'healthy':
                result['status'] = 'warning'
            result['warnings'].append({
                'type': 'temperature_high',
                'value': temperature,
                'threshold': temp_warn,
                'message': f'Temperature {temperature}°C exceeds warning threshold ({temp_warn}°C)'
            })

    # Available spare (percentage)
    available_spare = smart_data.get('available_spare', None)
    if available_spare is not None:
        result['metrics']['available_spare_pct'] = available_spare

        if available_spare <= spare_warn:
            if result['status'] == 'healthy':
                result['status'] = 'warning'
            result['warnings'].append({
                'type': 'spare_low',
                'value': available_spare,
                'threshold': spare_warn,
                'message': f'Available spare {available_spare}% at or below threshold ({spare_warn}%)'
            })

        if available_spare <= 10:
            result['status'] = 'critical'
            result['issues'].append({
                'type': 'spare_critical',
                'value': available_spare,
                'message': f'Available spare critically low at {available_spare}%'
            })

    # Percentage used (wear indicator)
    percentage_used = smart_data.get('percentage_used', None)
    if percentage_used is not None:
        result['metrics']['percentage_used'] = percentage_used

        if percentage_used >= 100:
            result['status'] = 'critical'
            result['issues'].append({
                'type': 'endurance_exceeded',
                'value': percentage_used,
                'message': f'Drive endurance exceeded ({percentage_used}% of rated writes)'
            })
        elif percentage_used >= 90:
            if result['status'] == 'healthy':
                result['status'] = 'warning'
            result['warnings'].append({
                'type': 'endurance_high',
                'value': percentage_used,
                'message': f'Drive approaching endurance limit ({percentage_used}% used)'
            })

    # Media and data integrity errors
    media_errors = smart_data.get('media_errors', smart_data.get('media_and_data_integrity_errors', 0))
    if media_errors and media_errors > 0:
        result['status'] = 'critical'
        result['metrics']['media_errors'] = media_errors
        result['issues'].append({
            'type': 'media_errors',
            'value': media_errors,
            'message': f'{media_errors} media/data integrity errors detected'
        })

    # Unsafe shutdowns
    unsafe_shutdowns = smart_data.get('unsafe_shutdowns', 0)
    if unsafe_shutdowns:
        result['metrics']['unsafe_shutdowns'] = unsafe_shutdowns
        if unsafe_shutdowns > 100:
            if result['status'] == 'healthy':
                result['status'] = 'warning'
            result['warnings'].append({
                'type': 'unsafe_shutdowns_high',
                'value': unsafe_shutdowns,
                'message': f'High number of unsafe shutdowns: {unsafe_shutdowns}'
            })

    # Power-on hours
    power_on_hours = smart_data.get('power_on_hours', smart_data.get('power_on_hours_raw', None))
    if power_on_hours is not None:
        result['metrics']['power_on_hours'] = power_on_hours
        result['metrics']['power_on_days'] = round(power_on_hours / 24, 1)

    # Data units read/written (in 512KB blocks)
    data_read = smart_data.get('data_units_read', 0)
    data_written = smart_data.get('data_units_written', 0)
    if data_read:
        # Convert to TB (each unit is 1000 * 512 bytes = 500KB)
        result['metrics']['data_read_tb'] = round(data_read * 500 / (1024 * 1024 * 1024), 2)
    if data_written:
        result['metrics']['data_written_tb'] = round(data_written * 500 / (1024 * 1024 * 1024), 2)

    # Error log entries
    error_log_entries = smart_data.get('num_err_log_entries', smart_data.get('error_log_entries', 0))
    if error_log_entries:
        result['metrics']['error_log_entries'] = error_log_entries

    return result


def output_plain(results: List[Dict[str, Any]], verbose: bool, warn_only: bool) -> None:
    """Output results in plain text format."""
    if warn_only:
        results = [r for r in results if r['status'] != 'healthy']
        if not results:
            print("All NVMe drives healthy")
            return

    print("NVMe Drive Health Monitor")
    print("=" * 70)
    print()

    for drive in results:
        status_icon = '✓' if drive['status'] == 'healthy' else '!' if drive['status'] == 'warning' else '✗'
        print(f"[{status_icon}] {drive['device']}: {drive['status'].upper()}")

        if drive.get('model'):
            print(f"    Model: {drive['model']}")
        if drive.get('serial'):
            print(f"    Serial: {drive['serial']}")
        if drive.get('firmware'):
            print(f"    Firmware: {drive['firmware']}")

        metrics = drive.get('metrics', {})
        if metrics.get('temperature_c') is not None:
            print(f"    Temperature: {metrics['temperature_c']}°C")
        if metrics.get('available_spare_pct') is not None:
            print(f"    Available Spare: {metrics['available_spare_pct']}%")
        if metrics.get('percentage_used') is not None:
            print(f"    Percentage Used: {metrics['percentage_used']}%")
        if metrics.get('power_on_days') is not None:
            print(f"    Power-On Time: {metrics['power_on_days']} days")

        if verbose:
            if metrics.get('data_written_tb') is not None:
                print(f"    Data Written: {metrics['data_written_tb']} TB")
            if metrics.get('data_read_tb') is not None:
                print(f"    Data Read: {metrics['data_read_tb']} TB")
            if metrics.get('unsafe_shutdowns') is not None:
                print(f"    Unsafe Shutdowns: {metrics['unsafe_shutdowns']}")
            if metrics.get('media_errors') is not None:
                print(f"    Media Errors: {metrics['media_errors']}")
            if metrics.get('error_log_entries') is not None:
                print(f"    Error Log Entries: {metrics['error_log_entries']}")

        # Show issues
        for issue in drive.get('issues', []):
            print(f"    [CRITICAL] {issue['message']}")

        for warning in drive.get('warnings', []):
            print(f"    [WARNING] {warning['message']}")

        print()

    # Summary
    total = len(results)
    healthy = sum(1 for r in results if r['status'] == 'healthy')
    warning = sum(1 for r in results if r['status'] == 'warning')
    critical = sum(1 for r in results if r['status'] == 'critical')

    print(f"Summary: {total} drives - {healthy} healthy, {warning} warning, {critical} critical")


def output_json(results: List[Dict[str, Any]]) -> None:
    """Output results in JSON format."""
    total = len(results)
    healthy = sum(1 for r in results if r['status'] == 'healthy')
    warning = sum(1 for r in results if r['status'] == 'warning')
    critical = sum(1 for r in results if r['status'] == 'critical')

    if critical > 0:
        overall_status = 'critical'
    elif warning > 0:
        overall_status = 'warning'
    else:
        overall_status = 'healthy'

    output = {
        'status': overall_status,
        'summary': {
            'total_drives': total,
            'healthy': healthy,
            'warning': warning,
            'critical': critical,
        },
        'drives': results,
    }

    print(json.dumps(output, indent=2))


def output_table(results: List[Dict[str, Any]], warn_only: bool) -> None:
    """Output results in table format."""
    if warn_only:
        results = [r for r in results if r['status'] != 'healthy']
        if not results:
            print("All NVMe drives healthy")
            return

    print(f"{'Device':<15} {'Model':<20} {'Temp':>6} {'Spare':>6} {'Used':>6} {'Status':<10}")
    print("=" * 75)

    for drive in results:
        device = drive['device'].replace('/dev/', '')
        model = drive.get('model', 'Unknown')[:20]
        metrics = drive.get('metrics', {})

        temp = f"{metrics.get('temperature_c', 'N/A')}°C" if metrics.get('temperature_c') is not None else 'N/A'
        spare = f"{metrics.get('available_spare_pct', 'N/A')}%" if metrics.get('available_spare_pct') is not None else 'N/A'
        used = f"{metrics.get('percentage_used', 'N/A')}%" if metrics.get('percentage_used') is not None else 'N/A'

        print(f"{device:<15} {model:<20} {temp:>6} {spare:>6} {used:>6} {drive['status'].upper():<10}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor NVMe drive health and performance metrics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Check all NVMe drives
  %(prog)s --device /dev/nvme0n1  Check specific drive
  %(prog)s --format json          Output in JSON for monitoring
  %(prog)s --warn-only            Only show drives with issues
  %(prog)s --verbose              Show detailed metrics
  %(prog)s --temp-warn 60         Custom temperature warning threshold

Key metrics monitored:
  - Temperature: High temps indicate cooling issues or high load
  - Available Spare: Below threshold means drive needs replacement
  - Percentage Used: Wear indicator (100%% = rated endurance reached)
  - Media Errors: Any non-zero value indicates data integrity issues
  - Critical Warning: Bitmap of critical conditions from controller

Exit codes:
  0 - All NVMe drives healthy
  1 - Warnings or critical issues detected
  2 - Usage error or nvme-cli not available
"""
    )

    parser.add_argument(
        '-d', '--device',
        metavar='PATH',
        help='Specific NVMe device to check (e.g., /dev/nvme0n1)'
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
        help='Show detailed metrics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show drives with warnings or issues'
    )

    parser.add_argument(
        '--temp-warn',
        type=int,
        default=60,
        metavar='CELSIUS',
        help='Temperature warning threshold (default: 60°C)'
    )

    parser.add_argument(
        '--temp-crit',
        type=int,
        default=75,
        metavar='CELSIUS',
        help='Temperature critical threshold (default: 75°C)'
    )

    parser.add_argument(
        '--spare-warn',
        type=int,
        default=20,
        metavar='PERCENT',
        help='Available spare warning threshold (default: 20%%)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.temp_warn >= args.temp_crit:
        print("Error: --temp-warn must be less than --temp-crit", file=sys.stderr)
        return 2

    if args.spare_warn < 0 or args.spare_warn > 100:
        print("Error: --spare-warn must be 0-100", file=sys.stderr)
        return 2

    # Check for nvme-cli
    if not check_nvme_cli_available():
        print("Error: nvme-cli not found", file=sys.stderr)
        print("Install with: sudo apt-get install nvme-cli", file=sys.stderr)
        print("         or: sudo yum install nvme-cli", file=sys.stderr)
        return 2

    # Get devices to check
    if args.device:
        if not os.path.exists(args.device):
            print(f"Error: Device {args.device} not found", file=sys.stderr)
            return 2
        devices = [args.device]
    else:
        devices = get_nvme_devices()

    if not devices:
        if args.format == 'json':
            print(json.dumps({'status': 'ok', 'message': 'No NVMe devices found', 'drives': []}))
        else:
            print("No NVMe devices found")
        return 0

    # Check each device
    results = []
    for device in devices:
        smart_data = get_nvme_smart_log(device)
        if smart_data is None:
            results.append({
                'device': device,
                'status': 'unknown',
                'issues': [{'type': 'read_error', 'message': 'Could not read SMART data'}],
                'warnings': [],
                'metrics': {},
            })
            continue

        id_data = get_nvme_id_ctrl(device)

        result = analyze_drive_health(
            device, smart_data, id_data,
            args.temp_warn, args.temp_crit, args.spare_warn
        )
        results.append(result)

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.warn_only)
    else:
        output_plain(results, args.verbose, args.warn_only)

    # Determine exit code
    has_critical = any(r['status'] == 'critical' for r in results)
    has_warning = any(r['status'] == 'warning' for r in results)

    if has_critical or has_warning:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
