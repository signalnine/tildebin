#!/usr/bin/env python3
"""
NVMe SSD health monitoring script.

Monitors NVMe-specific health metrics including wear level, power cycles,
unsafe shutdowns, media errors, and thermal throttling using nvme-cli.
Complements disk_health_check.py with NVMe-specific diagnostics.

Exit codes:
    0 - All NVMe devices are healthy
    1 - Warnings or errors detected (high wear, errors, throttling)
    2 - Missing dependency (nvme-cli not installed)
"""

import argparse
import subprocess
import sys
import json
import re


def check_nvme_cli():
    """Check if nvme-cli is installed"""
    try:
        result = subprocess.run(
            ['which', 'nvme'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_nvme_devices():
    """Get list of NVMe devices"""
    try:
        result = subprocess.run(
            ['nvme', 'list', '-o', 'json'],
            capture_output=True,
            text=True,
            check=True
        )
        data = json.loads(result.stdout)
        return data.get('Devices', [])
    except subprocess.CalledProcessError:
        # Fallback to parsing text output
        result = subprocess.run(
            ['nvme', 'list'],
            capture_output=True,
            text=True
        )
        devices = []
        for line in result.stdout.split('\n')[2:]:  # Skip header
            if line.strip() and line.startswith('/dev/nvme'):
                parts = line.split()
                if parts:
                    devices.append({'DevicePath': parts[0]})
        return devices
    except Exception as e:
        print(f"Error listing NVMe devices: {e}", file=sys.stderr)
        return []


def get_smart_log(device):
    """Get SMART log for NVMe device"""
    try:
        result = subprocess.run(
            ['nvme', 'smart-log', device, '-o', 'json'],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError:
        # Fallback to text parsing
        result = subprocess.run(
            ['nvme', 'smart-log', device],
            capture_output=True,
            text=True
        )
        return parse_smart_text(result.stdout)
    except Exception as e:
        print(f"Error reading SMART log for {device}: {e}", file=sys.stderr)
        return None


def parse_smart_text(output):
    """Parse text output from nvme smart-log"""
    data = {}
    for line in output.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            if 'percentage_used' in key.lower():
                data['percentage_used'] = int(value.rstrip('%'))
            elif 'power_cycles' in key.lower():
                data['power_cycles'] = int(value.replace(',', ''))
            elif 'unsafe_shutdowns' in key.lower():
                data['unsafe_shutdowns'] = int(value.replace(',', ''))
            elif 'media_errors' in key.lower():
                data['media_and_data_integrity_errors'] = int(value.replace(',', ''))
            elif 'temperature' in key.lower():
                # Extract numeric temperature
                match = re.search(r'(\d+)', value)
                if match:
                    data['temperature'] = int(match.group(1))
            elif 'thermal_temp1_transition_count' in key.lower():
                data['thermal_mgmt_temp1_transition_count'] = int(value.replace(',', ''))

    return data


def analyze_health(device_path, smart_data, thresholds):
    """Analyze NVMe health and return issues"""
    issues = []

    if not smart_data:
        return ['Unable to read SMART data']

    # Wear level check
    wear = smart_data.get('percentage_used', 0)
    if wear >= thresholds['critical_wear']:
        issues.append(f"CRITICAL: {wear}% wear level")
    elif wear >= thresholds['warn_wear']:
        issues.append(f"WARNING: {wear}% wear level")

    # Media errors
    media_errors = smart_data.get('media_and_data_integrity_errors', 0)
    if media_errors > 0:
        issues.append(f"CRITICAL: {media_errors} media errors detected")

    # Unsafe shutdowns
    unsafe_shutdowns = smart_data.get('unsafe_shutdowns', 0)
    if unsafe_shutdowns > thresholds['max_unsafe_shutdowns']:
        issues.append(f"WARNING: {unsafe_shutdowns} unsafe shutdowns")

    # Temperature check
    temp = smart_data.get('temperature', 0)
    if temp >= thresholds['critical_temp']:
        issues.append(f"CRITICAL: {temp}°C temperature")
    elif temp >= thresholds['warn_temp']:
        issues.append(f"WARNING: {temp}°C temperature")

    # Thermal throttling
    throttle_count = smart_data.get('thermal_mgmt_temp1_transition_count', 0)
    if throttle_count > 0:
        issues.append(f"WARNING: {throttle_count} thermal throttling events")

    return issues


def format_output_plain(results, warn_only):
    """Format output as plain text"""
    for result in results:
        if warn_only and not result['issues']:
            continue

        device = result['device']
        status = 'HEALTHY' if not result['issues'] else 'WARNING'

        smart = result.get('smart_data', {})
        wear = smart.get('percentage_used', 'N/A')
        temp = smart.get('temperature', 'N/A')
        power_cycles = smart.get('power_cycles', 'N/A')

        print(f"{device} {status} wear={wear}% temp={temp}°C power_cycles={power_cycles}")

        if result['issues']:
            for issue in result['issues']:
                print(f"  {issue}")


def format_output_table(results, warn_only):
    """Format output as table"""
    if warn_only:
        results = [r for r in results if r['issues']]

    if not results:
        print("No NVMe devices with issues found")
        return

    print(f"{'Device':<15} {'Status':<10} {'Wear%':<8} {'Temp°C':<8} {'Power Cycles':<15} {'Issues'}")
    print("-" * 80)

    for result in results:
        device = result['device'].split('/')[-1]
        status = 'HEALTHY' if not result['issues'] else 'WARNING'
        smart = result.get('smart_data', {})
        wear = smart.get('percentage_used', 'N/A')
        temp = smart.get('temperature', 'N/A')
        power_cycles = smart.get('power_cycles', 'N/A')
        issues_str = f"{len(result['issues'])} issues" if result['issues'] else ""

        print(f"{device:<15} {status:<10} {str(wear):<8} {str(temp):<8} {str(power_cycles):<15} {issues_str}")


def format_output_json(results):
    """Format output as JSON"""
    print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Monitor NVMe SSD health metrics (wear level, errors, temperature)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: %(default)s)"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show devices with warnings or issues"
    )

    parser.add_argument(
        "--warn-wear",
        type=int,
        default=80,
        help="Wear level warning threshold percentage (default: %(default)s)"
    )

    parser.add_argument(
        "--critical-wear",
        type=int,
        default=90,
        help="Wear level critical threshold percentage (default: %(default)s)"
    )

    parser.add_argument(
        "--warn-temp",
        type=int,
        default=70,
        help="Temperature warning threshold in Celsius (default: %(default)s)"
    )

    parser.add_argument(
        "--critical-temp",
        type=int,
        default=80,
        help="Temperature critical threshold in Celsius (default: %(default)s)"
    )

    parser.add_argument(
        "--max-unsafe-shutdowns",
        type=int,
        default=10,
        help="Maximum unsafe shutdowns before warning (default: %(default)s)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )

    args = parser.parse_args()

    # Check for nvme-cli
    if not check_nvme_cli():
        print("Error: 'nvme' command not found", file=sys.stderr)
        print("Install with: sudo apt-get install nvme-cli", file=sys.stderr)
        sys.exit(2)

    thresholds = {
        'warn_wear': args.warn_wear,
        'critical_wear': args.critical_wear,
        'warn_temp': args.warn_temp,
        'critical_temp': args.critical_temp,
        'max_unsafe_shutdowns': args.max_unsafe_shutdowns
    }

    # Get NVMe devices
    devices = get_nvme_devices()

    if not devices:
        print("No NVMe devices found", file=sys.stderr)
        sys.exit(0)

    # Collect health data
    results = []
    has_issues = False

    for device in devices:
        device_path = device.get('DevicePath', device.get('device', ''))
        if not device_path:
            continue

        smart_data = get_smart_log(device_path)
        issues = analyze_health(device_path, smart_data, thresholds)

        if issues:
            has_issues = True

        results.append({
            'device': device_path,
            'smart_data': smart_data or {},
            'issues': issues
        })

    # Output results
    if args.format == "json":
        format_output_json(results)
    elif args.format == "table":
        format_output_table(results, args.warn_only)
    else:  # plain
        format_output_plain(results, args.warn_only)

    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()
