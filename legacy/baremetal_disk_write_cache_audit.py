#!/usr/bin/env python3
"""
Audit disk write cache settings for data integrity compliance.

Checks hard disk and SSD write cache configuration to ensure data integrity.
Write cache (WCE - Write Cache Enable) can improve performance but poses
data loss risks during power failures. This is critical for:

- Database servers requiring data integrity guarantees
- Systems without UPS/battery-backed write cache
- Compliance with data retention requirements
- Storage systems using software RAID

The tool checks:
- Write cache status via hdparm (SATA/SAS) or sdparm (SCSI)
- NVMe volatile write cache status
- Device queue write cache settings
- Recommendations based on device type and configuration

Exit codes:
    0 - All disks have expected write cache settings
    1 - Write cache warnings detected (enabled when should be disabled or vice versa)
    2 - Usage error or missing dependencies
"""

import argparse
import glob
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


def read_sysfs(path):
    """Read a value from sysfs."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (IOError, OSError, PermissionError):
        return None


def get_block_devices():
    """Get list of block devices (excluding virtual devices)."""
    devices = []
    virtual_prefixes = ('loop', 'ram', 'dm-', 'md', 'nbd', 'zram')

    try:
        for path in glob.glob('/sys/block/*'):
            name = os.path.basename(path)
            if name.startswith(virtual_prefixes):
                continue

            # Check if it's a real device (has a device symlink)
            if os.path.exists(os.path.join(path, 'device')):
                devices.append(name)
    except OSError:
        pass

    return sorted(devices)


def is_nvme_device(device):
    """Check if device is an NVMe device."""
    return device.startswith('nvme')


def is_rotational(device):
    """Check if device is rotational (HDD) or non-rotational (SSD/NVMe)."""
    path = f'/sys/block/{device}/queue/rotational'
    value = read_sysfs(path)
    if value is not None:
        return value == '1'
    return None


def get_device_model(device):
    """Get device model/name."""
    # Try different paths for model info
    paths = [
        f'/sys/block/{device}/device/model',
        f'/sys/block/{device}/device/name',
    ]

    for path in paths:
        model = read_sysfs(path)
        if model:
            return model.strip()

    return "Unknown"


def get_device_size(device):
    """Get device size in bytes."""
    path = f'/sys/block/{device}/size'
    size_sectors = read_sysfs(path)
    if size_sectors:
        try:
            # Size is in 512-byte sectors
            return int(size_sectors) * 512
        except ValueError:
            pass
    return 0


def format_size(size_bytes):
    """Format size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f}PB"


def get_queue_write_cache(device):
    """Get write cache setting from block queue."""
    path = f'/sys/block/{device}/queue/write_cache'
    value = read_sysfs(path)
    if value:
        # Can be 'write back', 'write through', or 'write back, no read (dax)'
        return value
    return None


def get_hdparm_write_cache(device):
    """Get write cache status using hdparm."""
    if not check_tool_available('hdparm'):
        return None, "hdparm not available"

    returncode, stdout, stderr = run_command(['hdparm', '-W', f'/dev/{device}'])

    if returncode != 0:
        return None, stderr.strip() if stderr else "hdparm failed"

    # Parse output like: " write-caching =  1 (on)"
    match = re.search(r'write-caching\s*=\s*(\d+)\s*\((\w+)\)', stdout)
    if match:
        enabled = match.group(1) == '1'
        status = match.group(2)
        return {'enabled': enabled, 'status': status}, None

    # Alternative format: "write-caching = not supported"
    if 'not supported' in stdout.lower():
        return {'enabled': None, 'status': 'not supported'}, None

    return None, "Could not parse hdparm output"


def get_sdparm_write_cache(device):
    """Get write cache status using sdparm (for SCSI/SAS devices)."""
    if not check_tool_available('sdparm'):
        return None, "sdparm not available"

    returncode, stdout, stderr = run_command(['sdparm', '-q', '-g', 'WCE', f'/dev/{device}'])

    if returncode != 0:
        return None, stderr.strip() if stderr else "sdparm failed"

    # Parse output like: "WCE         1  [cha: y, def:  1, sav:  1]"
    match = re.search(r'WCE\s+(\d+)', stdout)
    if match:
        enabled = match.group(1) == '1'
        return {'enabled': enabled, 'status': 'on' if enabled else 'off'}, None

    return None, "Could not parse sdparm output"


def get_nvme_write_cache(device):
    """Get write cache status for NVMe device."""
    if not check_tool_available('nvme'):
        return None, "nvme-cli not available"

    # Extract the nvme device (nvme0, nvme1, etc.)
    match = re.match(r'(nvme\d+)', device)
    if not match:
        return None, "Invalid NVMe device name"

    nvme_dev = match.group(1)
    returncode, stdout, stderr = run_command(['nvme', 'id-ctrl', f'/dev/{nvme_dev}', '-H'])

    if returncode != 0:
        return None, stderr.strip() if stderr else "nvme id-ctrl failed"

    # Look for Volatile Write Cache (VWC)
    vwc_match = re.search(r'vwc\s*:\s*(\d+)', stdout.lower())
    if vwc_match:
        vwc_value = int(vwc_match.group(1))
        # Bit 0 indicates volatile write cache present
        has_vwc = bool(vwc_value & 0x1)
        return {
            'enabled': has_vwc,
            'status': 'present' if has_vwc else 'not present',
            'vwc_value': vwc_value
        }, None

    return None, "Could not parse NVMe VWC status"


def analyze_device(device, require_disabled=False):
    """Analyze write cache configuration for a device."""
    info = {
        'device': device,
        'path': f'/dev/{device}',
        'model': get_device_model(device),
        'size': format_size(get_device_size(device)),
        'rotational': is_rotational(device),
        'is_nvme': is_nvme_device(device),
        'queue_write_cache': get_queue_write_cache(device),
        'write_cache': None,
        'source': None,
        'issues': [],
        'recommendations': []
    }

    # Determine device type description
    if info['is_nvme']:
        info['type'] = 'NVMe SSD'
    elif info['rotational'] is True:
        info['type'] = 'HDD'
    elif info['rotational'] is False:
        info['type'] = 'SSD'
    else:
        info['type'] = 'Unknown'

    # Get write cache status
    if info['is_nvme']:
        result, error = get_nvme_write_cache(device)
        if result:
            info['write_cache'] = result
            info['source'] = 'nvme-cli'
        else:
            info['issues'].append(f"Could not check NVMe write cache: {error}")
    else:
        # Try hdparm first (most common for SATA)
        result, error = get_hdparm_write_cache(device)
        if result:
            info['write_cache'] = result
            info['source'] = 'hdparm'
        else:
            # Try sdparm for SCSI/SAS
            result, error = get_sdparm_write_cache(device)
            if result:
                info['write_cache'] = result
                info['source'] = 'sdparm'
            else:
                info['issues'].append(f"Could not determine write cache status: {error}")

    # Analyze and generate recommendations
    wc = info['write_cache']
    if wc and wc.get('enabled') is not None:
        if require_disabled and wc['enabled']:
            info['issues'].append("Write cache is ENABLED but policy requires it disabled")
            info['recommendations'].append(
                f"Disable write cache with: hdparm -W0 /dev/{device}"
                if not info['is_nvme'] else
                "Consider disabling volatile write cache via NVMe features"
            )
        elif not require_disabled and wc['enabled']:
            info['recommendations'].append(
                "Write cache enabled - ensure UPS/BBU protection for data integrity"
            )

    # Check queue write cache setting
    qwc = info['queue_write_cache']
    if qwc:
        if 'write back' in qwc.lower():
            info['recommendations'].append(
                "Queue uses write-back mode - enables caching but requires power protection"
            )
        elif 'write through' in qwc.lower():
            info['recommendations'].append(
                "Queue uses write-through mode - safer but slower"
            )

    return info


def format_plain(data, verbose=False, warn_only=False):
    """Format output as plain text."""
    lines = []

    lines.append("Disk Write Cache Audit Report")
    lines.append("=" * 60)
    lines.append("")

    # Summary
    total = data['summary']['total']
    enabled = data['summary']['write_cache_enabled']
    disabled = data['summary']['write_cache_disabled']
    unknown = data['summary']['write_cache_unknown']
    with_issues = data['summary']['devices_with_issues']

    lines.append(f"Summary:")
    lines.append(f"  Total devices: {total}")
    lines.append(f"  Write cache enabled: {enabled}")
    lines.append(f"  Write cache disabled: {disabled}")
    lines.append(f"  Write cache unknown: {unknown}")
    lines.append(f"  Devices with issues: {with_issues}")
    lines.append("")

    # Device details
    for device in data['devices']:
        if warn_only and not device['issues']:
            continue

        wc_status = "unknown"
        if device['write_cache']:
            wc = device['write_cache']
            if wc.get('enabled') is True:
                wc_status = "ENABLED"
            elif wc.get('enabled') is False:
                wc_status = "disabled"
            elif wc.get('status'):
                wc_status = wc['status']

        issue_marker = " [!]" if device['issues'] else ""
        lines.append(f"{device['device']} ({device['type']}, {device['size']}){issue_marker}")
        lines.append(f"  Model: {device['model']}")
        lines.append(f"  Write cache: {wc_status}")

        if device['queue_write_cache']:
            lines.append(f"  Queue mode: {device['queue_write_cache']}")

        if verbose and device['source']:
            lines.append(f"  Source: {device['source']}")

        for issue in device['issues']:
            lines.append(f"  [WARNING] {issue}")

        if verbose:
            for rec in device['recommendations']:
                lines.append(f"  [INFO] {rec}")

        lines.append("")

    return '\n'.join(lines)


def format_json(data):
    """Format output as JSON."""
    return json.dumps(data, indent=2)


def format_table(data, warn_only=False):
    """Format output as table."""
    lines = []

    header = f"{'Device':<12} {'Type':<10} {'Size':<10} {'Write Cache':<15} {'Issues'}"
    lines.append(header)
    lines.append("-" * 70)

    for device in data['devices']:
        if warn_only and not device['issues']:
            continue

        wc_status = "unknown"
        if device['write_cache']:
            wc = device['write_cache']
            if wc.get('enabled') is True:
                wc_status = "ENABLED"
            elif wc.get('enabled') is False:
                wc_status = "disabled"
            elif wc.get('status'):
                wc_status = wc['status']

        issues_str = str(len(device['issues'])) if device['issues'] else "-"

        lines.append(f"{device['device']:<12} {device['type']:<10} "
                     f"{device['size']:<10} {wc_status:<15} {issues_str}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Audit disk write cache settings for data integrity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Write Cache Considerations:
  - ENABLED: Better performance but data loss risk on power failure
  - DISABLED: Safer for data integrity but lower performance
  - Battery-backed caches (BBU/BBW) can safely enable write cache

Data Integrity Guidance:
  - Database servers: Consider disabling write cache or use UPS/BBU
  - Write-heavy workloads: May need write cache for performance
  - Software RAID: Write cache can cause data inconsistency

Examples:
  %(prog)s                        # Audit all disks
  %(prog)s --require-disabled     # Flag enabled write caches as issues
  %(prog)s --format json          # JSON output for automation
  %(prog)s -v                     # Verbose with recommendations

Exit codes:
  0 - All disks have expected write cache settings
  1 - Write cache warnings detected
  2 - Usage error or missing dependencies
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
        help="Show detailed information and recommendations"
    )

    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show devices with issues"
    )

    parser.add_argument(
        "--require-disabled",
        action="store_true",
        help="Flag enabled write caches as issues (for data integrity compliance)"
    )

    parser.add_argument(
        "-d", "--device",
        help="Check specific device only (e.g., sda, nvme0n1)"
    )

    args = parser.parse_args()

    # Get devices to check
    if args.device:
        devices = [args.device]
        # Verify device exists
        if not os.path.exists(f'/sys/block/{args.device}'):
            print(f"Error: Device {args.device} not found", file=sys.stderr)
            sys.exit(2)
    else:
        devices = get_block_devices()

    if not devices:
        print("No block devices found", file=sys.stderr)
        sys.exit(2)

    # Analyze devices
    results = []
    for device in devices:
        info = analyze_device(device, require_disabled=args.require_disabled)
        results.append(info)

    # Calculate summary
    summary = {
        'total': len(results),
        'write_cache_enabled': 0,
        'write_cache_disabled': 0,
        'write_cache_unknown': 0,
        'devices_with_issues': 0
    }

    for r in results:
        if r['write_cache']:
            if r['write_cache'].get('enabled') is True:
                summary['write_cache_enabled'] += 1
            elif r['write_cache'].get('enabled') is False:
                summary['write_cache_disabled'] += 1
            else:
                summary['write_cache_unknown'] += 1
        else:
            summary['write_cache_unknown'] += 1

        if r['issues']:
            summary['devices_with_issues'] += 1

    data = {
        'summary': summary,
        'devices': results,
        'require_disabled_policy': args.require_disabled
    }

    # Output
    if args.format == "json":
        print(format_json(data))
    elif args.format == "table":
        print(format_table(data, warn_only=args.warn_only))
    else:
        print(format_plain(data, verbose=args.verbose, warn_only=args.warn_only))

    # Exit code
    sys.exit(1 if summary['devices_with_issues'] > 0 else 0)


if __name__ == "__main__":
    main()
