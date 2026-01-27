#!/usr/bin/env python3
"""
Monitor TPM (Trusted Platform Module) health and status for baremetal systems.

This script checks TPM presence, version, and operational status. Useful for:

- Verifying TPM is present and functional for disk encryption (LUKS with TPM)
- Checking TPM version (1.2 vs 2.0) for compliance requirements
- Monitoring TPM state for remote attestation workflows
- Auditing security posture (many standards require functional TPM)
- Detecting TPM issues before they impact boot or encryption

The script uses sysfs and tpm2-tools to gather TPM information and analyzes
the results for common issues.

Exit codes:
    0 - TPM healthy, no issues detected
    1 - Issues detected (TPM missing, disabled, or errors)
    2 - Usage error or required tools unavailable
"""

import argparse
import json
import os
import re
import subprocess
import sys


def check_tpm_sysfs():
    """Check for TPM device via sysfs."""
    tpm_paths = [
        '/sys/class/tpm/tpm0',
        '/sys/class/misc/tpm0',
        '/dev/tpm0',
        '/dev/tpmrm0',
    ]

    found = {}
    for path in tpm_paths:
        found[path] = os.path.exists(path)

    return found


def get_tpm_version_sysfs():
    """Get TPM version from sysfs."""
    version_info = {
        'version': None,
        'manufacturer': None,
        'model': None,
    }

    # Try to read TPM version
    caps_path = '/sys/class/tpm/tpm0/caps'
    if os.path.exists(caps_path):
        try:
            with open(caps_path, 'r') as f:
                content = f.read()
                if 'TPM-Version' in content:
                    match = re.search(r'TPM-Version:\s+(\S+)', content)
                    if match:
                        version_info['version'] = match.group(1)
        except (PermissionError, IOError):
            pass

    # Try device_version for TPM 2.0
    device_version_path = '/sys/class/tpm/tpm0/device/description'
    if os.path.exists(device_version_path):
        try:
            with open(device_version_path, 'r') as f:
                version_info['description'] = f.read().strip()
        except (PermissionError, IOError):
            pass

    # Try tpm_version_major/minor
    major_path = '/sys/class/tpm/tpm0/tpm_version_major'
    minor_path = '/sys/class/tpm/tpm0/tpm_version_minor'

    if os.path.exists(major_path):
        try:
            with open(major_path, 'r') as f:
                major = f.read().strip()
            minor = '0'
            if os.path.exists(minor_path):
                with open(minor_path, 'r') as f:
                    minor = f.read().strip()
            version_info['version'] = f"{major}.{minor}"
        except (PermissionError, IOError):
            pass

    return version_info


def check_tpm2_tools_available():
    """Check if tpm2-tools is available."""
    try:
        result = subprocess.run(
            ['which', 'tpm2_getcap'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def run_tpm2_getcap(capability):
    """Run tpm2_getcap and return output."""
    try:
        result = subprocess.run(
            ['tpm2_getcap', capability],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", "tpm2_getcap not found"
    except Exception as e:
        return -1, "", str(e)


def get_tpm2_properties():
    """Get TPM 2.0 properties using tpm2-tools."""
    properties = {
        'manufacturer': None,
        'vendor_string': None,
        'firmware_version': None,
        'family': None,
        'revision': None,
        'lockout_counter': None,
        'lockout_interval': None,
        'lockout_recovery': None,
    }

    # Get fixed properties
    returncode, stdout, stderr = run_tpm2_getcap('properties-fixed')
    if returncode == 0:
        lines = stdout.strip().split('\n')
        for line in lines:
            if 'TPM2_PT_MANUFACTURER' in line:
                match = re.search(r'value:\s*(.+)', line)
                if match:
                    properties['manufacturer'] = match.group(1).strip()
            elif 'TPM2_PT_VENDOR_STRING' in line:
                match = re.search(r'value:\s*"(.+)"', line)
                if match:
                    properties['vendor_string'] = match.group(1).strip()
            elif 'TPM2_PT_FIRMWARE_VERSION' in line:
                match = re.search(r'value:\s*(.+)', line)
                if match:
                    properties['firmware_version'] = match.group(1).strip()
            elif 'TPM2_PT_FAMILY_INDICATOR' in line:
                match = re.search(r'value:\s*"(.+)"', line)
                if match:
                    properties['family'] = match.group(1).strip()
            elif 'TPM2_PT_REVISION' in line:
                match = re.search(r'value:\s*(.+)', line)
                if match:
                    properties['revision'] = match.group(1).strip()

    # Get variable properties (lockout status)
    returncode, stdout, stderr = run_tpm2_getcap('properties-variable')
    if returncode == 0:
        lines = stdout.strip().split('\n')
        for line in lines:
            if 'TPM2_PT_LOCKOUT_COUNTER' in line:
                match = re.search(r'value:\s*(\d+)', line)
                if match:
                    properties['lockout_counter'] = int(match.group(1))
            elif 'TPM2_PT_LOCKOUT_INTERVAL' in line:
                match = re.search(r'value:\s*(\d+)', line)
                if match:
                    properties['lockout_interval'] = int(match.group(1))
            elif 'TPM2_PT_LOCKOUT_RECOVERY' in line:
                match = re.search(r'value:\s*(\d+)', line)
                if match:
                    properties['lockout_recovery'] = int(match.group(1))

    return properties


def check_tpm2_selftest():
    """Run TPM 2.0 self-test."""
    try:
        result = subprocess.run(
            ['tpm2_selftest', '--fulltest'],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode == 0, result.stderr
    except subprocess.TimeoutExpired:
        return False, "Self-test timed out"
    except FileNotFoundError:
        return None, "tpm2_selftest not found"
    except Exception as e:
        return False, str(e)


def get_tpm_pcr_banks():
    """Get available PCR banks."""
    banks = []

    returncode, stdout, stderr = run_tpm2_getcap('pcrs')
    if returncode == 0:
        # Parse PCR bank info
        current_bank = None
        for line in stdout.strip().split('\n'):
            if line.strip().startswith('sha'):
                bank_match = re.match(r'\s*(sha\d+):', line)
                if bank_match:
                    current_bank = bank_match.group(1)
                    banks.append(current_bank)

    return banks


def analyze_tpm_status(sysfs_status, version_info, tpm2_props, selftest_ok, pcr_banks):
    """Analyze TPM status and return issues."""
    issues = []

    # Check if TPM device exists
    has_tpm = any(sysfs_status.values())
    if not has_tpm:
        issues.append({
            'severity': 'CRITICAL',
            'message': 'No TPM device detected',
            'recommendation': 'Check BIOS/UEFI settings to enable TPM'
        })
        return issues

    # Check device permissions
    if sysfs_status.get('/dev/tpm0') or sysfs_status.get('/dev/tpmrm0'):
        # Check if we can access it
        dev_path = '/dev/tpmrm0' if sysfs_status.get('/dev/tpmrm0') else '/dev/tpm0'
        if not os.access(dev_path, os.R_OK):
            issues.append({
                'severity': 'WARNING',
                'message': f'Cannot read {dev_path} (permission denied)',
                'recommendation': 'Add user to tss group or run as root'
            })

    # Check TPM version
    version = version_info.get('version')
    if version:
        try:
            major = int(version.split('.')[0])
            if major < 2:
                issues.append({
                    'severity': 'INFO',
                    'message': f'TPM version {version} detected (TPM 1.2)',
                    'recommendation': 'Consider upgrading to TPM 2.0 for better security features'
                })
        except (ValueError, IndexError):
            pass

    # Check self-test result
    if selftest_ok is False:
        issues.append({
            'severity': 'CRITICAL',
            'message': 'TPM self-test failed',
            'recommendation': 'TPM may be malfunctioning; check firmware or hardware'
        })
    elif selftest_ok is None:
        issues.append({
            'severity': 'INFO',
            'message': 'Could not run TPM self-test (tpm2_selftest not available)',
            'recommendation': 'Install tpm2-tools for full TPM health checking'
        })

    # Check lockout counter (TPM 2.0)
    if tpm2_props and tpm2_props.get('lockout_counter') is not None:
        lockout_count = tpm2_props['lockout_counter']
        if lockout_count > 0:
            issues.append({
                'severity': 'WARNING',
                'message': f'TPM lockout counter is {lockout_count} (failed auth attempts)',
                'recommendation': 'TPM may lock out if counter reaches max; investigate failed attempts'
            })

    # Check PCR banks
    if pcr_banks:
        if 'sha1' in pcr_banks and 'sha256' not in pcr_banks:
            issues.append({
                'severity': 'WARNING',
                'message': 'Only SHA-1 PCR bank available',
                'recommendation': 'Enable SHA-256 PCR bank for stronger security'
            })
    elif has_tpm and check_tpm2_tools_available():
        issues.append({
            'severity': 'INFO',
            'message': 'Could not enumerate PCR banks',
            'recommendation': 'Check TPM resource manager (tpm2-abrmd) is running'
        })

    return issues


def output_plain(data, issues, verbose, warn_only):
    """Output TPM status in plain text format."""
    if not warn_only:
        print(f"TPM Present: {'Yes' if data['tpm_present'] else 'No'}")

        if data['tpm_present']:
            if data['version']:
                print(f"TPM Version: {data['version']}")

            if data.get('tpm2_properties'):
                props = data['tpm2_properties']
                if props.get('manufacturer'):
                    print(f"Manufacturer: {props['manufacturer']}")
                if props.get('vendor_string'):
                    print(f"Vendor: {props['vendor_string']}")
                if props.get('firmware_version'):
                    print(f"Firmware: {props['firmware_version']}")

            if data.get('selftest_passed') is not None:
                status = 'Passed' if data['selftest_passed'] else 'Failed'
                print(f"Self-Test: {status}")

            if data.get('pcr_banks'):
                print(f"PCR Banks: {', '.join(data['pcr_banks'])}")

            if verbose:
                print(f"\nDevice Paths:")
                for path, exists in data['device_paths'].items():
                    status = 'Present' if exists else 'Absent'
                    print(f"  {path}: {status}")

    if issues:
        if not warn_only:
            print(f"\n{'='*50}")
            print("ISSUES DETECTED")
            print('='*50)

        for issue in issues:
            print(f"[{issue['severity']}] {issue['message']}")
            if verbose:
                print(f"  Recommendation: {issue['recommendation']}")

    if not issues and not warn_only:
        print("\nTPM health check passed - no issues detected.")


def output_json(data, issues):
    """Output TPM status in JSON format."""
    output = {
        'tpm_status': data,
        'issues': issues,
        'issue_count': len(issues),
        'healthy': len([i for i in issues if i['severity'] == 'CRITICAL']) == 0
    }

    print(json.dumps(output, indent=2))


def output_table(data, issues, verbose, warn_only):
    """Output TPM status in table format."""
    if not warn_only:
        print("="*60)
        print(f"{'TPM HEALTH STATUS':^60}")
        print("="*60)
        print()

        print(f"{'Property':<25} {'Value':<35}")
        print("-"*60)
        print(f"{'TPM Present':<25} {'Yes' if data['tpm_present'] else 'No':<35}")

        if data['tpm_present']:
            if data['version']:
                print(f"{'Version':<25} {data['version']:<35}")

            if data.get('tpm2_properties'):
                props = data['tpm2_properties']
                if props.get('manufacturer'):
                    print(f"{'Manufacturer':<25} {props['manufacturer']:<35}")
                if props.get('vendor_string'):
                    print(f"{'Vendor':<25} {props['vendor_string']:<35}")
                if props.get('firmware_version'):
                    print(f"{'Firmware':<25} {props['firmware_version']:<35}")
                if props.get('lockout_counter') is not None:
                    print(f"{'Lockout Counter':<25} {props['lockout_counter']:<35}")

            if data.get('selftest_passed') is not None:
                status = 'Passed' if data['selftest_passed'] else 'FAILED'
                print(f"{'Self-Test':<25} {status:<35}")

            if data.get('pcr_banks'):
                print(f"{'PCR Banks':<25} {', '.join(data['pcr_banks']):<35}")

        print()

    if issues:
        if not warn_only:
            print("="*60)
            print(f"{'ISSUES DETECTED':^60}")
            print("="*60)
            print()

        print(f"{'Severity':<12} {'Message':<48}")
        print("-"*60)

        for issue in issues:
            message = issue['message']
            if len(message) > 48:
                print(f"{issue['severity']:<12} {message[:48]}")
                remaining = message[48:]
                while remaining:
                    print(f"{'':<12} {remaining[:48]}")
                    remaining = remaining[48:]
            else:
                print(f"{issue['severity']:<12} {message:<48}")

            if verbose:
                rec = issue['recommendation']
                print(f"{'  -> Fix':<12} {rec[:48]}")
                if len(rec) > 48:
                    remaining = rec[48:]
                    while remaining:
                        print(f"{'':<12} {remaining[:48]}")
                        remaining = remaining[48:]
                print()

        print()

    if not issues and not warn_only:
        print("="*60)
        print(f"{'TPM HEALTHY - NO ISSUES':^60}")
        print("="*60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor TPM health and status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Basic TPM health check
  %(prog)s --verbose           # Show detailed TPM information
  %(prog)s --format json       # JSON output for automation
  %(prog)s --warn-only         # Only show issues

Exit codes:
  0 - TPM healthy, no issues detected
  1 - Issues detected (missing, disabled, or errors)
  2 - Usage error
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
        help='Show detailed TPM information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    parser.add_argument(
        '--skip-selftest',
        action='store_true',
        help='Skip TPM self-test (faster but less thorough)'
    )

    args = parser.parse_args()

    # Check TPM via sysfs
    sysfs_status = check_tpm_sysfs()
    tpm_present = any(sysfs_status.values())

    # Get version info
    version_info = get_tpm_version_sysfs()

    # TPM 2.0 specific checks
    tpm2_props = None
    selftest_ok = None
    pcr_banks = []

    if tpm_present and check_tpm2_tools_available():
        tpm2_props = get_tpm2_properties()

        if not args.skip_selftest:
            selftest_ok, _ = check_tpm2_selftest()

        pcr_banks = get_tpm_pcr_banks()

    # Analyze status
    issues = analyze_tpm_status(
        sysfs_status, version_info, tpm2_props, selftest_ok, pcr_banks
    )

    # Build output data
    data = {
        'tpm_present': tpm_present,
        'device_paths': sysfs_status,
        'version': version_info.get('version'),
        'tpm2_properties': tpm2_props,
        'selftest_passed': selftest_ok,
        'pcr_banks': pcr_banks,
    }

    # Output based on format
    if args.format == 'json':
        output_json(data, issues)
    elif args.format == 'table':
        output_table(data, issues, args.verbose, args.warn_only)
    else:
        output_plain(data, issues, args.verbose, args.warn_only)

    # Exit with appropriate code
    has_critical = any(i['severity'] == 'CRITICAL' for i in issues)
    has_warning = any(i['severity'] == 'WARNING' for i in issues)

    if has_critical:
        sys.exit(1)
    elif has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
