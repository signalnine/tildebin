#!/usr/bin/env python3
"""
Monitor CPU microcode versions for security and consistency.

This script reads CPU microcode information from /proc/cpuinfo and reports
on microcode versions across all CPU cores. Useful for:
- Verifying microcode updates are applied after security patches
- Detecting inconsistent microcode versions across cores
- Fleet-wide microcode inventory and compliance checking
- Identifying systems that need microcode updates

The script can check against a baseline version to identify outdated systems.

Exit codes:
    0 - All CPUs have consistent microcode, no issues detected
    1 - Microcode issues detected (outdated, inconsistent, or missing)
    2 - Usage error or required files not available
"""

import argparse
import sys
import json
import os
import re


def get_cpuinfo():
    """Read and parse /proc/cpuinfo.

    Returns:
        list: List of dicts, one per CPU core with relevant info
    """
    cpus = []

    try:
        with open('/proc/cpuinfo', 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print("Error: /proc/cpuinfo not found", file=sys.stderr)
        print("This script requires a Linux system with /proc filesystem",
              file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print("Error: Cannot read /proc/cpuinfo (permission denied)",
              file=sys.stderr)
        sys.exit(2)

    # Split by empty lines (each CPU block)
    blocks = content.split('\n\n')

    for block in blocks:
        if not block.strip():
            continue

        cpu = {}
        for line in block.split('\n'):
            if ':' not in line:
                continue

            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()

            if key == 'processor':
                cpu['processor'] = int(value)
            elif key == 'vendor_id':
                cpu['vendor'] = value
            elif key == 'model name':
                cpu['model_name'] = value
            elif key == 'microcode':
                cpu['microcode'] = value
            elif key == 'cpu family':
                cpu['cpu_family'] = value
            elif key == 'model':
                cpu['model'] = value
            elif key == 'stepping':
                cpu['stepping'] = value
            elif key == 'physical id':
                cpu['physical_id'] = int(value)
            elif key == 'core id':
                cpu['core_id'] = int(value)

        if 'processor' in cpu:
            cpus.append(cpu)

    return cpus


def get_dmesg_microcode():
    """Try to get microcode info from dmesg (useful for update history).

    Returns:
        list: List of microcode update messages from dmesg
    """
    updates = []

    try:
        # Try to read /var/log/dmesg or use dmesg command
        import subprocess
        result = subprocess.run(
            ['dmesg'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'microcode' in line.lower():
                    updates.append(line.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass

    return updates


def analyze_microcode(cpus, min_version=None):
    """Analyze microcode information across CPUs.

    Args:
        cpus: List of CPU info dicts
        min_version: Minimum acceptable microcode version (hex string)

    Returns:
        dict: Analysis results with summary and issues
    """
    if not cpus:
        return {
            'error': 'No CPU information available',
            'issues': [{'severity': 'ERROR', 'message': 'No CPUs found'}]
        }

    # Group by physical CPU (socket)
    sockets = {}
    for cpu in cpus:
        socket_id = cpu.get('physical_id', 0)
        if socket_id not in sockets:
            sockets[socket_id] = {
                'physical_id': socket_id,
                'cores': [],
                'microcode': set(),
                'vendor': cpu.get('vendor', 'Unknown'),
                'model_name': cpu.get('model_name', 'Unknown'),
                'cpu_family': cpu.get('cpu_family', 'Unknown'),
                'model': cpu.get('model', 'Unknown'),
                'stepping': cpu.get('stepping', 'Unknown'),
            }
        sockets[socket_id]['cores'].append(cpu)
        if 'microcode' in cpu:
            sockets[socket_id]['microcode'].add(cpu['microcode'])

    # Analyze results
    issues = []
    all_versions = set()
    missing_microcode = False

    for socket_id, socket_info in sockets.items():
        # Check for missing microcode
        if not socket_info['microcode']:
            missing_microcode = True
            issues.append({
                'severity': 'WARNING',
                'socket': socket_id,
                'message': f'Socket {socket_id}: No microcode version reported'
            })
        elif len(socket_info['microcode']) > 1:
            # Inconsistent microcode within socket
            versions = ', '.join(sorted(socket_info['microcode']))
            issues.append({
                'severity': 'WARNING',
                'socket': socket_id,
                'message': f'Socket {socket_id}: Inconsistent microcode versions ({versions})'
            })

        all_versions.update(socket_info['microcode'])

    # Check for inconsistency across sockets
    if len(all_versions) > 1 and len(sockets) > 1:
        versions = ', '.join(sorted(all_versions))
        issues.append({
            'severity': 'WARNING',
            'socket': 'all',
            'message': f'Inconsistent microcode versions across sockets ({versions})'
        })

    # Check against minimum version if specified
    if min_version and all_versions:
        try:
            # Convert hex strings to integers for comparison
            min_int = int(min_version, 16) if min_version.startswith('0x') else int(min_version, 16)

            for version in all_versions:
                try:
                    ver_int = int(version, 16) if version.startswith('0x') else int(version, 16)
                    if ver_int < min_int:
                        issues.append({
                            'severity': 'CRITICAL',
                            'socket': 'all',
                            'message': f'Microcode version {version} is below minimum {min_version}'
                        })
                except ValueError:
                    pass
        except ValueError:
            issues.append({
                'severity': 'ERROR',
                'socket': 'all',
                'message': f'Invalid minimum version format: {min_version}'
            })

    # Build summary
    sample_cpu = cpus[0] if cpus else {}
    summary = {
        'total_cpus': len(cpus),
        'total_sockets': len(sockets),
        'vendor': sample_cpu.get('vendor', 'Unknown'),
        'model_name': sample_cpu.get('model_name', 'Unknown'),
        'cpu_family': sample_cpu.get('cpu_family', 'Unknown'),
        'model': sample_cpu.get('model', 'Unknown'),
        'stepping': sample_cpu.get('stepping', 'Unknown'),
        'microcode_versions': sorted(all_versions) if all_versions else ['Unknown'],
        'current_microcode': list(all_versions)[0] if len(all_versions) == 1 else 'Mixed',
        'consistent': len(all_versions) <= 1 and not missing_microcode,
        'issue_count': len(issues),
    }

    return {
        'summary': summary,
        'sockets': {k: {**v, 'microcode': list(v['microcode'])} for k, v in sockets.items()},
        'issues': issues,
    }


def output_plain(result, verbose=False, warn_only=False):
    """Output results in plain text format."""
    summary = result['summary']
    issues = result['issues']

    if not warn_only:
        print(f"CPU: {summary['model_name']}")
        print(f"Vendor: {summary['vendor']}")
        print(f"Family/Model/Stepping: {summary['cpu_family']}/{summary['model']}/{summary['stepping']}")
        print(f"Sockets: {summary['total_sockets']}, Logical CPUs: {summary['total_cpus']}")
        print(f"Microcode: {summary['current_microcode']}")
        print()

        if verbose:
            print("Per-Socket Details:")
            for socket_id, socket_info in result['sockets'].items():
                versions = ', '.join(socket_info['microcode']) if socket_info['microcode'] else 'Unknown'
                core_count = len(socket_info['cores'])
                print(f"  Socket {socket_id}: {core_count} cores, microcode: {versions}")
            print()

    if issues:
        if not warn_only:
            print("Issues Detected:")
        for issue in issues:
            print(f"[{issue['severity']}] {issue['message']}")
    elif not warn_only:
        print("No microcode issues detected.")


def output_json(result):
    """Output results in JSON format."""
    print(json.dumps(result, indent=2))


def output_table(result, verbose=False, warn_only=False):
    """Output results in table format."""
    summary = result['summary']
    issues = result['issues']

    if not warn_only:
        print("=" * 70)
        print(f"{'CPU MICROCODE STATUS':^70}")
        print("=" * 70)
        print()

        print(f"{'Property':<25} {'Value':<45}")
        print("-" * 70)
        print(f"{'CPU Model':<25} {summary['model_name'][:45]:<45}")
        print(f"{'Vendor':<25} {summary['vendor']:<45}")
        print(f"{'Family/Model/Stepping':<25} {summary['cpu_family']}/{summary['model']}/{summary['stepping']:<45}")
        print(f"{'Sockets':<25} {summary['total_sockets']:<45}")
        print(f"{'Logical CPUs':<25} {summary['total_cpus']:<45}")
        print(f"{'Microcode Version':<25} {summary['current_microcode']:<45}")
        print(f"{'Consistent':<25} {'Yes' if summary['consistent'] else 'No':<45}")
        print()

        if verbose:
            print("=" * 70)
            print(f"{'PER-SOCKET DETAILS':^70}")
            print("=" * 70)
            print()

            print(f"{'Socket':<10} {'Cores':<10} {'Microcode':<50}")
            print("-" * 70)

            for socket_id, socket_info in result['sockets'].items():
                versions = ', '.join(socket_info['microcode']) if socket_info['microcode'] else 'Unknown'
                core_count = len(socket_info['cores'])
                print(f"{socket_id:<10} {core_count:<10} {versions[:50]:<50}")

            print()

    if issues:
        if not warn_only:
            print("=" * 70)
            print(f"{'ISSUES DETECTED':^70}")
            print("=" * 70)
            print()

        print(f"{'Severity':<12} {'Message':<58}")
        print("-" * 70)

        for issue in issues:
            msg = issue['message'][:58]
            print(f"{issue['severity']:<12} {msg:<58}")

        print()
    elif not warn_only:
        print("=" * 70)
        print(f"{'NO MICROCODE ISSUES DETECTED':^70}")
        print("=" * 70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor CPU microcode versions for security and consistency',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Check microcode status
  %(prog)s --verbose           # Show per-socket details
  %(prog)s --format json       # Output in JSON format
  %(prog)s --min-version 0x20  # Warn if version below 0x20

Exit codes:
  0 - All CPUs have consistent microcode, no issues
  1 - Microcode issues detected (outdated, inconsistent)
  2 - Usage error or required files not available

Notes:
  - Requires Linux /proc/cpuinfo
  - Microcode versions are typically hexadecimal (e.g., 0xde)
  - Inconsistent versions may indicate failed updates
  - Use --min-version for fleet compliance checking
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
        help='Show detailed per-socket information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    parser.add_argument(
        '--min-version',
        metavar='VERSION',
        help='Minimum acceptable microcode version (hex, e.g., 0x20)'
    )

    args = parser.parse_args()

    # Check for /proc/cpuinfo
    if not os.path.exists('/proc/cpuinfo'):
        print("Error: /proc/cpuinfo not found", file=sys.stderr)
        print("This script requires a Linux system", file=sys.stderr)
        sys.exit(2)

    # Get CPU information
    cpus = get_cpuinfo()

    if not cpus:
        print("Error: No CPU information available", file=sys.stderr)
        sys.exit(2)

    # Analyze microcode
    result = analyze_microcode(cpus, args.min_version)

    # Output results
    if args.format == 'json':
        output_json(result)
    elif args.format == 'table':
        output_table(result, args.verbose, args.warn_only)
    else:
        output_plain(result, args.verbose, args.warn_only)

    # Exit code based on issues
    has_critical = any(i['severity'] == 'CRITICAL' for i in result['issues'])
    has_issues = len(result['issues']) > 0

    if has_critical or has_issues:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
