#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [cpu, microcode, security, firmware]
#   requires: []
#   privilege: none
#   related: [cpu_isolation, cpu_time]
#   brief: Monitor CPU microcode versions for security and consistency

"""
Monitor CPU microcode versions for security and consistency.

Reads CPU microcode information from /proc/cpuinfo and reports on microcode
versions across all CPU cores. Useful for:
- Verifying microcode updates are applied after security patches
- Detecting inconsistent microcode versions across cores
- Fleet-wide microcode inventory and compliance checking
- Identifying systems that need microcode updates

The script can check against a baseline version to identify outdated systems.
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_cpuinfo(content: str) -> list[dict[str, Any]]:
    """Parse /proc/cpuinfo content.

    Returns:
        list: List of dicts, one per CPU core with relevant info
    """
    cpus = []

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


def analyze_microcode(cpus: list[dict], min_version: str | None = None) -> dict[str, Any]:
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
            'issues': [{'severity': 'error', 'message': 'No CPUs found'}]
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
        if not socket_info['microcode']:
            missing_microcode = True
            issues.append({
                'severity': 'warning',
                'socket': socket_id,
                'message': f'Socket {socket_id}: No microcode version reported'
            })
        elif len(socket_info['microcode']) > 1:
            versions = ', '.join(sorted(socket_info['microcode']))
            issues.append({
                'severity': 'warning',
                'socket': socket_id,
                'message': f'Socket {socket_id}: Inconsistent microcode versions ({versions})'
            })

        all_versions.update(socket_info['microcode'])

    # Check for inconsistency across sockets
    if len(all_versions) > 1 and len(sockets) > 1:
        versions = ', '.join(sorted(all_versions))
        issues.append({
            'severity': 'warning',
            'socket': 'all',
            'message': f'Inconsistent microcode versions across sockets ({versions})'
        })

    # Check against minimum version if specified
    if min_version and all_versions:
        try:
            min_int = int(min_version, 16) if min_version.startswith('0x') else int(min_version, 16)

            for version in all_versions:
                try:
                    ver_int = int(version, 16) if version.startswith('0x') else int(version, 16)
                    if ver_int < min_int:
                        issues.append({
                            'severity': 'critical',
                            'socket': 'all',
                            'message': f'Microcode version {version} is below minimum {min_version}'
                        })
                except ValueError:
                    pass
        except ValueError:
            issues.append({
                'severity': 'error',
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
    }

    return {
        'summary': summary,
        'sockets': {k: {**v, 'microcode': list(v['microcode'])} for k, v in sockets.items()},
        'issues': issues,
    }


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor CPU microcode versions")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--min-version", metavar="VERSION",
                        help="Minimum acceptable microcode version (hex, e.g., 0x20)")
    opts = parser.parse_args(args)

    # Read /proc/cpuinfo
    try:
        cpuinfo = context.read_file('/proc/cpuinfo')
    except FileNotFoundError:
        output.error("/proc/cpuinfo not found. This script requires a Linux system.")
        return 2
    except OSError as e:
        output.error(f"Cannot read /proc/cpuinfo: {e}")
        return 2

    # Parse CPU information
    cpus = parse_cpuinfo(cpuinfo)

    if not cpus:
        output.error("No CPU information available")
        return 2

    # Analyze microcode
    analysis = analyze_microcode(cpus, opts.min_version)

    # Build result
    result = {
        'cpu': {
            'model_name': analysis['summary']['model_name'],
            'vendor': analysis['summary']['vendor'],
            'family_model_stepping': f"{analysis['summary']['cpu_family']}/{analysis['summary']['model']}/{analysis['summary']['stepping']}",
        },
        'microcode': {
            'current': analysis['summary']['current_microcode'],
            'versions': analysis['summary']['microcode_versions'],
            'consistent': analysis['summary']['consistent'],
        },
        'sockets': analysis['summary']['total_sockets'],
        'logical_cpus': analysis['summary']['total_cpus'],
        'issues': analysis['issues'],
    }

    if opts.verbose:
        result['per_socket'] = analysis['sockets']

    output.emit(result)

    # Set summary
    has_critical = any(i['severity'] == 'critical' for i in analysis['issues'])
    has_warnings = any(i['severity'] == 'warning' for i in analysis['issues'])

    if has_critical:
        output.set_summary(f"microcode {analysis['summary']['current_microcode']} below minimum")
    elif has_warnings:
        output.set_summary(f"microcode issues: {len(analysis['issues'])} warnings")
    else:
        output.set_summary(f"microcode {analysis['summary']['current_microcode']}, {analysis['summary']['total_sockets']} socket(s)")

    # Exit code
    if has_critical or has_warnings:
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
