#!/usr/bin/env python3
"""
Monitor SMT (Simultaneous Multithreading/Hyperthreading) status and security implications.

This script checks the status of SMT (Intel Hyper-Threading, AMD SMT) across all CPUs
and reports on security implications related to CPU vulnerabilities that can be
mitigated by disabling SMT.

SMT allows multiple logical threads to share a physical CPU core, which can expose
systems to side-channel attacks including:
- Spectre variants
- MDS (Microarchitectural Data Sampling)
- L1TF (L1 Terminal Fault)
- TAA (TSX Asynchronous Abort)

Environments handling sensitive data (financial, healthcare, government) may require
SMT to be disabled for security compliance.

This monitor checks:
- Current SMT status (enabled/disabled/not supported)
- Per-CPU thread siblings
- CPU vulnerability status and SMT-related mitigations
- Consistency of SMT configuration across the system

Exit codes:
    0 - SMT status is consistent and reported (no warnings)
    1 - SMT-related security warnings or inconsistencies detected
    2 - Usage error or missing dependencies
"""

import argparse
import glob
import json
import os
import re
import sys


def read_file(path):
    """Read a file and return its contents, or None if not readable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, IOError):
        return None


def get_smt_control():
    """Get SMT control status from sysfs.

    Returns:
        str: 'on', 'off', 'forceoff', 'notsupported', or None
    """
    content = read_file('/sys/devices/system/cpu/smt/control')
    return content


def get_smt_active():
    """Check if SMT is currently active.

    Returns:
        bool or None: True if active, False if not, None if unknown
    """
    content = read_file('/sys/devices/system/cpu/smt/active')
    if content is None:
        return None
    return content == '1'


def get_cpu_topology():
    """Get CPU topology information including thread siblings.

    Returns:
        dict: CPU topology with core mapping
    """
    topology = {
        'physical_packages': set(),
        'physical_cores': set(),
        'logical_cpus': [],
        'core_mapping': {},  # physical_core -> list of logical cpus
    }

    cpu_dirs = sorted(glob.glob('/sys/devices/system/cpu/cpu[0-9]*'))

    for cpu_dir in cpu_dirs:
        cpu_id = int(os.path.basename(cpu_dir).replace('cpu', ''))

        # Check if CPU is online
        online_path = os.path.join(cpu_dir, 'online')
        online = read_file(online_path)
        if online is not None and online == '0':
            continue

        # Get physical package (socket)
        package_id = read_file(os.path.join(cpu_dir, 'topology/physical_package_id'))
        if package_id:
            topology['physical_packages'].add(int(package_id))

        # Get core ID
        core_id = read_file(os.path.join(cpu_dir, 'topology/core_id'))
        if core_id and package_id:
            # Create unique physical core identifier (package:core)
            physical_core = f"{package_id}:{core_id}"
            topology['physical_cores'].add(physical_core)

            if physical_core not in topology['core_mapping']:
                topology['core_mapping'][physical_core] = []
            topology['core_mapping'][physical_core].append(cpu_id)

        # Get thread siblings
        siblings_list = read_file(os.path.join(cpu_dir, 'topology/thread_siblings_list'))

        topology['logical_cpus'].append({
            'cpu_id': cpu_id,
            'package_id': int(package_id) if package_id else None,
            'core_id': int(core_id) if core_id else None,
            'thread_siblings': siblings_list,
        })

    # Convert sets to counts
    topology['num_packages'] = len(topology['physical_packages'])
    topology['num_physical_cores'] = len(topology['physical_cores'])
    topology['num_logical_cpus'] = len(topology['logical_cpus'])

    # Calculate threads per core
    if topology['num_physical_cores'] > 0:
        topology['threads_per_core'] = topology['num_logical_cpus'] // topology['num_physical_cores']
    else:
        topology['threads_per_core'] = 1

    # Clean up for JSON serialization
    topology['physical_packages'] = list(topology['physical_packages'])
    topology['physical_cores'] = list(topology['physical_cores'])

    return topology


def get_cpu_vulnerabilities():
    """Get CPU vulnerability status related to SMT.

    Returns:
        dict: Vulnerability status for SMT-related issues
    """
    vulnerabilities = {}
    vuln_dir = '/sys/devices/system/cpu/vulnerabilities'

    # Vulnerabilities that are related to or can be mitigated by SMT
    smt_related = [
        'l1tf',           # L1 Terminal Fault
        'mds',            # Microarchitectural Data Sampling
        'tsx_async_abort', # TAA
        'mmio_stale_data', # Processor MMIO Stale Data
        'spec_store_bypass', # Speculative Store Bypass
        'spectre_v1',     # Spectre Variant 1
        'spectre_v2',     # Spectre Variant 2
        'srbds',          # Special Register Buffer Data Sampling
        'retbleed',       # Return-oriented blind side-channel
        'gds',            # Gather Data Sampling
    ]

    if not os.path.isdir(vuln_dir):
        return vulnerabilities

    for vuln in smt_related:
        status = read_file(os.path.join(vuln_dir, vuln))
        if status:
            vulnerabilities[vuln] = status

    return vulnerabilities


def analyze_smt_status(smt_control, smt_active, topology, vulnerabilities, require_disabled):
    """Analyze SMT status and identify issues.

    Args:
        smt_control: Current SMT control setting
        smt_active: Whether SMT is active
        topology: CPU topology information
        vulnerabilities: Vulnerability status dict
        require_disabled: Whether to warn if SMT is enabled

    Returns:
        list: List of issues found
    """
    issues = []

    # Check SMT status
    if smt_control == 'notsupported':
        # No issues - SMT not available
        pass
    elif smt_active is True:
        if require_disabled:
            issues.append({
                'severity': 'WARNING',
                'type': 'smt_enabled',
                'message': 'SMT is enabled but --require-disabled was specified'
            })
    elif smt_active is False:
        # SMT disabled - good for security
        pass

    # Check for inconsistent thread counts
    cores_with_multiple_threads = [
        core for core, cpus in topology['core_mapping'].items()
        if len(cpus) > 1
    ]

    if not smt_active and cores_with_multiple_threads:
        issues.append({
            'severity': 'WARNING',
            'type': 'inconsistent_state',
            'message': f'SMT reported as inactive but {len(cores_with_multiple_threads)} cores have multiple threads'
        })

    # Check vulnerabilities for SMT-related issues
    vuln_patterns = {
        'SMT vulnerable': 'Vulnerable with SMT',
        'SMT disabled': 'SMT disabled',
        'SMT Host state unknown': 'Unknown SMT state',
    }

    for vuln_name, status in vulnerabilities.items():
        status_lower = status.lower()

        # Check if vulnerable and SMT-related
        if 'vulnerable' in status_lower and 'smt' in status_lower:
            issues.append({
                'severity': 'WARNING',
                'type': 'vulnerability',
                'vuln': vuln_name,
                'status': status,
                'message': f'{vuln_name}: {status}'
            })
        elif 'not affected' not in status_lower and 'mitigation' not in status_lower:
            # Unknown or partially mitigated status
            if 'unknown' in status_lower or 'vulnerable' in status_lower:
                issues.append({
                    'severity': 'INFO',
                    'type': 'vulnerability',
                    'vuln': vuln_name,
                    'status': status,
                    'message': f'{vuln_name}: {status}'
                })

    return issues


def output_plain(smt_control, smt_active, topology, vulnerabilities, issues, verbose, warn_only):
    """Output results in plain text format."""
    if warn_only and not issues:
        return

    if not warn_only:
        print("SMT Status Monitor")
        print("=" * 50)
        print()

        # SMT status
        smt_status_str = smt_control if smt_control else 'unknown'
        active_str = 'yes' if smt_active else 'no' if smt_active is False else 'unknown'
        print(f"SMT Control:    {smt_status_str}")
        print(f"SMT Active:     {active_str}")
        print()

        # Topology summary
        print("CPU Topology:")
        print(f"  Sockets:        {topology['num_packages']}")
        print(f"  Physical Cores: {topology['num_physical_cores']}")
        print(f"  Logical CPUs:   {topology['num_logical_cpus']}")
        print(f"  Threads/Core:   {topology['threads_per_core']}")
        print()

        if verbose:
            # Show per-core thread mapping
            print("Core Mapping (physical_core -> logical_cpus):")
            for core, cpus in sorted(topology['core_mapping'].items()):
                cpu_list = ','.join(str(c) for c in sorted(cpus))
                print(f"  {core}: [{cpu_list}]")
            print()

            # Show vulnerability status
            if vulnerabilities:
                print("SMT-Related Vulnerabilities:")
                for vuln, status in sorted(vulnerabilities.items()):
                    # Truncate long status
                    if len(status) > 60:
                        status = status[:57] + '...'
                    print(f"  {vuln}: {status}")
                print()

    # Show issues
    if issues:
        warnings = [i for i in issues if i['severity'] == 'WARNING']
        infos = [i for i in issues if i['severity'] == 'INFO']

        if warnings:
            print(f"Warnings ({len(warnings)}):")
            for issue in warnings:
                print(f"  [!] {issue['message']}")
            print()

        if infos and verbose:
            print(f"Info ({len(infos)}):")
            for issue in infos:
                print(f"  [i] {issue['message']}")
            print()
    elif not warn_only:
        if smt_active is False or smt_control == 'notsupported':
            print("Status: OK - SMT is disabled or not supported")
        else:
            print("Status: OK - No SMT-related issues detected")


def output_json(smt_control, smt_active, topology, vulnerabilities, issues):
    """Output results in JSON format."""
    # Clean topology for JSON output
    topology_output = {
        'num_packages': topology['num_packages'],
        'num_physical_cores': topology['num_physical_cores'],
        'num_logical_cpus': topology['num_logical_cpus'],
        'threads_per_core': topology['threads_per_core'],
    }

    result = {
        'smt': {
            'control': smt_control,
            'active': smt_active,
        },
        'topology': topology_output,
        'vulnerabilities': vulnerabilities,
        'issues': issues,
        'summary': {
            'warning_count': len([i for i in issues if i['severity'] == 'WARNING']),
            'info_count': len([i for i in issues if i['severity'] == 'INFO']),
        }
    }

    print(json.dumps(result, indent=2))


def output_table(smt_control, smt_active, topology, vulnerabilities, issues, warn_only):
    """Output results in table format."""
    if warn_only and not issues:
        return

    if not warn_only:
        print("=" * 70)
        print("SMT STATUS SUMMARY")
        print("=" * 70)
        print(f"{'Metric':<25} {'Value':<20} {'Status':<25}")
        print("-" * 70)

        # SMT status
        smt_status = 'OK' if smt_active is False or smt_control == 'notsupported' else 'ENABLED'
        print(f"{'SMT Control':<25} {smt_control or 'unknown':<20} {smt_status:<25}")

        active_str = 'yes' if smt_active else 'no' if smt_active is False else 'unknown'
        print(f"{'SMT Active':<25} {active_str:<20} {'':<25}")

        print(f"{'Physical Cores':<25} {topology['num_physical_cores']:<20} {'':<25}")
        print(f"{'Logical CPUs':<25} {topology['num_logical_cpus']:<20} {'':<25}")
        print(f"{'Threads per Core':<25} {topology['threads_per_core']:<20} {'':<25}")
        print("=" * 70)
        print()

    if issues:
        print("ISSUES DETECTED")
        print("=" * 70)
        print(f"{'Severity':<10} {'Type':<20} {'Details':<40}")
        print("-" * 70)
        for issue in issues:
            details = issue.get('message', '')[:40]
            print(f"{issue['severity']:<10} {issue['type']:<20} {details:<40}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor SMT (Hyperthreading) status and security implications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Show SMT status and topology
  %(prog)s --format json          # JSON output for automation
  %(prog)s --require-disabled     # Warn if SMT is enabled
  %(prog)s -v                     # Verbose output with core mapping
  %(prog)s -w                     # Only show if there are warnings

SMT Security Considerations:
  SMT allows multiple threads to share CPU resources, which can leak
  information through side-channel attacks. Affected vulnerabilities:

  - L1TF (L1 Terminal Fault): Leaks L1 cache data
  - MDS (Microarchitectural Data Sampling): Leaks CPU buffer data
  - TAA (TSX Async Abort): Leaks data via TSX aborts
  - Spectre variants: Speculative execution attacks

  For high-security environments, consider disabling SMT:
    # Temporarily: echo off > /sys/devices/system/cpu/smt/control
    # Permanently: Add nosmt to kernel command line

Exit codes:
  0 - No warnings detected
  1 - SMT-related warnings or inconsistencies
  2 - Usage error or missing dependencies
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
        help='Show detailed information including core mapping'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if there are warnings'
    )

    parser.add_argument(
        '--require-disabled',
        action='store_true',
        help='Warn if SMT is enabled (for security-sensitive environments)'
    )

    args = parser.parse_args()

    # Check for Linux
    if not os.path.exists('/sys/devices/system/cpu'):
        print("Error: /sys/devices/system/cpu not found", file=sys.stderr)
        print("This script requires Linux sysfs", file=sys.stderr)
        sys.exit(2)

    # Gather information
    smt_control = get_smt_control()
    smt_active = get_smt_active()
    topology = get_cpu_topology()
    vulnerabilities = get_cpu_vulnerabilities()

    # Analyze
    issues = analyze_smt_status(
        smt_control, smt_active, topology, vulnerabilities,
        require_disabled=args.require_disabled
    )

    # Output
    if args.format == 'json':
        output_json(smt_control, smt_active, topology, vulnerabilities, issues)
    elif args.format == 'table':
        output_table(smt_control, smt_active, topology, vulnerabilities, issues, args.warn_only)
    else:  # plain
        output_plain(smt_control, smt_active, topology, vulnerabilities, issues,
                    args.verbose, args.warn_only)

    # Exit based on warnings
    has_warnings = any(i['severity'] == 'WARNING' for i in issues)
    sys.exit(1 if has_warnings else 0)


if __name__ == '__main__':
    main()
