#!/usr/bin/env python3
# boxctl:
#   category: baremetal/cpu
#   tags: [cpu, smt, hyperthreading, security, vulnerability]
#   requires: []
#   privilege: user
#   related: [scheduler_affinity, run_queue]
#   brief: Monitor SMT (Hyperthreading) status and security implications

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
"""

import argparse
import glob
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def read_file(path: str) -> str | None:
    """Read a file and return its contents, or None if not readable."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, IOError):
        return None


def get_smt_control() -> str | None:
    """Get SMT control status from sysfs."""
    return read_file('/sys/devices/system/cpu/smt/control')


def get_smt_active() -> bool | None:
    """Check if SMT is currently active."""
    content = read_file('/sys/devices/system/cpu/smt/active')
    if content is None:
        return None
    return content == '1'


def get_cpu_topology() -> dict[str, Any]:
    """Get CPU topology information including thread siblings."""
    topology = {
        'physical_packages': set(),
        'physical_cores': set(),
        'logical_cpus': [],
        'core_mapping': {},
    }

    cpu_dirs = sorted(glob.glob('/sys/devices/system/cpu/cpu[0-9]*'))

    for cpu_dir in cpu_dirs:
        cpu_id = int(os.path.basename(cpu_dir).replace('cpu', ''))

        # Check if CPU is online
        online_path = os.path.join(cpu_dir, 'online')
        online = read_file(online_path)
        if online is not None and online == '0':
            continue

        package_id = read_file(os.path.join(cpu_dir, 'topology/physical_package_id'))
        if package_id:
            topology['physical_packages'].add(int(package_id))

        core_id = read_file(os.path.join(cpu_dir, 'topology/core_id'))
        if core_id and package_id:
            physical_core = f"{package_id}:{core_id}"
            topology['physical_cores'].add(physical_core)

            if physical_core not in topology['core_mapping']:
                topology['core_mapping'][physical_core] = []
            topology['core_mapping'][physical_core].append(cpu_id)

        siblings_list = read_file(os.path.join(cpu_dir, 'topology/thread_siblings_list'))

        topology['logical_cpus'].append({
            'cpu_id': cpu_id,
            'package_id': int(package_id) if package_id else None,
            'core_id': int(core_id) if core_id else None,
            'thread_siblings': siblings_list,
        })

    topology['num_packages'] = len(topology['physical_packages'])
    topology['num_physical_cores'] = len(topology['physical_cores'])
    topology['num_logical_cpus'] = len(topology['logical_cpus'])

    if topology['num_physical_cores'] > 0:
        topology['threads_per_core'] = topology['num_logical_cpus'] // topology['num_physical_cores']
    else:
        topology['threads_per_core'] = 1

    # Clean up for JSON serialization
    topology['physical_packages'] = list(topology['physical_packages'])
    topology['physical_cores'] = list(topology['physical_cores'])

    return topology


def get_cpu_vulnerabilities() -> dict[str, str]:
    """Get CPU vulnerability status related to SMT."""
    vulnerabilities = {}
    vuln_dir = '/sys/devices/system/cpu/vulnerabilities'

    smt_related = [
        'l1tf',
        'mds',
        'tsx_async_abort',
        'mmio_stale_data',
        'spec_store_bypass',
        'spectre_v1',
        'spectre_v2',
        'srbds',
        'retbleed',
        'gds',
    ]

    if not os.path.isdir(vuln_dir):
        return vulnerabilities

    for vuln in smt_related:
        status = read_file(os.path.join(vuln_dir, vuln))
        if status:
            vulnerabilities[vuln] = status

    return vulnerabilities


def analyze_smt_status(smt_control: str | None, smt_active: bool | None,
                       topology: dict, vulnerabilities: dict,
                       require_disabled: bool) -> list[dict]:
    """Analyze SMT status and identify issues."""
    issues = []

    if smt_control == 'notsupported':
        pass  # No issues
    elif smt_active is True:
        if require_disabled:
            issues.append({
                'severity': 'WARNING',
                'type': 'smt_enabled',
                'message': 'SMT is enabled but --require-disabled was specified'
            })
    elif smt_active is False:
        pass  # SMT disabled - good for security

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
    for vuln_name, status in vulnerabilities.items():
        status_lower = status.lower()

        if 'vulnerable' in status_lower and 'smt' in status_lower:
            issues.append({
                'severity': 'WARNING',
                'type': 'vulnerability',
                'vuln': vuln_name,
                'status': status,
                'message': f'{vuln_name}: {status}'
            })
        elif 'not affected' not in status_lower and 'mitigation' not in status_lower:
            if 'unknown' in status_lower or 'vulnerable' in status_lower:
                issues.append({
                    'severity': 'INFO',
                    'type': 'vulnerability',
                    'vuln': vuln_name,
                    'status': status,
                    'message': f'{vuln_name}: {status}'
                })

    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no warnings, 1 = warnings found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor SMT (Hyperthreading) status and security implications"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed information including core mapping")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--require-disabled", action="store_true",
                        help="Warn if SMT is enabled (for security-sensitive environments)")
    opts = parser.parse_args(args)

    # Check for Linux sysfs
    if not os.path.exists('/sys/devices/system/cpu'):
        output.error("/sys/devices/system/cpu not found")
        return 2

    # Gather information
    smt_control = get_smt_control()
    smt_active = get_smt_active()
    topology = get_cpu_topology()
    vulnerabilities = get_cpu_vulnerabilities()

    # Analyze
    issues = analyze_smt_status(
        smt_control, smt_active, topology, vulnerabilities,
        require_disabled=opts.require_disabled
    )

    # Build output
    result = {
        'smt': {
            'control': smt_control,
            'active': smt_active,
        },
        'topology': {
            'num_packages': topology['num_packages'],
            'num_physical_cores': topology['num_physical_cores'],
            'num_logical_cpus': topology['num_logical_cpus'],
            'threads_per_core': topology['threads_per_core'],
        },
        'issues': issues,
        'warning_count': len([i for i in issues if i['severity'] == 'WARNING']),
    }

    if opts.verbose:
        result['vulnerabilities'] = vulnerabilities
        result['core_mapping'] = topology['core_mapping']

    output.emit(result)

    # Set summary
    if smt_control == 'notsupported':
        output.set_summary("SMT not supported")
    elif smt_active:
        output.set_summary(f"SMT enabled ({topology['threads_per_core']} threads/core)")
    else:
        output.set_summary(f"SMT disabled ({topology['num_physical_cores']} cores)")

    has_warnings = any(i['severity'] == 'WARNING' for i in issues)
    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
